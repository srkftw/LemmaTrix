"""Explicit common-image Library seed setup and recovery.

This adapter selects a signed native package, opaque purpose2 backing and scoped
relationships. Lean owns archive validation, serving, budgets and reconnection.
No content catalog, media decoder, payload store or acquisition worker runs here.
"""
import argparse
import hashlib
import json
import os
import signal
import struct
import subprocess
import time
from pathlib import Path
import library_peer
import live
import network
import nodes
import server_content

ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 6029312


def archive(slot, namespace, manifest, size):
    network.digest(namespace)
    network.digest(manifest)
    if slot not in range(4) or not 0 < size <= MAX_BYTES:
        raise ValueError('archive slot0..3 and selected byte ceiling1..6029312 required')
    return dict(slot=slot, namespace=namespace, manifest_sha256=manifest, bytes=size)


def relationship(slot, credentials, description, budget, lifetime):
    if slot not in range(4) or not 0 < budget <= 16777216 or not 0 < lifetime <= 100000:
        raise ValueError('connection slot0..3, byte budget1..16777216 and lifetime1..100000 required')
    credentials = credentials.resolve()
    description = description.resolve()
    role, material = network.load_credentials(credentials)
    _, descriptor, _ = network.load_description(description)
    if role != 2 or struct.unpack_from('<Q', descriptor, 16)[0] != 6:
        raise ValueError('Library seed requires server-role credentials and signed library-seed description')
    if material[:96] != descriptor[64:128] + hashlib.sha256(descriptor).digest():
        raise ValueError('credentials differ from explicitly selected signed service description')
    return dict(slot=slot, credentials=str(credentials), description=str(description),
                description_sha256=hashlib.sha256(description.read_bytes()).hexdigest(),
                budget=budget, lifetime=lifetime,
                disclosure='direct encrypted bulk endpoint and relationship metadata visible')


def validate(config):
    if config.get('schema') != 1 or config.get('role') != 'library-seed' or config.get('rights') != 1025:
        raise ValueError('unsupported Library seed configuration; exact read+network rights1025 required')
    raw = nodes.validate_package(config)
    if not Path(config['server_store']).is_file():
        raise ValueError('explicit server backing is unavailable')
    archives = [archive(a['slot'], a['namespace'], a['manifest_sha256'], a['bytes']) for a in config['archives']]
    relations = [relationship(r['slot'], Path(r['credentials']), Path(r['description']), r['budget'], r['lifetime'])
                 for r in config['relationships']]
    if not 1 <= len(archives) <= 4 or len({a['slot'] for a in archives}) != len(archives):
        raise ValueError('select1..4 distinct archive slots')
    if sum(a['bytes'] for a in archives) > MAX_BYTES:
        raise ValueError('simultaneously recovered roots exceed the shared6029312-byte volatile content profile')
    if not 1 <= len(relations) <= 4 or len({r['slot'] for r in relations}) != len(relations):
        raise ValueError('select1..4 distinct connection slots')
    for old, current in zip(config['relationships'], relations):
        if old['description_sha256'] != current['description_sha256']:
            raise ValueError('configured signed relationship changed; explicit reconfiguration required')
    return raw


def write_config(path, config, replace=False):
    validate(config)
    if replace:
        # An explicit add command may update only this operator-selected config.
        temporary = path.with_name(path.name + '.new')
        write_config(temporary, config)
        os.replace(temporary, path)
        return config
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as output:
        json.dump(config, output, indent=2)
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())
    return config


def initialize(args):
    approved = nodes.approved_package(args.package, args.public, args.release_id, 1025)
    return write_config(args.config, dict(schema=1, role='library-seed', **approved,
        server_store=str(args.store.resolve()), archives=[archive(args.archive_slot, args.namespace, args.manifest_sha256, args.bytes)],
        relationships=[relationship(args.connection_slot, args.credentials, args.description, args.budget, args.lifetime)],
        storage_policy='explicit purpose2 operator namespaces; intentional plaintext; no personal vault',
        service_policy='zero-price selected immutable roots; direct encrypted bulk only',
        restored_authority='none; fresh namespace and authenticated stream grants on every run'))


def recover_selected(client, config, instance):
    # Launcher is the explicitly authorized operator bootstrap caller. The
    # recovered read grants belong directly to the native serving incarnation.
    owner = struct.unpack_from('<Q', client.request(2), 32)[0]
    results = []
    for selected in config['archives']:
        grant = server_content.permit(client, owner, bytes.fromhex(selected['namespace']),
            bytes.fromhex(selected['manifest_sha256']), selected['bytes'], selected['slot'])
        try:
            result = server_content.recover(client, grant, time.time_ns() & 0x7fffffffffffffff, instance)
        finally:
            server_content.call(client, 256, grant)
        result.update(slot=selected['slot'], manifest_sha256=selected['manifest_sha256'])
        results.append(result)
    for selected in config['relationships']:
        slot = selected['slot']
        network.configure(client, Path(selected['credentials']), Path(selected['description']), slot)
        network.call(client, 13, slot=slot)
        _, material = network.load_credentials(Path(selected['credentials']))
        for result in results:
            root = bytes.fromhex(result['manifest_sha256'])
            stream = int.from_bytes(root[:8], 'little') | 1
            library_peer.call(client, instance, 400, slot, 2, stream, result['content_handle'],
                selected['budget'], selected['lifetime'], material[:32] + material[64:96] + root)
    return results


def inspect(client, config, instance):
    return dict(instance=instance, release_id=config['release_id'],
        archives=config['archives'],
        relationships=[network.status(client, r['slot']) for r in config['relationships']],
        scopes=[dict(scope=i, state=f[2], active=f[2] == 1, waiting_for_authentication=f[2] == 2, role=f[3], send_pending=bool(f[4]),
                     response_bytes=f[5], snapshot_id=f[6], last_error=f[7])
                for i in range(16) for f, _ in [library_peer.call(client, instance, 401, i)]],
        backing=config['server_store'], live_handles_persisted=False,
        limits='four archives; four relationships; aggregate recovered content6029312 bytes; fresh bounded stream policy')


def run(args, config):
    if args.socket.exists():
        raise ValueError('socket already exists; refusing to attach to or stop another guest')
    raw = validate(config)
    image = Path(args.image or os.environ.get('LT_GUEST_IMAGE') or ROOT/'build/live/guest.bin').resolve()
    image_sha = hashlib.sha256(image.read_bytes()).hexdigest()
    command = [str(ROOT/'lt'), 'run', '--backend', args.backend, '--socket', str(args.socket),
               '--image', str(image), '--server-store', config['server_store'], '--network-mux']
    process = subprocess.Popen(command, cwd=ROOT, start_new_session=True)
    client = None
    try:
        client = nodes.connect(args.socket, process)
        instance = nodes.start_package(client, config, raw)
        recovered = recover_selected(client, config, instance)
        print(json.dumps(dict(role='library-seed', instance=instance, image_sha256=image_sha,
            release_id=config['release_id'], recovered=recovered, socket=str(args.socket),
            authority='fresh explicit operator namespace and selected authenticated relationships'), indent=2), flush=True)
        client.close()
        client = None
        return process.wait()
    except KeyboardInterrupt:
        return 130
    finally:
        if client:
            client.close()
        if process.poll() is None:
            try:
                control = live.Client(args.socket, timeout=5)
                try:
                    control.request(70)
                finally:
                    control.close()
            except (OSError, EOFError, ValueError, TimeoutError):
                pass
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()


def add_selection_options(parser, kind):
    if kind == 'archive':
        parser.add_argument('--archive-slot', type=int, choices=range(4), required=True)
        parser.add_argument('--namespace', required=True)
        parser.add_argument('--manifest-sha256', required=True)
        parser.add_argument('--bytes', type=int, required=True)
    else:
        parser.add_argument('--connection-slot', type=int, choices=range(4), required=True)
        parser.add_argument('--credentials', type=Path, required=True)
        parser.add_argument('--description', type=Path, required=True)
        parser.add_argument('--budget', type=int, default=16777216)
        parser.add_argument('--lifetime', type=int, default=100000)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    command = commands.add_parser('init')
    command.add_argument('config', type=Path)
    command.add_argument('--package', type=Path, required=True)
    command.add_argument('--public', type=Path, required=True)
    command.add_argument('--release-id', required=True)
    command.add_argument('--store', type=Path, required=True)
    add_selection_options(command, 'archive')
    add_selection_options(command, 'relationship')
    for name, kind in [('add-archive', 'archive'), ('add-relationship', 'relationship')]:
        command = commands.add_parser(name)
        command.add_argument('config', type=Path)
        add_selection_options(command, kind)
    command = commands.add_parser('run')
    command.add_argument('config', type=Path)
    command.add_argument('--socket', type=Path, required=True)
    command.add_argument('--backend', choices=('qemu', 'x86_64', 'aarch64'), default='qemu')
    command.add_argument('--image', type=Path)
    for name in ('recover', 'inspect'):
        command = commands.add_parser(name)
        command.add_argument('config', type=Path)
        command.add_argument('--socket', type=Path, required=True)
        command.add_argument('--instance', type=int, required=True)
    command = commands.add_parser('stop')
    command.add_argument('--socket', type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == 'init':
        result = initialize(args)
    elif args.command.startswith('add-'):
        config = json.loads(args.config.read_text())
        if args.command == 'add-archive':
            config['archives'].append(archive(args.archive_slot, args.namespace, args.manifest_sha256, args.bytes))
        else:
            config['relationships'].append(relationship(args.connection_slot, args.credentials, args.description, args.budget, args.lifetime))
        result = write_config(args.config, config, replace=True)
    else:
        config = json.loads(args.config.read_text()) if args.command != 'stop' else None
        if config:
            validate(config)
        if args.command == 'run':
            return run(args, config)
        client = live.Client(args.socket, timeout=180)
        try:
            if args.command == 'stop':
                try:
                    client.request(70)
                except EOFError:
                    pass
                return 0
            result = inspect(client, config, args.instance) if args.command == 'inspect' else recover_selected(client, config, args.instance)
        finally:
            client.close()
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
