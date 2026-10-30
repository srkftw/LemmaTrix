"""Explicit common-image Library seed setup and recovery.

This adapter selects a signed native package, opaque purpose2 backing and scoped
relationships. Lean owns archive validation, serving, budgets and approved live-scope renewal.
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
import service_jobs

ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 6029312
INDEXED_MAX_BYTES = 67108864


def archive(slot, namespace, manifest, size):
    network.digest(namespace)
    network.digest(manifest)
    if slot not in range(4) or not 0 < size <= MAX_BYTES:
        raise ValueError('archive slot0..3 and selected byte ceiling1..6029312 required')
    return dict(slot=slot, namespace=namespace, manifest_sha256=manifest, bytes=size)


def indexed_item(slot, namespace, manifest, size):
    network.digest(namespace)
    network.digest(manifest)
    if slot not in range(16) or not 0 < size <= INDEXED_MAX_BYTES:
        raise ValueError('indexed item slot0..15 and byte ceiling1..67108864 required')
    return dict(slot=slot, namespace=namespace, manifest_sha256=manifest, bytes=size,
                storage='indexed-purpose2')


def relationship(slot, credentials, description, budget, lifetime):
    if slot not in range(4) or not 0 < budget <= 134217728 or not 0 < lifetime <= 100000:
        raise ValueError('connection slot0..3, byte budget1..134217728 and lifetime1..100000 required')
    credentials = credentials.resolve()
    description = description.resolve()
    role, material = network.load_credentials(credentials)
    _, descriptor, _ = network.load_description(description)
    if role != 2 or struct.unpack_from('<Q', descriptor, 16)[0] != 6:
        raise ValueError('Library seed requires server-role credentials and signed library-seed description')
    if budget > struct.unpack_from('<Q', descriptor, 48)[0]:
        raise ValueError('selected byte budget exceeds the signed service description')
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
    archives = [archive(a['slot'], a['namespace'], a['manifest_sha256'], a['bytes']) for a in config.get('archives', [])]
    indexed = [indexed_item(a['slot'], a['namespace'], a['manifest_sha256'], a['bytes'])
               for a in config.get('indexed_items', [])]
    relations = [relationship(r['slot'], Path(r['credentials']), Path(r['description']), r['budget'], r['lifetime'])
                 for r in config['relationships']]
    if len(archives) > 4 or len({a['slot'] for a in archives}) != len(archives):
        raise ValueError('select at most4 distinct legacy archive slots')
    if len(indexed) > 16 or len({a['slot'] for a in indexed}) != len(indexed):
        raise ValueError('select at most16 distinct indexed item slots')
    if not archives and not indexed:
        raise ValueError('select at least one retained archive or indexed item')
    if sum(a['bytes'] for a in archives) > MAX_BYTES:
        raise ValueError('simultaneously recovered roots exceed the shared6029312-byte volatile content profile')
    if not 1 <= len(relations) <= 4 or len({r['slot'] for r in relations}) != len(relations):
        raise ValueError('select1..4 distinct connection slots')
    if (len(archives) + len(indexed)) * len(relations) > 16:
        raise ValueError('selected root/relationship scopes exceed the native16-scope profile')
    policy = config.get('durable_service_policy')
    if policy is not None and (policy.get('generation', 0) < 1 or
            not 1 <= policy.get('attempts', 0) <= 256 or
            not 1 <= policy.get('quanta', 0) <= 1000000000 or
            policy.get('time_basis') != 'admitted-work-quanta'):
        raise ValueError('invalid explicit durable operator service policy')
    if policy is not None and (type(policy.get('automatic_resume')) is not bool or
            type(policy.get('automatic_scope_renewal', False)) is not bool or
            (policy.get('automatic_scope_renewal', False) and not policy['automatic_resume'])):
        raise ValueError('scope renewal requires explicit automatic-resume authority')
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
    selection = (indexed_item if args.indexed else archive)(
        args.archive_slot, args.namespace, args.manifest_sha256, args.bytes)
    return write_config(args.config, dict(schema=1, role='library-seed', **approved,
        server_store=str(args.store.resolve()), archives=[] if args.indexed else [selection],
        indexed_items=[selection] if args.indexed else [],
        relationships=[relationship(args.connection_slot, args.credentials, args.description, args.budget, args.lifetime)],
        storage_policy='explicit purpose2 operator namespaces; intentional plaintext; no personal vault',
        service_policy='zero-price selected immutable roots; direct encrypted bulk only',
        durable_service_policy=dict(generation=1, attempts=32, quanta=1000000,
            automatic_resume=True, automatic_scope_renewal=args.renew_scopes,
            time_basis='admitted-work-quanta'),
        restored_authority='none; fresh namespace and authenticated stream grants on every run'))


def service_selection(client, config, relation, selected, instance):
    policy = config.get('durable_service_policy')
    if policy is None:
        raise ValueError('legacy configuration needs explicit provision-policy before recoverable serving')
    _, material = network.load_credentials(Path(relation['credentials']))
    requester = material[:32]
    root = bytes.fromhex(selected['manifest_sha256'])
    namespace = bytes.fromhex(selected['namespace'])
    descriptor = material[64:96]
    # These identifiers are scoped to the selected relationship and namespace.
    # The guest compares the complete canonical request on duplicate operation.
    policy_id = hashlib.sha256(b'LT-OperatorPolicy-v1\0' + namespace + requester).digest()
    operation = hashlib.sha256(b'LT-RetrievalOperation-v1\0' + policy_id + root +
                              struct.pack('<Q', policy['generation'])).digest()
    slot = 16  # Native bounded allocator, or existing scoped operation on retry.
    canonical = service_jobs.terms(operation.hex(), requester.hex(), root.hex(),
        policy_id.hex(), 'retrieval', policy['generation'], relation['budget'],
        policy['attempts'], policy['quanta'], descriptor.hex(), policy['automatic_resume'])
    slot = service_jobs.submit(client, slot, canonical)
    state = service_jobs.inspect(client, slot)
    if state['state'] in ('paused', 'cancelled', 'complete', 'failed', 'exhausted'):
        return slot, False
    if state['state'] == 'awaiting-fresh-authority' and not policy['automatic_resume']:
        return slot, False
    fields, _ = service_jobs.call(client, 282, slot, instance, allow=(4, 6))
    if fields[0]:
        return slot, False
    return slot, True


def indexed_open(client, owner, selected, recipient):
    def call(op, h=0, a=0, b=0, c=0, d=0, data=b''):
        raw = client.request(op, struct.pack('<8Q', op, h, a, b, c, d, 0, 1) + data)
        if len(raw) < 64 or struct.unpack_from('<Q', raw)[0]:
            raise ValueError(f'indexed server item op{op} rejected')
        return struct.unpack_from('<8Q', raw), raw[64:]
    fields, _ = call(260, 2, selected['slot'], selected['bytes'], owner, 3,
                     bytes.fromhex(selected['namespace']) + bytes.fromhex(selected['manifest_sha256']))
    permit = fields[1]
    fields, binding = call(261, 2, selected['slot'], data=bytes.fromhex(selected['namespace']))
    if fields[2] != 2 or hashlib.sha256(binding[:256]).hexdigest() != selected['manifest_sha256']:
        raise ValueError('indexed item is not complete or differs from the configured immutable root')
    fields, _ = call(262, permit, recipient, time.time_ns() & 0x7fffffffffffffff)
    return dict(content_handle=fields[1], slot=selected['slot'],
                manifest_sha256=selected['manifest_sha256'],
                storage='indexed-purpose2', whole_payload_rehydrated=False)


def recover_selected(client, config, instance):
    # Launcher is the explicitly authorized operator bootstrap caller. The
    # recovered read grants belong directly to the native serving incarnation.
    owner = struct.unpack_from('<Q', client.request(2), 32)[0]
    service_jobs.call(client, 280)
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
    for selected in config.get('indexed_items', []):
        results.append(indexed_open(client, owner, selected, instance))
    for relation in config['relationships']:
        slot = relation['slot']
        network.configure(client, Path(relation['credentials']), Path(relation['description']), slot)
        network.call(client, 13, slot=slot)
        _, material = network.load_credentials(Path(relation['credentials']))
        for result in results:
            selections = config.get('indexed_items', []) if result.get('storage') == 'indexed-purpose2' else config['archives']
            selected = next(a for a in selections if a['slot'] == result['slot'] and
                            a['manifest_sha256'] == result['manifest_sha256'])
            durable_slot, permitted = service_selection(client, config, relation, selected, instance)
            if not permitted:
                continue
            root = bytes.fromhex(result['manifest_sha256'])
            stream = int.from_bytes(root[:8], 'little') | 1
            fields, _ = library_peer.call(client, instance, 400, slot, 2, stream, result['content_handle'],
                relation['budget'], relation['lifetime'], material[:32] + material[64:96] + root)
            library_peer.call(client, instance, 403, fields[1], durable_slot)
            if config['durable_service_policy'].get('automatic_scope_renewal', False):
                library_peer.call(client, instance, 404, fields[1], relation['lifetime'])
    return results


def inspect(client, config, instance):
    service_jobs.call(client, 280)
    return dict(instance=instance, release_id=config['release_id'],
        archives=config['archives'],
        indexed_items=config.get('indexed_items', []),
        relationships=[network.status(client, r['slot']) for r in config['relationships']],
        scopes=[dict(scope=i, state=f[2], active=f[2] == 1, waiting_for_authentication=f[2] == 2, role=f[3], send_pending=bool(f[4]),
                     response_bytes=f[5], snapshot_id=f[6], last_error=f[7])
                for i in range(16) for f, _ in [library_peer.call(client, instance, 401, i)]],
        backing=config['server_store'], live_handles_persisted=False,
        durable_service_policy=config.get('durable_service_policy'),
        durable_jobs=[r for i in range(16) if (r := service_jobs.inspect(client, i, by_index=True))],
        limits='16 selected root/relationship scopes; legacy archives share6029312 volatile bytes; indexed items read nonresident ranges')


def control(client, config, instance, action):
    service_jobs.call(client, 280)
    policy_ids = set()
    for relation in config['relationships']:
        _, material = network.load_credentials(Path(relation['credentials']))
        for selected in config.get('archives', []) + config.get('indexed_items', []):
            policy_ids.add(hashlib.sha256(b'LT-OperatorPolicy-v1\0' +
                bytes.fromhex(selected['namespace']) + material[:32]).hexdigest())
    selected_slots = {record['slot'] for i in range(16) if (record := service_jobs.inspect(client, i, by_index=True)) and
                      record['policy'] in policy_ids}
    for slot in sorted(selected_slots):
        state = service_jobs.inspect(client, slot)
        if state is None:
            continue
        if state['state'] in ('complete', 'cancelled', 'failed', 'exhausted'):
            continue
        service_jobs.call(client, dict(pause=286, drain=286, cancel=288, resume=289)[action], slot)
        if action == 'resume':
            service_jobs.call(client, 282, slot, instance)
    if action == 'cancel':
        for relation in config['relationships']:
            library_peer.call(client, instance, 402, relation['slot'])
    return dict(action=action, jobs=[r for slot in sorted(selected_slots)
                if (r := service_jobs.inspect(client, slot))],
                semantics='already reserved transmissions may finish; later payload requests require an active durable job')


def run(args, config):
    if args.socket.exists():
        raise ValueError('socket already exists; refusing to attach to or stop another guest')
    raw = validate(config)
    if config.get('durable_service_policy') is None:
        raise ValueError('run requires explicit provision-policy for this legacy configuration')
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
    if kind in ('archive', 'indexed'):
        parser.add_argument('--archive-slot', type=int, choices=range(16 if kind == 'indexed' else 4), required=True)
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
    import sys
    selected = list(sys.argv[1:] if argv is None else argv)
    if selected and selected[0] == 'acquire':
        import library_replication
        return library_replication.main(selected[1:])
    if selected and selected[0] == 'acquire-init':
        import library_replication
        return library_replication.main(['init', *selected[1:]])
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    command = commands.add_parser('init')
    command.add_argument('config', type=Path)
    command.add_argument('--package', type=Path, required=True)
    command.add_argument('--public', type=Path, required=True)
    command.add_argument('--release-id', required=True)
    command.add_argument('--store', type=Path, required=True)
    command.add_argument('--indexed', action='store_true', help='open an existing purpose2 indexed retained item without payload rehydration')
    command.add_argument('--renew-scopes', action='store_true', help='explicitly authorize live serving-scope renewal within remaining durable work and byte budgets')
    add_selection_options(command, 'indexed')
    add_selection_options(command, 'relationship')
    for name, kind in [('add-archive', 'archive'), ('add-indexed', 'indexed'), ('add-relationship', 'relationship')]:
        command = commands.add_parser(name)
        command.add_argument('config', type=Path)
        add_selection_options(command, kind)
    command = commands.add_parser('provision-policy')
    command.add_argument('config', type=Path)
    command.add_argument('--generation', type=int, default=1)
    command.add_argument('--attempts', type=int, default=32)
    command.add_argument('--quanta', type=int, default=1000000)
    command.add_argument('--await-approval-after-restart', action='store_true')
    command.add_argument('--renew-scopes', action='store_true', help='explicit live-scope renewal within the retained finite policy')
    command = commands.add_parser('run')
    command.add_argument('config', type=Path)
    command.add_argument('--socket', type=Path, required=True)
    command.add_argument('--backend', choices=('qemu', 'x86_64', 'aarch64'), default='qemu')
    command.add_argument('--image', type=Path)
    for name in ('recover', 'inspect', 'pause', 'drain', 'cancel', 'resume'):
        command = commands.add_parser(name)
        command.add_argument('config', type=Path)
        command.add_argument('--socket', type=Path, required=True)
        command.add_argument('--instance', type=int, required=True)
    command = commands.add_parser('stop')
    command.add_argument('--socket', type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == 'init':
        result = initialize(args)
    elif args.command == 'provision-policy':
        config = json.loads(args.config.read_text())
        config['durable_service_policy'] = dict(generation=args.generation,
            attempts=args.attempts, quanta=args.quanta,
            automatic_resume=not args.await_approval_after_restart,
            automatic_scope_renewal=args.renew_scopes,
            time_basis='admitted-work-quanta')
        result = write_config(args.config, config, replace=True)
    elif args.command.startswith('add-'):
        config = json.loads(args.config.read_text())
        if args.command == 'add-indexed':
            config.setdefault('indexed_items', []).append(indexed_item(
                args.archive_slot, args.namespace, args.manifest_sha256, args.bytes))
        elif args.command == 'add-archive':
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
            if args.command == 'inspect':
                result = inspect(client, config, args.instance)
            elif args.command == 'recover':
                result = recover_selected(client, config, args.instance)
            else:
                result = control(client, config, args.instance, args.command)
        finally:
            client.close()
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
