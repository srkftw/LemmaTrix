"""Explicit operator bootstrap for the normal native Library acquisition jobs.

The guest owns scheduling, durable attempts/resources, verified checkpoints and
publication. This adapter creates fresh handles from a selected configuration;
it neither polls chunks nor decides matches, providers or retry progress.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import federation
import inventory
import library
import live
import network
import nodes
import releases
import service_jobs

ROOT = Path(__file__).resolve().parents[1]


def validate(config):
    if config.get('schema') != 1 or config.get('role') != 'library-acquirer':
        raise ValueError('explicit library-acquirer schema1 configuration required')
    if config['acquirer']['rights'] != 3199 or config['registry']['rights'] != 2175:
        raise ValueError('exact native operator3199 and registry2175 approvals required')
    raw = nodes.validate_package(config['acquirer'])
    nodes.validate_package(config['registry'])
    modulus = releases.public_modulus(Path(config['federation_public']))
    if hashlib.sha256(modulus).hexdigest() != config['federation']:
        raise ValueError('selected federation key differs from configured identity')
    if not Path(config['server_store']).is_file():
        raise ValueError('explicit purpose2 backing required')
    selections = config['selections']
    if not 1 <= len(selections) <= 8 or len({x['collection'] for x in selections}) != len(selections):
        raise ValueError('select1..8 distinct collections, one exact retained target per collection')
    if len({x['slot'] for x in selections}) != len(selections):
        raise ValueError('independent target slots required')
    for item in selections:
        for key in ('collection', 'namespace', 'manifest'):
            inventory.identity(item[key])
        if item['slot'] not in range(16) or not 0 < item['bytes'] <= 67108864:
            raise ValueError('indexed slot0..15 and selected content byte ceiling required')
        if item['policy_generation'] != 2 or not 1 <= item['attempts'] <= 256 or not 1 <= item['quanta'] <= 1000000000:
            raise ValueError('v1 supports explicit generation2 and bounded attempts/quanta')
        if not item['bytes'] <= item['request_budget'] <= 1073741824:
            raise ValueError('finite request-payload budget must cover the selected content')
    relations = config['relationships']
    if (len(relations) not in (2, 3) or len({r['slot'] for r in relations}) != len(relations) or
            {r['slot'] for r in relations} not in ({0, 1}, {0, 2}, {0, 1, 2})):
        raise ValueError('select Registry0 and one or both providers1/2')
    for relation in relations:
        role, material = network.load_credentials(Path(relation['credentials']))
        _, descriptor, _ = network.load_description(Path(relation['description']))
        if role != 1 or struct.unpack_from('<Q', descriptor, 16)[0] != (5 if relation['slot'] == 0 else 6):
            raise ValueError('selected signed Library client relationships required')
        if material[:96] != descriptor[64:128] + hashlib.sha256(descriptor).digest():
            raise ValueError('credentials differ from selected signed description')
    return raw


def restore_item(client, instance, permission, operation):
    selected = b''.join(inventory.call(client, 265, permission, offset, 512)[1]
                        for offset in (0, 512, 1024))
    fields, _ = inventory.open_item(client, permission, instance, operation)
    original = client.import_object(selected, kind=2)
    delegated = client.objects(6, original, instance, 25)[0][1]
    try:
        return library.call(client, instance, 724, delegated, fields[1], fields[6])[0][1]
    finally:
        client.objects(47, original)


def configure(client, config):
    validate(config)
    service_jobs.call(client, 280)
    verifier = nodes.start_package(client, config['registry'], nodes.validate_package(config['registry']))
    federation.configure(client, verifier, Path(config['federation_public']), 'consumer', allowed_rights=8191)
    for relation in config['relationships']:
        network.configure(client, Path(relation['credentials']), Path(relation['description']), slot=relation['slot'])
        network.call(client, 13, slot=relation['slot'])
    instance = nodes.start_package(client, config['acquirer'], nodes.validate_package(config['acquirer']))
    client.request(184, struct.pack('<Q', instance))
    provider_mask = sum(1 << r['slot'] for r in config['relationships'] if r['slot'])
    scopes = []
    for item in config['selections']:
        collection, namespace, root = (bytes.fromhex(item[k]) for k in ('collection', 'namespace', 'manifest'))
        policy = hashlib.sha256(b'LT-LibraryOperatorPolicy-v1\0' + collection + namespace + bytes.fromhex(config['federation'])).digest()
        operation = hashlib.sha256(b'LT-LibraryStorageOperation-v1\0' + policy + root + struct.pack('<Q', item['policy_generation'])).digest()
        principal = hashlib.sha256(b'LT-LibraryOperatorPrincipal-v1\0' + namespace + collection).digest()
        description = hashlib.sha256(b'LT-SelectedLocalStorage-v1\0' + policy + root).digest()
        terms = service_jobs.terms(operation.hex(), principal.hex(), item['manifest'], policy.hex(), 'storage',
            item['policy_generation'], item['request_budget'], item['attempts'], item['quanta'], description.hex(), True,
            expected=item['manifest'])
        slot = service_jobs.submit(client, 16, terms)
        current = service_jobs.inspect(client, slot)
        f, _ = library.call(client, instance, 720, 1, item['bytes'], provider_mask,
                            data=collection+bytes.fromhex(config['federation']), c=3, d=1)
        ci = f[1]
        permission = inventory.permit(client, 2, item['slot'], item['bytes'], instance, namespace, root)
        library.call(client, instance, 722, ci, permission)
        try:
            present, _ = inventory.call(client, 261, 2, item['slot'], data=namespace)
        except ValueError as error:
            if 'status6' not in str(error):
                raise
            present = None
        if present:
            # Metadata/open bootstrap is called by Launcher. The separate
            # Operator-owned permit above remains bound for actual writes.
            launcher = struct.unpack_from('<Q', client.request(2), 32)[0]
            bootstrap = inventory.permit(client, 2, item['slot'], item['bytes'], launcher, namespace, root)
            try:
                restore_item(client, instance, bootstrap, present[6] or 1)
            finally:
                inventory.call(client, 266, bootstrap)
        if current['state'] == 'complete':
            library.call(client, instance, 720, 3, data=collection+bytes.fromhex(config['federation']), c=3)
            library.call(client, instance, 720, 2, 0, data=collection+bytes.fromhex(config['federation']), c=3)
        elif current['state'] in ('queued', 'active', 'awaiting-fresh-authority'):
            service_jobs.call(client, 282, slot, instance)
            library.call(client, instance, 728, ci, slot, data=root+policy)
        else:
            library.call(client, instance, 720, 3, data=collection+bytes.fromhex(config['federation']), c=3)
        scopes.append(dict(collection_slot=ci, durable_job=slot, state=current['state'], recovered_checkpoint=present[3] if present else 0))
    library.call(client, instance, 700, data=bytes.fromhex(config['federation']))
    return dict(instance=instance, local_verifier=verifier, scopes=scopes, host_queue=False,
                native_runtime='LibraryOperator -> existing Library jobs -> ContentSDK/indexed backing',
                time_basis='finite admitted request bytes, work quanta and attempts; no absolute expiry')


def run(args, config):
    validate(config)
    if args.socket.exists():
        raise ValueError('socket exists; refusing to attach or stop another guest')
    image = Path(args.image or os.environ.get('LT_GUEST_IMAGE') or ROOT/'build/live/guest.bin').resolve()
    process = subprocess.Popen([str(ROOT/'lt'), 'run', '--backend', args.backend, '--socket', str(args.socket),
        '--image', str(image), '--server-store', config['server_store'], '--network-mux'], cwd=ROOT, start_new_session=True)
    client = None
    try:
        client = nodes.connect(args.socket, process)
        result = configure(client, config)
        result.update(image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(), socket=str(args.socket))
        print(json.dumps(result, indent=2), flush=True)
        client.close(); client = None
        return process.wait()
    except KeyboardInterrupt:
        return 130
    finally:
        if client:
            client.close()
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL); process.wait()


def main(argv=None):
    import sys
    selected = list(sys.argv[1:] if argv is None else argv)
    if selected and selected[0] == 'init':
        parser = argparse.ArgumentParser(description='Provision one explicitly selected native replication target')
        parser.add_argument('config', type=Path)
        for name in ('package', 'public', 'registry-package', 'federation-public', 'store',
                     'registry-credentials', 'registry-description', 'provider-credentials', 'provider-description'):
            parser.add_argument('--'+name, type=Path, required=True)
        for name in ('release-id', 'registry-release-id', 'collection', 'namespace', 'manifest'):
            parser.add_argument('--'+name, required=True)
        parser.add_argument('--bytes', type=int, required=True)
        parser.add_argument('--archive-slot', type=int, choices=range(16), default=0)
        parser.add_argument('--provider-slot', type=int, choices=(1, 2), default=1)
        parser.add_argument('--request-budget', type=int)
        parser.add_argument('--attempts', type=int, default=16)
        parser.add_argument('--quanta', type=int, default=65536)
        a = parser.parse_args(selected[1:])
        config = dict(schema=1, role='library-acquirer',
            acquirer=nodes.approved_package(a.package, a.public, a.release_id, 3199),
            registry=nodes.approved_package(a.registry_package, a.public, a.registry_release_id, 2175),
            federation_public=str(a.federation_public.resolve()),
            federation=hashlib.sha256(releases.public_modulus(a.federation_public)).hexdigest(),
            server_store=str(a.store.resolve()),
            relationships=[dict(slot=0, credentials=str(a.registry_credentials.resolve()), description=str(a.registry_description.resolve())),
                dict(slot=a.provider_slot, credentials=str(a.provider_credentials.resolve()), description=str(a.provider_description.resolve()))],
            selections=[dict(collection=a.collection, namespace=a.namespace, manifest=a.manifest,
                bytes=a.bytes, slot=a.archive_slot, policy_generation=2, attempts=a.attempts,
                quanta=a.quanta, request_budget=a.request_budget or min(a.bytes*2, 1073741824))],
            authority='explicit retained operator configuration; fresh native grants and finite durable resources on restart',
            storage='purpose2 intentional plaintext; no personal vault or implicit personal disk cache')
        validate(config)
        fd=os.open(a.config,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w',encoding='utf-8') as stream:
            json.dump(config,stream,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())
        print(json.dumps(dict(config=str(a.config),provisioned=True,role=config['role'],native_approval_required_on_every_new_process=True),indent=2))
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('config', type=Path)
    parser.add_argument('--socket', type=Path, required=True)
    parser.add_argument('--backend', choices=('qemu', 'x86_64', 'aarch64'), default='qemu')
    parser.add_argument('--image', type=Path)
    args = parser.parse_args(selected)
    return run(args, json.loads(args.config.read_text()))
