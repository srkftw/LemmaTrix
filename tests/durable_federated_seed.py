"""Recover durable seed content, publish it, then discover and fetch after restart.

The publisher and first seed remain absent. No project fixture is imported into
any participant: the existing second seed recovers its own attached backing,
the registry receives the selected graph over Noise, and the fresh reader gets
signed metadata and source from independently restarted guest roles.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'tools'), str(ROOT / 'tests')]
import capsule
import federation
import forge
import live
import network
import nodes
import projects
import releases
import server_store
from creator_journey import rendered_text
from durable_signed_releases import Seed
from federation_forge import admission, install_registry
from federation_node import HeadlessRegistryNode
from forge_journey import wait
from forge_replication import authenticate
from graphical_devices import DeviceInput
from native_release_update import actual_score
from signed_forge_journey import ClientNode

EXPECTED_ROOT = 'bb6032251e098fe6268e8b3afb60be75c36b0a0a52dd9fef8763250b7489ac12'
SEED_NAMESPACE = 'f29bfe82756161f6244cf872cc6852e3eeab7b504efe7e803f75ec01aeedde9f'


class ExistingProcess:
    """Own already started test guests after loss of the harness parent only."""
    def __init__(self, pid, portal):
        self.pid = pid
        assert str(portal).encode() in Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')

    def poll(self):
        try:
            state = Path(f'/proc/{self.pid}/stat').read_text().split(') ', 1)[1].split()[0]
            return 0 if state == 'Z' else None
        except FileNotFoundError:
            return 0

    def wait(self, timeout=12):
        return wait(lambda: self.poll() is not None, 'existing test guest exits after normal stop', timeout) and 0


def attach_publication(path, pid, registry=False):
    node = (HeadlessRegistryNode if registry else Seed).__new__(HeadlessRegistryNode if registry else Seed)
    node.path, node.sock = path, path / 'portal.sock'
    process = ExistingProcess(pid, node.sock)
    node.log = (path / 'guest.log').open('ab')
    node.ui = None if registry else DeviceInput('qemu', path / 'display.qmp')
    if registry:
        node.proc, node.config = process, path / 'node.json'
    else:
        node.proc, node.qmp = process, path / 'display.qmp'
    client = node.client()
    try:
        raw = client.request(2)
        active = [struct.unpack_from('<4Q', raw, offset) for offset in range(0, len(raw), 32)]
        active = [row for row in active if 7 <= row[0] & 255 < 12 and 0 < row[1] < 5]
        assert [row[2] for row in active] == ([1151, 2175] if registry else [3967, 2175])
        node.instance = active[0][0]
        if registry:
            node.registry_instance = active[1][0]
    finally:
        client.close()
    return node


def endpoint():
    probe = socket.socket()
    probe.bind(('127.0.0.1', 0))
    value = f'127.0.0.1:{probe.getsockname()[1]}'
    probe.close()
    return value


def relationship(path, client_id, server_key, address, image_id, kind):
    path.mkdir()
    description = path / 'service.public'
    public = network.create_description(server_key, client_id, address, kind, description, image_id)
    client, server = path / 'client.credential', path / 'server.credential'
    network.provision(client, server, client_id, bytes.fromhex(public['server_id']),
                      bytes.fromhex(public['service_id']))
    return dict(client=client, server=server, description=description,
                client_id=client_id.hex(), server_id=public['server_id'], service_id=public['service_id'])


def bootstrap(binary, rights, key, path, name='native-forge'):
    raw, manifest = releases.make(binary, name, '0.4.6', rights, key, profile=2,
        sources=[ROOT / 'Guest/Forge.lean', ROOT / 'Guest/ForgeFederation.lean'], source_base=ROOT)
    path.write_bytes(raw)
    Path(str(path) + '.manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return path


def start_registry(path, backing, namespace, address, relation, headless_package,
                   registry_package, public, federation_public, image, recover=False):
    path.mkdir()
    server = HeadlessRegistryNode.__new__(HeadlessRegistryNode)
    server.path, server.sock = path, path / 'portal.sock'
    server.ui = server.proc = server.log = None
    server.config = path / 'node.json'
    primary, secondary = map(lambda package: releases.inspect(package.read_bytes()),
                             (headless_package, registry_package))
    assert primary['rights'] == 1151 and secondary['rights'] == 2175
    command = [str(ROOT / 'lt'), 'node', 'init', str(server.config), '--role', 'registry',
        '--package', str(headless_package), '--public', str(public),
        '--release-id', primary['release_id'], '--rights', '1151',
        '--credentials', str(relation['server']), '--description', str(relation['description']),
        '--store', str(backing), '--namespace', namespace, '--bytes', '1048576',
        '--endpoint', address, '--listen', '--registry-package', str(registry_package),
        '--registry-public', str(public), '--registry-release-id', secondary['release_id'],
        '--registry-rights', '2175', '--federation-public', str(federation_public),
        '--federation-policy', 'portable']
    initialized = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=True)
    (path / 'initialized.json').write_text(initialized.stdout)
    server.log = (path / 'guest.log').open('wb')
    run = [str(ROOT / 'lt'), 'node', 'run', str(server.config), '--socket', str(server.sock),
           '--image', str(image)]
    if recover:
        run.append('--recover-catalog')
    server.proc = subprocess.Popen(run, cwd=ROOT, stdout=server.log,
        stderr=subprocess.STDOUT, start_new_session=True)
    try:
        def ready():
            text = (path / 'guest.log').read_text()
            if server.proc.poll() is not None:
                raise AssertionError(('ordinary Registry startup failed', server.proc.returncode, text))
            return '"headless": true' in text
        wait(ready, 'ordinary isolated Registry startup with selected own backing', 180)
        client = server.client()
        try:
            raw = client.request(2)
            active = [struct.unpack_from('<4Q', raw, offset) for offset in range(0, len(raw), 32)]
            active = [row for row in active if 7 <= row[0] & 255 < 12 and 0 < row[1] < 5]
            assert [row[2] for row in active] == [1151, 2175], active
            server.instance, server.registry_instance = active[0][0], active[1][0]
            assert network.status(client)['public_service_description_verified']
            assert not projects.roots(client)
            server.startup_catalog = nodes.catalog(client, server.registry_instance)
        finally:
            client.close()
        return server
    except BaseException:
        server.stop()
        raise


def start_seed(path, backing, address, relation, package, public, listen=False):
    seed = Seed(path, address, listen, backing)
    try:
        seed.install(package, public)
        client = seed.client()
        try:
            network.configure(client, relation['server' if listen else 'client'], relation['description'])
            server_store.call(client, 230)
            forge.configure(client, seed.instance, relation['server' if listen else 'client'], 'seed')
            assert network.status(client)['public_service_description_verified']
            assert not projects.roots(client)
        finally:
            client.close()
        return seed
    except BaseException:
        seed.stop()
        raise


def exact_graph(node, root, archive):
    client = node.client()
    try:
        assert projects.project_identity(client, root) == archive['project_id']
        actual, cursor = {}, 0
        while True:
            fields, identities = client.objects(26, root, cursor)
            if not fields[1]:
                break
            actual[identities[:32].hex()] = (fields[4], fields[5], identities[32:64].hex(),
                                           client.read_object(fields[1], True))
            cursor = fields[3]
        expected = {record['id']: (record['kind'], record['schema'], record['parent'],
                                  base64.b64decode(record['payload'], validate=True))
                    for record in archive['nodes']}
        assert actual == expected, 'actual canonical closure differs from already signed selected public graph'
        return dict(records=len(actual), payload_bytes=sum(len(value[3]) for value in actual.values()))
    finally:
        client.close()


def broker_handles(node):
    client = node.client()
    try:
        raw = client.request(150, struct.pack('<Q', node.instance) + struct.pack('<8Q', 2, 0, 0, 0, 0, 0, 0, 1))
        assert len(raw) == 320 and struct.unpack_from('<Q', raw)[0] == 0
        return dict(metadata=struct.unpack_from('<Q', raw, 72)[0], content=struct.unpack_from('<Q', raw, 80)[0])
    finally:
        client.close()


def displayed_peer(node, expected):
    def shown():
        frame = node.ui.frame()
        values = [rendered_text(frame, x, 128, 16, 0xd8e6ed) for x in (140, 240, 340, 440)]
        if any(len(value) != 16 or any(c not in '0123456789abcdef' for c in value) for value in values):
            return None
        actual = b''.join(int(value, 16).to_bytes(8, 'little') for value in values).hex()
        return frame if actual == expected else None
    return wait(shown, 'actual native overview displays selected full peer identity', 120)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--gui-binary', type=Path, required=True)
    parser.add_argument('--server-binary', type=Path, required=True)
    parser.add_argument('--seed-store', type=Path, default=ROOT / 'build/durable-signed-four-node/seed2.img')
    parser.add_argument('--seed-namespace', default=SEED_NAMESPACE)
    parser.add_argument('--seed-network-key', type=Path, default=ROOT / 'build/durable-signed-four-node/network-role-2.pem')
    parser.add_argument('--publisher-public', type=Path, default=ROOT / 'build/signed-native-fork-journey-4/fork-publisher.pub')
    parser.add_argument('--expected-graph', type=Path, default=ROOT / 'build/native-release-update-3/published-closure.json')
    parser.add_argument('--registry-package', type=Path, default=ROOT / 'build/federation-wire/native-registry.ltrel')
    parser.add_argument('--operator-key', type=Path, default=ROOT / 'build/federation-wire/operator.pem')
    parser.add_argument('--operator-public', type=Path, default=ROOT / 'build/federation-wire/operator.pub')
    parser.add_argument('--resume-publication', action='store_true',
                        help='reattach own still-running publication guests after harness-parent loss')
    parser.add_argument('--registry-pid', type=int)
    parser.add_argument('--seed-pid', type=int)
    args = parser.parse_args()
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=args.resume_publication)
    if args.resume_publication and not (args.registry_pid and args.seed_pid):
        parser.error('resume requires explicit existing own Registry and Seed process IDs')
    args.image, args.seed_store = args.image.resolve(), args.seed_store.resolve()
    os.environ['LT_GUEST_IMAGE'] = str(args.image)
    image_id = hashlib.sha256(args.image.read_bytes()).digest()
    before_seed = hashlib.sha256(args.seed_store.read_bytes()).hexdigest()
    archive = json.loads(args.expected_graph.read_text())
    assert archive['selected'][0]['head'] == EXPECTED_ROOT
    publisher = releases.public_modulus(args.publisher_public)
    publication = releases.publication(archive['project_id'], hashlib.sha256(publisher).hexdigest())
    seed_package, reader_package, headless_package = [args.output / name for name in
                                                     ('seed.ltrel', 'reader.ltrel', 'headless.ltrel')]
    if not args.resume_publication:
        bootstrap(args.gui_binary, 3967, args.operator_key, seed_package)
        bootstrap(args.gui_binary, 1919, args.operator_key, reader_package)
        bootstrap(args.server_binary, 1151, args.operator_key, headless_package, 'forge-server')
    assert releases.inspect(args.registry_package.read_bytes())['publisher_key_id'] == \
        hashlib.sha256(releases.public_modulus(args.operator_public)).hexdigest()
    federation_key, federation_public = args.output / 'federation.pem', args.output / 'federation.pub'
    registry_key, registry_public = args.output / 'registry-network.pem', args.output / 'registry-network.pub'
    reader_key, reader_public = args.output / 'reader-network.pem', args.output / 'reader-network.pub'
    for private, public in ((federation_key, federation_public), (registry_key, registry_public), (reader_key, reader_public)):
        if not args.resume_publication:
            capsule.generate_key(private, public)
        else:
            assert private.is_file() and public.is_file()
    seed_id = hashlib.sha256(capsule.modulus(args.seed_network_key)).digest()
    reader_id = hashlib.sha256(releases.public_modulus(reader_public)).digest()
    registry_store = args.output / 'registry.img'
    if args.resume_publication:
        original_config = json.loads((args.output / 'registry-initial/node.json').read_text())
        registry_namespace = original_config['namespace']
        assert Path(original_config['server_store']) == registry_store
    else:
        server_store.provision(registry_store)
        registry_namespace = os.getrandom(32).hex()
    checks, running = [], []

    def passed(label, **facts):
        checks.append(dict(check=label, status='passed', **facts))
        report = dict(image=image_id.hex(), protocol='Forge1 + signed admission1; explicit independent peer reauthorization',
            root=EXPECTED_ROOT, logical_project=archive['project_id'], original_publisher_absent=True,
            first_seed_absent=True, project_compiler_executions=0, project_release_signatures_created=0,
            seed_backing=str(args.seed_store), seed_namespace=args.seed_namespace,
            bootstrap_packages={name: releases.inspect(path.read_bytes())['release_id'] for name, path in
                                [('seed', seed_package), ('reader', reader_package), ('headless', headless_package)]},
            environment='Independently restarted QEMU guests and own backing on one Linux development host', checks=checks)
        if args.resume_publication:
            report['harness_continuation'] = ('Initial harness parent exited unexpectedly after physical F9/F11 and '
                'completed network source ingestion, before signing; the same live guests were reattached through '
                'public SDK/QMP. No guest-memory patch, project replay or backing copy was used. Seed hash '
                'comparison starts at this explicit harness continuation.')
        (args.output / 'evidence.json').write_text(json.dumps(report, indent=2) + '\n')
        print('PASS', label, flush=True)

    def stop(node):
        node.stop()
        running.remove(node)

    try:
        if args.resume_publication:
            registry = attach_publication(args.output / 'registry-initial', args.registry_pid, True)
            running.append(registry)
            seed = attach_publication(args.output / 'seed2-publication', args.seed_pid)
            running.append(seed)
            preview = seed.archive()
            assert preview['phase'] == 8 and preview['head'] == EXPECTED_ROOT
            assert seed.inspect()['last_native_key'] == 87 and seed.inspect()['status'] == 10
        else:
            publish_endpoint = endpoint()
            publish_relation = relationship(args.output / 'seed-registry-relationship', seed_id, registry_key,
                                            publish_endpoint, image_id, 'registry')
            registry = start_registry(args.output / 'registry-initial', registry_store, registry_namespace,
                publish_endpoint, publish_relation, headless_package, args.registry_package,
                args.operator_public, federation_public, args.image)
            running.append(registry)
            seed = start_seed(args.output / 'seed2-publication', args.seed_store, publish_endpoint,
                              publish_relation, seed_package, args.operator_public)
            running.append(seed)
            authenticate(seed, registry)
            install_registry(seed, args.registry_package, args.operator_public, federation_public, 'portable')
            preview = seed.recover(bytes.fromhex(args.seed_namespace), EXPECTED_ROOT)
        source = next(root for root in seed.roots() if root['head'] == EXPECTED_ROOT)
        source_facts = exact_graph(seed, source['cap'], archive)
        assert source_facts == dict(records=17, payload_bytes=130344)
        if not args.resume_publication:
            assert not registry.roots(), 'Registry graph was preloaded before native publication'
            client = registry.client()
            try:
                federation.call(client, registry.registry_instance, 3, data=publication + publisher)
            finally:
                client.close()
            seed.ui.press(87)
        pending = wait(lambda: (record if (record := admission(registry, True))['local_phase'] == 1
                                and record['descriptor']['root'] == EXPECTED_ROOT else None),
                       'physical F11 sends recovered source and isolated Registry evaluates it', 300)
        assert pending['descriptor']['classification'] == 2
        received = next(root for root in registry.roots() if root['head'] == EXPECTED_ROOT)
        assert exact_graph(registry, received['cap'], archive) == source_facts
        client = registry.client()
        try:
            signed = federation.sign_once(client, registry.registry_instance, federation_key, 'portable')
        finally:
            client.close()
        assert signed['root'] == EXPECTED_ROOT and signed['listing'] == 2
        receipt = wait(lambda: (record if (record := admission(seed))['remote_phase'] == 2
                                and record['descriptor']['root'] == EXPECTED_ROOT else None),
                       'original federation signature returns to native publication surface', 180)
        (seed.path / 'signed-publication.ppm').write_bytes(seed.ui.frame().ppm())
        passed('own seed2 recovery publishes the exact signed generation through native F11 to a new isolated federation',
               preview=preview, graph=source_facts, signed=signed, receipt=receipt,
               seed_backing_unchanged=hashlib.sha256(args.seed_store.read_bytes()).hexdigest() == before_seed)
        stop(seed)
        stop(registry)
        committed_catalog = hashlib.sha256(registry_store.read_bytes()).hexdigest()

        discovery_endpoint = endpoint()
        discovery_relation = relationship(args.output / 'reader-registry-relationship', reader_id, registry_key,
                                          discovery_endpoint, image_id, 'registry')
        registry = start_registry(args.output / 'registry-restarted', registry_store, registry_namespace,
            discovery_endpoint, discovery_relation, headless_package, args.registry_package,
            args.operator_public, federation_public, args.image, recover=True)
        running.append(registry)
        assert len(registry.startup_catalog['entries']) == 1 and not registry.roots()
        reader = ClientNode(args.output / 'reader', discovery_endpoint)
        running.append(reader)
        client = reader.client()
        try:
            network.configure(client, discovery_relation['client'], discovery_relation['description'])
        finally:
            client.close()
        authenticate(reader, registry)
        reader.install(reader_package, args.operator_public)
        client = reader.client()
        try:
            forge.configure(client, reader.instance, discovery_relation['client'])
        finally:
            client.close()
        verifier_instance = install_registry(reader, args.registry_package, args.operator_public,
                                             federation_public, 'portable')
        reader.ui.press(61)
        catalog_record = wait(lambda: (record if (record := admission(reader))['remote_phase'] == 2
                                       and record['descriptor']['root'] == EXPECTED_ROOT else None),
                              'fresh native reader discovers and verifies own recovered catalog', 180)
        metadata = reader.inspect()
        assert metadata['metadata_nodes'] == metadata['metadata_bytes'] == 0
        assert not reader.roots() and not registry.roots()
        reader.ui.press(63)
        wait(lambda: reader.inspect()['status'] == 15, 'metadata-only discovery refuses unavailable content')
        reader.ui.press(59)
        (reader.path / 'registry-peer.ppm').write_bytes(displayed_peer(reader, discovery_relation['server_id']).ppm())
        old_handles = broker_handles(reader)
        passed('restarted Registry serves signed metadata only; fresh reader chooses content without importing or executing',
               record=catalog_record, metadata=metadata, graph_roots=0, fetch_denied_status=15,
               peer=discovery_relation['server_id'], service=discovery_relation['service_id'],
               local_handles=old_handles, verifier_instance=verifier_instance)
        stop(registry)
        assert hashlib.sha256(registry_store.read_bytes()).hexdigest() == committed_catalog

        # The same explicit numeric transport endpoint is now operated by the
        # independently identified seed. Its new description/PSK/service pins
        # are checked in the guest; the opaque relay never interprets a graph.
        seed_relation = relationship(args.output / 'reader-seed2-relationship', reader_id, args.seed_network_key,
                                     discovery_endpoint, image_id, 'forge')
        assert seed_relation['server_id'] != discovery_relation['server_id']
        assert seed_relation['service_id'] != discovery_relation['service_id']
        seed = start_seed(args.output / 'seed2-restarted', args.seed_store, discovery_endpoint,
                          seed_relation, seed_package, args.operator_public, True)
        running.append(seed)
        assert not seed.roots() and not admission(seed)['required']
        preview = seed.recover(bytes.fromhex(args.seed_namespace), EXPECTED_ROOT)
        assert not admission(seed)['descriptor']['signature_present'], 'seed boot replayed an admission from host memory'
        client = reader.client()
        try:
            network.configure(client, seed_relation['client'], seed_relation['description'])
            forge.configure(client, reader.instance, seed_relation['client'])
            assert network.status(client)['public_service_description_verified']
            # The verifier compartment, chosen federation and signed decision
            # remain local public knowledge. No old peer grants are restored.
            table = client.request(2)
            assert any(struct.unpack_from('<4Q', table, offset)[0] == verifier_instance and
                       struct.unpack_from('<4Q', table, offset)[2] == 2175
                       for offset in range(0, len(table), 32)), 'selected local verifier was replaced'
        finally:
            client.close()
        authenticate(reader, seed)
        reader.ui.press(61)
        available = wait(lambda: (state if (state := reader.inspect())['metadata_nodes'] == 17 else None),
                         'native discovery obtains actual seed availability', 180)
        reverified = wait(lambda: (record if (record := admission(reader))['remote_phase'] == 2
                                   and record['descriptor']['root'] == EXPECTED_ROOT else None),
                          'same-root public admission reverified after explicit fresh peer enrollment', 180)
        assert reverified['descriptor'] == catalog_record['descriptor']
        assert not reader.roots()
        # Incoming metadata may show admission details; physical F1 returns to
        # the overview before comparing the actual newly selected peer pins.
        if rendered_text(reader.ui.frame(), 10, 56, 34, 0x9fc6a5).rstrip() == 'FEDERATION ADMISSION / F1 RETURN':
            reader.ui.press(59)
        (reader.path / 'seed-peer.ppm').write_bytes(displayed_peer(reader, seed_relation['server_id']).ppm())
        new_handles = broker_handles(reader)
        assert old_handles['metadata'] != new_handles['metadata'], 'fresh enrollment reused the old operational handle'
        reader.ui.press(63)
        def fetched():
            state = reader.inspect()
            if state['status'] == 9:
                raise AssertionError(('combined seed graph transfer rejected', state, seed.inspect()))
            return state if state['status'] == 11 and not state['import_transaction'] else None
        completed = wait(fetched, 'actual chosen-federation-authorized source retrieved from restarted seed2', 300)
        root = next(root for root in reader.roots() if root['head'] == EXPECTED_ROOT)
        assert exact_graph(reader, root['cap'], archive) == source_facts
        wait(lambda: seed.inspect()['status'] == 10, 'validated seed content completion receipt', 120)
        passed('fresh seed2 session revalidates portable admission and fetches its own retained signed closure',
               preview=preview, graph=source_facts, metadata=available, reverified=reverified,
               before_peer=discovery_relation['server_id'], after_peer=seed_relation['server_id'],
               before_service=discovery_relation['service_id'], after_service=seed_relation['service_id'],
               old_handles=old_handles, fresh_handles=new_handles, complete=completed,
               selected_federation_unchanged=True, no_admission_replayed_into_seed=True)
        client = reader.client()
        try:
            client.request(10, publication + publisher)
        finally:
            client.close()
        reader.ui.press(64)
        wait(lambda: rendered_text(reader.ui.frame(), 16, 12, 24) == 'SIGNED PACKAGE CANDIDATE',
             'actual fetched publisher signature and native authority inspected', 180)
        frame = reader.ui.frame()
        assert rendered_text(frame, 136, 110, 4) == '0300'
        (reader.path / 'native-release-approval.ppm').write_bytes(frame.ppm())
        time.sleep(.3)
        reader.ui.press(28)
        wait(lambda: actual_score(reader) == '00000000', 'explicitly approved retained native generation starts', 120)
        reader.ui.textASCII('cat123', delay=.08)
        wait(lambda: actual_score(reader) == '00000020', 'retained generation consumes supplied native input', 120)
        client = reader.client()
        try:
            active = client.request(29, publication)
            assert active[160:192].hex() == catalog_record['descriptor']['release_id']
        finally:
            client.close()
        (reader.path / 'native-input.ppm').write_bytes(reader.ui.frame().ppm())
        assert hashlib.sha256(args.seed_store.read_bytes()).hexdigest() == before_seed
        assert hashlib.sha256(registry_store.read_bytes()).hexdigest() == committed_catalog
        passed('publisher and seed1 absent; native signed generation runs after durable federation and content recovery',
               release=catalog_record['descriptor']['release_id'], publication=publication.hex(),
               approved_rights=768, input='cat123', score='00000020', seed_store_unchanged=True,
               registry_store_unchanged=True, execution_approved_by_physical_input=True)
    except BaseException:
        for node in running:
            try:
                (node.path / 'failure-state.json').write_text(json.dumps(dict(
                    forge=node.inspect(), federation=admission(node), roots=node.roots()), indent=2))
                if node.ui:
                    (node.path / 'failure.ppm').write_bytes(node.ui.frame().ppm())
            except BaseException:
                pass
        raise
    finally:
        for node in reversed(running):
            try:
                node.stop()
            except BaseException:
                pass


if __name__ == '__main__':
    main()
