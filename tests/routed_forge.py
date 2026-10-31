"""Existing Forge/Registry metadata across three relays and inner terminal NK.

The public project is an existing signed exported graph. The terminal's native
Registry evaluates it; disclosed RSA bootstrap signs only that native decision.
The host never creates a catalog answer or owns any live node/circuit keys.
"""
import argparse, base64, hashlib, json, os, signal, socket, struct, subprocess, sys, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'tools'), str(ROOT/'tests')]
import capsule, federation, forge, identity, live, messenger, projects, releases
import onion_route as route

PUBLIC = ROOT/'tests/keys/development-rsa-public.pem'
PRIVATE = ROOT/'tests/keys/development-rsa.pem'

def raw_call(client, target, op, h=0, a=0, b=0, data=b''):
    raw = client.request(150, struct.pack('<Q8Q', target, op, h, a, b, 0, 0, 0, 1)+data)
    assert len(raw) >= 64, raw
    return struct.unpack_from('<8Q', raw), raw[64:]

def denied(client, registry, descriptor, root, expected):
    fields, _ = raw_call(client, registry, 11, data=descriptor+root)
    assert fields[0] == expected, fields

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--image', type=Path, default=ROOT/'build/live/guest.bin')
    p.add_argument('--forge-binary', type=Path, default=ROOT/'build/live/apps/forge-routed-candidate.bin')
    p.add_argument('--public-graph', type=Path, default=ROOT/'build/signed-forge-journey-2/published-closure.json')
    p.add_argument('--publisher', type=Path, default=ROOT/'build/signed-forge-journey-2/publisher.pub')
    p.add_argument('--output', type=Path, default=ROOT/'build/routed-forge')
    p.add_argument('--client-backend', choices=('qemu', 'x86_64'), default='qemu')
    args = p.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    image = args.output/'guest.bin'
    image.write_bytes(args.image.read_bytes())
    image_id = hashlib.sha256(image.read_bytes()).hexdigest()
    packages = {}
    for name, binary, rights in (
        ('identity', ROOT/'build/live/apps/identity.bin', 0),
        ('native-forge', args.forge_binary, 1919),
        ('native-registry', ROOT/'build/live/apps/native-registry.bin', 2175)):
        package = args.output/(name+'.ltrel')
        raw, _ = releases.make(binary, name, '0.8.0', rights, PRIVATE, profile=2)
        package.write_bytes(raw)
        packages[name] = dict(path=package, rights=rights, release_id=releases.inspect(raw)['release_id'],
                              binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
    fedkey, fedpub = args.output/'federation.pem', args.output/'federation.pub'
    capsule.generate_key(fedkey, fedpub)
    archive = json.loads(args.public_graph.read_text())
    root_id = bytes.fromhex(archive['selected'][0]['head'])
    records = [dict(record, payload=base64.b64decode(record['payload'], validate=True)) for record in archive['nodes']]
    clients, processes, logs, observations, checks = [], [], [], [], []
    started = time.monotonic()
    try:
        for i in range(5):
            directory = args.output/f'node{i}'
            directory.mkdir()
            portal = directory/'portal.sock'
            log = (directory/'guest.log').open('wb')
            logs.append(log)
            backend = args.client_backend if i == 0 else 'qemu'
            command = [ROOT/'lt', 'run', '--backend', backend, '--image', image, '--socket', portal, '--network-mux']
            processes.append(subprocess.Popen(list(map(str, command)), cwd=ROOT, stdout=log,
                                               stderr=subprocess.STDOUT, start_new_session=True))
            route.wait(portal.exists, 90)
            client = live.Client(portal, timeout=600)
            client.request(1)
            clients.append(client)
            if i:
                identity.start(client, packages['identity']['path'], PUBLIC)
        certificates = []
        for i in range(1, 5):
            probe = socket.socket()
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
            probe.close()
            certificate, fingerprint = route.create(clients[i], f'127.0.0.1:{port}',
                                                     f'public Forge terminal operator {i}', 7 if i < 4 else 8)
            certificates.append(certificate)
            (args.output/f'node{i}.certificate').write_bytes(certificate)
            observations.append(dict(node=i, kind='relay' if i < 4 else 'mailbox terminal',
                                     fingerprint=fingerprint.hex(),
                                     private_keys='generated only inside this native operator guest'))
            print('created native routed Forge operator', i, flush=True)
        for slot, certificate in enumerate(certificates):
            route.enroll(clients[0], slot, certificate)
            print('client approved public service', slot, flush=True)
        for i in range(1, 4):
            route.enroll(clients[i], 0, certificates[i])
        print('relays approved next-hop public services', flush=True)
        registry_package = packages['native-registry']['path']
        server = clients[4]
        server_registry, _ = messenger.install(server, registry_package, PUBLIC, 2175)
        configuration = federation.configure(server, server_registry, fedpub, 'portable')
        federation_id = bytes.fromhex(configuration['federation_id'])
        actual_root = projects.import_records(server, archive['selected'], records)[0]['cap']
        assert projects.project_identity(server, actual_root) == archive['project_id']
        publisher = releases.public_modulus(args.publisher)
        publication = releases.publication(archive['project_id'], hashlib.sha256(publisher).hexdigest())
        federation.call(server, server_registry, 3, data=publication+publisher)
        delegated = server.objects(27, actual_root, server_registry, 25)[0][1]
        pending, decision = federation.call(server, server_registry, 2, h=delegated)
        assert len(decision) == 512 and struct.unpack_from('<Q', decision, 16)[0] == 2
        fields, _ = raw_call(server, server_registry, 6)
        assert fields[0] == 6, fields
        signed = federation.sign_once(server, server_registry, fedkey, 'portable')
        assert signed['listing'] == 2 and signed['root'] == root_id.hex()
        _, descriptor = federation.call(server, server_registry, 6)
        assert len(descriptor) == 768
        checks.append('existing native Registry evaluates actual signed public project; unsigned catalog entry unavailable')
        print('actual existing Registry signed admission ready', flush=True)
        client = clients[0]
        forge_instance, _ = messenger.install(client, packages['native-forge']['path'], PUBLIC, 1919)
        client_registry, _ = messenger.install(client, registry_package, PUBLIC, 2175)
        federation.configure(client, client_registry, fedpub, 'portable')
        forge.federation_configure(client, forge_instance, federation_id.hex(), 1)
        assert not projects.roots(client), 'recipient received public graph through host bootstrap'
        route.route(server, 46, h=server_registry, data=federation_id)
        for operator in clients[1:]:
            route.route(operator, 30)
        began = time.monotonic()
        route.route(client, 31)
        route.wait(lambda: route.route(client, 32)[0][2] == 3, 300)
        circuit_seconds = time.monotonic()-began
        print('native Forge circuit built', circuit_seconds, flush=True)
        route.route(client, 38, h=3, a=17, b=forge_instance, c=1048576, d=128)
        def terminal_ready():
            state, pin = route.route(client, 41)
            if state[3]:
                raise AssertionError(('terminal setup failed', state))
            return pin if state[1] == 1 and state[2] == 3 else None
        assert route.wait(terminal_ready, 240) == hashlib.sha256(certificates[3]).digest()
        print('inner Forge terminal authenticated', flush=True)
        checks.append('three real relay guests telescope circuit; independent inner NK pins selected terminal descriptor')
        def inspect():
            fields, payload = raw_call(client, forge_instance, 67)
            assert fields[0] == 0, fields
            return fields, payload
        def query(expected_phase):
            fields, _ = raw_call(client, forge_instance, 66, a=1, data=root_id)
            assert fields[0] == 0, fields
            def completed():
                fields, payload = inspect()
                if fields[1] in (1, 2, 5):
                    return None
                assert fields[1] == expected_phase, fields
                return fields, payload
            return route.wait(completed, 180)
        began = time.monotonic()
        fields, payload = query(3)
        metadata_seconds = time.monotonic()-began
        assert payload[:32] == root_id and payload[32:] == descriptor
        accepted = forge.federation_inspect(client, forge_instance)
        assert accepted['remote_phase'] == 2 and accepted['classification'] == 2
        assert accepted['descriptor']['root'] == root_id.hex()
        assert accepted['descriptor']['federation_id'] == federation_id.hex()
        assert accepted['descriptor']['signature_present']
        assert not projects.roots(client), 'routed metadata silently imported project content'
        checks.append('existing Forge66 obtains Registry metadata through same routed broker; local Registry verifies signature/federation/admission')
        print('real routed Forge accepted signed metadata', metadata_seconds, flush=True)
        tampered = bytearray(descriptor)
        tampered[192] ^= 1
        denied(client, client_registry, bytes(tampered), root_id, 5)
        denied(client, client_registry, descriptor, bytes(32), 5)
        wrong_federation = bytearray(descriptor)
        wrong_federation[288] ^= 1
        denied(client, client_registry, bytes(wrong_federation), root_id, 5)
        fields, _ = raw_call(client, forge_instance, 66, a=2, data=root_id)
        assert fields[0] != 0, fields
        checks.append('signature tamper, wrong immutable root, wrong federation and unsupported privacy mode denied')
        # A real newer signed revocation crosses the identical protected API;
        # the client verifier then rejects the previously valid stale decision.
        federation.call(server, server_registry, 8, h=pending[2], a=signed['sequence'])
        revoked = federation.sign_once(server, server_registry, fedkey, 'portable')
        assert revoked['listing'] == 3 and revoked['sequence'] > signed['sequence']
        fields, _ = query(4)
        assert fields[2] == 5, fields
        denied(client, client_registry, descriptor, root_id, 3)
        assert not projects.roots(client)
        checks.append('newer signed native revocation reaches existing Forge through same circuit; stale prior admission denied after knowledge update')
        package_record = {name: {k: str(v) if isinstance(v, Path) else v for k, v in item.items()}
                          for name, item in packages.items()}
        report = dict(schema=1, result='pass', image_sha256=image_id, packages=package_record,
                      backends=[args.client_backend, 'qemu', 'qemu', 'qemu', 'qemu'], nodes=observations,
                      project_root=root_id.hex(), logical_project=archive['project_id'],
                      federation=federation_id.hex(), publisher=hashlib.sha256(publisher).hexdigest(),
                      circuit_seconds=circuit_seconds, routed_metadata_seconds=metadata_seconds,
                      total_seconds=time.monotonic()-started, checks=checks,
                      imported_source_nodes=len(records), imported_source_bytes=sum(len(r['payload']) for r in records),
                      recipient_content_imported=False, recipient_execution_approved=False,
                      limits='Component integration uses explicit native Forge control66, not conversation GUI handoff. Public project import and narrowly scoped package/federation RSA bootstrap are disclosed. All live node/circuit/Noise private keys stay native. Local operators on one host do not establish independence, Tor interoperability or traffic-analysis resistance.')
        (args.output/'evidence.json').write_text(json.dumps(report, indent=2)+'\n')
        print(json.dumps(report, indent=2))
    except BaseException as error:
        (args.output/'failure.json').write_text(json.dumps(dict(schema=1, image_sha256=image_id,
            error=repr(error), checks_completed=checks, nodes=observations,
            circuit_seconds=locals().get('circuit_seconds'),
            total_seconds=time.monotonic()-started), indent=2)+'\n')
        raise
    finally:
        for client in clients:
            try: client.close()
            except OSError: pass
        for process in processes:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
        for process in processes:
            try: process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        for log in logs:
            log.close()

if __name__ == '__main__':
    main()
