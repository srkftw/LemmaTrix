"""Refresh shared verifier knowledge before physical Fetch and installation.

This is a focused authority regression, not another complete Forge journey.
The original operator's own catalog supplies genuine signed positive/negative
descriptors through public Registry APIs. A seed recovers only its own backing.
Administrative fault injection forwards the old public positive over the real
authenticated broker, then another public SDK caller teaches the recipient's
isolated verifier the genuine newer revocation without updating Forge metadata.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'tools'), str(ROOT / 'tests')]
import capsule
import federation
import forge
import network
import releases
from creator_journey import rendered_text
from durable_federated_seed import (EXPECTED_ROOT, SEED_NAMESPACE, admission_bytes,
    endpoint, exact_graph, relationship, start_registry, start_seed)
from federation_forge import admission, install_registry
from forge_journey import wait
from forge_replication import authenticate
from signed_forge_journey import ClientNode


def inject_descriptor(seed, credential, descriptor):
    """Forward immutable public evidence, never graph data or local handles."""
    side, material = network.load_credentials(credential)
    assert side == 2
    client = seed.client()
    try:
        grant = network.call(client, 2, a=3, b=3, c=8192, d=65536, e=100000,
            data=material[:32] + material[64:96] + bytes(32) + struct.pack('<Q', 1))[0][1]
        sequence = struct.unpack_from('<Q', descriptor, 48)[0]
        for kind, payload in [(9, descriptor[:512]), (10, descriptor[512:])]:
            packet = struct.pack('<8Q', 0x3145475246544c, 1, kind, sequence, 0, 0, 0, 0) + \
                     bytes.fromhex(EXPECTED_ROOT) + payload
            job = network.call(client, 3, grant, a=1, data=packet)[0][1]
            wait(lambda: network.call(client, 4, job)[0][2] == 3,
                 'authentic immutable public admission transmitted through encrypted broker', 120)
        network.call(client, 8, grant)
    finally:
        client.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--journey', type=Path, default=ROOT / 'build/durable-federated-seed')
    parser.add_argument('--gui-package', type=Path, default=ROOT / 'build/forge-audit-packages/native-forge.ltrel')
    parser.add_argument('--server-package', type=Path, default=ROOT / 'build/forge-audit-packages/forge-server.ltrel')
    parser.add_argument('--public', type=Path, default=ROOT / 'build/federation-wire/operator.pub')
    parser.add_argument('--registry-package', type=Path, default=ROOT / 'build/federation-wire/native-registry.ltrel')
    parser.add_argument('--seed-store', type=Path, default=ROOT / 'build/durable-signed-four-node/seed2.img')
    parser.add_argument('--seed-namespace', default=SEED_NAMESPACE)
    parser.add_argument('--seed-key', type=Path, default=ROOT / 'build/durable-signed-four-node/network-role-2.pem')
    parser.add_argument('--expected-graph', type=Path, default=ROOT / 'build/native-release-update-3/published-closure.json')
    args = parser.parse_args()
    args.output = args.output.resolve()
    args.output.mkdir(parents=True)
    args.image, args.journey = args.image.resolve(), args.journey.resolve()
    os.environ['LT_GUEST_IMAGE'] = str(args.image)
    image_id = hashlib.sha256(args.image.read_bytes()).digest()
    original = json.loads((args.journey / 'evidence.json').read_text())
    assert image_id.hex() == original['image'] and original['root'] == EXPECTED_ROOT
    config = json.loads((args.journey / 'registry-initial/node.json').read_text())
    backing = Path(config['server_store'])
    before_store = hashlib.sha256(backing.read_bytes()).hexdigest()
    before_seed = hashlib.sha256(args.seed_store.read_bytes()).hexdigest()
    archive = json.loads(args.expected_graph.read_text())
    for path, expected in [(args.gui_package, 3967), (args.server_package, 1151)]:
        assert releases.inspect(path.read_bytes())['rights'] == expected
    checks, running = [], []

    def passed(label, **facts):
        checks.append(dict(check=label, status='passed', **facts))
        report = dict(image=image_id.hex(), protocol='Forge1 + Admission1 authority refresh',
            root=EXPECTED_ROOT, project_compilations=0, project_release_signatures_created=0,
            environment='Separate QEMU guests on one Linux development host',
            setup='Own retained source recovery and public SDK signed-descriptor forwarding; no graph preload or UI-private setter',
            bootstrap_packages={name: releases.inspect(path.read_bytes())['release_id'] for name, path in
                                [('gui', args.gui_package), ('server', args.server_package)]},
            checks=checks)
        (args.output / 'evidence.json').write_text(json.dumps(report, indent=2) + '\n')
        print('PASS', label, flush=True)

    try:
        address = endpoint()
        relation = relationship(args.output / 'registry-public-inspection', os.getrandom(32),
            args.journey / 'registry-network.pem', address, image_id, 'registry')
        registry = start_registry(args.output / 'registry', backing, config['namespace'], address, relation,
            args.server_package, args.registry_package, args.public, args.journey / 'federation.pub',
            args.image, recover=True)
        running.append(registry)
        client = registry.client()
        try:
            records = [federation.call(client, registry.registry_instance, 7, h=slot)[1] for slot in (0, 1)]
        finally:
            client.close()
        positive, negative = records
        assert len(positive) == len(negative) == 768
        assert [struct.unpack_from('<Q', p, 48)[0] for p in records] == [1, 2]
        assert [struct.unpack_from('<Q', p, 16)[0] for p in records] == [2, 3]
        assert struct.unpack_from('<Q', negative, 24)[0] == 6
        assert all(p[320:352].hex() == EXPECTED_ROOT for p in records)
        registry.stop()
        running.remove(registry)
        assert hashlib.sha256(backing.read_bytes()).hexdigest() == before_store
        passed('own recovered catalog exposes genuine positive1 and newer signed revocation2 without source replay',
               positive_sha256=hashlib.sha256(positive).hexdigest(),
               negative_sha256=hashlib.sha256(negative).hexdigest(), source_roots=0, store_unchanged=True)

        for action in ['fetch', 'install']:
            key, public = args.output / (action + '-reader.pem'), args.output / (action + '-reader.pub')
            capsule.generate_key(key, public)
            reader_id = hashlib.sha256(releases.public_modulus(public)).digest()
            address = endpoint()
            relation = relationship(args.output / (action + '-relationship'), reader_id, args.seed_key,
                                    address, image_id, 'forge')
            seed = start_seed(args.output / (action + '-seed2'), args.seed_store, address,
                              relation, args.gui_package, args.public, True)
            running.append(seed)
            seed.recover(bytes.fromhex(args.seed_namespace), EXPECTED_ROOT)
            reader = ClientNode(args.output / (action + '-reader'), address)
            running.append(reader)
            client = reader.client()
            try:
                network.configure(client, relation['client'], relation['description'])
            finally:
                client.close()
            authenticate(reader, seed)
            reader.install(args.gui_package, args.public)
            client = reader.client()
            try:
                forge.configure(client, reader.instance, relation['client'])
            finally:
                client.close()
            verifier = install_registry(reader, args.registry_package, args.public,
                                        args.journey / 'federation.pub', 'portable')
            reader.ui.press(61)
            wait(lambda: reader.inspect()['metadata_nodes'] == 17, 'physical native discovery of retained seed root', 180)
            inject_descriptor(seed, relation['server'], positive)
            cached = wait(lambda: (r if (r := admission(reader))['remote_phase'] == 2
                                  and r['remote_sequence'] == 1 else None),
                          'recipient independently verifies genuine older positive admission', 180)
            assert admission_bytes(reader) == positive and not reader.roots()
            if action == 'install':
                reader.ui.press(63)
                wait(lambda: reader.inspect()['status'] == 11 and not reader.inspect()['import_transaction'],
                     'actual source graph arrives while chosen admission remains positive', 300)
                root = next(root for root in reader.roots() if root['head'] == EXPECTED_ROOT)
                assert exact_graph(reader, root['cap'], archive) == dict(records=17, payload_bytes=130344)
                wait(lambda: seed.inspect()['status'] == 10, 'honest completion receipt after real graph commit', 120)
            prior_roots = reader.roots()
            before = admission(reader)
            assert before['remote_phase'] == 2 and before['remote_sequence'] == 1
            # Launcher management proxies this independent public Registry SDK
            # call. Forge receives no metadata, decision, signature or setter.
            client = reader.client()
            try:
                fields, verified = federation.call(client, verifier, 11,
                    data=negative + bytes.fromhex(EXPECTED_ROOT))
                assert fields[1:3] == (3, 6) and verified == negative
            finally:
                client.close()
            stale = admission(reader)
            assert stale['remote_phase'] == 2 and stale['remote_sequence'] == 1
            assert stale['metadata_epoch'] == before['metadata_epoch']
            assert admission_bytes(reader) == positive
            reader.ui.press(63 if action == 'fetch' else 64)
            wait(lambda: reader.inspect()['status'] == 14, 'physical action refreshes shared verifier knowledge and denies', 180)
            after = admission(reader)
            assert after['remote_phase'] == 3 and after['reason'] == 8
            assert after['metadata_epoch'] == before['metadata_epoch'], 'test learned revocation through new metadata'
            assert reader.roots() == prior_roots and not reader.inspect()['import_transaction']
            if rendered_text(reader.ui.frame(), 10, 56, 34, 0x9fc6a5).rstrip() == 'FEDERATION ADMISSION / F1 RETURN':
                reader.ui.press(59)
            frame = wait(lambda: (f if rendered_text((f := reader.ui.frame()), 60, 278, 40, 0x9fc6a5) ==
                                  'FEDERATION DECISION REQUIRED OR REJECTED' else None),
                         'actual native denial renders without a Launcher candidate', 120)
            (reader.path / 'shared-verifier-denial.ppm').write_bytes(frame.ppm())
            passed('physical ' + ('F5 Fetch' if action == 'fetch' else 'F6 install') +
                   ' denies newer shared-verifier revocation without incoming metadata or admission frames',
                   cached=before, stale_after_other_caller=stale, refreshed=after,
                   metadata_epoch_unchanged=True, root_count_before=len(prior_roots), root_count_after=len(reader.roots()),
                   denied_status=14, import_transaction=0, verifier_instance=verifier,
                   negative_sha256=hashlib.sha256(negative).hexdigest())
            reader.stop()
            running.remove(reader)
            seed.stop()
            running.remove(seed)
        assert hashlib.sha256(args.seed_store.read_bytes()).hexdigest() == before_seed
        assert hashlib.sha256(backing.read_bytes()).hexdigest() == before_store
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
            node.stop()


if __name__ == '__main__':
    main()
