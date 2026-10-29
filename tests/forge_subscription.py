"""Physical Subscribe observes a newer signed generation without fetching it.

The two existing signed generation bundles are explicitly recovered on the
publisher only. The fresh subscriber learns every descriptor through the guest
network and checks its signature in a separately isolated Registry process.
No compiler or application-release signing is performed by this test.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'tools'), str(ROOT / 'tests')]
import capsule
import federation
import forge
import network
import projects
import releases
from creator_journey import rendered_text
from federation_forge import admission, install_registry
from forge_journey import Node, wait


def subscription(node):
    client = node.client()
    try:
        return forge.subscription_inspect(client, node.instance)
    finally:
        client.close()


def recover_selected(node, archive, alias):
    selected = [dict(archive['selected'][0], name=alias)]
    records = [dict(record, payload=base64.b64decode(record['payload'], validate=True))
               for record in archive['nodes']]
    client = node.client()
    try:
        root = projects.import_records(client, selected, records)[0]['cap']
        assert projects.project_identity(client, root) == archive['project_id']
        shell = struct.unpack_from('<Q', client.request(2), 4 * 32)[0]
        client.objects(27, root, shell, 127)
        return root
    finally:
        client.close()


def approve_admission(node, alias, head, registry, key):
    if rendered_text(node.ui.frame(), 10, 56, 34, 0x9fc6a5).rstrip() == 'FEDERATION ADMISSION / F1 RETURN':
        node.ui.press(59)
        wait(lambda: rendered_text(node.ui.frame(), 350, 322, 2, 0xe9bc75) == '00',
             'publisher physically returns to native scope overview', 120)
    node.select(alias)
    node.ui.press(87)  # Physical F11: native exact-root federation admission.
    pending = wait(lambda: (value if (value := admission(node, True))['local_phase'] == 1
                            and value['descriptor']['root'] == head else None),
                   'native exact generation submitted to isolated Registry', 180)
    assert pending['descriptor']['classification'] == 2, pending
    client = node.client()
    try:
        signed = federation.sign_once(client, registry, key, 'portable')
    finally:
        client.close()
    assert signed and signed['root'] == head and signed['listing'] == 2, signed
    wait(lambda: admission(node, True)['local_phase'] == 2,
         'Registry verifies the signed generation decision', 180)
    return signed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--image', required=True, type=Path)
    parser.add_argument('--forge-package', type=Path,
                        default=ROOT / 'build/forge-bootstrap-004/native-forge-server.ltrel')
    parser.add_argument('--forge-public', type=Path,
                        default=ROOT / 'build/forge-server-recovery-final2/operator.pub')
    parser.add_argument('--registry-package', type=Path,
                        default=ROOT / 'build/federation-wire/native-registry.ltrel')
    parser.add_argument('--registry-public', type=Path,
                        default=ROOT / 'build/federation-wire/operator.pub')
    parser.add_argument('--publisher-public', type=Path,
                        default=ROOT / 'build/signed-native-fork-journey-4/fork-publisher.pub')
    parser.add_argument('--generation1', type=Path,
                        default=ROOT / 'build/signed-native-fork-journey-4/fork-published-closure.json')
    parser.add_argument('--generation2', type=Path,
                        default=ROOT / 'build/native-release-update-3/published-closure.json')
    args = parser.parse_args()
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    os.environ['LT_GUEST_IMAGE'] = str(args.image.resolve())
    image = hashlib.sha256(args.image.read_bytes()).hexdigest()
    archives = [json.loads(path.read_text()) for path in (args.generation1, args.generation2)]
    assert archives[0]['project_id'] == archives[1]['project_id']
    heads = [archive['selected'][0]['head'] for archive in archives]
    assert heads[0] != heads[1]
    logical = archives[0]['project_id']
    publisher = releases.public_modulus(args.publisher_public)
    publication = releases.publication(logical, hashlib.sha256(publisher).hexdigest())
    probe = socket.socket()
    probe.bind(('127.0.0.1', 0))
    endpoint = f'127.0.0.1:{probe.getsockname()[1]}'
    probe.close()
    credentials = [args.output / 'publisher.credential', args.output / 'subscriber.credential']
    network.provision(*credentials, os.getrandom(32), os.getrandom(32),
                      hashlib.sha256(b'LT native subscription admission1').digest())
    key, public = args.output / 'federation.pem', args.output / 'federation.pub'
    capsule.generate_key(key, public)
    checks, nodes = [], []

    def passed(label, **facts):
        checks.append(dict(check=label, status='passed', **facts))
        report = dict(image=image,
                      forge_release=releases.inspect(args.forge_package.read_bytes())['release_id'],
                      registry_release=releases.inspect(args.registry_package.read_bytes())['release_id'],
                      environment='Two isolated QEMU guests on one development host; no personal vault or server backing',
                      protocol='Forge1 / admission1 / RegistrySDK1 / Subscription1', checks=checks)
        (args.output / 'evidence.json').write_text(json.dumps(report, indent=2) + '\n')
        print('PASS', label, flush=True)

    try:
        reader = Node(args.output / 'subscriber', endpoint, True)
        nodes.append(reader)
        sender = Node(args.output / 'publisher', endpoint)
        nodes.append(sender)
        for node, credential in zip((sender, reader), credentials):
            client = node.client()
            try:
                network.configure(client, credential)
            finally:
                client.close()

        def authenticated():
            results = []
            for node in nodes:
                client = node.client()
                try:
                    results.append(network.status(client)['endpoint_authenticated'])
                finally:
                    client.close()
            return all(results)

        wait(authenticated, 'fresh ordered-pair Noise endpoint authentication', 180)
        registries = []
        for node, credential, role in ((sender, credentials[0], 'registry'),
                                       (reader, credentials[1], 'client')):
            node.install(args.forge_package, args.forge_public)
            client = node.client()
            try:
                forge.configure(client, node.instance, credential, role)
            finally:
                client.close()
            registry = install_registry(node, args.registry_package, args.registry_public,
                                        public, 'portable')
            registries.append(registry)
        client = sender.client()
        try:
            federation.call(client, registries[0], 3, data=publication + publisher)
        finally:
            client.close()
        assert not reader.roots()
        recover_selected(sender, archives[0], 'sub-generation-1')
        first = approve_admission(sender, 'sub-generation-1', heads[0], registries[0], key)
        reader.ui.press(61)  # F3 queries metadata; never requests content.
        observed = wait(lambda: (value if (value := admission(reader))['remote_phase'] == 2
                                 and value['descriptor']['root'] == heads[0] else None),
                        'initial signed native generation travels through peer', 180)
        assert observed['descriptor']['logical_project_id'] == logical
        assert observed['descriptor']['publication_id'] == publication.hex()
        assert not reader.roots()
        # A signature displays the actual admission details. S is deliberately
        # only active in the overview, so physical F1 returns there first.
        reader.ui.press(59)
        wait(lambda: rendered_text(reader.ui.frame(), 350, 322, 2, 0xe9bc75) == '00',
             'native overview exposes unsubscribed state', 120)
        reader.ui.press(31)
        before = wait(lambda: (value if (value := subscription(reader))['subscribed'] else None),
                      'physical S subscribes to verified native descriptor')
        assert before['state'] == 1 and before['desired_root'] == heads[0]
        assert before['logical_project_id'] == logical and before['publication_id'] == publication.hex()
        assert before['federation_id'] == first['federation']
        (reader.path / 'subscribed.ppm').write_bytes(reader.ui.frame().ppm())
        passed('physical Subscribe binds actual logical project, publication, federation and peer',
               subscription=before, descriptor=observed['descriptor'], recipient_graph_roots=0)

        recover_selected(sender, archives[1], 'sub-generation-2')
        second = approve_admission(sender, 'sub-generation-2', heads[1], registries[0], key)
        assert second['sequence'] > first['sequence']
        # No manual F3 is sent after S. The guest's bounded subscription timer
        # discovers the new signed generation over its existing broker grant.
        updated = wait(lambda: (value if (value := subscription(reader))['state'] == 2
                                and value['desired_root'] == heads[1]
                                and value['metadata_queries'] > before['metadata_queries'] else None),
                       'bounded subscription query observes signed newer generation', 240)
        assert updated['metadata_queries'] > before['metadata_queries']
        assert updated['sequence'] == second['sequence']
        assert updated['backoff_turns'] <= 128000
        assert updated['logical_project_id'] == before['logical_project_id']
        assert updated['publication_id'] == before['publication_id']
        assert updated['federation_id'] == before['federation_id']
        assert updated['peer_id'] == before['peer_id']
        actual = reader.inspect()
        assert not reader.roots(), 'Subscribe silently fetched graph payload'
        assert not actual['import_transaction'] and not actual['selected_root']
        client = reader.client()
        try:
            try:
                client.request(29, publication)
            except ValueError:
                pass
            else:
                raise AssertionError('Subscribe activated an executable without approval')
        finally:
            client.close()
        # New verified metadata opens the authority detail view. Return to the
        # overview to observe its actual rendered update flag, not just status.
        reader.ui.press(59)
        frame = wait(lambda: (frame if rendered_text(frame := reader.ui.frame(), 350, 322, 2,
                                                     0xe9bc75) == '02' else None),
                     'actual native overview displays pending update flag', 120)
        (reader.path / 'update-available.ppm').write_bytes(frame.ppm())
        passed('bounded guest metadata queries announce a real signed update without fetching or activating it',
               subscription=updated, first_root=heads[0], update_root=heads[1],
               first_release=observed['descriptor']['release_id'], update_release=second['release_id'],
               first_sequence=first['sequence'], update_sequence=second['sequence'],
               rendered_update_flag='02', recipient_graph_roots=0, import_transaction=0,
               execution_approved=False, personal_retention=False)
        reader.ui.press(31)
        disabled = wait(lambda: (value if not (value := subscription(reader))['subscribed'] else None),
                        'physical S unsubscribes')
        assert disabled['desired_root'] == '00' * 32 and disabled['metadata_queries'] == 0
        assert not reader.roots()
        passed('physical unsubscribe clears only subscription identity and timer state', subscription=disabled)
    except BaseException:
        for node in nodes:
            try:
                (node.path / 'failure.ppm').write_bytes(node.ui.frame().ppm())
                (node.path / 'failure-state.json').write_text(json.dumps(dict(
                    forge=node.inspect(), admission=admission(node), subscription=subscription(node)), indent=2))
            except BaseException:
                pass
        raise
    finally:
        for node in nodes:
            try:
                node.stop()
            except BaseException:
                pass


if __name__ == '__main__':
    main()
