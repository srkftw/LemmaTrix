"""Retain two actual signed generations on each independent seed, then run them.

Only the creator imports explicit already signed exports. Every seed and reader
obtains its graph through physical Forge controls and the encrypted guest path.
Each seed recovers from its own purpose-bound device, never a copied graph file.
"""
import argparse, base64, hashlib, json, os, socket, struct, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'tools'), str(ROOT/'tests')]
import capsule, forge, network, projects, releases, server_store
from creator_journey import rendered_text
from forge_journey import wait
from forge_replication import Peer, authenticate, save
from native_release_update import actual_score
from signed_forge_journey import ClientNode


class Seed(Peer):
    focus = ClientNode.focus

    def setup(self, package, public, credential, description):
        self.install(package, public)
        client = self.client()
        try:
            network.configure(client, credential, description)
            assert network.status(client)['public_service_description_verified']
            forge.configure(client, self.instance, credential)
        finally:
            client.close()

    def namespace(self, digest):
        client = self.client()
        try:
            grant = server_store.call(client, 231, self.instance, 2, 1048576, digest)[0][1]
            # Only select a fresh, already-authorized namespace. This operation
            # grants no storage authority and does not reset the network peer.
            raw = client.request(150, struct.pack('<Q', self.instance) +
                                 struct.pack('<8Q', 61, 0, grant, 0, 0, 0, 0, 1))
            assert len(raw) == 64 and struct.unpack_from('<Q', raw)[0] == 0
        finally:
            client.close()

    def recover(self, namespace, head):
        self.focus(self.instance)
        self.namespace(namespace)
        self.ui.press(67)
        preview = wait(lambda: (s if (s := self.archive())['phase'] == 4 else None),
                       'native inspection of chosen retained generation', 180)
        assert preview['head'] == head, preview
        (self.path/(head[:12]+'-recovery-scope.ppm')).write_bytes(self.ui.frame().ppm())
        self.ui.press(67)
        def complete():
            state = self.archive()
            if state['phase'] == 9:
                raise AssertionError(('retained signed graph recovery failed', state))
            return state if state['phase'] == 8 else None
        wait(complete, 'native recovery of complete retained generation', 240)
        root = next(r for r in self.roots() if r['head'] == head)
        self.select(root['name'])
        self.ui.press(62)
        wait(lambda: self.inspect()['status'] in (4, 5), 'recovered exact generation offer', 90)
        return preview


def transfer(sender, receiver, archive):
    head = archive['selected'][0]['head']
    receiver.focus(receiver.instance)
    receiver.ui.press(61)
    wait(lambda: receiver.inspect()['status'] == 6, 'actual selected seed metadata', 150)
    prior = len(receiver.roots())
    receiver.ui.press(63)
    def complete():
        state = receiver.inspect()
        if state['status'] == 9:
            raise AssertionError(('native signed closure transfer rejected', state, sender.inspect()))
        return state if state['status'] == 11 and not state['import_transaction'] else None
    state = wait(complete, 'complete signed generation transfer', 300)
    root = next(r for r in receiver.roots() if r['head'] == head)
    client = receiver.client()
    try:
        assert projects.project_identity(client, root['cap']) == archive['project_id']
        actual = {}
        cursor = 0
        while True:
            fields, ids = client.objects(26, root['cap'], cursor)
            if not fields[1]:
                break
            actual[ids[:32].hex()] = (fields[4], fields[5], ids[32:64].hex(),
                                     client.read_object(fields[1], True))
            cursor = fields[3]
        expected = {r['id']: (r['kind'], r['schema'], r['parent'],
                             base64.b64decode(r['payload'], validate=True)) for r in archive['nodes']}
        assert actual == expected, 'actual received closure differs from selected signed graph'
    finally:
        client.close()
    wait(lambda: sender.inspect()['status'] == 10, 'guest validated-completion receipt', 120)
    return dict(head=head, records=len(actual), payload_bytes=sum(len(v[3]) for v in actual.values()),
                prior_roots=prior, completed=state)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--public', type=Path, required=True)
    parser.add_argument('--publisher-public', type=Path, required=True)
    parser.add_argument('--generation', type=Path, action='append', required=True)
    args = parser.parse_args()
    if len(args.generation) != 2:
        parser.error('select exactly two already signed generations in parent order')
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    os.environ['LT_GUEST_IMAGE'] = str(args.image.resolve())
    archives = [json.loads(path.read_text()) for path in args.generation]
    assert archives[0]['project_id'] == archives[1]['project_id']
    role_keys, identities = [], []
    for i in range(4):
        private, public = args.output/('network-role-'+str(i)+'.pem'), args.output/('network-role-'+str(i)+'.pub')
        capsule.generate_key(private, public)
        role_keys.append(private)
        identities.append(hashlib.sha256(releases.public_modulus(public)).digest())
    namespaces = [[hashlib.sha256(os.getrandom(32)).digest() for _ in range(2)] for _ in range(2)]
    disks = [args.output/'seed1.img', args.output/'seed2.img']
    for disk in disks:
        server_store.provision(disk)
    nodes, checks = [], []
    def passed(check, **data):
        checks.append(dict(check=check, result='pass', **data))
        report = dict(image=hashlib.sha256(args.image.read_bytes()).hexdigest(),
                      environment='Four distinct QEMU guests on one Linux host; own identities/backing',
                      checks=checks)
        (args.output/'journey.json').write_text(json.dumps(report, indent=2)+'\n')
        print('PASS', check, flush=True)
    def stop_all():
        while nodes:
            nodes.pop().stop()
    def pair(label, client_id, server_id, client_disk=None, server_disk=None):
        relationship = args.output/label
        relationship.mkdir()
        probe = socket.socket(); probe.bind(('127.0.0.1', 0)); port = probe.getsockname()[1]; probe.close()
        endpoint = '127.0.0.1:'+str(port)
        description = relationship/'service.public'
        network.create_description(role_keys[identities.index(server_id)], client_id, endpoint, 'forge',
                                   description, hashlib.sha256(args.image.read_bytes()).digest())
        _, descriptor, _ = network.load_description(description)
        client_key, server_key = relationship/'client.credential', relationship/'server.credential'
        network.provision(client_key, server_key, client_id, server_id, hashlib.sha256(descriptor).digest())
        server = Seed(args.output/(label+'-server'), endpoint, True, server_disk)
        client = Seed(args.output/(label+'-client'), endpoint, False, client_disk)
        nodes.extend([server, client])
        server.setup(args.package, args.public, server_key, description)
        client.setup(args.package, args.public, client_key, description)
        # The store mount is explicitly separate from Network/Forge enrollment.
        for node, disk in ((server, server_disk), (client, client_disk)):
            if disk:
                c = node.client()
                try: server_store.call(c, 230)
                finally: c.close()
        authenticate(client, server)
        return client, server
    try:
        creator, seed1 = pair('creator-seed1', identities[0], identities[1], server_disk=disks[0])
        c = creator.client()
        try:
            shell = struct.unpack_from('<Q', c.request(2), 4*32)[0]
            for i, archive in enumerate(archives):
                selected = [dict(archive['selected'][0], name='generation-'+str(i+1))]
                records = [dict(r, payload=base64.b64decode(r['payload'], validate=True)) for r in archive['nodes']]
                root = projects.import_records(c, selected, records)[0]['cap']
                c.objects(27, root, shell, 127)
            private = c.import_object(b'PRIVATE unrelated '+os.getrandom(97), 10)
            private_id = c.objects(21, private)[1][:32].hex()
        finally:
            c.close()
        for i, archive in enumerate(archives):
            creator.select('generation-'+str(i+1)); creator.ui.press(62)
            wait(lambda: creator.inspect()['status'] in (4, 5), 'native immutable generation offer', 90)
            received = transfer(creator, seed1, archive)
            seed1.namespace(namespaces[0][i]); committed = save(seed1)
            passed('creator publishes signed generation '+str(i+1)+' to independently durable seed1',
                   transfer=received, committed=committed, private_excluded=private_id)
        stop_all()
        seed1, seed2 = pair('seed1-seed2', identities[1], identities[2], disks[0], disks[1])
        assert not seed1.roots() and not seed2.roots()
        for i, archive in enumerate(archives):
            preview = seed1.recover(namespaces[0][i], archive['selected'][0]['head'])
            received = transfer(seed1, seed2, archive)
            seed2.namespace(namespaces[1][i]); committed = save(seed2)
            passed('publisher absent; seed1 recovers own generation '+str(i+1)+' and replicates to seed2',
                   preview=preview, transfer=received, committed=committed)
        stop_all()
        reader, seed2 = pair('reader-seed2', identities[3], identities[2], server_disk=disks[1])
        assert not seed2.roots() and not reader.roots()
        publisher = hashlib.sha256(releases.public_modulus(args.publisher_public)).hexdigest()
        publication = releases.publication(archives[0]['project_id'], publisher)
        c = reader.client()
        try: c.request(10, publication+releases.public_modulus(args.publisher_public))
        finally: c.close()
        for i, archive in enumerate(archives):
            preview = seed2.recover(namespaces[1][i], archive['selected'][0]['head'])
            received = transfer(seed2, reader, archive)
            reader.ui.press(64)
            wait(lambda: rendered_text(reader.ui.frame(), 16, 12, 24) == 'SIGNED PACKAGE CANDIDATE',
                 'actual retained Release signature and authority inspection', 120)
            prompt = reader.ui.frame()
            assert rendered_text(prompt, 136, 110, 4) == '0300'
            (reader.path/('generation-'+str(i+1)+'-approval.ppm')).write_bytes(prompt.ppm())
            time.sleep(.3); reader.ui.press(28)
            wait(lambda: actual_score(reader) == '00000000', 'approved native app starts', 120)
            reader.ui.textASCII('cat123', delay=.08)
            score = ['0000001b', '00000020'][i]
            wait(lambda: actual_score(reader) == score, 'retained generation real supplied input', 120)
            passed('publisher and seed1 absent; reader retrieves and runs seed2 retained generation '+str(i+1),
                   preview=preview, transfer=received, input='cat123', score=score)
            reader.focus(reader.instance)
    finally:
        stop_all()


if __name__ == '__main__':
    main()
