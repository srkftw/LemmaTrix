"""Actual native Game Project closure acquisition from a separate provider.

Only the provider imports the public publisher graph fixture. The recipient
receives signed admission metadata; LibraryFetch owns all network requests,
Objects staging, integrity/dependency validation and atomic publication.
"""
import argparse
import base64
import hashlib
import json
import os
import socket
import struct
import sys
import time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'tools'), str(ROOT/'tests')]
import capsule
import federation
import library_peer
import network
import nodes
import projects
import releases
from library_journey import Node, wait


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, default=ROOT/'build/live/guest.bin')
    parser.add_argument('--archive', type=Path, default=ROOT/'build/campaign005/game-secure-editions/game1-closure.json')
    parser.add_argument('--game', type=Path, default=ROOT/'build/campaign005/game-secure-editions/game1/crate-workshop.ltrel')
    parser.add_argument('--registry', type=Path, default=ROOT/'build/live/apps/registry.bin')
    parser.add_argument('--peer', type=Path, default=ROOT/'build/live/apps/library-peer.bin')
    parser.add_argument('--fetch', type=Path, default=ROOT/'build/live/apps/library-fetch.bin')
    parser.add_argument('--harness', type=Path, default=ROOT/'build/live/apps/library-fetch-harness.bin')
    parser.add_argument('--key', type=Path, default=ROOT/'build/campaign005/publisher.pem')
    parser.add_argument('--public', type=Path, default=ROOT/'build/campaign005/publisher.pub')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--keep-on-failure', action='store_true')
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(exist_ok=False)
    image = out/'platform.bin'
    image.write_bytes(args.image.read_bytes())
    provider = receiver = None
    success = False
    identities = {}
    def install(node, binary, name, rights):
        raw, _ = releases.make(binary, name, '1.0.0', rights, args.key, profile=2, license='NOASSERTION')
        package = out/(name+'.ltrel')
        package.write_bytes(raw)
        info = releases.inspect(raw)
        with node.client() as client:
            instance = nodes.start_package(client, nodes.approved_package(package,args.public,info['release_id'],rights),raw)
        identities[name] = dict(instance=instance, release_id=info['release_id'], binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
        return instance
    def call(client, who, op, h=0, a=0, b=0, c=0, data=b''):
        raw = client.request(150, struct.pack('<Q8Q',who,op,h,a,b,c,0,0,1)+data)
        return struct.unpack_from('<8Q', raw), raw[64:]
    try:
        provider = Node('provider', out, image)
        provider_registry = install(provider,args.registry,'graph-provider-registry',2175)
        peer = install(provider,args.peer,'graph-provider-peer',1025)
        receiver = Node('receiver',out,image)
        receiver_registry = install(receiver,args.registry,'graph-receiver-registry',2175)
        fetcher = install(receiver,args.fetch,'graph-receiver-fetch',1151)
        harness = install(receiver,args.harness,'graph-library-submitter',127)
        (out/'instances.json').write_text(json.dumps(identities,indent=2)+'\n')
        fedkey, fedpub = out/'federation.pem', out/'federation.pub'
        capsule.generate_key(fedkey,fedpub)
        archived = json.loads(args.archive.read_text())
        expected = {r['id']: dict(r,payload=base64.b64decode(r['payload'])) for r in archived['nodes']}
        game = releases.inspect(args.game.read_bytes())
        with provider.client() as client:
            federation.configure(client,provider_registry,fedpub,'consumer',allowed_rights=8191)
            root = projects.import_records(client,archived['selected'],list(expected.values()))[0]['cap']
            federation.call(client,provider_registry,3,data=bytes.fromhex(game['project_id'])+releases.public_modulus(args.public))
            admitted = client.objects(27,root,provider_registry,25)[0][1]
            federation.call(client,provider_registry,2,h=admitted)
            decision = federation.sign_once(client,provider_registry,fedkey,'consumer',8191)
            assert decision['listing'] == 5, decision
            _, admission = federation.call(client,provider_registry,6)
            assert len(admission) == 768 and admission[320:352].hex() == archived['selected'][0]['head']
            scope = client.objects(27,root,peer,1)[0][1]
        with receiver.client() as client:
            federation.configure(client,receiver_registry,fedpub,'consumer',allowed_rights=8191)
            client.request(184,struct.pack('<Q',harness))
            assert projects.roots(client) == [], 'recipient unexpectedly owns preloaded Project roots'
            denied, _ = call(client,fetcher,710,1,100,1048576,data=admission)
            assert denied[0] == 1 and not any(denied[1:7]), denied
        identity = hashlib.sha256(os.urandom(32)).digest()
        private, public = out/'network.pem',out/'network.pub'
        capsule.generate_key(private,public)
        probe = socket.socket();probe.bind(('127.0.0.1',0));port = probe.getsockname()[1];probe.close()
        description = out/'game.service'
        detail = network.create_description(private,identity,'127.0.0.1:'+str(port),'library-seed',description)
        credentials = [out/'reader.credential',out/'provider.credential']
        network.provision(*credentials,identity,bytes.fromhex(detail['server_id']),bytes.fromhex(detail['service_id']))
        head = admission[320:352]
        stream = int.from_bytes(head[:8],'little') | 1
        with provider.client() as client:
            network.configure(client,credentials[1],description,slot=1)
            network.call(client,13,slot=1)
            try:library_peer.call(client,peer,400,1,3,stream,scope,16777216,100000,identity+bytes.fromhex(detail['service_id'])+bytes(32))
            except ValueError as error:assert 'status2' in str(error)
            else:raise AssertionError('provider accepted Project head substitution')
            library_peer.call(client,peer,400,1,3,stream,scope,16777216,100000,identity+bytes.fromhex(detail['service_id'])+head)
        with receiver.client() as client:
            network.configure(client,credentials[0],description,slot=1)
            network.call(client,13,slot=1)
            wait(lambda:network.status(client,1)['endpoint_authenticated'],300,'game provider authentication')
            operation = time.time_ns() & 0x7fffffffffffffff
            fields, _ = call(client,harness,720,fetcher,1,operation,1048576,data=admission)
            assert fields[0] == 0 and fields[2] == 1, fields
            fields, _ = call(client,harness,722,fetcher,operation)
            assert fields[0] == 0 and fields[2] == 3, fields
            operation += 1
            malformed = bytearray(admission);malformed[600] ^= 1
            fields, _ = call(client,harness,720,fetcher,1,operation,1048576,data=malformed)
            def failed():
                f,_ = call(client,harness,721,fetcher,operation)
                return f if f[2] == 4 else None
            failure = wait(failed,180,'malformed signed admission rejection')
            assert failure[5] == 12 and failure[1] == 0, failure
            operation += 1
            fields, _ = call(client,harness,720,fetcher,1,operation,1048576,data=admission)
            started = time.monotonic()
            progress = []
            def complete():
                f,_ = call(client,harness,721,fetcher,operation)
                if not progress or progress[-1] != f[3]:
                    progress.append(f[3])
                if f[2] in (3,4):
                    raise RuntimeError(('native fetch terminal',f))
                return f if f[2] == 2 else None
            fields = wait(complete,900,'actual Game closure acquisition')
            assert fields[0] == 0 and fields[1] and fields[3] == sum(len(r['payload']) for r in expected.values()), fields
            again,_ = call(client,harness,721,fetcher,operation)
            assert again == fields, (again,fields)
            wrong,_ = call(client,fetcher,711,operation)
            assert wrong[0] == 1 and not any(wrong[1:7]), wrong
            owner = struct.unpack_from('<Q',client.request(2),32)[0]
            delegated,_ = call(client,harness,723,fields[1],owner)
            assert delegated[0] == 0
            selected = delegated[1]
            actual_head = client.objects(29,selected)[1][:32]
            assert actual_head == head
            actual = {};cursor = 0
            while True:
                meta, ids = client.objects(26,selected,cursor)
                if not meta[1]:
                    break
                cursor = meta[3]
                raw = client.read_object(meta[1])
                node_id = ids[:32].hex()
                assert node_id in expected and raw == expected[node_id]['payload']
                assert ids[32:64].hex() == expected[node_id]['parent']
                assert meta[4] == expected[node_id]['kind'] and meta[5] == expected[node_id].get('schema',1)
                actual[node_id] = hashlib.sha256(raw).hexdigest()
            assert set(actual) == set(expected), (set(actual),set(expected))
        result = dict(schema=1,result='passed',image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),
            packages=identities,game_release_id=game['release_id'],project_head=head.hex(),nodes=len(actual),
            payload_bytes=sum(len(r['payload']) for r in expected.values()),actual_node_payload_sha256=actual,
            observed_progress=progress,elapsed_seconds=time.monotonic()-started,
            recipient_host_payload_import=False,local_execution_approval=False,
            checks=['actual native consumer+executable admission classification5 from separate Registry',
                    'provider rejects expected-head substitution', 'only selected Library incarnation may submit/poll',
                    'cancel reclaims unpublished work', 'malformed admission signature rejected before acquisition',
                    'Game closure acquired through native Network-v2 ops7/8/9',
                    'every returned node payload,kind,schema,parent and immutable Project head checked',
                    'terminal selected read/share/revoke/export root delegation is queryable and idempotent; execution remains separate'])
        (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps(result,indent=2))
        success = True
    finally:
        if success or not args.keep_on_failure:
            if receiver:receiver.stop()
            if provider:provider.stop()


if __name__ == '__main__':
    main()
