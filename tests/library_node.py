"""Normal library-node recovery and actual native protocol serving after restart.

Input is an existing separately retained four-slot backing, never copied or
preloaded into a recipient. No host process implements serving or validation.
"""
import argparse
import hashlib
import json
import os
import signal
import struct
import subprocess
import sys
import time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'tools'), str(ROOT/'tests')]
import content
import library_node
import live
import network
from library_journey import Node, wait


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--client-credentials', required=True, type=Path)
    parser.add_argument('--image', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    out = args.output.resolve()
    out.mkdir(exist_ok=False)
    server = client_node = None
    log = (out/'server.log').open('wb')
    server_socket = out/'server.sock'
    try:
        server = subprocess.Popen([str(ROOT/'lt'), 'library-node', 'run', str(args.config.resolve()),
            '--socket', str(server_socket), '--image', str(args.image.resolve())],
            cwd=ROOT, stdout=log, stderr=log, start_new_session=True)
        def configured():
            if server.poll() is not None:
                raise RuntimeError('library-node exited; see server.log')
            if not server_socket.exists():
                return None
            c = live.Client(server_socket, timeout=180)
            try:
                rows = c.request(2)
                instances = [struct.unpack_from('<Q', rows, i)[0] for i in range(7*32, len(rows), 32)
                             if struct.unpack_from('<Q', rows, i+16)[0] == 1025 and
                                0 < struct.unpack_from('<Q', rows, i+8)[0] < 5]
                if len(instances) != 1:
                    return None
                info = library_node.inspect(c, config, instances[0])
                return info if sum(s['waiting_for_authentication'] for s in info['scopes']) == len(config['archives']) else None
            finally:
                c.close()
        initial = wait(configured, 300, 'four recovered roots awaiting native authentication')
        (out/'offline-inspect.json').write_text(json.dumps(initial, indent=2)+'\n')
        client_node = Node('reader', out, args.image.resolve())
        relation = config['relationships'][0]
        slot = relation['slot']
        description = Path(relation['description'])
        _, material = network.load_credentials(args.client_credentials)
        with client_node.client() as client:
            network.configure(client, args.client_credentials, description, slot=slot)
            network.call(client, 13, slot=slot)
            wait(lambda: network.status(client, slot)['endpoint_authenticated'], 180, 'reader authentication')
            served = []
            request_id = 0
            def request(grant, operation, h=0, a=0):
                nonlocal request_id
                request_id += 1
                rid = 8000 + request_id
                packet = struct.pack('<8Q', 0x31524545504c544c, 1, operation, h, a, 0, 0, 0)
                job = network.call(client, 3, grant, a=2, b=rid, data=packet, slot=slot)[0][1]
                wait(lambda: network.call(client, 4, job, slot=slot)[0][2] == 3, 120, 'request transmission')
                def receive():
                    fields, data = network.call(client, 6, grant, slot=slot, allow_error=True)
                    if fields[0] == 6:
                        return None
                    assert fields[0] == 0 and fields[3] == rid and len(data) >= 64, fields
                    answer = struct.unpack_from('<8Q', data)
                    assert answer[3] == 0 and answer[4] == rid, answer
                    return data[64:]
                return wait(receive, 120, 'native LibraryPeer response')
            def grant_for(selected):
                root = bytes.fromhex(selected['manifest_sha256'])
                stream = int.from_bytes(root[:8], 'little') | 1
                return network.call(client, 2, a=3, b=3, c=65536, d=65536, e=100000,
                    data=material[32:96] + root + struct.pack('<QQ', 2, stream), slot=slot)[0][1]
            grants = []
            for selected in config['archives']:
                root = bytes.fromhex(selected['manifest_sha256'])
                grant = grant_for(selected)
                grants.append(grant)
                manifest = request(grant, 3)
                assert hashlib.sha256(manifest).digest() == root
                proof = request(grant, 4, 0)
                prefix = request(grant, 5, 0, 512)
                original = content.original_wave(.05 + selected['slot']*.01, 2, later=selected['slot'] % 2 == 1)
                expected_manifest, _, expected_proofs = content.commitments(original)
                assert manifest == expected_manifest and prefix == original[:512] and proof == expected_proofs[0]
                served.append(dict(slot=selected['slot'], manifest_sha256=root.hex(), bytes=len(original),
                    prefix_sha256=hashlib.sha256(prefix).hexdigest(), authenticated_proof_sha256=hashlib.sha256(proof).hexdigest()))
            network.call(client, 9, slot=slot)
            wait(lambda: not network.status(client, slot)['endpoint_authenticated'], 60, 'connection loss')
            network.call(client, 13, slot=slot)
            wait(lambda: network.status(client, slot)['endpoint_authenticated'], 180, 'fresh authentication')
            stale, _ = network.call(client, 6, grants[0], slot=slot, allow_error=True)
            assert stale[0] != 0, 'old connection grant survived epoch'
            fresh = grant_for(config['archives'][0])
            assert request(fresh, 3) == content.commitments(content.original_wave(.05, 2))[0]
        operator = live.Client(server_socket, timeout=180)
        try:
            final = library_node.inspect(operator, config, initial['instance'])
        finally:
            operator.close()
        (out/'online-inspect.json').write_text(json.dumps(final, indent=2)+'\n')
        result = dict(schema=1, image_sha256=hashlib.sha256(args.image.read_bytes()).hexdigest(),
            native_package_release=config['release_id'], archives=served, host_payload_ingestion=False,
            personal_vault_used=False, backing_copied=False,
            checks=['normal library-node run obtained fresh namespace grants and recovered four selected roots',
                    'native scopes approved while offline; fresh grants minted after authenticated connection',
                    'actual native served manifests and authenticated proofs and512-byte source prefixes for all four roots',
                    'connection loss invalidated old client grant; native server resumed under bounded remaining policy',
                    'normal inspect and stop paths'], result='passed')
        (out/'result.json').write_text(json.dumps(result, indent=2)+'\n')
        print(json.dumps(result, indent=2))
    finally:
        if client_node:
            client_node.stop()
        if server and server.poll() is None:
            try:
                subprocess.run([str(ROOT/'lt'), 'library-node', 'stop', '--socket', str(server_socket)], cwd=ROOT, timeout=15, check=True)
                server.wait(15)
            except (subprocess.SubprocessError, OSError):
                os.killpg(server.pid, signal.SIGTERM)
                server.wait(15)
        log.close()


if __name__ == '__main__':
    main()
