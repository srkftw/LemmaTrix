"""Purpose2 native content archive retention/restart/recovery boundary checks.

Restart the guest between phases with only its explicit server backing attached.
No personal vault/key is used, and no backing is copied between nodes.
"""
import argparse
import hashlib
import json
import struct
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import content
import server_content
from live import Client


def rejected(fn, code):
    try:
        fn()
    except ValueError as error:
        assert f'status{code}' in str(error), str(error)
    else:
        raise AssertionError('unauthorized server content operation accepted')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket', required=True, type=Path)
    parser.add_argument('--phase', required=True, choices=('retain', 'recover'))
    parser.add_argument('--namespace', default=hashlib.sha256(b'explicit-original-seed-namespace').hexdigest())
    parser.add_argument('--metadata', type=Path)
    parser.add_argument('--old-grant', type=int)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    client = content.ContentClient(Client(args.socket, timeout=180))
    try:
        raw = content.original_wave(1, 2)
        manifest, chunks, proofs = content.commitments(raw)
        owner = struct.unpack_from('<Q', client.request(2), 32)[0]
        namespace = bytes.fromhex(args.namespace)
        operation = time.time_ns() & 0x7fffffffffffffff
        grant = server_content.permit(client, owner, namespace, content.sha(manifest), len(raw))
        if args.old_grant:
            rejected(lambda: server_content.call(client, 252, args.old_grant), 1)
        started = time.monotonic()
        if args.phase == 'retain':
            selected, _ = content.import_content(client, raw, operation,
                                                 hashlib.sha256(b'explicit-source-provider').digest(),
                                                 hashlib.sha256(b'explicit-source-federation').digest())
            metadata = client.import_object(args.metadata.read_bytes(), kind=2) if args.metadata else None
            result = server_content.retain(client, grant, selected, operation + 1, metadata)
            fields, stored_manifest = server_content.call(client, 255, grant)
            assert stored_manifest == manifest and fields[3] == len(raw)
            result['checks'] = ['intentional server retention without personal vault/key',
                                'exact manifest inspect under fresh namespace and byte ceiling']
        else:
            wrong_hash = server_content.permit(client, owner, namespace, hashlib.sha256(b'wrong manifest').digest(), len(raw))
            rejected(lambda: server_content.call(client, 253, wrong_hash, owner, operation + 10), 1)
            server_content.call(client, 256, wrong_hash)
            wrong_namespace = server_content.permit(client, owner, hashlib.sha256(b'wrong namespace').digest(), content.sha(manifest), len(raw))
            rejected(lambda: server_content.call(client, 253, wrong_namespace, owner, operation + 11), 5)
            server_content.call(client, 256, wrong_namespace)
            too_small = server_content.permit(client, owner, namespace, content.sha(manifest), len(raw) - 1)
            rejected(lambda: server_content.call(client, 253, too_small, owner, operation + 12), 1)
            server_content.call(client, 256, too_small)
            result = server_content.recover(client, grant, operation)
            selected = result['content_handle']
            actual = hashlib.sha256()
            for offset in range(0, len(raw), 512):
                actual.update(client.objects(307, selected, offset, min(512, len(raw) - offset))[1])
            assert actual.digest() == content.sha(raw)
            assert client.objects(313, selected, len(chunks) - 1)[1] == proofs[-1]
            if args.metadata:
                assert client.read_object(result['metadata_handle']) == args.metadata.read_bytes()
            result['checks'] = ['fresh operator namespace grant after restart', 'wrong namespace/root/budget reject',
                                'all actual recovered media bytes and proof path match', 'fresh selected read authority only']
            result['actual_recovered_sha256'] = actual.hexdigest()
        rejected(lambda: server_content.call(client, 252, grant ^ 0x100), 1)
        server_content.call(client, 256, grant)
        rejected(lambda: server_content.call(client, 252, grant), 1)
        result.update({'schema': 1, 'phase': args.phase, 'bytes': len(raw), 'chunks': len(chunks),
                       'namespace': namespace.hex(), 'grant_for_stale_restart_check': grant,
                       'manifest_sha256': content.sha(manifest).hex(), 'elapsed_seconds': time.monotonic() - started,
                       'personal_vault_or_key_used': False})
    finally:
        client.close()
    text = json.dumps(result, indent=2) + '\n'
    if args.output:
        args.output.write_text(text)
    print(text, end='')


if __name__ == '__main__':
    main()
