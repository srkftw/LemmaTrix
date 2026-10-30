"""Two-phase native streamed vault recovery check; restart between phases.

The selected backing and key must be explicitly provisioned. Retain uses an
in-memory original composition, never a plaintext personal download directory.
Recovery only obtains the guest-created selected read grant and compares bytes.
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
import project_vault
from live import Client


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket', required=True, type=Path)
    parser.add_argument('--key', required=True, type=Path)
    parser.add_argument('--phase', required=True, choices=['retain', 'recover'])
    parser.add_argument('--seconds', type=float, default=1)
    parser.add_argument('--later', action='store_true')
    parser.add_argument('--metadata', type=Path, help='actual admitted public 1536-byte catalog record for atomic v4 selection')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    client = content.ContentClient(Client(args.socket, timeout=120))
    try:
        project_vault.unlock(client, args.key.read_bytes())
        original = content.original_wave(args.seconds, 2, args.later)
        manifest, chunks, proofs = content.commitments(original)
        operation = time.time_ns() & 0x7fffffffffffffff
        started = time.monotonic()
        if args.phase == 'retain':
            handle, _ = content.import_content(client, original, operation,
                                               hashlib.sha256(b'explicit-test-source').digest(),
                                               hashlib.sha256(b'explicit-test-federation').digest())
            metadata_object = client.import_object(args.metadata.read_bytes(), kind=2) if args.metadata else None
            result = content.retain(client, handle, operation + 1, metadata=metadata_object)
            fields, retained_manifest = content.vault_call(client, 246)
            assert retained_manifest == manifest
            assert fields[3] == len(original) and fields[5] == len(chunks)
            # The previous two formats are still readable and unmodified.
            legacy = client.request(202, struct.pack('<8Q', 202, 0, 3, 0, 0, 0, 0, 1))
            assert struct.unpack_from('<Q', legacy)[0] == 0
            client.objects(309, handle)
            result['checks'] = ['native complete-root scoped retention', 'encrypted authenticated inventory',
                                'legacy vault status remains readable']
            if args.metadata:
                result['checks'].append('content and selected admitted consumer metadata retained in one v4 commit')
        else:
            result = content.recover(client, operation)
            handle = result['handle']
            fields, recovered_manifest = client.objects(306, handle)
            assert recovered_manifest == manifest and fields[2] == 2
            actual = hashlib.sha256()
            for offset in range(0, len(original), 512):
                actual.update(client.objects(307, handle, offset, min(512, len(original) - offset))[1])
            assert actual.digest() == hashlib.sha256(original).digest()
            for index in (0, len(chunks) - 1):
                assert client.objects(313, handle, index)[1] == proofs[index]
            try:
                client.objects(301, handle, 0, data=proofs[0])
            except ValueError as error:
                assert 'status1' in str(error)
            else:
                raise AssertionError('recovery accidentally restored acquisition authority')
            result['checks'] = ['fresh recipient read grant', 'actual recovered range bytes match original SHA256',
                                'recovered authenticated proof paths match', 'no restored acquisition authority']
            if args.metadata:
                assert result['metadata_handle'] != 0
                assert client.read_object(result['metadata_handle']) == args.metadata.read_bytes()
                result['metadata_sha256'] = hashlib.sha256(args.metadata.read_bytes()).hexdigest()
                result['checks'].append('fresh selected metadata object matches exact admitted bytes from same committed generation')
            result['actual_recovered_sha256'] = actual.hexdigest()
        result.update({'schema': 1, 'phase': args.phase, 'bytes': len(original), 'chunks': len(chunks),
                       'manifest_sha256': hashlib.sha256(manifest).hexdigest(),
                       'original_sha256': hashlib.sha256(original).hexdigest(),
                       'elapsed_seconds': time.monotonic() - started,
                       'boundary': 'native ContentJobs + encrypted ContentVault-v3; explicit selected backing/key'})
    finally:
        client.close()
    text = json.dumps(result, indent=2) + '\n'
    if args.output:
        args.output.write_text(text)
    print(text, end='')


if __name__ == '__main__':
    main()
