"""Real native Objects content-boundary checks through the normal guest portal.

No guest memory is patched and no host service makes validation decisions.
Use --socket for an already running guest; the image must include Content-v1.
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
from live import Client


def rejected(fn, status):
    try:
        fn()
    except ValueError as error:
        assert f'status{status}' in str(error), str(error)
    else:
        raise AssertionError(f'operation unexpectedly accepted; expected status{status}')


def run(client, large=True, tiny=False):
    client = content.api(client)
    provider = hashlib.sha256(b'explicit-test-provider').digest()
    federation = hashlib.sha256(b'explicit-test-federation').digest()
    raw = content.original_wave(.05 if tiny else (6 if large else 1), 2)
    manifest, chunks, proofs = content.commitments(raw)
    checks = []
    operation = time.time_ns() & 0x7fffffffffffffff
    binding = manifest + content.sha(manifest) + provider + federation
    for mode in (1, 2, 4, 7):
        rejected(lambda mode=mode: client.objects(300, a=operation, b=len(raw), c=mode, data=binding), 7)
    rejected(lambda: client.objects(300, a=operation, b=len(raw), c=3, d=1, data=binding), 1)
    rejected(lambda: client.objects(300, a=operation, b=len(raw) - 1, c=3, data=binding), 4)
    bad = bytearray(binding)
    bad[256] ^= 1
    rejected(lambda: client.objects(300, a=operation, b=len(raw), c=3, data=bad), 5)
    checks.append('privacy mode enum, invalid durable permit, byte budget and manifest substitution reject')
    root, _, chunks, proofs = content.reserve(client, raw, operation, provider, federation)
    too_large = bytearray(manifest)
    struct.pack_into('<QQ', too_large, 24, content.VOLATILE_CAPACITY, content.VOLATILE_CAPACITY // content.CHUNK)
    struct.pack_into('<Q', too_large, 48, 11)
    full_binding = bytes(too_large) + content.sha(too_large) + provider + federation
    rejected(lambda: client.objects(300, a=operation + 1, b=content.VOLATILE_CAPACITY, c=3, data=full_binding), 4)
    assert client.objects(300, a=operation, b=len(raw), c=3, data=binding)[0][1] == root
    changed_binding = binding[:288] + bytes(reversed(provider)) + federation
    rejected(lambda: client.objects(300, a=operation, b=len(raw), c=3, data=changed_binding), 2)
    rejected(lambda: client.objects(307, root, 0, 64), 6)
    rejected(lambda: client.objects(307, root ^ 0x100, 0, 64), 1)
    rejected(lambda: client.objects(301, root, len(chunks), data=proofs[0]), 2)
    rejected(lambda: client.objects(301, root, 0, data=proofs[0][:-1]), 2)
    checks.append('aggregate reservation quota, idempotency, conflicting operation, stale handle, missing range and malformed proof reject')
    # The first job is cancelled before publication. Its former handle stays a
    # queryable terminal result until explicit forget, and cannot accept bytes.
    cancelled = client.objects(301, root, 0, data=proofs[0])[0][1]
    client.objects(302, cancelled, 0, data=chunks[0][:512])
    client.objects(305, cancelled, 1)
    assert client.objects(304, cancelled)[0][2] == 3
    rejected(lambda: client.objects(302, cancelled, 512, data=chunks[0][512:1024]), 2)
    client.objects(305, cancelled, 2)
    client.objects(305, cancelled, 3)
    assert client.objects(304, cancelled)[0][2] == 5
    rejected(lambda: client.objects(307, root, 0, 64), 6)
    client.objects(305, cancelled, 4)
    rejected(lambda: client.objects(304, cancelled), 3)
    checks.append('pause/resume/cancel, terminal retrieval and stale forgotten job reject')
    # Hash substitution and a valid hash with a wrong Merkle position each fail
    # inside the Lean guest. Neither publishes a range or consumes a page.
    for substitute_proof, substitute_bytes in [(proofs[0], bytes([chunks[0][0] ^ 1]) + chunks[0][1:]),
                                               (proofs[1], chunks[1])]:
        job = client.objects(301, root, 0, data=substitute_proof)[0][1]
        for offset in range(0, len(substitute_bytes), 512):
            client.objects(302, job, offset, data=substitute_bytes[offset:offset + 512])
        client.objects(303, job)
        deadline = time.monotonic() + 60
        while True:
            result = client.objects(304, job)[0]
            if result[2] >= 4:
                break
            assert time.monotonic() < deadline
        assert result[2] == 6 and result[5] == 5, result
        client.objects(305, job, 4)
        rejected(lambda: client.objects(307, root, 0, 64), 6)
    checks.append('chunk-byte and position/Merkle substitution fail without range publication')
    started = time.monotonic()
    content.ingest_chunk(client, root, 0, chunks[0], proofs[0])
    assert client.objects(307, root, 0, 512)[1] == raw[:512]
    rejected(lambda: client.objects(307, root, 4090, 16), 2)
    rejected(lambda: client.objects(307, root, 0, 641), 2)
    rejected(lambda: client.objects(310, root), 6)
    checks.append('validated partial range readable; unvalidated/cross-chunk/oversized ranges and premature completion reject')
    # Ordinary Objects operations are served between hash quanta. A separate
    # small record is imported/read while a real 4KiB chunk hash is outstanding.
    next_job = client.objects(301, root, 1, data=proofs[1])[0][1]
    for offset in range(0, len(chunks[1]), 512):
        client.objects(302, next_job, offset, data=chunks[1][offset:offset + 512])
    client.objects(303, next_job)
    before = client.objects(304, next_job)[0]
    unrelated = b'Unrelated Objects import during private incremental content hashing.\n'
    object_handle = client.import_object(unrelated)
    assert client.objects(4, object_handle, 0, len(unrelated))[1] == unrelated
    after = client.objects(304, next_job)[0]
    content.wait_job(client, next_job)
    client.objects(305, next_job, 4)
    client.objects(8, object_handle)
    checks.append({'unrelated_objects_import_and_read_between_content_quanta': True,
                   'job_state_before': before[2], 'cursor_before': before[3],
                   'job_state_after': after[2], 'cursor_after': after[3]})
    for index in range(2, len(chunks)):
        content.ingest_chunk(client, root, index, chunks[index], proofs[index])
    final_job = client.objects(310, root)[0][1]
    content.wait_job(client, final_job)
    assert client.objects(304, final_job)[0][2] == 4
    client.objects(305, final_job, 4)
    fields, _ = client.objects(306, root)
    assert fields[2:7] == (2, len(raw), len(raw), len(chunks), len(chunks)), fields
    actual = hashlib.sha256()
    for offset in range(0, len(raw), 512):
        count = min(512, len(raw) - offset)
        actual.update(client.objects(307, root, offset, count)[1])
    assert actual.digest() == hashlib.sha256(raw).digest()
    checks.append('complete root publishes once; all actual streamed range bytes match source SHA256')
    for index in (0, len(chunks) // 2, len(chunks) - 1):
        _, actual_proof = client.objects(313, root, index)
        assert actual_proof == proofs[index], (index, actual_proof.hex(), proofs[index].hex())
    checks.append('authorized complete-root proof exports match independently constructed paths')
    # An explicit reference release invalidates that handle immediately. A new
    # incarnation or unrelated caller cannot recycle it as content authority.
    client.objects(309, root)
    rejected(lambda: client.objects(307, root, 0, 64), 1)
    client.objects(312)
    checks.append('released root grant cannot read; collection enqueues bounded page reclamation')
    return {'schema': 1, 'boundary': 'native guest ContentJobs-v1 endpoint5 via ABI2 portal',
            'input_bytes': len(raw), 'chunks': len(chunks), 'max_chunk_buffer_per_job': 4096,
            'manifest_sha256': hashlib.sha256(manifest).hexdigest(),
            'actual_read_sha256': actual.hexdigest(), 'elapsed_seconds': time.monotonic() - started,
            'retention': 'this run uses volatile storage; unissued durable permits reject', 'checks': checks}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket', required=True)
    parser.add_argument('--small', action='store_true')
    parser.add_argument('--tiny', action='store_true', help='valid 50ms WAV for representative changed-backend boundaries')
    parser.add_argument('--output')
    args = parser.parse_args()
    client = Client(Path(args.socket), timeout=120)
    try:
        result = run(client, not args.small, args.tiny)
    finally:
        client.close()
    text = json.dumps(result, indent=2) + '\n'
    if args.output:
        Path(args.output).write_text(text)
    print(text, end='')


if __name__ == '__main__':
    main()
