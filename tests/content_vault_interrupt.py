"""Deliberate crash after a real v3 encrypted chunk write, before root commit.

Requires an explicitly selected running test guest PID/backing/key. This tool
does not edit guest memory or backing. Restart normally, then run the matching
content_vault.py --phase recover to prove the previous complete selection.
"""
import argparse
import hashlib
import json
import os
import signal
import struct
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import content
import project_vault
from live import Client


def read_at(path, offset, length):
    with open(path, 'rb') as stream:
        stream.seek(offset)
        return stream.read(length)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket', required=True, type=Path)
    parser.add_argument('--key', required=True, type=Path)
    parser.add_argument('--backing', required=True, type=Path)
    parser.add_argument('--guest-pid', required=True, type=int)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    client = content.ContentClient(Client(args.socket, timeout=120))
    try:
        project_vault.unlock(client, args.key.read_bytes())
        prior, prior_manifest = content.vault_call(client, 246)
        previous_generation = prior[1]
        old_roots = read_at(args.backing, 20992 * 512, 1024)
        operation = time.time_ns() & 0x7fffffffffffffff
        raw = content.original_wave(.75, 2, later=False)
        selected, _ = content.import_content(client, raw, operation,
                                              hashlib.sha256(b'explicit-interruption-source').digest(),
                                              hashlib.sha256(b'explicit-interruption-federation').digest())
        vault_instance = struct.unpack_from('<Q', client.request(2), 96)[0]
        delegated = client.objects(308, selected, vault_instance)[0][1]
        target_sector = 21000 + ((previous_generation + 1) % 2) * 14728 + 2
        prior_chunk = read_at(args.backing, target_sector * 512, 5120)
        content.vault_call(client, 240, delegated, operation + 1)
        deadline = time.monotonic() + 120
        while True:
            fields, _ = content.vault_call(client, 241)
            assert fields[2] == 1, fields
            written_chunk = read_at(args.backing, target_sector * 512, 5120)
            if fields[3] >= 4096 and written_chunk != prior_chunk and written_chunk != bytes(5120):
                break
            assert time.monotonic() < deadline
        assert written_chunk != prior_chunk and written_chunk != bytes(5120)
        assert read_at(args.backing, 20992 * 512, 1024) == old_roots
        # Fault injection targets only the explicitly named test guest. The
        # reported progress follows successful encrypted block write replies.
        os.kill(args.guest_pid, signal.SIGKILL)
        result = {'schema': 1, 'fault': 'SIGKILL after completed encrypted chunk write before root publication',
                  'previous_generation': previous_generation, 'candidate_generation': fields[5],
                  'reported_written_bytes': fields[3], 'candidate_total_bytes': fields[4],
                  'written_encrypted_chunk_sha256': hashlib.sha256(written_chunk).hexdigest(),
                  'root_sectors_unchanged_before_crash': True,
                  'previous_manifest_sha256': hashlib.sha256(prior_manifest).hexdigest(),
                  'recovery_check_required': 'restart same explicit backing; content_vault.py --phase recover'}
    finally:
        client.close()
    text = json.dumps(result, indent=2) + '\n'
    args.output.write_text(text)
    print(text, end='')


if __name__ == '__main__':
    main()
