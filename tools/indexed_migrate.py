"""Explicit bounded migration of one approved legacy content scope.

Only selected range/proof RPC bytes cross the adapter. No personal plaintext
file, backing clone, host store index or old grant is persisted. The original
legacy committed bank and existing save records remain intact throughout.
"""
import argparse
import hashlib
import json
from pathlib import Path
import time
import struct
import content
import inventory
import live


def migrate(client, source, permission, operation, provider, federation, metadata=0):
    api = content.api(client)
    fields, manifest = api.objects(306, source)
    if fields[2] != 2 or len(manifest) != 256:
        raise ValueError('migration requires one complete approved legacy content read scope')
    total, count = fields[4], fields[6]
    if metadata:
        vault = struct.unpack_from('<Q', client.request(2), 96)[0]
        delegated = client.objects(6, metadata, vault, 25)[0][1]
        inventory.call(client, 264, permission, delegated)
    binding = manifest + hashlib.sha256(manifest).digest() + provider + federation
    fields, _ = api.objects(300, a=operation, b=total, c=3, d=permission, data=binding)
    target = fields[1]
    for index in range(count):
        _, proof = api.objects(313, source, index)
        fields, _ = api.objects(301, target, index, data=proof)
        if fields[1] == 0 and fields[2] == 4:
            continue
        job = fields[1]
        length = min(4096, total-index*4096)
        for offset in range(0, length, 640):
            n = min(640, length-offset)
            _, data = api.objects(307, source, index*4096+offset, n)
            if len(data) != n:
                raise ValueError('short selected migration range')
            api.objects(302, job, offset, data=data)
        api.objects(303, job)
        content.wait_job(api, job)
        api.objects(305, job, 4)
    fields, _ = api.objects(310, target)
    if fields[1] != target:
        content.wait_job(api, fields[1])
        api.objects(305, fields[1], 4)
    return dict(content=target, bytes=total, manifest_sha256=hashlib.sha256(manifest).hexdigest(),
        old_committed_root_preserved=True, existing_save_regions_modified=False,
        personal_plaintext_files_created=False, automatic_reformat=False)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--socket', type=Path, required=True)
    p.add_argument('--source-content', type=int, required=True)
    p.add_argument('--destination-grant', type=int, required=True)
    p.add_argument('--operation', type=int, required=True)
    p.add_argument('--metadata', type=int, default=0, help='exact optional legacy selected consumer/admission object')
    p.add_argument('--provider', required=True)
    p.add_argument('--federation', required=True)
    a = p.parse_args(argv)
    client = live.Client(a.socket, timeout=180)
    try:
        started = time.monotonic()
        result = migrate(client, a.source_content, a.destination_grant, a.operation,
            inventory.identity(a.provider), inventory.identity(a.federation), a.metadata)
        result['elapsed_seconds'] = time.monotonic()-started
        print(json.dumps(result, indent=2))
    finally:
        client.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
