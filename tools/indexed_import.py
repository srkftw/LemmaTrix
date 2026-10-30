"""Explicit opaque operator input export and guest-validated indexed import jobs.

The adapter writes no authoritative directory, queue, encryption or allocation
index. It exports one selected input and canonical proofs to a disclosed raw
operator staging extent. Lean validates every record and commits its own store.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import struct
import time
import content
import inventory
import live
import server_store


def stage_input(store, source, descriptor, *, plaintext_export_approved, format_id=1):
    if not plaintext_export_approved:
        raise ValueError('explicit --approve-plaintext-operator-input-export is required')
    if descriptor.exists():
        raise FileExistsError(descriptor)
    raw = source.read_bytes()
    manifest, chunks, proofs = content.commitments(raw, provenance=content.sha(raw), format_id=format_id)
    flags = os.O_RDWR | os.O_NOFOLLOW
    fd = os.open(store, flags)
    try:
        initial = os.fstat(fd).st_size
        if initial != inventory.SECTORS * 512:
            raise ValueError('staging requires an explicitly provisioned indexed operator backing with no prior appended input extent')
        header = os.pread(fd, 512, 0)
        if struct.unpack_from('<3Q', header) != (server_store.FORMAT, 1, server_store.SECTORS):
            raise ValueError('explicit purpose2 operator backing header required')
        source_sector = inventory.SECTORS
        end = (source_sector + len(chunks) * 10) * 512
        soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
        if hard != resource.RLIM_INFINITY and hard < end:
            raise ValueError('selected opaque input extent exceeds the process hard file-size limit')
        if soft != resource.RLIM_INFINITY and soft < end:
            resource.setrlimit(resource.RLIMIT_FSIZE, (end, hard))
        os.ftruncate(fd, end)
        depth = struct.unpack_from('<Q', manifest, 48)[0]
        for index, (part, proof) in enumerate(zip(chunks, proofs)):
            record = (struct.pack('<4Q', index, len(part), depth, 0) + proof).ljust(512, b'\0')
            record += part.ljust(4096, b'\0')
            record = record.ljust(5120, b'\0')
            if os.pwrite(fd, record, (source_sector+index*10)*512) != len(record):
                raise OSError('short opaque input export')
        os.fsync(fd)
    finally:
        os.close(fd)
    result = dict(schema=1, format='LT-OpaqueOperatorInput-v1', source=str(source.resolve()),
        staging_backing=str(store.resolve()), staging_purpose=2,
        intentional_plaintext_operator_input_export=True, source_sector=source_sector,
        records=len(chunks), record_bytes=5120, bytes=len(raw),
        payload_sha256=hashlib.sha256(raw).hexdigest(), manifest_hex=manifest.hex(),
        manifest_sha256=hashlib.sha256(manifest).hexdigest(), format_id=format_id,
        authoritative_store_index=False, recipient_store_reformatted=False)
    with descriptor.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    return result


def submit(client, permission, operation, descriptor, provider, federation):
    manifest = bytes.fromhex(descriptor['manifest_hex'])
    if hashlib.sha256(manifest).hexdigest() != descriptor['manifest_sha256']:
        raise ValueError('descriptor manifest commitment differs')
    binding = manifest + content.sha(manifest) + provider + federation
    fields, _ = inventory.call(client, 267, permission, operation,
        descriptor['source_sector'], descriptor['records'], descriptor['bytes'], 3, data=binding)
    return fields


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('stage')
    p.add_argument('--operator-store', type=Path, required=True)
    p.add_argument('--input', type=Path, required=True)
    p.add_argument('--descriptor', type=Path, required=True)
    p.add_argument('--format', choices=('wave','artifact'), required=True)
    p.add_argument('--approve-plaintext-operator-input-export', action='store_true')
    p = sub.add_parser('submit')
    p.add_argument('--socket', type=Path, required=True)
    p.add_argument('--grant', type=int, required=True)
    p.add_argument('--operation', type=int, required=True)
    p.add_argument('--descriptor', type=Path, required=True)
    p.add_argument('--provider', required=True)
    p.add_argument('--federation', required=True)
    for name in ('inspect', 'cancel'):
        p = sub.add_parser(name)
        p.add_argument('--socket', type=Path, required=True)
        p.add_argument('--operation', type=int, required=True)
    args = parser.parse_args(argv)
    if args.command == 'stage':
        result = stage_input(args.operator_store, args.input, args.descriptor,
            plaintext_export_approved=args.approve_plaintext_operator_input_export,
            format_id=1 if args.format == 'wave' else 2)
    else:
        client = live.Client(args.socket, timeout=180)
        try:
            if args.command == 'submit':
                result = dict(fields=submit(client, args.grant, args.operation,
                    json.loads(args.descriptor.read_text()), inventory.identity(args.provider),
                    inventory.identity(args.federation)))
            else:
                result = dict(fields=inventory.call(client, 269 if args.command == 'inspect' else 270,
                    args.operation)[0])
        finally:
            client.close()
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
