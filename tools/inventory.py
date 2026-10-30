"""Explicit selected scopes for the Lean indexed inventory; no host catalog or queue."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import content
import live

SECTORS = 5394976
KINDS = {'personal': 1, 'operator': 2}

def call(client, op, h=0, a=0, b=0, c=0, d=0, e=0, data=b''):
    raw = client.request(op, struct.pack('<8Q', op, h, a, b, c, d, e, 1) + data)
    if len(raw) < 64:
        raise ValueError('short indexed inventory response')
    fields = struct.unpack_from('<8Q', raw)
    if fields[0]:
        raise ValueError(f'indexed inventory status{fields[0]}')
    return fields, raw[64:]

def identity(value):
    raw = bytes.fromhex(value)
    if len(raw) != 32 or not any(raw):
        raise ValueError('explicit nonzero scoped identity32 required')
    return raw

def permit(client, kind, slot, quota, recipient, namespace, manifest):
    return call(client, 260, kind, slot, quota, recipient, 3, data=namespace+manifest)[0][1]

def open_item(client, grant, recipient, operation):
    fields, payload = call(client, 262, grant, recipient, operation)
    return fields, payload

def export(client, handle, output):
    """User-selected destination; exactly one selected immutable root, no host paths in guest."""
    api = content.api(client)
    fields, manifest = api.objects(306, handle)
    total = fields[4]
    if fields[2] != 2:
        raise ValueError('export requires complete local content; streaming/partial is separate')
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    digest = hashlib.sha256()
    try:
        with os.fdopen(fd, 'wb') as stream:
            for offset in range(0, total, 512):
                count = min(512, total-offset, 4096-offset%4096)
                _, data = api.objects(307, handle, offset, count)
                if len(data) != count:
                    raise ValueError('short selected export range')
                stream.write(data)
                digest.update(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        # A failed destination is visibly partial and must never appear complete.
        # link() creates the marker exclusively: rename() could overwrite an
        # unrelated pre-existing .incomplete file. Preserve the original if the
        # filesystem cannot create a marker, rather than risking another file.
        partial = output.with_name(output.name+'.incomplete')
        for attempt in range(16):
            try:
                os.link(output, partial, follow_symlinks=False)
                output.unlink()
                break
            except FileExistsError:
                partial = output.with_name(output.name+'.incomplete.'+os.urandom(8).hex())
            except OSError:
                break
        raise
    return dict(path=str(output), bytes=total, sha256=digest.hexdigest(),
                manifest_sha256=content.sha(manifest).hex(), scope='one selected immutable content read grant')

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket', type=Path, required=True)
    sub = parser.add_subparsers(dest='command', required=True)
    p=sub.add_parser('permit')
    p.add_argument('--kind', choices=KINDS, required=True)
    p.add_argument('--slot', type=int, choices=range(16), required=True)
    p.add_argument('--bytes', type=int, required=True)
    p.add_argument('--recipient', type=int, required=True)
    p.add_argument('--namespace', required=True)
    p.add_argument('--manifest', required=True)
    p=sub.add_parser('list')
    p.add_argument('--kind', choices=KINDS, required=True)
    p.add_argument('--cursor', type=int, default=0)
    p.add_argument('--namespace', required=True)
    for name in ('open','delete'):
        p=sub.add_parser(name)
        p.add_argument('--grant', type=int, required=True)
        if name=='open':
            p.add_argument('--recipient', type=int, required=True)
            p.add_argument('--operation', type=int, required=True)
    p=sub.add_parser('ingest')
    p.add_argument('--grant', type=int, required=True)
    p.add_argument('--input', type=Path, required=True)
    p.add_argument('--operation', type=int, required=True)
    p.add_argument('--provider', required=True)
    p.add_argument('--federation', required=True)
    p.add_argument('--format', choices=('wave','artifact'), required=True)
    p=sub.add_parser('export')
    p.add_argument('--content', type=int, required=True)
    p.add_argument('--output', type=Path, required=True)
    args=parser.parse_args(argv)
    client=live.Client(args.socket, timeout=180)
    try:
        if args.command=='permit':
            result=dict(permit=permit(client,KINDS[args.kind],args.slot,args.bytes,args.recipient,
                                      identity(args.namespace),identity(args.manifest)), durable_grants_persisted=False)
        elif args.command=='list':
            fields,payload=call(client,261,KINDS[args.kind],args.cursor,data=identity(args.namespace))
            result=dict(fields=fields,metadata=payload.hex(),payload_rehydrated=False)
        elif args.command=='open':
            fields,payload=open_item(client,args.grant,args.recipient,args.operation)
            result=dict(fields=fields,metadata=payload.hex(),fresh_read_authority=True)
        elif args.command=='delete':
            fields,_=call(client,263,args.grant)
            result=dict(fields=fields,secure_erasure=False)
        elif args.command=='export':
            result=export(client,args.content,args.output)
        else:
            raw=args.input.read_bytes()  # Explicit import/bootstrap; guest validates all bytes.
            format_id=1 if args.format=='wave' else 2
            api=content.api(client)
            handle,manifest,chunks,proofs=content.reserve(api,raw,args.operation,identity(args.provider),
                identity(args.federation),durable=args.grant,format_id=format_id)
            for i,(chunk,proof) in enumerate(zip(chunks,proofs)):
                content.ingest_chunk(api,handle,i,chunk,proof)
            fields,_=api.objects(310,handle)
            if fields[1]!=handle:
                content.wait_job(api,fields[1])
                api.objects(305,fields[1],4)
            result=dict(content=handle,bytes=len(raw),sha256=content.sha(raw).hex(),
                        manifest_sha256=content.sha(manifest).hex(),format=args.format)
        print(json.dumps(result,indent=2))
        return 0
    finally:
        client.close()

if __name__=='__main__':
    raise SystemExit(main())
