"""Opaque setup/inspection adapter for guest-owned intentional content archives.

No host content index, validation, decoder, personal retention or server job
scheduler is implemented here. Every online archive operation executes in Lean.
"""
import argparse
import json
import struct
import time
from pathlib import Path
import content
from live import Client


def call(client, op, handle=0, a=0, b=0, c=0, d=0, data=b'', e=0):
    raw = client.request(op, struct.pack('<8Q', op, handle, a, b, c, d, e, 1) + data)
    if len(raw) < 64:
        raise ValueError('short ServerContent reply')
    fields = struct.unpack_from('<8Q', raw)
    if fields[0]:
        raise ValueError(f'ServerContent status{fields[0]}')
    return fields, raw[64:]


def permit(client, owner, namespace, manifest, budget, slot=0):
    if len(namespace) != 32 or len(manifest) != 32:
        raise ValueError('exact selected namespace and immutable manifest SHA256 required')
    return call(client, 250, a=owner, b=budget, c=2, d=3, data=namespace + manifest, e=slot)[0][1]


def wait(client, grant, operation, timeout=3600):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        fields, payload = call(client, 252, grant)
        if fields[1] != operation:
            raise ValueError('server operation identity changed')
        if fields[2] >= 4:
            if fields[2] != 4:
                raise ValueError(f'ServerContent terminal state{fields[2]}, reason{fields[6]}')
            return fields, payload
        time.sleep(.02)
    raise TimeoutError('server completion remains queryable; timeout does not roll back committed data')


def retain(client, grant, selected, operation, metadata=None):
    client = content.api(client)
    vault = struct.unpack_from('<Q', client.request(2), 96)[0]
    delegated = client.objects(308, selected, vault)[0][1]
    delegated_metadata = client.objects(6, metadata, vault, 25)[0][1] if metadata else 0
    try:
        call(client, 251, grant, delegated, delegated_metadata, operation)
        fields, _ = wait(client, grant, operation)
    finally:
        if delegated_metadata:
            client.objects(7, metadata, delegated_metadata)
    return {'operation': fields[1], 'state': fields[2], 'bytes': fields[4], 'generation': fields[5],
            'retention': 'explicit authorized operator namespace; purpose2; intentional plaintext'}


def recover(client, grant, operation, recipient=None):
    if recipient is None:
        recipient = struct.unpack_from('<Q', client.request(2), 32)[0]
    call(client, 253, grant, recipient, operation)
    fields, payload = wait(client, grant, operation)
    return {'operation': fields[1], 'state': fields[2], 'bytes': fields[4], 'generation': fields[5],
            'content_handle': struct.unpack_from('<Q', payload)[0],
            'metadata_handle': struct.unpack_from('<Q', payload, 8)[0] if len(payload) >= 16 else 0,
            'recipient': recipient, 'restored_network_or_execution_authority': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket', required=True, type=Path)
    commands = parser.add_subparsers(dest='command', required=True)
    p = commands.add_parser('permit')
    p.add_argument('--owner', type=int, required=True)
    p.add_argument('--namespace', required=True)
    p.add_argument('--manifest-sha256', required=True)
    p.add_argument('--bytes', type=int, required=True)
    p.add_argument('--slot', type=int, choices=range(4), default=0)
    for name in ('retain', 'recover', 'inspect', 'revoke'):
        p = commands.add_parser(name)
        p.add_argument('--grant', type=int, required=True)
        if name in ('retain', 'recover'):
            p.add_argument('--operation', type=int, required=True)
        if name == 'retain':
            p.add_argument('--content', type=int, required=True)
            p.add_argument('--metadata', type=int)
        if name == 'recover':
            p.add_argument('--recipient', type=int)
    args = parser.parse_args(argv)
    client = Client(args.socket, timeout=180)
    try:
        if args.command == 'permit':
            result = {'grant': permit(client, args.owner, bytes.fromhex(args.namespace),
                                      bytes.fromhex(args.manifest_sha256), args.bytes, args.slot)}
        elif args.command == 'retain':
            result = retain(client, args.grant, args.content, args.operation, args.metadata)
        elif args.command == 'recover':
            result = recover(client, args.grant, args.operation, args.recipient)
        elif args.command == 'inspect':
            fields, manifest = call(client, 255, args.grant)
            result = {'generation': fields[1], 'bytes': fields[3], 'chunks': fields[5],
                      'manifest_sha256': content.sha(manifest).hex()}
        else:
            result = {'revoked': call(client, 256, args.grant)[0][1]}
    finally:
        client.close()
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
