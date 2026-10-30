"""Public provisioning portal for the Lean Identity-v1 broker.

This adapter builds no identities and never receives their private keys. Package
publisher provisioning uses the existing, explicitly disclosed RSA bootstrap.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import struct
import live
import releases

ROLES = {'project': 1, 'messenger': 2, 'node': 3, 'receipt': 4}
PURPOSES = {'contact': 1, 'service': 2}
OPERATIONS = tuple(range(400, 408))
IDENTITY_MAGIC = 0x314449544c
SIGNING_MAGIC = 0x31474953544c
CONTACT_MAGIC = 0x315443544c
NODE_MAGIC = 0x31444e544c


def digest(value):
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError('expected an exact 32-byte hexadecimal commitment') from exc
    if len(raw) != 32 or not any(raw):
        raise ValueError('expected a nonzero exact 32-byte commitment')
    return raw


def fields(raw):
    if len(raw) < 64:
        raise ValueError('truncated Identity-v1 response')
    values = struct.unpack_from('<8Q', raw)
    if values[0]:
        names = {1: 'authorization denied', 2: 'malformed request', 3: 'stale or revoked authority',
                 4: 'finite capacity exhausted', 6: 'entropy unavailable', 7: 'unsupported operation'}
        raise ValueError('Identity: ' + names.get(values[0], f'status {values[0]}'))
    return values, raw[64:]


def instances(client):
    raw = client.request(2)
    return [struct.unpack_from('<4Q', raw, i) for i in range(0, len(raw), 32)]


def bind(client, service, caller, service_release, caller_release, operation, prior=0):
    if operation not in OPERATIONS:
        raise ValueError('Identity-v1 operation outside 400..407')
    if len(service_release) != 32 or len(caller_release) != 32:
        raise ValueError('exact admitted release commitments required')
    body = struct.pack('<6Q', 1, 1, service, caller, operation, prior)
    raw = client.request(171, body + service_release + caller_release + bytes(16))
    if len(raw) != 8:
        raise ValueError('truncated kernel service-binding result')
    return struct.unpack_from('<Q', raw)[0]


def endpoint(client, operation):
    raw = client.request(172, struct.pack('<2Q', 1, operation))
    if len(raw) != 8:
        raise ValueError('truncated kernel endpoint result')
    target = struct.unpack_from('<Q', raw)[0]
    if target == 2**64-1:
        raise ValueError('Identity: no current service binding for this operation')
    return target


def invoke(client, op, h=0, a=0, b=0, c=0, data=b''):
    target = endpoint(client, op)
    raw = client.request(150, struct.pack('<Q8Q', target, op, h, a, b, c, 0, 0, 1) + data)
    return fields(raw)


def start(client, release_path, public_path):
    raw = Path(release_path).read_bytes()
    info = releases.inspect(raw)
    if info['rights'] != 0 or struct.unpack_from('<Q', raw, 400)[0] != 2:
        raise ValueError('Identity service must use profile2 with exactly zero package rights')
    # Explicit operator-selected publisher pin, before normal signature admission.
    client.request(10, raw[128:160] + releases.public_modulus(public_path))
    slot, admitted = client.install(release_path)
    service = struct.unpack_from('<Q', client.request(25, struct.pack('<Q', slot)), 8)[0]
    launcher = next(row[0] for row in instances(client) if row[0] & 255 == 1)
    try:
        generations = {op: bind(client, service, launcher, bytes.fromhex(admitted['release_id']), bytes(32), op)
                       for op in OPERATIONS}
    except BaseException:
        # Stop only the process created by this attempt. Kernel teardown revokes
        # its partial bindings and preserves any independently running signer.
        try:
            client.request(26, struct.pack('<Q', service))
        except (ValueError, OSError, EOFError, TimeoutError):
            pass
        raise
    return {'service': service, 'release': admitted['release_id'], 'rights': 0,
            'bindings': generations, 'retention': 'ephemeral'}


def decode_public(payload):
    if len(payload) != 288 or struct.unpack_from('<2Q', payload) != (IDENTITY_MAGIC, 1):
        raise ValueError('invalid public Identity-v1 descriptor')
    if hashlib.sha256(payload[:192]).digest() != payload[256:288]:
        raise ValueError('public descriptor fingerprint mismatch')
    return {'role': struct.unpack_from('<Q', payload, 16)[0],
            'generation': struct.unpack_from('<Q', payload, 24)[0],
            'federation': payload[32:64].hex(), 'scope': payload[64:96].hex(),
            'public_key': payload[96:128].hex(), 'fingerprint': payload[256:288].hex(),
            'signature': payload[192:256].hex(), 'retention': 'ephemeral',
            'validity': 'explicit revocation; no reboot-relative expiry',
            'person_identity': 'not established by this self-signed descriptor'}


def main(argv=None):
    parser = argparse.ArgumentParser(description='Native scoped identities; no host identity secrets')
    parser.add_argument('--socket', type=Path, required=True)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('start'); p.add_argument('--release', required=True, type=Path); p.add_argument('--public', required=True, type=Path)
    p = sub.add_parser('bind'); p.add_argument('--service', required=True, type=int); p.add_argument('--service-release', required=True)
    p.add_argument('--caller', required=True, type=int); p.add_argument('--caller-release', required=True)
    p.add_argument('--operation', required=True, type=int, choices=OPERATIONS); p.add_argument('--generation', default=0, type=int)
    p = sub.add_parser('create'); p.add_argument('--role', required=True, choices=ROLES); p.add_argument('--federation', required=True); p.add_argument('--scope', required=True); p.add_argument('--output', type=Path)
    p = sub.add_parser('export'); p.add_argument('key', type=int); p.add_argument('--output', required=True, type=Path)
    p = sub.add_parser('approve'); p.add_argument('--key', required=True, type=int); p.add_argument('--recipient', required=True, type=int); p.add_argument('--purpose', required=True, choices=PURPOSES); p.add_argument('--body', required=True, type=Path)
    p = sub.add_parser('certify'); p.add_argument('permit', type=int); p.add_argument('--body', required=True, type=Path); p.add_argument('--output', required=True, type=Path)
    p = sub.add_parser('revoke'); p.add_argument('key', type=int)
    p = sub.add_parser('cancel-approval'); p.add_argument('permit', type=int)
    sub.add_parser('lock'); sub.add_parser('status')
    p = sub.add_parser('revoke-binding'); p.add_argument('--caller', default=0, type=int); p.add_argument('--operation', default=0, type=int); p.add_argument('--generation', default=0, type=int)
    args = parser.parse_args(argv)
    client = live.Client(args.socket, timeout=180)
    try:
        if args.command == 'start':
            result = start(client, args.release, args.public)
        elif args.command == 'bind':
            result = {'generation': bind(client, args.service, args.caller, digest(args.service_release),
                                         bytes(32) if args.caller & 255 <= 6 else digest(args.caller_release),
                                         args.operation, args.generation)}
        elif args.command in ('create', 'export'):
            if args.command == 'create':
                f, payload = invoke(client, 400, a=ROLES[args.role], data=digest(args.federation)+digest(args.scope))
            else:
                f, payload = invoke(client, 401, h=args.key)
            result = dict(key=f[1], **decode_public(payload))
            if args.output:
                args.output.write_bytes(payload)
        elif args.command == 'approve':
            body = args.body.read_bytes()
            purpose = PURPOSES[args.purpose]
            if len(body) != (128 if purpose == 1 else 256):
                raise ValueError('canonical body must be128 contact or256 service bytes')
            f, _ = invoke(client, 405, h=args.key, a=args.recipient, b=purpose, c=len(body), data=hashlib.sha256(body).digest())
            result = {'permit': f[1], 'purpose': purpose, 'bytes': len(body), 'uses': 1}
        elif args.command == 'certify':
            body = args.body.read_bytes()
            if len(body) not in (128, 256):
                raise ValueError('unsupported certificate body size')
            f, payload = invoke(client, 402, h=args.permit, data=body)
            args.output.write_bytes(payload)
            result = {'key': f[1], 'purpose': f[2], 'signed_bytes': f[3], 'output': str(args.output)}
        elif args.command == 'revoke-binding':
            raw = client.request(173, struct.pack('<4Q', 1, args.caller, args.operation, args.generation))
            result = {'revoked': struct.unpack_from('<Q', raw)[0]}
        elif args.command == 'cancel-approval':
            f, _ = invoke(client, 407, h=args.permit)
            result = {'cancelled': f[1]}
        else:
            op = {'revoke':403, 'lock':404, 'status':406}[args.command]
            f, _ = invoke(client, op, h=getattr(args, 'key', 0))
            result = {'status': f[0], 'profile': f[1], 'key_limit': f[2], 'approval_limit': f[3],
                      'active_keys': f[4], 'active_approvals': f[5], 'retention': 'ephemeral'}
        print(json.dumps(result, indent=2))
    finally:
        client.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
