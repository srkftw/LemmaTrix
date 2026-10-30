"""Provision and inspect guest-owned recoverable zero-price operator jobs.

The adapter passes canonical terms and fresh selected process identities only.
Lifecycle, idempotency, durable reservation and recovery execute in Vault.
"""
import argparse
import hashlib
import json
import struct
import tempfile
from pathlib import Path
import live
import network
import capsule
import releases

STATES = {1: 'queued', 2: 'active', 3: 'paused', 4: 'complete', 5: 'cancelled',
          6: 'awaiting-fresh-authority', 7: 'failed', 8: 'exhausted'}
ROLES = {'retrieval': 1, 'storage': 2, 'builder': 3, 'verifier': 4}


def call(client, op, slot=0, a=0, b=0, c=0, data=b'', allow=()):
    raw = client.request(op, struct.pack('<8Q', op, slot, a, b, c, 0, 0, 1) + data)
    if len(raw) < 64:
        raise ValueError('short native service job response')
    fields = struct.unpack_from('<8Q', raw)
    if fields[0] not in (0, *allow):
        raise ValueError(f'native service job status {fields[0]} (slot {slot})')
    return fields, raw[64:]


def terms(operation, requester, root, policy, role, generation, budget,
          attempts, quanta, description, resume=True, expected=None):
    return b''.join(network.digest(v) for v in (operation, requester, root, policy)) + struct.pack(
        '<8Q', ROLES[role], generation, 3, budget, attempts, quanta, 3 if resume else 2, 0
    ) + network.digest(description) + (network.digest(expected) if expected else bytes(32))


def submit(client, slot, canonical):
    if len(canonical) != 256:
        raise ValueError('ServiceTerms-v1 must contain exactly 256 canonical bytes')
    return call(client, 281, slot, data=canonical)[0][1]


def inspect(client, slot):
    fields, raw = call(client, 285, slot, allow=(3,))
    if fields[0] == 3:
        return None
    if len(raw) != 512:
        raise ValueError('wrong native service record length')
    q = struct.unpack('<64Q', raw)
    return dict(slot=slot, generation=q[3], state=STATES[q[4]],
                reserved_transmission_bytes=q[5], checkpoint=q[6], attempts=q[7],
                operation=raw[64:96].hex(), requester=raw[96:128].hex(),
                input_root=raw[128:160].hex(), policy=raw[160:192].hex(),
                role=next(k for k, v in ROLES.items() if v == q[24]),
                policy_generation=q[25], mode=q[26], byte_ceiling=q[27],
                attempt_ceiling=q[28], work_quantum_ceiling=q[29],
                automatic_resume=bool(q[30] & 1), price=q[31],
                description=raw[256:288].hex(), expected_result=raw[288:320].hex(),
                request_sha256=raw[320:352].hex(), result_root=raw[352:384].hex(),
                result_bytes=q[48], reason=q[49], consumed_work_quanta=q[50],
                time_basis='remaining admitted work quanta; no absolute wall-clock expiry',
                accounting='provider reservation before transmission; client acceptance unasserted',
                settlement='unavailable; voluntary zero-price',
                live_authority_persisted=False)


def sign(client, slot, signing_key):
    # This disclosed bootstrap can sign only a fixed native-prepared receipt
    # for a persisted approved operation, never a caller-provided message/file.
    _, body = call(client, 294, slot)
    if len(body) != 256 or struct.unpack_from('<2Q', body) != (0x315043525653544c, 1):
        raise ValueError('native canonical service receipt unavailable')
    role = struct.unpack_from('<Q', body, 24)[0]
    public = capsule.modulus(Path(signing_key))
    call(client, 293, role, data=public)
    with tempfile.TemporaryDirectory(prefix='lt-service-receipt-sign-') as temporary:
        source = Path(temporary) / 'native-receipt'
        source.write_bytes(body)
        signature = releases.pkg.crypto(['dgst', '-sha256', '-sign', Path(signing_key), source]).stdout
    if len(signature) != 256:
        raise ValueError('RSA2048/SHA256 service receipt signature required')
    raw = client.request(160, struct.pack('<8Q', 17, slot, 0, 0, 0, 0, 0, 1) + body + signature)
    if len(raw) != 64 or struct.unpack_from('<Q', raw)[0]:
        raise ValueError('native exact-terms service receipt verification/commit rejected')
    return read_receipt(client, slot)


def read_receipt(client, slot):
    raw = client.request(160, struct.pack('<8Q', 18, slot, 0, 0, 0, 0, 0, 1))
    if len(raw) != 832 or struct.unpack_from('<Q', raw)[0] or struct.unpack_from('<Q', raw, 16)[0] != 1:
        raise ValueError('native scoped receipt signature verification failed or no receipt is retained')
    body, signature, public = raw[64:320], raw[320:576], raw[576:832]
    q = struct.unpack('<32Q', body)
    return dict(schema=1, state=STATES[q[2]], role=next(k for k, v in ROLES.items() if v == q[3]),
                record_generation=q[4], reserved_transmission_bytes=q[5], checkpoint=q[6], attempts=q[7],
                operation=body[64:96].hex(), requester=body[96:128].hex(), input_root=body[128:160].hex(),
                exact_terms_sha256=body[160:192].hex(), result_root=body[192:224].hex(),
                result_bytes=q[28], consumed_work_quanta=q[29], policy_generation=q[30],
                provider_assertion=bool(q[31] & 1), failure_reason=q[31] >> 32,
                client_integrity_acceptance='not asserted', independent_verification='not asserted',
                settlement='unavailable; voluntary zero-price', remote_attestation=False, zero_knowledge=False,
                signature='RSA2048/SHA256 verified in the guest', provider_key_sha256=hashlib.sha256(public).hexdigest(),
                receipt_sha256=hashlib.sha256(body + signature).hexdigest(),
                canonical_body=body.hex(), signature_bytes=signature.hex(), public_modulus=public.hex(),
                signer_boundary='explicit host bootstrap outside the key-free network-disabled compiler sandbox')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket', type=Path, required=True)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('recover')
    commands.add_parser('list')
    command = commands.add_parser('submit')
    command.add_argument('--slot', type=int, choices=range(16), required=True)
    for name in ('operation', 'requester', 'root', 'policy', 'description'):
        command.add_argument('--' + name, required=True)
    command.add_argument('--role', choices=ROLES, required=True)
    command.add_argument('--generation', type=int, required=True)
    command.add_argument('--bytes', type=int, required=True)
    command.add_argument('--attempts', type=int, default=32)
    command.add_argument('--quanta', type=int, default=1000000)
    command.add_argument('--await-approval-after-restart', action='store_true')
    command.add_argument('--expected-result')
    for name in ('inspect', 'bind', 'pause', 'drain', 'cancel', 'retry', 'forget'):
        command = commands.add_parser(name)
        command.add_argument('--slot', type=int, choices=range(16), required=True)
        if name == 'bind':
            command.add_argument('--instance', type=int, required=True)
    command = commands.add_parser('sign')
    command.add_argument('--slot', type=int, choices=range(16), required=True)
    command.add_argument('--sign-key', type=Path, required=True)
    command = commands.add_parser('receipt')
    command.add_argument('--slot', type=int, choices=range(16), required=True)
    args = parser.parse_args(argv)
    client = live.Client(args.socket)
    try:
        call(client, 280)
        if args.command == 'recover':
            result = dict(records=[r for i in range(16) if (r := inspect(client, i))],
                          fresh_authority_required=True)
        elif args.command == 'list':
            result = [r for i in range(16) if (r := inspect(client, i))]
        elif args.command == 'submit':
            canonical = terms(args.operation, args.requester, args.root, args.policy,
                              args.role, args.generation, args.bytes, args.attempts,
                              args.quanta, args.description,
                              not args.await_approval_after_restart, args.expected_result)
            result = inspect(client, submit(client, args.slot, canonical))
        elif args.command == 'inspect':
            result = inspect(client, args.slot)
        elif args.command == 'sign':
            result = sign(client, args.slot, args.sign_key)
        elif args.command == 'receipt':
            result = read_receipt(client, args.slot)
        else:
            call(client, dict(bind=282, pause=286, drain=286, cancel=288, retry=289, forget=299)[args.command],
                 args.slot, getattr(args, 'instance', 0))
            result = inspect(client, args.slot)
    finally:
        client.close()
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
