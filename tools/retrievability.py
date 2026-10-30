"""Provision a bounded native fresh-data challenge over an approved Library relationship.

The guest chooses samples and verifies actual returned chunks and Merkle paths.
This adapter only transports explicit inputs and displays canonical guest results.
"""
import argparse
import json
from pathlib import Path
import struct
import live
import nodes

QUALIFICATION = ('Only the listed completed samples passed native chunk and Merkle verification. '
                 'This unsigned result does not prove permanent preservation, independent '
                 'administration, absence of collusion, remote attestation, or paid settlement.')
REASONS = {0: 'none', 1: 'selected provider relationship is unavailable or unauthenticated',
    2: 'verified service description is unavailable or has another role',
    3: 'scoped network grant was denied', 4: 'request transmission failed',
    5: 'proof response failed exact request/index/length binding',
    6: 'data response failed exact request/range/length binding',
    7: 'actual returned chunk hash differs from proof', 8: 'Merkle path differs from expected root',
    9: 'boot-relative challenge deadline expired', 10: 'invalid native phase',
    11: 'fresh native entropy unavailable', 12: 'bounded unique-sample selection exhausted'}


def call(client, instance, operation, h=0, a=0, b=0, c=0, d=0, e=0, data=b''):
    raw = client.request(150, struct.pack('<Q8Q', instance, operation, h, a, b, c, d, e, 1)+data)
    if len(raw) < 64:
        raise ValueError('short native retrievability response')
    fields = struct.unpack_from('<8Q', raw)
    if fields[0]:
        raise ValueError(f'native retrievability status{fields[0]}')
    return fields, raw[64:]


def manifest(path):
    raw = Path(path).read_bytes()
    if len(raw) != 256:
        description = json.loads(raw)
        raw = bytes.fromhex(description.get('manifest_hex') or description['manifest'])
    if len(raw) != 256:
        raise ValueError('explicit canonical manifest256 required')
    return raw


def result(fields, body):
    value = dict(operation=fields[1], state={0: 'idle', 1: 'active', 4: 'complete',
        5: 'cancelled', 7: 'failed'}.get(fields[2], 'unknown'), completed_samples=fields[3],
        requested_samples=fields[4], verified_response_bytes=fields[5], reason=fields[6],
        reason_text=(f'provider refused proof request (remote status{fields[6]-100})' if 101 <= fields[6] <= 116 else
                     f'provider refused data request (remote status{fields[6]-200})' if 201 <= fields[6] <= 216 else
                     REASONS.get(fields[6], 'unknown native refusal')),
        authority='selected native Network relationship; the result carries no reusable grant',
        durability='volatile native job; retaining its canonical result requires a separate approved scope',
        freshness='a new operation draws fresh entropy; an exact retry returns the previous outcome',
        time_basis='boot-relative monotonic ticks scoped to the recorded sampler incarnation',
        qualification=QUALIFICATION)
    if body:
        if len(body) != 736 or struct.unpack_from('<2Q', body) != (0x315254455254544c, 1):
            raise ValueError('unsupported canonical retrievability result')
        words = struct.unpack_from('<8Q', body)
        if not 0 <= words[5] <= words[4] <= 8:
            raise ValueError('invalid bounded native sample counts')
        value.update(nonce=body[64:96].hex(), manifest_sha256=body[96:128].hex(),
            merkle_root=body[128:160].hex(), provider=body[160:192].hex(),
            signed_description_sha256=body[192:224].hex(),
            transport_epoch=struct.unpack_from('<Q', body, 224)[0],
            sampler_incarnation=struct.unpack_from('<Q', body, 232)[0],
            started_tick=struct.unpack_from('<Q', body, 240)[0],
            deadline_tick=struct.unpack_from('<Q', body, 248)[0],
            finished_tick=struct.unpack_from('<Q', body, 256)[0],
            declared_payload_bytes=struct.unpack_from('<Q', body, 280)[0],
            declared_chunks=struct.unpack_from('<Q', body, 288)[0],
            broker_incarnation_epoch=struct.unpack_from('<Q', body, 304)[0],
            native_evidence_sha256=body[704:736].hex(), canonical_native_result=body.hex(),
            signature='none; native unsigned sampled-response evidence', host_data_verification=False,
            samples=[dict(index=struct.unpack_from('<Q', body, 320+i*48)[0],
                bytes=struct.unpack_from('<Q', body, 328+i*48)[0],
                actual_raw_sha256=body[336+i*48:368+i*48].hex()) for i in range(words[5])])
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket', type=Path, required=True)
    sub = parser.add_subparsers(dest='command', required=True)
    start = sub.add_parser('start')
    start.add_argument('--package', type=Path, required=True)
    start.add_argument('--public', type=Path, required=True)
    start.add_argument('--release-id', required=True)
    for name in ('submit', 'sample', 'inspect', 'wait', 'cancel'):
        p = sub.add_parser(name)
        p.add_argument('--instance', type=int, required=True)
        p.add_argument('--operation', type=int, required=True)
        if name in ('submit', 'sample'):
            p.add_argument('--slot', type=int, choices=(1, 2), required=True)
            p.add_argument('--manifest', type=Path, required=True)
            p.add_argument('--samples', type=int, choices=range(3, 9), default=8)
            p.add_argument('--deadline-ticks', type=int, default=3000)
    args = parser.parse_args(argv)
    client = live.Client(args.socket, timeout=180)
    try:
        if args.command == 'start':
            config = nodes.approved_package(args.package, args.public, args.release_id, 1025)
            value = dict(instance=nodes.start_package(client, config, nodes.validate_package(config)),
                rights=1025, role='bounded native sampled-response verifier')
        else:
            if args.command in ('submit', 'sample'):
                if not 0 < args.operation < 1 << 64 or not 0 < args.deadline_ticks <= 10000:
                    raise ValueError('nonzero operation word and deadline1..10000 ticks required')
                fields, body = call(client, args.instance, 740, args.slot, args.operation,
                    args.samples, args.deadline_ticks, 3, data=manifest(args.manifest))
                if args.command == 'sample':
                    fields, body = call(client, args.instance, 743, args.operation)
            else:
                fields, body = call(client, args.instance,
                    {'inspect': 741, 'wait': 743, 'cancel': 742}[args.command], args.operation)
            value = result(fields, body)
        print(json.dumps(value, indent=2))
        return 0
    finally:
        client.close()


if __name__ == '__main__':
    raise SystemExit(main())
