"""Actual guest release scope, publisher pin and signed profile boundary checks.

One existing QEMU image is used throughout. No OS image/source is rebuilt, patched
or replaced. Raw malformed fixtures bypass the host envelope inspector so only an
actual guest stage rejection satisfies a boundary assertion.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import time

from live_acceptance import (ROOT, Session, active, app, capsule, install,
                             passed, pkg, processes, release_file, releases,
                             require, start, trust, value)

EXPECTED_IMAGE = '6c8a9979bf46a33e03b8edbd8d39a421393139c7521de5479c16ac479cdc1c5e'


def raw_stage(client, raw):
    """Return only the actual guest's inspected header; do not inspect on host."""
    client.request(20, struct.pack('<Q', len(raw)))
    for offset in range(0, len(raw), 512):
        client.request(21, struct.pack('<Q', offset) + raw[offset:offset + 512])
    return client.request(22)


def require_guest_rejection(client, raw, label):
    try:
        raw_stage(client, raw)
    except ValueError as error:
        require('guest rejected command' in str(error), label + ': rejection was not issued by guest')
        client.request(3)
        return str(error)
    raise AssertionError(label + ': actual guest inspected forbidden envelope')


def signed_mutation(raw, key, directory, label, change):
    """Re-sign a malformed header, isolating profile checks from signature checks."""
    altered = bytearray(raw)
    change(altered)
    altered[160:192] = bytes(32)
    altered[160:192] = hashlib.sha256(altered[:512]).digest()
    header = directory / (label + '.header')
    header.write_bytes(altered[:512])
    signature = pkg.crypto(['dgst', '-sha256', '-sign', key, header]).stdout
    require(len(signature) == 256, 'fixture signing did not produce RSA2048 signature')
    altered[512:768] = signature
    return bytes(altered)


def check(expected_image):
    image = ROOT / 'build/live/guest.bin'
    original_image = image.read_bytes()
    image_id = hashlib.sha256(original_image).hexdigest()
    require(not expected_image or image_id == expected_image, 'existing image differs from explicitly selected identity')
    binary = ROOT / 'build/live/inspector.bin'
    require(binary.is_file(), 'build the independent native Inspector before running this check')
    run = ROOT / 'build/release-boundaries' / ('run-' + str(time.time_ns()))
    run.mkdir(parents=True)
    checks = []
    result = dict(schema=1, backend='qemu', image_sha256=image_id,
                  native_binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                  result='running', checks=checks, transport_log=str((run / 'transport.log').relative_to(ROOT)))
    report = ROOT / 'build/release-boundaries-evidence.json'
    try:
        with tempfile.TemporaryDirectory(prefix='lt-publisher-boundaries-') as temp:
            fixtures = Path(temp)
            key_a, public_a = fixtures / 'a.pem', fixtures / 'a.pub'
            key_b, public_b = fixtures / 'b.pem', fixtures / 'b.pub'
            capsule.generate_key(key_a, public_a)
            capsule.generate_key(key_b, public_b)
            modulus_a, modulus_b = capsule.modulus(key_a), capsule.modulus(key_b)
            require(modulus_a != modulus_b, 'explicit publisher fixtures unexpectedly share a key')
            result['publisher_key_ids'] = dict(a=hashlib.sha256(modulus_a).hexdigest(),
                                               b=hashlib.sha256(modulus_b).hexdigest())
            project_a, project_b = 'release-boundary-a', 'release-boundary-b'
            baseline, baseline_info = release_file(binary, project_a, '1.0.0', 1, key_a, fixtures)
            candidate, candidate_info = release_file(binary, project_a, '2.0.0', 1, key_b, fixtures,
                                                     parent=baseline_info['release_id'])
            with Session('qemu', run) as client:
                trust(client, project_a, key_a)
                trust(client, project_b, key_b)
                slot, info = install(client, baseline)
                instance = start(client, slot)
                selected = b'Explicit publisher boundary object\x00\xff\nNative Inspector must remain alive.\n'
                handle = client.import_object(selected)
                grant = client.objects(6, handle, instance, 1)[0][1]
                selected_hash = hashlib.sha256(selected).digest()
                result.update(project=project_a, baseline_release_id=info['release_id'],
                              candidate_release_id=candidate_info['release_id'],
                              selected_sha256=selected_hash.hex(), baseline_instance=instance)

                def unchanged():
                    require(active(client, project_a) == info['release_id'], 'rejection changed the active release')
                    require(client.read_object(handle) == selected, 'rejection changed selected object bytes')
                    header, digest = app(client, instance, 22, grant)
                    require(header[2] == len(selected) and digest == selected_hash,
                            'existing native Inspector lost scoped metadata authority')
                    header, content = app(client, instance, 4, grant, 0, len(selected))
                    require(header[1] == len(selected) and content == selected,
                            'existing native Inspector no longer reads its exact selected object')
                    row = next(row for row in processes(client) if row['instance'] == instance)
                    require(row['state'] in (1, 2, 3) and row['rights'] == 1,
                            'rejection stopped or changed authority of the baseline process')

                unchanged()
                error = require_guest_rejection(client, candidate.read_bytes(), 'publisher B trusted only for another project')
                unchanged()
                passed(checks, 'publisher trusted for project B cannot stage a signed project A candidate', rejection=error)

                trust(client, project_a, key_b)
                inspected = raw_stage(client, candidate.read_bytes())
                require(inspected == candidate.read_bytes()[:512], 'guest did not inspect the exact B-signed candidate')
                approval = bytes.fromhex(candidate_info['release_id']) + struct.pack('<Q', candidate_info['rights'])
                client.request(23, approval)
                try:
                    client.request(24)
                except ValueError as error:
                    require('guest rejected command24' in str(error), 'pin rejection did not occur at actual activation')
                    pin_error = str(error)
                else:
                    raise AssertionError('freshly approved publisher B replaced the existing publisher A project pin')
                client.request(3)
                unchanged()
                passed(checks, 'fresh approved B-signed A update is rejected by existing publisher pin; active A and native reads survive',
                       candidate_inspection='accepted', fresh_exact_approval='accepted', activation=pin_error)

                valid = baseline.read_bytes()
                def q(offset, number):
                    return lambda raw: struct.pack_into('<Q', raw, offset, number)
                malformed = [
                    ('reserved-tail', lambda raw: raw.__setitem__(488, 1)),
                    ('reserved-name-padding', lambda raw: raw.__setitem__(432 + len(project_a), 1)),
                    ('unknown-right-bit', q(64, 0x101)),
                    ('wrong-fixed-header-size', q(16, 256)),
                    ('wrong-machine-profile', q(40, 1)),
                    ('wrong-runtime-profile', q(48, 1)),
                    ('wrong-ipc-profile', q(56, 1)),
                    ('unsupported-dependencies', q(384, 1)),
                    ('unsupported-dependency-lock', q(392, 1)),
                    ('wrong-entry-count', q(400, 2)),
                    ('wrong-data-profile', q(408, 131072)),
                    ('wrong-stack-profile', q(416, 32768)),
                    ('wrong-entry-address', q(32, 0x400004)),
                ]
                for label, change in malformed:
                    raw = signed_mutation(valid, key_a, fixtures, label, change)
                    error = require_guest_rejection(client, raw, label)
                    unchanged()
                    passed(checks, 'actual guest rejects signed header: ' + label,
                           envelope_sha256=hashlib.sha256(raw).hexdigest(), rejection=error)
                layouts = [
                    ('truncated-code', valid[:-4]),
                    ('unaligned-code-length', valid[:-1]),
                    ('truncated-fixed-header', valid[:128]),
                    ('trailing-code-bytes', valid + bytes(4)),
                    ('old-128-byte-header-layout', valid[:128] + valid[512:]),
                    ('signature-before-header-layout', valid[512:768] + valid[:512] + valid[768:]),
                ]
                for label, raw in layouts:
                    error = require_guest_rejection(client, raw, label)
                    unchanged()
                    passed(checks, 'actual guest rejects envelope boundary: ' + label,
                           envelope_sha256=hashlib.sha256(raw).hexdigest(), rejection=error)
                passed(checks, 'active release, process rights and native/launcher selected-object reads remain unchanged after every rejection',
                       retained_instance=instance, selected_sha256=selected_hash.hex())
        require(image.read_bytes() == original_image, 'test altered the existing OS image')
        result['result'] = 'pass'
        result['os_image_unchanged'] = True
    except BaseException as error:
        result['result'] = 'fail'
        result['error'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        report.write_text(json.dumps(result, indent=2) + '\n')
    print('Evidence:', report, flush=True)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-image', default=EXPECTED_IMAGE)
    args = parser.parse_args()
    check(args.expected_image)
