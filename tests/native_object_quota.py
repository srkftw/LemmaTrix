"""Installed rights799 Objects quota separation, with real native SDK calls.

Graph records remain uncommitted stages. The only committed record is an
opaque public profile, checked through native append/commit/read. This is a
quota regression probe, not evidence of a committed project or Feed account.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'tools'), str(ROOT/'tests')]
import live_build
import messenger
import releases
from messenger_journey import Guest, PUB, SIGN


class Actor:
    def __init__(self, guest, instance):
        self.guest, self.instance = guest, instance

    def call(self, operation, handle=0, a=0, b=0, data=b'', allowed=(0,)):
        raw = self.guest.client.request(150, struct.pack(
            '<Q8Q', self.instance, operation, handle, a, b, 0, 0, 0, 1)+data)
        assert len(raw) >= 64
        fields = struct.unpack_from('<8Q', raw)
        assert fields[0] in allowed, (operation, fields)
        return fields, raw[64:]

    def stage(self, size, kind, allowed=(0,)):
        fields, _ = self.call(1, a=size, b=kind, allowed=allowed)
        if fields[0] == 0:
            assert fields[1] != 0 and fields[2] == size and fields[4] == kind and fields[5] == 1, fields
        return fields

    def abort(self, handles):
        for handle in handles:
            self.call(13, handle)


def check(backend, out, image, package):
    out.mkdir()
    started = time.monotonic()
    report = dict(backend=backend, aarch64_emulated=backend == 'aarch64', checks=[])
    guest = Guest('quota', backend, out, image).start()

    def passed(label, **detail):
        report['checks'].append(dict(check=label, result='pass', **detail))
        print('PASS', backend, label, detail, flush=True)

    try:
        instance, _ = messenger.install(guest.client, package, PUB, 799)
        actor = Actor(guest, instance)
        report['native_instance'] = instance
        graph = [actor.stage(64, 10)[1] for _ in range(8)]
        profile = bytearray(2048)
        struct.pack_into('<3Q', profile, 0, 0x3154524f5046544c, 1, 0)
        note = b'Public quota probe: profile storage remains usable after graph staging; no author keys or account state.'
        profile[256:256+len(note)] = note
        profile = bytes(profile)
        digest = hashlib.sha256(profile).digest()
        profile_handle = actor.stage(len(profile), 6)[1]
        for offset in range(0, len(profile), 512):
            chunk = profile[offset:offset+512]
            fields, _ = actor.call(2, profile_handle, offset, data=chunk)
            assert fields[1] == offset+len(chunk), fields
        committed, native_digest = actor.call(3, profile_handle, data=digest)
        assert committed[1] == profile_handle and committed[5] == 2 and native_digest == digest
        read = b''.join(actor.call(4, profile_handle, offset, 512)[1] for offset in range(0, len(profile), 512))
        assert read == profile
        passed('eight graph stages do not prevent native commit/read of an ordinary public profile',
               graph_stages=8, profile_bytes=len(profile), profile_sha256=digest.hex(), native_commit=list(committed))

        ordinary = [actor.stage(1, 6)[1] for _ in range(7)]
        refused = actor.stage(0, 6, allowed=(4,))
        passed('eight ordinary records retain their independent record ceiling', ordinary_records=8, next_ordinary_status=refused[0])
        graph += [actor.stage(1, 10)[1] for _ in range(8)]
        aggregate_refused = actor.stage(0, 10, allowed=(4,))
        passed('mixed ordinary and graph records retain the aggregate24 ceiling',
               ordinary_records=8, graph_stages=len(graph), next_graph_status=aggregate_refused[0])
        actor.abort(ordinary+graph)
        actor.call(8, profile_handle)
        reclaimed = actor.stage(1, 6)[1]
        actor.abort([reclaimed])
        passed('explicit abort and profile drop reclaim the accepted reservations')

        graph = [actor.stage(65536, 10)[1] for _ in range(4)]
        ordinary = [actor.stage(65536, 6)[1] for _ in range(4)]
        ordinary_refused = actor.stage(1, 6, allowed=(4,))
        passed('graph256KiB does not consume the ordinary256KiB allowance; its own next byte refuses',
               graph_reserved_bytes=262144, ordinary_reserved_bytes=262144,
               ordinary_records=4, next_ordinary_status=ordinary_refused[0])
        graph += [actor.stage(65536, 10)[1] for _ in range(8)]
        aggregate_refused = actor.stage(1, 10, allowed=(4,))
        passed('mixed reservations retain the aggregate1MiB byte ceiling below the24-record ceiling',
               records=len(graph)+len(ordinary), aggregate_reserved_bytes=1048576,
               next_graph_status=aggregate_refused[0])
        actor.abort([graph.pop()])
        reused = actor.stage(65536, 10)[1]
        actor.abort(ordinary+graph+[reused])
        passed('aggregate byte exhaustion reclaims and reuses exactly one aborted reservation')
        report['result'] = 'pass'
    except BaseException as error:
        report.update(result='fail', error=repr(error), traceback=traceback.format_exc())
        raise
    finally:
        report['seconds'] = time.monotonic()-started
        (out/'evidence.json').write_text(json.dumps(report, indent=2)+'\n')
        guest.stop()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--backend', action='append', choices=('qemu', 'x86_64', 'aarch64'))
    parser.add_argument('--binary', type=Path, help='use an already compiled exact ObjectQuotaProbe binary')
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    image = out/'guest.bin'
    image.write_bytes(args.image.read_bytes())
    binary = args.binary or live_build.app('tests.fixtures.ObjectQuotaProbe', 'Guest.ObjectQuotaProbe.main', 'object-quota-probe', 2)
    package = out/'object-quota-probe.ltrel'
    raw, _ = releases.make(binary, 'object-quota-probe', '0.9.0', 799, SIGN, profile=2, license='NOASSERTION')
    package.write_bytes(raw)
    report = dict(schema=1, image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),
                  source_head=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                  probe_rights=799, probe_code_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                  probe_release=releases.inspect(raw)['release_id'], checks=[],
                  limits=['Installed ordinary app and actual native Objects SDK/IPC; graph records are uncommitted reservations, not fabricated project evidence.',
                          'The committed opaque profile proves ordinary storage remains available, not Feed identity recovery or project Fork itself.',
                          'AArch64 backend, if selected, is emulated; no physical hardware qualification.'])
    try:
        for backend in args.backend or ('qemu', 'aarch64'):
            report['checks'].append(check(backend, out/backend, image, package))
        report['result'] = 'pass'
    except BaseException as error:
        report.update(result='fail', error=repr(error))
        raise
    finally:
        (out/'evidence.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2), flush=True)


if __name__ == '__main__':
    main()
