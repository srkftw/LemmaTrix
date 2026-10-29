"""Actual headless BuildJobs admission, revocation and incarnation boundaries."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'tools'), str(ROOT / 'tests')]
import live
import projects
import releases
from forge_journey import wait


def probe(client, instance, op, handle=0):
    raw = client.request(150, struct.pack('<Q', instance) + struct.pack('<8Q', op, handle, 0, 0, 0, 0, 0, 1))
    assert len(raw) >= 64
    return struct.unpack_from('<8Q', raw), raw


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=ROOT / 'build/build-requester')
    parser.add_argument('--binary', type=Path, default=ROOT / 'build/live/apps/build-request-probe.bin')
    parser.add_argument('--operator-key', type=Path, default=ROOT / 'build/forge-server-recovery-final2/operator.pem')
    parser.add_argument('--operator-public', type=Path, default=ROOT / 'build/forge-server-recovery-final2/operator.pub')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    package = args.output / 'headless-build-probe.ltrel'
    if not package.exists():
        raw, manifest = releases.make(args.binary, 'headless-build-probe', '0.4.0', 127,
            args.operator_key, profile=2, sources=[ROOT / 'tests/fixtures/BuildRequesterProbe.lean'], source_base=ROOT)
        package.write_bytes(raw)
        Path(str(package) + '.manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    info = releases.inspect(package.read_bytes())
    assert info['rights'] == 127 and info['executable_sha256'] == hashlib.sha256(args.binary.read_bytes()).hexdigest()
    sock = args.output / 'portal.sock'
    if sock.exists():
        raise ValueError('refusing to replace an existing guest endpoint')
    log = (args.output / 'guest.log').open('wb')
    process = subprocess.Popen([str(ROOT / 'lt'), 'run', '--image', str(args.image.resolve()), '--socket', str(sock)],
        cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    client = None
    report = dict(image=hashlib.sha256(args.image.read_bytes()).hexdigest(), backend='qemu',
        probe_rights=127, host_compiler_executions=0, checks=[])

    def passed(label, **fields):
        report['checks'].append(dict(check=label, result='pass', **fields))
        (args.output / 'evidence.json').write_text(json.dumps(report, indent=2) + '\n')
        print('PASS', label, flush=True)

    try:
        wait(sock.exists, 'guest boot', 60)
        client = live.Client(sock, timeout=30)
        raw = package.read_bytes()
        client.request(10, raw[128:160] + releases.public_modulus(args.operator_public))
        slot, _ = client.install(package)
        instance = struct.unpack_from('<Q', client.request(25, struct.pack('<Q', slot)), 8)[0]
        source = b'import Guest.LiveSDK\nnamespace Main\ndef main (t : UInt64) : UInt64 := Guest.LiveSDK.syscall 10 0 0 0 0 t\nend Main\n'
        source_id = projects.canonical_node(10, source)
        manifest = projects.manifest([('Main.lean', 10, source_id)])
        head = projects.canonical_node(11, manifest)
        root = projects.import_records(client, [dict(name='headless-authorized-input', head=head)],
            [dict(kind=11, id=head, payload=manifest), dict(kind=10, id=source_id, payload=source)])[0]['cap']
        granted = client.objects(27, root, instance, 127)[0][1]
        assert struct.unpack('<Q', client.request(183))[0] == 0
        assert probe(client, instance, 1, granted)[0][0] == 0xffffffffffffffff
        passed('headless caller cannot enqueue through object read authority alone', instance=instance)
        client.request(182, struct.pack('<Q', instance))
        assert struct.unpack('<Q', client.request(183))[0] == instance
        fields, job = probe(client, instance, 1, granted)
        assert fields[0] == 0 and fields[1] and fields[2] == 1 and len(job) == 256
        assert job[64:96].hex() == head
        job_id = fields[1]
        assert probe(client, instance, 4, job_id)[0][2] == 1
        assert probe(client, instance, 2)[0][0] != 0, 'enqueue grant supplied admin queue inspection'
        assert probe(client, instance, 6)[0][0] == 0xffffffffffffffff, 'enqueue grant supplied networking'
        assert probe(client, instance, 5, job_id)[0][0] == 0
        passed('explicit full-incarnation grant admits and cancels actual frozen job only', job=job_id, source_root=head, build_service=fields[3], compiler_run=False, network_denied=True, admin_queue_denied=True)
        client.request(182, struct.pack('<Q', 0))
        assert struct.unpack('<Q', client.request(183))[0] == 0
        assert probe(client, instance, 1, granted)[0][0] == 0xffffffffffffffff
        passed('revocation denies subsequent enqueue without changing source', instance=instance)
        client.request(182, struct.pack('<Q', instance))
        client.request(26, struct.pack('<Q', instance))
        replacement = struct.unpack_from('<Q', client.request(25, struct.pack('<Q', slot)), 8)[0]
        assert replacement != instance and replacement & 255 == instance & 255
        assert struct.unpack('<Q', client.request(183))[0] == instance
        fresh = client.objects(27, root, replacement, 127)[0][1]
        assert probe(client, replacement, 1, fresh)[0][0] == 0xffffffffffffffff
        try:
            client.request(182, struct.pack('<Q', instance))
        except ValueError:
            pass
        else:
            raise AssertionError('dead incarnation was accepted for a new operator grant')
        client.request(182, struct.pack('<Q', replacement))
        fields, job = probe(client, replacement, 1, fresh)
        assert fields[0] == 0 and fields[2] == 1 and job[64:96].hex() == head
        assert probe(client, replacement, 5, fields[1])[0][0] == 0
        client.request(182, struct.pack('<Q', 0))
        passed('slot reuse inherits no old incarnation grant; fresh explicit grant required', old=instance, replacement=replacement, source_root=head)
        report['result'] = 'pass'
    except BaseException as error:
        report.update(result='fail', error=repr(error))
        raise
    finally:
        (args.output / 'evidence.json').write_text(json.dumps(report, indent=2) + '\n')
        if client:
            try:
                client.request(70)
            except (OSError, EOFError, ValueError):
                pass
            client.close()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        log.close()


if __name__ == '__main__':
    main()
