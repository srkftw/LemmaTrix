"""A live app cannot reuse a Store grant after its service restarts/regrants."""
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
import releases
import server_store
from forge_journey import wait


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--image', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--binary', type=Path, default=ROOT / 'build/live/apps/import-quota-probe.bin')
    parser.add_argument('--key', type=Path, default=ROOT / 'build/signed-forge-journey-2/publisher.pem')
    parser.add_argument('--public', type=Path, default=ROOT / 'build/signed-forge-journey-2/publisher.pub')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    package = args.output / 'probe.ltrel'
    raw, manifest = releases.make(args.binary, 'store-grant-probe', '0.4.0', 2175, args.key, profile=2)
    package.write_bytes(raw)
    Path(str(package) + '.manifest.json').write_text(json.dumps(manifest, sort_keys=True, separators=(',', ':')))
    backing = args.output / 'server.img'
    server_store.provision(backing)
    socket = args.output / 'portal.sock'
    log = (args.output / 'guest.log').open('wb')
    process = subprocess.Popen([str(ROOT / 'lt'), 'run', '--image', str(args.image.resolve()),
                                '--socket', str(socket), '--server-store', str(backing)],
                               cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    client = None
    report = dict(image=hashlib.sha256(args.image.read_bytes()).hexdigest(), backend='qemu',
                  probe_rights=2175, server_format=1, purpose='lt-server-v1',
                  project_compilations=0, checks=[])

    def record(label, **fields):
        report['checks'].append(dict(check=label, result='pass', **fields))
        print('PASS', label, flush=True)

    try:
        wait(socket.exists, 'server grant test guest boot', 60)
        client = live.Client(socket, timeout=60)
        client.request(10, releases.project('store-grant-probe') + releases.public_modulus(args.public))
        slot, _ = client.install(package)
        instance = struct.unpack_from('<Q', client.request(25, struct.pack('<Q', slot)), 8)[0]

        def app(op, handle, a=0, b=0, data=b'', status=0):
            raw = client.request(150, struct.pack('<Q8Q', instance, op, handle, a, b, 0, 0, 0, 1) + data)
            assert len(raw) >= 64, (op, len(raw))
            fields = struct.unpack_from('<8Q', raw)
            assert fields[0] == status, (op, fields, status)
            return fields, raw[64:]

        def process_row(identity):
            table = client.request(2)
            return next(struct.unpack_from('<4Q', table, offset) for offset in range(0, len(table), 32)
                        if struct.unpack_from('<Q', table, offset)[0] == identity)

        server_store.call(client, 230)
        namespace_a = hashlib.sha256(b'no implicit retention: previous service namespace').digest()
        namespace_b = hashlib.sha256(b'explicit reauthorization: new service namespace').digest()
        old_grant = server_store.call(client, 231, instance, 2, 4096, namespace_a)[0][1]
        app(238, old_grant)
        table = client.request(2)
        old_service = struct.unpack_from('<Q', table, 3 * 32)[0]
        client.request(32, struct.pack('<Q', old_service))
        assert process_row(old_service)[1] == 5
        new_service = struct.unpack_from('<Q', client.request(33, struct.pack('<Q', old_service)), 8)[0]
        assert new_service != old_service and new_service & 255 == 3
        assert 0 < process_row(instance)[1] < 5, 'caller was replaced instead of kept alive'
        server_store.call(client, 230)
        app(238, old_grant, status=1)
        new_grant = server_store.call(client, 231, instance, 2, 4096, namespace_b)[0][1]
        # Both services issue their first grant into the same empty slot.
        # Only the service epoch distinguishes these operational authorities.
        assert old_grant & 0xffffffff == new_grant & 0xffffffff == 257
        assert old_grant >> 32 != new_grant >> 32
        app(238, old_grant, status=1)
        app(238, new_grant)
        record('service restart and same-slot regrant cannot revive old authority for a live caller',
               caller=instance, old_service=old_service, new_service=new_service,
               old_grant=old_grant, new_grant=new_grant,
               old_namespace=namespace_a.hex(), new_namespace=namespace_b.hex())

        payload = b'Only the new explicit namespace grant can read this committed server content.'
        app(232, new_grant, len(payload), data=hashlib.sha256(payload).digest())
        app(233, new_grant, data=payload)
        assert app(234, new_grant)[0][1] == 1
        row = app(236, new_grant)[1]
        assert row[48:80] == namespace_b and row[80:112] == hashlib.sha256(payload).digest()
        assert app(237, new_grant, 0, len(payload))[1] == payload
        app(236, old_grant, status=1)
        app(237, old_grant, 0, len(payload), status=1)
        app(232, old_grant, len(payload), data=hashlib.sha256(payload).digest(), status=1)
        # Reauthorization within the new incarnation also advances the counter.
        replacement = server_store.call(client, 231, instance, 2, 4096, namespace_b)[0][1]
        assert replacement != new_grant and replacement >> 32 == new_grant >> 32
        app(238, new_grant, status=1)
        assert app(237, replacement, 0, len(payload))[1] == payload
        record('stale grants cannot inspect, read, or overwrite the new namespace; fresh grants preserve committed bytes',
               bytes=len(payload), sha256=hashlib.sha256(payload).hexdigest(), replacement_grant=replacement)
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
