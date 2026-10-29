"""Fragment raw management bytes across actual keyboard-driven Launcher RPCs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'tools'), str(ROOT / 'tests')]
import live
import releases
from creator_journey import rendered_text
from graphical_devices import DeviceInput


def wait(check, label, seconds=30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(.04)
    raise TimeoutError(label)


def reply(client, rid):
    """Read the actual wire reply without sending a replacement request."""
    seen = []
    while True:
        where = client.buffer.find(live.REPLY)
        if where >= 0:
            del client.buffer[:where]
            if len(client.buffer) >= 32:
                _, status, answer, length, reserved = struct.unpack_from('<4sIQQQ', client.buffer)
                if length > 1024 or reserved:
                    raise ValueError('invalid management reply header')
                if len(client.buffer) >= 32 + length:
                    payload = bytes(client.buffer[32:32 + length])
                    del client.buffer[:32 + length]
                    seen.append(dict(rid=answer, status=status, length=length))
                    if answer == rid:
                        return status, payload, seen
                    continue
        elif len(client.buffer) > 4096:
            del client.buffer[:-3]
        data = client.stream.recv(65536)
        if not data:
            raise EOFError('management transport closed before the original reply')
        client.buffer.extend(data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=ROOT / 'build/launcher-interleaving')
    parser.add_argument('--package', type=Path, default=ROOT / 'build/forge-server-recovery-final2/native-forge-server.ltrel')
    parser.add_argument('--public', type=Path, default=ROOT / 'build/forge-server-recovery-final2/operator.pub')
    parser.add_argument('--case', choices=('all', 'magic', 'header', 'payload'), default='all')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    sock, qmp = args.output / 'portal.sock', args.output / 'display.qmp'
    # Refuse to replace another test/operator session.
    if sock.exists() or qmp.exists():
        raise ValueError('use a fresh output directory without active endpoint paths')
    report = dict(image=hashlib.sha256(args.image.read_bytes()).hexdigest(), backend='qemu', checks=[])
    process = client = ui = None
    log = (args.output / 'guest.log').open('wb')
    try:
        process = subprocess.Popen([str(ROOT / 'lt'), 'run', '--image', str(args.image.resolve()),
            '--socket', str(sock), '--graphics', str(qmp)], cwd=ROOT,
            stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        wait(sock.exists, 'guest management readiness', 60)
        ui = DeviceInput('qemu', qmp)
        client = live.Client(sock, timeout=30)
        assert len(client.request(2)) == 384
        client.request(10, releases.project('native-forge') + releases.public_modulus(args.public))
        info = client.stage(args.package)
        report['candidate_release'] = info['release_id']
        report['candidate_approved'] = False
        client.stream.settimeout(5)

        def prompt():
            frame = ui.frame()
            return frame if rendered_text(frame, 16, 12, 24) == 'SIGNED PACKAGE CANDIDATE' else None

        cases = ('magic', 'header', 'payload') if args.case == 'all' else (args.case,)
        for case in cases:
            op = 100 if case == 'payload' else 2
            payload = struct.pack('<8Q', 10, 0, 0, 0, 0, 0, 0, 1) if op == 100 else b''
            rid = max(client.counter + 1, time.time_ns())
            client.counter = rid
            frame = struct.pack('<4sIQQQ', live.MAGIC, len(payload), rid, op, 0) + payload
            split = dict(magic=2, header=20, payload=56)[case]
            record = dict(case=case, op=op, rid=rid, split=split, total=len(frame))
            report['checks'].append(record)
            client.stream.sendall(frame[:split])
            # The portal relays raw bytes immediately. This lets the guest consume
            # the prefix and enter the kernel's blocking UART read before F12.
            time.sleep(.3)
            ui.press(88)
            presented = wait(prompt, 'physical F12 did not render the trusted candidate', 15)
            (args.output / f'{case}-gui-wake.ppm').write_bytes(presented.ppm())
            record['actual_gui_rpc_completed'] = True
            started = time.monotonic()
            client.stream.sendall(frame[split:])
            status, result, seen = reply(client, rid)
            record.update(status=status, response_length=len(result), replies=seen,
                          seconds_after_suffix=time.monotonic() - started)
            assert status == 0, ('original request rejected after GUI wake', record)
            if op == 2:
                assert len(result) == 384
                launcher, state = struct.unpack_from('<2Q', result, 32)
                assert launcher & 255 == 1 and state > 0, 'no actual Launcher process row'
            else:
                assert len(result) == 64 and struct.unpack_from('<Q', result)[0] == 0, ('read-only Objects request changed', record)
            # Dismiss and reopen through physical controls: no direct UI setters
            # and no local execution approval are used by this regression test.
            ui.press(1)
            wait(lambda: not prompt(), 'physical Escape did not dismiss candidate', 15)
            assert len(client.request(2)) == 384
            record['followup_process_query'] = True
            record['physical_escape_dismissed'] = True
            record['result'] = 'pass'
            (args.output / 'evidence.json').write_text(json.dumps(report, indent=2) + '\n')
            print('PASS', case, 'same request identity survived native GUI RPC', flush=True)
        report['result'] = 'pass'
    except BaseException as error:
        report.update(result='fail', error=repr(error))
        if ui:
            try:
                (args.output / 'failure.ppm').write_bytes(ui.frame().ppm())
            except BaseException:
                pass
        raise
    finally:
        (args.output / 'evidence.json').write_text(json.dumps(report, indent=2) + '\n')
        if client:
            client.close()
        if ui:
            ui.close()
        # A deliberately corrupted old parser cannot be trusted to accept a
        # shutdown frame. Terminate only this explicitly owned fault-test group.
        if process and process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        log.close()


if __name__ == '__main__':
    main()
