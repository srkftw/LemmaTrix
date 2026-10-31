"""Isolated raw Insert input reaches Messenger; no central actors are used.

There is deliberately no received project in this guest. Insert must reach the
native app and show its explicit unavailable-selection state. This checks the
keyboard binding rather than claiming attachment decryption/import coverage.
"""
from __future__ import annotations
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
sys.path[:0] = [str(ROOT/'tools'), str(ROOT/'tests')]
import live
import messenger
import releases
from graphical_devices import DeviceInput


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--packages', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    ready = json.loads(args.packages.read_text())
    socket, graphics = out/'isolated.sock', out/'isolated.qmp'
    log = (out/'guest.log').open('wb')
    process = subprocess.Popen([str(ROOT/'lt'), 'run', '--backend', 'qemu',
        '--image', str(args.image.resolve()), '--socket', str(socket),
        '--graphics', str(graphics)], cwd=ROOT, stdout=log, stderr=log,
        start_new_session=True)
    client = None
    began = time.monotonic()
    try:
        deadline = time.monotonic()+120
        while not socket.exists():
            if process.poll() is not None:
                raise RuntimeError((out/'guest.log').read_text())
            if time.monotonic() >= deadline:
                raise TimeoutError('isolated graphical startup')
            time.sleep(.05)
        client = live.Client(socket, timeout=120)
        public = ROOT/'tests/keys/development-rsa-public.pem'
        owner, sid = messenger.install(client, Path(ready['owner']), public, 0)
        ui, uid = messenger.install(client, Path(ready['ui']), public, 799)
        for operation in range(420, 436):
            messenger.bind(client, 2, owner, ui, operation, sid, uid)

        def inspect():
            deadline = time.monotonic()+30
            while True:
                try:
                    raw = client.request(150, struct.pack('<Q8Q', ui,782,0,0,0,0,0,0,1))
                    assert len(raw) == 96
                    return struct.unpack_from('<8Q', raw)
                except ValueError as error:
                    if str(error) != 'guest rejected command150, status1' or time.monotonic() >= deadline:
                        raise
                    time.sleep(.1)

        with DeviceInput('qemu', graphics, timeout=120) as device:
            time.sleep(1)
            device.chord(56, 15)
            time.sleep(.4)
            before = inspect()
            assert before[4] != 45
            device.press(110, delay=.15)
            deadline = time.monotonic()+15
            while True:
                after = inspect()
                if after[4] == 45:
                    break
                if time.monotonic() >= deadline:
                    raise TimeoutError(('Insert did not reach native import control', after))
                time.sleep(.1)
            time.sleep(.5)
            frame = device.frame()
            (out/'insert-unavailable.ppm').write_bytes(frame.ppm())
        report = dict(schema=1, result='passed-isolated-keyboard-control',
            backend='qemu', image_sha256=hashlib.sha256(args.image.read_bytes()).hexdigest(),
            owner_release=sid.hex(), ui_release=uid.hex(),
            ui_package_sha256=hashlib.sha256(Path(ready['ui']).read_bytes()).hexdigest(),
            ui_code_bytes=releases.inspect(Path(ready['ui']).read_bytes())['size'],
            input=dict(source='raw QMP keyboard', scan_code=110, key='Insert'),
            before=list(before), after=list(after), elapsed_seconds=time.monotonic()-began,
            limits='No received attachment exists. This verifies keyboard dispatch and fail-closed selection, not decryption, project import, networking or retention.')
        (out/'evidence.json').write_text(json.dumps(report, indent=2)+'\n')
        print(json.dumps(report, indent=2), flush=True)
    finally:
        if client:
            client.close()
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(20)
        log.close()


if __name__ == '__main__':
    main()
