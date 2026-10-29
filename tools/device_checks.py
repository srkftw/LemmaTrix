"""Focused actual-guest UART, virtio block and OS entropy checks.

Probe code calls the maintained Guest.Devices Lean driver. Backing files are
explicit disposable fixtures; neither canonical guest.bin nor personal data is
modified. ARM execution uses the real assembly executable under qemu-aarch64.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import struct
import subprocess
import tempfile
import time

try:
    from . import driver as d
except ImportError:
    import driver as d

PROBE = '''import Guest.Devices
namespace Guest
partial def deviceFill (p n value token : UInt64) : UInt64 :=
  if n == 0 then token else deviceFill (p+1) (n-1) value (store8 p value token)
partial def deviceCopy (src dst n token : UInt64) : UInt64 :=
  if n == 0 then token else deviceCopy (src+1) (dst+1) (n-1) (store8 dst (load8 src token) token)
partial def deviceDifferent (a b n accumulated token : UInt64) : UInt64 :=
  if n == 0 then accumulated else
    deviceDifferent (a+1) (b+1) (n-1) (accumulated ||| (load8 a token ^^^ load8 b token)) token
partial def deviceRandomRepeat (n token : UInt64) : UInt64 :=
  if n == 0 then 0 else
    let result := Devices.random Devices.randomBuffer 32 token
    if result != 0 then result else deviceRandomRepeat (n-1) result
partial def deviceWaitInput (token : UInt64) : UInt64 :=
  if (load8 0x10000005 token &&& 1) == 0 then deviceWaitInput token else load8 0x10000000 token

def deviceNormal (initial : UInt64) : UInt64 :=
  let first := Devices.random Devices.randomBuffer 32 initial
  if first != 0 then 1 else
  let token := deviceCopy Devices.randomBuffer (Devices.randomBuffer+64) 32 first
  let next := deviceRandomRepeat 9 token
  if next != 0 || deviceDifferent Devices.randomBuffer (Devices.randomBuffer+64) 32 0 next == 0 then 2 else
  let token := deviceFill Devices.blockBuffer 4096 83 next
  let written := Devices.block 1 1 Devices.blockBuffer 4096 token
  if written != 0 then 3 else
  let token := deviceFill Devices.blockBuffer 4096 0 written
  let read := Devices.block 0 1 Devices.blockBuffer 4096 token
  if read != 0 || load8 Devices.blockBuffer read != 83 || load8 (Devices.blockBuffer+4095) read != 83 then 4 else
  let flushed := Devices.block 4 0 Devices.blockBuffer 0 read
  if flushed != 0 then 5 else
  let denied := Devices.block 0 (Devices.capacity flushed) Devices.blockBuffer 512 flushed
  if denied != Devices.error then 6 else
  -- Exercise device-side bounds independently of the driver's checked front door.
  let token := store64 Devices.request 0 denied
  let token := store64 (Devices.request+8) (Devices.capacity token) token
  let token := store8 Devices.statusByte 255 token
  let token := Devices.descriptor Devices.blockQueue Devices.request 16 1 1 token
  let token := Devices.descriptor (Devices.blockQueue+16) Devices.blockBuffer 512 3 2 token
  let token := Devices.descriptor (Devices.blockQueue+32) Devices.statusByte 1 2 0 token
  let completed := Devices.submit (load64 Devices.state token) Devices.blockQueue (Devices.state+16) token
  if completed != 0 || load8 Devices.statusByte completed != 1 then 7 else store8 0x10000000 68 completed

def deviceCheck (initial : UInt64) : UInt64 :=
  let token := Devices.init initial
  let mode := load64 0x80e06000 token
  if mode == 1 then
    let denied := Devices.block 1 1 Devices.blockBuffer 512 token
    if denied != Devices.error then 8 else store8 0x10000000 82 denied
  else if mode == 2 then
    let token := store8 0x10000000 84 token
    let token := deviceWaitInput token
    let result := Devices.block 0 63 Devices.blockBuffer 512 token
    if result != Devices.error then 9 else store8 0x10000000 83 result
  else if mode == 3 then
    let base := load64 Devices.state token
    let token := store32 (base+0x40) 0x90000 token
    let token := store32 (base+0x50) 0 token
    if (load32 (base+0x70) token &&& 128) == 0 then 10 else store8 0x10000000 77 token
  else if mode == 4 then
    if load64 Devices.state token != 0 then 11 else
    let result := Devices.random Devices.randomBuffer 32 token
    if result != 0 then 12 else store8 0x10000000 78 result
  else if mode == 5 then
    -- Deliberately submit into an unconfigured ring while the real queue is
    -- empty. No device consumes it, so the maintained wait bound expires.
    let base := load64 Devices.state token
    let completed := Devices.submit base 0x80e10000 (Devices.state+40) token
    if completed != Devices.error || (load32 (base+0x70) completed &&& 128) == 0 then 13 else
    let index := load64 (Devices.state+16) completed
    let denied := Devices.block 0 0 Devices.blockBuffer 512 completed
    if denied != Devices.error || load64 (Devices.state+16) denied != index then 14 else
    let reset := Devices.init denied
    let recovered := Devices.block 0 0 Devices.blockBuffer 512 reset
    if recovered != 0 then 15 else store8 0x10000000 70 recovered
  else deviceNormal token
end Guest
'''
STARTUP = '''.option norvc
.section .text.boot
.globl _start
_start:
 li sp,0x80f00000
 li a0,0
 call lt_Guest_deviceCheck
 call lt_finish
'''
UART = '''.option norvc
.text
.globl _start
_start:
 li t0,0x10000000
1: lbu t1,5(t0)
 andi t1,t1,1
 beqz t1,1b
 lbu t1,0(t0)
 sb t1,0(t0)
 li t0,0x100000
 li t1,0x5555
 sw t1,0(t0)
'''


def command(backend, image, executable, backing=None, readonly=False):
    if backend == 'qemu':
        args = [d.tool('qemu-system-riscv64'), '-M', 'virt', '-cpu', 'rv64', '-m', '128M',
                '-smp', '1', '-bios', 'none', '-nographic', '-monitor', 'none',
                '-global', 'virtio-mmio.force-legacy=true', '-kernel', image,
                '-object', 'rng-random,filename=/dev/urandom,id=lt-rng',
                '-device', 'virtio-rng-device,rng=lt-rng']
        if backing is not None:
            args += ['-drive', f'file={backing},format=raw,if=none,id=lt-vault' + (',readonly=on' if readonly else ''),
                     '-device', 'virtio-blk-device,drive=lt-vault']
        return list(map(str, args))
    args = [executable, image]
    if backing is not None:
        args += ['--vault', backing]
    if readonly:
        args += ['--vault-readonly']
    if backend == 'aarch64':
        args = [d.tool('qemu-aarch64'), *args]
    return list(map(str, args))


def checked_run(args, expected, **kwargs):
    result = subprocess.run(args, capture_output=True, timeout=15, **kwargs)
    if result.returncode != 0 or result.stdout != expected:
        raise RuntimeError(f'device probe failed ({result.returncode}): stdout={result.stdout!r} stderr={result.stderr!r}')
    return result


def check(driver=None, timeout_only=False):
    directory = d.BUILD / 'device-checks'
    directory.mkdir(parents=True, exist_ok=True)
    for module in ('Primitives', 'DevicePrimitives', 'Devices'):
        d.lean(['-o', f'Guest/{module}.olean', f'Guest/{module}.lean'])
    source = d.BUILD / 'DeviceCheck.lean'
    source.write_text(PROBE)
    d.lean(['-o', source.with_suffix('.olean'), source])
    startup = directory / 'start.S'
    startup.write_text(STARTUP)
    d.compile_guest('build.DeviceCheck', ['Guest.deviceCheck'], 'device-check', str(startup), 'runtime/kernel.ld')
    base = (d.BUILD / 'device-check.bin').read_bytes()
    images = {}
    for mode in range(6):
        image = bytearray(base)
        image.extend(bytes(max(0, 0xe06008 - len(image))))
        struct.pack_into('<Q', image, 0xe06000, mode)
        path = directory / f'probe-{mode}.bin'
        path.write_bytes(image)
        images[mode] = path
    uart_source, uart_object, uart_image = directory / 'uart.S', directory / 'uart.o', directory / 'uart.bin'
    uart_source.write_text(UART)
    d.asm(uart_source, uart_object)
    d.run([d.tool('ld.lld'), '-m', 'elf64lriscv', '--no-relax', '-Ttext=0x80000000', '--oformat=binary',
           uart_object, '-o', uart_image])
    executables = {}
    for arch in ('x86_64', 'aarch64'):
        obj, executable = directory / (arch + '.o'), directory / ('lt-' + arch)
        d.asm(d.ROOT / f'emulator/{arch}.S', obj, arch + '-linux-gnu')
        d.run([d.tool('ld.lld'), '-static', '-e', '_start', obj, '-o', executable])
        executables[arch] = executable
    checks = []
    for backend in ('qemu', 'x86_64', 'aarch64'):
        with tempfile.TemporaryDirectory(prefix='timeout-', dir=directory) as temporary:
            backing = Path(temporary) / 'explicit-development.img'
            backing.write_bytes(bytes(512 * 64))
            checked_run(command(backend, images[5], executables.get(backend), backing), b'F')
            checks.append({'backend': backend, 'check': 'timeout fails transport closed until explicit driver reset', 'result': 'pass'})
    if timeout_only:
        report = {'result': 'DEVICE TIMEOUT CHECK PASS', 'checks': checks,
                  'image_sha256': hashlib.sha256(images[5].read_bytes()).hexdigest()}
        (directory / 'timeout-evidence.json').write_text(json.dumps(report, indent=2) + '\n')
        print('DEVICE TIMEOUT CHECK PASS (3 actual-guest checks)')
        return report
    for backend in ('qemu', 'x86_64', 'aarch64'):
        executable = executables.get(backend)
        checked_run(command(backend, uart_image, executable), b'Q', input=b'Q')
        checks.append({'backend': backend, 'check': 'actual UART stdin RX/LSR/echo', 'result': 'pass'})
        with tempfile.TemporaryDirectory(prefix='backing-', dir=directory) as temporary:
            backing = Path(temporary) / 'explicit-development.img'
            backing.write_bytes(bytes(512 * 64))
            checked_run(command(backend, images[0], executable, backing), b'D')
            data = backing.read_bytes()
            if data[512:4608] != b'S' * 4096 or data[:512] != bytes(512) or data[4608:] != bytes(len(data) - 4608):
                raise RuntimeError('block request changed bytes outside its exact 8-sector range')
            checks.append({'backend': backend, 'check': '8-sector OUT/IN/FLUSH, device bounds, entropy and queue wrap', 'result': 'pass'})
            digest = hashlib.sha256(data).hexdigest()
            checked_run(command(backend, images[1], executable, backing, readonly=True), b'R')
            if hashlib.sha256(backing.read_bytes()).hexdigest() != digest:
                raise RuntimeError('read-only device modified backing bytes')
            checks.append({'backend': backend, 'check': 'explicit read-only request denied without mutation', 'result': 'pass'})
        checked_run(command(backend, images[4], executable), b'N')
        checks.append({'backend': backend, 'check': 'no implicit block backing; entropy still available', 'result': 'pass'})
    for backend in ('x86_64', 'aarch64'):
        executable = executables[backend]
        with tempfile.TemporaryDirectory(prefix='adapter-', dir=directory) as temporary:
            backing = Path(temporary) / 'explicit-development.img'
            backing.write_bytes(bytes(512 * 64))
            checked_run(command(backend, images[3], executable, backing), b'M')
            checks.append({'backend': backend, 'check': 'out-of-RAM DMA fails device without host memory access', 'result': 'pass'})
            process = subprocess.Popen(command(backend, images[2], executable, backing), stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                ready, _, _ = select.select([process.stdout], [], [], 10)
                if not ready or os.read(process.stdout.fileno(), 1) != b'T':
                    raise RuntimeError('short-I/O probe never reached synchronization point')
                backing.write_bytes(b'')
                process.stdin.write(b'X')
                process.stdin.flush()
                out, err = process.communicate(timeout=10)
                if process.returncode != 0 or out != b'S':
                    raise RuntimeError(f'short-I/O adapter accepted incomplete read: {out!r} {err!r}')
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
            checks.append({'backend': backend, 'check': 'real host short read becomes guest I/O error', 'result': 'pass'})
            absent = Path(temporary) / 'not-created.img'
            result = subprocess.run(command(backend, images[4], executable, absent), capture_output=True, timeout=5)
            if result.returncode == 0 or absent.exists():
                raise RuntimeError('explicit nonexistent backing was accepted or created')
            checks.append({'backend': backend, 'check': 'missing explicit backing fails; file is not created', 'result': 'pass'})
    report = {'result': 'DEVICE CHECK PASS', 'checks': checks,
              'image_sha256': hashlib.sha256(images[0].read_bytes()).hexdigest(),
              'uart_image_sha256': hashlib.sha256(uart_image.read_bytes()).hexdigest(),
              'environment': 'Linux x86-64; ARM64 assembly executable runs under qemu-aarch64',
              'limits': ['Entropy freshness is a functioning-source check, not a statistical quality or security proof.',
                         'Transport polling is implemented; PLIC/virtio interrupt delivery is outside this subset.']}
    (directory / 'evidence.json').write_text(json.dumps(report, indent=2) + '\n')
    print('DEVICE CHECK PASS (' + str(len(checks)) + ' focused actual-guest checks)')
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--timeout-only', action='store_true')
    args = parser.parse_args(argv)
    check(timeout_only=args.timeout_only)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
