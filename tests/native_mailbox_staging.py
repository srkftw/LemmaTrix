"""Run native mailbox staging diagnostics without a common-image rebuild.

The compiled fixture exercises read-only administrator queries and the bounded
inactivity lease. A guest trap supplies current-token results and explicit
monotonic readings; this does not qualify live grants or timer behavior.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'tools'), str(ROOT / 'tests')]
import driver
from structured_runtime import BOOT

SOURCE = r'''
import Guest.Mailbox
namespace build.MailboxStagingDiagnostics
open Guest Guest.LiveSDK Guest.Mailbox
def calls : UInt64 := 0x7a0080
def commandFor (action t : UInt64) : UInt64 :=
  store64 command 440 (store64 (command+8) action (store64 (command+56) 1 (zero command 128 t)))
def testId : UInt64 := 0x7a0100
def testToken : UInt64 := 0x7a0140
def testRequest : UInt64 := 0x7a0180
def terminalCommand (action a b t : UInt64) : UInt64 :=
  let t := zero command 128 t
  let t := store64 command 441 (store64 (command+8) action (store64 (command+16) a
    (store64 (command+24) b (store64 (command+56) 1 t))))
  copy testId (command+64) 32 (copy testToken (command+96) 32 t)
def beginCommand (count t : UInt64) : UInt64 :=
  copy testRequest (command+128) 32 (terminalCommand 1 count 1 t)
def appendCommand (h offset count t : UInt64) : UInt64 :=
  let t := terminalCommand 2 h offset t
  let t := store64 (command+128) 0xaabb t
  -- Only the public test helper usescount; the actual decoder uses rawlength.
  store64 (command+40) count t
def progressChecks (t : UInt64) : UInt64 :=
  let t := zero st 64 (zero active (bytes/8) (zero calls 4 (zero testId 20 t)))
  let t := store64 st 77 (store64 (calls+16) 1 (store64 (calls+24) 100 t))
  let t := store64 testId 11 (store64 testToken 22 (store64 testRequest 33 t))
  let p := recipient active 0
  let t := store64 p 1 (copy testId (p+32) 32 t)
  let t := copy hashed (p+64) 32 (hash testToken 32 t)
  let t := store64 (p+128) 8388608 (store64 (p+144) 65536 t)
  let r := dispatch 55 0x100000000 10 192 (beginCommand 1536 t)
  if status r != 0 || load64 (wire+8) r != 1 || load64 (st+224) r != 1100 || load64 (st+312) r != 0 then 20 else
  let r := dispatch 55 0x100000000 11 640 (appendCommand 1 0 512 (store64 (calls+24) 1000 r))
  if status r != 0 || load64 (st+72) r != 512 || load64 (st+224) r != 2000 || load64 (st+312) r != 1 then 21 else
  let r := dispatch 55 0x100000000 12 640 (appendCommand 1 0 512 (store64 (calls+24) 1500 r))
  if status r != 2 || load64 (st+224) r != 2000 || load64 (st+312) r != 1 then 22 else
  let r := dispatch 56 0x100000000 13 640 (appendCommand 1 512 512 r)
  if status r != 2 || load64 (st+224) r != 2000 then 23 else
  let r := dispatch 55 0x100000000 14 640 (appendCommand 2 512 512 r)
  if status r != 2 || load64 (st+224) r != 2000 then 24 else
  let r := dispatch 55 0x100000000 15 640 (store64 (command+96) 23 (appendCommand 1 512 512 r))
  if status r != 2 || load64 (st+224) r != 2000 then 25 else
  let r := dispatch 55 0x100000000 16 640 (store64 (command+64) 12 (appendCommand 1 512 512 r))
  if status r != 2 || load64 (st+224) r != 2000 then 26 else
  let r := dispatch 55 0x100000000 17 128 (appendCommand 1 512 0 r)
  if status r != 2 || load64 (st+224) r != 2000 || load64 (st+312) r != 1 then 27 else
  let r := dispatch 55 0x100000000 18 641 (appendCommand 1 512 513 r)
  if status r != 2 || load64 (st+224) r != 2000 then 28 else
  let r := dispatch 55 0x100000000 19 640 (appendCommand 1 513 512 r)
  if status r != 2 || load64 (st+224) r != 2000 then 29 else
  let r := dispatch 55 0x100000000 20 640 (appendCommand 1 512 512 (store64 (calls+24) 1900 r))
  if status r != 0 || load64 (st+72) r != 1024 || load64 (st+224) r != 2900 || load64 (st+312) r != 2 then 30 else
  let r := dispatch 55 0x100000000 21 640 (appendCommand 1 1024 512 (store64 (calls+24) 2800 r))
  if status r != 0 || load64 (st+72) r != 1536 || load64 (st+224) r != 3800 || load64 (st+312) r != 3 then 31 else
  let r := dispatch 55 0x100000000 22 128 (terminalCommand 3 1 0 (store64 (calls+24) 3800 r))
  if status r != 2 || load64 (st+48) r != 0 || load64 (st+264) r != 1 ||
    load64 (st+288) r != 1536 || load64 (st+296) r != 3800 || load64 (st+304) r != 3800 then 32 else
  let r := dispatch 55 0x100000000 23 192 (beginCommand 512 (store64 (calls+24) 4000 r))
  if status r != 0 || load64 (st+224) r != 5000 || load64 (st+312) r != 0 then 33 else
  let r := dispatch 55 0x100000000 24 384 (appendCommand 1 0 256 (store64 (calls+24) 4100 r))
  if status r != 0 || load64 (st+224) r != 5100 || load64 (st+72) r != 256 then 34 else
  let r := dispatch 55 0x100000000 25 192 (beginCommand 512 (store64 (calls+24) 5100 r))
  if status r != 0 || load64 (wire+16) r != 0 || load64 (st+72) r != 0 ||
    load64 (st+224) r != 6100 || load64 (st+312) r != 0 || load64 (st+264) r != 2 then 35 else
  let r := dispatch 55 0x100000000 26 192 (beginCommand 512 (store64 (calls+24) 5200 r))
  if status r != 0 || load64 (st+224) r != 6100 || load64 (st+312) r != 0 then 36 else
  let r := dispatch 55 0x100000000 27 160 (appendCommand 1 0 32 (store64 (calls+24) 6100 r))
  if status r != 2 || load64 (st+48) r != 0 || load64 (st+296) r != 6100 || load64 (st+304) r != 6100 then 37 else
  let r := dispatch 55 0x100000000 28 192 (beginCommand 512 (store64 (calls+24) 7000 r))
  let r := dispatch 55 0x100000000 29 129 (appendCommand 1 0 1 (store64 (st+312) 8192 (store64 (calls+24) 7001 r)))
  if status r != 2 || load64 (st+224) r != 8000 || load64 (st+312) r != 8192 || load64 (st+72) r != 0 then 38 else
  let r := dispatch 55 0x100000000 30 129 (appendCommand 1 0 1 (store64 (st+312) 8191 (store64 (calls+24) 7002 r)))
  if status r != 0 || load64 (st+224) r != 8002 || load64 (st+312) r != 8192 || load64 (st+72) r != 1 then 39 else
  let r := dispatch 55 0x100000000 31 129 (appendCommand 1 1 1 (store64 (calls+24) 7003 r))
  if status r != 2 || load64 (st+224) r != 8002 || load64 (st+312) r != 8192 then 40 else 0
def check (t : UInt64) : UInt64 :=
  let t := zero st 64 (zero calls 4 (zero staged 1024 t))
  let t := store64 st 77 (store64 (st+16) 1 (store64 (st+48) 55 (store64 (st+56) 123
    (store64 (st+64) 7680 (store64 (st+72) 512 (store64 (st+224) 1000 (store64 (calls+16) 1 (store64 (calls+24) 4096 t))))))))
  let t := store64 staged 0xaabb t
  let r := dispatch 55 2048 1 64 (commandFor 6 t)
  if status r != 1 || load64 (st+48) r != 55 || load64 staged r != 0xaabb then 1 else
  let r := dispatch 55 0x100000000 2 64 r
  if r != 64 || status r != 0 || load64 (wire+8) r != 1 || load64 (wire+16) r != 123 ||
    load64 (wire+24) r != 7680 || load64 (wire+32) r != 512 || load64 (wire+40) r != 1000 ||
    load64 (wire+48) r != 4096 || load64 (wire+56) r != 1 then 2 else
  if load64 (st+16) r != 1 || load64 (st+48) r != 55 || load64 staged r != 0xaabb || load64 (st+264) r != 0 then 3 else
  let r := dispatch 55 0x100000000 3 64 (commandFor 7 r)
  if status r != 0 || load64 (wire+8) r != 0 || load64 (wire+16) r != 0 || load64 (wire+48) r != 0 then 4 else
  let t := expireStaging 1000 r
  if load64 (st+48) t != 55 || load64 (st+264) t != 0 || load64 staged t != 0xaabb then 5 else
  let t := expireStaging 999 (store64 (st+16) 0 t)
  if load64 (st+48) t != 55 || load64 (st+264) t != 0 then 6 else
  let t := expireStaging 1000 t
  if load64 (st+48) t != 0 || load64 (st+264) t != 1 || load64 (st+272) t != 123 ||
    load64 (st+280) t != 7680 || load64 (st+288) t != 512 || load64 (st+296) t != 1000 ||
    load64 (st+304) t != 1000 || !Guest.ProjectGraph.allZero staged 8192 t then 7 else
  let t := expireStaging 4000 t
  if load64 (st+264) t != 1 then 8 else
  let t := store64 (st+48) 55 (store64 (st+56) 124 (store64 (st+64) 1024
    (store64 (st+72) 1024 (store64 (st+224) 5000 t))))
  let t := expireStaging 5000 (store64 staged 0xccdd t)
  if load64 (st+264) t != 2 || load64 (st+272) t != 124 || load64 (st+280) t != 1024 ||
    load64 (st+288) t != 1024 || load64 (st+296) t != 5000 || load64 (st+304) t != 5000 ||
    !Guest.ProjectGraph.allZero staged 8192 t then 9 else
  let t := store64 (st+16) 1 (store64 (st+48) 55 (store64 (st+56) 125 t))
  let r := dispatch 55 0x100000000 4 64 (commandFor 7 t)
  if status r != 0 || load64 (wire+8) r != 2 || load64 (wire+16) r != 124 ||
    load64 (wire+24) r != 1024 || load64 (wire+32) r != 1024 || load64 (wire+40) r != 5000 ||
    load64 (wire+48) r != 5000 || load64 (st+48) r != 55 || load64 (st+16) r != 1 then 10 else
  let r := dispatch 55 0x100000000 5 64 (store64 (calls+16) 0 r)
  if status r != 2 || load64 (st+264) r != 2 || load64 (st+48) r != 55 then 11 else progressChecks r
end build.MailboxStagingDiagnostics
'''

TRAP = r'''
fixtureTrap:
 csrr t0,mcause
 li t1,9
 bne t0,t1,fatal
 li t0,0x805a0080
 ld t1,0(t0)
 addi t1,t1,1
 sd t1,0(t0)
 sd a7,8(t0)
 li a0,-1
 li t1,116
 beq a7,t1,fixtureNow
 li t1,131
 bne a7,t1,fixtureReturn
 ld t1,16(t0)
 beqz t1,fixtureReturn
 li a0,0
 j fixtureReturn
fixtureNow:
 ld a0,24(t0)
fixtureReturn:
 csrr t0,mepc
 addi t0,t0,4
 csrw mepc,t0
 mret
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backend', action='append', choices=('qemu', 'x86_64', 'aarch64'))
    parser.add_argument('--output', type=Path, default=ROOT / 'build/native-mailbox-staging-diagnostics')
    args = parser.parse_args()
    folder = args.output.resolve()
    folder.mkdir(parents=True, exist_ok=True)
    source = ROOT / 'build/MailboxStagingDiagnostics.lean'
    source.write_text(SOURCE.lstrip(), encoding='utf8')
    driver.lean(['-o', ROOT / 'Guest/Mailbox.olean', ROOT / 'Guest/Mailbox.lean'])
    driver.lean(['-o', source.with_suffix('.olean'), source])
    assembly = folder / 'check.S'
    driver.lean(['--run', 'Compiler/Main.lean', 'build.MailboxStagingDiagnostics',
                 assembly, 'build.MailboxStagingDiagnostics.check'])
    # VA7a0080 maps to PA805a0080 in this fixture's extra 2MiB leaf.
    boot = BOOT.replace('lt_Examples_StructuredConsumer_check',
                        'lt_build_MailboxStagingDiagnostics_check')
    boot = boot.replace(' li t1,0x40000cf',
                        ' li t1,0x201000cf\n sd t1,24(t0)\n li t1,0x40000cf')
    boot = boot.replace(' la t0,fatal', ' la t0,fixtureTrap') + TRAP
    # Preserve the failing native assertion number in the test-device status.
    boot = boot.replace(' call lt_finish\nfatal:',
                        ' beqz a0,okay\n slli t4,a0,16\n li t0,0x100000\n'
                        ' li t1,0x3333\n or t1,t1,t4\n sw t1,0(t0)\n1: j 1b\n'
                        'okay:\n call lt_finish\nfatal:')
    boot_path = folder / 'boot.S'
    boot_path.write_text(boot, encoding='utf8')
    objects = []
    for i, path in enumerate((assembly, boot_path, ROOT / 'runtime/primitives.S')):
        obj = folder / f'{i}.o'
        driver.asm(path, obj)
        objects.append(obj)
    elf = folder / 'check.elf'
    binary = folder / 'check.bin'
    driver.run([driver.tool('ld.lld'), '-m', 'elf64lriscv', '--no-relax', '-T',
                ROOT / 'runtime/kernel.ld', *objects, '-o', elf])
    driver.run([driver.tool('llvm-objcopy'), '-O', 'binary', elf, binary])
    checks = []
    for backend in args.backend or ('qemu',):
        if backend == 'qemu':
            command = [driver.tool('qemu-system-riscv64'), '-M', 'virt', '-cpu', 'rv64',
                       '-m', '64M', '-smp', '1', '-bios', 'none', '-nographic',
                       '-monitor', 'none', '-kernel', binary]
        else:
            obj = folder / (backend + '.o')
            exe = folder / ('lt-' + backend)
            driver.asm(ROOT / f'emulator/{backend}.S', obj, backend + '-linux-gnu')
            driver.run([driver.tool('ld.lld'), '-static', '-e', '_start', obj, '-o', exe])
            command = ([driver.tool('qemu-aarch64')] if backend == 'aarch64' else [])
            command += [exe, binary, '--interactive']
        began = time.monotonic()
        result = subprocess.run(list(map(str, command)), capture_output=True, timeout=120)
        if result.returncode:
            raise RuntimeError((backend, result.returncode, result.stdout.hex(), result.stderr.decode()))
        checks.append(dict(backend=backend, result='pass', seconds=time.monotonic() - began))
    report = dict(
        schema=1, result='pass', checks=checks,
        image_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
        mailbox_source_sha256=hashlib.sha256((ROOT / 'Guest/Mailbox.lean').read_bytes()).hexdigest(),
        fixture_source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        boundaries=[
            'ordinary rights and rejected current-token denied',
            'current staging query remains read-only while publication pending',
            'last-expiration query available before busy gate',
            'pending or predeadline staging is not expired',
            'original exact deadline clears staged8192bytes and records only public scalars',
            'repeated no-stage check does not increment count',
            'next expiration updates bounded volatile scalar metadata',
            'authenticated exact positive appends renew only the existing1000ticks and make progress beyond initial absolute deadline',
            'wrong caller handle token id offset replay zero or oversize count cannot renew',
            'expired commit and append reject before loop maintenance and clear staged data',
            'matching begin after expiry starts from offsetzero; unchanged live retry never renews',
            'live8192renewal guard denies another increment while8191may advance exactly once',
        ],
        limits=('Compiled native Mailbox transition fixture. Guest trap supplies current-token '
                'success/rejection and explicit monotonic readings; it does not test installed kernel '
                'grants, real timer advancement, live routes or backing durability. No operational '
                'actor access; AArch64 backend is emulated.'),
    )
    (folder / 'evidence.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
