"""Compiled RV64 inspector keyboard isolation; no campaign actors are used.

The actual Messenger.key function runs in a bounded bare native probe. Escape
must close a completed inspector without cancelling a retained outbox or an
unrelated background request. Printable input, Backspace and Enter in the
inspector must leave composition and send state alone. This is a transition
and call-denial check, not an installed graphical or routed campaign.
"""
from __future__ import annotations
import argparse,hashlib,json,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import driver
from structured_runtime import BOOT
B=ROOT/'build/native-messenger-ui-keys'
SOURCE='''import Guest.Messenger
namespace build.NativeMessengerUIKeys
open Guest Guest.LiveSDK Guest.Messenger
def trapState : UInt64 := 0x7aff00
def chosen : UInt64 := 0x7afe00
def baseline (t : UInt64) : UInt64 :=
  let t := zero st 64 (zero transfer 32 (zero composeBuffer 64 (zero wire 128 t)))
  let t := store64 (st+32) 6 (store64 (st+24) 1 (store64 (st+48) 1 t))
  let t := store64 (st+64) 0xabcdef (store64 (st+104) 3 (store64 (st+40) 3 t))
  store64 composeBuffer 0x00434241 (store64 wire 0x11223344 t)
def unchanged (t : UInt64) : Bool :=
  load64 (st+32) t == 6 && load64 (st+40) t == 3 && load64 composeBuffer t == 0x00434241 &&
  load64 (st+64) t == 0xabcdef && load64 (st+104) t == 3 && load64 (st+144) t == 0 &&
  load64 (st+152) t == 0 && load64 (st+248) t == 0 && load64 wire t == 0x11223344 &&
  load64 (st+8) t == 0 && load64 (st+16) t == 0
def check (t : UInt64) : UInt64 :=
  let t := baseline (zero trapState 2 t)
  let t := store64 (st+144) 77 (store64 (st+152) 420 t)
  let t := key 1 t
  if load64 (st+32) t != 0 || load64 (st+16) t != 44 || load64 (st+8) t != 1 then 1 else
  if load64 (st+64) t != 0xabcdef || load64 (st+104) t != 3 ||
     load64 (st+144) t != 77 || load64 (st+152) t != 420 || load64 wire t != 0x11223344 then 2 else
  if load64 (st+40) t != 3 || load64 composeBuffer t != 0x00434241 then 3 else
  let t := key 30 (baseline t)
  if !unchanged t then 4 else
  let t := key 28 (baseline t)
  if !unchanged t then 5 else
  let t := key 14 (baseline t)
  if !unchanged t then 6 else
  -- The pointer's Send control calls the same function directly. It must not
  -- submit a compose buffer hidden behind an inspector or credential form.
  let t := send (baseline t)
  if load64 (st+40) t != 3 || load64 composeBuffer t != 0x00434241 || load64 (st+64) t != 0xabcdef ||
    load64 (st+144) t != 0 || load64 (st+16) t != 45 then 16 else
  -- A rejected new attachment action cannot replace the admitted action.
  let t := store64 (st+144) 77 (store64 (st+152) 434 (store64 (st+256) 16 (store64 (transfer+128) 16 (baseline t))))
  let t := submitTagged 463 21 64 t
  if load64 (st+144) t != 77 || load64 (st+256) t != 16 || load64 (transfer+128) t != 16 then 7 else
  -- Native ciphertext publication, rather than a resumed UI counter, decides
  -- whether the exact final batch is locally available, not remotely accepted.
  let t := store64 (transfer+232) 1 (header 0 0x100000001 1 1 73651 144 144 (baseline t))
  let t := attachmentCompleted 21 128 t
  if load64 transfer t != 10 then 8 else
  let t := store64 (transfer+232) 1 (header 0 0x100000001 1 1 73651 144 140 t)
  let t := attachmentCompleted 21 128 t
  if load64 transfer t != 10 then 9 else
  -- Completion belongs to its admitted action/contact, even if a newer UI
  -- selection or an obsolete transfer tag exists when the reply arrives.
  let t := zero (contact 1) 16 (zero (contact 2) 16 (baseline t))
  let t := store64 (st+264) 1 (store64 (st+24) 2 (store64 (st+248) 2 (store64 (transfer+128) 461 t)))
  let t := completed 426 0 64 (header 0 42 1 0 0 0 0 t)
  if load64 (contact 1+48) t != 42 || load64 (contact 2+48) t != 0 || load64 (st+248) t != 1 ||
    load64 (st+64) t != 42 || load64 (st+40) t != 0 || load64 (st+16) t != 18 then 10 else
  let t := store64 (st+32) 0 (store64 (st+24) 1 t)
  let t := key 109 t
  if load64 (st+24) t != 1 || load64 (st+248) t != 1 || load64 (st+64) t != 42 then 11 else
  -- Only the final two cases admit exactly one lookup and one async submit.
  -- Recovery's transfer enumeration must retain action21 after admission.
  let t := store64 trapState 1 (store64 (trapState+8) 0 (store64 (st+208) 4 (baseline t)))
  let t := nextRestoredContact t
  if load64 (trapState+8) t != 2 || load64 (st+144) t != 99 || load64 (st+152) t != 434 ||
    load64 (st+256) t != 21 || load64 (transfer+128) t != 21 then 12 else
  if load64 wire t != 434 || load64 (wire+8) t != 0 || load64 (wire+16) t != 21 ||
    load64 (wire+56) t != 1 || load64 (st+208) t != 0 || load64 (transfer+232) t != 0 then 13 else
  let t := zero trapState 2 (baseline t)
  let p := history 1+640
  let t := zero chosen 8 (zero p 10 t)
  let t := store64 chosen 0x0102030405060708 (store64 (chosen+24) 0x3132333435363738 t)
  let t := store64 (chosen+32) 0x4142434445464748 (store64 (chosen+56) 0x7172737475767778 t)
  let t := store64 p 2 (copy chosen (p+8) 64 t)
  let t := store64 trapState 2 (store64 (st+32) 0 t)
  let t := inspectProjectReference t
  if load64 (trapState+8) t != 2 || load64 (st+144) t != 99 || load64 (st+152) t != 463 ||
    load64 (st+256) t != 303 || load64 (transfer+128) t != 303 || load64 (st+32) t != 6 then 14 else
  if load64 wire t != 463 || load64 (wire+8) t != 0 || load64 (wire+16) t != 3 ||
    load64 (wire+56) t != 1 || load64 (wire+128) t != 2 then 15 else
  -- Changing the source view cannot change the frozen, submitted reference.
  let t := zero p 10 t
  if !Guest.ProjectGraph.equal chosen reference 64 t || load64 (reference+64) t != 2 ||
    !Guest.ProjectGraph.equal chosen (wire+64) 64 t || load64 (wire+128) t != 2 then 16 else
  let t := zero trapState 2 t
  0
end build.NativeMessengerUIKeys
'''


def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--backend',action='append',choices=('qemu','x86_64','aarch64'))
 a=p.parse_args();B.mkdir(parents=True,exist_ok=True)
 source=ROOT/'build/NativeMessengerUIKeys.lean';source.write_text(SOURCE)
 driver.lean(['-o',ROOT/'Guest/Messenger.olean',ROOT/'Guest/Messenger.lean'])
 driver.lean(['-o',source.with_suffix('.olean'),source]);assembly=B/'check.S'
 driver.lean(['--run','Compiler/Main.lean','build.NativeMessengerUIKeys',assembly,'build.NativeMessengerUIKeys.check'])
 boot=BOOT.replace('lt_Examples_StructuredConsumer_check','lt_build_NativeMessengerUIKeys_check').replace(' li t1,0x40000cf',' li t1,0x201000cf\n sd t1,24(t0)\n li t1,0x40000cf')
 # This M-mode handler is test-only. Private VA0x7aff00 maps to physical
 #0x805aff00 in this probe. Earlier cases keep phase0 and reject every ecall.
 # Final phases admit precisely lookup128 then submit133, checking the ABI
 #registers used by runtime/primitives.S. No production guest uses this stub.
 boot=boot.replace(' call lt_finish\nfatal:\n li a0,2\n call lt_finish',
  ''' beqz a0,okay
 j failed
fatal:
 csrr t0,mcause
 li t1,9
 bne t0,t1,unexpected
 li t0,0x805aff00
 ld t1,0(t0)
 li t2,1
 beq t1,t2,restore_call
 li t2,2
 bne t1,t2,unexpected
 li t3,4
 li t4,463
 li t5,88
 li t6,136
 j checked_phase
restore_call:
 li t3,2
 li t4,434
 li t5,77
 li t6,64
checked_phase:
 ld t1,8(t0)
 beqz t1,lookup
 li t2,1
 bne t1,t2,unexpected
 li t2,133
 bne a7,t2,unexpected
 bne a0,t5,unexpected
 li t2,0x411000
 bne a1,t2,unexpected
 bne a2,t6,unexpected
 li t2,1024
 bne a3,t2,unexpected
 li a0,99
 j admitted
lookup:
 li t2,128
 bne a7,t2,unexpected
 bne a0,t3,unexpected
 bne a1,t4,unexpected
 bnez a2,unexpected
 bnez a3,unexpected
 mv a0,t5
admitted:
 addi t1,t1,1
 sd t1,8(t0)
 csrr t0,mepc
 addi t0,t0,4
 csrw mepc,t0
 mret
unexpected:
 li a0,31
failed:
 slli t4,a0,16
 li t0,0x100000
 li t1,0x3333
 or t1,t1,t4
 sw t1,0(t0)
1: j 1b
okay:
 call lt_finish''')
 (B/'boot.S').write_text(boot);objects=[]
 for i,path in enumerate((assembly,B/'boot.S',ROOT/'runtime/primitives.S')):
  obj=B/f'{i}.o';driver.asm(path,obj);objects.append(obj)
 elf=B/'check.elf';binary=B/'check.bin'
 driver.run([driver.tool('ld.lld'),'-m','elf64lriscv','--no-relax','-T',ROOT/'runtime/kernel.ld',*objects,'-o',elf])
 driver.run([driver.tool('llvm-objcopy'),'-O','binary',elf,binary]);checks=[]
 for backend in a.backend or('qemu',):
  if backend=='qemu':
   command=[driver.tool('qemu-system-riscv64'),'-M','virt','-cpu','rv64','-m','64M','-smp','1','-bios','none','-nographic','-monitor','none','-kernel',binary]
  else:
   obj=B/(backend+'.o');exe=B/('lt-'+backend)
   driver.asm(ROOT/f'emulator/{backend}.S',obj,backend+'-linux-gnu')
   driver.run([driver.tool('ld.lld'),'-static','-e','_start',obj,'-o',exe])
   command=([driver.tool('qemu-aarch64')]if backend=='aarch64'else[])+[exe,binary,'--interactive']
  began=time.monotonic();result=subprocess.run(list(map(str,command)),capture_output=True,timeout=120)
  if result.returncode:raise RuntimeError((backend,result.returncode,result.stdout.hex(),result.stderr.decode()))
  checks.append(dict(backend=backend,result='pass',seconds=time.monotonic()-began,emulated_arm=backend=='aarch64'))
 report=dict(schema=1,result='pass',checks=checks,image_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),image_bytes=binary.stat().st_size,
  messenger_source_sha256=hashlib.sha256((ROOT/'Guest/Messenger.lean').read_bytes()).hexdigest(),
  boundaries=['completed inspector Escape closes local view and preserves nonzero retained outbox','completed inspector Escape preserves unrelated pending background request without cancellation','inspector printable Backspace and Enter preserve compose/outbox/pending-request and wire state','direct pointer Send denies a hidden compose buffer in a modal view','rejected attachment action preserves the admitted completion identity','locally published restore remains an uncertain exact-batch retry without inventing a durable remote receipt','text completion uses its captured contact and action, not a newer view or obsolete transfer tag','contact selection waits for in-flight text routing','actual recovery enumeration captures role2/434 action21 through checked128 and133 calls','actual reference inspection captures role4/463 action303 and immutable root federation policy through checked128 and133 calls','all other native IPC/syscalls fail the bare probe'],
  limits='Actual compiled UI transitions and admitted-call identity fixture only. A test-only M-mode trap accepts exactly two parameter-checked SDK calls per gated admission case; it implements no service or protocol. No installed graphical input, real kernel grants, network, storage or connected campaign claim. AArch64 is emulated.')
 (B/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))


if __name__=='__main__':main()
