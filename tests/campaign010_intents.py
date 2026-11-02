"""Focused production intent queue transitions on RV64 and emulated AArch64.

The test trap supplies only public binding snapshots and a monotonic clock.
It does not install an app, authorize a real service, retain a vault, send a
message or manufacture a Feed acceptance. Connected evidence is separate.
"""
import hashlib,json,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import driver,live_build
from structured_runtime import BOOT
B=ROOT/'build/campaign010-intents'
SOURCE='''import Guest.AppIntent
namespace build.Campaign010Intents
open Guest Guest.LiveSDK
-- Public test authorization state, separate from the production queue.
def authority : UInt64 := 0x7a0000
def payload : UInt64 := 0x7a0100
def backup : UInt64 := 0x7a1000
def request (action operation destination bytes t : UInt64) : UInt64 :=
  let t := store64 command 482 (store64 (command+8) action (store64 (command+16) operation
    (store64 (command+24) destination (store64 (command+32) bytes (store64 (command+40) 1000 t)))))
  copy payload (command+64) bytes t
@[noinline] def check (t : UInt64) : UInt64 :=
  let t := Guest.AppIntent.clear (zero authority 2 t)
  let t := store64 authority 7 (store64 (authority+8) 0xaaa (store64 payload 0x7365746f6e t))
  let r := Guest.AppIntent.request 55 1001 88 482 69 (request 0 123 0 5 t)
  if r != 64 || status r != 0 || result r != 1 || load64 (wire+16) r != 1 then 1 else
  let r := Guest.AppIntent.request 55 2001 88 482 64 (request 1 1 0 0 r)
  if status r != 1 then 2 else
  let r := Guest.AppIntent.review 55 r
  if r != 101 || status r != 0 || load64 (wire+16) r != 5 || !Guest.LiveMemory.equal (wire+96) payload 5 r then 3 else
  let t := store8 payload 78 r
  let wrong := Guest.AppIntent.approve 55 1 0 payload 5 t
  if wrong != error then 4 else
  let t := store8 payload 110 wrong
  let p := Guest.AppIntent.approve 55 1 0 payload 5 t
  if p == error then 5 else
  let t := Guest.AppIntent.reserveCommit p 13 t
  if t == error || !Guest.AppIntent.cacheValid 0 t then 6 else
  if Guest.AppIntent.approve 55 1 0 payload 5 t != error then 7 else
  let t := Guest.AppIntent.evidence 1 8 12 t
  let r := Guest.AppIntent.request 55 1001 88 482 64 (request 1 1 0 0 t)
  if status r != 0 || load64 (wire+16) r != 8 || load64 (wire+24) r != 12 then 8 else
  let r := Guest.AppIntent.request 55 1001 88 482 64 (request 2 1 0 0 r)
  if status r != 12 then 9 else
  -- Only durable public keys are restored. Live caller/service/generation and
  -- old approval bytes are deliberately destroyed before a new authorized call.
  let t := copy Guest.AppIntent.durable backup 384 r
  let t := Guest.AppIntent.clear t
  let t := copy backup Guest.AppIntent.durable 384 t
  let r := Guest.AppIntent.request 55 3001 88 482 69 (request 0 123 0 5 t)
  if status r != 0 || load64 (wire+16) r != 8 || load64 (Guest.AppIntent.row 0+56) r != 13 then 10 else
  let h := result r
  let t := store8 payload 78 r
  let r := Guest.AppIntent.request 55 4001 88 482 69 (request 0 123 0 5 t)
  if status r != 9 then 11 else
  let t := store8 payload 110 r
  let t := store64 authority 8 t
  let r := Guest.AppIntent.request 55 3001 88 482 64 (request 1 h 0 0 t)
  if status r != 3 then 12 else
  let r := Guest.AppIntent.request 56 3001 88 482 64 (request 1 h 0 0 r)
  if status r != 3 then 13 else
  let t := store64 (authority+8) 0xbbb r
  let r := Guest.AppIntent.request 55 2001 88 482 69 (request 0 124 0 5 t)
  if status r != 0 || load64 (wire+16) r != 1 then 14 else
  let h := result r
  let r := Guest.AppIntent.request 55 2001 88 482 64 (request 2 h 0 0 r)
  if status r != 0 || load64 (wire+16) r != 6 then 15 else
  let t := store8 payload 0xc0 r
  let r := Guest.AppIntent.request 55 2001 88 482 65 (request 0 125 0 1 t)
  if status r != 2 then 16 else 0
end build.Campaign010Intents
'''
TRAP=''' beqz a0,okay
 j failed
fatal:
 csrr t0,mcause
 li t1,9
 bne t0,t1,unexpected
 li t0,116
 beq a7,t0,clock
 li t0,158
 beq a7,t0,capture
 li t0,159
 beq a7,t0,current
 j unexpected
clock:
 li a0,10
 j admitted
capture:
 li t0,0x7fe00000
 add t0,t0,a1
 sd a0,0(t0)
 li t1,99
 sd t1,8(t0)
 sd a2,16(t0)
 li t1,0x805a0000
 ld t2,0(t1)
 sd t2,24(t0)
 ld t2,8(t1)
 sd t2,32(t0)
 li t1,0xccc
 sd t1,64(t0)
 li a0,96
 j admitted
current:
 li t0,0x7fe00000
 add t0,t0,a1
 ld t1,24(t0)
 li t2,0x805a0000
 ld t2,0(t2)
 bne t1,t2,denied
 li a0,0
 j admitted
denied:
 li a0,-1
admitted:
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
 li t0,0x10000000
 li t1,80
 sb t1,0(t0)
 call lt_finish'''
def main():
 B.mkdir(parents=True,exist_ok=True)
 live_build.compile_module('Guest.AppIntent')
 source=ROOT/'build/Campaign010Intents.lean';source.write_text(SOURCE);driver.lean(['-o',source.with_suffix('.olean'),source])
 assembly=B/'check.S';driver.lean(['--run','Compiler/Main.lean','build.Campaign010Intents',assembly,'build.Campaign010Intents.check'])
 boot=BOOT.replace('lt_Examples_StructuredConsumer_check','lt_build_Campaign010Intents_check').replace(' li t1,0x40000cf',' li t1,0x201000cf\n sd t1,24(t0)\n li t1,0x40000cf').replace(' call lt_finish\nfatal:\n li a0,2\n call lt_finish',TRAP)
 (B/'boot.S').write_text(boot);objects=[]
 for i,path in enumerate((assembly,B/'boot.S',ROOT/'runtime/primitives.S')):
  obj=B/f'{i}.o';driver.asm(path,obj);objects.append(obj)
 elf=B/'check.elf';binary=B/'check.bin';driver.run([driver.tool('ld.lld'),'-m','elf64lriscv','--no-relax','-T',ROOT/'runtime/kernel.ld',*objects,'-o',elf]);driver.run([driver.tool('llvm-objcopy'),'-O','binary',elf,binary]);checks=[]
 for backend in ('qemu','aarch64'):
  if backend=='qemu':command=[driver.tool('qemu-system-riscv64'),'-M','virt','-cpu','rv64','-m','64M','-smp','1','-bios','none','-nographic','-monitor','none','-kernel',binary]
  else:
   obj=B/'aarch64.o';exe=B/'lt-aarch64';driver.asm(ROOT/'emulator/aarch64.S',obj,'aarch64-linux-gnu');driver.run([driver.tool('ld.lld'),'-static','-e','_start',obj,'-o',exe]);command=[driver.tool('qemu-aarch64'),exe,binary,'--interactive']
  started=time.monotonic();r=subprocess.run(list(map(str,command)),capture_output=True,timeout=60)
  if r.returncode or r.stdout!=b'P':raise RuntimeError((backend,r.returncode,r.stdout.hex(),r.stderr.decode()))
  checks.append(dict(backend=backend,result='pass',seconds=time.monotonic()-started,emulated_aarch64=backend=='aarch64'))
 report=dict(schema=1,result='pass',binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),production_source_sha256=hashlib.sha256((ROOT/'Guest/AppIntent.lean').read_bytes()).hexdigest(),checks=checks,boundaries=['cross-app result denial','frozen payload mismatch','one-use approval','uncertain cancellation','durable exact outbox association after fresh caller','changed payload refusal','revoked generation refusal','changed owner authority refusal','precommit cancellation','malformed UTF-8 refusal'],limits='Native queue transition fixture with test-only public authority snapshots/clock; not actual kernel grants, protected vault recovery, installed-app UI, Feed publication or Messenger delivery evidence.')
 (B/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
