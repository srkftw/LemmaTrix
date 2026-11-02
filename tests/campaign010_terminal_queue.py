"""Compiled production queue/pause ownership predicates with public state fixtures.

This is not live route/delivery evidence. The test trap supplies a clock and exact
owner liveness, while deterministic public bytes stand in for buffered results.
"""
import hashlib,json,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import driver,live_build
from structured_runtime import BOOT
B=ROOT/'build/campaign010-terminal-queue'
SOURCE='''import Guest.OnionTerminal
namespace build.Campaign010TerminalQueue
open Guest Guest.LiveSDK
open Guest.OnionTerminal
def authority : UInt64 := 0x7a0000
def commandFor (request t : UInt64) : UInt64 :=
  let t := zero command 16 t
  store64 (command+8) request (store64 (command+64) 441 (store64 (command+120) 1 t))
def check (t : UInt64) : UInt64 :=
  let t := zero control 64 (zero st 4096 (zero 0x770000 8192 (zero authority 2 t)))
  let p := Guest.NodeEnrollment.peer 3
  let t := zero p 128 t
  let t := store64 p 1 (store64 (p+208) 8 (store64 (p+232) 4096 (store64 (p+240) 128 (store64 (p+512) 0xabc t))))
  let t := store64 Guest.TorRouter.state 1 (store64 (Guest.TorRouter.state+8) 1 (store64 (Guest.TorRouter.state+24) 3 t))
  let r := beginClient 3 17 101 1024 10 t
  if r != 64 || status r != 0 || ownerProfile 101 0 r != 0 then 1 else
  let r := submitRequest 101 128 (commandFor 77 r)
  if status r != 0 || load64 (st+136) r != 960 || load64 (st+144) r != 9 then 2 else
  let r := submitRequest 102 128 (commandFor 78 r)
  if status r != 8 || load64 (st+136) r != 960 then 3 else
  let r := beginClient 3 18 102 1024 10 r
  if status r != 0 || ownerProfile 102 0 r != 1 then 4 else
  let r := submitRequest 102 128 (commandFor 99 r)
  if status r != 0 then 5 else
  -- Deterministic result bytes qualify bank preservation, not network success.
  let t := selectContext 0 r
  let t := store64 (st+8) 3 (store64 (st+40) 77 (store64 (st+48) 64 (store64 (st+56) 64 (store64 received 0x1234 t))))
  let t := store64 (control+128) 1 (store64 (control+136) 0 t)
  let t := pauseClientProfiles t
  if load64 (control+128) t != 0 || load64 (control+136) t != 1 then 6 else
  let t := selectContext 1 t
  if load64 (st+72) t != 64 || load64 (st+136) t != 960 || load64 (st+144) t != 9 || load64 (st+240) t != 101000 then 7 else
  let t := selectContext 0 t
  let r := collectResponse 101 64 (commandFor 77 t)
  if r != 128 || status r != 0 || load64 (wire+64) r != 0x1234 || load64 (st+136) r != 960 then 8 else
  let t := selectContext 1 r
  let t := store64 (st+8) 3 (store64 (control+128) 2 t)
  let t := pauseClientProfiles t
  let t := selectContext 1 t
  let r := collectResponse 102 64 (commandFor 99 t)
  if r != 64 || status r != 14 || result r != 26 || load64 (st+136) r != 960 then 9 else
  let r := submitRequest 102 128 (commandFor 100 r)
  if status r != 0 || load64 (st+136) r != 896 || load64 (st+144) r != 8 || load64 (st+256) r != 0 then 10 else
  let r := beginClient 3 19 102 1024 10 r
  if status r != 4 || load64 (context 1 r+136) r != 896 then 11 else
  let t := store64 authority 101 r
  if vacantProfile 0 t != 0 then 12 else
  let r := beginClient 3 20 103 1024 10 t
  if status r != 0 || ownerProfile 101 0 r != error || ownerProfile 103 0 r != 0 || load64 (context 1 r+136) r != 896 then 13 else
  let r := dispatch 101 0 40 64 (commandFor 77 r)
  if status r != 8 then 14 else 0
end build.Campaign010TerminalQueue
'''
TRAP=''' beqz a0,passed
 j failed
fatal:
 csrr t0,mcause
 li t1,9
 bne t0,t1,unexpected
 li t0,110
 beq a7,t0,clock
 li t0,34
 beq a7,t0,owner
 j unexpected
clock:
 li a0,1000
 j admitted
owner:
 li t0,0x805a0000
 ld t0,0(t0)
 beq a0,t0,dead
 li a0,0
 j admitted
dead:
 li a0,-1
admitted:
 csrr t0,mepc
 addi t0,t0,4
 csrw mepc,t0
 mret
unexpected:
 li a0,31
failed:
 slli a0,a0,16
 li t0,0x100000
 li t1,0x3333
 or t1,t1,a0
 sw t1,0(t0)
1: j 1b
passed:
 li t0,0x10000000
 li t1,80
 sb t1,0(t0)
 call lt_finish'''
def main():
 B.mkdir(parents=True,exist_ok=True);live_build.compile_module('Guest.OnionTerminal')
 path=ROOT/'build/Campaign010TerminalQueue.lean';path.write_text(SOURCE);driver.lean(['-o',path.with_suffix('.olean'),path])
 assembly=B/'check.S';driver.lean(['--run','Compiler/Main.lean','build.Campaign010TerminalQueue',assembly,'build.Campaign010TerminalQueue.check'])
 boot=BOOT.replace('lt_Examples_StructuredConsumer_check','lt_build_Campaign010TerminalQueue_check').replace(' li t1,0x40000cf',' li t1,0x201000cf\n sd t1,24(t0)\n li t1,0x40000cf').replace(' call lt_finish\nfatal:\n li a0,2\n call lt_finish',TRAP)
 (B/'boot.S').write_text(boot);objects=[]
 for i,p in enumerate((assembly,B/'boot.S',ROOT/'runtime/primitives.S')):
  obj=B/f'{i}.o';driver.asm(p,obj);objects.append(obj)
 elf=B/'check.elf';binary=B/'check.bin';driver.run([driver.tool('ld.lld'),'-m','elf64lriscv','--no-relax','-T',ROOT/'runtime/kernel.ld',*objects,'-o',elf]);driver.run([driver.tool('llvm-objcopy'),'-O','binary',elf,binary])
 import onion_crypto as native
 native.B=B
 record=dict(schema=1,result='pass',image_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),source_sha256=hashlib.sha256((ROOT/'Guest/OnionTerminal.lean').read_bytes()).hexdigest(),checks=[native.execute(binary,b)for b in('qemu','aarch64')],boundaries=['exact owner request/collection','finite byte/attempt charge','duplicate configuration cannot renew totals','completed banked result survives route replacement','unsent queued work retains original deadline and charge','lost live request retains exact failure through rebind','dead owner reclamation preserves another owner totals'],limits=__doc__)
 (B/'evidence.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))
if __name__=='__main__':main()
