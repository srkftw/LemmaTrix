"""Native Feed owner receipt/query completion cadence, with exact clock/RPC trap.

The public signed envelope comes from the recorded native common-image author.
No host author key, installed actor, policy mutation or social history is used.
"""
from __future__ import annotations
import argparse,hashlib,json,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import driver
from structured_runtime import BOOT
B=ROOT/'build/native-feed-account-cadence'
SOURCE='''import build.FeedCadenceAccount
namespace build.NativeFeedCadence
open Guest Guest.LiveSDK build.FeedCadenceAccount
def oracle : UInt64 := 0x7aff00
def publicEvent (t : UInt64) : UInt64 :=
@EVENT@
def bodyRequest (offset t : UInt64) : UInt64 :=
 let t := header 480 6 offset 8 0 0 0 t
 let t := copy trustedId (wire+64) 32 t
 query 6 96 (copy wire command 96 t)
def check (t : UInt64) : UInt64 :=
 let t := zero st 64 (zero oracle 8 (zero wire 128 t))
 let t := publicEvent (store64 oracle 1000 t)
 let t := store64 (st+32) 6 (store64 (st+232) 500 (store64 (st+240) 9 (store64 (st+160) 123 (store64 (st+72) 88 t))))
 let t := complete 64 4 (header 0 0 2 0 0 0 0 t)
 if load64 (st+232) t != 1500 || load64 (st+240) t != 9 || load64 (st+160) t != 123 || load64 (st+72) t != 88 then 1 else
 let t := pump t
 if load64 (oracle+8) t != 0 || load64 (st+64) t != 0 then 2 else
 -- The same owner admits a GUI timeline inside the post-completion interval.
 let t := query 5 64 (copy wire command 64 (header 480 5 0 0 0 0 0 t))
 if status t != 6 || load64 (st+64) t != 89 || load64 (oracle+16) t != 5 || load64 (st+240) t != 9 then 3 else
 -- A genuine original native signature validates the actual timeline path.
 let t := store64 oracle 2000 (publicEvent (zero wire 128 t))
 let t := copy envelope (wire+96) 480 t
 let t := hash envelope 480 (wire+64) (header 0 1 1 2 1330 1 7 t)
 let t := complete 576 5 t
 if status t != 0 || load64 (st+232) t != 2500 || load64 (st+136) t != 576 || load64 (st+64) t != 0 then 4 else
 let t := pump t
 if load64 (oracle+8) t != 1 || load64 (st+240) t != 9 then 5 else
 let n := outcome t
 if n != 576 || load64 (wire+8) n != 1 then 6 else
 let t := bodyRequest 0 n
 if status t != 6 || load64 (st+64) t != 90 || load64 (oracle+16) t != 6 then 7 else
 -- A partial checked-body completion gets the same handoff interval. These
 -- fixture bytes are not displayed or claimed as a complete signed body.
 let t := store64 oracle 2600 (store64 (wire+64) 0x747261702079646f (header 0 0 0 0 0 0 0 t))
 let t := complete 72 6 t
 if status t != 0 || load64 (st+232) t != 3100 || load64 (st+256) t != 8 then 8 else
 let t := pump t
 if load64 (oracle+8) t != 2 || load64 (st+240) t != 9 then 9 else
 let t := bodyRequest 8 t
 if status t != 6 || load64 (st+64) t != 91 then 10 else
 let t := complete 72 6 (store64 oracle 2900 (store64 (wire+64) 0x747261702074786e (header 0 0 0 0 0 0 0 t)))
 if status t != 0 || load64 (st+232) t != 3400 || load64 (st+256) t != 16 then 11 else
 -- The postponement expires; receipt work progresses and stays charged.
 let t := pump (store64 oracle 3400 t)
 if load64 (oracle+8) t != 4 || load64 (oracle+16) t != 4 || load64 (st+64) t != 92 || load64 (st+240) t != 10 || load64 (st+160) t != 127 then 12 else
 let t := complete 64 4 (store64 oracle 5000 (header 0 0 2 0 0 0 0 t))
 let t := pump t
 if load64 (st+232) t != 5500 || load64 (oracle+8) t != 4 then 13 else
 let t := pump (store64 oracle 5500 t)
 if load64 (oracle+8) t != 5 || load64 (st+240) t != 11 || load64 (st+72) t != 93 then 14 else
 let t := complete 64 4 (header 0 0 2 0 0 0 0 t)
 let t := pump (store64 (st+240) 64 (store64 oracle 99999 t))
 if load64 (oracle+8) t != 5 || load64 (st+240) t != 64 then 15 else 0
end build.NativeFeedCadence
'''
TRAP=''' beqz a0,okay
 j failed
fatal:
 csrr t0,mcause
 li t1,9
 bne t0,t1,unexpected
 li t0,0x805aff00
 li t1,116
 beq a7,t1,clock
 li t1,30
 bne a7,t1,unexpected
 li t1,6
 bne a0,t1,unexpected
 li t1,0x411000
 bne a1,t1,unexpected
 li t1,0x80211000
 ld t2,0(t1)
 li t3,39
 bne t2,t3,unexpected
 ld t2,8(t0)
 addi t2,t2,1
 sd t2,8(t0)
 ld t2,72(t1)
 sd t2,16(t0)
 sd zero,0(t1)
 li a0,64
 j returned
clock:
 ld a0,0(t0)
returned:
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
 global B
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--backend',action='append',choices=('qemu','aarch64'));p.add_argument('--account-source',type=Path,default=ROOT/'Guest/FeedAccount.lean');p.add_argument('--output',type=Path,default=B);a=p.parse_args();B=a.output;B.mkdir(parents=True,exist_ok=True)
 before={str(p):hashlib.sha256(p.read_bytes()).hexdigest()for p in(ROOT/'Guest').glob('*.olean')}
 copied=ROOT/'build/FeedCadenceAccount.lean';copied.write_text(a.account_source.read_text().replace('namespace Guest.FeedAccount','namespace build.FeedCadenceAccount\nopen Guest').replace('end Guest.FeedAccount','end build.FeedCadenceAccount'));driver.lean(['-o',copied.with_suffix('.olean'),copied])
 envelope=(ROOT/'tests/fixtures/campaign009-native-feed-long-event.bin').read_bytes();assert len(envelope)==480
 import struct
 initialization='\n'.join(' let t := store64 (envelope+'+str(offset)+') '+str(struct.unpack_from('<Q',envelope,offset)[0])+' t'for offset in range(0,480,8))+'\n t'
 source=ROOT/'build/NativeFeedCadence.lean';source.write_text(SOURCE.replace('@EVENT@',initialization));driver.lean(['-o',source.with_suffix('.olean'),source])
 assembly=B/'check.S';driver.lean(['--run','Compiler/Main.lean','build.NativeFeedCadence',assembly,'build.NativeFeedCadence.check'])
 boot=BOOT.replace('lt_Examples_StructuredConsumer_check','lt_build_NativeFeedCadence_check').replace(' li t1,0x40000cf',' li t1,0x201000cf\n sd t1,24(t0)\n li t1,0x40000cf').replace(' call lt_finish\nfatal:\n li a0,2\n call lt_finish',TRAP);(B/'boot.S').write_text(boot);objects=[]
 for i,path in enumerate((assembly,B/'boot.S',ROOT/'runtime/primitives.S')):
  obj=B/f'{i}.o';driver.asm(path,obj);objects.append(obj)
 elf=B/'check.elf';binary=B/'check.bin';driver.run([driver.tool('ld.lld'),'-m','elf64lriscv','--no-relax','-T',ROOT/'runtime/kernel.ld',*objects,'-o',elf]);driver.run([driver.tool('llvm-objcopy'),'-O','binary',elf,binary]);checks=[]
 for backend in a.backend or('qemu','aarch64'):
  if backend=='qemu':command=[driver.tool('qemu-system-riscv64'),'-M','virt','-cpu','rv64','-m','64M','-smp','1','-bios','none','-nographic','-monitor','none','-kernel',binary]
  else:
   obj=B/(backend+'.o');exe=B/('lt-'+backend);driver.asm(ROOT/f'emulator/{backend}.S',obj,backend+'-linux-gnu');driver.run([driver.tool('ld.lld'),'-static','-e','_start',obj,'-o',exe]);command=[driver.tool('qemu-aarch64'),exe,binary,'--interactive']
  began=time.monotonic();r=subprocess.run(list(map(str,command)),capture_output=True,timeout=180)
  if r.returncode or r.stdout!=b'P':raise RuntimeError((backend,r.returncode,r.stdout.hex(),r.stderr.decode()))
  checks.append(dict(backend=backend,result='pass',seconds=time.monotonic()-began,emulated_aarch64=backend=='aarch64'))
 assert before=={str(p):hashlib.sha256(p.read_bytes()).hexdigest()for p in(ROOT/'Guest').glob('*.olean')}
 record=dict(schema=1,result='pass',account_source_sha256=hashlib.sha256(a.account_source.read_bytes()).hexdigest(),fixture_image_bytes=binary.stat().st_size,fixture_image_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),public_native_envelope_sha256=hashlib.sha256(envelope).hexdigest(),checks=checks,production_guest_oleans_unchanged=True,boundaries=['receipt RTT longer than500ticks starts a new500tick interval after completion','real signed timeline and partial-body completions postpone due receipts for GUIhandoff','body requests are admitted during that interval','later due receipt still runs; serials/work/pollcount remain charged','64receipt guard unchanged'],limits='Compiled actual owner functions with exact test-only monotonic-clock/Network39-admission trap. The public envelope is original native common-image event1ed50359…; supplied partial bytes are never displayed or claimed as a complete verified body. No installed Nativekernel grants, storage, policy or network claim; AArch64 assembly backend execution is emulated.')
 (B/'evidence.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))

if __name__=='__main__':main()
