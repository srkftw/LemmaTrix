"""Compile the actual Native Feed rejected-query completion boundary in isolation.

The trap supplies only AccountSDK lookup/submit results, not an event service.
No installed actor, key, production Guest olean or social database is touched.
"""
from __future__ import annotations
import argparse,hashlib,json,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import driver
from structured_runtime import BOOT
from native_feed_local_block import TRAP
TRAP=TRAP.replace(' li t0,0x805aff00', ' li t2,134\n beq a7,t2,bad_collect\n li t0,0x805aff00').replace(' li a0,99',' ld a0,8(t0)\n bnez a0,returned_value\n li a0,99\nreturned_value:').replace('unexpected:\n li a0,31','bad_collect:\n li t2,99\n bne a0,t2,unexpected\n li t2,0x411000\n bne a1,t2,unexpected\n li t2,1024\n bne a2,t2,unexpected\n li a0,17\n csrr t0,mepc\n addi t0,t0,4\n csrw mepc,t0\n mret\nunexpected:\n li a0,31')
B=ROOT/'build/native-feed-busy-read'
SOURCE='''import build.FeedBusyReadUI
import build.FeedBusyReadAccount
namespace build.NativeFeedBusyRead
open Guest Guest.LiveSDK
abbrev st := build.FeedBusyReadUI.st
abbrev content := build.FeedBusyReadUI.content
abbrev selected := build.FeedBusyReadUI.selected
abbrev eventId := build.FeedBusyReadUI.eventId
def trapState : UInt64 := 0x7aff00
partial def zeroed (p words t : UInt64) : Bool :=
 if words == 0 then true else load64 p t == 0 && zeroed (p+8) (words-1) t
partial def filled (p words value t : UInt64) : UInt64 :=
 if words == 0 then t else filled (p+8) (words-1) value (store64 p value t)
def baseline (t : UInt64) : UInt64 :=
 let t := zero st 64 (zero trapState 2 (zero wire 128 t))
 let t := filled content 2048 0x72706576696f7573 (filled selected 60 0x1122334455667788 (filled eventId 4 0x8877665544332211 t))
 let t := zero build.FeedBusyReadAccount.st 64 t
 let t := filled build.FeedBusyReadAccount.answer 72 0x1111111111111111 t
 let t := store64 (build.FeedBusyReadAccount.st+136) 576 (store64 (build.FeedBusyReadAccount.st+144) 5 t)
 store64 (st+56) 3 (store64 (st+64) 3 (store64 (st+72) 512
  (store64 (st+176) 1330 (store64 (st+200) 6 (store64 (st+192) 6 (store64 (st+168) 1 (store64 (st+40) 47 t)))))))
def hidden (t : UInt64) : Bool :=
 zeroed content 2048 t && zeroed selected 60 t && zeroed eventId 4 t &&
 load64 (st+200) t == 0 && load64 (st+72) t == 0 && load64 (st+176) t == 0 &&
 load64 (st+56) t == 3 && load64 (st+64) t == 3 && load64 (st+192) t == 6 &&
 load64 (st+168) t == 1 && load64 (st+40) t == 47
def requestIs (action t : UInt64) : Bool :=
 load64 trapState t == 2 && load64 wire t == 480 && load64 (wire+8) t == action &&
 load64 (st+16) t == action && load64 (st+8) t == 99
@[noinline] def check (t : UInt64) : UInt64 :=
 -- A saved timeline answer exists when the new body query is refused busy.
 let t := baseline t
 let t := build.FeedBusyReadUI.completed 6 64 (header 4 0 0 0 6 0 0 t)
 if !hidden t || load64 (st+32) t != 12 || load64 (st+96) t != 4 then 1 else
 -- The real periodic branch chooses inspect, not outcome16, after the abort.
 let t := if load64 (st+200) t != 0 then build.FeedBusyReadUI.submit 16 0 0 0 0 0 0 t else build.FeedBusyReadUI.inspect t
 if !requestIs 0 t then 2 else
 let t := build.FeedBusyReadUI.completed 0 160 (header 0 1 0 0 6 0 0 t)
 if !hidden t then 3 else
 -- The old owner answer is still576 bytes, but is never mistaken for a body.
 let n := build.FeedBusyReadAccount.outcome t
 if n != 576 || load64 (build.FeedBusyReadAccount.answer+64) n != 0x1111111111111111 || !hidden n then 4 else
 -- A rejected timeline start and rejected outcome also clear the same state.
 let t := build.FeedBusyReadUI.completed 5 64 (header 4 0 0 0 6 0 0 (baseline t))
 if !hidden t then 5 else
 let t := build.FeedBusyReadUI.completed 16 64 (header 9 0 0 0 6 0 0 (baseline t))
 if !hidden t then 6 else
 -- Ordinary Enter preserves the native cursor; a fresh admitted timeline and
 -- its own accepted body completion can subsequently be consumed correctly.
 let t := build.FeedBusyReadUI.key 28 t
 if !requestIs 5 t || load64 (wire+16) t != 3 then 7 else
 let t := build.FeedBusyReadUI.completed 5 64 (header 6 0 5 0 6 0 0 t)
 if load64 (st+200) t != 5 then 8 else
 let t := zero wire 128 (zero trapState 2 t)
 let t := store64 (wire+64) 0x99887766 (store64 (wire+96+112) 0xaabbccdd (header 0 4 4 2 8 1 0 t))
 let t := build.FeedBusyReadUI.completed 16 576 t
 if !requestIs 6 t || load64 (wire+24) t != 8 || load64 (wire+64) t != 0x99887766 then 9 else
 let t := build.FeedBusyReadUI.completed 6 64 (header 6 0 6 0 6 0 0 t)
 let t := build.FeedBusyReadUI.completed 16 72 (store64 (wire+64) 0x21656c6269736976 (header 0 0 0 0 6 0 0 t))
 if load64 (st+200) t != 0 || load64 (st+72) t != 8 || load64 content t != 0x21656c6269736976 || load64 eventId t != 0x99887766 then 10 else
 -- Query-specific local submit failure and malformed collection cannot arm
 -- the same stale-response path either; unrelated publication state survives.
 let t := store64 (trapState+8) error (baseline t)
 let t := build.FeedBusyReadUI.submit 6 0 8 0 0 eventId 32 t
 if !hidden t || load64 (st+32) t != 14 then 11 else
 let t := store64 (st+8) 99 (store64 (st+16) 6 (baseline t))
 let t := build.FeedBusyReadUI.collect t
 if !hidden t || load64 (st+32) t != 12 || load64 (st+8) t != 0 then 12 else
 0
end build.NativeFeedBusyRead
'''

def main():
 global B
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--backend',action='append',choices=('qemu','aarch64'));p.add_argument('--ui-source',type=Path,default=ROOT/'Guest/Feed.lean');p.add_argument('--output',type=Path,default=B);a=p.parse_args();B=a.output;B.mkdir(parents=True,exist_ok=True)
 before={str(p):hashlib.sha256(p.read_bytes()).hexdigest()for p in (ROOT/'Guest').glob('*.olean')};sources={}
 for original,name in(('Feed','FeedBusyReadUI'),('FeedAccount','FeedBusyReadAccount')):
  p=a.ui_source if original=='Feed'else ROOT/'Guest'/(original+'.lean');sources[original]=hashlib.sha256(p.read_bytes()).hexdigest();copied=ROOT/'build'/(name+'.lean')
  copied.write_text(p.read_text().replace('namespace Guest.'+original,'namespace build.'+name+'\nopen Guest').replace('end Guest.'+original,'end build.'+name));driver.lean(['-o',copied.with_suffix('.olean'),copied])
 source=ROOT/'build/NativeFeedBusyRead.lean';source.write_text(SOURCE);driver.lean(['-o',source.with_suffix('.olean'),source])
 assembly=B/'check.S';driver.lean(['--run','Compiler/Main.lean','build.NativeFeedBusyRead',assembly,'build.NativeFeedBusyRead.check'])
 boot=BOOT.replace('lt_Examples_StructuredConsumer_check','lt_build_NativeFeedBusyRead_check').replace(' li t1,0x40000cf',' li t1,0x201000cf\n sd t1,24(t0)\n li t1,0x40000cf').replace(' call lt_finish\nfatal:\n li a0,2\n call lt_finish',TRAP)
 (B/'boot.S').write_text(boot);objects=[]
 for i,p in enumerate((assembly,B/'boot.S',ROOT/'runtime/primitives.S')):
  obj=B/f'{i}.o';driver.asm(p,obj);objects.append(obj)
 elf=B/'check.elf';binary=B/'check.bin';driver.run([driver.tool('ld.lld'),'-m','elf64lriscv','--no-relax','-T',ROOT/'runtime/kernel.ld',*objects,'-o',elf]);driver.run([driver.tool('llvm-objcopy'),'-O','binary',elf,binary]);checks=[]
 for backend in a.backend or('qemu','aarch64'):
  if backend=='qemu':command=[driver.tool('qemu-system-riscv64'),'-M','virt','-cpu','rv64','-m','64M','-smp','1','-bios','none','-nographic','-monitor','none','-kernel',binary]
  else:
   obj=B/(backend+'.o');exe=B/('lt-'+backend);driver.asm(ROOT/f'emulator/{backend}.S',obj,backend+'-linux-gnu');driver.run([driver.tool('ld.lld'),'-static','-e','_start',obj,'-o',exe]);command=[driver.tool('qemu-aarch64'),exe,binary,'--interactive']
  began=time.monotonic();r=subprocess.run(list(map(str,command)),capture_output=True,timeout=180)
  if r.returncode or r.stdout!=b'P':raise RuntimeError((backend,r.returncode,r.stdout.hex(),r.stderr.decode()))
  checks.append(dict(backend=backend,result='pass',seconds=time.monotonic()-began,emulated_aarch64=backend=='aarch64'))
 after={str(p):hashlib.sha256(p.read_bytes()).hexdigest()for p in (ROOT/'Guest').glob('*.olean')};assert before==after
 record=dict(schema=1,result='pass',sources=sources,fixture_image_bytes=binary.stat().st_size,fixture_image_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),checks=checks,production_guest_oleans_unchanged=True,boundaries=['busy body6 clears collection and all cached content/identity while preserving pagination, author and accepted publication','periodic branch invokes status0 instead of stale outcome16','prior native owner576B timeline answer remains unconsumed','timeline5 rejection and outcome16 failure share cleanup','ordinary Enter retries current native cursor; later accepted timeline/body renders its own bytes','query-local submit failure and malformed collection clear read state without cancelling owner work'],limits='Compiled actual UI completion/navigation and native owner outcome with public sentinels and exact test-only AccountSDK128/133 trap. No installed service/network/retention or cryptographic-authority claim; AArch64 assembly execution is emulated.')
 (B/'evidence.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))

if __name__=='__main__':main()
