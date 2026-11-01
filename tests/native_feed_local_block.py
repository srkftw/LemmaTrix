"""Compile isolated copies of the real Feed block producer/consumer and controls.

Only build/ fixture modules are compiled. The test-only trap accepts exact
AccountSDK lookup/submit calls; it supplies no event history or native service.
The active campaign and production Guest oleans/packages are never modified.
"""
from __future__ import annotations
import argparse,hashlib,json,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import driver
from structured_runtime import BOOT
B=ROOT/'build/native-feed-local-block'
SOURCE='''import build.FeedLocalBlockUI
import build.FeedLocalBlockAccount
namespace build.NativeFeedLocalBlock
open Guest Guest.LiveSDK
namespace UI
abbrev st := build.FeedLocalBlockUI.st
abbrev selected := build.FeedLocalBlockUI.selected
abbrev eventId := build.FeedLocalBlockUI.eventId
abbrev content := build.FeedLocalBlockUI.content
end UI
def trapState : UInt64 := 0x7aff00
def author : UInt64 := 0x7afe00
partial def zeroed (p words t : UInt64) : Bool :=
 if words == 0 then true else load64 p t == 0 && zeroed (p+8) (words-1) t
partial def filled (p words value t : UInt64) : UInt64 :=
 if words == 0 then t else filled (p+8) (words-1) value (store64 p value t)
def baseline (t : UInt64) : UInt64 :=
 let t := zero UI.st 48 (zero trapState 2 (zero wire 128 t))
 let t := zero build.FeedLocalBlockAccount.st 64 (zero build.FeedLocalBlockAccount.preferences 192 t)
 let t := filled UI.content 2048 0x7478657420646c6f t
 let t := filled UI.selected 60 0x1122334455667788 (filled UI.eventId 4 0x8877665544332211 t)
 let t := store64 author 0x0102030405060708 (store64 (author+8) 0x1112131415161718
  (store64 (author+16) 0x2122232425262728 (store64 (author+24) 0x3132333435363738 t)))
 let t := copy author (UI.selected+112) 32 t
 store64 (UI.st+56) 3 (store64 (UI.st+64) 3 (store64 (UI.st+72) 1600
  (store64 (UI.st+80) 900 (store64 (UI.st+176) 1600 (store64 (UI.st+200) 5 t)))))
def hidden (keepAuthor t : UInt64) : Bool :=
 zeroed UI.content 2048 t && zeroed UI.eventId 4 t && zeroed UI.selected 14 t &&
 zeroed (UI.selected+144) 42 t &&
 (if keepAuthor == 1 then Guest.LiveMemory.equal (UI.selected+112) author 32 t else zeroed (UI.selected+112) 4 t) &&
 load64 (UI.st+72) t == 0 && load64 (UI.st+80) t == 0 && load64 (UI.st+176) t == 0 && load64 (UI.st+200) t == 0
def requestIs (action h a bytes t : UInt64) : Bool :=
 load64 trapState t == 2 && load64 wire t == 480 && load64 (wire+8) t == action &&
 load64 (wire+16) t == h && load64 (wire+24) t == a && load64 (wire+32) t == 0 &&
 load64 (wire+40) t == 0 && load64 (wire+48) t == 0 && load64 (wire+56) t == 1 &&
 load64 (UI.st+8) t == 99 && load64 (UI.st+16) t == action &&
 (bytes == 64 || Guest.LiveMemory.equal (wire+64) author 32 t)
def ownerSelection (filter blocked t : UInt64) : UInt64 :=
 let p := build.FeedLocalBlockAccount.preferences
 let answer := build.FeedLocalBlockAccount.answer
 let st := build.FeedLocalBlockAccount.st
 let t := filled answer 72 0xfedcba9876543210 t
 let t := copy author (answer+208) 32 (store64 (answer+8) 9 (store64 (answer+16) 9 t))
 let t := store64 (st+136) 576 (store64 (st+144) 5 (store64 (st+184) filter t))
 let t := store64 p 1 (store64 (p+8) (if blocked == 1 then 2 else 0) (copy author (p+16) 32 t))
 build.FeedLocalBlockAccount.outcome t
partial def glyphMatches (character row col t : UInt64) : Bool :=
 if row == 9 then true else
 if col == 6 then glyphMatches character (row+1) 0 t else
 let bits := Guest.Raster.glyph character
 let c := if row < 7 && col < 5 && ((bits >>> (row*5+4-col)) &&& 1) == 1 then build.FeedLocalBlockUI.accent else build.FeedLocalBlockUI.bg
 let p := Guest.Raster.pixels+(102+row)*2560+(14+col)*4
 load8 p t == (c &&& 255) && load8 (p+1) t == ((c >>> 8) &&& 255) &&
 load8 (p+2) t == ((c >>> 16) &&& 255) && glyphMatches character row (col+1) t
@[noinline] def check (t : UInt64) : UInt64 :=
 -- The actual owner returns one public author and the same two cursors.
 let t := baseline t
 let n := ownerSelection 0 1 t
 if n != 96 || status n != 15 || result n != 9 || load64 (wire+16) n != 9 || load64 (wire+24) n != 0 ||
  !Guest.LiveMemory.equal (wire+64) author 32 n then 1 else
 let t := build.FeedLocalBlockUI.completed 16 n n
 if load64 (UI.st+32) t != 16 || load64 UI.st t != 1 || load64 (UI.st+56) t != 9 || load64 (UI.st+64) t != 9 || !hidden 1 t then 2 else
 -- Actual rendering shows the local-block notice; no cached body is readable.
 let t := build.FeedLocalBlockUI.draw 0 t
 if !glyphMatches 76 0 0 t then 3 else
 -- Enter uses the returned next cursor, rather than querying the block again.
 let t := build.FeedLocalBlockUI.key 28 t
 if !requestIs 5 9 0 64 t then 4 else
 -- The next admitted row/read can complete after the visible blocked marker.
 let t := build.FeedLocalBlockUI.completed 5 64 (header 0 0 5 0 0 0 0 t)
 let t := zero wire 128 t
 let t := store64 (wire+64) 0x99887766 (store64 (wire+96+112) 0xaabbccdd t)
 let t := store64 (wire+96+176) 1 (header 0 10 10 2 8 1 0 t)
 let t := zero trapState 2 t
 let t := build.FeedLocalBlockUI.completed 16 576 t
 if load64 (UI.st+56) t != 10 || load64 (UI.st+64) t != 10 || load64 (wire+8) t != 6 ||
  load64 (wire+24) t != 8 || load64 (wire+64) t != 0x99887766 then 5 else
 let t := build.FeedLocalBlockUI.completed 6 64 (header 0 0 6 0 0 0 0 t)
 let t := store64 (wire+64) 0x21656c6269736976 (header 0 0 0 0 0 0 0 t)
 let t := build.FeedLocalBlockUI.completed 16 72 t
 if load64 (UI.st+32) t != 15 || load64 (UI.st+72) t != 8 || load64 UI.content t != 0x21656c6269736976 then 6 else
 -- PgDn also starts beyond the blocked row; no stale scroll offset consumes it.
 let t := baseline t
 let n := ownerSelection 0 1 t
 let t := build.FeedLocalBlockUI.completed 16 n n
 let t := build.FeedLocalBlockUI.key 109 t
 if !requestIs 5 9 0 64 t then 7 else
 -- F8 on a filtered marker submits only its public author, then actually
 -- toggles the native owner preference; no event ID or body is needed.
 let t := baseline t
 let n := ownerSelection 0 1 t
 let t := build.FeedLocalBlockUI.completed 16 n n
 let t := build.FeedLocalBlockUI.key 66 t
 if !requestIs 7 2 2 96 t then 8 else
 let t := copy wire command 96 t
 let n := build.FeedLocalBlockAccount.preference 96 t
 if n != 64 || status n != 0 || result n != 2 || load64 (wire+16) n != 0 ||
  build.FeedLocalBlockAccount.blocked author 0 n then 9 else
 let t := build.FeedLocalBlockUI.completed 7 n n
 if load64 (UI.st+32) t != 51 || !hidden 1 t then 10 else
 -- Blocking a currently readable selected row hides it on completion, keeps
 -- pagination, and still provides only the exact public F8 unblock target.
 let t := baseline t
 let t := build.FeedLocalBlockUI.key 66 t
 if !requestIs 7 2 2 96 t then 11 else
 let t := copy wire command 96 t
 let n := build.FeedLocalBlockAccount.preference 96 t
 if n != 64 || load64 (wire+16) n != 1 || !build.FeedLocalBlockAccount.blocked author 0 n then 12 else
 let t := build.FeedLocalBlockUI.completed 7 n n
 if load64 (UI.st+32) t != 18 || load64 (UI.st+56) t != 3 || load64 (UI.st+64) t != 3 || !hidden 1 t then 13 else
 let t := zero trapState 2 t
 let t := build.FeedLocalBlockUI.key 66 t
 if !requestIs 7 2 2 96 t then 14 else
 let t := copy wire command 96 t
 let n := build.FeedLocalBlockAccount.preference 96 t
 if n != 64 || load64 (wire+16) n != 0 || build.FeedLocalBlockAccount.blocked author 0 n then 15 else
 let t := build.FeedLocalBlockUI.completed 7 n n
 if load64 (UI.st+32) t != 51 || !hidden 1 t then 16 else
 -- A followed-only omission remains64 bytes and automatically requests its
 -- next cursor under the selected local filter; it discloses no author.
 let t := store64 (UI.st+160) 1 (baseline t)
 let n := ownerSelection 1 0 t
 if n != 64 || status n != 15 || load64 (wire+24) n != 1 then 17 else
 let t := build.FeedLocalBlockUI.completed 16 n n
 if !requestIs 5 9 1 64 t || !hidden 0 t || load64 (UI.st+56) t != 9 || load64 (UI.st+64) t != 9 then 18 else
 0
end build.NativeFeedLocalBlock
'''
TRAP=''' beqz a0,okay
 j failed
fatal:
 csrr t0,mcause
 li t1,9
 bne t0,t1,unexpected
 li t0,0x805aff00
 ld t1,0(t0)
 beqz t1,lookup
 li t2,1
 bne t1,t2,unexpected
 li t2,133
 bne a7,t2,unexpected
 li t2,77
 bne a0,t2,unexpected
 li t2,0x411000
 bne a1,t2,unexpected
 li t2,1024
 bne a3,t2,unexpected
 li t2,64
 beq a2,t2,accepted_submit
 li t2,96
 bne a2,t2,unexpected
accepted_submit:
 li a0,99
 j admitted
lookup:
 li t2,128
 bne a7,t2,unexpected
 li t2,5
 bne a0,t2,unexpected
 li t2,480
 bne a1,t2,unexpected
 bnez a2,unexpected
 bnez a3,unexpected
 li a0,77
admitted:
 addi t1,t1,1
 sd t1,0(t0)
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
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--backend',action='append',choices=('qemu','aarch64'));a=p.parse_args()
 B.mkdir(parents=True,exist_ok=True)
 before={str(path):hashlib.sha256(path.read_bytes()).hexdigest()for path in (ROOT/'Guest').glob('*.olean')}
 sources={}
 for original,name in(('Feed','FeedLocalBlockUI'),('FeedAccount','FeedLocalBlockAccount')):
  path=ROOT/'Guest'/(original+'.lean');source=path.read_text();sources[original]=hashlib.sha256(path.read_bytes()).hexdigest()
  copied=ROOT/'build'/(name+'.lean');copied.write_text(source.replace('namespace Guest.'+original,'namespace build.'+name+'\nopen Guest').replace('end Guest.'+original,'end build.'+name))
  driver.lean(['-o',copied.with_suffix('.olean'),copied])
 source=ROOT/'build/NativeFeedLocalBlock.lean';source.write_text(SOURCE);driver.lean(['-o',source.with_suffix('.olean'),source])
 assembly=B/'check.S';driver.lean(['--run','Compiler/Main.lean','build.NativeFeedLocalBlock',assembly,'build.NativeFeedLocalBlock.check'])
 boot=BOOT.replace('lt_Examples_StructuredConsumer_check','lt_build_NativeFeedLocalBlock_check').replace(' li t1,0x40000cf',' li t1,0x201000cf\n sd t1,24(t0)\n li t1,0x40000cf')
 boot=boot.replace(' call lt_finish\nfatal:\n li a0,2\n call lt_finish',TRAP);(B/'boot.S').write_text(boot);objects=[]
 for i,path in enumerate((assembly,B/'boot.S',ROOT/'runtime/primitives.S')):
  obj=B/f'{i}.o';driver.asm(path,obj);objects.append(obj)
 elf=B/'check.elf';binary=B/'check.bin';driver.run([driver.tool('ld.lld'),'-m','elf64lriscv','--no-relax','-T',ROOT/'runtime/kernel.ld',*objects,'-o',elf]);driver.run([driver.tool('llvm-objcopy'),'-O','binary',elf,binary]);checks=[]
 for backend in a.backend or('qemu','aarch64'):
  if backend=='qemu':command=[driver.tool('qemu-system-riscv64'),'-M','virt','-cpu','rv64','-m','64M','-smp','1','-bios','none','-nographic','-monitor','none','-kernel',binary]
  else:
   obj=B/(backend+'.o');exe=B/('lt-'+backend);driver.asm(ROOT/f'emulator/{backend}.S',obj,backend+'-linux-gnu');driver.run([driver.tool('ld.lld'),'-static','-e','_start',obj,'-o',exe]);command=[driver.tool('qemu-aarch64'),exe,binary,'--interactive']
  started=time.monotonic();result=subprocess.run(list(map(str,command)),capture_output=True,timeout=180)
  if result.returncode or result.stdout!=b'P':raise RuntimeError((backend,result.returncode,result.stdout.hex(),result.stderr.decode()))
  checks.append(dict(backend=backend,result='pass',seconds=time.monotonic()-started,emulated_aarch64=backend=='aarch64'))
 after={str(path):hashlib.sha256(path.read_bytes()).hexdigest()for path in (ROOT/'Guest').glob('*.olean')};assert before==after,'production Guest oleans changed during isolated fixture'
 report=dict(schema=1,result='pass',sources=sources,fixture_image_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),fixture_image_bytes=binary.stat().st_size,checks=checks,production_guest_oleans_unchanged=True,
  boundaries=['actual owner local-block outcome returns96B header+publicauthor only, preserving both cursors','UI clears cached body, envelope and eventID while retaining only author for F8','native renderer draws visible local-block notice','Enter and PgDn submit returned next cursor; subsequent actual completion/read makes progress','F8 from filtered marker unblocks exact native author preference','F8 block completion immediately hides prior readable row and preserves pagination; second F8 unblocks exact author','followed-only marker stays64B and automatically advances under the same local filter'],
  limits='Compiled native producer/consumer/render/control transition fixture with provisioned public row/preference sentinels. Test-only M-mode trap accepts exact AccountSDK128/133 calls; no real kernel grants, authored history, installed package, networking, retention or complete community claim. AArch64 assembly backend runs under qemu-aarch64.')
 (B/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))

if __name__=='__main__':main()
