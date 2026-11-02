"""Execute shipped transport framing and known publisher lineage predicates.

The clock is supplied by a test trap. Public state fixtures test refusal and
slot isolation; this is not network delivery or publisher signing evidence.
"""
import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import driver,live_build,onion_crypto
from structured_runtime import BOOT
from campaign010_terminal_queue import TRAP
B=ROOT/'build/campaign010-source-import-policy'
SOURCE='''import Guest.Network
import Guest.ProjectPublisher
import Guest.Launcher
import Guest.SourceImportPolicy
namespace build.Campaign010TransportLineage
open Guest Guest.LiveSDK
def packet (op version t : UInt64) : UInt64 :=
  store64 (command+56) version (store64 command op (zero command 8 t))
partial def fillProjects (i t : UInt64) : UInt64 :=
  if i == 15 then t else fillProjects (i+1) (store64 (Guest.Launcher.project i) 1 t)
def check (t : UInt64) : UInt64 :=
  let t := zero Guest.Network.st 32 (zero Guest.Network.control 32 (zero Guest.Transport.st 512 (zero Guest.OnionTerminal.control 64 (zero Guest.OnionTerminal.st 4096 (zero 0x770000 8192 t)))))
  let t := store64 Guest.Transport.st 1 t
  if Guest.Network.transportSlot 0 t != 12 || Guest.Network.transportSlot 3 t != 15 then 1 else
  let r := Guest.Network.dispatch 101 1024 64 (packet 40 1 t)
  if status r != 8 then 2 else
  let r := Guest.Network.dispatch 101 1024 64 (packet 1 1 r)
  if status r != 2 then 3 else
  let t := store64 Guest.Transport.st 0 (store64 (Guest.Network.st+8) 2 r)
  let r := Guest.Network.dispatch 101 0x100000000 64 (packet 16 2 t)
  if status r != 8 || Guest.Transport.enabled r then 4 else
  let t := store64 (Guest.Network.st+8) 0 r
  let r := Guest.Network.dispatch 101 0x100000000 64 (packet 16 2 t)
  if r != 160 || status r != 0 || Guest.Transport.selected r != 12 then 5 else
  let r := Guest.Network.dispatch 101 0x100000000 64 (packet 16 770 r)
  if r != 160 || status r != 0 || Guest.Transport.selected r != 15 then 6 else
  let t := store64 (Guest.Network.control+128) 1 r
  if Guest.Network.transportSlot 0 t != 12 || Guest.Network.transportSlot 3 t != 15 then 7 else
  let t := zero Guest.ProjectPublisher.st 64 (zero Guest.ProjectPublisher.h 64 (zero (Guest.ProjectPublisher.history 0) 80 t))
  let t := store64 (Guest.ProjectPublisher.h+128) 11 (store64 (Guest.ProjectPublisher.st+128) 22 t)
  if !Guest.ProjectPublisher.lineageCurrent t then 8 else
  let p := Guest.ProjectPublisher.history 0
  let t := store64 p 1 (store64 (p+8) 33 (store64 (p+128) 22 t))
  if Guest.ProjectPublisher.lineageCurrent t then 9 else
  let t := store64 (Guest.ProjectPublisher.st+128) 44 t
  if !Guest.ProjectPublisher.lineageCurrent t then 10 else
  let t := store64 (Guest.ProjectPublisher.h+128) 33 (store64 (Guest.ProjectPublisher.h+288) 55 (store64 (p+40) 55 (store64 (p+72) 1 (store64 (Guest.ProjectPublisher.h+72) 2 t))))
  if !Guest.ProjectPublisher.lineageCurrent t then 11 else
  let t := store64 (Guest.ProjectPublisher.h+96) 99 t
  if Guest.ProjectPublisher.lineageCurrent t then 12 else
  let t := zero (Guest.Launcher.project 0) 256 (zero 0x6c6000 4 t)
  let p := Guest.Launcher.project 15
  let t := store64 p 1 (store64 (p+8) 123 (store64 (p+72) 9 (store64 0x6c6000 123 t)))
  if Guest.Launcher.findProject 0x6c6000 0 t != 16 || Guest.Launcher.freeProject 0 t != 1 then 13 else
  if !Guest.Launcher.referenced 8 0 t then 14 else
  let t := fillProjects 0 t
  if Guest.Launcher.freeProject 0 t != 0 then 15 else
  if !Guest.SourceImportPolicy.accepts false 1 64 1048576 192 then 16 else
  if Guest.SourceImportPolicy.accepts false 1 65 1048576 192 then 17 else
  if Guest.SourceImportPolicy.accepts false 1 64 1048577 192 then 18 else
  if Guest.SourceImportPolicy.accepts false 5 64 1048576 704 then 19 else
  if !Guest.SourceImportPolicy.accepts true 5 64 4194304 704 then 20 else
  if Guest.SourceImportPolicy.accepts false 1 32 280261 191 then 21 else 0
end build.Campaign010TransportLineage
'''
def main():
 B.mkdir(parents=True,exist_ok=True)
 for module in ('Guest.Network','Guest.Launcher','Guest.SourceImportPolicy'):live_build.compile_module(module)
 path=ROOT/'build/Campaign010TransportLineage.lean';path.write_text(SOURCE);driver.lean(['-o',path.with_suffix('.olean'),path])
 assembly=B/'check.S';driver.lean(['--run','Compiler/Main.lean','build.Campaign010TransportLineage',assembly,'build.Campaign010TransportLineage.check'])
 boot=BOOT.replace('lt_Examples_StructuredConsumer_check','lt_build_Campaign010TransportLineage_check').replace(' li t1,0x40000cf',' li t1,0x201000cf\n sd t1,24(t0)\n li t1,0x40000cf').replace(' call lt_finish\nfatal:\n li a0,2\n call lt_finish',TRAP)
 (B/'boot.S').write_text(boot);objects=[]
 for i,p in enumerate((assembly,B/'boot.S',ROOT/'runtime/primitives.S')):
  obj=B/f'{i}.o';driver.asm(p,obj);objects.append(obj)
 elf=B/'check.elf';binary=B/'check.bin';driver.run([driver.tool('ld.lld'),'-m','elf64lriscv','--no-relax','-T',ROOT/'runtime/kernel.ld',*objects,'-o',elf]);driver.run([driver.tool('llvm-objcopy'),'-O','binary',elf,binary]);onion_crypto.B=B
 report=dict(schema=1,result='pass',image_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),checks=[onion_crypto.execute(binary,b)for b in ('qemu','aarch64')],boundaries=['MUX reserves bulk12..15 before router setup','frozen SDK terminal v1 keeps caller ownership checks','legacy raw connection cannot migrate into MUX','ordinary v1 bulk is rejected under MUX','peer bank3 selects channel15','known logical identity cannot switch publisher without fork','current parent and newer version required','installed project16 remains discoverable and protects its retained release','full16-project metadata table refuses further allocation','ordinary source import admits64nodes within1MiB','node65 and ordinarybyte/root/length escalation rejected','privileged bootstrap keeps existing4MiB/sixroot bounds'],limits=__doc__)
 (B/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
