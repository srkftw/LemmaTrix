"""Execute shipped finite grant refresh rules with public broker state fixtures.

The trap supplies exact owner liveness. These checks exercise the real refresh,
expiry, revoke and reset helpers; they establish no network delivery or signing.
"""
import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import driver,live_build,onion_crypto
from structured_runtime import BOOT
from campaign010_terminal_queue import TRAP
B=ROOT/'build/campaign010-grant-lease'
SOURCE='''import Guest.Network
import Guest.NetworkGrantLease
namespace build.Campaign010GrantLease
open Guest Guest.LiveSDK
open Guest.Network
def authority : UInt64 := 0x7a0000
def saved : UInt64 := 0x7a1000
def seed (t : UInt64) : UInt64 :=
  let t := zero st 32 (zero control 32 (zero pins 16 (zero (grantAt 0) 128 (zero (jobAt 0) 1024 (zero Guest.PeerDescription.st 16 (zero authority 2 t))))))
  let t := store64 st 1000 (store64 (st+8) 2 (store64 (control+8) 7 t))
  let t := store64 pins 11 (store64 (pins+64) 22 t)
  let g := grantAt 0
  let t := store64 g 1 (store64 (g+8) (localId 0 1 t) (store64 (g+16) 101 (store64 (g+24) 3 t)))
  let t := store64 (g+32) 4096 (store64 (g+40) 512 (store64 (g+48) 2048 (store64 (g+56) 1100 t)))
  let t := store64 (g+64) 1000 (store64 (g+72) 256 (store64 (g+80) 1 (store64 (g+88) 23 t)))
  copy g saved 256 (store64 (g+96) 11 (store64 (g+128) 22 (store64 (g+160) 33 t)))
def contractUnchanged (t : UInt64) : Bool :=
  equal (grantAt 0+8) (saved+8) 48 t && equal (grantAt 0+64) (saved+64) 192 t
def check (t : UInt64) : UInt64 :=
  let t := seed t
  let g := grantAt 0
  let handle := load64 (g+8) t
  let r := refreshLease 101 handle 0 t
  if r != 64 || status r != 0 || load64 (wire+16) r != 3584 || load64 (wire+24) r != 512 ||
    load64 (wire+32) r != 1100 || !equal g saved 256 r then 1 else
  let r := refreshLease 101 handle 50 r
  if r != 64 || status r != 0 || load64 (g+56) r != 1050 || !contractUnchanged r then 2 else
  let t := store64 (g+56) 900 (seed r)
  let t := expireGrants 0 t
  if load64 g t != 0 || load64 (g+56) t != 900 || !contractUnchanged t then 3 else
  let r := refreshLease 101 handle 100000 t
  if status r != 0 || load64 g r != 1 || load64 (g+56) r != 101000 ||
    load64 (wire+16) r != 3584 || load64 (wire+24) r != 512 || !contractUnchanged r then 4 else
  let t := store64 (g+40) 4096 (seed r)
  let r := refreshLease 101 handle 100 t
  if status r != 4 || load64 (g+40) r != 4096 || load64 (g+56) r != 1100 then 5 else
  let r := refreshLease 101 handle 0 r
  if status r != 0 || load64 (wire+16) r != 0 || load64 (wire+24) r != 4096 then 6 else
  let r := refreshLease 102 handle 100 (seed r)
  if status r != 3 || !equal g saved 256 r then 7 else
  let r := refreshLease 101 handle 100 (store64 pins 12 (seed r))
  if status r != 3 || !equal g saved 256 r then 8 else
  let r := refreshLease 101 handle 100 (store64 (pins+64) 23 (seed r))
  if status r != 3 || !equal g saved 256 r then 9 else
  let r := refreshLease 101 handle 100 (store64 (st+8) 0 (seed r))
  if status r != 3 || !equal g saved 256 r then 10 else
  let t := store64 (jobAt 0) 1 (store64 (jobAt 0+24) handle (seed r))
  let r := refreshLease 101 handle 100 t
  if status r != 4 || !equal g saved 256 r then 11 else
  let r := refreshLease 101 handle 100 (store64 (jobAt 0) 4 r)
  if status r != 0 || !contractUnchanged r then 12 else
  let r := refreshLease 101 handle 100001 (seed r)
  if status r != 4 || !equal g saved 256 r then 13 else
  let t := store64 st 18446744073709551600 (seed r)
  let r := refreshLease 101 handle 100 t
  if status r != 4 || !equal g saved 256 r then 14 else
  let t := seed r
  let t := zero (bank 1) 8192 t
  let t := selectContext 1 t
  let r := refreshLease 101 handle 100 t
  if status r != 3 then 15 else
  let t := selectContext 0 r
  if !equal g saved 256 t then 16 else
  let t := store64 (g+56) 900 (seed t)
  let t := expireGrants 0 t
  let r := dispatchOrdinary 101 8 handle 64 t
  if status r != 0 || load64 (g+8) r != 0 || load64 (g+56) r != 0 then 17 else
  let r := refreshLease 101 handle 100 r
  if status r != 3 then 18 else
  let t := disconnect 16 (seed r)
  let r := refreshLease 101 handle 100 t
  if status r != 3 || load64 (g+8) r != 0 then 19 else
  let t := store64 authority 101 (seed r)
  let r := refreshLease 101 handle 100 t
  if status r != 3 || !equal g saved 256 r then 20 else
  let t := expireGrants 0 r
  if load64 g t != 0 || load64 (g+8) t != 0 || load64 (g+56) t != 0 then 21 else
  let r := refreshLease 101 handle 100 (store64 authority 0 t)
  if status r != 3 then 22 else
  let t := seed r
  let t := store64 (g+8) (localId 0 2 t) t
  let r := refreshLease 101 handle 100 t
  if status r != 3 || load64 (g+8) r != localId 0 2 r then 23 else
  let t := seed r
  let t := zero command 8 t
  let r := dispatchOrdinary 101 17 handle 64 (store64 (command+16) 100 t)
  if status r != 0 || load64 (g+56) r != 1100 || !contractUnchanged r then 24 else
  if Guest.NetworkGrantLease.accepts false true true 4096 512 1 1000 then 25 else
  if Guest.NetworkGrantLease.accepts true false true 4096 512 1 1000 then 26 else
  if Guest.NetworkGrantLease.accepts true true false 4096 512 1 1000 then 27 else
  if Guest.NetworkGrantLease.accepts true true true 4096 4096 1 1000 then 28 else
  if Guest.NetworkGrantLease.accepts true true true 4096 4097 1 1000 then 29 else
  if Guest.NetworkGrantLease.accepts true true true 4096 512 0 1000 then 30 else
  if Guest.NetworkGrantLease.accepts true true true 4096 512 100001 1000 then 31 else
  if Guest.NetworkGrantLease.accepts true true true 4096 512 100 18446744073709551600 then 32 else
  if !Guest.NetworkGrantLease.accepts true true true 4096 4095 100000 1000 then 33 else
  let t := store64 (g+40) 4097 (seed r)
  let r := refreshLease 101 handle 0 t
  if status r != 3 || load64 (g+40) r != 4097 || load64 (g+56) r != 1100 || load64 (wire+16) r != 0 then 34 else
  let r := refreshLease 101 handle 100 r
  if status r != 3 || load64 (g+40) r != 4097 || load64 (g+56) r != 1100 then 35 else 0
end build.Campaign010GrantLease
'''
BOUNDARIES=['owner inspection returns exact remaining/used and changes no bytes','active refresh changes only lease state/expiry','expired tombstone retains exact contract and finite spent allowance','exhausted grants refuse refresh while owner inspection reports zero remaining','wrong caller, peer, service or absent relationship refuses refresh','pending immutable send blocks refresh until reconciled/cancelled','lifetime100001 and UInt64 clock wrap refuse refresh','wrong context cannot collect or refresh another context grant','explicit revocation of expired tombstone erases authority permanently','relationship reset and dead-owner cleanup erase authority','slot reuse cannot revive old incarnation-bound handle','malformed used greater than budget refuses inspection and refresh without unsigned underflow','actual op17 dispatch reaches the same shipped refresh helper','policy independently rejects missing ownership/current context/idle state, exhaustion and invalid lifetime']
def main():
 B.mkdir(parents=True,exist_ok=True);live_build.compile_module('Guest.Network')
 path=ROOT/'build/Campaign010GrantLease.lean';path.write_text(SOURCE);driver.lean(['-o',path.with_suffix('.olean'),path])
 assembly=B/'check.S';driver.lean(['--run','Compiler/Main.lean','build.Campaign010GrantLease',assembly,'build.Campaign010GrantLease.check'])
 boot=BOOT.replace('lt_Examples_StructuredConsumer_check','lt_build_Campaign010GrantLease_check').replace(' li t1,0x40000cf',' li t1,0x201000cf\n sd t1,24(t0)\n li t1,0x40000cf').replace(' call lt_finish\nfatal:\n li a0,2\n call lt_finish',TRAP)
 (B/'boot.S').write_text(boot);objects=[]
 for i,p in enumerate((assembly,B/'boot.S',ROOT/'runtime/primitives.S')):
  obj=B/f'{i}.o';driver.asm(p,obj);objects.append(obj)
 elf=B/'check.elf';binary=B/'check.bin';driver.run([driver.tool('ld.lld'),'-m','elf64lriscv','--no-relax','-T',ROOT/'runtime/kernel.ld',*objects,'-o',elf]);driver.run([driver.tool('llvm-objcopy'),'-O','binary',elf,binary]);onion_crypto.B=B
 report=dict(schema=1,result='pass',image_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),source_sha256={n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest()for n in('Guest/Network.lean','Guest/NetworkGrantLease.lean')},checks=[onion_crypto.execute(binary,b)for b in('qemu','aarch64')],cases=35,boundaries=BOUNDARIES,environment='x86-64 Linux: QEMU RV64 system emulation and AArch64 assembly emulator under qemu-aarch64; no physical ARM hardware claim',limitations=__doc__)
 (B/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
