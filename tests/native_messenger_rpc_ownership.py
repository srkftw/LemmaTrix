"""Compiled Delivery RPC lifetime/cleanup; declared Network and clock oracles."""
import argparse,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import driver,onion_crypto as native
SOURCE='''import Guest.MessengerDelivery
namespace build.NativeMessengerRPCOwnership
open Guest Guest.LiveSDK Guest.MessengerDelivery
def oracle : UInt64 := 0x7a1000
def prepared (id purpose deadline clock mode t : UInt64) : UInt64 :=
  let t := zero st 64 (zero preflight 128 (zero oracle 16 t))
  let t := store64 (st+88) id (store64 (st+96) purpose (store64 (st+232) deadline t))
  let t := store64 oracle clock (store64 (oracle+8) mode t)
  store64 ciphertext 0xaabb (store64 commitment 0xccdd (store64 requestId 0xeeff t))
def retained (t : UInt64) : Bool :=
  load64 ciphertext t == 0xaabb && load64 commitment t == 0xccdd && load64 requestId t == 0xeeff
def check (t : UInt64) : UInt64 :=
  -- Actual rpc admission names a finite child deadline with parent margin.
  let t := prepared 0 30 0 1000 1 t
  let t := store64 (st+80) 40 (zero request 128 t)
  let t := rpc 128 30 t
  if t == error || load64 (st+88) t != 41 || load64 (st+232) t != 91000 ||
    load64 (oracle+56) t != 41 || rpcWaitBudget != 90000 || rpcDeadline 0xfffffffffffffff0 != 0xffffffffffffffff then 1 else
  -- A response available past the old5000 limit must be consumed normally.
  let r := collectRPC (store64 oracle 7000 t)
  if load64 (st+88) r != 0 || load64 (preflight+128) r != 5 ||
    load64 (oracle+16) r != 1 || load64 (oracle+24) r != 0 || !retained r then 2 else
  -- Ready wins even exactly on the hard deadline; it is already collected.
  let r := collectRPC (prepared 51 30 90000 90000 1 r)
  if load64 (st+88) r != 0 || load64 (preflight+128) r != 5 ||
    load64 (oracle+24) r != 0 || !retained r then 3 else
  let r := collectRPC (prepared 61 10 90000 89999 0 r)
  if load64 (st+88) r != 61 || load64 (st+232) r != 90000 ||
    load64 (oracle+16) r != 1 || load64 (oracle+24) r != 0 || !retained r then 4 else
  -- Pending at expiry cancels ONLY61 while the native local handle still61.
  let r := collectRPC (store64 oracle 90000 r)
  if load64 (st+88) r != 0 || load64 (st+160) r != 7 || load64 (st+200) r != 14 ||
    load64 (oracle+16) r != 2 || load64 (oracle+24) r != 1 ||
    load64 (oracle+32) r != 61 || load64 (oracle+48) r != 61 || !retained r then 5 else
  -- Malformed and transport-error results use the same exact owned cleanup.
  let r := collectRPC (prepared 71 10 90000 6000 2 r)
  if load64 (st+88) r != 0 || load64 (st+200) r != 9 || load64 (oracle+24) r != 1 ||
    load64 (oracle+32) r != 71 || load64 (oracle+48) r != 71 || !retained r then 6 else
  let r := collectRPC (prepared 81 10 90000 6000 3 r)
  if load64 (st+88) r != 0 || load64 (st+200) r != 14 || load64 (oracle+24) r != 1 ||
    load64 (oracle+32) r != 81 || load64 (oracle+48) r != 81 || !retained r then 7 else
  let r := collectRPC (prepared 0 10 90000 90000 0 r)
  if load64 (oracle+16) r != 0 || load64 (oracle+24) r != 0 || !retained r then 8 else
  -- A valid new session-owner binding does not rewind this Delivery's counter.
  let t := zero Guest.ForgeRouted.st 512 (prepared 0 10 0 1000 0 r)
  let t := store64 st 66 (store64 (st+80) 991 (store64 (Guest.ForgeRouted.st+16) 1001
    (store64 (command+8) 77 t)))
  let r := configure 123 64 t
  if status r != 0 || load64 st r != 77 || load64 (st+80) r != 1001 ||
    load64 (st+8) r != 222 || load64 (oracle+64) r != 1 then 9 else
  -- A completed foreground serial joins the same monotonically increasing lane.
  let t := store64 Guest.ForgeRouted.st 3 (store64 (Guest.ForgeRouted.st+16) 2001 r)
  let r := syncForgeSerial t
  if load64 (st+80) r != 2001 then 10 else
  let r := syncForgeSerial (store64 (Guest.ForgeRouted.st+16) 2000 r)
  if load64 (st+80) r != 2001 then 11 else
  -- Reconfiguration cannot discard an active or queued foreground request.
  let t := store64 st 66 (store64 (st+8) 0 (store64 (st+152) 0
    (store64 Guest.ForgeRouted.st 1 r)))
  let r := configure 123 64 t
  if status r != 4 || load64 st r != 66 || load64 (st+80) r != 2001 ||
    load64 Guest.ForgeRouted.st r != 1 then 12 else
  let r := configure 123 64 (store64 Guest.ForgeRouted.st 3 (store64 foreground 1 r))
  if status r != 4 || load64 foreground r != 1 || load64 (st+80) r != 2001 then 13 else 0
end build.NativeMessengerRPCOwnership
'''
TRAP='''
fixtureTrap:
 csrr t0,mcause
 li t1,9
 bne t0,t1,fatal
 li t0,0x805a1000
 li t1,116
 beq a7,t1,fixtureClock
 li t1,128
 beq a7,t1,fixtureEndpoint
 li t1,131
 beq a7,t1,fixtureGrant
 li t1,133
 beq a7,t1,fixtureOwner
 li t1,30
 bne a7,t1,fatal
 li t1,6
 bne a0,t1,fatal
 li t1,0x411000
 bne a1,t1,fatal
 li t1,0x80211000
 ld t2,0(t1)
 ld t5,8(t1)
 li t3,39
 beq t2,t3,fixtureSubmit
 li t3,40
 beq t2,t3,fixturePoll
 li t3,42
 bne t2,t3,fatal
 ld t2,24(t0)
 addi t2,t2,1
 sd t2,24(t0)
 sd t5,32(t0)
 li t2,0x80450058
 ld t2,0(t2)
 sd t2,48(t0)
 sd zero,0(t1)
 li a0,64
 j fixtureReturn
fixtureSubmit:
 sd t5,56(t0)
 sd zero,0(t1)
 li a0,64
 j fixtureReturn
fixturePoll:
 ld t2,16(t0)
 addi t2,t2,1
 sd t2,16(t0)
 ld t4,8(t0)
 li t2,3
 beq t4,t2,fixtureError
 mv t2,t1
 li t3,16
fixtureZero:
 sd zero,0(t2)
 addi t2,t2,8
 addi t3,t3,-1
 bnez t3,fixtureZero
 beqz t4,fixturePending
 sd t5,8(t1)
 li t2,64
 sd t2,16(t1)
 li t2,2
 beq t4,t2,fixtureMalformed
 li a0,128
 j fixtureReturn
fixtureMalformed:
 li t2,63
 sd t2,16(t1)
 li a0,127
 j fixtureReturn
fixturePending:
 li t2,6
 sd t2,0(t1)
 li a0,64
 j fixtureReturn
fixtureError:
 li a0,-1
 j fixtureReturn
fixtureEndpoint:
 li t1,2
 bne a0,t1,fatal
 li t1,434
 bne a1,t1,fatal
 li a0,77
 j fixtureReturn
fixtureGrant:
 li t1,123
 bne a0,t1,fatal
 li a0,0
 j fixtureReturn
fixtureOwner:
 li t1,77
 bne a0,t1,fatal
 li t1,0x411000
 bne a1,t1,fatal
 li t1,64
 bne a2,t1,fatal
 ld t1,64(t0)
 addi t1,t1,1
 sd t1,64(t0)
 li a0,222
 j fixtureReturn
fixtureClock:
 ld a0,0(t0)
fixtureReturn:
 csrr t0,mepc
 addi t0,t0,4
 csrw mepc,t0
 mret
'''
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--backend',action='append',choices=('qemu','aarch64'));p.add_argument('--output',type=Path,default=ROOT/'build/native-messenger-rpc-ownership');a=p.parse_args()
 native.B=a.output.resolve();binary=native.build(SOURCE,'NativeMessengerRPCOwnership')
 boot=native.B/'boot.S';boot.write_text(boot.read_text().replace(' la t0,fatal',' la t0,fixtureTrap')+TRAP)
 driver.asm(boot,native.B/'1.o');driver.run([driver.tool('ld.lld'),'-m','elf64lriscv','--no-relax','-T',ROOT/'runtime/kernel.ld',*(native.B/f'{i}.o'for i in range(3)),'-o',native.B/'check.elf']);driver.run([driver.tool('llvm-objcopy'),'-O','binary',native.B/'check.elf',binary])
 report=dict(schema=1,result='pass',image_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),delivery_source_sha256=hashlib.sha256((ROOT/'Guest/MessengerDelivery.lean').read_bytes()).hexdigest(),fixture_source_sha256=hashlib.sha256(SOURCE.encode()).hexdigest(),checks=[native.execute(binary,b)for b in a.backend or('qemu','aarch64')],boundaries=['actual rpc admits90000tick bounded deadline with10000tick margin before parent100000; addition saturates','late response available beyond old5000tick limit and ready at harddeadline both complete without cancellation','pending read does not renew its deadline; expiry polls then cancels exact nonzero current request before dropping its local handle','malformed or failed network results also cancel the exact owned request before failure; ciphertext commitment and stable request state survive','no pending local request causes no poll or cancellation','actual valid configuration preserves the maximum live RPC serial across a session-owner change; completed Forge counter synchronization cannot rewind it','configuration refuses active or queued foreground work without discarding its ownership'],limits='Actual compiled MessengerDelivery rpc/collectRPC transitions. Declared Network/clock and current Owner endpoint/grant/admission oracles supply response bytes, permit configuration, and record exact42 request/local handle; it does not implement a kernel grant, real Network cancellation, mailbox, wire, durability or AEAD. The separate c514 terminal-request fixture verifies actual stale42 refusal/isolation. AArch64 assembly backend is emulated under qemu-aarch64.')
 (native.B/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
