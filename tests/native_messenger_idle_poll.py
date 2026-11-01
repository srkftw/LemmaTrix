"""Compiled Delivery idle-probe liveness with an explicit finite parent oracle.

Only namespace-renamed build/ copies are compiled. A test-only Network/clock
trap counts each actual admission and never refunds its attempts/payload bytes.
This is not a live Mailbox, kernel authority or encrypted Messenger journey.
"""
from __future__ import annotations
import argparse,hashlib,json,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import driver,native_messenger_rpc_ownership as ownership
from structured_runtime import BOOT
B=ROOT/'build/native-messenger-idle-poll'
SOURCE='''import build.MessengerIdleDelivery
namespace build.NativeMessengerIdlePoll
open Guest Guest.LiveSDK build.MessengerIdleDelivery
def oracle : UInt64 := 0x7a2000
def reply : UInt64 := 0x7a3000
def useful : UInt64 := 0x7a4000
def baseline (t : UInt64) : UInt64 :=
 let t := zero st 64 (zero preflight 128 (zero parked 256 (zero oracle 16 (zero reply 128 t))))
 let t := store64 oracle 1000 (store64 (oracle+8) 4096 (store64 (oracle+112) 0xbeef t))
 let t := store64 st 77 (store64 (preflight+40) 17 (store64 (st+24) 11 t))
 let t := makeRequest 5 0 0 512 t
 copy wire answer 64 (copy wire reply 64 t)
def empty (t : UInt64) : UInt64 :=
 let t := header 6 0 0 0 0 0 0 t
 store64 (oracle+72) 64 (copy wire reply 64 (copy wire answer 64 t))
partial def probes (remaining t : UInt64) : UInt64 :=
 if remaining == 0 then t else
 let r := rpc 128 10 (empty t)
 if r == error then error else
 let r := collectRPC r
 if load64 (st+88) r != 0 || load64 (st+216) r != 7 || load64 (st+160) r != 0 ||
  load64 (preflight+40) r != 17 || load64 (st+24) r != 11 then error else probes (remaining-1) r
def usefulReply (offset count t : UInt64) : UInt64 :=
 let t := header 0 77 608 offset count 0 0 t
 let t := copy wire reply 64 t
 store64 (oracle+72) (64+count) (copy (useful+offset) (reply+64) count t)
def rejectBase (t : UInt64) : UInt64 :=
 store64 (st+216) 9 (empty (baseline t))
def noRefund (purpose length t : UInt64) : Bool :=
 let r := rpcCompleted purpose length t
 load64 (st+216) r == 9
@[noinline] def refusals (t : UInt64) : UInt64 :=
'''
# Each is a single concrete departure from the exact completed empty probe.
NEGATIVE=[('nonzero pending mailbox handle','answer+8',77,10,64),('nonzero total','answer+16',1,10,64),
 ('nonzero result offset','answer+24',1,10,64),('nonzero result count','answer+32',1,10,64),
 ('extra response field','answer+40',1,10,64),('wrong response version','answer+56',2,10,64),
 ('wrong request operation','request',440,10,64),('wrong request action','request+8',4,10,64),
 ('selected request handle','request+16',77,10,64),('partial request offset','request+24',512,10,64),
 ('different request count','request+32',256,10,64),('wrong request version','request+56',2,10,64),
 ('uncollected RPC','st+88',99,10,64),('partial receive phase','st+160',1,10,64),
 ('owner-commit phase','st+160',2,10,64),('partial receive offset','st+136',1,10,64),
 ('explicitly selected attachment','st+280',1,10,64),('wrong reply length',None,0,10,72),
 ('nonempty success response','answer',0,10,64),('sender purpose',None,0,2,64),
 ('ACK purpose',None,0,11,64),('preflight purpose',None,0,31,64)]
for i,(_,address,value,purpose,length) in enumerate(NEGATIVE,1):
 SOURCE+=' let t := rejectBase t\n'
 if address:SOURCE+=f' let t := store64 ({address}) {value} t\n'
 SOURCE+=f' if !noRefund {purpose} {length} t then {i} else\n'
SOURCE+='''
 -- A valid completed idle response returns exactly one charge, never all work.
 let t := store64 (st+80) 123 (rejectBase t)
 let r := rpcCompleted 10 64 t
 if load64 (st+216) r != 8 || load64 (st+328) r != 1 || load64 (st+80) r != 123 || load64 (preflight+40) r != 17 || load64 (st+24) r != 11 then 23 else
 let r := rpcCompleted 10 64 (store64 (st+216) 0 (empty (baseline r)))
 if load64 (st+216) r != 0 || load64 (st+328) r != 0 then 24 else
 let r := rpcCompleted 10 64 (store64 (st+328) 0xffffffffffffffff (rejectBase r))
 if load64 (st+328) r != 0xffffffffffffffff then 35 else 0
@[noinline] def check (t : UInt64) : UInt64 :=
 let r := refusals t
 if r != 0 then r else
 -- More than the512-workflow guard's limit can elapse as successful empty
 -- idle probes; seven previously charged work units remain throughout.
 let t := probes 600 (store64 (st+216) 7 (empty (baseline r)))
 if t == error then 25 else
 if load64 (st+328) t != 600 || load64 (st+80) t != 600 || load64 (oracle+16) t != 600 || load64 (oracle+24) t != 76800 ||
  load64 (oracle+32) t != 600 || load64 (oracle+40) t != 0 || load64 (oracle+48) t != 0 then 26 else
 -- One real bounded attachment blob follows those probes. Both chunks pass
 -- the actual coordinator decoder/hash/park path, without idle refunds.
 let t := zero useful 76 t
 let t := store64 useful blobMagic (store64 (useful+8) 1 (store64 (useful+16) 0x12345678
  (store64 (useful+56) 1 (store64 (useful+72) 528 t))))
 let t := store64 (useful+600) 0xaabbccdd t
 let r := rpc 128 10 (usefulReply 0 512 t)
 if r == error then 27 else
 let t := collectRPC r
 if load64 (st+160) t != 1 || load64 (st+136) t != 512 || load64 (st+216) t != 8 then 28 else
 let r := rpc 128 10 (usefulReply 512 96 (makeRequest 5 77 512 512 t))
 if r == error then 29 else
 let t := collectRPC r
 if load64 parked t != 77 || load64 (parked+104) t != 608 || load64 (parked+88) t != 1 ||
  load64 (st+160) t != 0 || load64 (st+136) t != 0 || load64 (st+216) t != 0 ||
  load64 (st+328) t != 600 || load64 (st+80) t != 602 || load64 (oracle+16) t != 602 || load64 (oracle+24) t != 77056 then 30 else
 -- The unchanged local guard rejects non-idle workflow work at512 before
 -- making a Network call. No serial, pending token or parent budget changes.
 let t := store64 (st+216) 512 (empty (baseline t))
 let r := rpc 128 10 t
 if r != error || load64 (st+80) r != 0 || load64 (st+88) r != 0 || load64 (oracle+16) r != 0 then 31 else
 -- Local idle liveness never renews finite parent authority. Its second
 -- request is refused after one paid successful empty probe, with no refund.
 let t := store64 (oracle+8) 1 (empty (baseline r))
 let r := rpc 128 10 t
 if r == error then 32 else
 let t := collectRPC r
 if load64 (st+216) t != 0 then 33 else
 let r := rpc 128 10 (empty t)
 if r != error || load64 (oracle+16) r != 1 || load64 (oracle+24) r != 128 ||
  load64 (oracle+88) r != 1 || load64 (st+80) r != 2 || load64 (st+216) r != 0 then 34 else
 -- Public diagnostic action5 is current-token and Launcher-only. It reports
 -- scalars without mutating counters, workflow, current request or authority.
 let t := store64 (st+216) 7 (store64 (st+80) 602 (store64 (st+88) 55
  (store64 (st+160) 1 (store64 (st+200) 14 (store64 (st+328) 600 r)))))
 let t := header 464 0 5 0 0 0 0 t
 let t := copy wire command 64 t
 let r := dispatch 42 0 999 64 t
 if status r != 1 || load64 (st+216) r != 7 || load64 (st+328) r != 600 then 36 else
 let r := dispatch 42 0x100000000 999 64 r
 if r != 64 || status r != 0 || result r != 7 || load64 (wire+16) r != 602 || load64 (wire+24) r != 55 ||
  load64 (wire+32) r != 1 || load64 (wire+40) r != 14 || load64 (wire+48) r != 600 ||
  load64 (st+216) r != 7 || load64 (st+80) r != 602 || load64 (st+88) r != 55 || load64 (st+328) r != 600 then 37 else 0
end build.NativeMessengerIdlePoll
'''
TRAP='''
fixtureTrap:
 csrr t0,mcause
 li t1,9
 bne t0,t1,fatal
 li t0,0x805a2000
 li t1,116
 beq a7,t1,clock
 li t1,131
 beq a7,t1,current_token
 li t1,30
 bne a7,t1,fatal
 li t1,6
 bne a0,t1,fatal
 li t1,0x411000
 bne a1,t1,fatal
 li t1,1024
 bne a3,t1,fatal
 li t1,0x80211000
 ld t2,0(t1)
 ld t5,8(t1)
 li t3,39
 beq t2,t3,admit
 li t3,40
 beq t2,t3,poll
 li t3,42
 bne t2,t3,fatal
 li t3,64
 bne a2,t3,fatal
 ld t2,40(t0)
 bne t5,t2,fatal
 sd t5,56(t0)
 li t2,0x80450058
 ld t3,0(t2)
 sd t3,64(t0)
 ld t2,48(t0)
 addi t2,t2,1
 sd t2,48(t0)
 sd zero,40(t0)
 j response_ok
admit:
 li t3,192
 bne a2,t3,fatal
 ld t2,104(t0)
 bgeu t2,t5,fatal
 sd t5,104(t0)
 ld t2,16(t0)
 ld t3,8(t0)
 bgeu t2,t3,exhausted
 addi t2,t2,1
 sd t2,16(t0)
 ld t2,24(t0)
 addi t2,t2,128
 sd t2,24(t0)
 sd t5,40(t0)
 j response_ok
exhausted:
 ld t2,88(t0)
 addi t2,t2,1
 sd t2,88(t0)
 li t2,4
 j response_code
poll:
 li t3,64
 bne a2,t3,fatal
 ld t2,40(t0)
 bne t5,t2,fatal
 ld t2,32(t0)
 addi t2,t2,1
 sd t2,32(t0)
 ld t2,80(t0)
 bnez t2,pending
 sd zero,40(t0)
 sd zero,0(t1)
 sd zero,8(t1)
 ld t3,72(t0)
 sd t3,16(t1)
 sd zero,24(t1)
 sd zero,32(t1)
 sd zero,40(t1)
 sd zero,48(t1)
 li t2,1
 sd t2,56(t1)
 li t2,0x805a3000
 addi t4,t1,64
 mv t5,t3
copy_response:
 beqz t5,copied
 ld t6,0(t2)
 sd t6,0(t4)
 addi t2,t2,8
 addi t4,t4,8
 addi t5,t5,-8
 j copy_response
copied:
 addi a0,t3,64
 j returned
pending:
 li t2,6
 j response_code
response_ok:
 li t2,0
response_code:
 sd t2,0(t1)
 sd zero,8(t1)
 sd zero,16(t1)
 sd zero,24(t1)
 sd zero,32(t1)
 sd zero,40(t1)
 sd zero,48(t1)
 li t2,1
 sd t2,56(t1)
 li a0,64
 j returned
current_token:
 li t1,999
 bne a0,t1,fatal
 li a0,0
 j returned
clock:
 ld a0,0(t0)
returned:
 csrr t0,mepc
 addi t0,t0,4
 csrw mepc,t0
 mret
'''


def build(source,module,trap,output):
 output.mkdir(parents=True,exist_ok=True);path=ROOT/'build'/(module+'.lean');path.write_text(source)
 driver.lean(['-o',path.with_suffix('.olean'),path]);assembly=output/'check.S'
 driver.lean(['--run','Compiler/Main.lean','build.'+module,assembly,'build.'+module+'.check'])
 boot=BOOT.replace('lt_Examples_StructuredConsumer_check','lt_build_'+module+'_check').replace(' li t1,0x40000cf',' li t1,0x201000cf\n sd t1,24(t0)\n li t1,0x40000cf')
 boot=boot.replace(' la t0,fatal',' la t0,fixtureTrap')+trap
 boot=boot.replace(' call lt_finish\nfatal:', ' beqz a0,okay\n slli t4,a0,16\n li t0,0x100000\n li t1,0x3333\n or t1,t1,t4\n sw t1,0(t0)\n1: j 1b\nokay:\n li t0,0x10000000\n li t1,80\n sb t1,0(t0)\n call lt_finish\nfatal:')
 (output/'boot.S').write_text(boot);objects=[]
 for i,path in enumerate((assembly,output/'boot.S',ROOT/'runtime/primitives.S')):
  obj=output/f'{i}.o';driver.asm(path,obj);objects.append(obj)
 elf=output/'check.elf';binary=output/'check.bin';driver.run([driver.tool('ld.lld'),'-m','elf64lriscv','--no-relax','-T',ROOT/'runtime/kernel.ld',*objects,'-o',elf]);driver.run([driver.tool('llvm-objcopy'),'-O','binary',elf,binary]);return binary


def execute(binary,backend):
 if backend=='qemu':command=[driver.tool('qemu-system-riscv64'),'-M','virt','-cpu','rv64','-m','64M','-smp','1','-bios','none','-nographic','-monitor','none','-kernel',binary]
 else:
  obj=binary.parent/(backend+'.o');exe=binary.parent/('lt-'+backend);driver.asm(ROOT/f'emulator/{backend}.S',obj,backend+'-linux-gnu');driver.run([driver.tool('ld.lld'),'-static','-e','_start',obj,'-o',exe]);command=[driver.tool('qemu-aarch64'),exe,binary,'--interactive']
 start=time.monotonic();r=subprocess.run(list(map(str,command)),capture_output=True,timeout=180)
 if r.returncode or r.stdout!=b'P':raise RuntimeError((backend,r.returncode,r.stdout.hex(),r.stderr.decode()))
 return dict(backend=backend,result='pass',seconds=time.monotonic()-start,emulated_aarch64=backend=='aarch64')


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--backend',action='append',choices=('qemu','aarch64'));a=p.parse_args()
 B.mkdir(parents=True,exist_ok=True);before={str(p):hashlib.sha256(p.read_bytes()).hexdigest()for p in(ROOT/'Guest').glob('*.olean')}
 delivery=ROOT/'Guest/MessengerDelivery.lean';copied=ROOT/'build/MessengerIdleDelivery.lean'
 copied.write_text(delivery.read_text().replace('namespace Guest.MessengerDelivery','namespace build.MessengerIdleDelivery\nopen Guest').replace('end Guest.MessengerDelivery','end build.MessengerIdleDelivery'))
 driver.lean(['-o',copied.with_suffix('.olean'),copied])
 binary=build(SOURCE,'NativeMessengerIdlePoll',TRAP,B/'idle')
 old=ownership.SOURCE.replace('import Guest.MessengerDelivery','import build.MessengerIdleDelivery').replace('open Guest Guest.LiveSDK Guest.MessengerDelivery','open Guest Guest.LiveSDK build.MessengerIdleDelivery')
 lifecycle=build(old,'NativeMessengerRPCOwnership',ownership.TRAP,B/'rpc-lifecycle')
 checks=[]
 for backend in a.backend or('qemu','aarch64'):
  checks.append(dict(fixture='idle-liveness',**execute(binary,backend)))
  checks.append(dict(fixture='existing-rpc-lifetime-ownership',**execute(lifecycle,backend)))
 after={str(p):hashlib.sha256(p.read_bytes()).hexdigest()for p in(ROOT/'Guest').glob('*.olean')};assert before==after,'production Guest oleans changed'
 report=dict(schema=1,result='pass',delivery_source_sha256=hashlib.sha256(delivery.read_bytes()).hexdigest(),checks=checks,
  fixture_images={name:dict(sha256=hashlib.sha256(path.read_bytes()).hexdigest(),bytes=path.stat().st_size)for name,path in(('idle',binary),('rpc-lifecycle',lifecycle))},
  completed_empty_probes=600,preserved_prior_local_work_charges=7,following_useful_blob_bytes=608,
  modeled_parent_admissions=602,modeled_parent_fetch_payload_bytes=77056,monotonic_serial=602,
  negative_cases=[n[0]for n in NEGATIVE],production_guest_oleans_unchanged=True,
  boundaries=['only an exact fully completed64B no-row idle fetch returns its own one local workflow charge','zero charge does not underflow, completed-empty observation count saturates and other local work is not reset','actual rpc/collectRPC pass600 empty responses then receive and park a two-chunk608B blob','unchanged512 local guard refuses workflow admission; finite modeled parent still refuses when its paid allowance exhausts','existing exact-owned cancellation,90000tick deadline, ready-at-deadline, serial and reconfiguration cases pass against the same copied source','actual current-token diagnostic464action5 is Launcher-only and returns local work counter, monotonic serial, current RPC id, receive phase/reason and completed-empty count without mutation'],
  limits='Compiled namespace-renamed Native Delivery transitions with declared finite Network/clock and Owner oracles. Parent charges count each admitted128B fetch request and one attempt; real parent wire costs/authority remain separately qualified. No live kernel, Mailbox, socket, AEAD/session, retained state or connected Messenger claim. AArch64 assembly backend runs under qemu-aarch64.')
 (B/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))

if __name__=='__main__':main()
