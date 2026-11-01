"""Compiled RV64 session transition tests with a disclosed test-only entropy trap.
This tests the real owner functions, not routing, kernel grants, or durable retention.
"""
import argparse,hashlib,json,subprocess,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import driver
sys.path.insert(0,str(Path(__file__).resolve().parent))
from structured_runtime import BOOT
from network_crypto import store_bytes
ROOT=driver.ROOT;B=ROOT/'build/native-messenger-session'
def source():
 s='''import Guest.MessengerSession
namespace build.NativeMessengerSession
open Guest Guest.LiveSDK
def invoke (op h a payload len t : UInt64) : UInt64 :=
  let t := header op h a 0 0 0 0 t
  let t := copy payload (wire+64) len t
  let t := copy wire command (64+len) t
  Guest.MessengerSession.dispatch 10 0 1 (64+len) t
def check (t : UInt64) : UInt64 :=
'''
 for p,raw in [(0x7a1000,b'hello routed world'),(0x7a1100,b'reply from Bob'),(0x7a1800,b'F'*32)]:s+=store_bytes(p,raw)+'\n'
 s+='''  let t := Guest.MessengerSession.lock t
  let t := invoke 421 0 0 0x7a1800 32 t
  if status t != 0 then 1 else
  let t := header 434 0 3 0 0 0 0 t
  let t := copy wire command 64 t
  let t := Guest.MessengerSession.dispatch 10 1024 1 64 t
  if status t != 1 then 25 else
  let t := header 434 0 11 0 0 0 0 t
  let t := copy wire command 64 t
  let t := Guest.MessengerSession.dispatch 10 1024 1 64 t
  if status t != 0 || Guest.load64 (wire+16) t != 128 then 26 else
  let t := copy 0x650000 0x6c0000 32768 t
  let t := Guest.MessengerSession.lock t
  let t := invoke 421 0 0 0x7a1800 32 t
  if status t != 0 then 2 else
  let t := invoke 423 0 0 0x6c1000 256 t
  if status t != 0 then 3 else
  let t := copy (wire+64) 0x7a1400 32 t
  let t := invoke 424 1 0 0x7a1400 32 t
  if status t != 0 then 4 else
  let t := copy 0x650000 0x6c8000 32768 t
  let t := copy 0x6c0000 0x650000 32768 t
  let t := invoke 423 0 0 0x6c9000 256 t
  if status t != 0 then 5 else
  let t := copy (wire+64) 0x7a1400 32 t
  let t := invoke 424 1 0 0x7a1400 32 t
  if status t != 0 then 6 else
  let t := invoke 426 1 18 0x7a1000 18 t
  if status t != 0 || result t != 1 then 7 else
  let t := invoke 427 1 0 0x7a1000 0 t
  if status t != 0 then 8 else
  let t := copy (wire+64) 0x7a2000 226 t
  let t := invoke 435 1 0 0x7a1000 0 t
  if status t != 0 || !Guest.MessengerSession.eq (wire+64) 0x7a2000 226 t then 9 else
  let t := copy 0x650000 0x6c0000 32768 t
  let t := copy 0x6c8000 0x650000 32768 t
  let t := invoke 428 0 226 0x7a2000 226 t
  if status t != 0 then 10 else
  let t := invoke 429 1 0 0x7a1000 0 t
  if status t != 0 || load64 (wire+16) t != 18 || !Guest.MessengerSession.eq (wire+64) 0x7a1000 18 t then 11 else
  let nr := load64 (Guest.MessengerSession.contactAt 0+32) t
  let t := invoke 428 0 226 0x7a2000 226 t
  if status t != 10 || load64 (Guest.MessengerSession.contactAt 0+32) t != nr then 12 else
  let t := Guest.store8 0x7a20d0 (Guest.load8 0x7a20d0 t ^^^ 1) t
  let t := invoke 428 0 226 0x7a2000 226 t
  if status t != 12 && status t != 9 then 13 else
  if load64 (Guest.MessengerSession.contactAt 0+32) t != nr then 14 else
  let t := Guest.store8 0x7a20d0 (Guest.load8 0x7a20d0 t ^^^ 1) t
  let t := invoke 426 1 14 0x7a1100 14 t
  if status t != 0 then 15 else
  let t := invoke 427 1 0 0x7a1000 0 t
  if status t != 0 then 16 else
  let t := copy (wire+64) 0x7a3000 222 t
  let t := copy 0x650000 0x6c8000 32768 t
  let t := copy 0x6c0000 0x650000 32768 t
  let t := invoke 428 0 222 0x7a3000 222 t
  if status t != 0 then 17 else
  let t := invoke 429 1 0 0x7a1000 0 t
  if status t != 0 || !Guest.MessengerSession.eq (wire+64) 0x7a1100 14 t then 18 else
  let t := invoke 430 1 0 0x7a1000 0 t
  if status t != 0 then 19 else
  let before := load64 (Guest.MessengerSession.contactAt 0+24) t
  let t := invoke 426 1 18 0x7a1000 18 t
  if status t != 0 then 20 else
  let t := invoke 430 2 0 0x7a1000 0 t
  if status t != 0 || load64 (Guest.MessengerSession.contactAt 0+24) t != before then 21 else
  let t := invoke 425 1 0 0x7a1000 0 t
  let t := invoke 426 1 18 0x7a1000 18 t
  if status t != 8 then 22 else
  let t := Guest.MessengerSession.lock t
  if Guest.Ed25519.nonzero 0x650000 32768 0 t != 0 then 23 else
  let t := invoke 426 1 18 0x7a1000 18 t
  if status t != 5 then 24 else 0
end build.NativeMessengerSession
'''
 return s
TRAP='''
fixtureTrap:
 csrr t0,mcause
 li t1,9
 bne t0,t1,fatal
 li t0,131
 beq a7,t0,fixtureDone
 li t0,140
 beq a7,t0,fixtureDone
 li t0,130
 bne a7,t0,fatal
 li t0,0x804f0000
 ld t1,0(t0)
 addi t1,t1,1
 sd t1,0(t0)
 li t2,67
 mul t1,t1,t2
 addi t1,t1,42
 li t0,0x7fe00000
 add t0,a1,t0
 li t2,32
fixtureEntropy:
 sb t1,0(t0)
 addi t0,t0,1
 addi t1,t1,13
 addi t2,t2,-1
 bnez t2,fixtureEntropy
fixtureDone:
 csrr t0,mepc
 addi t0,t0,4
 csrw mepc,t0
 li a0,0
 mret
'''
def main():
 p=argparse.ArgumentParser();p.add_argument('--backend',action='append',choices=['qemu','x86_64','aarch64']);args=p.parse_args();B.mkdir(parents=True,exist_ok=True)
 path=ROOT/'build/NativeMessengerSession.lean';path.write_text(source())
 for name in ['MessengerPolicy','MessengerCrypto','MessengerAttachment','MessengerVault','MessengerSession']:
  src=ROOT/f'Guest/{name}.lean';out=src.with_suffix('.olean')
  if not out.exists() or src.stat().st_mtime>out.stat().st_mtime:driver.lean(['-o',out,src])
 driver.lean(['-o',path.with_suffix('.olean'),path]);assembly=B/'check.S';driver.lean(['--run','Compiler/Main.lean','build.NativeMessengerSession',assembly,'build.NativeMessengerSession.check'])
 boot=BOOT.replace('lt_Examples_StructuredConsumer_check','lt_build_NativeMessengerSession_check').replace(' la t0,fatal',' la t0,fixtureTrap').replace(' li t1,0x40000cf',' li t1,0x201000cf\n sd t1,24(t0)\n li t1,0x40000cf')
 boot=boot.replace(' call lt_finish\nfatal:', ' beqz a0,okay\n slli t4,a0,16\n li t0,0x100000\n li t1,0x3333\n or t1,t1,t4\n sw t1,0(t0)\n1: j 1b\nokay:\n call lt_finish\nfatal:')+TRAP
 (B/'boot.S').write_text(boot);objects=[]
 for i,src in enumerate([assembly,B/'boot.S',ROOT/'runtime/primitives.S']):
  obj=B/f'{i}.o';driver.asm(src,obj);objects.append(obj)
 elf=B/'check.elf';binary=B/'check.bin';driver.run([driver.tool('ld.lld'),'-m','elf64lriscv','--no-relax','-T',ROOT/'runtime/kernel.ld',*objects,'-o',elf]);driver.run([driver.tool('llvm-objcopy'),'-O','binary',elf,binary]);checks=[]
 for backend in args.backend or ['qemu']:
  if backend=='qemu':cmd=[driver.tool('qemu-system-riscv64'),'-M','virt','-cpu','rv64','-m','64M','-smp','1','-bios','none','-nographic','-monitor','none','-kernel',binary]
  else:
   obj=B/(backend+'.o');exe=B/('lt-'+backend);driver.asm(ROOT/f'emulator/{backend}.S',obj,backend+'-linux-gnu');driver.run([driver.tool('ld.lld'),'-static','-e','_start',obj,'-o',exe]);cmd=([driver.tool('qemu-aarch64')] if backend=='aarch64' else [])+[exe,binary,'--interactive']
  start=time.monotonic();r=subprocess.run([str(x) for x in cmd],capture_output=True,timeout=1200)
  if r.returncode:raise RuntimeError(f'{backend}: exit {r.returncode} stdout {r.stdout.hex()} stderr {r.stderr.decode()}')
  checks.append(dict(backend=backend,result='pass',seconds=time.monotonic()-start))
 report=dict(schema=1,image_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),image_bytes=binary.stat().st_size,checks=checks,entropy='Test-only deterministic supervisor trap; no live credentials. Two separate owner memory snapshots.',boundaries=['X3DH initial text','Double Ratchet reply','exact committed ciphertext retry','duplicate receive','tamper preserves state','cancel pending preserves chain','block','network coordinator denied plaintext attachment actions','lock clears owner'],limits='Owner transition fixture, not graphical/routed/kernel-authority/durable acceptance.')
 previous=B/'evidence.json'
 if previous.exists():
  prior=json.loads(previous.read_text())
  if prior.get('image_sha256')==report['image_sha256']:
   current={item['backend']:item for item in prior['checks']};current.update({item['backend']:item for item in checks});report['checks']=list(current.values())
  else:(B/('evidence-'+prior['image_sha256'][:8]+'.json')).write_text(json.dumps(prior,indent=2)+'\n')
 previous.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
