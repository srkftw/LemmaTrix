"""Compile Lean-authored Tor crypto to RV64 and compare independent public fixtures.
No operational private key is generated or installed by this test.
"""
import argparse,hashlib,json,subprocess,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import driver
sys.path.insert(0,str(driver.ROOT/'tests'))
from network_crypto import store_bytes
from structured_runtime import BOOT
ROOT=driver.ROOT
B=ROOT/'build/onion-crypto'

def source():
 s='import Guest.AES\nimport Guest.SHA1\nimport Guest.SHA3\nimport Guest.Noise25519\nnamespace build.OnionCrypto\n'
 s+='partial def difference (a b n v t : UInt64) : UInt64 :=\n  if n == 0 then v else difference (a+1) (b+1) (n-1) (v ||| (Guest.load8 a t ^^^ Guest.load8 b t)) t\n'
 s+='set_option maxRecDepth 10000\nset_option maxHeartbeats 4000000\ndef check (t : UInt64) : UInt64 :=\n'
 index=0
 for n in [0,3,55,56,63,64,135,136,137,509]:
  data=bytes((i*17+11)%256 for i in range(n));s+=store_bytes(0x700000,data)+'\n'
  for name,expected in [('sha1',hashlib.sha1(data).digest()),('sha3',hashlib.sha3_256(data).digest()),('shake',hashlib.shake_256(data).digest(200))]:
   index+=1;s+=store_bytes(0x701000,expected)+'\n'
   f={'sha1':'Guest.SHA1.hash 0x6c0000 0x6c1000 0x700000 '+str(n)+' 0x702000 t','sha3':'Guest.SHA3.sha3 0x6c0000 0x6c1000 0x700000 '+str(n)+' 0x702000 t','shake':'Guest.SHA3.shake 0x6c0000 0x6c1000 0x700000 '+str(n)+' 0x702000 200 t'}[name]
   s+=f'  let t := {f}\n  if difference 0x701000 0x702000 {len(expected)} 0 t != 0 then {index} else\n'
 # NIST SP800-38A F.5 AES128 and AES256 CTR four-block fixtures.
 plain=bytes.fromhex('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710')
 iv=bytes.fromhex('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff')
 for key,expected in [('2b7e151628aed2a6abf7158809cf4f3c','874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee'),('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4','601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6')]:
  key=bytes.fromhex(key);expected=bytes.fromhex(expected);s+=store_bytes(0x700000,key)+'\n'+store_bytes(0x701000,plain)+'\n'+store_bytes(0x703000,expected)+'\n'
  s+=f'  let t := Guest.AES.init 0x6c0000 0x700000 {len(key)} t\n'
  s+=store_bytes(0x6c0000+248,iv)+'\n'
  s+='  let t := Guest.AES.crypt 0x6c0000 0x701000 0x702000 17 t\n  let t := Guest.AES.crypt 0x6c0000 0x701011 0x702011 47 t\n'
  index+=1;s+=f'  if difference 0x703000 0x702000 64 0 t != 0 then {index} else\n'
 s+='  0\nend build.OnionCrypto\n';return s

def build(src,module='OnionCrypto'):
 B.mkdir(parents=True,exist_ok=True)
 path=ROOT/f'build/{module}.lean';path.write_text(src)
 for name in ['Primitives','AES','SHA1','SHA3','Noise25519']:
  p=ROOT/f'Guest/{name}.lean';o=p.with_suffix('.olean')
  if not o.exists() or p.stat().st_mtime>o.stat().st_mtime:driver.lean(['-o',o,p])
 driver.lean(['-o',path.with_suffix('.olean'),path])
 assembly=B/'check.S';driver.lean(['--run','Compiler/Main.lean','build.'+module,assembly,'build.'+module+'.check'])
 boot=BOOT.replace('lt_Examples_StructuredConsumer_check','lt_build_'+module+'_check').replace(' li t1,0x40000cf',' li t1,0x201000cf\n sd t1,24(t0)\n li t1,0x40000cf')
 boot=boot.replace(' call lt_finish\nfatal:\n li a0,2\n call lt_finish',''' beqz a0,passed
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
 li a0,0
 call lt_finish
fatal:
 li a0,2
 call lt_finish''')
 (B/'boot.S').write_text(boot);objects=[]
 for i,p in enumerate([assembly,B/'boot.S',ROOT/'runtime/primitives.S']):
  o=B/f'{i}.o';driver.asm(p,o);objects.append(o)
 elf=B/'check.elf';binary=B/'check.bin';driver.run([driver.tool('ld.lld'),'-m','elf64lriscv','--no-relax','-T',ROOT/'runtime/kernel.ld',*objects,'-o',elf]);driver.run([driver.tool('llvm-objcopy'),'-O','binary',elf,binary]);return binary

def execute(binary,backend):
 if backend=='qemu':args=[driver.tool('qemu-system-riscv64'),'-M','virt','-cpu','rv64','-m','64M','-smp','1','-bios','none','-nographic','-monitor','none','-kernel',binary]
 else:
  obj=B/(backend+'.o');exe=B/('lt-'+backend);driver.asm(ROOT/f'emulator/{backend}.S',obj,backend+'-linux-gnu');driver.run([driver.tool('ld.lld'),'-static','-e','_start',obj,'-o',exe]);args=([driver.tool('qemu-aarch64')] if backend=='aarch64' else [])+[exe,binary,'--interactive']
 start=time.monotonic();r=subprocess.run([str(x) for x in args],capture_output=True,timeout=600)
 if r.returncode or r.stdout!=b'P':raise RuntimeError(f'{backend}: exit={r.returncode}; stdout={r.stdout.hex()}; stderr={r.stderr.decode()}')
 return dict(backend=backend,seconds=time.monotonic()-start,result='pass')

def main():
 p=argparse.ArgumentParser();p.add_argument('--backend',action='append',choices=['qemu','x86_64','aarch64']);a=p.parse_args()
 binary=build(source());report=dict(schema=1,profile='FIPS197 AES128/AES256 CTR; FIPS180-4 SHA1; FIPS202 SHA3-256/SHAKE256',image_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),image_bytes=binary.stat().st_size,checks=[execute(binary,b) for b in a.backend or ['qemu']],fixtures='NIST SP800-38A F.5 four-block AES CTR; Python hashlib independent SHA1/SHA3/SHAKE padding and multiple-rate boundaries',limitations='Primitive vectors; no enabled mode1 route, no constant-time/compiler proof or independent audit.')
 (B/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
