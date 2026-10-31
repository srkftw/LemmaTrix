"""Execute compiled RV64 XEdDSA and KDF fixtures; OpenSSL independently verifies signatures."""
import argparse,hashlib,hmac,json,subprocess,sys,time,tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import driver
sys.path.insert(0,str(Path(__file__).resolve().parent))
from structured_runtime import BOOT
from network_crypto import store_bytes
ROOT=driver.ROOT;B=ROOT/'build/native-messenger-crypto'
P=2**255-19;L=2**252+27742317777372353535851937790883648493;D=-121665*pow(121666,-1,P)%P
Y=4*pow(5,-1,P)%P
X=pow((Y*Y-1)*pow(D*Y*Y+1,-1,P)%P,(P+3)//8,P)
if (X*X*(D*Y*Y+1)-(Y*Y-1))%P:X=X*pow(2,(P-1)//4,P)%P
if X&1:X=P-X
BASE=(X,Y)
def add(a,b):
 x,y=a;u,v=b;d=D*x*u*y*v%P
 return ((x*v+y*u)*pow(1+d,-1,P)%P,(y*v+x*u)*pow(1-d,-1,P)%P)
def mul(k):
 a=(0,1);b=BASE
 while k:
  if k&1:a=add(a,b)
  b=add(b,b);k>>=1
 return a
def enc(a):return (a[1]|((a[0]&1)<<255)).to_bytes(32,'little')
def fixture(i):
 raw=hashlib.sha256(b'public XEdDSA fixture'+bytes([i])).digest();k=int.from_bytes(raw,'little')&((1<<254)-8)|(1<<254);a=k%L;A=enc(mul(a))
 if A[31]&128:a=(-a)%L;A=enc(mul(a))
 msg=b'\x05'+hashlib.sha256(b'published prekey'+bytes([i])).digest();z=hashlib.sha512(b'public randomized signature fixture'+bytes([i])).digest()
 r=int.from_bytes(hashlib.sha512(b'\xfe'+b'\xff'*31+a.to_bytes(32,'little')+msg+z).digest(),'little')%L;R=enc(mul(r));h=int.from_bytes(hashlib.sha512(R+A+msg).digest(),'little')%L
 sig=R+((r+h*a)%L).to_bytes(32,'little');u=((1+int.from_bytes(A,'little'))*pow(1-int.from_bytes(A,'little'),-1,P)%P).to_bytes(32,'little')
 with tempfile.TemporaryDirectory(prefix='xeddsa-oracle-') as d:
  p=Path(d);(p/'key.der').write_bytes(bytes.fromhex('302a300506032b6570032100')+A);(p/'message').write_bytes(msg);(p/'signature').write_bytes(sig)
  subprocess.run([driver.tool('openssl'),'pkeyutl','-verify','-rawin','-pubin','-keyform','DER','-inkey',p/'key.der','-in',p/'message','-sigfile',p/'signature'],capture_output=True,check=True)
 return raw,u,msg,z,sig

def source():
 s='import Guest.MessengerCrypto\nnamespace build.NativeMessengerCrypto\ndef check (t : UInt64) : UInt64 :=\n'
 for i in range(2):
  raw,u,msg,z,sig=fixture(i)
  for addr,data in [(0x650000,raw),(0x650040,u),(0x650080,msg),(0x650100,z),(0x650180,sig)]:s+=store_bytes(addr,data)+'\n'
  s+=f'''  let t := Guest.MessengerCrypto.publicKey 0x650000 0x651000 t
  if Guest.Ed25519.difference 0x650040 0x651000 32 0 t != 0 then {1+i*10} else
  let t := Guest.MessengerCrypto.sign 0x650000 0x650080 33 0x650100 0x651000 t
  if Guest.Ed25519.difference 0x650180 0x651000 64 0 t != 0 then {2+i*10} else
  if !Guest.MessengerCrypto.verify 0x650040 0x650080 33 0x650180 t then {3+i*10} else
  let t := Guest.store8 0x650081 (Guest.load8 0x650081 t ^^^ 1) t
  if Guest.MessengerCrypto.verify 0x650040 0x650080 33 0x650180 t then {4+i*10} else
  let t := Guest.store8 0x650081 (Guest.load8 0x650081 t ^^^ 1) t
'''
 salt=hashlib.sha256(b'salt').digest();ikm=hashlib.sha256(b'DH').digest();prk=hmac.digest(salt,ikm,'sha256');o1=hmac.digest(prk,b'LemmaTrix-DR-v1\x01','sha256');o2=hmac.digest(prk,o1+b'LemmaTrix-DR-v1\x02','sha256')
 for addr,data in [(0x650000,salt),(0x650040,ikm),(0x650080,o1+o2)]:s+=store_bytes(addr,data)+'\n'
 s+='''  let t := Guest.MessengerCrypto.hkdf 0x650000 0x650040 32 2 0x651000 t
  if Guest.Ed25519.difference 0x650080 0x651000 64 0 t != 0 then 30 else
  let t := Guest.MessengerCrypto.dh 0x650000 Guest.MessengerCrypto.zeroKey 0x651000 t
  if t != Guest.MessengerCrypto.err then 31 else
  let t := Guest.MessengerCrypto.clear t
  if Guest.Ed25519.nonzero Guest.MessengerCrypto.scratch 16384 0 t != 0 then 32 else 0
end build.NativeMessengerCrypto
'''
 return s

def main():
 p=argparse.ArgumentParser();p.add_argument('--backend',action='append',choices=['qemu','x86_64','aarch64']);args=p.parse_args();B.mkdir(parents=True,exist_ok=True)
 path=ROOT/'build/NativeMessengerCrypto.lean';path.write_text(source())
 for name in ['Primitives','Structured','Effects','Noise25519','SHA512','Ed25519','VaultCrypto','ServiceSHA256','ServiceHash','MessengerCrypto']:
  src=ROOT/f'Guest/{name}.lean';out=src.with_suffix('.olean')
  if not out.exists() or src.stat().st_mtime>out.stat().st_mtime:driver.lean(['-o',out,src])
 driver.lean(['-o',path.with_suffix('.olean'),path]);assembly=B/'check.S';driver.lean(['--run','Compiler/Main.lean','build.NativeMessengerCrypto',assembly,'build.NativeMessengerCrypto.check'])
 boot=BOOT.replace('lt_Examples_StructuredConsumer_check','lt_build_NativeMessengerCrypto_check').replace(' li t1,0x40000cf',' li t1,0x201000cf\n sd t1,24(t0)\n li t1,0x40000cf')
 (B/'boot.S').write_text(boot);objects=[]
 for i,src in enumerate([assembly,B/'boot.S',ROOT/'runtime/primitives.S']):
  obj=B/f'{i}.o';driver.asm(src,obj);objects.append(obj)
 elf=B/'check.elf';binary=B/'check.bin';driver.run([driver.tool('ld.lld'),'-m','elf64lriscv','--no-relax','-T',ROOT/'runtime/kernel.ld',*objects,'-o',elf]);driver.run([driver.tool('llvm-objcopy'),'-O','binary',elf,binary]);checks=[]
 for backend in args.backend or ['qemu']:
  if backend=='qemu':cmd=[driver.tool('qemu-system-riscv64'),'-M','virt','-cpu','rv64','-m','64M','-smp','1','-bios','none','-nographic','-monitor','none','-kernel',binary]
  else:
   obj=B/(backend+'.o');exe=B/('lt-'+backend);driver.asm(ROOT/f'emulator/{backend}.S',obj,backend+'-linux-gnu');driver.run([driver.tool('ld.lld'),'-static','-e','_start',obj,'-o',exe]);cmd=([driver.tool('qemu-aarch64')] if backend=='aarch64' else [])+[exe,binary,'--interactive']
  start=time.monotonic();r=subprocess.run([str(x) for x in cmd],capture_output=True,timeout=900)
  if r.returncode:raise RuntimeError(f'{backend}: exit {r.returncode} stdout {r.stdout.hex()} stderr {r.stderr.decode()}')
  checks.append(dict(backend=backend,result='pass',seconds=time.monotonic()-start))
 report=dict(schema=1,profile='XEd25519 revision1; HKDF-SHA256 DR-v1',image_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),image_bytes=binary.stat().st_size,assembly_sha256=hashlib.sha256(assembly.read_bytes()).hexdigest(),independent_oracle='Python bigint Edwards arithmetic, OpenSSL Ed25519 verification, Python hashlib/hmac',checks=checks,limits='Primitive fixture checks; no constant-time compiler proof or independent review.')
 previous=B/'evidence.json'
 if previous.exists():
  prior=json.loads(previous.read_text())
  if prior.get('image_sha256')==report['image_sha256']:
   current={item['backend']:item for item in prior['checks']}
   current.update({item['backend']:item for item in checks});report['checks']=list(current.values())
 previous.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
