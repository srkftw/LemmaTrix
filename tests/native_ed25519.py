"""RFC8032 / SHA512 vectors through the actual Lean-to-RV64 compiler.

All seeds in this probe are published test fixtures. Host code generates no live
identity keys. QEMU and both assembly backends execute the same identified guest.
"""
import argparse, hashlib, json, os, re, subprocess, sys, tempfile, time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import driver
sys.path.insert(0,str(Path(__file__).resolve().parent))
from structured_runtime import BOOT
from network_crypto import store_bytes
ROOT=driver.ROOT
B=ROOT/'build/native-ed25519'

def independent_vectors():
 # Public deterministic probe seeds only. OpenSSL controls no live broker keys.
 vectors=[]
 with tempfile.TemporaryDirectory(prefix='ed25519-fixtures-') as directory:
  p=Path(directory)
  for n in [113,4096]:
   seed=hashlib.sha256(('LemmaTrix RFC8032 independent fixture '+str(n)).encode()).digest()
   message=bytes((i*37+11)%256 for i in range(n))
   (p/'key.der').write_bytes(bytes.fromhex('302e020100300506032b657004220420')+seed)
   (p/'message').write_bytes(message)
   def openssl(args):return subprocess.run([driver.tool('openssl'),*args],capture_output=True,check=True).stdout
   public=openssl(['pkey','-inform','DER','-in',str(p/'key.der'),'-pubout','-outform','DER'])[-32:]
   signature=openssl(['pkeyutl','-sign','-rawin','-keyform','DER','-inkey',str(p/'key.der'),'-in',str(p/'message')])
   vectors.append(dict(name='OpenSSL boundary '+str(n),seed=seed.hex(),public_key=public.hex(),message=message.hex(),signature=signature.hex()))
 return vectors

def source(vectors,full=False):
 s='import Guest.Ed25519\nset_option maxRecDepth 10000\nset_option maxHeartbeats 4000000\nnamespace build.NativeEd25519\n'
 s+='def check (t : UInt64) : UInt64 :=\n'
 for i,v in enumerate(vectors):
  seed,pub,msg,sig=map(bytes.fromhex,[v['seed'],v['public_key'],v['message'],v['signature']])
  for p,raw in [(0x650000,seed),(0x650040,pub),(0x650080,sig),(0x651000,msg),(0x653000,hashlib.sha512(msg).digest())]:s+=store_bytes(p,raw)+'\n'
  s+=f'''  let t := Guest.SHA512.sha512At Guest.Ed25519.hashScratch 0x651000 {len(msg)} 0x660000 t
  if Guest.Ed25519.difference 0x653000 0x660000 64 0 t != 0 then {i*10+1} else
  let t := Guest.Ed25519.publicKey 0x650000 0x660000 t
  if Guest.Ed25519.nonzero 0x640000 28672 0 t != 0 then 81 else
  if Guest.Ed25519.difference 0x650040 0x660000 32 0 t != 0 then {i*10+2} else
  let t := Guest.Ed25519.sign 0x650000 0x650040 0x651000 {len(msg)} 0x660000 t
  if Guest.Ed25519.difference 0x650080 0x660000 64 0 t != 0 then {i*10+3} else
  if Guest.Ed25519.nonzero 0x640000 28672 0 t != 0 then 82 else
  if !Guest.Ed25519.verify 0x650040 0x651000 {len(msg)} 0x650080 t then {i*10+4} else
  if Guest.Ed25519.nonzero 0x640000 28672 0 t != 0 then 83 else
  let t := Guest.store8 0x10000000 {65+i} t
'''
 # Strict public-input and cleanup checks retain published last vector seed.
 n=len(bytes.fromhex(vectors[-1]['message']))
 s+=store_bytes(0x654000,bytes.fromhex(vectors[-1]['signature']))+'\n'
 s+=store_bytes(0x654020,(2**252+27742317777372353535851937790883648493).to_bytes(32,'little'))+'\n'
 s+=f"""  if Guest.Ed25519.verify 0x650040 0x651000 {n} 0x654000 t then 84 else
  if Guest.Ed25519.nonzero 0x640000 28672 0 t != 0 then 85 else
"""
 # Noncanonical public y=p, negative-zero encoding, identity, and nonsquare y=2.
 for i,public in enumerate([(2**255-19).to_bytes(32,'little'),(1+2**255).to_bytes(32,'little'),(1).to_bytes(32,'little'),(2).to_bytes(32,'little')]):
  s+=store_bytes(0x654100,public)+'\n'
  s+=f"""  if Guest.Ed25519.verify 0x654100 0x651000 {n} 0x650080 t then {86+i} else
  if Guest.Ed25519.nonzero 0x640000 28672 0 t != 0 then 90 else
"""
 # Oversized operations must clear poisoned scratch and not touch output.
 s+="""  let t := Guest.store64 0x640000 0x12345678 t
  let t := Guest.store64 0x646ff8 0x87654321 t
  let t := Guest.store64 0x660000 0x1122334455667788 t
  let r := Guest.Ed25519.sign 0x650000 0x650040 0x651000 4097 0x660000 t
  if r != Guest.Ed25519.err || Guest.load64 0x660000 r != 0x1122334455667788 then 91 else
  if Guest.Ed25519.nonzero 0x640000 28672 0 r != 0 then 92 else
  let t := Guest.store64 0x640000 0x12345678 r
  if Guest.Ed25519.verify 0x650040 0x651000 4097 0x650080 t then 93 else
  if Guest.Ed25519.nonzero 0x640000 28672 0 t != 0 then 94 else
"""
 if full:
  s+=f"""  let t := Guest.store8 0x651000 (Guest.load8 0x651000 t ^^^ 1) t
  if Guest.Ed25519.verify 0x650040 0x651000 {n} 0x650080 t then 95 else
  let t := Guest.store8 0x651000 (Guest.load8 0x651000 t ^^^ 1) t
  let t := Guest.store8 0x650081 (Guest.load8 0x650081 t ^^^ 1) t
  if Guest.Ed25519.verify 0x650040 0x651000 {n} 0x650080 t then 96 else
"""
 for n in [111,112,127,128,129]:
  message=bytes((i*19+7)%256 for i in range(n));s+=store_bytes(0x651000,message)+'\n';s+=store_bytes(0x653000,hashlib.sha512(message).digest())+'\n'
  s+=f"""  let t := Guest.SHA512.sha512At Guest.Ed25519.hashScratch 0x651000 {n} 0x660000 t
  if Guest.Ed25519.difference 0x653000 0x660000 64 0 t != 0 then 97 else
"""
 s+='  Guest.Ed25519.clear t\nend build.NativeEd25519\n'
 return s

def build(vectors,full=False):
 B.mkdir(parents=True,exist_ok=True)
 module='NativeEd25519Full' if full else 'NativeEd25519Compact'
 path=ROOT/('build/'+module+'.lean');generated=source(vectors,full).replace('build.NativeEd25519','build.'+module);path.write_text(generated);(B/'probe.lean').write_text(generated)
 for name in ['Primitives','Structured','Effects','Noise25519','SHA512','Ed25519']:
  module_source=ROOT/f'Guest/{name}.lean';module_output=module_source.with_suffix('.olean')
  if not module_output.exists() or module_source.stat().st_mtime>module_output.stat().st_mtime:driver.lean(['-o',module_output,module_source])
 driver.lean(['-o',path.with_suffix('.olean'),path])
 assembly=B/'check.S';driver.lean(['--run','Compiler/Main.lean','build.'+module,assembly,'build.'+module+'.check'])
 boot=BOOT.replace('lt_Examples_StructuredConsumer_check','lt_build_'+module+'_check')
 boot=boot.replace(' li t1,0x40000cf',' li t1,0x201000cf\n sd t1,24(t0)\n li t1,0x40000cf')
 boot=boot.replace(' call lt_finish\nfatal:\n li a0,2\n call lt_finish',''' beqz a0,passed
 mv t4,a0
 li t0,0x660000
 li t1,64
 li t2,0x10000000
debug_output:
 lbu t3,0(t0)
 sb t3,0(t2)
 addi t0,t0,1
 addi t1,t1,-1
 bnez t1,debug_output
 slli t4,t4,16
 li t0,0x100000
 li t1,0x3333
 or t1,t1,t4
 sw t1,0(t0)
1: j 1b
passed:
 li t0,0x10000000
 li t1,80
 sb t1,0(t0)
 li a0,0
 call lt_finish
fatal:
 li t0,0x100000
 li t1,0x00403333
 sw t1,0(t0)
1: j 1b''')
 (B/'boot.S').write_text(boot)
 objects=[]
 for i,p in enumerate([assembly,B/'boot.S',ROOT/'runtime/primitives.S']):
  o=B/f'{i}.o';driver.asm(p,o);objects.append(o)
 elf=B/'check.elf';binary=B/'check.bin'
 driver.run([driver.tool('ld.lld'),'-m','elf64lriscv','--no-relax','-T',ROOT/'runtime/kernel.ld',*objects,'-o',elf])
 driver.run([driver.tool('llvm-objcopy'),'-O','binary',elf,binary])
 return binary

def inspect_assembly(path):
 # This guards the explicit compiler cleanup policy. The arithmetic observations
 # are a manual review of these emitted routines, not a taint/constant-time proof.
 routines=dict(re.findall(r'^lt_(Guest_(?:Ed25519|Noise25519|SHA512)_[^:]+):\n(.*?)^\.size ',path.read_text(),re.M|re.S))
 returns=0
 for name,body in routines.items():
  paths=body.split('  ret\n')[:-1];returns+=len(paths)
  if body.count('secret_frame_clear')<2*len(paths):raise RuntimeError('missing frame erasure: '+name)
  if any(not part.rstrip().endswith('li t6, 0') for part in paths):raise RuntimeError('missing register erasure: '+name)
 reviewed=['Guest_Ed25519_scalarLoop','Guest_Ed25519_pointSwap','Guest_Ed25519_reduceBits','Guest_Ed25519_reduceSelect','Guest_Ed25519_reduceSubtract','Guest_Ed25519_reduceShift','Guest_Ed25519_multiplyInner','Guest_Ed25519_carryWide','Guest_Noise25519_multiplyInner','Guest_SHA512_rounds']
 summaries={name:dict(sha256=hashlib.sha256(routines[name].encode()).hexdigest(),conditional_branches=len(re.findall(r'^  b(?:eq|ne|nez|eqz|lt|ge)',routines[name],re.M))) for name in reviewed}
 return dict(sensitive_functions=len(routines),sensitive_return_paths=returns,fixed_frame_and_argument_temporary_register_erasure='present on every emitted return',reviewed_routines=summaries,manual_control_flow_review='Scalar-bit selection and reduction use masks. Core loop exits use public counters; addresses use fixed scratch, public pointers and public indices. SHA padding uses public length/offset and constants use public round indices.',limits='No dynamic taint proof, compiler correctness proof, microarchitectural constant-time proof or independent audit. Live result a0 and protected in-progress kernel contexts remain necessary; whole-process termination cleanup belongs to the kernel.')

def main():
 global B
 p=argparse.ArgumentParser();p.add_argument('--backend',action='append',choices=['qemu','x86_64','aarch64']);p.add_argument('--first',action='store_true');a=p.parse_args()
 B=B/('compact' if a.first else 'full')
 vectors=json.loads((ROOT/'tests/fixtures/ed25519_rfc8032.json').read_text())['vectors']
 if a.first:vectors=vectors[:1]
 else:vectors+=independent_vectors()
 binary=build(vectors,not a.first);checks=[]
 for backend in a.backend or ['qemu']:
  if backend=='qemu':args=[driver.tool('qemu-system-riscv64'),'-M','virt','-cpu','rv64','-m','64M','-smp','1','-bios','none','-nographic','-monitor','none','-kernel',binary]
  else:
   obj=B/(backend+'.o');executable=B/('lt-'+backend);driver.asm(ROOT/f'emulator/{backend}.S',obj,backend+'-linux-gnu');driver.run([driver.tool('ld.lld'),'-static','-e','_start',obj,'-o',executable]);args=([driver.tool('qemu-aarch64')] if backend=='aarch64' else [])+[executable,binary,'--interactive']
  start=time.monotonic();r=subprocess.run([str(x) for x in args],capture_output=True,timeout=1800)
  if r.returncode or r.stdout!=bytes(range(65,65+len(vectors)))+b'P':raise RuntimeError(f'{backend} failed: exit={r.returncode}; stdout={r.stdout.hex()}; stderr={r.stderr.decode()}')
  checks.append(dict(backend=backend,seconds=time.monotonic()-start,result='pass',vectors=len(vectors)))
 report=dict(schema=1,profile='RFC8032 pure Ed25519',image_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),image_bytes=binary.stat().st_size,assembly_inspection=inspect_assembly(B/'check.S'),source_sha256=hashlib.sha256((B/'probe.lean').read_bytes()).hexdigest(),assembly_sha256=hashlib.sha256((B/'check.S').read_bytes()).hexdigest(),checks=checks,strict_inputs=['S=L','y=p','negative_zero','identity_public_key','nonsquare_y','sign_and_verify_length_bound'],scratch_cleanup='28672 bytes zero after public derivation, signing, verification and failure',sha512_padding_boundaries=[111,112,127,128,129],independent_implementation=subprocess.run([driver.tool('openssl'),'version'],capture_output=True,text=True,check=True).stdout.strip() if not a.first else 'published RFC8032 vector only',assurance='Implementation vectors only; no constant-time proof or independent cryptographic review.')
 (B/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
