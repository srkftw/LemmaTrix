"""Generated freestanding RV64 crypto checks against independent Noise transcripts."""
import hashlib,json,subprocess,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import driver
ROOT=driver.ROOT
B=ROOT/'build/network-crypto'
sys.path.insert(0,str(ROOT/'tests'))
from structured_runtime import BOOT

def store_bytes(address, raw):
 lines=[]
 for i in range(0,len(raw),8):
  chunk=raw[i:i+8]
  if len(chunk)==8:lines.append(f'  let t := Guest.store64 {address+i} 0x{int.from_bytes(chunk,"little"):016x} t')
  else:
   for j,v in enumerate(chunk):lines.append(f'  let t := Guest.store8 {address+i+j} {v} t')
 return '\n'.join(lines)

def vectors_source(v):
 source='import Guest.NetworkCryptoChecks\nimport Guest.Noise\nnamespace build.NetworkCryptoVectors\n'
 source+='def setup (role privateKey t : UInt64) : UInt64 :=\n'
 source+=store_bytes(0x600120,bytes.fromhex(v['psk']))+'\n'
 source+=store_bytes(0x600140,bytes.fromhex(v['prologue']))+'\n'
 source+='  let t := Guest.VaultCrypto.copy privateKey Guest.Noise.privateKey 32 t\n  Guest.Noise.initHandshake role t\n'
 source+='def check (t : UInt64) : UInt64 :=\n'
 addresses={};address=0x650000
 for name in ['client_private','server_private','first','second','client_plain','server_plain','client_transport','server_transport']:
  addresses[name]=address;raw=bytes.fromhex(v[name]);source+=store_bytes(address,raw)+'\n';address+=256
 c,s,first,second,cp,sp,ct,st=[addresses[n] for n in addresses]
 cl=len(bytes.fromhex(v['client_plain']));sl=len(bytes.fromhex(v['server_plain']))
 source+=f'''  let initial := Guest.NetworkCryptoChecks.x25519 t
  if initial != 0 then 1 else
  let t := setup 1 {c} initial
  let t := Guest.Noise.writeFirst 0x642000 t
  if !Guest.NetworkCryptoChecks.equal 0x642000 {first} 48 t then 2 else
  let t := Guest.Noise.readSecond {second} t
  if t == Guest.Noise.err then 3 else
  let t := Guest.Noise.sealRecord {cp} {cl} 0x642000 t
  if !Guest.NetworkCryptoChecks.equal 0x642000 {ct} {cl+16} t then 4 else
  let t := Guest.Noise.openRecord {st} {sl+16} 0x642000 t
  if t == Guest.Noise.err || !Guest.NetworkCryptoChecks.equal 0x642000 {sp} {sl} t then 5 else
  let t := Guest.Noise.openRecord {st} {sl+16} 0x642000 t
  if t != Guest.Noise.err then 6 else
  let t := Guest.Noise.disconnect t
  let t := setup 2 {s} t
  let t := Guest.Noise.readFirst {first} t
  if t == Guest.Noise.err then 7 else
  let t := Guest.Noise.writeSecond 0x642000 t
  if !Guest.NetworkCryptoChecks.equal 0x642000 {second} 48 t then 8 else
  let t := Guest.Noise.openRecord {ct} {cl+16} 0x642000 t
  if t == Guest.Noise.err || !Guest.NetworkCryptoChecks.equal 0x642000 {cp} {cl} t then 9 else
  let t := Guest.Noise.sealRecord {sp} {sl} 0x642000 t
  if !Guest.NetworkCryptoChecks.equal 0x642000 {st} {sl+16} t then 10 else
  let t := Guest.Noise.disconnect t
  let t := setup 2 {s} t
  let t := Guest.store8 {first+40} (Guest.load8 {first+40} t ^^^ 1) t
  let t := Guest.Noise.readFirst {first} t
  if t != Guest.Noise.err then 11 else
  let t := Guest.Noise.disconnect t
  let t := setup 2 {s} t
  let t := Guest.store8 {first+40} (Guest.load8 {first+40} t ^^^ 1) t
  let t := Guest.store8 Guest.Noise.h (Guest.load8 Guest.Noise.h t ^^^ 1) t
  let t := Guest.Noise.readFirst {first} t
  if t != Guest.Noise.err then 12 else 0
end build.NetworkCryptoVectors
'''
 return source

def main():
 B.mkdir(parents=True,exist_ok=True)
 v=json.loads((ROOT/'tests/fixtures/noise_nnpsk0.json').read_text())
 (ROOT/'build/NetworkCryptoVectors.lean').write_text(vectors_source(v))
 for path in ['Guest/Primitives','Guest/Noise25519','Guest/NetworkCryptoChecks','Guest/VaultCrypto','Guest/ServiceSHA256','Guest/Noise','build/NetworkCryptoVectors']:
  driver.lean(['-o',path+'.olean',path+'.lean'])
 assembly=B/'check.S'
 driver.lean(['--run','Compiler/Main.lean','build.NetworkCryptoVectors',assembly,'build.NetworkCryptoVectors.check'])
 boot=BOOT.replace('lt_Examples_StructuredConsumer_check','lt_build_NetworkCryptoVectors_check')
 boot=boot.replace(' li t1,0x40000cf',' li t1,0x201000cf\n sd t1,24(t0)\n li t1,0x40000cf')
 boot=boot.replace(' call lt_finish\nfatal:\n li a0,2\n call lt_finish',""" beqz a0,passed
 li t0,0x642000
 li t1,48
 li t2,0x10000000
debug_output:
 lbu t3,0(t0)
 sb t3,0(t2)
 addi t0,t0,1
 addi t1,t1,-1
 bnez t1,debug_output
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
 li t0,0x100000
 li t1,0x00403333
 sw t1,0(t0)
1: j 1b""")
 (B/'boot.S').write_text(boot)
 objects=[]
 for i,source in enumerate([assembly,B/'boot.S',ROOT/'runtime/primitives.S']):
  output=B/f'{i}.o';driver.asm(source,output);objects.append(output)
 elf=B/'check.elf';binary=B/'check.bin'
 driver.run([driver.tool('ld.lld'),'-m','elf64lriscv','--no-relax','-T',ROOT/'runtime/kernel.ld',*objects,'-o',elf])
 driver.run([driver.tool('llvm-objcopy'),'-O','binary',elf,binary])
 args=[driver.tool('qemu-system-riscv64'),'-M','virt','-cpu','rv64','-m','64M','-smp','1','-bios','none','-nographic','-monitor','none','-kernel',binary]
 result=subprocess.run([str(a) for a in args],cwd=ROOT,capture_output=True,timeout=60)
 if result.returncode or result.stdout!=b'P':raise RuntimeError(f'native network crypto failed: exit{result.returncode}, {result.stderr.decode()}, output {result.stdout.hex()}')
 report={'schema':1,'environment':'QEMU RV64 system emulation; generated Lean native crypto','binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'RFC7748_section6_1':'pass','Noise_NNpsk0_independent_transcript_and_bidirectional_records':'pass','replay_tamper_transcript_mismatch':'reject'}
 (B/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
