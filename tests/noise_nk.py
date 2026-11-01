"""Execute native Noise NK against an independent cryptography transcript.

All private inputs here are deterministic public test fixtures, never node keys.
"""
import argparse, hashlib, hmac, json, subprocess, sys, time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import driver, live_build
from network_crypto import store_bytes
from structured_runtime import BOOT
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
B=ROOT/'build/noise-nk'

def oracle():
    a,b,s=[hashlib.sha256(x).digest() for x in (b'public NK client fixture',b'public NK responder ephemeral fixture',b'public NK responder static fixture')]
    def pub(k):return X25519PrivateKey.from_private_bytes(k).public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    def dh(k,p):return X25519PrivateKey.from_private_bytes(k).exchange(X25519PublicKey.from_public_bytes(p))
    def mac(k,v):return hmac.new(k,v,hashlib.sha256).digest()
    h=ck=b'Noise_NK_25519_ChaChaPoly_SHA256'
    descriptor=hashlib.sha256(b'public descriptor test fixture').digest()
    h=hashlib.sha256(h+b'LT-OnionChannel-v1'+descriptor).digest()
    h=hashlib.sha256(h+pub(s)).digest()
    def mix(v):
        nonlocal ck
        prk=mac(ck,v);ck=mac(prk,b'\x01');return mac(prk,ck+b'\x02')
    h=hashlib.sha256(h+pub(a)).digest();key=mix(dh(a,pub(s)))
    tag=ChaCha20Poly1305(key).encrypt(bytes(12),b'',h)
    first=pub(a)+tag;h=hashlib.sha256(h+tag).digest()
    h=hashlib.sha256(h+pub(b)).digest();key=mix(dh(b,pub(a)))
    tag=ChaCha20Poly1305(key).encrypt(bytes(12),b'',h)
    second=pub(b)+tag;h=hashlib.sha256(h+tag).digest()
    key2=mix(b'');key1=ck
    plain=b'NK transport responder proof'
    record=ChaCha20Poly1305(key1).encrypt(bytes(12),plain,b'')
    response=ChaCha20Poly1305(key2).encrypt(bytes(12),plain,b'')
    return locals()

def source(v):
    s='import Guest.NoiseNK\nimport Guest.Transport\nnamespace build.NoiseNKCheck\ndef check (t : UInt64) : UInt64 :=\n'
    vals=[('a',v['a']),('b',v['b']),('s',v['s']),('pub',v['pub'](v['s'])),('desc',v['descriptor']),('first',v['first']),('second',v['second']),('plain',v['plain']),('record',v['record']),('response',v['response'])]
    addr={}
    for i,(k,raw) in enumerate(vals):addr[k]=0x700000+i*256;s+=store_bytes(addr[k],raw)+'\n'
    a,b,sk,pk,desc,first,second,plain,record,response=[addr[k] for k,_ in vals]
    s+=f'''  let t := Guest.NoiseNK.init 1 0 {pk} {desc} {a} t
  let t := Guest.NoiseNK.writeFirst 0x710000 t
  if t == Guest.LiveSDK.error || Guest.Noise.difference 0x710000 {first} 48 0 t != 0 then 1 else
  let t := Guest.NoiseNK.readSecond {second} t
  if t == Guest.LiveSDK.error then 2 else
  let t := Guest.Noise.sealRecord {plain} {len(v['plain'])} 0x710000 t
  if Guest.Noise.difference 0x710000 {record} {len(v['record'])} 0 t != 0 then 3 else
  let t := Guest.Noise.openRecord {response} {len(v['response'])} 0x710000 t
  if t == Guest.LiveSDK.error || Guest.Noise.difference 0x710000 {plain} {len(v['plain'])} 0 t != 0 then 4 else
  let t := Guest.NoiseNK.init 2 {sk} {pk} {desc} {b} t
  let t := Guest.NoiseNK.readFirst {first} t
  if t == Guest.LiveSDK.error then 5 else
  let t := Guest.NoiseNK.writeSecond 0x710000 t
  if t == Guest.LiveSDK.error || Guest.Noise.difference 0x710000 {second} 48 0 t != 0 then 6 else
  let t := Guest.Noise.openRecord {record} {len(v['record'])} 0x710000 t
  if t == Guest.LiveSDK.error then 7 else
  let t := Guest.Noise.openRecord {record} {len(v['record'])} 0x710000 t
  if t != Guest.LiveSDK.error then 8 else
  let t := Guest.store8 {desc} (Guest.load8 {desc} t ^^^ 1) t
  let t := Guest.NoiseNK.init 2 {sk} {pk} {desc} {b} t
  let t := Guest.NoiseNK.readFirst {first} t
  if t != Guest.LiveSDK.error then 9 else
  let t := Guest.store8 {desc} (Guest.load8 {desc} t ^^^ 1) t
  let t := Guest.store8 {first+40} (Guest.load8 {first+40} t ^^^ 1) t
  let t := Guest.NoiseNK.init 2 {sk} {pk} {desc} {b} t
  let t := Guest.NoiseNK.readFirst {first} t
  if t != Guest.LiveSDK.error then 10 else 0
end build.NoiseNKCheck
'''
    return s

def main():
    p=argparse.ArgumentParser();p.add_argument('--backend',choices=['qemu','x86_64','aarch64'],action='append');a=p.parse_args()
    B.mkdir(parents=True,exist_ok=True);path=ROOT/'build/NoiseNKCheck.lean';path.write_text(source(oracle()))
    live_build.compile_module('build.NoiseNKCheck')
    assembly=B/'check.S';driver.lean(['--run','Compiler/Main.lean','build.NoiseNKCheck',assembly,'build.NoiseNKCheck.check'])
    boot=BOOT.replace('lt_Examples_StructuredConsumer_check','lt_build_NoiseNKCheck_check')
    boot=boot.replace(' li t1,0x40000cf',' li t1,0x201000cf\n sd t1,24(t0)\n li t1,0x40000cf')
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
 li t0,0x100000
 li t1,0x00403333
 sw t1,0(t0)
1: j 1b''')
    (B/'boot.S').write_text(boot);objects=[]
    for i,src in enumerate([assembly,B/'boot.S',ROOT/'runtime/primitives.S']):
        obj=B/f'{i}.o';driver.asm(src,obj);objects.append(obj)
    elf=B/'check.elf';binary=B/'check.bin';driver.run([driver.tool('ld.lld'),'-m','elf64lriscv','--no-relax','-T',ROOT/'runtime/kernel.ld',*objects,'-o',elf]);driver.run([driver.tool('llvm-objcopy'),'-O','binary',elf,binary])
    checks=[]
    for backend in a.backend or ['qemu']:
        if backend=='qemu':command=[driver.tool('qemu-system-riscv64'),'-M','virt','-cpu','rv64','-m','64M','-smp','1','-bios','none','-nographic','-monitor','none','-kernel',binary]
        else:
            obj=B/(backend+'.o');exe=B/('lt-'+backend);driver.asm(ROOT/f'emulator/{backend}.S',obj,backend+'-linux-gnu');driver.run([driver.tool('ld.lld'),'-static','-e','_start',obj,'-o',exe]);command=([driver.tool('qemu-aarch64')] if backend=='aarch64' else [])+[exe,binary,'--interactive']
        began=time.monotonic();r=subprocess.run(list(map(str,command)),capture_output=True,timeout=900)
        if r.returncode or r.stdout!=b'P':raise RuntimeError(f'{backend}: exit={r.returncode}, stdout={r.stdout.hex()}, stderr={r.stderr.decode()}')
        checks.append(dict(backend=backend,seconds=time.monotonic()-began,result='pass'))
    report=dict(schema=1,profile='Noise_NK_25519_ChaChaPoly_SHA256',prologue='LT-OnionChannel-v1 || descriptorSHA256',binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),checks=checks,tests=['independent first/second transcript','bidirectional independent transport records','record replay denied','descriptor substitution denied','tag corruption denied'],limitation='component execution, not circuit or Tor interoperability')
    (B/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
