"""Independent OpenSSL/Hashlib ntor-v3 transcript oracle vs compiled RV64.
Published deterministic fixture scalars only, never live node provisioning.
"""
import hashlib,json,subprocess,sys,tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import onion_crypto as native
from network_crypto import store_bytes
import driver

def fixtures():
 with tempfile.TemporaryDirectory(prefix='ntor-fixture-') as tmp:
  p=Path(tmp)
  def run(args):return subprocess.run([driver.tool('openssl'),*args],capture_output=True,check=True).stdout
  def private(name):
   secret=hashlib.sha256(('Tor ntor-v3 independent fixture '+name).encode()).digest()
   (p/(name+'.der')).write_bytes(bytes.fromhex('302e020100300506032b656e04220420')+secret)
   public=run(['pkey','-inform','DER','-in',str(p/(name+'.der')),'-pubout','-outform','DER'])[-32:]
   (p/(name+'.pub')).write_bytes(bytes.fromhex('302a300506032b656e032100')+public);return secret,public
  def dh(a,b):return run(['pkeyutl','-derive','-inkey',str(p/(a+'.der')),'-keyform','DER','-peerkey',str(p/(b+'.pub')),'-peerform','DER'])
  x,X=private('client');b,B=private('onion');y,Y=private('server')
  ID=hashlib.sha256(b'Public test relay Ed25519 ID fixture').digest();ver=b'LemmaTrix ntor-v3 fixture descriptor binding';proto=b'ntor3-curve25519-sha3_256-1'
  encap=lambda a:len(a).to_bytes(8,'big')+a
  h=lambda tag,msg:hashlib.sha3_256(encap(proto+tag)+msg).digest()
  kdf=lambda tag,msg,n:hashlib.shake_256(encap(proto+tag)+msg).digest(n)
  def aes(key,msg):return subprocess.run([driver.tool('openssl'),'enc','-aes-256-ctr','-K',key.hex(),'-iv','00'*16],input=msg,capture_output=True,check=True).stdout
  bx=dh('client','onion');xy=dh('client','server')
  phase=kdf(b':kdf_phase1',bx+ID+X+B+proto+encap(ver),64)
  cm=aes(phase[:32],b'\0');mac=h(b':msg_mac',encap(phase[32:])+ID+B+X+cm)
  first=ID+B+X+cm+mac
  secret=xy+bx+ID+B+X+Y+proto+encap(ver);seed=h(b':key_seed',secret);verify=h(b':verify',secret)
  stream=kdf(b':kdf_final',seed,124);sm=aes(stream[:32],b'\0');auth=h(b':auth_final',verify+ID+B+Y+X+mac+encap(sm)+proto+b'Server')
  return dict(x=x,X=X,b=b,B=B,y=y,Y=Y,ID=ID,ver=ver,first=first,second=Y+auth+sm,keys=stream[32:])

def source(v):
 s='import Guest.TorNtor\nset_option maxRecDepth 10000\nnamespace build.OnionNtor\n'
 s+='def check (t : UInt64) : UInt64 :=\n'
 addresses={name:0x700000+i*512 for i,name in enumerate(v)}
 for name,data in v.items():s+=store_bytes(addresses[name],data)+'\n'
 args=0x708000;st=0x709000;first=0x70a000;second=0x70b000;keys=0x70c000;scratch=0x6c0000
 for offset,value in [(0,addresses['ID']),(8,addresses['B']),(16,addresses['x']),(24,addresses['ver']),(32,len(v['ver'])),(40,0x708100),(48,1),(56,addresses['b'])]:s+=f'  let t := Guest.store64 {args+offset} {value} t\n'
 s+=f'  let t := Guest.store8 0x708100 0 t\n  let t := Guest.TorNtor.clientStart {scratch} {st} {args} {first} t\n'
 s+=f'  if t == Guest.TorNtor.err || Guest.TorNtor.difference {first} {addresses["first"]} 129 0 t != 0 then 1 else\n'
 s+=f'  let t := Guest.store64 {args+16} {addresses["y"]} t\n  let t := Guest.TorNtor.serverRespond {scratch} {args} {first} 129 {second} {keys} t\n'
 s+=f'  if t == Guest.TorNtor.err || Guest.TorNtor.difference {second} {addresses["second"]} 65 0 t != 0 then 2 else\n'
 s+=f'  if Guest.TorNtor.difference {keys} {addresses["keys"]} 92 0 t != 0 then 3 else\n'
 s+=f'  let t := Guest.TorNtor.clientFinish {scratch} {st} {args} {second} 65 {keys+128} t\n'
 s+=f'  if t == Guest.TorNtor.err || Guest.TorNtor.difference {keys+128} {addresses["keys"]} 92 0 t != 0 then 4 else\n'
 s+=f'  if Guest.TorNtor.nonzero {scratch} 8192 0 t != 0 || Guest.TorNtor.nonzero {st} 256 0 t != 0 then 5 else\n'
 # tamper first MAC, reply AUTH; forbidden DH, wrong descriptor, replay finish.
 s+=f'  let t := Guest.store8 {first+100} (Guest.load8 {first+100} t ^^^ 1) t\n  let r := Guest.TorNtor.serverRespond {scratch} {args} {first} 129 {second} {keys} t\n  if r != Guest.TorNtor.err then 6 else\n'
 s+=f'  let t := Guest.store8 {first+100} (Guest.load8 {first+100} r ^^^ 1) r\n  let t := Guest.store64 {args+16} {addresses["x"]} t\n  let t := Guest.TorNtor.clientStart {scratch} {st} {args} {first} t\n'
 s+=f'  let t := Guest.store8 {second+40} (Guest.load8 {second+40} t ^^^ 1) t\n  let r := Guest.TorNtor.clientFinish {scratch} {st} {args} {second} 65 {keys} t\n  if r != Guest.TorNtor.err then 7 else\n'
 s+=f'  if Guest.TorNtor.nonzero {scratch} 8192 0 r != 0 || Guest.TorNtor.nonzero {st} 256 0 r != 0 then 8 else\n'
 s+='  0\nend build.OnionNtor\n';return s

def main():
 import argparse
 p=argparse.ArgumentParser();p.add_argument('--backend',action='append',choices=['qemu','x86_64','aarch64']);a=p.parse_args()
 v=fixtures();driver.lean(['-o','Guest/TorNtor.olean','Guest/TorNtor.lean']);native.B=driver.ROOT/'build/onion-ntor';binary=native.build(source(v),'OnionNtor')
 report=dict(schema=1,profile='ntor3-curve25519-sha3_256-1; canonical CM/SM byte0',image_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),image_bytes=binary.stat().st_size,fixtures={k:b.hex() for k,b in v.items()},checks=[native.execute(binary,b) for b in a.backend or ['qemu']],assurance='OpenSSL X25519/AES256CTR and hashlib SHA3/SHAKE independent differential transcript, compiled RV64; no live circuit or interoperability claim')
 (native.B/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
