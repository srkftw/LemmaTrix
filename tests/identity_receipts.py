"""Installed native Identity finite receipts and sealed seed recovery.

Operational keys are generated only by each native Identity service. OpenSSL
verifies public signatures as an independent oracle; it receives no private key.
The real Mailbox cache/publication integration is exercised separately.
"""
import argparse, hashlib, json, os, signal, struct, subprocess, sys, time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools')]
import driver, identity, live, live_build, messenger, releases
PUB=ROOT/'tests/keys/development-rsa-public.pem'
KEY=ROOT/'tests/keys/development-rsa.pem'

def main():
 p=argparse.ArgumentParser();p.add_argument('--image',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
 image=out/'guest.bin';image.write_bytes(a.image.read_bytes())
 packages={}
 for name,module,entry,rights in [('identity','Guest.Identity','Guest.Identity.main',0),('receipt-caller','tests.fixtures.ReceiptCaller','Tests.ReceiptCaller.main',2048)]:
  binary=live_build.app(module,entry,'receipt-'+name,2)
  raw,_=releases.make(binary,name,'0.8.0',rights,KEY,profile=2)
  path=out/(name+'.ltrel');path.write_bytes(raw);packages[name]=path
 sock=out/'guest.sock';log=(out/'guest.log').open('wb');process=client=None;checks=[]
 def passed(message):checks.append(message);print('PASS',message,flush=True)
 def raw(target,op,h=0,data=b''):
  response=client.request(150,struct.pack('<Q8Q',target,op,h,0,0,0,0,0,1)+data)
  return struct.unpack_from('<8Q',response),response[64:]
 def expect_failure(fn):
  try:fn()
  except ValueError:return
  raise AssertionError('unexpected native acceptance')
 def verify(public,message,signature):
  (out/'public.der').write_bytes(bytes.fromhex('302a300506032b6570032100')+public)
  (out/'message').write_bytes(message);(out/'signature').write_bytes(signature)
  subprocess.run([driver.tool('openssl'),'pkeyutl','-verify','-pubin','-inkey',str(out/'public.der'),'-keyform','DER','-rawin','-in',str(out/'message'),'-sigfile',str(out/'signature')],check=True,capture_output=True)
 def key(role,fed,scope):
  fields,payload=identity.invoke(client,400,a=role,data=fed+scope)
  return fields[1],payload[96:128]
 try:
  process=subprocess.Popen([str(ROOT/'lt'),'run','--backend','qemu','--image',str(image),'--socket',str(sock)],cwd=ROOT,stdout=log,stderr=log,start_new_session=True)
  until=time.monotonic()+90
  while not sock.exists():
   if process.poll()is not None or time.monotonic()>until:raise RuntimeError('guest start')
   time.sleep(.05)
  client=live.Client(sock,timeout=600)
  identity_raw=packages['identity'].read_bytes()
  client.request(10,identity_raw[128:160]+releases.public_modulus(PUB))
  signer_slot,admitted=client.install(packages['identity'])
  signer_sid=bytes.fromhex(admitted['release_id'])
  def start_signer():
   service=struct.unpack_from('<Q',client.request(25,struct.pack('<Q',signer_slot)),8)[0]
   for operation in identity.OPERATIONS:identity.bind(client,service,messenger.launcher(client),signer_sid,bytes(32),operation)
   return service
  signer=start_signer()
  caller,caller_sid=messenger.install(client,packages['receipt-caller'],PUB,2048)
  for op in (440,441):messenger.bind(client,3,caller,messenger.launcher(client),op,caller_sid)
  binding=identity.bind(client,signer,caller,signer_sid,caller_sid,409)
  fed=hashlib.sha256(b'native receipt federation').digest();scope=hashlib.sha256(b'native operator scope').digest()
  node,npub=key(3,fed,scope);receipt,rpub=key(4,fed,scope)
  nodehash=hashlib.sha256(b'public component accepted node descriptor').digest();terms=hashlib.sha256(b'finite zero-price byte and work terms').digest()
  declaration=struct.pack('<2Q',0x314b52544c,1)+rpub+nodehash+struct.pack('<2Q',1,1)+bytes(32)
  launcher=messenger.launcher(client)
  permit,_=identity.invoke(client,405,h=node,a=launcher,b=3,c=128,data=hashlib.sha256(declaration).digest())
  _,certificate=identity.invoke(client,402,h=permit[1],data=declaration)
  assert len(certificate)==352;verify(npub,certificate[:288],certificate[288:])
  passed('native role3 certifies only typed role4 receipt-key declaration')
  fields,_=identity.invoke(client,409,a=receipt,b=caller,c=1,data=terms+nodehash);grant=fields[1]
  body=struct.pack('<4Q',0x315250544c,1,1,caller)+hashlib.sha256(b'actual request').digest()+hashlib.sha256(b'actual ciphertext').digest()+terms+nodehash+struct.pack('<4Q',713,1,1,0)
  def sign(grant,data,who=caller):
   fields,_=raw(who,440,h=grant,data=data);assert fields[0]==0,fields
   until=time.monotonic()+180
   while True:
    fields,sig=raw(who,441)
    if fields[0]!=6:return fields,sig
    if time.monotonic()>until:raise TimeoutError('native receipt signing')
    time.sleep(.05)
  fields,signature=sign(grant,body);assert fields[0]==0 and fields[2]==0 and len(signature)==64
  verify(rpub,body,signature)
  fields,_=sign(grant,body);assert fields[0]==3,fields
  passed('exact admitted service signs fixed receipt once; finite exhaustion fails closed')
  grant=identity.invoke(client,409,a=receipt,b=caller,c=2,data=terms+nodehash)[0][1]
  expect_failure(lambda:identity.invoke(client,409,h=grant,data=body))
  altered=bytearray(body);altered[96]^=1
  fields,_=sign(grant,bytes(altered));assert fields[0]==1,fields
  altered=bytearray(body);struct.pack_into('<Q',altered,24,caller+1)
  fields,_=sign(grant,bytes(altered));assert fields[0]==2,fields
  client.request(173,struct.pack('<4Q',1,caller,409,binding))
  fields,_=raw(caller,440,h=grant,data=body);assert fields[0]!=0
  identity.bind(client,signer,caller,signer_sid,caller_sid,409)
  fields,_=sign(grant,body);assert fields[0]==3,fields
  passed('wrong caller, changed terms, wrong service incarnation, revoked and replaced exact binding denied')
  credential=hashlib.sha256(b'public high-entropy retention test credential').digest()
  _,sealed=identity.invoke(client,408,a=node,b=receipt,data=credential);assert len(sealed)==192
  client.request(26,struct.pack('<Q',signer))
  signer=start_signer()
  expect_failure(lambda:identity.invoke(client,408,h=1,data=bytes(32)+npub+sealed))
  tampered=bytearray(sealed);tampered[63]^=1
  expect_failure(lambda:identity.invoke(client,408,h=1,data=credential+npub+bytes(tampered)))
  expect_failure(lambda:identity.invoke(client,408,h=1,data=credential+bytes(32)+sealed))
  fields,_=identity.invoke(client,408,h=1,data=credential+npub+sealed);newnode,newreceipt=fields[1:3]
  _,exported=identity.invoke(client,401,h=newnode);assert exported[96:128]==npub
  _,exported=identity.invoke(client,401,h=newreceipt);assert exported[96:128]==rpub
  passed('actual Identity process restart recovers same keys only by native sealed unwrap; wrong credential/tamper/substitution denied')
  report=dict(schema=1,result='pass',image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),checks=checks,node_public=npub.hex(),receipt_public=rpub.hex(),sealed_blob_bytes=192,private_key_exported=False,limits='Focused installed-service test. Public test unlock credential; real node descriptor/cache/operator backing restart are exercised by the connected Mailbox receipt test.')
  (out/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
 finally:
  if client:client.close()
  if process and process.poll()is None:os.killpg(process.pid,signal.SIGTERM);process.wait(20)
  log.close()
if __name__=='__main__':main()
