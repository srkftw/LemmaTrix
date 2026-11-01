"""Native signed Mailbox acceptance, exact retry and protected operator restart.

Every operational Ed25519/X25519 key is generated inside the guest. The host
passes public certificates, opaque sealed backups and explicit unlock fixtures.
"""
import argparse, hashlib, json, os, signal, struct, subprocess, sys, time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools')]
import driver, identity, live, live_build, messenger, onion, releases, server_store
PUB=ROOT/'tests/keys/development-rsa-public.pem';KEY=ROOT/'tests/keys/development-rsa.pem'

def main():
 p=argparse.ArgumentParser();p.add_argument('--image',required=True,type=Path);p.add_argument('--output',required=True,type=Path);a=p.parse_args()
 out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);image=out/'guest.bin';image.write_bytes(a.image.read_bytes());disk=out/'operator.img';server_store.provision(disk)
 packages={}
 for name,module,rights in [('identity','Guest.Identity',0),('mailbox','Guest.Mailbox',2048)]:
  binary=live_build.app(module,module+'.main','receipt-actual-'+name,2)
  raw,_=releases.make(binary,'receipt-actual-'+name,'0.8.0',rights,KEY,profile=2);path=out/(name+'.ltrel');path.write_bytes(raw);packages[name]=path
 fed=hashlib.sha256(b'native receipt restart federation').digest();scope=hashlib.sha256(b'native receipt operator scope').digest();credential=hashlib.sha256(b'public operator unlock test fixture for receipt recovery').digest()
 recipient=hashlib.sha256(b'public receipt recipient fixture').digest();deposit=hashlib.sha256(b'public receipt deposit fixture').digest();fetch=hashlib.sha256(b'public receipt fetch fixture').digest();namespace=hashlib.sha256(b'explicit receipt mailbox operator namespace').digest()
 terms=hashlib.sha256(struct.pack('<8Q',1,1,8388608,65536,8192,16,8,1)).digest();checks=[];c=process=log=None;sock=out/'guest.sock'
 def passed(s):checks.append(s);print('PASS',s,flush=True)
 def start():
  nonlocal c,process,log
  sock.unlink(missing_ok=True);log=(out/'guest.log').open('ab');process=subprocess.Popen([str(ROOT/'lt'),'run','--backend','qemu','--image',str(image),'--socket',str(sock),'--server-store',str(disk)],cwd=ROOT,stdout=log,stderr=log,start_new_session=True)
  until=time.monotonic()+90
  while not sock.exists():
   if process.poll()is not None or time.monotonic()>until:raise RuntimeError('guest start')
   time.sleep(.05)
  c=live.Client(sock,timeout=600);identity.start(c,packages['identity'],PUB)
 def stop():
  nonlocal c,process,log
  if c:c.close();c=None
  if process and process.poll()is None:os.killpg(process.pid,signal.SIGTERM);process.wait(20)
  if log:log.close()
  process=log=None
 def verify(pub,message,sig):
  (out/'public.der').write_bytes(bytes.fromhex('302a300506032b6570032100')+pub);(out/'message').write_bytes(message);(out/'signature').write_bytes(sig)
  subprocess.run([driver.tool('openssl'),'pkeyutl','-verify','-pubin','-inkey',str(out/'public.der'),'-keyform','DER','-rawin','-in',str(out/'message'),'-sigfile',str(out/'signature')],check=True,capture_output=True)
 def invoke(op,**kwargs):return messenger.invoke(c,3,op,allowed_status=(0,6),**kwargs)
 def admin(**kwargs):
  fields,payload=invoke(440,**kwargs)
  until=time.monotonic()+180
  while fields[0]==6:
   if time.monotonic()>until:raise TimeoutError('native mailbox administration')
   fields,payload=invoke(441,h=4);time.sleep(.01)
  return fields,payload
 def setup_mailbox(receipt,cert,nodehash):
  service,sid=messenger.install(c,packages['mailbox'],PUB,2048);launcher=messenger.launcher(c)
  for op in (440,441):messenger.bind(c,3,service,launcher,op,sid)
  signer=identity.endpoint(c,409);signer_sid=bytes.fromhex(releases.inspect(packages['identity'].read_bytes())['release_id']);identity.bind(c,signer,service,signer_sid,sid,409)
  server_store.call(c,230);grant=server_store.call(c,231,service,2,1048576,namespace)[0][1];admin(a=grant)
  authority=identity.invoke(c,409,a=receipt,b=service,c=1,data=terms+nodehash)[0][1]
  admin(h=4,a=authority,data=cert+terms+nodehash)
  fields,profile=invoke(441,h=10);assert fields[0]==0 and profile==cert+terms+nodehash
  return service
 def deposit_one(index,receipt_pub,nodehash):
  payload=b'Opaque ciphertext accepted only after a native signed durable receipt.\0'+hashlib.shake_256(('opaque receipt component '+str(index)).encode()).digest(643)
  request=hashlib.sha256(('stable actual receipt request '+str(index)).encode()).digest();commit=hashlib.sha256(payload).digest();auth=recipient+deposit
  fields,_=invoke(441,h=1,a=len(payload),b=1,data=auth+request+commit);handle=fields[1];assert fields[0]==0
  for offset in range(0,len(payload),512):invoke(441,h=2,a=handle,b=offset,data=auth+payload[offset:offset+512])
  fields,accepted=invoke(441,h=3,a=handle,data=auth)
  until=time.monotonic()+240
  while fields[0]==6:
   if time.monotonic()>until:raise TimeoutError('native signed durable publication')
   fields,accepted=invoke(441,h=4,a=handle,data=auth);time.sleep(.01)
  assert len(accepted)==256,(fields,len(accepted));body,sig=accepted[:192],accepted[192:]
  assert body[32:64]==request and body[64:96]==commit and body[96:128]==terms and body[128:160]==nodehash
  assert struct.unpack_from('<Q',body,160)[0]==len(payload);verify(receipt_pub,body,sig)
  repeated,again=invoke(441,h=1,a=len(payload),b=1,data=auth+request+commit)
  assert repeated[0]==0 and again==accepted,'lost acknowledgment retry changed signed acceptance'
  return dict(request=request,commit=commit,payload=payload,handle=handle,receipt=accepted)
 try:
  start();_,public=onion.call(c,20)
  node=identity.invoke(c,400,a=3,data=fed+scope)[0][1]
  body=bytearray(256);struct.pack_into('<8Q',body,0,identity.NODE_MAGIC,2,8,1,1,1048576,65536,1);body[64:128]=public;body[128:160]=hashlib.sha256(b'one explicitly declared operator family').digest();endpoint=b'127.0.0.1:39481';struct.pack_into('<3Q',body,160,1,0,len(endpoint));body[184:184+len(endpoint)]=endpoint
  launcher=messenger.launcher(c);permit=identity.invoke(c,405,h=node,a=launcher,b=2,c=256,data=hashlib.sha256(body).digest())[0][1];_,nodecert=identity.invoke(c,402,h=permit,data=body);_,nodehash=onion.call(c,21,data=nodecert)
  fields,public=identity.invoke(c,400,a=4,data=fed+scope);receipt=fields[1];receipt_pub=public[96:128]
  declaration=struct.pack('<2Q',0x314b52544c,1)+receipt_pub+nodehash+struct.pack('<2Q',1,1)+bytes(32)
  permit=identity.invoke(c,405,h=node,a=launcher,b=3,c=128,data=hashlib.sha256(declaration).digest())[0][1];_,cert=identity.invoke(c,402,h=permit,data=declaration);verify(nodecert[112:144],cert[:288],cert[288:])
  _,sealed=identity.invoke(c,408,a=node,b=receipt,data=credential);assert len(sealed)==192
  who=next(row[0] for row in identity.instances(c) if row[0]&255==6);c.request(178,struct.pack('<2Q',who,1));onion.call(c,43,data=credential+sealed)
  service=setup_mailbox(receipt,cert,nodehash);admin(h=1,a=1048576,b=32,data=recipient+hashlib.sha256(deposit).digest()+hashlib.sha256(fetch).digest())
  first=deposit_one(1,receipt_pub,nodehash);passed('actual installed Mailbox commits ciphertext and exact signed receipt before acceptance; retry uses cached signature after one-use grant exhaustion')
  stop();start();who=next(row[0] for row in identity.instances(c) if row[0]&255==6);c.request(178,struct.pack('<2Q',who,1));_,restored=onion.call(c,44,data=credential);assert restored==sealed
  _,restoredcert=onion.call(c,25,h=4);assert restoredcert[:480]==nodecert and restoredcert[480:]==nodehash
  fields,_=identity.invoke(c,408,h=1,data=credential+nodecert[112:144]+restored);node,receipt=fields[1:3]
  _,rpub=identity.invoke(c,401,h=receipt);assert rpub[96:128]==receipt_pub
  permit=identity.invoke(c,405,h=node,a=messenger.launcher(c),b=3,c=128,data=hashlib.sha256(declaration).digest())[0][1];_,newcert=identity.invoke(c,402,h=permit,data=declaration);assert newcert==cert
  service=setup_mailbox(receipt,cert,nodehash)
  fields,accepted=invoke(441,h=1,a=len(first['payload']),b=1,data=recipient+deposit+first['request']+first['commit']);assert fields[0]==0 and accepted==first['receipt']
  second=deposit_one(2,receipt_pub,nodehash)
  passed('actual whole guest/operator backing restart restores both native Identity seeds; declaration and historical receipt unchanged; fresh finite authority signs new acceptance')
  fields,chunk=invoke(441,h=5,a=first['handle'],b=0,c=512,data=recipient+fetch);assert chunk==first['payload'][:512]
  report=dict(schema=1,result='pass',image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),checks=checks,node_certificate_sha256=nodehash.hex(),receipt_public=receipt_pub.hex(),first_receipt_sha256=hashlib.sha256(first['receipt']).hexdigest(),second_receipt_sha256=hashlib.sha256(second['receipt']).hexdigest(),operator_sectors=[1,6],keys_generated_only_native=True,limits='One QEMU component guest with public recipient/unlock fixtures; full Messenger circuit/UI journey is separate. Native static keys and receipt seeds are never exported unwrapped.')
  (out/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
 finally:stop()
if __name__=='__main__':main()
