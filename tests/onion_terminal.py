"""Five real guests:3-hop circuits plus independent inner mailbox NoiseNK.
Mailbox bearer tokens and ciphertext are public component fixtures. Node/circuit/
channel private keys are generated only inside their respective native guests.
This does not substitute for graphical Messenger/X3DH/recovery acceptance.
"""
import argparse,hashlib,json,os,signal,socket,struct,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tests'));sys.path.insert(0,str(ROOT/'tools'))
import server_store
import onion_route as route,driver,identity,live,messenger,releases

def words(raw):
 assert len(raw)>=64
 return struct.unpack_from('<8Q',raw)

def main():
 p=argparse.ArgumentParser();p.add_argument('--image',type=Path,default=ROOT/'build/live/guest.bin');p.add_argument('--output',type=Path,default=ROOT/'build/onion-terminal');a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
 image=a.output/'guest.bin';image.write_bytes(a.image.read_bytes());image_id=hashlib.sha256(image.read_bytes()).hexdigest()
 signer=a.output/'identity.ltrel';raw,_=releases.make(ROOT/'build/live/apps/identity.bin','identity','1.0.0',0,ROOT/'tests/keys/development-rsa.pem',profile=2);signer.write_bytes(raw)
 mailbox=a.output/'mailbox.ltrel';raw,_=releases.make(ROOT/'build/live/apps/mailbox.bin','mailbox','1.0.0',2048,ROOT/'tests/keys/development-rsa.pem',profile=2);mailbox.write_bytes(raw)
 backing=a.output/'operator.img';server_store.provision(backing)
 clients=[];processes=[];logs=[];observations=[];checks=[];started=time.monotonic()
 try:
  for i in range(5):
   base=a.output/f'node{i}';base.mkdir(exist_ok=True);path=base/'portal.sock';path.unlink(missing_ok=True);log=(base/'guest.log').open('wb');logs.append(log)
   command=[ROOT/'lt','run','--backend','qemu','--image',image,'--socket',path,'--network-mux']
   if i==4:command+=['--server-store',backing]
   processes.append(subprocess.Popen(list(map(str,command)),cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,start_new_session=True));route.wait(path.exists,90);c=live.Client(path,timeout=600);c.request(1);clients.append(c)
   if i:identity.start(c,signer,ROOT/'tests/keys/development-rsa-public.pem')
  certs=[]
  for i in range(1,5):
   probe=socket.socket();probe.bind(('127.0.0.1',0));port=probe.getsockname()[1];probe.close()
   cert,fingerprint=route.create(clients[i],f'127.0.0.1:{port}',f'terminal public operator family{i}',7 if i<4 else 8);certs.append(cert);(a.output/f'node{i}.certificate').write_bytes(cert);observations.append(dict(node=i,kind='relay' if i<4 else 'mailbox',fingerprint=fingerprint.hex()));print('created native operator',i,flush=True)
  for i,cert in enumerate(certs):route.enroll(clients[0],i,cert)
  for i in range(1,4):route.enroll(clients[i],0,certs[i])
  # Native mailbox intentional storage; exact Network441 grant is separate from
  # Launcher administrative440. Host provisions only an explicit empty backing.
  mc=clients[4];service,sid=messenger.install(mc,mailbox,ROOT/'tests/keys/development-rsa-public.pem',2048);launcher=messenger.launcher(mc)
  for op in (440,441):messenger.bind(mc,3,service,launcher,op,sid)
  network=next(row[0] for row in identity.instances(mc) if row[0]&255==6);messenger.bind(mc,3,service,network,441,sid)
  server_store.call(mc,230);ns=hashlib.sha256(b'explicit terminal component operator namespace').digest();grant=server_store.call(mc,231,service,2,1048576,ns)[0][1];messenger.invoke(mc,3,440,a=grant)
  recipient=hashlib.sha256(b'public terminal component recipient').digest();deposit=hashlib.sha256(b'public terminal component deposit bearer').digest();fetch=hashlib.sha256(b'public terminal component fetch bearer').digest();authority=recipient+hashlib.sha256(deposit).digest()+hashlib.sha256(fetch).digest()
  f,_=messenger.invoke(mc,3,440,h=1,a=1048576,b=128,data=authority,allowed_status=(0,6))
  while f[0]==6:f,_=messenger.invoke(mc,3,441,h=4,allowed_status=(0,6))
  for c in clients[1:]:route.route(c,30)
  began=time.monotonic();route.route(clients[0],31)
  route.wait(lambda:route.route(clients[0],32)[0][2]==3,240);setup=time.monotonic()-began;print('native3hop built',setup,flush=True)
  owner=messenger.launcher(clients[0]);route.route(clients[0],38,h=3,a=17,b=owner,c=1048576,d=128)
  def terminal_ready():
   f,pin=route.route(clients[0],41)
   if f[3]:raise AssertionError(('terminal setup failure',f))
   return pin if f[1]==1 and f[2]==3 else None
  pin=route.wait(terminal_ready,240);assert pin==hashlib.sha256(certs[3]).digest();checks.append('inner client/mailbox NoiseNK authenticates selected mailbox descriptor through3relays');print('inner terminal authenticated',flush=True)
  serial=0
  def rpc(action,a=0,b=0,c=0,data=b''):
   nonlocal serial
   serial+=1;request=struct.pack('<8Q',441,action,a,b,c,0,0,1)+data;route.route(clients[0],39,h=serial,data=request)
   def collect():
    f,answer=route.route(clients[0],40,h=serial,allow_error=True)
    if f[0]==6:return None
    assert f[0]==0,(f,answer);return answer
   answer=route.wait(collect,120);return words(answer),answer[64:]
  f,_=rpc(4);assert f[0]==0;checks.append('authenticated terminal request invokes actual exact-bound native Mailbox441')
  payload=b'Opaque public component ciphertext fixture\0'+hashlib.shake_256(b'terminal native ciphertext component fixture').digest(1495);commitment=hashlib.sha256(payload).digest();request=hashlib.sha256(b'public terminal component stable request').digest()
  f,_=rpc(1,len(payload),1,data=recipient+deposit+request+commitment);assert f[0]==0,f;handle=f[1]
  for offset in range(0,len(payload),512):
   f,_=rpc(2,handle,offset,data=recipient+deposit+payload[offset:offset+512]);assert f[0]==0,f
  f,_=rpc(3,handle,data=recipient+deposit);assert f[0] in (0,6),f
  while f[0]==6:f,_=rpc(4,handle,data=recipient+deposit)
  assert f[0]==0;checks.append('bounded opaque deposit publishes durably before accepted response')
  f,_=rpc(5,handle,0,512,data=recipient+bytes(32));assert f[0]==1,f;checks.append('wrong-recipient fetch authority denied inside authenticated terminal session')
  received=bytearray()
  for offset in range(0,len(payload),512):
   f,chunk=rpc(5,handle,offset,512,data=recipient+fetch);assert f[0]==0,f;received.extend(chunk)
  assert bytes(received)==payload and hashlib.sha256(received).digest()==commitment;checks.append('routed bounded512-byte fetch preserves complete ciphertext integrity')
  f,_=rpc(6,handle,data=recipient+fetch+commitment);assert f[0] in (0,6),f
  while f[0]==6:f,_=rpc(4,handle,data=recipient+fetch)
  assert f[0]==0;checks.append('native committed ciphertext acknowledgment/reclamation runs through same inner terminal')
  report=dict(schema=1,result='pass',image_sha256=image_id,backends=['qemu']*5,nodes=observations,setup_seconds=setup,total_seconds=time.monotonic()-started,checks=checks,fixture_ciphertext_bytes=len(payload),fixture_ciphertext_sha256=commitment.hex(),operator_backing=str(backing),mailbox_release=sid.hex(),limits='Component integration, not graphical Messenger/X3DH/recovery. Bearer tokens and opaque ciphertext are public test fixtures; all node, circuit and terminal Noise private keys are native and never exported. OnehostdoesnotestablishoperatorindependenceorTorinteroperability.');(a.output/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
 except BaseException as error:
  (a.output/'failure.json').write_text(json.dumps(dict(schema=1,image_sha256=image_id,error=repr(error),nodes=observations,checks_completed=checks),indent=2)+'\n');raise
 finally:
  for c in clients:
   try:c.close()
   except OSError:pass
  for process in processes:
   if process.poll() is None:os.killpg(process.pid,signal.SIGTERM)
  for process in processes:
   try:process.wait(timeout=10)
   except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait()
  for log in logs:log.close()
if __name__=='__main__':main()
