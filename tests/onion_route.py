"""Four native guests: public enrollment, NK links,3-hop ntor-v3 circuit.
Host moves public certificates and opaque socket bytes. Every operator generates
its own private keys inside its own guest through supported native commands.
"""
import argparse,hashlib,json,os,signal,socket,struct,subprocess,sys,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'));sys.path.insert(0,str(ROOT/'tests'))
import driver,identity,live,network,releases,onion

def wait(check,seconds=180):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  result=check()
  if result:return result
  time.sleep(.1)
 raise TimeoutError('bounded native circuit condition did not complete')

def route(client,op,h=0,a=0,b=0,c=0,d=0,e=0,data=b'',slot=0,allow_error=False):
 target=next(row[0] for row in identity.instances(client) if row[0]&255==6)
 token=struct.unpack('<Q',client.request(175,struct.pack('<Q8Q',target,op,h,a,b,c,d,e,2)+data))[0]
 until=time.monotonic()+600
 while time.monotonic()<until:
  raw=client.request(176,struct.pack('<Q',token))
  if len(raw)==8:time.sleep(.05);continue
  f=struct.unpack_from('<8Q',raw)
  if f[0] and not allow_error:raise ValueError(f'native circuit status{f[0]}')
  return f,raw[64:]
 client.request(177,struct.pack('<Q',token));raise TimeoutError('native circuit completion')

def create(c,endpoint,family,kind=7):
 _,public=onion.call(c,20)
 federation=hashlib.sha256(b'Campaign008 native circuit selected federation').digest();scope=hashlib.sha256(b'Campaign008 relay enrollment').digest()
 f,_=identity.invoke(c,400,a=3,data=federation+scope);key=f[1]
 b=bytearray(256);struct.pack_into('<8Q',b,0,identity.NODE_MAGIC,2,kind,1,1,1048576,65536,1);b[64:128]=public;b[128:160]=hashlib.sha256(family.encode()).digest();ep=endpoint.encode();struct.pack_into('<3Q',b,160,1,0,len(ep));b[184:184+len(ep)]=ep
 launcher=next(row[0] for row in identity.instances(c) if row[0]&255==1)
 f,_=identity.invoke(c,405,h=key,a=launcher,b=2,c=256,data=hashlib.sha256(b).digest());_,cert=identity.invoke(c,402,h=f[1],data=b)
 _,fingerprint=onion.call(c,21,data=cert)
 return cert,fingerprint

def enroll(c,slot,cert):
 _,body=onion.call(c,22,h=slot,data=cert);fingerprint=body[480:512]
 onion.call(c,23,h=slot,data=fingerprint)
 return fingerprint.hex()

def main():
 p=argparse.ArgumentParser();p.add_argument('--image',type=Path,default=ROOT/'build/live/guest.bin');p.add_argument('--output',type=Path,default=ROOT/'build/onion-route');p.add_argument('--client-backend',choices=('qemu','x86_64'),default='x86_64');p.add_argument('--relay-backend',choices=('qemu','x86_64'),default='qemu');p.add_argument('--signer',type=Path);p.add_argument('--keep',action='store_true');a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
 image=a.image.resolve();frozen=a.output/'guest.bin';frozen.write_bytes(image.read_bytes());image_id=hashlib.sha256(frozen.read_bytes()).hexdigest()
 signer=a.signer or a.output/'identity.ltrel'
 if not a.signer:
  raw,_=releases.make((ROOT/'build/live/apps/identity.bin'),'identity','1.0.0',0,ROOT/'tests/keys/development-rsa.pem',profile=2);signer.write_bytes(raw)
 processes=[];clients=[];logs=[];observations=[]
 try:
  for i,backend in enumerate([a.client_backend,*([a.relay_backend]*3)]):
   base=a.output/f'node{i}';base.mkdir(exist_ok=True);path=base/'portal.sock';path.unlink(missing_ok=True);log=(base/'guest.log').open('wb');logs.append(log)
   processes.append(subprocess.Popen([str(ROOT/'lt'),'run','--backend',backend,'--image',str(frozen),'--socket',str(path),'--network-mux'],cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,start_new_session=True))
   wait(path.exists,90);c=live.Client(path,timeout=600);clients.append(c);c.request(1)
   if i:identity.start(c,signer,ROOT/'tests/keys/development-rsa-public.pem')
  certs=[];began=time.monotonic()
  for i in range(1,4):
   probe=socket.socket();probe.bind(('127.0.0.1',0));port=probe.getsockname()[1];probe.close()
   cert,fingerprint=create(clients[i],f'127.0.0.1:{port}',f'independent declared family {i}');certs.append(cert);(a.output/f'relay{i}.certificate').write_bytes(cert)
   observations.append(dict(node=i,public_certificate_sha256=hashlib.sha256(cert).hexdigest(),fingerprint=fingerprint.hex(),endpoint=f'127.0.0.1:{port}',private_keys='generated and retained only by this native guest'))
   print('created native relay credential',i,flush=True)
  for slot,cert in enumerate(certs):
   enroll(clients[0],slot,cert);print('approved public relay',slot,flush=True)
  enroll(clients[1],0,certs[1]);enroll(clients[2],0,certs[2]);print('approved native next-hop neighbors',flush=True)
  for c in clients[1:]:route(c,30,h=0,slot=0)
  route(clients[0],31,slot=0);setup_started=time.monotonic()
  def status():
   try:states=[route(c,32,slot=0)[0] for c in clients]
   except ValueError as error:
    if 'guest rejected command170, status1' in str(error):return None
    raise
   if states[0][2]==3:return states
   if any(s[3] for s in states):raise AssertionError('native route failed '+repr(states))
   return None
  states=wait(status,300);setup_seconds=time.monotonic()-setup_started;print('native3hopcircuit built',setup_seconds,flush=True)
  text=b'First native three-relay circuit text crossing';route(clients[0],33,a=17,data=text,slot=0)
  def take(c):
   f,data=route(c,34,slot=0,allow_error=True)
   if f[0]==4:return None
   assert f[0]==0 and f[2]==17,(f,data);return data
  assert wait(lambda:take(clients[3]),120)==text
  reply=b'Native third relay replies through all three backward layers';route(clients[3],36,a=17,data=reply,slot=0);assert wait(lambda:take(clients[0]),120)==reply
  # Stop an actual middle relay: client must become unavailable, never direct.
  try:clients[2].request(70)
  except EOFError:pass
  def failed():
   f,_=route(clients[0],32,slot=0);return f if f[3]!=0 else None
  # Socket teardown propagates through adjacent links; bounded engine close.
  broken=wait(failed,120)
  f,_=route(clients[0],33,a=17,data=b'must not direct downgrade',slot=0,allow_error=True);assert f[0]!=0
  report=dict(schema=1,image_sha256=image_id,image_bytes=frozen.stat().st_size,backend_roles=[a.client_backend,*([a.relay_backend]*3)],nodes=observations,result='pass',native_setup_seconds=setup_seconds,total_seconds=time.monotonic()-began,checks=['each of3relay guests independently generated private transport/onion/certification credentials','client public pin approval and declared family uniqueness','NoiseNK adjacent public responder authentication','CREATE2/ntor-v3 firsthop and2 protected EXTEND2 telescoping operations','opaque text delivered across3native relay guests','reply across3 independent backward relay layers','actual middle-relay shutdown produces unavailable and denies retry'],limits='This is native circuit-engine validation. It is not Messenger/X3DH/mailbox persistence or terminal service authentication acceptance; application mode1 remains unavailable until those integrations qualify.')
  (a.output/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
 except BaseException as error:
  (a.output/'failure.json').write_text(json.dumps(dict(schema=1,image_sha256=image_id,error=repr(error),observed_nodes=observations,scope='native circuit-engine integration; failure preserved'),indent=2)+'\n')
  raise
 finally:
  for c in clients:
   try:c.close()
   except OSError:pass
  if not a.keep:
   for process in processes:
    if process.poll() is None:os.killpg(process.pid,signal.SIGTERM)
   for process in processes:
    try:process.wait(timeout=10)
    except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait()
  for log in logs:log.close()
if __name__=='__main__':main()
