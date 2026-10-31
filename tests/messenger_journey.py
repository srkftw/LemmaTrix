"""Connected native Messenger journey through three independent relay guests.

Host adapters start machines, move explicitly exchanged public material, supply
real input/display, and carry opaque TCP/block bytes. All keys, circuits,
mailbox publication, session encryption and decryption execute in the guests.
"""
from __future__ import annotations
import argparse,contextlib,hashlib,json,os,resource,signal,socket,struct,subprocess,sys,time,traceback
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import driver,identity,live,live_build,messenger,onion,projects,releases,server_store
from graphical_devices import DeviceInput
PUB=ROOT/'tests/keys/development-rsa-public.pem'
SIGN=ROOT/'tests/keys/development-rsa.pem'
FED=hashlib.sha256(b'Campaign008 native circuit selected federation').digest()
SCOPE=hashlib.sha256(b'Campaign008 relay enrollment').digest()
ERR=2**64-1

def wait(check,seconds=600,label='native condition'):
 end=time.monotonic()+seconds;last=None
 while time.monotonic()<end:
  result=check()
  if result:return result
  time.sleep(.1)
 raise TimeoutError(label)

def async_call(c,target,op,h=0,a=0,b=0,cword=0,d=0,e=0,data=b'',version=1,allow=()):
 token=struct.unpack('<Q',c.request(175,struct.pack('<Q8Q',target,op,h,a,b,cword,d,e,version)+data))[0]
 if token==ERR:raise ValueError(f'async admission denied target{target} operation{op}')
 trace=getattr(c,'journey_trace',None)
 if trace:trace.write_text(json.dumps({'scope':'host management adapter request only; no Messenger protocol or key state','target':target,'operation':op,'token':token,'pending':True})+'\n')
 def collect():
  raw=c.request(176,struct.pack('<Q',token))
  if len(raw)==8:return None
  if len(raw)<64:raise ValueError('short native completion')
  f=struct.unpack_from('<8Q',raw)
  if f[0] and f[0] not in allow:raise ValueError(f'native operation{op} status{f[0]} fields{f}')
  return f,raw[64:]
 try:
  answer=wait(collect,900,f'native operation{op} completion')
  if trace:trace.write_text(json.dumps({'target':target,'operation':op,'token':token,'pending':False,'response_fields':list(answer[0])})+'\n')
  return answer
 except BaseException:
  with contextlib.suppress(Exception):c.request(177,struct.pack('<Q',token))
  raise

def role(g,number,op,**kwargs):return async_call(g.client,messenger.endpoint(g.client,number,op),op,**kwargs)
def net(g,op,**kwargs):return async_call(g.client,g.network,op,version=2,**kwargs)
def port():
 s=socket.socket();s.bind(('127.0.0.1',0));p=s.getsockname()[1];s.close();return p

class AttachedProcess:
 def __init__(self,pid):self.pid=pid
 def poll(self):
  try:
   state=Path(f'/proc/{self.pid}/stat').read_text().split(') ',1)[1][0]
   return 0 if state=='Z' else None
  except FileNotFoundError:return 0
 def wait(self,timeout):
  try:return wait(lambda: True if self.poll() is not None else None,timeout,'attached adapter exit')
  except TimeoutError:raise subprocess.TimeoutExpired(str(self.pid),timeout)

class Guest:
 def __init__(self,name,backend,out,image,*,graphical=False,vault=None,store=None):
  self.name,self.backend,self.out,self.image=name,backend,out,image
  self.graphical,self.vault,self.store=graphical,vault,store;self.client=self.process=self.log=None;self.device=None
  self.path=out/(name+'.sock');self.graphics=out/(name+'.qmp')
 def start(self):
  backing_bytes=max((path.stat().st_size for path in (self.vault,self.store) if path),default=0)
  soft,hard=resource.getrlimit(resource.RLIMIT_FSIZE)
  if soft!=resource.RLIM_INFINITY and soft<backing_bytes:
   if hard!=resource.RLIM_INFINITY and hard<backing_bytes:raise RuntimeError('host file-size limit is below explicitly selected backing')
   resource.setrlimit(resource.RLIMIT_FSIZE,(backing_bytes,hard))
  self.log=(self.out/(self.name+'.log')).open('ab')
  command=[str(ROOT/'lt'),'run','--backend',self.backend,'--image',str(self.image),'--socket',str(self.path),'--network-mux']
  if self.graphical:command+=['--graphics',str(self.graphics)]
  if self.vault:command+=['--vault',str(self.vault)]
  if self.store:command+=['--server-store',str(self.store)]
  self.process=subprocess.Popen(command,cwd=ROOT,stdout=self.log,stderr=self.log,start_new_session=True)
  wait(lambda:self.path.exists() or (self.process.poll() is not None and (_ for _ in ()).throw(RuntimeError('guest startup exited'))),120,self.name+' startup')
  self.client=live.Client(self.path,timeout=900);self.client.journey_trace=self.out/(self.name+'.management-request.json');self.client.request(1)
  self.network=next(row[0] for row in identity.instances(self.client) if row[0]&255==6)
  if self.graphical:self.device=DeviceInput(self.backend,self.graphics,timeout=120)
  return self
 def attach(self,previous):
  command=subprocess.check_output(['ps','-eo','pid,args'],text=True)
  found=[int(row.split(None,1)[0]) for row in command.splitlines() if 'python3 ' in row and 'lt run --backend '+self.backend in row and '--socket '+str(self.path)+' ' in row]
  assert len(found)==1,(self.name,found)
  self.process=AttachedProcess(found[0]);self.client=live.Client(self.path,timeout=900);self.client.journey_trace=self.out/(self.name+'.management-request.json');self.client.request(1)
  self.network=next(row[0] for row in identity.instances(self.client) if row[0]&255==6)
  if self.graphical:self.device=DeviceInput(self.backend,self.graphics,timeout=120)
  return self
 def stop(self):
  if self.device:self.device.close();self.device=None
  if self.client:
   with contextlib.suppress(Exception):self.client.request(70)
   self.client.close();self.client=None
  if self.process and self.process.poll() is None:
   try:self.process.wait(timeout=10)
   except subprocess.TimeoutExpired:os.killpg(self.process.pid,signal.SIGTERM);self.process.wait(timeout=20)
  if self.log:self.log.close();self.log=None
  self.path.unlink(missing_ok=True);Path(str(self.path)+'.client.lock').unlink(missing_ok=True)
  self.graphics.unlink(missing_ok=True)

def package(out,module,entry,name,rights):
 binary=live_build.app(module,entry,'journey-'+name,2)
 raw,_=releases.make(binary,'journey-'+name,'1.0.0',rights,SIGN,profile=2,license='NOASSERTION')
 path=out/(name+'.ltrel');path.write_bytes(raw)
 return path,releases.inspect(raw)

def install(g,packages,name,rights):
 owner,sid=messenger.install(g.client,packages[name][0],PUB,rights)
 return owner,sid

def public_node(g,packages,kind):
 g.identity_package=packages['identity'][0]
 g.identity_service=identity.start(g.client,g.identity_package,PUB)['service']
 _,public=net(g,20)
 f,_=identity.invoke(g.client,400,a=3,data=FED+SCOPE)
 b=bytearray(256);struct.pack_into('<8Q',b,0,identity.NODE_MAGIC,2,kind,1,1,8388608,65536,1)
 b[64:128]=public;b[128:160]=hashlib.sha256(('declared independent family '+g.name).encode()).digest()
 endpoint=f'127.0.0.1:{port()}'.encode();struct.pack_into('<3Q',b,160,1,0,len(endpoint));b[184:184+len(endpoint)]=endpoint
 launcher=messenger.launcher(g.client)
 permit,_=identity.invoke(g.client,405,h=f[1],a=launcher,b=2,c=256,data=hashlib.sha256(b).digest())
 _,cert=identity.invoke(g.client,402,h=permit[1],data=b)
 _,pin=net(g,21,data=cert)
 g.certificate,g.pin,g.endpoint=cert,pin,endpoint.decode()
 g.node_key=f[1]
 receipt,receipt_public=identity.invoke(g.client,400,a=4,data=FED+SCOPE)
 g.receipt_key,g.receipt_public,g.receipt_key_generation=receipt[1],receipt_public[96:128],receipt[3]
 credential=hashlib.sha256(('disclosed protected operator unlock fixture '+g.name).encode()).digest()
 _,sealed=identity.invoke(g.client,408,a=g.node_key,b=g.receipt_key,data=credential)
 assert len(sealed)==192 and any(sealed)
 g.client.request(178,struct.pack('<2Q',g.network,1));net(g,43,data=credential+sealed)
 g.identity_seed_retained=True
 (g.out/(g.name+'.certificate')).write_bytes(cert)
 configuration=dict(name=g.name,backend=g.backend,endpoint=g.endpoint,pin=pin.hex(),certificate_sha256=hashlib.sha256(cert).hexdigest(),receipt_public=g.receipt_public.hex(),operator_schema=3,identity_seeds_sealed=True,private_key_origin='independently generated inside this guest; only native Identity unwraps its protected retention')
 (g.out/(g.name+'.public-configuration.json')).write_text(json.dumps(configuration,indent=2)+'\n')
 return configuration

def restore_operator(g,previous):
 expected=(previous/(g.name+'.certificate')).read_bytes()
 g.identity_package=getattr(g,'identity_package',g.out/'identity.ltrel')
 try:g.identity_service=identity.endpoint(g.client,400)
 except ValueError:g.identity_service=identity.start(g.client,g.identity_package,PUB)['service']
 credential=hashlib.sha256(('disclosed protected operator unlock fixture '+g.name).encode()).digest()
 g.client.request(178,struct.pack('<2Q',g.network,1));_,sealed=net(g,44,data=credential)
 _,restored=net(g,25,h=4)
 assert restored[:480]==expected and len(restored)==512
 g.certificate,g.pin=expected,restored[480:]
 if len(sealed)!=192 or not any(sealed):raise AssertionError('operator backing has no explicitly authorized sealed Identity seeds; full receipt journey cannot resume it')
 handles,_=identity.invoke(g.client,408,h=1,data=credential+expected[112:144]+sealed)
 g.node_key,g.receipt_key=handles[1:3]
 receipt,public=identity.invoke(g.client,401,h=g.receipt_key)
 g.receipt_public,g.receipt_key_generation=public[96:128],receipt[3]
 g.identity_seed_retained=True
 body=expected[160:416];n=struct.unpack_from('<Q',body,176)[0];g.endpoint=body[184:184+n].decode()
 (g.out/(g.name+'.certificate')).write_bytes(expected)
 configuration=dict(name=g.name,backend=g.backend,endpoint=g.endpoint,pin=g.pin.hex(),certificate_sha256=hashlib.sha256(expected).hexdigest(),receipt_public=g.receipt_public.hex(),operator_schema=3,identity_seeds_sealed=True,private_key_origin='previous independently generated native guest keys; native protected operator and Identity recovery only',prior_campaign=str(previous))
 (g.out/(g.name+'.public-configuration.json')).write_text(json.dumps(configuration,indent=2)+'\n')
 return configuration

def enroll(g,index,cert):
 prior,material=net(g,25,h=index,allow=(3,))
 if prior[0]==0 and prior[2]==1 and material[:480]==cert and material[480:]==hashlib.sha256(cert).digest():return material[480:]
 _,body=net(g,22,h=index,data=cert);pin=body[480:512]
 net(g,23,h=index,data=pin)
 return pin

def inspect(g):
 raw=g.client.request(150,struct.pack('<Q8Q',g.ui,782,0,0,0,0,0,0,1))
 assert len(raw)==96
 return struct.unpack_from('<8Q',raw),raw[64:]

def wait_ui(g,predicate,label):
 last=[None]
 def check():
  state,fp=inspect(g)
  if state!=last[0]:print(g.name,'UI',state,flush=True);last[0]=state
  return (state,fp) if predicate(state) else None
 return wait(check,900,g.name+' '+label)

def screenshot(g,name):
 frame=g.device.frame();(g.out/(g.name+'-'+name+'.ppm')).write_bytes(frame.ppm());return frame.digest

def setup_personal(g,packages,mailpin):
 g.owner,sid=install(g,packages,'owner',0);g.ui,uid=install(g,packages,'ui',packages['ui'][1]['rights']);g.delivery,did=install(g,packages,'delivery',1024)
 launcher=messenger.launcher(g.client)
 for op in (420,421,422,429,431,432,433,434):messenger.bind(g.client,2,g.owner,launcher,op,sid)
 for op in range(420,436):messenger.bind(g.client,2,g.owner,g.ui,op,sid,uid)
 for op in (427,428,434):messenger.bind(g.client,2,g.owner,g.delivery,op,sid,did)
 for op in range(460,464):messenger.bind(g.client,4,g.delivery,g.ui,op,did,uid)
 messenger.bind(g.client,4,g.delivery,launcher,464,did)
 g.client.request(150,struct.pack('<Q8Q',g.ui,781,0,0,0,0,0,0,1)+FED)
 g.device.chord(56,15);time.sleep(.3)
 g.device.press(60);wait_ui(g,lambda f:f[4]==41,'graphical identity creation')
 role(g,2,434,a=13,data=mailpin)
 return sid

def unlock_ui(g,key,mode):
 g.client.request(174,struct.pack('<2Q',g.owner,1))
 g.device.press(67,delay=.15);g.device.press(59+mode,delay=.15);g.device.press(62,delay=.15)
 g.device.textASCII(key.hex(),delay=.08);time.sleep(.5);g.device.press(28,delay=.15)
 wait_ui(g,lambda f:f[4] in (34,64),'explicit graphical domain2 unlock')
 f,_=role(g,2,420);assert f[1]==1 and f[5]==1,('owner retention state',f)
 raw=g.client.request(150,struct.pack('<Q8Q',g.ui,783,0,0,0,0,0,0,1))
 status=struct.unpack_from('<8Q',raw);assert status[5]==0 and status[6]==0,('graphical owner completion',status)


def approve_ui(g,invitation):
 raw=g.client.request(150,struct.pack('<Q8Q',g.ui,780,0,0,0,0,0,0,1)+invitation)
 assert struct.unpack_from('<Q',raw)[0]==0
 state,fingerprint=wait_ui(g,lambda f:f[2]==1,'candidate fingerprint')
 assert any(fingerprint) and state[5]==0
 screenshot(g,'contact-candidate');g.device.click(500,96)
 wait_ui(g,lambda f:f[5]==1 and f[4]==32,'pointer contact approval')
 return fingerprint.hex()

def mailbox_start(g,packages):
 g.identity_package=packages['identity'][0]
 try:current_identity=identity.endpoint(g.client,400)
 except ValueError:current_identity=None
 if current_identity is None or not hasattr(g,'node_key'):restore_operator(g,g.out)
 g.mailbox,sid=install(g,packages,'mailbox',2048);launcher=messenger.launcher(g.client)
 for op in (440,441):messenger.bind(g.client,3,g.mailbox,launcher,op,sid)
 messenger.bind(g.client,3,g.mailbox,g.network,441,sid)
 server_store.call(g.client,230)
 namespace=hashlib.sha256(b'Campaign008 intentional ciphertext mailbox backing').digest()
 grant=server_store.call(g.client,231,g.mailbox,2,1048576,namespace)[0][1]
 role(g,3,440,h=0,a=grant)
 identity_sid=bytes.fromhex(releases.inspect(g.identity_package.read_bytes())['release_id'])
 identity.bind(g.client,g.identity_service,g.mailbox,identity_sid,sid,409)
 declaration=struct.pack('<2Q',0x314b52544c,1)+g.receipt_public+g.pin+struct.pack('<2Q',g.receipt_key_generation,1)+bytes(32)
 permit=identity.invoke(g.client,405,h=g.node_key,a=launcher,b=3,c=128,data=hashlib.sha256(declaration).digest())[0][1]
 _,certificate=identity.invoke(g.client,402,h=permit,data=declaration)
 assert len(certificate)==352
 authority=identity.invoke(g.client,409,a=g.receipt_key,b=g.mailbox,c=65536,data=messenger.MAILBOX_TERMS_HASH+g.pin)[0][1]
 f,_=role(g,3,440,h=4,a=authority,data=certificate+messenger.MAILBOX_TERMS_HASH+g.pin,allow=(6,))
 if f[0]==6:
  def committed():
   f,_=role(g,3,441,h=4,allow=(6,))
   return f if f[0]==0 else None
  wait(committed,240,'durable native receipt profile publication')
 _,profile=role(g,3,441,h=10)
 assert profile==certificate+messenger.MAILBOX_TERMS_HASH+g.pin
 g.receipt_certificate=certificate
 (g.out/(g.name+'.receipt-profile')).write_bytes(profile)
 (g.out/(g.name+'.receipt-configuration.json')).write_text(json.dumps(dict(schema=1,service=g.mailbox,profile_sha256=hashlib.sha256(profile).hexdigest(),node_certificate_sha256=g.pin.hex(),receipt_public=g.receipt_public.hex(),terms_sha256=messenger.MAILBOX_TERMS_HASH.hex(),finite_authorizations=65536,identity_seed_retained=True,private_key_exported=False),indent=2)+'\n')

def enroll_mailbox(g,public):
 role(g,3,440,h=1,a=8388608,b=65536,data=public,allow=(6,))
 def done():
  f,_=role(g,3,441,h=4,a=0,allow=(6,))
  return f if f[0]==0 else None
 wait(done,240,'durable native mailbox recipient enrollment')

def listen_operators(relays,mailbox):
 for g in [*relays,mailbox]:net(g,30,h=0)

def reset_operators(relays,mailbox):
 for g in [*relays,mailbox]:
  with contextlib.suppress(ValueError):net(g,42)
  net(g,35)
 listen_operators(relays,mailbox)

def route(g,certs,mailbox):
 assert mailbox.pin==hashlib.sha256(mailbox.certificate).digest(),('native public mailbox pin',mailbox.pin.hex(),hashlib.sha256(mailbox.certificate).hexdigest())
 for i,cert in enumerate(certs):
  print(g.name,'native route pin',i,flush=True);enroll(g,i,cert)
 print(g.name,'native mailbox pin',flush=True);enroll(g,3,mailbox.certificate)
 def configured():
  f,_=role(g,4,464,h=g.owner,allow=(4,))
  return f if f[0]==0 else None
 print(g.name,'native delivery configure',flush=True);wait(configured,120,'idle native delivery configure')
 began=time.monotonic();print(g.name,'native circuit start',flush=True);net(g,31)
 last=[None]
 def circuit():
  f,_=net(g,32)
  if f!=last[0]:print(g.name,'native circuit state',f,flush=True);last[0]=f
  if f[3]:raise AssertionError((g.name,'native circuit failure',f))
  return f if f[2]==3 else None
 wait(circuit,900,'native three-hop circuit')
 print(g.name,'native terminal start',flush=True);net(g,38,h=3,a=1,b=g.delivery,cword=8388608,d=65536)
 last=[None]
 def terminal():
  f,pin=net(g,41)
  if f!=last[0]:print(g.name,'native terminal state',f,'pin',pin.hex(),'expected',mailbox.pin.hex(),flush=True);last[0]=f
  if f[3]:raise AssertionError((g.name,'native terminal failure',f))
  if f[2]==3:
   assert pin==mailbox.pin,('authenticated selected mailbox pin',pin.hex(),mailbox.pin.hex());return f
  return None
 wait(terminal,240,'authenticated protected terminal stream')
 return time.monotonic()-began

def send_ui(g,text):
 g.device.textASCII(text,delay=.025)
 wait_ui(g,lambda f:f[3]==len(text),'keyboard composition')
 g.device.press(28)
 state,_=wait_ui(g,lambda f:f[6]!=0,'native queued message')
 message=state[6];began=time.monotonic()
 for attempt in range(4):
  outcome,_=wait_ui(g,lambda f:f[4] in (19,27),'mailbox acceptance or bounded admission result')
  if outcome[4]==19:break
  if attempt==3:raise RuntimeError('native broker still reports quota after three graphical exact-ciphertext retries')
  g.device.press(65,delay=.08)
  wait_ui(g,lambda f:f[4] in (18,28,19),'graphical exact-ciphertext retry admitted')
 screenshot(g,'mailbox-accepted')
 return message,time.monotonic()-began

def import_useful_project(g):
 records=[];entries=[];files={}
 for name in ('Guest/Messenger.lean','Guest/MessengerDelivery.lean'):
  payload=(ROOT/name).read_bytes();assert 0<len(payload)<=65536
  identifier=projects.canonical_node(10,payload)
  records.append(dict(kind=10,id=identifier,payload=payload));entries.append((name,10,identifier));files[name]=payload
 assert sum(map(len,files.values()))>65536
 payload=projects.manifest(entries);head=projects.canonical_node(11,payload)
 records.insert(0,dict(kind=11,id=head,payload=payload))
 root=projects.import_records(g.client,[dict(name='messenger-review-source',head=head)],records)[0]['cap']
 compositor=next(row[0] for row in identity.instances(g.client) if row[0]&255==4)
 g.client.objects(27,root,compositor,31)
 return root,head,files

def transfer_state(g):
 raw=g.client.request(150,struct.pack('<Q8Q',g.ui,784,0,0,0,0,0,0,1))
 assert len(raw)==64
 return struct.unpack('<8Q',raw)

def continue_stored(previous,out,recipient_recovery=False):
 previous=previous.resolve();out=out.resolve();out.mkdir(parents=True,exist_ok=False)
 packages={name:(previous/(name+'.ltrel'),releases.inspect((previous/(name+'.ltrel')).read_bytes())) for name in ('owner','ui','delivery','identity','mailbox')}
 report=json.loads((previous/'progress.json').read_text());report['continuation_directory']=str(previous);report['result']='running';checks=report['checks'];guests=[];began=time.monotonic()
 def record(label,**more):
  checks.append({'check':label,'result':'pass',**more});print('PASS',label,flush=True);(out/'progress.json').write_text(json.dumps(report,indent=2)+'\n')
 def actor(name,graphical=False,attach=True):
  g=Guest(name,'qemu',previous,previous/'guest.bin',graphical=graphical,vault=previous/(name+'.img') if graphical else None,store=None if graphical else previous/(name+'.img'))
  g.out=out
  if attach:g.attach(previous)
  guests.append(g);return g
 def personalize_existing(g):
  g.owner=messenger.endpoint(g.client,2,420);g.delivery=messenger.endpoint(g.client,4,464)
  g.ui=next(row[0] for row in identity.instances(g.client) if row[2]==packages['ui'][1]['rights'])
 def lock_ui(g):
  g.device.press(66,delay=.1)
  wait(lambda:role(g,2,420)[0][1]==0,120,'actual owner locked')
  wait_ui(g,lambda f:f[4]==23,'actual graphical lock')
  wait(lambda:struct.unpack_from('<8Q',g.client.request(150,struct.pack('<Q8Q',g.ui,783,0,0,0,0,0,0,1)))[6]==0,120,'lock broker collection')
  f,_=role(g,2,420);assert f[1]==0
  denied,_=role(g,2,429,h=1,allow=(5,));assert denied[0]==5
 try:
  mailbox=actor('mailbox');relays=[actor('relay'+str(i)) for i in (1,2,3)]
  for g in [*relays,mailbox]:
   certificate=(previous/(g.name+'.certificate')).read_bytes();_,material=net(g,25,h=4)
   assert material[:480]==certificate and material[480:]==hashlib.sha256(certificate).digest()
   g.certificate,g.pin=certificate,material[480:]
  certs=[g.certificate for g in relays]
  alice=actor('alice',True);personalize_existing(alice)
  state,_=inspect(alice);assert state[6]==1
  if not recipient_recovery:
   assert state[4]==19;screenshot(alice,'actual-stored-after-f7')
  inventory,_=role(mailbox,3,440,h=2,a=0)
  assert inventory[2]==1 and inventory[3]==251
  committed=json.loads((previous/'alice-outbox-before-retry.json').read_text())
  record('actual graphical F7 retransmits committed251byte text through three relays and authenticated terminal into native durable mailbox',native_ui=list(state),native_mailbox_inventory=list(inventory),committed_ciphertext_sha256=committed['ciphertext_sha256'],initial_native_admission_error=4,scope='test-only earlier text owner broker profile; final product journey still required')
  if not recipient_recovery:lock_ui(alice)
  else:
   f,_=role(alice,2,420);assert f[1]==0
   report['opaque_adapter_correction']=json.loads((ROOT/'build/messenger-text-checkpoint-connected/host-backing-limit-correction.json').read_text())
  net(alice,35);reset_operators(relays,mailbox)
  bk=hashlib.sha256(b'Campaign008 disclosed Bob vault-unlock fixture').digest();ak=hashlib.sha256(b'Campaign008 disclosed Alice vault-unlock fixture').digest()
  bob=actor('bob',True,recipient_recovery)
  if recipient_recovery:
   personalize_existing(bob);lock_ui(bob);net(bob,35);reset_operators(relays,mailbox);unlock_ui(bob,bk,1)
  else:bob.start();setup_personal_after_recovery(bob,packages,mailbox.pin,bk)
  bob.device.press(1,delay=.1);wait_ui(bob,lambda f:f[2]==0 and f[5]==1,'recovered approved contact selection')
  setup=route(bob,certs,mailbox);wait_ui(bob,lambda f:f[4]==20,'actual routed authenticated message receive')
  f,text=role(bob,2,429,h=1);assert text==b'native offline message through three relays'
  screenshot(bob,'actual-received-after-restart')
  record('separate recipient guest restarts and explicitly recovers graphically before routed fetch decrypt and committed display once',route_setup_seconds=setup,inbox_serial=f[1],plaintext_bytes=len(text))
  message,seconds=send_ui(bob,'native routed reply after recovery')
  record('recipient composes native graphical reply and obtains durable routed mailbox acceptance',message=message,acceptance_seconds=seconds)
  lock_ui(bob);net(bob,35);reset_operators(relays,mailbox)
  unlock_ui(alice,ak,1);alice.device.press(1,delay=.1);wait_ui(alice,lambda f:f[2]==0 and f[5]==1,'Alice recovered approved contact')
  setup=route(alice,certs,mailbox);wait_ui(alice,lambda f:f[4]==20,'actual routed reply receive')
  f,text=role(alice,2,429,h=1);assert text==b'native routed reply after recovery'
  screenshot(alice,'actual-reply')
  record('original sender decrypts routed reply after actual graphical lock and authorized recovery; locked reads denied5',route_setup_seconds=setup,inbox_serial=f[1],plaintext_bytes=len(text))
  report.update(result='passed-connected-text-checkpoint',continuation_elapsed_seconds=time.monotonic()-began,incomplete_acceptance=['final product53KiB owner/broker journey','mailbox restart in this checkpoint','routed useful attachment and existing Forge consumer in this checkpoint','finite delegated signed receipts and prekey claim lifecycle','full connected failure matrix'])
  (out/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
 except BaseException as error:
  report.update(result='failed-preserved-actors',error=repr(error),traceback=traceback.format_exc(),continuation_elapsed_seconds=time.monotonic()-began)
  (out/'failure.json').write_text(json.dumps(report,indent=2)+'\n');raise
 finally:
  # Host adapter detaches only. Native actors deliberately remain alive.
  for g in guests:
   if g.device:g.device.close()
   if g.client:g.client.close()

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',required=True,type=Path);p.add_argument('--output',required=True,type=Path);p.add_argument('--keep',action='store_true');p.add_argument('--restart-mailbox',action='store_true');p.add_argument('--resume-operators',type=Path,help='explicit earlier campaign directory with native-encrypted operator backings and public certificates');p.add_argument('--attach-running',type=Path,help='reattach public portals of this harness after an adapter interruption; no native state restoration');p.add_argument('--resume-alice-vault',type=Path,help='explicit already authorized native Messenger backing; actual normal graphical recovery required');p.add_argument('--checkpoint-packages',type=Path,help='explicit prior frozen owner/UI packages with test-only outer-v2 text broker');p.add_argument('--all-qemu',action='store_true');p.add_argument('--resume-personals',type=Path,help='explicit native-encrypted personal backings; graphical recover required');p.add_argument('--continue-stored',type=Path,help='continue an actually stored first text through preserved native actors');p.add_argument('--resume-recipient',action='store_true',help='resume preserved recipient after disclosed host block adapter limit correction');a=p.parse_args()
 if a.continue_stored:return continue_stored(a.continue_stored,a.output,a.resume_recipient)
 out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);image=out/'guest.bin';image.write_bytes(a.image.read_bytes());guests=[];checks=[];observations=[];stage='package build';began=time.monotonic()
 report=dict(schema=1,image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),checks=checks,nodes=observations,host_authority='public-material/bootstrap/raw-byte/input adapters only; no session or node private keys',result='running',operator_independence=False,limits='All machines run on one host under one test operator; family declarations are not Sybil resistance. Classical profile, no Tor interoperability or global traffic-correlation guarantee.')
 def record(name,**data):checks.append(dict(check=name,result='pass',**data));print('PASS',name,flush=True);(out/'progress.json').write_text(json.dumps(report,indent=2)+'\n')
 try:
  if a.attach_running:
   previous=a.attach_running.resolve()
   assert (previous/'guest.bin').read_bytes()==image.read_bytes()
   packages={name:(previous/(name+'.ltrel'),releases.inspect((previous/(name+'.ltrel')).read_bytes())) for name in ('owner','ui','delivery','identity','mailbox')}
   report['packages']={n:i for n,(_,i) in packages.items()}
   report['adapter_recovery']={'previous_directory':str(previous),'reason':'UI changed its successful unlock notice from34 to64; native owner retained state already committed; public portals reattached without guest state edits'}
   def attached(name,backend,graphical=False):
    g=Guest(name,backend,previous,image,graphical=graphical,vault=previous/(name+'.img') if graphical else None,store=None if graphical else previous/(name+'.img'))
    g.out=out;g.attach(previous);guests.append(g);return g
   mailbox=attached('mailbox','qemu');relays=[attached('relay'+str(i),backend) for i,backend in enumerate(('qemu','x86_64','qemu'),1)]
   for g in [*relays,mailbox]:
    certificate=(previous/(g.name+'.certificate')).read_bytes();_,material=net(g,25,h=4)
    assert material[:480]==certificate and len(material)==512
    g.certificate,g.pin=certificate,material[480:];(out/(g.name+'.certificate')).write_bytes(certificate)
    observations.append({'name':g.name,'backend':g.backend,'certificate_sha256':hashlib.sha256(certificate).hexdigest(),'pin':g.pin.hex(),'private_key_origin':'already running independently generated guest credentials, public portal reattachment'})
   certs=[g.certificate for g in relays]
   operator_keys={g.name:hashlib.sha256(('disclosed protected operator unlock fixture '+g.name).encode()).digest() for g in [*relays,mailbox]}
   alice=attached('alice','qemu',True);bob=attached('bob','qemu',True)
   alice.owner=messenger.endpoint(alice.client,2,420);alice.delivery=messenger.endpoint(alice.client,4,464)
   alice.ui=next(row[0] for row in identity.instances(alice.client) if row[2]==packages['ui'][1]['rights'])
   f,_=role(alice,2,420);assert f[1]==1 and f[5]==1,('native Alice retention',f)
   state,_=inspect(alice);assert state[4]==64
   record('public adapter recovery preserves already committed graphical Alice identity and domain2 state',actual_native_owner_state=list(f),actual_ui_state=list(state))
   ak=hashlib.sha256(b'Campaign008 disclosed Alice vault-unlock fixture').digest();bk=hashlib.sha256(b'Campaign008 disclosed Bob vault-unlock fixture').digest()
   if a.resume_personals:setup_personal_after_recovery(bob,packages,mailbox.pin,bk)
   else:setup_personal(bob,packages,mailbox.pin);unlock_ui(bob,bk,0)
  else:
   if a.checkpoint_packages:
    packages={}
    for name in ('owner','ui','identity','mailbox'):
     path=out/(name+'.ltrel');path.write_bytes((a.checkpoint_packages/(name+'.ltrel')).read_bytes());packages[name]=(path,releases.inspect(path.read_bytes()))
    raw,_=releases.make(ROOT/'build/live/apps/messenger-text-checkpoint.bin','journey-text-checkpoint','1.0.0',1024,SIGN,profile=2,license='NOASSERTION')
    path=out/'delivery.ltrel';path.write_bytes(raw);packages['delivery']=(path,releases.inspect(raw))
    report['checkpoint_compatibility']='Explicit test-only earlier text-owner API; outerNetworkv2 fix; product broker retains newer owner settlement20 requirement.'
   else:
    packages={name:package(out,module,entry,name,rights) for name,module,entry,rights in [('owner','Guest.MessengerSession','Guest.MessengerSession.main',0),('ui','Guest.Messenger','Guest.Messenger.main',799),('delivery','Guest.MessengerDelivery','Guest.MessengerDelivery.main',1024),('identity','Guest.Identity','Guest.Identity.main',0),('mailbox','Guest.Mailbox','Guest.Mailbox.main',2048)]}
   report['packages']={n:i for n,(_,i) in packages.items()}
   resource.setrlimit(resource.RLIMIT_FSIZE,(resource.RLIM_INFINITY,resource.RLIM_INFINITY))
   for name in ['relay1','relay2','relay3','mailbox']:
    if a.resume_operators:subprocess.run(['cp','--reflink=auto','--sparse=always',str(a.resume_operators/(name+'.img')),str(out/(name+'.img'))],check=True)
    else:server_store.provision(out/(name+'.img'))
   for name in ['alice','bob']:
    if a.resume_personals:subprocess.run(['cp','--reflink=auto','--sparse=always',str(a.resume_personals/(name+'.img')),str(out/(name+'.img'))],check=True)
    elif name=='alice' and a.resume_alice_vault:subprocess.run(['cp','--reflink=auto','--sparse=always',str(a.resume_alice_vault),str(out/'alice.img')],check=True)
    else:
     with (out/(name+'.img')).open('xb') as f:f.truncate(5396000*512)
   stage='independent operator enrollment'
   mailbox=Guest('mailbox','qemu',out,image,store=out/'mailbox.img').start();guests.append(mailbox);observations.append(restore_operator(mailbox,a.resume_operators) if a.resume_operators else public_node(mailbox,packages,8));mailbox_start(mailbox,packages)
   relays=[]
   for i,backend in enumerate(['qemu','qemu' if a.all_qemu else 'x86_64','qemu'],1):
    g=Guest('relay'+str(i),backend,out,image,store=out/('relay'+str(i)+'.img')).start();guests.append(g);relays.append(g);observations.append(restore_operator(g,a.resume_operators) if a.resume_operators else public_node(g,packages,7))
   certs=[g.certificate for g in relays]
   allcerts=[*certs,mailbox.certificate]
   assert len({c[112:144] for c in allcerts})==4
   assert len({c[224:256] for c in allcerts})==4
   assert len({c[256:288] for c in allcerts})==4
   enroll(relays[0],0,certs[1]);enroll(relays[1],0,certs[2]);enroll(relays[2],0,mailbox.certificate)
   operator_keys={}
   for operator in [*relays,mailbox]:
    operator_keys[operator.name]=hashlib.sha256(('disclosed protected operator unlock fixture '+operator.name).encode()).digest()
    operator.client.request(178,struct.pack('<2Q',operator.network,1))
    if not a.resume_operators and not getattr(operator,'identity_seed_retained',False):net(operator,43,data=operator_keys[operator.name])
   record('three distinct native relay guests and mailbox generate independent credentials',mixed_backend='all QEMU checkpoint after recorded mixed-native terminal timeout' if a.all_qemu else 'middle relay is native x86-64 assembly; clients and other operators QEMU')
   stage='graphical personal identities and explicit retention'
   alice=Guest('alice','qemu',out,image,graphical=True,vault=out/'alice.img').start();guests.append(alice)
   bob=Guest('bob','qemu',out,image,graphical=True,vault=out/'bob.img').start();guests.append(bob)
   ak=hashlib.sha256(b'Campaign008 disclosed Alice vault-unlock fixture').digest();bk=hashlib.sha256(b'Campaign008 disclosed Bob vault-unlock fixture').digest()
   if a.resume_alice_vault or a.resume_personals:setup_personal_after_recovery(alice,packages,mailbox.pin,ak)
   else:setup_personal(alice,packages,mailbox.pin);unlock_ui(alice,ak,0)
   if a.resume_personals:setup_personal_after_recovery(bob,packages,mailbox.pin,bk)
   else:setup_personal(bob,packages,mailbox.pin);unlock_ui(bob,bk,0)
  _,ai=role(alice,2,434,a=12);_,bi=role(bob,2,434,a=12)
  assert len(ai)==320 and len(bi)==320 and ai[32:64]!=bi[32:64]
  record('both graphical F2 actions create distinct scoped messaging credentials; graphical consent unlocks domain2')
  stage='graphical contact approval and public mailbox enrollment'
  afp=approve_ui(alice,bi);bfp=approve_ui(bob,ai)
  _,authority=role(alice,2,434,a=10);enroll_mailbox(mailbox,authority)
  _,authority=role(bob,2,434,a=10);enroll_mailbox(mailbox,authority)
  record('real pointer approval of imported fingerprints and separate native deposit/fetch capability enrollment',alice_contact=afp,bob_contact=bfp)
  bob.stop();record('recipient guest is actually offline before sender circuit or deposit')
  stage='first connected graphical offline text'
  listen_operators(relays,mailbox);setup_seconds=route(alice,certs,mailbox)
  message,delivery_seconds=send_ui(alice,'native offline message through three relays')
  record('graphical sender commits text then traverses three distinct relays into durable mailbox',message=message,route_setup_seconds=setup_seconds,delivery_seconds=delivery_seconds)
  if a.restart_mailbox:
   stage='actual mailbox guest restart and protected operator recovery'
   net(alice,42);net(alice,35)
   for relay in relays:net(relay,35)
   mailbox.stop();mailbox.start()
   restore_operator(mailbox,out)
   mailbox_start(mailbox,packages)
   record('actual mailbox guest restart recovers durable ciphertext and independently protected same certified node credentials')
  stage='recipient guest restart and authorized graphical recovery'
  net(alice,42);net(alice,35);reset_operators(relays,mailbox)
  bob.start();setup_personal_after_recovery(bob,packages,mailbox.pin,bk)
  approve_ui(bob,ai)
  setup_seconds=route(bob,certs,mailbox)
  wait_ui(bob,lambda f:f[4]==20,'received/decrypted routed inbox')
  _,text=role(bob,2,429,h=1)
  assert text==b'native offline message through three relays'
  screenshot(bob,'received');record('recipient native guest restarts, explicitly recovers, fetches and decrypts mailbox text',route_setup_seconds=setup_seconds)
  message,reply_seconds=send_ui(bob,'native routed reply after recovery')
  net(bob,42);net(bob,35);reset_operators(relays,mailbox)
  route(alice,certs,mailbox)
  wait_ui(alice,lambda f:f[4]==20,'routed reply decrypt')
  _,reply=role(alice,2,429,h=1);assert reply==b'native routed reply after recovery'
  screenshot(alice,'reply');record('recipient composes graphical reply and sender decrypts it through the routed path',message=message,reply_acceptance_seconds=reply_seconds)
  report.update(result='passed-connected-text',elapsed_seconds=time.monotonic()-began,incomplete_acceptance=([*(['mailbox guest restart (flag not selected)'] if not a.restart_mailbox else []),'routed useful attachment transfer','failure matrix and old-backup import in this connected run','existing routed Forge/Library consumer']))
  (out/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
 except BaseException as error:
  report.update(result='failed',stage=stage,error=repr(error),traceback=traceback.format_exc(),elapsed_seconds=time.monotonic()-began)
  (out/'failure.json').write_text(json.dumps(report,indent=2)+'\n');raise
 finally:
  if not a.keep:
   for g in reversed(guests):
    with contextlib.suppress(Exception):g.stop()

def setup_personal_after_recovery(g,packages,mailpin,key):
 # Install exact packages and grants without creating a replacement identity.
 g.owner,sid=install(g,packages,'owner',0);g.ui,uid=install(g,packages,'ui',packages['ui'][1]['rights']);g.delivery,did=install(g,packages,'delivery',1024)
 launcher=messenger.launcher(g.client)
 for op in (420,421,422,429,431,432,433,434):messenger.bind(g.client,2,g.owner,launcher,op,sid)
 for op in range(420,436):messenger.bind(g.client,2,g.owner,g.ui,op,sid,uid)
 for op in (427,428,434):messenger.bind(g.client,2,g.owner,g.delivery,op,sid,did)
 for op in range(460,464):messenger.bind(g.client,4,g.delivery,g.ui,op,did,uid)
 messenger.bind(g.client,4,g.delivery,launcher,464,did)
 g.client.request(150,struct.pack('<Q8Q',g.ui,781,0,0,0,0,0,0,1)+FED)
 g.device.chord(56,15);time.sleep(.3);unlock_ui(g,key,1)

if __name__=='__main__':main()
