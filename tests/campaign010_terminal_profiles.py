"""Independent native terminals: scoped queued selection preserves a real result.

Public enrollment/configuration use operator interfaces. Only actual network RPC
replies are collected; no controller edits guest memory or supplies acceptance.
"""
import argparse,contextlib,hashlib,json,os,signal,socket,struct,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import live,live_build,identity,messenger,onion_route as route,releases
from graphical_devices import DeviceInput
from creator_journey import rendered_text

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--image',type=Path,required=True);p.add_argument('--identity',type=Path,required=True)
 p.add_argument('--output',type=Path,default=ROOT/'build/campaign010-terminal-profiles')
 p.add_argument('--backend',choices=('qemu','x86_64'),default='x86_64')
 a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
 image=bytearray(a.image.read_bytes());parts={}
 for pid,name in ((1,'launcher'),(4,'compositor'),(6,'network')):
  data=(ROOT/f'build/live/{name}.bin').read_bytes();start,bound=live_build.service_image_bounds(pid)
  if len(data)>bound:raise ValueError('service image exceeds declared bound')
  image[start:start+bound]=bytes(bound);image[start:start+len(data)]=data
  struct.pack_into('<Q',image,0x200000+pid*32,len(data));parts[name]=hashlib.sha256(data).hexdigest()
 frozen=a.output/'guest.bin';frozen.write_bytes(image)
 package=a.output/'mailbox.ltrel';raw,_=releases.make(ROOT/'build/live/apps/mailbox.bin','mailbox','1.0.0',2048,ROOT/'tests/keys/development-rsa.pem',profile=2);package.write_bytes(raw)
 clients=[];processes=[];logs=[];checks=[];observations=[];times={};started=time.monotonic();ui=None
 last_states=[]
 def boot(i):
  nonlocal ui
  base=a.output/f'node{i}';base.mkdir(exist_ok=True);path=base/'portal.sock';path.unlink(missing_ok=True)
  log=(base/'guest.log').open('wb');logs.append(log)
  backend=a.backend if i==0 else 'qemu'
  command=[ROOT/'lt','run','--image',frozen,'--backend',backend,'--socket',path,'--network-mux']
  if i==0:command+=['--graphics',base/'display.qmp']
  processes.append(subprocess.Popen(list(map(str,command)),cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,start_new_session=True))
  route.wait(path.exists,90);c=live.Client(path,timeout=600);clients.append(c);c.request(1)
  if i:identity.start(c,a.identity,ROOT/'tests/keys/development-rsa-public.pem')
  else:ui=DeviceInput(backend,base/'display.qmp')
 def credential(i):
  begin=time.monotonic();probe=socket.socket();probe.bind(('127.0.0.1',0));port=probe.getsockname()[1];probe.close()
  cert,pin=route.create(clients[i],f'127.0.0.1:{port}',f'Campaign010 independent terminal operator{i}',7 if i<=3 else 8)
  (a.output/f'node{i}.certificate').write_bytes(cert)
  observations.append(dict(node=i,role='relay' if i<=3 else 'mailbox',pin=pin.hex(),certificate_sha256=hashlib.sha256(cert).hexdigest(),credential_seconds=time.monotonic()-begin))
  print('native independent operator credential',i,flush=True);return cert
 try:
  for i in range(4):boot(i)
  certs=[credential(i)for i in range(1,4)]
  for slot,cert in enumerate(certs):route.enroll(clients[0],slot,cert)
  for i in (1,2):route.enroll(clients[i],0,certs[i])
  for c in clients[1:]:route.route(c,30)
  personal=clients[0];route.route(personal,31);begin=time.monotonic()
  def circuit_ready():
   nonlocal last_states
   states=[route.route(c,32)[0]for c in clients]
   if states!=last_states:print('actual circuit states',states,flush=True)
   last_states=states
   if any(row[3]for row in states):raise AssertionError(('actual circuit unavailable',states))
   return states[0][2]==3
  route.wait(circuit_ready,300);times['four_actor_cold_setup_seconds']=time.monotonic()-started;times['three_hop_circuit_seconds']=time.monotonic()-begin
  checks.append('actual three-hop circuit across independently keyed native relays')
  for i in (4,5):
   boot(i);cert=credential(i);certs.append(cert)
   route.enroll(personal,i-1,cert);route.enroll(clients[3],i-4,cert)
   service,sid=messenger.install(clients[i],package,ROOT/'tests/keys/development-rsa-public.pem',2048)
   launcher=messenger.launcher(clients[i]);network=next(r[0]for r in identity.instances(clients[i])if r[0]&255==6)
   for op in(440,441):messenger.bind(clients[i],3,service,launcher,op,sid)
   messenger.bind(clients[i],3,service,network,441,sid);route.route(clients[i],30)
  owner=messenger.launcher(personal);other=next(r[0] for r in identity.instances(personal) if r[0]&255==6)
  def profile(index):
   f,body=route.route(personal,49);return f,struct.unpack_from('<8Q',body,index*128),body[index*128+64:index*128+96]
  def ready(index):
   f,row,pin=profile(index)
   if row[4]==4:raise AssertionError(('terminal unavailable',index,row))
   return f[1]==index+1 and row[4]==3
  def native_select(index,label):
   ui.chord(56,49);time.sleep(.4)
   frame=ui.wait_frame()
   assert rendered_text(frame,12,8,23)=='Approved service routes','trusted route chooser did not open'
   for _ in range(index):ui.press(108);time.sleep(.1)
   time.sleep(.3);ui.press(28);time.sleep(.3)
   (a.output/(label+'.ppm')).write_bytes(ui.frame().ppm())
   ui.press(1);time.sleep(.2)
  begin=time.monotonic();route.route(personal,38,h=3,a=17,b=owner,c=1048576,d=128);route.wait(lambda:ready(0),180)
  times['first_terminal_seconds']=time.monotonic()-begin
  route.route(personal,38,h=4,a=18,b=other,c=1048576,d=128)
  route.wait(lambda:ready(1),180)
  checks.append('two separately approved native peer pins configured for distinct exact owner incarnations')
  # Return to the first owner and leave one genuine response uncollected.
  native_select(0,'native-select-first');route.wait(lambda:ready(0),180)
  route.route(personal,39,h=101,data=struct.pack('<8Q',441,4,0,0,0,0,0,1))
  route.wait(lambda:profile(0)[1][4]==3 and struct.unpack_from('<Q',route.route(personal,49)[1],112)[0]!=0,120)
  before=profile(0)[1];old_stream=before[3]
  begin=time.monotonic();native_select(1,'native-select-second');route.wait(lambda:ready(1),180)
  times['native_reselection_seconds']=time.monotonic()-begin
  f,answer=route.route(personal,40,h=101)
  assert f[0]==0 and len(answer)>=64 and struct.unpack_from('<Q',answer)[0]==0,(f,answer.hex())
  parked=profile(0)[1]
  assert parked[4]==5 and parked[6:8]==before[6:8],(before,parked)
  checks.append('physical Alt+N native review queues existing selected profile with exact peer pin and finite totals')
  checks.append('first owner collects its actual mailbox reply while another terminal is active; remaining totals unchanged')
  # A new request automatically queues its existing profile, without operator
  # stop/listen, reconfiguration, new byte allowance or a direct-mode fallback.
  route.route(personal,39,h=102,data=struct.pack('<8Q',441,4,0,0,0,0,0,1))
  def take():
   f,reply=route.route(personal,40,h=102,allow_error=True)
   if f[0]==6:return None
   assert f[0]==0 and struct.unpack_from('<Q',reply)[0]==0,(f,reply.hex())
   return reply
  begin=time.monotonic();route.wait(take,180);times['queued_rebind_and_rpc_seconds']=time.monotonic()-begin
  after=profile(0)[1]
  assert after[3]>old_stream and after[6]==before[6]-64 and after[7]==before[7]-1,(before,after)
  refused,_=route.route(personal,38,h=3,a=19,b=owner,c=1048576,d=128,allow_error=True)
  assert refused[0]==4 and profile(0)[1][6:8]==after[6:8]
  checks.append('queued owner rebinds a fresh never-reused stream and sends actual RPC; attempts/bytes charged once; duplicate configuration cannot renew totals')
  report=dict(schema=1,result='pass',source_image_sha256=hashlib.sha256(a.image.read_bytes()).hexdigest(),image_sha256=hashlib.sha256(image).hexdigest(),services=parts,backend_roles=[a.backend,*(['qemu']*5)],operators=observations,timings=times,total_seconds=time.monotonic()-started,checks=checks,limits='Native component selection and real mailbox RPC evidence. This does not establish Project Notes Feed/Messenger UI sharing or durable operation recovery.')
  (a.output/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
 except BaseException as error:
  (a.output/'failure.json').write_text(json.dumps(dict(schema=1,result='failure',error=repr(error),last_router_states=last_states,services=parts,checks=checks,timings=times,operators=observations),indent=2)+'\n');raise
 finally:
  if ui:ui.close()
  for c in clients:
   with contextlib.suppress(Exception):c.close()
  for process in processes:
   if process.poll() is None:os.killpg(process.pid,signal.SIGTERM)
  for process in processes:
   with contextlib.suppress(subprocess.TimeoutExpired):process.wait(timeout=10)
   if process.poll() is None:os.killpg(process.pid,signal.SIGKILL);process.wait()
  for log in logs:log.close()
if __name__=='__main__':main()
