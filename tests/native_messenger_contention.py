"""Native graphical Messenger and routed Forge while a third client stalls.

Services listen once and remain unattended. Native guests own all messaging,
operator and receipt keys. The optional fault adapter pauses opaque bytes only.
"""
import argparse,base64,contextlib,hashlib,json,os,struct,subprocess,sys,time,traceback
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import capsule,federation,identity,messenger,projects,releases,server_store
from messenger_journey import Guest,net,role,wait,wait_ui,inspect,screenshot,route,enroll,public_node,mailbox_start,listen_operators,enroll_mailbox,approve_ui,send_ui,FED,PUB,SIGN
from messenger_product_journey import prepare_personal,publication,ui_public
from messenger_routed_project import send_reference

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--image',type=Path,default=ROOT/'build/live/guest.bin');p.add_argument('--network',type=Path)
 p.add_argument('--ready',type=Path,default=ROOT/'build/campaign009-messenger-packages/ready.json')
 p.add_argument('--mailbox',type=Path,help='exact signed Mailbox package override for the shared-service fix')
 p.add_argument('--output',type=Path,default=ROOT/'build/native-messenger-contention')
 p.add_argument('--registry',type=Path,default=ROOT/'build/live/apps/native-registry.bin')
 p.add_argument('--public-graph',type=Path,default=ROOT/'build/signed-forge-journey-2/published-closure.json')
 p.add_argument('--publisher',type=Path,default=ROOT/'build/signed-forge-journey-2/publisher.pub')
 p.add_argument('--stop-on-exit',action='store_true')
 a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
 image=out/'guest.bin';data=bytearray(a.image.read_bytes())
 if a.network:
  assert struct.unpack_from('<Q',data,0x200000+6*32+24)[0]==425984,'Network splice requires current416KiB kernel image'
  part=a.network.read_bytes();assert len(part)<=425984
  data[0x340000:0x3a8000]=bytes(425984);data[0x340000:0x340000+len(part)]=part
  struct.pack_into('<Q',data,0x200000+6*32,len(part))
 image.write_bytes(data)
 wait(lambda:a.ready.exists(),1800,'current native signed product packages')
 manifest=json.loads(a.ready.read_text());packages={}
 for name in ('owner','ui','delivery','identity','mailbox'):
  source=a.mailbox if name=='mailbox'and a.mailbox else Path(manifest[name]);target=out/(name+'.ltrel');target.write_bytes(source.read_bytes())
  packages[name]=(target,releases.inspect(target.read_bytes()))
 archive=json.loads(a.public_graph.read_text());root=bytes.fromhex(archive['selected'][0]['head'])
 records=[dict(n,payload=base64.b64decode(n['payload'],validate=True)) for n in archive['nodes']]
 key,pub=out/'federation.pem',out/'federation.pub';capsule.generate_key(key,pub)
 fed=hashlib.sha256(releases.public_modulus(pub)).digest()
 registry_package=out/'registry.ltrel';raw,_=releases.make(a.registry,'contention-existing-registry','0.9.0',2175,SIGN,profile=2);registry_package.write_bytes(raw)
 actors=[];checks=[];began=time.monotonic();stage='native operators'
 report=dict(schema=1,result='running',image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),packages={n:i for n,(_,i) in packages.items()},checks=checks,limits='Onehost local integration, classical native crypto. Existing project/Registry RSA bootstrap only; no host messaging keys or protocol-state authority.')
 def record(label,**extra):
  checks.append(dict(check=label,result='pass',**extra));(out/'progress.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS',label,flush=True)
 def actor(name,personal=False,stall=False):
  backing=out/(name+'.img')
  if personal:messenger.main(['vault-init',str(backing)])
  elif not stall:server_store.provision(backing)
  g=Guest(name,'qemu',out,image,graphical=personal,vault=backing if personal else None,store=backing if not personal and not stall else None,network_fault_control=out/'stall-fault.sock' if stall else None).start();actors.append(g);return g
 def stall_rpc(g,serial,action,a=0,b=0,c=0,data=b''):
  net(g,39,h=serial,data=struct.pack('<8Q',441,action,a,b,c,0,0,1)+data)
  def collect():
   f,payload=net(g,40,h=serial,allow=(6,))
   if f[0]==6:return None
   assert f[0]==0
   return struct.unpack_from('<8Q',payload),payload[64:]
  return wait(collect,240,'thirdclient routed opaque upload')
 def fault(op,slot=0,epoch=None):
  import socket
  command=dict(op=op,slot=slot)
  if epoch is not None:command['epoch']=epoch
  s=socket.socket(socket.AF_UNIX);s.settimeout(10);s.connect(str(out/'stall-fault.sock'));s.sendall(json.dumps(command).encode()+b'\n');response=b''
  while b'\n' not in response:response+=s.recv(4096)
  s.close();value=json.loads(response);assert value['ok'],value;return value
 try:
  mailbox=actor('mailbox');public_node(mailbox,packages,8);mailbox_start(mailbox,packages)
  relays=[]
  for i in (1,2,3):
   g=actor('relay'+str(i));public_node(g,packages,7);relays.append(g)
  certs=[g.certificate for g in relays]
  for i in range(3):enroll(relays[i],0,certs[i+1] if i<2 else mailbox.certificate)
  # Exact existing Registry admission is configured while services keep running.
  alice=actor('alice',personal=True);bob=actor('bob',personal=True)
  registry_mailbox,_=messenger.install(mailbox.client,registry_package,PUB,2175)
  registry_bob,_=messenger.install(bob.client,registry_package,PUB,2175)
  for g,registry in ((mailbox,registry_mailbox),(bob,registry_bob)):federation.configure(g.client,registry,pub,'portable')
  actual=projects.import_records(mailbox.client,archive['selected'],records)[0]['cap']
  modulus=releases.public_modulus(a.publisher)
  publication_id=releases.publication(archive['project_id'],hashlib.sha256(modulus).hexdigest())
  federation.call(mailbox.client,registry_mailbox,3,data=publication_id+modulus)
  delegated=mailbox.client.objects(27,actual,registry_mailbox,25)[0][1]
  _,decision=federation.call(mailbox.client,registry_mailbox,2,h=delegated)
  assert len(decision)==512
  signed=federation.sign_once(mailbox.client,registry_mailbox,key,'portable')
  net(mailbox,46,h=registry_mailbox,data=fed)
  listen_operators(relays,mailbox) # The only operator listener command in this journey.
  record('native operators listen once; actual existing signed project admitted by native Registry',root=root.hex(),admission=signed)
  stage='native graphical identities and contacts'
  ai=prepare_personal(alice,packages,mailbox.pin,hashlib.sha256(b'Campaign009 Alice explicit vault credential').digest())
  bi=prepare_personal(bob,packages,mailbox.pin,hashlib.sha256(b'Campaign009 Bob explicit vault credential').digest())
  approve_ui(alice,bi);approve_ui(bob,ai)
  for g in (alice,bob):
   _,authority=role(g,2,434,a=10);enroll_mailbox(mailbox,authority)
  stage='three independent native admissions'
  for g in (alice,bob):
   route(g,certs,mailbox);wait(lambda g=g:publication(g),240,g.name+' native prekey publication')
  stalled=actor('stall',stall=True)
  for i,certificate in enumerate([*certs,mailbox.certificate]):enroll(stalled,i,certificate)
  net(stalled,31);wait(lambda:net(stalled,32)[0][2]==3,300,'third native3hop route')
  net(stalled,38,h=3,a=17,b=messenger.launcher(stalled.client),cword=8388608,d=65536)
  wait(lambda:net(stalled,41)[0][2]==3,240,'third authenticated native terminal')
  rid=hashlib.sha256(b'Campaign009 third stalled recipient').digest();deposit=hashlib.sha256(b'Campaign009 third public deposit fixture').digest();fetch=hashlib.sha256(b'Campaign009 third public fetch fixture').digest()
  enroll_mailbox(mailbox,rid+hashlib.sha256(deposit).digest()+hashlib.sha256(fetch).digest())
  payload=b'Bounded opaque native staging transfer.\n'*41
  f,_=stall_rpc(stalled,1,1,len(payload),1,data=rid+deposit+hashlib.sha256(b'Campaign009 third stable upload').digest()+hashlib.sha256(payload).digest());assert f[0]==0
  h=f[1];f,_=stall_rpc(stalled,2,2,h,0,data=rid+deposit+payload[:512]);assert f[0]==0
  epoch=fault('status')['channel']['epoch'];fault('pause',epoch=epoch)
  net(stalled,39,h=3,data=struct.pack('<8Q',441,2,h,512,0,0,0,1)+rid+deposit+payload[512:1024])
  stalled_at=time.monotonic()
  record('three clients concurrently admitted; third transfer stalls on exact opaque adapter epoch without operator reset',epoch=epoch,stage=h)
  stage='graphical Messenger text and reply during independent stall'
  message,seconds=send_ui(alice,'native shared service text while another client stalls')
  def received(g,text):
   f,_=role(g,2,420)
   for cursor in range(1,f[4]+1):
    read,body=role(g,2,429,h=cursor,allow=(3,))
    if read[0]==0 and body==text:return read
   return None
  wait(lambda:received(bob,b'native shared service text while another client stalls'),600,'native graphical recipient text')
  reply,reply_seconds=send_ui(bob,'native shared service reply while third client stalls')
  wait(lambda:received(alice,b'native shared service reply while third client stalls'),600,'native authenticated reply')
  record('actual graphical Messenger text and reply complete through same running mailbox while third client stalls',message=message,reply=reply,acceptance_seconds=seconds,reply_seconds=reply_seconds)
  stage='actual routed existing Forge request during independent stall'
  _,serial,seconds,_=send_reference(alice,'LT-PROJECT1 '+root.hex()+' '+fed.hex()+' 1')
  wait(lambda:received(bob,('LT-PROJECT1 '+root.hex()+' '+fed.hex()+' 1').encode()),600,'native encrypted project reference')
  roots_before=projects.roots(bob.client)
  # Select the actual displayed conversation reference and use its existing F1.
  wait_ui(bob,lambda f:f[4]==20,'received project reference displayed')
  bob.device.press(59,delay=.15)
  def verified():
   f,chosen=ui_public(bob,785)
   if f[1]!=6 or f[5]!=0:return None
   assert f[2]==2 and f[3]==0 and f[4]==signed['sequence'] and chosen==root+fed,(f,chosen)
   return f
  fields=wait(verified,900,'actual existing routed Forge verification')
  assert projects.roots(bob.client)==roots_before
  record('conversation F1 completes actual existing Forge signature and admission inspection while thirdclient stalled',displayed=list(fields),execution_approved=False,metadata_seconds=seconds)
  assert fault('status')['channel']['tx_paused']
  fault('resume',epoch=epoch);net(stalled,42);net(stalled,35);stalled.stop()
  for g in (alice,bob):assert net(g,41)[0][2]==3
  record('third client cancellation and disconnect preserve both unrelated authenticated terminal sessions',stalled_seconds=time.monotonic()-stalled_at)
  screenshot(alice,'shared-reply');screenshot(bob,'shared-forge')
  report.update(result='pass',elapsed_seconds=time.monotonic()-began)
  (out/'evidence.json').write_text(json.dumps(report,indent=2)+'\n')
 except BaseException as error:
  report.update(result='failed-preserved-actors',stage=stage,error=repr(error),traceback=traceback.format_exc(),elapsed_seconds=time.monotonic()-began)
  (out/'failure.json').write_text(json.dumps(report,indent=2)+'\n');raise
 finally:
  for g in actors:
   if a.stop_on_exit:g.stop()
   else:
    if g.device:g.device.close()
    if g.client:g.client.close()
    if g.log:g.log.close()
if __name__=='__main__':main()
