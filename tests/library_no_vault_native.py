"""Native metadata Add/Subscribe is ephemeral without an Objects-vault backing.

A separate metadata-only Registry serves an actually admitted consumer record.
The personal guest uses physical keyboard selection, query, Add and Subscribe;
no seed, payload import, acquisition approval or personal backing is selected.
"""
import argparse,contextlib,hashlib,json,os,signal,socket,struct,subprocess,sys,time,traceback
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import capsule,consumers,content,federation,library_peer,live,network,nodes,projects,releases
from creator_journey import Journey,require,rendered_text
from graphical_devices import DeviceInput
from library_journey import appcall,wait


class Guest:
 def __init__(self,name,out,image,graphics=False):
  self.base=out/name;self.base.mkdir();self.socket=self.base/'portal.sock';self.graphics=self.base/'display.qmp';self.ui=None
  self.log=(self.base/'guest.log').open('wb')
  self.command=list(map(str,[ROOT/'lt','run','--backend','qemu','--image',image,'--socket',self.socket,'--network-mux']+(['--graphics',self.graphics] if graphics else [])))
  self.proc=subprocess.Popen(self.command,cwd=ROOT,stdout=self.log,stderr=self.log,start_new_session=True)
  def ready():
   if self.proc.poll() is not None:raise RuntimeError(name+' exited before portal readiness')
   return self.socket.exists()
  wait(ready,90,name+' boot')
  if graphics:self.ui=DeviceInput('qemu',self.graphics)
  self.normal_shutdown=False
 @contextlib.contextmanager
 def client(self):
  c=live.Client(self.socket,timeout=240)
  try:yield c
  finally:c.close()
 def stop(self):
  if self.ui:self.ui.close();self.ui=None
  if self.proc.poll() is None:
   try:
    with self.client() as c:
     try:c.request(70)
     except EOFError:pass
    self.proc.wait(20);self.normal_shutdown=self.proc.returncode==0
   except (OSError,ValueError,TimeoutError,subprocess.TimeoutExpired):
    os.killpg(self.proc.pid,signal.SIGTERM)
    try:self.proc.wait(10)
    except subprocess.TimeoutExpired:os.killpg(self.proc.pid,signal.SIGKILL);self.proc.wait()
  self.log.close()


def rejected(action,label):
 try:action()
 except ValueError as error:return str(error)
 raise AssertionError(label+' accepted stale or foreign authority')


def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--image',type=Path,required=True);p.add_argument('--packages',type=Path,required=True)
 p.add_argument('--key',type=Path,default=ROOT/'build/campaign005/publisher.pem');p.add_argument('--public',type=Path,default=ROOT/'build/campaign005/publisher.pub');p.add_argument('--output',type=Path,required=True)
 a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);guests=[];checks=[];package_records=[]
 image_id=hashlib.sha256(a.image.read_bytes()).hexdigest()
 def passed(label,**facts):
  checks.append(dict(check=label,result='passed',**facts));print('PASS',label,flush=True)
  (out/'progress.json').write_text(json.dumps(dict(image_sha256=image_id,checks=checks),indent=2)+'\n')
 def install(node,name):
  path=a.packages/(name+'.ltrel');raw=path.read_bytes();info=releases.inspect(raw)
  with node.client() as c:instance=nodes.start_package(c,nodes.approved_package(path,a.public,info['release_id'],info['rights']),raw)
  package_records.append(dict(guest=node.base.name,project=name,release_id=info['release_id'],package_sha256=hashlib.sha256(raw).hexdigest(),rights=info['rights']))
  return instance
 def trust_library(node):
  j=Journey(argparse.Namespace(output=node.base/'native-actions',public=a.public,image=a.image));j.socket=node.socket;j.graphics=node.graphics;j.ui=node.ui;j.image=image_id
  path=a.packages/'library-native.ltrel';info,instance=j.trust_stage(path,'library-native')
  package_records.append(dict(guest=node.base.name,project='library-native',release_id=info['release_id'],package_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),rights=info['rights']))
  with node.client() as c:c.request(184,struct.pack('<Q',instance))
  return instance
 def state(node,instance):
  with node.client() as c:return appcall(c,instance,701)[1]
 def snapshot(node,instance):
  raw=state(node,instance);word=lambda n:struct.unpack_from('<Q',raw,n)[0]
  with node.client() as c:
   jobs=[struct.unpack_from('<Q',appcall(c,instance,704,i,0,128)[1])[0] for i in range(4)]
   pages=content.api(c).objects(312)[0][1];peer_status=network.status(c,0)
   vault=struct.unpack_from('<8Q',c.request(202,struct.pack('<8Q',202,0,3,0,0,0,0,1)))
  require(vault[0]==0 and vault[2]==0 and vault[5]==0,'unexpected unlocked or populated Objects vault')
  return dict(catalog_rows=word(16),monitoring=word(88),automatic_acquisition=word(96),charged_bytes=word(120),policy_generation=word(128),selected_collection=raw[288:320].hex(),jobs=jobs,resident_content_pages=pages,network=peer_status,vault_status=list(vault))
 fedkey=out/'federation.pem';fedpub=out/'federation.pub';capsule.generate_key(fedkey,fedpub);fid=hashlib.sha256(releases.public_modulus(fedpub)).digest()
 identity=hashlib.sha256(os.urandom(32)).digest();netkey=out/'registry.pem';netpub=out/'registry.pub';capsule.generate_key(netkey,netpub)
 probe=socket.socket();probe.bind(('127.0.0.1',0));port=probe.getsockname()[1];probe.close()
 description=out/'registry.service';details=network.create_description(netkey,identity,'127.0.0.1:'+str(port),'library-registry',description)
 credentials=[out/'personal.credential',out/'registry.credential'];network.provision(*credentials,identity,bytes.fromhex(details['server_id']),bytes.fromhex(details['service_id']))
 # Only the immutable 256-byte manifest is attached to the public catalog.
 # No WAV file, Content-store chunks or provider scope is installed anywhere.
 original=content.original_wave(1,2);manifest,_,_=content.commitments(original);del original
 collection=hashlib.sha256(b'Original no-vault native monitoring collection').digest()
 record=consumers.create(key=a.key,project='no-vault-native-metadata',collection=collection,item=hashlib.sha256(b'Original metadata-only item').digest(),edition=hashlib.sha256(b'original stereo edition').digest(),title='Open Courtyard - metadata only',resource=manifest,frames=48000,channels=2,license_id=1)
 try:
  registry=Guest('registry',out,a.image);guests.append(registry);reg=install(registry,'library-registry');peer=install(registry,'library-peer')
  with registry.client() as c:
   federation.configure(c,reg,fedpub,'consumer',allowed_rights=8191)
   root=consumers.attach(c,record,manifest,name='no-vault-public-metadata')['root']
   federation.call(c,reg,3,data=record[32:64]+releases.public_modulus(a.public));federation.call(c,reg,2,h=c.objects(27,root,reg,25)[0][1])
   decision=federation.sign_once(c,reg,fedkey,'consumer',8191);require(decision['listing']==4,'native Registry did not admit media metadata')
   require(content.api(c).objects(312)[0][1]==0,'metadata Registry acquired payload pages')
   network.configure(c,credentials[1],description,slot=0);network.call(c,13,slot=0)
   library_peer.call(c,peer,400,0,1,1,0,65536,100000,identity+bytes.fromhex(details['service_id'])+fid)
  passed('separate metadata-only native Registry admits signed original consumer record',consumer_record_sha256=hashlib.sha256(record).hexdigest(),manifest_sha256=hashlib.sha256(manifest).hexdigest(),payload_pages=0,classification=decision['listing'])
  personal=Guest('personal',out,a.image,True);guests.append(personal);verifier=install(personal,'library-registry')
  with personal.client() as c:federation.configure(c,verifier,fedpub,'consumer',allowed_rights=8191);network.configure(c,credentials[0],description,slot=0)
  lib=trust_library(personal)
  with personal.client() as c:appcall(c,lib,700,data=fid)
  personal.ui.press(60);personal.ui.press(2);personal.ui.press(28)
  def authenticated():
   with personal.client() as c:return network.status(c,0)['endpoint_authenticated']
  wait(authenticated,300,'native registry enrollment selection')
  personal.ui.press(59);personal.ui.press(16)
  wait(lambda:struct.unpack_from('<Q',state(personal,lib),16)[0]==1,300,'native metadata query')
  personal.ui.press(30)
  def added():
   with personal.client() as c:return struct.unpack_from('<Q',appcall(c,lib,703,0,8,8)[1])[0]
  metadata=wait(added,120,'native metadata Add');personal.ui.press(31)
  wait(lambda:struct.unpack_from('<Q',state(personal,lib),88)[0]==1,60,'native monitoring-only Subscribe')
  before=snapshot(personal,lib)
  require(before['catalog_rows']==1 and before['monitoring']==1 and before['selected_collection']==collection.hex(),'actual native collection/watch state missing')
  require(before['automatic_acquisition']==0 and before['charged_bytes']==0 and before['policy_generation']==0 and before['jobs']==[0]*4 and before['resident_content_pages']==0,'monitor-only action acquired content or authority')
  wait(lambda:rendered_text(personal.ui.frame(),12,58,13)=='LEMMA LIBRARY',60,'native Library surface')
  frame=personal.ui.frame();(personal.base/'added-subscribed.ppm').write_bytes(frame.ppm())
  with personal.client() as c:
   actual=appcall(c,lib,703,0,1024,640)[1]+appcall(c,lib,703,0,1664,128)[1]
   require(actual==record,'Library row differs from actual publisher-signed consumer record')
   foreign_before=rejected(lambda:c.read_object(metadata),'foreign Library metadata reference')
   private_bytes=b'explicit ephemeral Objects boundary alongside native Library Add';private=c.import_object(private_bytes,2)
   require(c.read_object(private)==private_bytes,'private boundary Object was unreadable before restart')
  passed('physical F2/1/Enter F1/Q A S create metadata-only selected collection and monitoring without acquisition',library_instance=lib,metadata_reference=metadata,state=before,frame_sha256=frame.digest,foreign_caller_metadata_read_before_restart=foreign_before)
  personal.stop();require(personal.normal_shutdown,'first personal guest did not exit normally through command70')
  fresh=Guest('fresh',out,a.image,True);guests.append(fresh)
  with fresh.client() as c:
   require(projects.roots(c)==[] and c.objects(10)[0][1:4]==(0,0,0),'fresh no-vault Objects store is not empty')
   stale_before=dict(library_metadata=rejected(lambda:c.read_object(metadata),'old Library metadata'),private_object=rejected(lambda:c.read_object(private),'old previously readable private Object'))
  newlib=trust_library(fresh);empty=snapshot(fresh,newlib)
  require(empty['catalog_rows']==0 and empty['monitoring']==0 and empty['automatic_acquisition']==0 and empty['charged_bytes']==0 and empty['policy_generation']==0 and empty['selected_collection']==bytes(32).hex() and empty['jobs']==[0]*4 and empty['resident_content_pages']==0,'native collection, watch or acquisition policy survived restart')
  require(empty['network']['configured_role']=='unconfigured' and not empty['network']['endpoint_authenticated'],'old enrollment or session was restored')
  with fresh.client() as c:
   require(appcall(c,newlib,703,0,0,64)[0][0]==2,'fresh Library exposes an old catalog row')
   allocated=c.import_object(b'fresh explicitly allocated private Object',2);require(allocated not in (metadata,private),'old numeric Object token aliased a fresh allocation')
   require(c.read_object(allocated)==b'fresh explicitly allocated private Object','fresh private Object is not usable')
   stale_after=dict(library_metadata=rejected(lambda:c.read_object(metadata),'old Library metadata after allocation'),private_object=rejected(lambda:c.read_object(private),'old previously readable Object after allocation'))
  wait(lambda:rendered_text(fresh.ui.frame(),12,58,13)=='LEMMA LIBRARY',60,'fresh native Library surface')
  (fresh.base/'empty-library.ppm').write_bytes(fresh.ui.frame().ppm())
  passed('fresh identical no-vault Library has no collection watch policy jobs or enrollment; old Object tokens remain denied after fresh allocation',fresh_library_instance=newlib,state=empty,stale_before_allocation=stale_before,stale_after_allocation=stale_after,fresh_object=allocated)
  fresh.stop();require(fresh.normal_shutdown,'fresh personal guest did not exit normally through command70')
  registry.stop();require(registry.normal_shutdown,'metadata Registry did not exit normally')
  commands=[dict(guest=g.base.name,command=g.command,normal_shutdown=g.normal_shutdown,returncode=g.proc.returncode) for g in guests]
  require(all('--vault' not in g.command and '--server-store' not in g.command and '--pcm-sink' not in g.command for g in guests),'unexpected personal/storage/media adapter')
  require(not any(p.suffix in ('.vault','.store','.img','.wav') for p in out.rglob('*') if p.is_file()),'unexpected backing or media file')
  result=dict(schema=1,result='passed',backend='qemu',image_sha256=image_id,packages=package_records,checks=checks,commands=commands,old_handles=dict(library_metadata=metadata,previously_readable_private_object=private),no_vault_or_server_store=True,payload_provider_instances=0,payload_pages=0,native_actions=['F12/Enter signed Library approval','F2/1/Enter registry selection','F1/Q catalog query','A metadata Add','S monitoring-only Subscribe'],limitations=['metadata-only focused no-vault check; no payload, playback, saves, retention or automatic acquisition approval','Library metadata references are caller-scoped: their Launcher denial was already expected before restart; the separate private Object proves a previously readable token becomes stale','normal process restart and volatile state behavior; no physical memory-remanence claim','publisher keys, explicit ephemeral enrollment credentials, UART logs and framebuffer captures are named test artifacts; none are silently restored as guest authority'])
  (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
 except BaseException as error:
  failure=dict(error=repr(error),traceback=traceback.format_exc(),guests=[])
  for node in guests:
   row=dict(guest=node.base.name,pid=node.proc.pid,returncode=node.proc.poll())
   try:
    if node.proc.poll() is None:
     with node.client() as c:row['processes']=[list(struct.unpack_from('<4Q',r,i)) for r in [c.request(2)] for i in range(0,len(r),32)]
     if node.ui:(node.base/'failure.ppm').write_bytes(node.ui.frame().ppm())
   except Exception as e:row['inspection_error']=repr(e)
   failure['guests'].append(row)
  (out/'failure.json').write_text(json.dumps(failure,indent=2)+'\n');raise
 finally:
  for node in reversed(guests):
   if node.proc.poll() is None:node.stop()


if __name__=='__main__':main()
