"""Native Library metadata -> policy -> streamed acquisition -> PCM journey.

Four distinct guests; source payloads enter only the explicitly selected seeds.
Personal UI is operated through raw keyboard input, never UI-state setters.
The test does not claim durable seed replication or encrypted job checkpoints.
"""
import argparse,contextlib,hashlib,json,os,signal,socket,struct,subprocess,sys,time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import capsule,consumers,content,federation,library_peer,live,network,nodes,releases
from creator_journey import Journey,require,rendered_text
from graphical_devices import DeviceInput

def wait(check,seconds=180,label='condition'):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  value=check()
  if value:return value
  time.sleep(.12)
 raise TimeoutError(label)

class Node:
 def __init__(self,name,out,image,graphics=False,server_store=None):
  self.name=name;self.base=out/name;self.base.mkdir();self.socket=self.base/'portal.sock';self.graphics=self.base/'display.qmp';self.capture=self.base/'guest.pcm';self.ui=None
  self.log=(self.base/'transport.log').open('wb')
  command=[ROOT/'lt','run','--backend','qemu','--socket',self.socket,'--image',image,'--network-mux']
  if server_store:command+=['--server-store',server_store]
  if graphics:command+=['--graphics',self.graphics,'--pcm-sink',self.capture]
  self.proc=subprocess.Popen(list(map(str,command)),cwd=ROOT,stdout=self.log,stderr=self.log,start_new_session=True)
  wait(lambda:self.socket.exists() or (self.proc.poll() is not None and self.failed()),90,name+' boot')
  if graphics:self.ui=DeviceInput('qemu',self.graphics)
 def failed(self):raise RuntimeError(self.name+' exited; see '+str(self.base/'transport.log'))
 @contextlib.contextmanager
 def client(self):
  c=live.Client(self.socket,timeout=240)
  try:yield c
  finally:c.close()
 def stop(self):
  if self.ui:self.ui.close();self.ui=None
  if self.proc.poll() is None:
   os.killpg(self.proc.pid,signal.SIGTERM)
   try:self.proc.wait(5)
   except subprocess.TimeoutExpired:os.killpg(self.proc.pid,signal.SIGKILL);self.proc.wait()
  self.log.close()

def appcall(c,instance,op,h=0,a=0,b=0,data=b''):
 # Launcher can be serving a physical approval while an application is inside
 # another broker call. A timed-out read has no committed effect to replay.
 # Retry only listed inspections, and only while this exact incarnation lives.
 deadline=time.monotonic()+60
 while True:
  try:
   raw=c.request(150,struct.pack('<Q8Q',instance,op,h,a,b,0,0,0,1)+data);break
  except ValueError as error:
   if str(error)!='guest rejected command150, status1' or op not in (500,601,701,703,704,708) or time.monotonic()>=deadline:raise
   table=c.request(2)
   if not any(struct.unpack_from('<Q',table,i)[0]==instance and 0<struct.unpack_from('<Q',table,i+8)[0]<5 for i in range(0,len(table),32)):raise
   time.sleep(.15)
 require(len(raw)>=64,'short native app result')
 return struct.unpack_from('<8Q',raw),raw[64:]

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--image',type=Path,default=ROOT/'build/live/guest.bin');parser.add_argument('--library',type=Path,default=ROOT/'build/live/apps/library.bin');parser.add_argument('--player',type=Path,default=ROOT/'build/campaign005/player.ltrel');parser.add_argument('--registry',type=Path,default=ROOT/'build/live/apps/registry-consumer-check.bin');parser.add_argument('--peer',type=Path,default=ROOT/'build/live/apps/library-peer.bin');parser.add_argument('--key',type=Path,default=ROOT/'build/campaign005/publisher.pem');parser.add_argument('--public',type=Path,default=ROOT/'build/campaign005/publisher.pub');parser.add_argument('--output',type=Path,required=True);parser.add_argument('--seconds',type=int,default=6);parser.add_argument('--timeout',type=int,default=2400);parser.add_argument('--failover',action='store_true')
 args=parser.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
 image=out/'platform.bin';image.write_bytes(args.image.read_bytes());image_id=hashlib.sha256(image.read_bytes()).hexdigest();report=[];guests=[]
 def passed(label,**facts):
  report.append(dict(check=label,result='passed',**facts));print('PASS',label,flush=True)
  (out/'journey.json').write_text(json.dumps(dict(image=image_id,checks=report,limitations=['seeds are explicitly volatile in this run','no retained transfer checkpoint or physical vault claim']),indent=2)+'\n')
 packages={}
 def package(binary,name,rights):
  raw,manifest=releases.make(binary,name,'1.0.0',rights,args.key,profile=2,license='NOASSERTION');path=out/(name+'.ltrel');path.write_bytes(raw);packages[name]=(path,releases.inspect(raw));return path
 regpkg=package(args.registry,'library-registry-role',2175);peerpkg=package(args.peer,'library-peer-role',1025)
 def install(node,path):
  raw=path.read_bytes();info=releases.inspect(raw);config=nodes.approved_package(path,args.public,info['release_id'],info['rights'])
  with node.client() as c:return nodes.start_package(c,config,raw)
 try:
  personal=Node('personal',out,image,True);guests.append(personal)
  registry=Node('registry',out,image);guests.append(registry)
  seeds=[Node('seed'+str(i+1),out,image) for i in range(2)];guests.extend(seeds)
  fedkey=out/'federation.pem';fedpublic=out/'federation.pub';capsule.generate_key(fedkey,fedpublic);federation_id=hashlib.sha256(releases.public_modulus(fedpublic)).digest()
  registry_instance=install(registry,regpkg);registry_peer=install(registry,peerpkg);local_registry=install(personal,regpkg);seed_instances=[install(seed,peerpkg) for seed in seeds]
  for node,instance in ((registry,registry_instance),(personal,local_registry)):
   with node.client() as c:federation.configure(c,instance,fedpublic,'consumer',allowed_rights=8191)
  # Both publisher-signed offered editions are genuine metadata records. The
  # later item is deliberately not admitted until after the first acquisition.
  wave_stereo=content.original_wave(args.seconds,2);wave_mono=content.original_wave(args.seconds,1);wave_later=content.original_wave(args.seconds,2,later=True)
  require(len(wave_stereo)>1048576,'select at least6seconds to exceed old1MiB transfer/store limit')
  item=hashlib.sha256(b'Open Courtyard first original recording').digest();collection=content.COLLECTION
  offered=[]
  for title,wave,channels,edition in [('Open Courtyard - mono',wave_mono,1,b'mono'),('Open Courtyard - lossless stereo',wave_stereo,2,b'stereo'),('Open Courtyard - new evening movement',wave_later,2,b'later')]:
   manifest,_,_=content.commitments(wave)
   raw=consumers.create(key=args.key,project='open-courtyard-'+edition.decode(),collection=collection,item=item if edition!=b'later' else hashlib.sha256(b'evening movement').digest(),edition=hashlib.sha256(edition).digest(),title=title,resource=manifest,frames=args.seconds*48000,channels=channels,license_id=1,sequence=2 if edition==b'later' else 1)
   offered.append(dict(title=title,wave=wave,manifest=manifest,record=raw,root=hashlib.sha256(manifest).digest(),channels=channels))
  def admit(index):
   record=offered[index]
   with registry.client() as c:
    root=consumers.attach(c,record['record'],record['manifest'],name='consumer-'+str(index))['root']
    federation.call(c,registry_instance,3,data=record['record'][32:64]+releases.public_modulus(args.public))
    delegated=c.objects(27,root,registry_instance,25)[0][1];fields,_=federation.call(c,registry_instance,2,h=delegated)
    decision=federation.sign_once(c,registry_instance,fedkey,'consumer',8191)
    require(decision and decision['listing']==4,'actual native consumer admission failed')
    return decision
  admit(0);admit(1)
  client_identity=hashlib.sha256(os.getrandom(32)).digest();relationships=[]
  for slot,node in enumerate([registry,*seeds]):
   probe=socket.socket();probe.bind(('127.0.0.1',0));port=probe.getsockname()[1];probe.close()
   private=out/f'network-role{slot}.pem';public=out/f'network-role{slot}.pub';capsule.generate_key(private,public);description=out/f'provider{slot}.service'
   details=network.create_description(private,client_identity,f'127.0.0.1:{port}','library-registry' if slot==0 else 'library-seed',description)
   creds=[out/f'client{slot}.credential',out/f'server{slot}.credential'];network.provision(*creds,client_identity,bytes.fromhex(details['server_id']),bytes.fromhex(details['service_id']))
   with node.client() as c:
    network.configure(c,creds[1],description,slot=0);wait(lambda:network.call(c,13,slot=0,allow_error=True)[0][0]==0,label='headless listen backpressure')
   with personal.client() as c:network.configure(c,creds[0],description,slot=slot)
   relationships.append(dict(description=description,credentials=creds,details=details))
  # Explicit headless population is parallel across independent seeds. Personal
  # never receives these bootstrap bytes or any host payload file/path.
  def populate(index):
   result=[];seed=seeds[index];provider=bytes.fromhex(relationships[index+1]['details']['server_id'])
   with seed.client() as c:
    for n,record in enumerate(offered):
     print('POPULATE',seed.name,record['title'],len(record['wave']),flush=True)
     handle,_=content.import_content(c,record['wave'],1000+n,provider,federation_id)
     shared=content.api(c).objects(308,handle,seed_instances[index])[0][1];result.append(shared)
   return result
  with ThreadPoolExecutor(max_workers=2) as pool:seed_handles=list(pool.map(populate,range(2)))
  # GUI approval installs and runs exact signed first-party packages.
  libpkg=package(args.library,'library-native',1919)
  j=Journey(argparse.Namespace(output=out/'native-actions',public=args.public));j.socket=personal.socket;j.graphics=personal.graphics;j.ui=personal.ui;j.image=image_id
  player_info,player_instance=j.trust_stage(args.player,'native-player')
  lib_info,library_instance=j.trust_stage(libpkg,'library-native')
  with personal.client() as c:
   c.request(184,struct.pack('<Q',library_instance));appcall(c,library_instance,700,data=federation_id)
  def state():
   with personal.client() as c:return appcall(c,library_instance,701)[1]
  def word(offset):return struct.unpack_from('<Q',state(),offset)[0]
  def scope(op,index=0):
   with personal.client() as c:return appcall(c,library_instance,op,index,0,128)
  personal.ui.press(60)
  for slot in range(3):
   personal.ui.press(slot+2);personal.ui.press(28)
   def online():
    with personal.client() as c:return network.status(c,slot)['endpoint_authenticated']
   wait(online,300,'native provider selection '+str(slot))
  for slot,node in enumerate([registry,*seeds]):
   details=relationships[slot]['details'];pins=client_identity+bytes.fromhex(details['service_id'])
   with node.client() as c:
    if slot==0:library_peer.call(c,registry_peer,400,0,1,1,0,16777216,100000,pins+federation_id)
    else:
     for record,handle in zip(offered,seed_handles[slot-1]):
      stream=int.from_bytes(record['root'][:8],'little')|1
      library_peer.call(c,seed_instances[slot-1],400,0,2,stream,handle,16777216,100000,pins+record['root'])
  passed('native enrollment selection keeps registry and two distinct seed guests authenticated',slots=[0,1,2],image=image_id)
  personal.ui.press(59);personal.ui.press(16);wait(lambda:word(16)==2,300,'native catalog records')
  personal.ui.press(30);wait(lambda:word(176)==22,120,'native metadata Add')
  with personal.client() as c:resident_pages=content.api(c).objects(312)[0][1]
  require(resident_pages==0,'metadata Add unexpectedly acquired content chunks')
  passed('Q catalog and A metadata-only Add import actual signed offered editions',catalog_rows=word(16),resident_content_pages=resident_pages)
  # Move to preferred offered stereo, approve a bounded monitoring policy and
  # let the native rule decide and acquire. No packet-by-packet host decisions.
  personal.ui.press(108);personal.ui.press(34);wait(lambda:word(208)==1,30,'native policy approval');personal.ui.press(28)
  wait(lambda:word(96)==1,30,'approved automatic acquisition policy')
  started=time.monotonic()
  def job():return scope(704,0)[1]
  def jobword(offset):return struct.unpack_from('<Q',job(),offset)[0]
  wait(lambda:jobword(56)>8192,300,'actual chunk acquisition progress')
  personal.ui.press(25);wait(lambda:jobword(0)==11,60,'native pause')
  before=jobword(56);personal.ui.press(16);wait(lambda:word(16)==2,120,'unrelated registry query during paused transfer')
  personal.ui.press(20)
  if args.failover:
   wait(lambda:jobword(56)>before+4096,180,'progress before provider interruption')
   with seeds[0].client() as c:network.call(c,14,slot=0)
   wait(lambda:jobword(0)>=12,120,'observable seed disconnect')
   personal.ui.press(3);personal.ui.press(20)
   passed('native transfer retried through independently authorized seed2',validated_bytes_before=before)
  wait(lambda:jobword(0)==10,args.timeout,'large media acquisition and native validation')
  passed('native preferred stereo acquisition validates complete content with bounded4KiB chunks',bytes=len(wave_stereo),chunks=(len(wave_stereo)+4095)//4096,elapsed_seconds=time.monotonic()-started,selected_provider=jobword(16),job_state=jobword(0))
  # Publish a genuinely new signed item only after monitoring was approved.
  later=admit(2);wait(lambda:word(16)==3,300,'monitoring discovers newly admitted item')
  passed('monitoring discovers actually newly published item',sequence=later['sequence'],catalog_rows=word(16))
  # Attach through Library's native content delegation, then play by real input.
  personal.ui.press(35);personal.ui.press(57);personal.ui.chord(56,15);personal.ui.press(57)
  def ended():
   with personal.client() as c:return appcall(c,player_instance,601)[0][2]==5
  wait(ended,300,'actual native PCM playback')
  captured=personal.capture.read_bytes();require(captured==wave_stereo[44:],'actual guest-produced PCM differs from acquired stereo content')
  passed('Library scoped handoff and native WAV decoding produce exact decoded PCM',pcm_bytes=len(captured),pcm_sha256=hashlib.sha256(captured).hexdigest(),speaker_output=False)
  (out/'library.ppm').write_bytes(personal.ui.frame().ppm())
  print(json.dumps(dict(image=image_id,library_release=lib_info['release_id'],player_release=player_info['release_id'],checks=report),indent=2))
 finally:
  for node in reversed(guests):node.stop()
if __name__=='__main__':main()
