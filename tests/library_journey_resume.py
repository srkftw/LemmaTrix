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
 def __init__(self,name,out,image,graphics=False):
  self.name=name;self.base=out/name;self.base.mkdir();self.socket=self.base/'portal.sock';self.graphics=self.base/'display.qmp';self.capture=self.base/'guest.pcm';self.ui=None
  self.log=(self.base/'transport.log').open('wb')
  command=[ROOT/'lt','run','--backend','qemu','--socket',self.socket,'--image',image,'--network-mux']
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
 raw=c.request(150,struct.pack('<Q8Q',instance,op,h,a,b,0,0,0,1)+data)
 require(len(raw)>=64,'short native app result')
 return struct.unpack_from('<8Q',raw),raw[64:]

def main():
 parser=argparse.ArgumentParser(description='Resume populated native journey after correcting two-console QEMU bus attachment');parser.add_argument('--source',type=Path,required=True);parser.add_argument('--timeout',type=int,default=2400);args=parser.parse_args();out=args.source.resolve();image=out/'platform.bin';image_id=hashlib.sha256(image.read_bytes()).hexdigest();report=[]
 public=ROOT/'build/campaign005/publisher.pub';key=ROOT/'build/campaign005/publisher.pem'
 class Existing:
  def __init__(self,name):self.name=name;self.base=out/name;self.socket=self.base/'portal.sock'
  @contextlib.contextmanager
  def client(self):
   c=live.Client(self.socket,timeout=240)
   try:yield c
   finally:c.close()
 registry=Existing('registry');seeds=[Existing('seed1'),Existing('seed2')]
 def instance(node,rights):
  with node.client() as c:raw=c.request(2)
  return next(struct.unpack_from('<Q',raw,i)[0] for i in range(7*32,len(raw),32) if struct.unpack_from('<Q',raw,i+16)[0]==rights and 0<struct.unpack_from('<Q',raw,i+8)[0]<5)
 def install(node,path):
  raw=path.read_bytes();info=releases.inspect(raw)
  with node.client() as c:return nodes.start_package(c,nodes.approved_package(path,public,info['release_id'],info['rights']),raw)
 registry_instance=instance(registry,2175);registry_peer=instance(registry,1025);seed_instances=[instance(n,1025) for n in seeds]
 old=Existing('personal')
 try:
  with old.client() as c:c.request(70)
 except (EOFError,ConnectionError):pass
 time.sleep(1)
 (out/'personal').rename(out/'personal-before-adapter-fix')
 personal=Node('personal',out,image,True)
 local_registry=install(personal,out/'library-registry-role.ltrel');fedkey=out/'federation.pem';fedpublic=out/'federation.pub';federation_id=hashlib.sha256(releases.public_modulus(fedpublic)).digest()
 with personal.client() as c:federation.configure(c,local_registry,fedpublic,'consumer',allowed_rights=8191)
 offered=[];item=hashlib.sha256(b'Open Courtyard first original recording').digest()
 for title,channels,edition in [('Open Courtyard - mono',1,b'mono'),('Open Courtyard - lossless stereo',2,b'stereo'),('Open Courtyard - new evening movement',2,b'later')]:
  wave=content.original_wave(6,channels,later=edition==b'later');manifest,_,_=content.commitments(wave);raw=consumers.create(key=key,project='open-courtyard-'+edition.decode(),collection=content.COLLECTION,item=item if edition!=b'later' else hashlib.sha256(b'evening movement').digest(),edition=hashlib.sha256(edition).digest(),title=title,resource=manifest,frames=6*48000,channels=channels,license_id=1,sequence=2 if edition==b'later' else 1)
  offered.append(dict(title=title,wave=wave,manifest=manifest,record=raw,root=hashlib.sha256(manifest).digest(),channels=channels))
 def admit(index):
  record=offered[index]
  with registry.client() as c:
   root=consumers.attach(c,record['record'],record['manifest'],name='consumer-'+str(index))['root'];federation.call(c,registry_instance,3,data=record['record'][32:64]+releases.public_modulus(public));delegated=c.objects(27,root,registry_instance,25)[0][1];federation.call(c,registry_instance,2,h=delegated);return federation.sign_once(c,registry_instance,fedkey,'consumer',8191)
 for slot,node in enumerate([registry,*seeds]):
  description=out/f'provider{slot}.service'
  with node.client() as c:wait(lambda:network.call(c,13,slot=0,allow_error=True)[0][0]==0,label='source listen')
  with personal.client() as c:network.configure(c,out/f'client{slot}.credential',description,slot=slot)
 j=Journey(argparse.Namespace(output=out/'resumed-native-actions',public=public));j.socket=personal.socket;j.graphics=personal.graphics;j.ui=personal.ui;j.image=image_id
 player_info,player_instance=j.trust_stage(ROOT/'build/campaign005/player.ltrel','native-player');lib_info,library_instance=j.trust_stage(out/'library-native.ltrel','library-native')
 with personal.client() as c:c.request(184,struct.pack('<Q',library_instance));appcall(c,library_instance,700,data=federation_id)
 def passed(label,**facts):
  report.append(dict(check=label,result='passed',**facts));print('PASS',label,flush=True);(out/'resumed-journey.json').write_text(json.dumps(dict(image=image_id,library_release=lib_info['release_id'],player_release=player_info['release_id'],checks=report,limitations=['original media6seconds; useful longer recipes separate','seeds volatile; no durable replication claim','no speaker hardware output']),indent=2)+'\n')
 def word(offset):
  with personal.client() as c:return struct.unpack_from('<Q',appcall(c,library_instance,701)[1],offset)[0]
 def jobword(offset):
  with personal.client() as c:return struct.unpack_from('<Q',appcall(c,library_instance,704,0,0,128)[1],offset)[0]
 personal.ui.press(60)
 for slot in range(3):
  personal.ui.press(slot+2);personal.ui.press(28)
  def online():
   with personal.client() as c:return network.status(c,slot)['endpoint_authenticated']
  wait(online,300,'native provider authentication '+str(slot));print('AUTH',slot,flush=True)
 for slot,node in enumerate([registry,*seeds]):
  _,desc,_=network.load_description(out/f'provider{slot}.service');pins=desc[64:96]+hashlib.sha256(desc).digest()
  with node.client() as c:
   if slot==0:library_peer.call(c,registry_peer,400,0,1,1,0,16777216,100000,pins+federation_id)
   else:
    for n,record in enumerate(offered):
     handle,_,_,_=content.reserve(c,record['wave'],1000+n,desc[96:128],federation_id);shared=content.api(c).objects(308,handle,seed_instances[slot-1])[0][1];stream=int.from_bytes(record['root'][:8],'little')|1;library_peer.call(c,seed_instances[slot-1],400,0,2,stream,shared,16777216,100000,pins+record['root'])
 passed('native registry and two separate seed provider selections authenticated simultaneously',source_instances=[registry_peer,*seed_instances],source_payloads_reimported=False)
 personal.ui.press(59);personal.ui.press(16);wait(lambda:word(16)==2,300,'native catalog')
 personal.ui.press(30);wait(lambda:word(176)==22,120,'metadata Add')
 with personal.client() as c:pages=content.api(c).objects(312)[0][1]
 require(pages==0,'metadata Add acquired payload');passed('native Q catalog and A metadata Add remain payload-free',rows=word(16),pages=pages)
 personal.ui.press(108);personal.ui.press(34);wait(lambda:word(208)==1,30,'policy approval');personal.ui.press(28);wait(lambda:word(96)==1,30,'approved bounded automatic acquisition')
 started=time.monotonic();wait(lambda:jobword(56)>8192,300,'actual acquisition progress');personal.ui.press(25);wait(lambda:jobword(0)==11,60,'pause');before=jobword(56);personal.ui.press(16);wait(lambda:word(16)==2,120,'registry query while paused');personal.ui.press(20);passed('native pause and retry preserve checked progress',bytes_before=before)
 wait(lambda:jobword(0)==10,args.timeout,'native large content acquisition');passed('native preferred stereo edition acquired and validated from seed1',bytes=len(offered[1]['wave']),chunks=(len(offered[1]['wave'])+4095)//4096,elapsed_seconds=time.monotonic()-started,provider=jobword(16))
 later=admit(2);wait(lambda:word(16)==3,300,'actual newly published item');passed('monitoring discovers newly published signed collection item',sequence=later['sequence'],rows=word(16))
 personal.ui.press(35);personal.ui.press(57);personal.ui.chord(56,15);personal.ui.press(57)
 def ended():
  with personal.client() as c:return appcall(c,player_instance,601)[0][2]==5
 wait(ended,300,'actual PCM playback');captured=personal.capture.read_bytes();require(captured==offered[1]['wave'][44:],'PCM mismatch');passed('native Library handoff and WAV decoder produce exact acquired samples',pcm_bytes=len(captured),pcm_sha256=hashlib.sha256(captured).hexdigest(),speaker_output=False)
 (out/'resumed-library.ppm').write_bytes(personal.ui.frame().ppm());personal.ui.close();personal.ui=None
 print('JOURNEY COMPLETE; populated guests intentionally remain for replication and follow-up',flush=True)
if __name__=='__main__':main()
