"""Continue an approved native checkpoint using the original live seed2.

The recipient receives no host payload or preloaded collection. Its only
personal data source is the previously approved encrypted checkpoint. The
surviving publisher may reacquire its existing owner scope by operation ID.
"""
import argparse, contextlib, hashlib, json, os, struct, sys, time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import content, federation, library_peer, live, network, nodes, project_vault, releases
from creator_journey import Journey, require, rendered_text
from library_game_save import Guest, preserve_failure
from library_journey import appcall, wait
from graphical_devices import DeviceInput

class ProcessIdentity:
 def __init__(self,pid):self.pid=pid
 def poll(self):
  try:os.kill(self.pid,0);return None
  except ProcessLookupError:return 0

class Existing:
 def __init__(self,base):self.base=base;self.socket=base/'portal.sock'
 @contextlib.contextmanager
 def client(self):
  c=live.Client(self.socket,timeout=240)
  try:yield c
  finally:c.close()
 def role(self,rights):
  with self.client() as c:raw=c.request(2)
  return next(struct.unpack_from('<Q',raw,i)[0] for i in range(7*32,len(raw),32) if 0<struct.unpack_from('<Q',raw,i+8)[0]<5 and struct.unpack_from('<Q',raw,i+16)[0]==rights)
 def stop(self):
  if getattr(self,'ui',None):self.ui.close();self.ui=None
  with self.client() as c:
   try:c.request(70)
   except EOFError:pass

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--base',type=Path,required=True);p.add_argument('--image',type=Path,required=True);p.add_argument('--player',type=Path,required=True);p.add_argument('--seconds',type=int,default=1);p.add_argument('--packages',type=Path);p.add_argument('--game',type=Path);p.add_argument('--public',type=Path,default=ROOT/'build/campaign005/publisher.pub');a=p.parse_args();out=a.base.resolve();report=json.loads((out/'journey.json').read_text());guests=[]
 registry=Existing(out/'registry');seed=Existing(out/'seed2');regpeer=registry.role(1025);seedpeer=seed.role(1025);fid=hashlib.sha256(releases.public_modulus(out/'federation.pub')).digest();wave=content.original_wave(a.seconds,2);manifest,_,_=content.commitments(wave);rootsha=hashlib.sha256(manifest).digest();checked=next(check['verified_bytes'] for check in report['checks'] if 'verified_bytes' in check)
 regpkg=a.packages/'library-registry.ltrel' if a.packages else out/'retain-registry.ltrel';libpkg=a.packages/'library-native.ltrel' if a.packages else out/'retain-library.ltrel';libname='library-native' if a.packages else 'retain-library'
 def passed(label,**facts):
  report['checks'].append(dict(check=label,result='passed',**facts));report['continuation_image']=hashlib.sha256(a.image.read_bytes()).hexdigest();(out/'journey.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS',label,flush=True)
 def install(node,path):
  raw=path.read_bytes();info=releases.inspect(raw)
  with node.client() as c:return nodes.start_package(c,nodes.approved_package(path,a.public,info['release_id'],info['rights']),raw)
 def boot(name,online):
  reused=name=='p2' and (out/name/'portal.sock').exists()
  if reused:
   previous=json.loads((out/'failure.json').read_text())
   item=next(g for g in previous['guests'] if Path(g['directory']).name==name)
   node=Existing(out/name);node.proc=ProcessIdentity(item['pid']);node.graphics=node.base/'display.qmp';node.capture=node.base/'guest.pcm';node.ui=DeviceInput('qemu',node.graphics)
  else:node=Guest(name,out,a.image,out/'personal.vault')
  guests.append(node)
  if online and not reused:
   try:verifier=node.role(2175)
   except (AttributeError,StopIteration):verifier=install(node,regpkg)
   with node.client() as c:
    federation.configure(c,verifier,out/'federation.pub','consumer',allowed_rights=8191)
    for slot in (0,2):network.configure(c,out/('client'+str(slot)+'.credential'),out/('provider'+str(slot)+'.service'),slot=slot)
  j=Journey(argparse.Namespace(output=node.base/'native-actions',public=a.public,image=a.image));j.socket=node.socket;j.graphics=node.graphics;j.ui=node.ui;_,player=j.trust_stage(a.player,'native-player');_,lib=j.trust_stage(libpkg,libname)
  with node.client() as c:c.request(184,struct.pack('<Q',lib));project_vault.unlock(c,(out/'personal.key').read_bytes());appcall(c,lib,700,data=fid)
  def word(offset):
   with node.client() as c:return struct.unpack_from('<Q',appcall(c,lib,701)[1],offset)[0]
  require(word(16)==0 and word(96)==0,'personal collection or acquisition authority silently restored')
  node.ui.press(22);wait(lambda:rendered_text(node.ui.frame(),16,16,7)=='TRUSTED',300,'native U approval');node.ui.press(28);wait(lambda:word(16)==1 and word(376)==0,1200,'selected checkpoint recovery')
  return node,lib,player,word
 try:
  personal,lib,player,word=boot('p2',True)
  with personal.client() as c:
   q,_=appcall(c,lib,705,0);state=content.api(c).objects(306,q[1])[0];require(state[2]==1 and state[3]==checked,'recovery published partial as complete or lost checked bytes')
  require(word(96)==0,'old automatic acquisition authority restored')
  personal.ui.press(60)
  for slot in (0,2):
   personal.ui.press(slot+2);personal.ui.press(28)
   def authenticated():
    with personal.client() as c:return network.status(c,slot)['endpoint_authenticated']
   wait(authenticated,300,'fresh native provider '+str(slot))
  for slot,node,peer in [(0,registry,regpeer),(2,seed,seedpeer)]:
   _,material=network.load_credentials(out/('client'+str(slot)+'.credential'))
   with node.client() as c:
    h=0
    if slot==2:
     h=content.reserve(content.api(c),wave,7001,material[32:64],fid)[0]
     h=content.api(c).objects(308,h,peer)[0][1]
    library_peer.call(c,peer,402,0)
    library_peer.call(c,peer,400,0,1 if slot==0 else 2,1 if slot==0 else int.from_bytes(rootsha[:8],'little')|1,h,16777216,100000,material[:32]+material[64:96]+(fid if slot==0 else rootsha))
  personal.ui.press(59);personal.ui.press(16);wait(lambda:word(40)!=0,60,'current catalog refresh starts');wait(lambda:word(40)==0,300,'current metadata verified');personal.ui.press(3);personal.ui.press(34);wait(lambda:word(208)==1,60,'fresh acquisition consent');personal.ui.press(28)
  def job():
   with personal.client() as c:return struct.unpack('<16Q',appcall(c,lib,704,0,0,128)[1])
  def completed():
   q=job()
   if q[0] in (12,13,14):raise RuntimeError(('alternate acquisition',q))
   return q[0]==10
  responsive=None
  if a.game:
   from native_responsive import NativeResponsive
   responsive=NativeResponsive.install(personal,a.game,a.public,lib)
   hashing=responsive.hashing(1200);responsive.focus_library()
   passed('game input and unrelated Objects complete during actual alternate-provider integrity validation',**hashing)
  wait(completed,1200,'seed2 acquisition with retained progress')
  with personal.client() as c:
   q,_=appcall(c,lib,705,0);actual=b''.join(content.api(c).objects(307,q[1],off,min(512,len(wave)-off))[1] for off in range(0,len(wave),512))
  require(actual==wave and job()[2]==2,'alternate bytes/provider mismatch')
  passed('fresh native consent resumes retained verified chunks from seed2 after seed1 shutdown',verified_reused=checked,remaining_bytes=len(wave)-checked,provider=2,payload_sha256=hashlib.sha256(actual).hexdigest(),old_authority_restored=False)
  personal.ui.press(19);wait(lambda:rendered_text(personal.ui.frame(),16,16,7)=='TRUSTED',300,'complete retention approval');personal.ui.press(28)
  wait(lambda:rendered_text(personal.ui.frame(),12,58,13)=='LEMMA LIBRARY',300,'complete retention panel dismissed')
  if responsive:
   persistence=responsive.persisting(300);responsive.focus_library()
   passed('game input and unrelated Objects complete during actual selected encrypted persistence',**persistence)
  wait(lambda:word(376)==0 and word(176)==17,1200,'complete content retained');personal.stop();registry.stop();seed.stop()
  offline,lib,player,word=boot('p3',False)
  # Physical approval dismissal and app IPC are asynchronous. Wait for the
  # trusted incarnation/focused surface before issuing each dependent action.
  def focus(instance):
   for _ in range(4):
    current=rendered_text(offline.ui.frame(),520,34,16)
    if current==f'{instance:016x}':return
    offline.ui.chord(56,15)
    wait(lambda:rendered_text(offline.ui.frame(),520,34,16)!=current,30,'trusted focus changed')
   raise AssertionError('expected native application focus')
  focus(lib)
  wait(lambda:rendered_text(offline.ui.frame(),12,58,13)=='LEMMA LIBRARY',120,'offline Library repaint')
  offline.ui.press(35);wait(lambda:word(160)==player,120,'selected Player binding')
  offline.ui.press(57)
  def attached():
   with offline.client() as c:return appcall(c,player,601)[0][2]==1
  wait(attached,180,'offline verified content attachment')
  focus(player);offline.ui.press(57)
  def ended():
   with offline.client() as c:return appcall(c,player,601)[0][2]==5
  wait(ended,600,'offline PCM playback');wait(lambda:offline.capture.exists() and offline.capture.stat().st_size>=len(wave)-44,60,'decoded host sample sink drains');captured=offline.capture.read_bytes();require(captured==wave[44:],'offline PCM bytes differ');passed('fresh U/Enter recovers selected collection/content and emits exact offline native PCM',pcm_bytes=len(captured),pcm_sha256=hashlib.sha256(captured).hexdigest(),network_providers_running=False,recipient_network_configured=False,speaker_output=False)
 except BaseException as error:
  preserve_failure(guests,out,error);print('PRESERVED recipient and original sources for diagnosis',flush=True);guests=[];raise
 finally:
  for node in reversed(guests):
   if node.proc.poll() is None:node.stop()
if __name__=='__main__':main()
