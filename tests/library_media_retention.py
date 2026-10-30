"""Native R/Enter and fresh offline U/Enter preserve one selected media edition.

Genuine signed records come from a separate guest Registry and actual payload
chunks from a separate authorized seed. Personal state is never preloaded. A
fresh offline guest recovers the co-committed signed selection/content and its
native WAV player produces the exact retained PCM through the audio device.
"""
import argparse,hashlib,json,os,socket,struct,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import capsule,consumers,content,federation,library_peer,network,nodes,project_vault,releases
from creator_journey import Journey,require,rendered_text
from library_game_save import Guest,preserve_failure
from library_journey import appcall,wait

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,default=ROOT/'build/live/guest.bin');p.add_argument('--library',type=Path,default=ROOT/'build/live/apps/library.bin');p.add_argument('--registry',type=Path,default=ROOT/'build/live/apps/registry.bin');p.add_argument('--peer',type=Path,default=ROOT/'build/live/apps/library-peer.bin');p.add_argument('--player',type=Path,default=ROOT/'build/campaign005/player.ltrel');p.add_argument('--key',type=Path,default=ROOT/'build/campaign005/publisher.pem');p.add_argument('--public',type=Path,default=ROOT/'build/campaign005/publisher.pub');p.add_argument('--packages',type=Path);p.add_argument('--seconds',type=int,default=1);p.add_argument('--keep-running',action='store_true',help='preserve failed guests and their observed fault state');p.add_argument('--game',type=Path,help='optional signed game for actual input/Objects responsiveness during content work');p.add_argument('--output',type=Path,required=True);a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);image=out/'platform.bin';image.write_bytes(a.image.read_bytes());image_id=hashlib.sha256(image.read_bytes()).hexdigest();guests=[];report=[]
 package_records=[]
 def passed(label,**facts):
  report.append(dict(check=label,result='passed',**facts));print('PASS',label,flush=True);(out/'journey.json').write_text(json.dumps(dict(image=image_id,packages=package_records,checks=report,limitations=['explicit development backing file; no physical-vault durability claim','captured decoded samples; speaker output not exercised']),indent=2)+'\n')
 def package(binary,name,rights):
  raw,_=releases.make(binary,name,'1.0.0',rights,a.key,profile=2,license='NOASSERTION');path=out/(name+'.ltrel');path.write_bytes(raw);return path
 regpkg=a.packages/'library-registry.ltrel' if a.packages else package(a.registry,'retain-registry',2175);peerpkg=a.packages/'library-peer.ltrel' if a.packages else package(a.peer,'retain-peer',1025);libpkg=a.packages/'library-native.ltrel' if a.packages else package(a.library,'retain-library',1919);libname='library-native' if a.packages else 'retain-library'
 def install(node,path):
  raw=path.read_bytes();info=releases.inspect(raw)
  with node.client() as c:instance=nodes.start_package(c,nodes.approved_package(path,a.public,info['release_id'],info['rights']),raw)
  package_records.append(dict(guest=node.base.name,release_id=info['release_id'],package_sha256=hashlib.sha256(raw).hexdigest(),rights=info['rights']));return instance
 vault=out/'personal.vault';key=out/'personal.key';subprocess.run([str(ROOT/'lt'),'vault-init',str(vault),'--sectors','60000','--key-out',str(key)],cwd=ROOT,check=True)
 fedkey=out/'federation.pem';fedpub=out/'federation.pub';capsule.generate_key(fedkey,fedpub);fid=hashlib.sha256(releases.public_modulus(fedpub)).digest();identity=hashlib.sha256(os.urandom(32)).digest()
 wave=content.original_wave(a.seconds,2);manifest,_,_=content.commitments(wave);rootsha=hashlib.sha256(manifest).digest();record=consumers.create(key=a.key,project='native-retained-courtyard',collection=content.COLLECTION,item=hashlib.sha256(b'Native retention original Courtyard').digest(),edition=hashlib.sha256(b'approved stereo').digest(),title='Open Courtyard / selected retained stereo',resource=manifest,frames=a.seconds*48000,channels=2,license_id=1)
 try:
  registry=Guest('registry',out,image);seed=Guest('seed',out,image);personal=Guest('personal',out,image,vault);guests.extend([registry,seed,personal]);reg=install(registry,regpkg);regpeer=install(registry,peerpkg);seedpeer=install(seed,peerpkg);verifier=install(personal,regpkg)
  for node,instance in [(registry,reg),(personal,verifier)]:
   with node.client() as c:federation.configure(c,instance,fedpub,'consumer',allowed_rights=8191)
  with registry.client() as c:
   root=consumers.attach(c,record,manifest,name='retained-media-metadata')['root'];federation.call(c,reg,3,data=record[32:64]+releases.public_modulus(a.public));federation.call(c,reg,2,h=c.objects(27,root,reg,25)[0][1]);decision=federation.sign_once(c,reg,fedkey,'consumer',8191);require(decision['listing']==4,'actual signed media admission failed')
  relationships=[]
  for slot,node in enumerate([registry,seed]):
   private=out/('provider'+str(slot)+'.pem');public=out/('provider'+str(slot)+'.pub');capsule.generate_key(private,public);probe=socket.socket();probe.bind(('127.0.0.1',0));port=probe.getsockname()[1];probe.close();description=out/('provider'+str(slot)+'.service');details=network.create_description(private,identity,'127.0.0.1:'+str(port),'library-registry' if slot==0 else 'library-seed',description);creds=[out/('client'+str(slot)+'.credential'),out/('server'+str(slot)+'.credential')];network.provision(*creds,identity,bytes.fromhex(details['server_id']),bytes.fromhex(details['service_id']))
   with node.client() as c:network.configure(c,creds[1],description,slot=0);network.call(c,13,slot=0)
   with personal.client() as c:network.configure(c,creds[0],description,slot=slot)
   relationships.append(dict(details=details,description=description,creds=creds))
  with seed.client() as c:
   h,_=content.import_content(c,wave,7001,bytes.fromhex(relationships[1]['details']['server_id']),fid);seedh=content.api(c).objects(308,h,seedpeer)[0][1]
  def approve_apps(node):
   j=Journey(argparse.Namespace(output=node.base/'native-actions',public=a.public,image=image));j.socket=node.socket;j.graphics=node.graphics;j.ui=node.ui;j.image=image_id;player_info,player=j.trust_stage(a.player,'native-player');libinfo,lib=j.trust_stage(libpkg,libname)
   package_records.extend(dict(guest=node.base.name,release_id=info['release_id'],package_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),rights=info['rights']) for info,path in [(player_info,a.player),(libinfo,libpkg)])
   with node.client() as c:c.request(184,struct.pack('<Q',lib));project_vault.unlock(c,key.read_bytes());appcall(c,lib,700,data=fid)
   def word(offset):
    with node.client() as c:return struct.unpack_from('<Q',appcall(c,lib,701)[1],offset)[0]
   return j,player,lib,word
  j,player,lib,word=approve_apps(personal);personal.ui.press(60)
  responsive=None
  if a.game:
   from native_responsive import NativeResponsive
   responsive=NativeResponsive.install(personal,a.game,a.public,lib);responsive.focus_library();personal.ui.press(60)
  for slot in range(2):
   personal.ui.press(slot+2);personal.ui.press(28)
   def authenticated():
    with personal.client() as c:return network.status(c,slot)['endpoint_authenticated']
   wait(authenticated,300,'native selected provider '+str(slot))
  with registry.client() as c:library_peer.call(c,regpeer,400,0,1,1,0,16777216,100000,identity+bytes.fromhex(relationships[0]['details']['service_id'])+fid)
  with seed.client() as c:library_peer.call(c,seedpeer,400,0,2,int.from_bytes(rootsha[:8],'little')|1,seedh,16777216,100000,identity+bytes.fromhex(relationships[1]['details']['service_id'])+rootsha)
  personal.ui.press(59);personal.ui.press(16);wait(lambda:word(16)==1,300,'native metadata catalog');personal.ui.press(30);wait(lambda:word(176)==22,60,'metadata-only Add');personal.ui.press(34);wait(lambda:word(208)==1,30,'native bounded acquisition approval');personal.ui.press(28)
  def job_state():
   with personal.client() as c:return struct.unpack_from('<Q',appcall(c,lib,704,0,0,8)[1])[0]
  if responsive:
   hashing=responsive.hashing(1200);responsive.focus_library();passed('native game input and unrelated Objects complete while the same integrity job remains active',**hashing)
  wait(lambda:job_state()==10,1200,'actual acquired media validation');personal.ui.press(19);wait(lambda:rendered_text(personal.ui.frame(),16,16,7)=='TRUSTED',300,'native content retention approval');frame=personal.ui.frame();(out/'content-approval.ppm').write_bytes(frame.ppm());personal.ui.press(28);wait(lambda:rendered_text(personal.ui.frame(),12,58,13)=='LEMMA LIBRARY',300,'selected content transaction started and panel dismissed')
  if responsive:
   persistence=responsive.persisting(300);responsive.focus_library();passed('native game input and unrelated Objects complete while selected encrypted persistence remains active',**persistence)
  wait(lambda:word(176)==17,1200,'native co-committed media retention')
  with personal.client() as c:
   status=c.request(246,struct.pack('<8Q',246,0,3,0,0,0,0,1));require(len(status)>=64,'short retained content inventory');generation=struct.unpack_from('<Q',status,8)[0]
  passed('native metadata Add, bounded policy, acquisition and R/Enter co-retain exact media plus signed selection',bytes=len(wave),chunks=(len(wave)+4095)//4096,manifest_sha256=rootsha.hex(),consumer_sha256=hashlib.sha256(record).hexdigest(),generation=generation)
  personal.stop();registry.stop();seed.stop();personal=Guest('offline-restarted',out,image,vault);guests.append(personal);j,player,lib,word=approve_apps(personal)
  require(word(16)==0,'unapproved collection rows silently recovered');personal.ui.press(22);wait(lambda:rendered_text(personal.ui.frame(),16,16,7)=='TRUSTED',300,'native selected content recovery approval');frame=personal.ui.frame();(out/'recovery-approval.ppm').write_bytes(frame.ppm());personal.ui.press(28);wait(lambda:rendered_text(personal.ui.frame(),12,58,13)=='LEMMA LIBRARY',300,'content recovery transaction started and panel dismissed');wait(lambda:word(16)==1 and word(176)==17,1200,'native U/Enter co-recovery');personal.ui.press(35);personal.ui.press(57)
  def loaded():
   with personal.client() as c:return appcall(c,player,601)[0][2]==1
  wait(loaded,300,'actual selected content attached to native Player')
  for _ in range(5):
   previous=rendered_text(personal.ui.frame(),520,34,16)
   if previous==f'{player:016x}':break
   personal.ui.chord(56,15);wait(lambda:rendered_text(personal.ui.frame(),520,34,16)!=previous,60,'actual native Player focus')
  require(rendered_text(personal.ui.frame(),520,34,16)==f'{player:016x}','trusted focus is not selected Player');personal.ui.press(57)
  def ended():
   with personal.client() as c:return appcall(c,player,601)[0][2]==5
  wait(ended,300,'actual offline decoded PCM playback');captured=personal.capture.read_bytes();require(captured==wave[44:],'retained offline guest PCM differs from selected media')
  (out/'offline-playback.ppm').write_bytes(personal.ui.frame().ppm());passed('fresh U/Enter recovers co-committed selected collection and content; offline native player emits exact PCM',network_providers_running=False,recipient_network_configured=False,pcm_bytes=len(captured),pcm_sha256=hashlib.sha256(captured).hexdigest(),speaker_output=False)
 except BaseException as error:
  preserve_failure(guests,out,error)
  if a.keep_running:guests=[]
  raise
 finally:
  for node in reversed(guests):
   if node.proc.poll() is None:node.stop()
if __name__=='__main__':main()
