"""Resume owned native retention test guests after an interrupted harness.

No guest state setter is used. Existing signed catalog/source objects are read
through public services; fresh relationships and every approval use the same
native protocols/input as the uninterrupted focused harnesses.
"""
import argparse,contextlib,hashlib,json,os,struct,sys,time,traceback
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import content,federation,library_peer,live,network,nodes,projects,project_vault,releases
from creator_journey import Journey,require,rendered_text
from graphical_devices import DeviceInput
from library_game_save import Guest
from library_journey import appcall,wait
from crate_game import state as game_state

class Existing:
 def __init__(self,path,graphics=False):
  self.base=Path(path);self.socket=self.base/'portal.sock';self.graphics=self.base/'display.qmp';self.capture=self.base/'guest.pcm';self.ui=DeviceInput('qemu',self.graphics) if graphics else None
 @contextlib.contextmanager
 def client(self):
  c=live.Client(self.socket,timeout=240)
  try:yield c
  finally:c.close()
 def stop(self):
  if self.ui:self.ui.close();self.ui=None
  with self.client() as c:
   try:c.request(70)
   except EOFError:pass
  time.sleep(.6)

def instances(node,rights):
 with node.client() as c:raw=c.request(2)
 return [struct.unpack_from('<Q',raw,i)[0] for i in range(7*32,len(raw),32) if struct.unpack_from('<Q',raw,i+16)[0]==rights and 0<struct.unpack_from('<Q',raw,i+8)[0]<5]
def installed(node,path,public):
 matches=instances(node,releases.inspect(path.read_bytes())['rights'])
 if matches:return matches[0]
 raw=path.read_bytes();info=releases.inspect(raw)
 with node.client() as c:return nodes.start_package(c,nodes.approved_package(path,public,info['release_id'],info['rights']),raw)
def relationship(server,personal,description,server_credentials,client_credentials,slot):
 _,desc,_=network.load_description(description)
 with server.client() as c:network.configure(c,server_credentials,description,slot=0)
 with personal.client() as c:network.configure(c,client_credentials,description,slot=slot)
 with server.client() as c:wait(lambda:network.call(c,13,slot=0,allow_error=True)[0][0]==0,60,'server listen output backpressure')
 personal.ui.press(60);personal.ui.press(slot+2);personal.ui.press(28)
 def ready():
  with personal.client() as c:return network.status(c,slot)['endpoint_authenticated']
 wait(ready,300,'fresh native provider authentication '+str(slot))
 return desc[64:96],hashlib.sha256(desc).digest(),desc[96:128]
def frame_text(node,x,y,text):return rendered_text(node.ui.frame(),x,y,len(text))==text
def focus(node,name):
 for _ in range(5):
  if (name=='Library' and frame_text(node,12,58,'LEMMA LIBRARY')) or (name=='Game' and frame_text(node,8,56,'CRATE WORKSHOP')):return
  node.ui.chord(56,15);time.sleep(.5)
 raise AssertionError('native '+name+' focus not visible')

def run_game(a):
 out=a.base;image=a.image or out/'platform.bin';image_id=hashlib.sha256(image.read_bytes()).hexdigest();registry=Existing(out/'registry');personal=Existing(out/a.personal_dir,not a.restart_personal);reg=instances(registry,2175)[0];peer=instances(registry,1025)[0];lib=0 if a.restart_personal else (instances(personal,1919) or [0])[0];fid=hashlib.sha256(releases.public_modulus(out/'federation.pub')).digest();report=json.loads((out/'journey.json').read_text());report['recipient_image']=image_id
 regpkg=a.packages/'library-registry.ltrel' if a.packages else out/'game-save-registry.ltrel';libpkg=a.packages/'library-native.ltrel' if a.packages else out/'game-save-library.ltrel';libname='library-native' if a.packages else 'game-save-library'
 if a.restart_personal:
  try:personal.stop()
  except (FileNotFoundError,ConnectionRefusedError):pass
  personal=Guest(a.restart_dir,out,image,out/'personal.vault');verifier=installed(personal,regpkg,a.public)
  with personal.client() as c:
   federation.configure(c,verifier,out/'federation.pub','consumer',allowed_rights=8191);project_vault.unlock(c,(out/'personal.key').read_bytes());archived=json.loads(a.archive.read_text());import base64
   root=projects.import_records(c,archived['selected'],[dict(r,payload=base64.b64decode(r['payload'])) for r in archived['nodes']])[0]['cap'];shell=struct.unpack_from('<Q',c.request(2),4*32)[0];c.objects(27,root,shell,127);info=releases.inspect(a.game.read_bytes());c.request(10,bytes.fromhex(info['project_id'])+releases.public_modulus(a.public))
 if a.restart_personal or lib==0:
  j=Journey(argparse.Namespace(output=personal.base/'native-actions',public=a.public,image=image));j.socket=personal.socket;j.graphics=personal.graphics;j.ui=personal.ui;j.image=image_id;libinfo,lib=j.trust_stage(libpkg,libname);report.setdefault('recipient_packages',[]).append(libinfo)
  with personal.client() as c:c.request(184,struct.pack('<Q',lib));appcall(c,lib,700,data=fid)
  print('RESUME recipient image '+image_id+'; selected public graph imported through Objects; source Registry preserved',flush=True)
 def passed(label,**facts):
  report['checks'].append(dict(check=label,result='passed',**facts));(out/'journey.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS',label,flush=True)
 def word(offset):
  with personal.client() as c:return struct.unpack_from('<Q',appcall(c,lib,701)[1],offset)[0]
 def save_handle():
  with personal.client() as c:return struct.unpack_from('<Q',appcall(c,lib,703,0,96,8)[1])[0]
 def played():
  with personal.client() as c:return game_state(c,game)
 def connect_catalog():
  identity,service,_=relationship(registry,personal,out/'registry.service',out/'registry.credential',out/'personal.credential',0)
  with registry.client() as c:library_peer.call(c,peer,402,0);library_peer.call(c,peer,400,0,1,1,0,16777216,100000,identity+service+fid)
  personal.ui.press(59);personal.ui.press(16);wait(lambda:word(16)==1,300,'actual signed Game catalog')
 def install_game():
  personal.ui.press(62);personal.ui.press(23);wait(lambda:frame_text(personal,32,107,'crate-workshop-1'),120,'native selected Project picker');personal.ui.press(28)
  wait(lambda:frame_text(personal,16,12,'SIGNED P'),300,'actual native package approval');personal.ui.press(28)
  game=wait(lambda:(instances(personal,795) or [None])[0],120,'Library I approved Game install');focus(personal,'Library');personal.ui.press(36);wait(lambda:word(168)==game,60,'J exact executable release binding');return game
 if a.approve_pending_save:
  game=instances(personal,795)[0];save=save_handle();require(save and played()['won']==1 and word(168)==game,'pending selected save/game differs')
  require(frame_text(personal,16,16,'TRUSTED'),'no pending native trusted save approval')
  with personal.client() as c:
   before=c.request(202,struct.pack('<8Q',202,0,3,0,0,0,0,1));require(struct.unpack_from('<Q',before,16)[0]==0,'pending unapproved save already persisted');active=c.request(29,bytes.fromhex(releases.inspect(a.game.read_bytes())['project_id']));require(active[160:192].hex()==releases.inspect(a.game.read_bytes())['release_id'],'pending game package differs')
 else:
  connect_catalog();game=install_game();focus(personal,'Game');personal.ui.press(32);personal.ui.press(32);wait(lambda:played()['won']==1,60,'DD actual puzzle win');focus(personal,'Library');personal.ui.press(37);save=wait(save_handle,60,'K ephemeral save')
  with personal.client() as c:before=c.request(202,struct.pack('<8Q',202,0,3,0,0,0,0,1));require(struct.unpack_from('<Q',before,16)[0]==0,'K unexpectedly persisted')
  personal.ui.press(48);wait(lambda:frame_text(personal,16,16,'TRUSTED'),300,'B trusted save approval');(out/'save-approval.ppm').write_bytes(personal.ui.frame().ppm());personal.ui.press(1);wait(lambda:word(176)==21,60,'B cancellation')
  with personal.client() as c:after=c.request(202,struct.pack('<8Q',202,0,3,0,0,0,0,1));require(after==before,'Esc changed retained object root')
  wait(lambda:frame_text(personal,12,58,'LEMMA LIBRARY'),120,'cancelled panel visibly dismissed')
  personal.ui.press(48);wait(lambda:frame_text(personal,16,16,'TRUSTED'),300,'second B approval')
 personal.ui.press(28);wait(lambda:frame_text(personal,12,58,'LEMMA LIBRARY'),300,'B approval mutation completed and dismissed');wait(lambda:word(176)==17,300,'B physical Enter selected save commit')
 with personal.client() as c:retained=c.request(202,struct.pack('<8Q',202,0,3,0,0,0,0,1));require(struct.unpack_from('<Q',retained,16)[0]==192,'save retained wrong size');digest=retained[64:96].hex()
 passed('Library I/J/K/B and physical Enter retain only selected typed game save',state=played(),save_sha256=digest,save_bytes=192,cancel_left_ephemeral=True,save_handle_before_restart=save,interrupted_harness_resumed=True)
 personal.stop();personal=Guest('restarted',out,image,out/'personal.vault');verifier=installed(personal,regpkg,a.public)
 with personal.client() as c:
  federation.configure(c,verifier,out/'federation.pub','consumer',allowed_rights=8191);project_vault.unlock(c,(out/'personal.key').read_bytes());archived=json.loads(a.archive.read_text());import base64
  root=projects.import_records(c,archived['selected'],[dict(r,payload=base64.b64decode(r['payload'])) for r in archived['nodes']])[0]['cap'];shell=struct.unpack_from('<Q',c.request(2),4*32)[0];c.objects(27,root,shell,127);game_info=releases.inspect(a.game.read_bytes());c.request(10,bytes.fromhex(game_info['project_id'])+releases.public_modulus(a.public))
 j=Journey(argparse.Namespace(output=personal.base/'native-actions',public=a.public,image=image));j.socket=personal.socket;j.graphics=personal.graphics;j.ui=personal.ui;j.image=image_id;libinfo,lib=j.trust_stage(libpkg,libname);report.setdefault('recipient_packages',[]).append(libinfo)
 with personal.client() as c:c.request(184,struct.pack('<Q',lib));appcall(c,lib,700,data=fid)
 connect_catalog();game=install_game();require(played()['won']==0,'fresh Game inherited progress');personal.ui.press(49);wait(lambda:frame_text(personal,16,16,'TRUSTED'),300,'N trusted recovery approval');(out/'save-recovery-approval.ppm').write_bytes(personal.ui.frame().ppm());personal.ui.press(28);wait(lambda:frame_text(personal,12,58,'LEMMA LIBRARY'),300,'N approval mutation completed and dismissed');wait(lambda:word(176)==61,300,'N physical Enter recovery');personal.ui.press(38);wait(lambda:played()['won']==1,60,'L actual compatible recovered game');focus(personal,'Game');(out/'recovered-native-game.ppm').write_bytes(personal.ui.frame().ppm());passed('fresh Library N/Enter/L and fresh execution approval recover exact compatible progress',state=played(),save_sha256=digest,stale_capabilities_reused=False,network_session_reauthenticated=True)
 if a.mod:
  focus(personal,'Library');personal.ui.press(50);wait(lambda:frame_text(personal,32,107,'crate-workshop-1'),120,'M selected Project');personal.ui.press(28);wait(lambda:frame_text(personal,16,176,'assets/near-goal.ltlevels'),120,'actual Source pack choice');personal.ui.press(28)
  expected=hashlib.sha256((ROOT/'resources/crate-workshop/near-goal.ltlevels').read_bytes()).hexdigest();wait(lambda:played()['pack']==expected,120,'M scoped Source data handoff');focus(personal,'Game');personal.ui.press(32);wait(lambda:played()['won']==1,60,'actual one-push mod win');require(played()['moves']==1,'native M did not change target');focus(personal,'Library');personal.ui.press(38);wait(lambda:word(176)==42,60,'explicit old-save pack incompatibility');require(played()['pack']==expected and played()['moves']==1,'incompatible save destroyed mod progress');focus(personal,'Game');personal.ui.press(50);focus(personal,'Library');personal.ui.press(38);wait(lambda:played()['won']==1 and played()['moves']==2,60,'original pack compatible prior save reload');passed('native Library M selected Source mod changes gameplay and incompatible saved pack remains recoverable',mod_sha256=expected,mod_moves=1,recovered_original_moves=2)
 personal.stop();registry.stop()

def run_media(a):
 out=a.base;image=out/'platform.bin';image_id=hashlib.sha256(image.read_bytes()).hexdigest();registry=Existing(out/'registry');seed=Existing(out/'seed');old=None;personal=Existing(out/a.personal_dir,True) if a.personal_dir!='personal' else Existing(out/'personal',True);reg=instances(registry,2175)[0];regpeer=instances(registry,1025)[0];seedpeer=instances(seed,1025)[0];fid=hashlib.sha256(releases.public_modulus(out/'federation.pub')).digest();wave=content.original_wave(1,2);report={'image':image_id,'checks':[],'limitations':['explicit development backing; no physical durability or freshness claim','captured decoded PCM; speaker output not exercised','recipient restarted to correct physical console wiring before content acquisition']}
 def passed(label,**facts):
  report['checks'].append(dict(check=label,result='passed',**facts));(out/'journey.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS',label,flush=True)
 with registry.client() as c:
  page,desc=federation.call(c,reg,6);_,record=federation.call(c,reg,20,h=page[2]);require(len(record)==768 and struct.unpack_from('<Q',desc,16)[0]==4,'retained source catalog not admitted')
 manifest,_,_=content.commitments(wave);rootsha=hashlib.sha256(manifest).digest();require(record[192:224]==rootsha,'retained source metadata differs from recipe')
 _,seeddesc,_=network.load_description(out/'provider1.service')
 with seed.client() as c:
  h,oldmanifest,_,_=content.reserve(c,wave,7001,seeddesc[96:128],fid);require(oldmanifest==manifest,'idempotent source manifest changed');f,_=content.api(c).objects(306,h)
  if f[2]!=2:
   job=content.api(c).objects(310,h)[0][1]
   if job!=h:content.wait_job(c,job,240);content.api(c).objects(305,job,4)
  seedh=content.api(c).objects(308,h,seedpeer)[0][1];require(content.api(c).objects(306,h)[0][2]==2,'source payload population was incomplete')
 print('RESUME own seed validated payload reused by exact operation; no host copy or reupload',flush=True)
 def approve_apps(node,with_verifier):
  if with_verifier:
   verifier=installed(node,out/'retain-registry.ltrel',a.public)
   with node.client() as c:federation.configure(c,verifier,out/'federation.pub','consumer',allowed_rights=8191)
  if instances(node,1919) and instances(node,4865):return None,instances(node,4865)[0],instances(node,1919)[0]
  j=Journey(argparse.Namespace(output=node.base/'native-actions',public=a.public,image=image));j.socket=node.socket;j.graphics=node.graphics;j.ui=node.ui;j.image=image_id;_,player=j.trust_stage(a.player,'native-player');_,lib=j.trust_stage(out/'retain-library.ltrel','retain-library')
  with node.client() as c:project_vault.unlock(c,(out/'personal.key').read_bytes());c.request(184,struct.pack('<Q',lib));appcall(c,lib,700,data=fid)
  return j,player,lib
 j,player,lib=approve_apps(personal,True)
 def word(offset):
  with personal.client() as c:return struct.unpack_from('<Q',appcall(c,lib,701)[1],offset)[0]
 for slot,node in enumerate([registry,seed]):
  identity,service,_=relationship(node,personal,out/('provider'+str(slot)+'.service'),out/('server'+str(slot)+'.credential'),out/('client'+str(slot)+'.credential'),slot)
  with node.client() as c:
   if slot==0:library_peer.call(c,regpeer,402,0);library_peer.call(c,regpeer,400,0,1,1,0,16777216,100000,identity+service+fid)
   else:library_peer.call(c,seedpeer,402,0);library_peer.call(c,seedpeer,400,0,2,int.from_bytes(rootsha[:8],'little')|1,seedh,16777216,100000,identity+service+rootsha)
 personal.ui.press(59);personal.ui.press(16);wait(lambda:word(16)==1,300,'actual signed media catalog');personal.ui.press(30);wait(lambda:word(176)==22,120,'metadata Add');personal.ui.press(34);wait(lambda:word(208)==1,60,'bounded policy approval');personal.ui.press(28)
 def ready():
  with personal.client() as c:return struct.unpack_from('<Q',appcall(c,lib,704,0,0,8)[1])[0]==10
 wait(ready,1200,'actual remote content acquisition');passed('native remote catalog/Add/policy acquires actual independently populated seed media',bytes=len(wave),chunks=(len(wave)+4095)//4096,manifest_sha256=rootsha.hex(),consumer_sha256=hashlib.sha256(record).hexdigest())
 personal.ui.press(19);wait(lambda:frame_text(personal,16,16,'TRUSTED'),60,'R trusted selected content approval');(out/'content-approval.ppm').write_bytes(personal.ui.frame().ppm());time.sleep(.3);personal.ui.press(28);wait(lambda:word(176)==17,1200,'R physical Enter media+metadata commit')
 with personal.client() as c:inv=c.request(246,struct.pack('<8Q',246,0,3,0,0,0,0,1));generation=struct.unpack_from('<Q',inv,8)[0]
 passed('R/Enter co-commits exact selected signed metadata and actual content',generation=generation,retained_content_bytes=len(wave),selected_metadata_bytes=1536)
 personal.stop();registry.stop();seed.stop();personal=Guest('offline-restarted',out,image,out/'personal.vault');j,player,lib=approve_apps(personal,False);require(word(16)==0,'personal collection rows silently restored before approval');personal.ui.press(22);wait(lambda:frame_text(personal,16,16,'TRUSTED'),60,'U trusted selected content recovery');(out/'recovery-approval.ppm').write_bytes(personal.ui.frame().ppm());time.sleep(.3);personal.ui.press(28);wait(lambda:word(16)==1 and word(176)==17,1200,'U physical Enter exact co-recovery');personal.ui.press(35);personal.ui.press(57);personal.ui.chord(56,15);personal.ui.press(57)
 def ended():
  with personal.client() as c:return appcall(c,player,601)[0][2]==5
 wait(ended,300,'offline native WAV PCM');actual=personal.capture.read_bytes();require(actual==wave[44:],'offline decoded samples differ');(out/'offline-playback.ppm').write_bytes(personal.ui.frame().ppm());passed('fresh offline U/Enter recovers selected collection/content and player emits exact retained PCM',pcm_bytes=len(actual),pcm_sha256=hashlib.sha256(actual).hexdigest(),network_providers_running=False,recipient_network_configured=False,speaker_output=False);personal.stop()

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('kind',choices=['game','media']);p.add_argument('--base',type=Path,required=True);p.add_argument('--public',type=Path,default=ROOT/'build/campaign005/publisher.pub');p.add_argument('--archive',type=Path,default=ROOT/'build/campaign005/game-stable-graph/game1-closure.json');p.add_argument('--game',type=Path,default=ROOT/'build/campaign005/consumer-catalog-2/game1/crate-workshop.ltrel');p.add_argument('--player',type=Path,default=ROOT/'build/campaign005/player.ltrel');p.add_argument('--image',type=Path);p.add_argument('--packages',type=Path);p.add_argument('--mod',action='store_true');p.add_argument('--approve-pending-save',action='store_true',help='continue an actually displayed unapproved selected-save panel in the preserved guest');p.add_argument('--restart-personal',action='store_true');p.add_argument('--restart-dir',default='personal-fixed');p.add_argument('--personal-dir',default='personal');a=p.parse_args();a.base=a.base.resolve()
 try:(run_game if a.kind=='game' else run_media)(a)
 except BaseException:
  (a.base/'resume-error.txt').write_text(traceback.format_exc());raise
if __name__=='__main__':main()
