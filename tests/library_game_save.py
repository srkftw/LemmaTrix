"""Native Library game install and explicitly approved save/recovery boundary.

The catalog is served by another guest's real signed Registry. The recipient
imports an explicitly selected public source/release graph through Objects;
Library I must then choose its exact admitted head before trusted installation.
All game, save and approval actions use hardware keyboard input. This focused
test does not claim remote graph acquisition or encrypted collection retention.
"""
import argparse,base64,contextlib,hashlib,json,os,signal,socket,struct,subprocess,sys,time,traceback
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import capsule,federation,live,network,nodes,projects,project_vault,releases,library_peer
from creator_journey import Journey,require,rendered_text
from graphical_devices import DeviceInput
from crate_game import state as game_state
from library_journey import appcall,wait

class Guest:
 def __init__(self,name,out,image,vault=None,pcm_play=False):
  self.base=out/name;self.base.mkdir();self.socket=self.base/'portal.sock';self.graphics=self.base/'display.qmp';self.capture=self.base/'guest.pcm';self.ui=None
  self.log=(self.base/'guest.log').open('wb');cmd=[ROOT/'lt','run','--image',image,'--socket',self.socket,'--network-mux']
  if vault:cmd+=['--vault',vault,'--graphics',self.graphics,'--pcm-sink',self.capture]
  if pcm_play:cmd+=['--pcm-play']
  self.proc=subprocess.Popen(list(map(str,cmd)),cwd=ROOT,stdout=self.log,stderr=self.log,start_new_session=True)
  def ready():
   if self.proc.poll() is not None:raise RuntimeError(name+' exited before portal readiness; see '+str(self.base/'guest.log'))
   return self.socket.exists()
  wait(ready,90,name+' boot')
  if vault:self.ui=DeviceInput('qemu',self.graphics)
 @contextlib.contextmanager
 def client(self):
  c=live.Client(self.socket,timeout=240)
  try:yield c
  finally:c.close()
 def stop(self):
  if self.ui:self.ui.close();self.ui=None
  if self.proc.poll() is None:
   # Let the guest finish and the raw adapter close/reap its selected sink.
   # A bounded fallback remains for a deliberately faulted/unresponsive VM.
   try:
    c=live.Client(self.socket,timeout=5)
    try:
     try:c.request(70)
     except EOFError:pass
    finally:c.close()
   except (OSError,ValueError,TimeoutError):os.killpg(self.proc.pid,signal.SIGTERM)
   try:self.proc.wait(10)
   except subprocess.TimeoutExpired:os.killpg(self.proc.pid,signal.SIGKILL);self.proc.wait()
  self.log.close()

def preserve_failure(guests,out,error):
 """Record real process exit causes before any optional teardown."""
 result={'error':repr(error),'traceback':traceback.format_exc(),'guests':[]}
 for node in guests:
  item={'directory':str(node.base),'pid':node.proc.pid,'returncode':node.proc.poll()}
  try:
   with node.client() as c:
    raw=c.request(2);item['processes']=[dict(zip(['instance','state','rights','exit_cause'],struct.unpack_from('<4Q',raw,i))) for i in range(0,len(raw),32)]
  except Exception as e:item['inspection_error']=repr(e)
  try:
   if node.ui:(node.base/'failure.ppm').write_bytes(node.ui.frame().ppm())
  except Exception as e:item['frame_error']=repr(e)
  result['guests'].append(item)
 (out/'failure.json').write_text(json.dumps(result,indent=2)+'\n')

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--image',type=Path,default=ROOT/'build/live/guest.bin');p.add_argument('--library',type=Path,default=ROOT/'build/live/apps/library.bin');p.add_argument('--registry',type=Path,default=ROOT/'build/live/apps/registry.bin');p.add_argument('--peer',type=Path,default=ROOT/'build/live/apps/library-peer.bin')
 p.add_argument('--archive',type=Path,default=ROOT/'build/campaign005/game-stable-graph/game1-closure.json');p.add_argument('--game',type=Path,default=ROOT/'build/campaign005/consumer-catalog-2/game1/crate-workshop.ltrel');p.add_argument('--key',type=Path,default=ROOT/'build/campaign005/publisher.pem');p.add_argument('--public',type=Path,default=ROOT/'build/campaign005/publisher.pub');p.add_argument('--packages',type=Path);p.add_argument('--mod',action='store_true');p.add_argument('--keep-running',action='store_true',help='keep failed guests alive after collecting process/fault/frame evidence');p.add_argument('--output',type=Path,required=True)
 a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);image=out/'platform.bin';image.write_bytes(a.image.read_bytes());image_id=hashlib.sha256(image.read_bytes()).hexdigest();guests=[];report=[];package_records=[]
 def passed(label,**facts):
  report.append(dict(check=label,result='passed',**facts));print('PASS',label,flush=True);(out/'journey.json').write_text(json.dumps(dict(image=image_id,packages=package_records,checks=report,limitations=['public release graph explicitly imported through Objects; no remote game graph acquisition claim','speaker playback and media retention not exercised by this focused test']),indent=2)+'\n')
 def package(binary,name,rights):
  raw,_=releases.make(binary,name,'1.0.0',rights,a.key,profile=2,license='NOASSERTION');path=out/(name+'.ltrel');path.write_bytes(raw);return path
 regpkg=a.packages/'library-registry.ltrel' if a.packages else package(a.registry,'game-save-registry',2175);peerpkg=a.packages/'library-peer.ltrel' if a.packages else package(a.peer,'game-save-peer',1025);libpkg=a.packages/'library-native.ltrel' if a.packages else package(a.library,'game-save-library',1919);libname='library-native' if a.packages else 'game-save-library'
 def install(node,path):
  raw=path.read_bytes();info=releases.inspect(raw)
  with node.client() as c:instance=nodes.start_package(c,nodes.approved_package(path,a.public,info['release_id'],info['rights']),raw)
  package_records.append(dict(guest=node.base.name,release_id=info['release_id'],package_sha256=hashlib.sha256(raw).hexdigest(),rights=info['rights']));return instance
 archived=json.loads(a.archive.read_text());records=[dict(record,payload=base64.b64decode(record['payload'])) for record in archived['nodes']];game_info=releases.inspect(a.game.read_bytes())
 vault=out/'personal.vault';vault_key=out/'personal.key';subprocess.run([str(ROOT/'lt'),'vault-init',str(vault),'--sectors','60000','--key-out',str(vault_key)],cwd=ROOT,check=True)
 fedkey=out/'federation.pem';fedpub=out/'federation.pub';capsule.generate_key(fedkey,fedpub);fid=hashlib.sha256(releases.public_modulus(fedpub)).digest()
 identity=hashlib.sha256(os.urandom(32)).digest();private=out/'provider.pem';public=out/'provider.pub';capsule.generate_key(private,public);probe=socket.socket();probe.bind(('127.0.0.1',0));port=probe.getsockname()[1];probe.close();description=out/'registry.service';details=network.create_description(private,identity,'127.0.0.1:'+str(port),'library-registry',description);credentials=[out/'personal.credential',out/'registry.credential'];network.provision(*credentials,identity,bytes.fromhex(details['server_id']),bytes.fromhex(details['service_id']))
 try:
  registry=Guest('registry',out,image);guests.append(registry);reg=install(registry,regpkg);peer=install(registry,peerpkg)
  with registry.client() as c:
   federation.configure(c,reg,fedpub,'consumer',allowed_rights=8191);root=projects.import_records(c,archived['selected'],records)[0]['cap'];federation.call(c,reg,3,data=bytes.fromhex(game_info['project_id'])+releases.public_modulus(a.public));grant=c.objects(27,root,reg,25)[0][1];federation.call(c,reg,2,h=grant);decision=federation.sign_once(c,reg,fedkey,'consumer',8191);require(decision['listing']==5,'actual native+consumer game admission failed');network.configure(c,credentials[1],description,slot=0);network.call(c,13,slot=0)
  passed('separate guest Registry admits actual canonical game release',release=game_info['release_id'],head=archived['selected'][0]['head'],classification=decision['listing'])
  def boot_personal(name):
   node=Guest(name,out,image,vault);guests.append(node);verifier=install(node,regpkg)
   with node.client() as c:
    federation.configure(c,verifier,fedpub,'consumer',allowed_rights=8191);project_vault.unlock(c,vault_key.read_bytes());network.configure(c,credentials[0],description,slot=0)
    root=projects.import_records(c,archived['selected'],records)[0]['cap'];shell=struct.unpack_from('<Q',c.request(2),4*32)[0];c.objects(27,root,shell,127);c.request(10,bytes.fromhex(game_info['project_id'])+releases.public_modulus(a.public))
   j=Journey(argparse.Namespace(output=node.base/'native-actions',public=a.public,image=image));j.socket=node.socket;j.graphics=node.graphics;j.ui=node.ui;j.image=image_id;libinfo,lib=j.trust_stage(libpkg,libname);package_records.append(dict(guest=node.base.name,release_id=libinfo['release_id'],package_sha256=hashlib.sha256(libpkg.read_bytes()).hexdigest(),rights=libinfo['rights']))
   with node.client() as c:c.request(184,struct.pack('<Q',lib));appcall(c,lib,700,data=fid)
   def libword(offset):
    with node.client() as c:return struct.unpack_from('<Q',appcall(c,lib,701)[1],offset)[0]
   node.ui.press(60);node.ui.press(2);node.ui.press(28)
   def authenticated():
    with node.client() as c:return network.status(c,0)['endpoint_authenticated']
   wait(authenticated,300,'native registry connect')
   with registry.client() as c:library_peer.call(c,peer,402,0);library_peer.call(c,peer,400,0,1,1,0,16777216,100000,identity+bytes.fromhex(details['service_id'])+fid)
   node.ui.press(59);node.ui.press(16);wait(lambda:libword(16)==1,300,'real Library Game catalog')
   node.ui.press(62);node.ui.press(23)
   def picker():return rendered_text(node.ui.frame(),32,107,len('crate-workshop-1'))=='crate-workshop-1'
   wait(picker,120,'native game Project picker');node.ui.press(28);wait(lambda:rendered_text(node.ui.frame(),16,12,8)=='SIGNED P',300,'actual signed Game approval');node.ui.press(28)
   def game_running():
    with node.client() as c:
     table=c.request(2);matches=[struct.unpack_from('<Q',table,i)[0] for i in range(7*32,len(table),32) if struct.unpack_from('<Q',table,i+16)[0]==795 and 0<struct.unpack_from('<Q',table,i+8)[0]<5];return matches[0] if matches else None
   game=wait(game_running,120,'Library selected native game installation')
   def focus_library():
    for _ in range(4):
     if rendered_text(node.ui.frame(),12,58,13)=='LEMMA LIBRARY':return
     node.ui.chord(56,15);time.sleep(.4)
    raise AssertionError('Library native focus not visible')
   def focus_game():
    for _ in range(4):
     if rendered_text(node.ui.frame(),8,56,14)=='CRATE WORKSHOP':return
     node.ui.chord(56,15);time.sleep(.4)
    raise AssertionError('game native focus not visible')
   focus_library();node.ui.press(36);wait(lambda:libword(168)==game,30,'exact release game binding')
   return node,j,lib,game,libword,focus_library,focus_game
  personal,j,lib,game,word,focus_library,focus_game=boot_personal('personal')
  focus_game();personal.ui.press(32);personal.ui.press(32)
  def played(node,game):
   with node.client() as c:return game_state(c,game)
  wait(lambda:played(personal,game)['won']==1,30,'real native game win');focus_library();personal.ui.press(37)
  def selected_save():
   with personal.client() as c:return struct.unpack_from('<Q',appcall(c,lib,703,0,96,8)[1])[0]
  save=wait(selected_save,30,'Library K selected save')
  with personal.client() as c:before=struct.unpack_from('<8Q',c.request(202,struct.pack('<8Q',202,0,3,0,0,0,0,1)));require(before[2]==0,'ephemeral K unexpectedly retained a save')
  personal.ui.press(48);wait(lambda:rendered_text(personal.ui.frame(),16,16,7)=='TRUSTED',300,'native trusted save approval');frame=personal.ui.frame();(out/'save-approval.ppm').write_bytes(frame.ppm())
  # Cancel the first request and prove that snapshot alone plus a rejected
  # approval does not change the encrypted domain's committed generation.
  personal.ui.press(1);wait(lambda:word(176)==21,30,'save cancellation')
  with personal.client() as c:cancelled=struct.unpack_from('<8Q',c.request(202,struct.pack('<8Q',202,0,3,0,0,0,0,1)));require(cancelled[7]==before[7] and cancelled[2]==0,'cancelled save persisted')
  wait(lambda:rendered_text(personal.ui.frame(),12,58,13)=='LEMMA LIBRARY',120,'cancelled approval visibly dismissed')
  personal.ui.press(48);wait(lambda:rendered_text(personal.ui.frame(),16,16,7)=='TRUSTED',300,'second native save approval');personal.ui.press(28);wait(lambda:rendered_text(personal.ui.frame(),12,58,13)=='LEMMA LIBRARY',300,'save approval mutation completed and dismissed');wait(lambda:word(176)==17,300,'native save retention completion')
  with personal.client() as c:
   retained=c.request(202,struct.pack('<8Q',202,0,3,0,0,0,0,1));require(struct.unpack_from('<Q',retained,16)[0]==192,'retained save length differs');save_sha=retained[64:96].hex()
  passed('Library I/J/K/B and physical Enter retain only selected typed game save',state=played(personal,game),save_sha256=save_sha,save_bytes=192,cancel_left_ephemeral=True,save_handle_before_restart=save)
  personal.stop();personal,j,lib,game,word,focus_library,focus_game=boot_personal('restarted')
  require(played(personal,game)['won']==0,'fresh game unexpectedly inherited progress')
  personal.ui.press(49);wait(lambda:rendered_text(personal.ui.frame(),16,16,7)=='TRUSTED',300,'native trusted recovery approval');frame=personal.ui.frame();(out/'save-recovery-approval.ppm').write_bytes(frame.ppm());personal.ui.press(28);wait(lambda:rendered_text(personal.ui.frame(),12,58,13)=='LEMMA LIBRARY',300,'recovery approval mutation completed and dismissed');wait(lambda:word(176)==61,300,'Library approved save recovery');personal.ui.press(38);wait(lambda:played(personal,game)['won']==1,120,'Library L loads exact recovered save')
  focus_game();j.wait_text(280,280,'SOLVED - choose another level');(out/'recovered-native-game.ppm').write_bytes(personal.ui.frame().ppm())
  passed('fresh Library N/Enter/L and fresh execution approval recover exact compatible progress',state=played(personal,game),save_sha256=save_sha,stale_capabilities_reused=False,network_session_reauthenticated=True)
  if a.mod:
   focus_library();personal.ui.press(50);wait(lambda:rendered_text(personal.ui.frame(),32,107,len('crate-workshop-1'))=='crate-workshop-1',60,'M trusted project picker');personal.ui.press(28)
   wait(lambda:rendered_text(personal.ui.frame(),16,176,len('assets/near-goal.ltlevels'))=='assets/near-goal.ltlevels',60,'native bounded Source mod choices');personal.ui.press(28)
   expected=hashlib.sha256((ROOT/'resources/crate-workshop/near-goal.ltlevels').read_bytes()).hexdigest();wait(lambda:played(personal,game)['pack']==expected,60,'native M scoped Source pack handoff');focus_game();personal.ui.press(32);wait(lambda:played(personal,game)['won']==1,30,'actual modded puzzle win');require(played(personal,game)['moves']==1,'M did not change actual target')
   focus_library();personal.ui.press(38);wait(lambda:word(176)==42,30,'explicit old-save pack incompatibility');require(played(personal,game)['pack']==expected and played(personal,game)['moves']==1,'incompatible old save destroyed mod progress');focus_game();personal.ui.press(50);focus_library();personal.ui.press(38);wait(lambda:played(personal,game)['won']==1 and played(personal,game)['moves']==2,30,'original pack compatible prior save reload')
   passed('Library M explicitly selects Source data that changes gameplay; incompatible save is refused and remains recoverable',mod_sha256=expected,modified_win_moves=1,prior_save_recovered_moves=2,arbitrary_execution_authority=False)
 except BaseException as error:
  preserve_failure(guests,out,error)
  if a.keep_running:guests=[]
  raise
 finally:
  for node in reversed(guests):
   if node.proc.poll() is None:node.stop()
if __name__=='__main__':main()
