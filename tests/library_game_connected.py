"""Current-image native remote Game acquisition, approved save, update and rollback.

Only the public provider imports Game graphs. Each fresh personal guest receives
metadata/enrollment and existing signed Library/Fetcher packages; native O/I must
fetch the actual Game before trusted execution. Save and recovery use B/N with
physical Enter; update is a real new signed registry record and provider head.
"""
import argparse,base64,contextlib,hashlib,json,socket,struct,subprocess,sys,time,traceback
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import federation,library_peer,live,network,nodes,projects,project_vault,releases
from creator_journey import Journey,require,rendered_text
from crate_game import state as game_state,app as game_call
from library_game_save import Guest
from library_journey import appcall,wait
from library_native_resume import Existing,instances
from library_game_generations import pick_project
from native_responsive import NativeResponsive


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,required=True);p.add_argument('--packages',type=Path,required=True);p.add_argument('--editions',type=Path,default=ROOT/'build/campaign005/game-secure-editions');p.add_argument('--public',type=Path,default=ROOT/'build/campaign005/publisher.pub');p.add_argument('--reference-checks',type=int,default=0,help='bounded repeated native K/N check on generation2 after remote update');p.add_argument('--mod',action='store_true');p.add_argument('--mod-only',action='store_true',help='stop after one fresh remote install and native scoped mod check');p.add_argument('--resume-bootstrap',action='store_true');p.add_argument('--keep-running',action='store_true');p.add_argument('--output',type=Path,required=True);a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=a.resume_bootstrap);image=out/'platform.bin';
 if a.resume_bootstrap:require(image.read_bytes()==a.image.read_bytes(),'resumed selected platform differs')
 else:image.write_bytes(a.image.read_bytes())
 image_id=hashlib.sha256(image.read_bytes()).hexdigest();base=out/'s';personal=None;source=None;success=False;game=0;lib=0;fetch=0;checks=[];packages=[]
 editions=[]
 for i in (1,2):
  archive=json.loads((a.editions/f'game{i}-closure.json').read_text());path=a.editions/f'game{i}/crate-workshop.ltrel';editions.append((archive,path,releases.inspect(path.read_bytes(),releases.public_modulus(a.public))))
 vault=out/'personal.vault';key=out/'personal.key'
 if not a.resume_bootstrap:subprocess.run([str(ROOT/'lt'),'vault-init',str(vault),'--sectors','60000','--key-out',str(key)],cwd=ROOT,check=True)
 report={'image_sha256':image_id,'checks':checks,'packages':packages,'recipient_host_game_import':False,'game_releases':[x[2]['release_id']for x in editions],'limitations':['explicit volatile public provider; no independently operated or durable Game provider claim','explicit development encrypted backing; no physical durability or rollback-freshness claim','focused current-image Game flow; connected media/audio has its own evidence']}
 def passed(label,**facts):
  checks.append(dict(check=label,result='passed',**facts));(out/'journey.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS',label,flush=True)
 def word(offset):
  with personal.client()as c:return struct.unpack_from('<Q',appcall(c,lib,701)[1],offset)[0]
 def row(i,offset,count):
  with personal.client()as c:return appcall(c,lib,703,i,offset,count)[1]
 def current():
  with personal.client()as c:return game_state(c,game)
 def text(x,y,value):return rendered_text(personal.ui.frame(),x,y,len(value))==value
 def library_surface():return rendered_text(personal.ui.frame(),520,34,16)==f'{lib:016x}' and text(12,58,'LEMMA LIBRARY')
 def focus_library():
  if game:NativeResponsive(personal,game,lib).focus_library();return
  for _ in range(6):
   old=rendered_text(personal.ui.frame(),520,34,16)
   if old==f'{lib:016x}':wait(library_surface,60,'actual Library repaint');return
   personal.ui.chord(56,15);wait(lambda:rendered_text(personal.ui.frame(),520,34,16)!=old,60,'actual Library focus')
  raise AssertionError('native Library absent')
 def select(index):
  focus_library()
  while word(8)!=index:
   old=word(8);personal.ui.press(108 if old<index else 103);wait(lambda:word(8)!=old,60,'native consumer edition selection')
 def scope(slot,head=None,root=None):
  with source.client()as c:
   library_peer.call(c,peer,402,slot)
   if slot==0:
    _,desc,_=network.load_description(out/'registry.service');body=desc[64:96]+hashlib.sha256(desc).digest()+fid;library_peer.call(c,peer,400,0,1,1,0,16777216,100000,body)
   else:
    if root is None:root=next(r['cap']for r in projects.roots(c)if r['head']==head)
    handle=c.objects(27,root,peer,1)[0][1];_,desc,_=network.load_description(base/'game.service');raw=bytes.fromhex(head);library_peer.call(c,peer,400,1,3,int.from_bytes(raw[:8],'little')|1,handle,16777216,100000,desc[64:96]+hashlib.sha256(desc).digest()+raw)
 def fresh_server():
  with source.client()as c:
   for slot,credential,description in [(0,out/'registry.server',out/'registry.service'),(1,base/'provider.credential',base/'game.service')]:
    library_peer.call(c,peer,402,slot);network.configure(c,credential,description,slot=slot);wait(lambda slot=slot:network.call(c,13,slot=slot,allow_error=True)[0][0]==0,60,'fresh provider listen')
 def boot(name):
  nonlocal personal,lib,fetch,game
  game=0;personal=Guest(name,out,image,vault);path=a.packages/'library-registry.ltrel';raw=path.read_bytes();info=releases.inspect(raw)
  with personal.client()as c:
   verifier=nodes.start_package(c,nodes.approved_package(path,a.public,info['release_id'],2175),raw);federation.configure(c,verifier,base/'federation.pub','consumer',allowed_rights=8191);project_vault.unlock(c,key.read_bytes());network.configure(c,out/'registry.client',out/'registry.service',slot=0);network.configure(c,base/'reader.credential',base/'game.service',slot=1);c.request(10,bytes.fromhex(editions[0][2]['project_id'])+releases.public_modulus(a.public));require(not projects.roots(c),'fresh recipient contains Game graph preload')
  j=Journey(argparse.Namespace(output=personal.base/'native-actions',public=a.public,image=image));j.socket=personal.socket;j.graphics=personal.graphics;j.ui=personal.ui;j.image=image_id
  for name,rights in [('library-fetch',1151),('library-native',1919)]:
   info,who=j.trust_stage(a.packages/(name+'.ltrel'),name);packages.append(dict(guest=personal.base.name,release=info['release_id'],executable_sha256=info['executable_sha256'],rights=rights));
   if name=='library-fetch':fetch=who
   else:lib=who
  with personal.client()as c:c.request(184,struct.pack('<Q',lib));appcall(c,lib,700,data=fid)
  setup_library()
 def setup_library():
  focus_library()
  for slot in (0,1):
   with personal.client()as c:already=network.status(c,slot)['endpoint_authenticated']
   if already:continue
   personal.ui.press(60);personal.ui.press(slot+2);personal.ui.press(28)
   def authenticated():
    with personal.client()as c:return network.status(c,slot)['endpoint_authenticated']
   wait(authenticated,300,'native provider authentication '+str(slot))
  scope(0);scope(1,editions[0][0]['selected'][0]['head']);personal.ui.press(59);personal.ui.press(16);wait(lambda:word(16)==1,300,'actual signed remote Game catalog');wait(library_surface,60,'Library visible before metadata Add');personal.ui.press(30);wait(lambda:struct.unpack('<Q',row(0,8,8))[0]!=0,60,'native metadata-only Add');personal.ui.press(62);personal.ui.press(2);personal.ui.press(24);wait(lambda:word(528)==fetch,60,'native O selected Fetch binding')
  with personal.client()as c:require(not projects.roots(c),'recipient Game root appeared before native I')
  passed('fresh recipient enrolls registry and seed, Adds signed metadata, binds O and has no Game root before I',recipient=personal.base.name,library=lib,fetch=fetch,recipient_game_roots_before_I=0,fresh_network_authority=True)
 def install(index):
  nonlocal game
  select(index);personal.ui.press(62);personal.ui.press(2);personal.ui.press(23);wait(lambda:word(536)!=0,60,'native I starts selected immutable acquisition');wait(lambda:text(16,12,'SIGNED P'),1200,'remote Game closure validation and trusted execution approval');(out/f'{personal.base.name}-game{index+1}-approval.ppm').write_bytes(personal.ui.frame().ppm())
  before=instances(personal,795)
  with personal.client()as c:
   for who in before:require(game_state(c,who)['generation']!=index+1,'selected generation executed before fresh physical approval')
  time.sleep(.5);personal.ui.press(28)
  def matching():
   for who in instances(personal,795):
    with personal.client()as c:s=game_state(c,who)
    if s['generation']==index+1:return who
  game=wait(matching,180,'actual exact approved native Game');NativeResponsive(personal,game,lib).focus_game();(out/f'{personal.base.name}-game{index+1}-running.ppm').write_bytes(personal.ui.frame().ppm());focus_library();personal.ui.press(36);wait(lambda:word(168)==game,60,'native J exact executable binding')
  with personal.client()as c:active=c.request(29,bytes.fromhex(editions[index][2]['project_id']));require(active[160:192].hex()==editions[index][2]['release_id'],'installed native release differs from selected signed consumer')
  passed('native O/I remotely acquires selected canonical Game and physical Enter approves its exact executable',recipient=personal.base.name,head=editions[index][0]['selected'][0]['head'],nodes=len(editions[index][0]['nodes']),payload_bytes=sum(len(base64.b64decode(r['payload']))for r in editions[index][0]['nodes']),game_release=editions[index][2]['release_id'],game_instance=game,game_not_running_before_approval=True,recipient_host_game_import=False)
 def save(index,producer):
  focus_library();personal.ui.press(37);wait(lambda:struct.unpack('<Q',row(index,96,8))[0],60,'K selected immutable save snapshot')
  with personal.client()as c:
   exported=game_call(c,game,502)[0];require(exported[0]==0,'exact current save inspection denied');raw=c.read_object(exported[1])
  require(len(raw)==192 and struct.unpack_from('<Q',raw,80)[0]==producer,'save producer/schema differs');digest=hashlib.sha256(raw).hexdigest();personal.ui.press(48);wait(lambda:text(16,16,'TRUSTED'),300,'B selected save approval');(out/f'{personal.base.name}-producer{producer}-save-approval.ppm').write_bytes(personal.ui.frame().ppm());time.sleep(.5);personal.ui.press(28);wait(library_surface,300,'save commit panel dismissed');wait(lambda:retained_sha()==digest,300,'B physical Enter selected save commit')
  with personal.client()as c:inv=c.request(202,struct.pack('<8Q',202,0,3,0,0,0,0,1));require(struct.unpack_from('<Q',inv,16)[0]==192 and inv[64:96].hex()==digest,'retained selected save bytes differ')
  passed('native K/B/Enter retains only the selected typed192-byte save',recipient=personal.base.name,producer=producer,save_sha256=digest,state=current());return digest
 def retained_sha():
  with personal.client()as c:inv=c.request(202,struct.pack('<8Q',202,0,3,0,0,0,0,1));return inv[64:96].hex()
 def recover(label,digest):
  prior=struct.unpack('<Q',row(word(8),96,8))[0]
  focus_library();personal.ui.press(49);wait(lambda:text(16,16,'TRUSTED'),300,'N explicit selected save recovery');time.sleep(.5);personal.ui.press(28);wait(library_surface,300,'N recovery panel dismissed');wait(lambda:struct.unpack('<Q',row(word(8),96,8))[0] not in (0,prior),300,'fresh selected save grant');personal.ui.press(38);wait(lambda:current()['won']==1 and current()['moves']==2,120,'L compatible actual saved puzzle state')
  with personal.client()as c:inv=c.request(202,struct.pack('<8Q',202,0,3,0,0,0,0,1));require(inv[64:96].hex()==digest,'recovery selected a different approved snapshot')
  passed(label,recipient=personal.base.name,save_sha256=digest,state=current(),fresh_save_scope=True)
 def reference_checks(count):
  require(32<count<=64,'reference checks must exceed old32-grant quota and stay bounded')
  held=0
  try:
   with personal.client()as c:
    fields,_=game_call(c,game,502);require(fields[0]==0,'held prior reader export failed');held=fields[1];preserved=c.read_object(held)
   snapshots=[]
   for iteration in range(count):
    NativeResponsive(personal,game,lib).focus_game();personal.ui.press(19);wait(lambda:current()['moves']==0 and not current()['won'],60,'reference-check actual Game reset')
    if iteration%2:personal.ui.press(32);wait(lambda:current()['moves']==1,60,'reference-check actual right push')
    focus_library();previous=struct.unpack('<Q',row(1,96,8))[0];personal.ui.press(37);new=wait(lambda:(h if(h:=struct.unpack('<Q',row(1,96,8))[0])not in(0,previous)else 0),60,'native K replaces selected save without leaking old grant')
    with personal.client()as c:require(c.read_object(held)==preserved,'new snapshots destroyed a held immutable reader')
    snapshots.append(dict(iteration=iteration,selected_save_handle=new,moves=current()['moves']))
   passed('more than32 native changed-state K snapshots succeed after remote generation2 update while a prior reader stays byte-exact',iterations=count,held_save_sha256=hashlib.sha256(preserved).hexdigest(),snapshots=snapshots)
   # The retained producer1 save is still the explicitly approved selection.
   # Every N creates a fresh caller grant; replaced references must retire the
   # former Launcher-owned recovery record once no reader holds it.
   baseline=None;recoveries=[]
   for iteration in range(count):
    focus_library();previous=struct.unpack('<Q',row(1,96,8))[0];personal.ui.press(49);wait(lambda:text(16,16,'TRUSTED'),300,'native N selected recovery approval');time.sleep(.5);personal.ui.press(28);wait(library_surface,300,'N physical approval panel dismissed');new=wait(lambda:(h if(h:=struct.unpack('<Q',row(1,96,8))[0])not in(0,previous)else 0),60,'N replaces prior selected recovery grant');personal.ui.press(38);wait(lambda:current()['moves']==2 and current()['won']==1,60,'L actual compatible recovered state')
    with personal.client()as c:
     require(c.read_object(held)==preserved,'N recovery retired a different held reader');stats=c.objects(10)[0]
    if baseline is None:baseline=stats[1:4]
    require(stats[1:4]==baseline,'native repeated N accumulated Launcher-owned records/references');recoveries.append(dict(iteration=iteration,selected_save_handle=new,launcher_owned_records=stats[1],launcher_owned_bytes=stats[2],launcher_grants=stats[3]))
   passed('more than32 physical N/Enter/L recoveries keep Launcher record/byte/grant counts stable and preserve an independent old reader',iterations=count,stable_launcher_stats=list(baseline),recoveries=recoveries,held_save_sha256=hashlib.sha256(preserved).hexdigest())
  finally:
   if held:
    with personal.client()as c:c.objects(47,held)

 try:
  if not a.resume_bootstrap:
   subprocess.run([sys.executable,str(ROOT/'tests/library_graph_provider.py'),'--image',str(image),'--packages',str(a.packages.resolve()),'--archive',str((a.editions/'game1-closure.json').resolve()),'--game',str(editions[0][1].resolve()),'--public',str(a.public.resolve()),'--output',str(base)],cwd=ROOT,check=True)
  source=Existing(base/'provider');provider=json.loads((base/'provider.json').read_text());report['provider']=provider;reg=provider['packages']['library-registry']['instance'];peer=provider['packages']['library-peer']['instance'];fid=hashlib.sha256(releases.public_modulus(base/'federation.pub')).digest();_,seed_description,_=network.load_description(base/'game.service');client_id=seed_description[64:96]
  if not a.resume_bootstrap:
   probe=socket.socket();probe.bind(('127.0.0.1',0));port=probe.getsockname()[1];probe.close();description=out/'registry.service';details=network.create_description(base/'network.pem',client_id,'127.0.0.1:'+str(port),'library-registry',description);network.provision(out/'registry.client',out/'registry.server',client_id,bytes.fromhex(details['server_id']),bytes.fromhex(details['service_id']))
  if a.resume_bootstrap:
   personal=Existing(out/'p1',True);lib=instances(personal,1919)[0];fetch=instances(personal,1151)[0]
   with personal.client()as c:
    require(not projects.roots(c),'bootstrap resume contains unexpected Game payload');c.request(184,struct.pack('<Q',lib));appcall(c,lib,700,data=fid)
   for name in ['library-fetch','library-native']:
    info=releases.inspect((a.packages/(name+'.ltrel')).read_bytes());packages.append(dict(guest='p1',release=info['release_id'],executable_sha256=info['executable_sha256'],rights=info['rights']))
   report['controller_bootstrap_resume']=True;setup_library()
  else:fresh_server();boot('p1')
  install(0);NativeResponsive(personal,game,lib).focus_game();personal.ui.press(32);personal.ui.press(32);wait(lambda:current()['won']==1,60,'actual DD original puzzle win');wait(lambda:text(280,280,'SOLVED - choose another level'),60,'native solved board pixels');(out/'first-remote-game-win.ppm').write_bytes(personal.ui.frame().ppm());first_save=save(0,1);first_instance=game
  if not a.mod_only:
   personal.stop();personal=None;fresh_server();boot('p2');install(0);require(current()['moves']==0 and not current()['won'],'fresh Game inherited unapproved RAM progress');require(game!=first_instance,'old executable incarnation survived restart');recover('fresh personal restart, fresh O/I execution approval and N/Enter/L recover prior approved progress',first_save)
  if a.mod or a.mod_only:
   focus_library()
   with personal.client()as c:root=next(r for r in projects.roots(c)if r['head']==editions[0][0]['selected'][0]['head'])
   personal.ui.press(50);wait(lambda:text(12,10,'TRUSTED PROJECT OPEN'),300,'explicit data-only native picker');require(text(12,50,'ALLOW READ SHARE REVOKE - DATA ONLY'),'M picker did not show exact data-only approval');(out/'mod-data-only-approval.ppm').write_bytes(personal.ui.frame().ppm());pick_project(personal,root['name'],root['head']);wait(lambda:text(16,176,'assets/near-goal.ltlevels'),300,'actual downloaded Source mod choice');time.sleep(.5);personal.ui.press(28);expected=hashlib.sha256((ROOT/'resources/crate-workshop/near-goal.ltlevels').read_bytes()).hexdigest();wait(lambda:current()['pack']==expected,120,'M actual downloaded Source pack');NativeResponsive(personal,game,lib).focus_game();personal.ui.press(32);wait(lambda:current()['won']==1 and current()['moves']==1,60,'one push solves real downloaded mod');focus_library();personal.ui.press(38);wait(lambda:word(176)==42,60,'old pack save explicitly incompatible');NativeResponsive(personal,game,lib).focus_game();personal.ui.press(50);focus_library();personal.ui.press(38);wait(lambda:current()['won']==1 and current()['moves']==2,60,'original pack prior save restored');passed('native M selects a downloaded Source mod, changes gameplay and refuses incompatible save without deleting it',mod_sha256=expected,mod_moves=1,restored_original_moves=2)
  if a.mod_only:
   report['result']='passed';report['targeted_mod_only']=True;report['provider_and_recipient_image_match']=provider['image_sha256']==image_id;(out/'journey.json').write_text(json.dumps(report,indent=2)+'\n');success=True;return
  archive,_,info=editions[1]
  with source.client()as c:
   records=[dict(r,payload=base64.b64decode(r['payload']))for r in archive['nodes']];root=projects.import_records(c,archive['selected'],records)[0]['cap'];federation.call(c,reg,2,h=c.objects(27,root,reg,25)[0][1]);decision=federation.sign_once(c,reg,base/'federation.pem','consumer',8191);require(decision['listing']==5 and decision['release_id']==info['release_id'],'actual second native+consumer admission differs')
  scope(1,archive['selected'][0]['head'],root);focus_library();personal.ui.press(16);wait(lambda:word(16)==2,300,'native Q discovers newly admitted generation2');require(row(1,1280,32).hex()==info['release_id'],'new consumer does not bind exact executable');select(1);personal.ui.press(30);wait(lambda:struct.unpack('<Q',row(1,8,8))[0]!=0,60,'metadata-only Add second edition');old_game=game;install(1);require(current()['generation']==2 and not current()['won'],'new Game did not start separately');recover('actually newly admitted/downloaded generation2 loads compatible approved prior save',first_save)
  if a.reference_checks:reference_checks(a.reference_checks)
  second_save=save(1,2)
  with personal.client()as c:
   catalog=[]
   for slot in range(16):
    try:record=c.request(13,struct.pack('<Q',slot))
    except ValueError:continue
    if len(record)==512:catalog.append(record)
  chosen=next(i for i,r in enumerate(catalog)if r[160:192].hex()==editions[0][2]['release_id']);personal.ui.chord(56,67);wait(lambda:text(8,8,'TRUSTED'),180,'trusted native generation controls')
  for i in range(chosen):
   old=personal.ui.frame().digest;personal.ui.press(108);personal.ui.wait_frame(old);time.sleep(.5)
  (out/'native-rollback-choice.ppm').write_bytes(personal.ui.frame().ppm());time.sleep(.5);personal.ui.press(48)
  def rolled():
   with personal.client()as c:return c.request(29,bytes.fromhex(editions[0][2]['project_id']))[160:192].hex()==editions[0][2]['release_id']
  wait(rolled,180,'actual native rollback active package');personal.ui.press(1);select(0);game=old_game;personal.ui.press(36);wait(lambda:word(168)==game,60,'J old exact executable after rollback');NativeResponsive(personal,game,lib).focus_game();personal.ui.press(19);wait(lambda:current()['moves']==0 and not current()['won'],60,'explicit reset proves old state is actually reloaded');recover('explicit trusted rollback and J/N/Enter/L load approved producer2 save in actual older Game',second_save);NativeResponsive(personal,game,lib).focus_game();wait(lambda:text(280,280,'SOLVED - choose another level'),60,'rollback compatible win rendered');(out/'rollback-recovered-producer2.ppm').write_bytes(personal.ui.frame().ppm());report['result']='passed';report['save_sha256']=[first_save,second_save];report['provider_and_recipient_image_match']=provider['image_sha256']==image_id;(out/'journey.json').write_text(json.dumps(report,indent=2)+'\n');success=True
 except BaseException:
  (out/'error.txt').write_text(traceback.format_exc());print(traceback.format_exc(),flush=True)
  if personal:
   try:
    with personal.client()as c:(out/'failure-processes.json').write_text(json.dumps([struct.unpack_from('<4Q',raw,i)for raw in [c.request(2)]for i in range(0,len(raw),32)],indent=2)+'\n')
    if personal.ui:(out/'failure.ppm').write_bytes(personal.ui.frame().ppm())
   except Exception:pass
  raise
 finally:
  if success or not a.keep_running:
   if personal:personal.stop()
   if source:source.stop()
  elif personal and personal.ui:personal.ui.close()
if __name__=='__main__':main()
