"""Library-listed native game update and explicit rollback preserve an approved save.

Only canonical signed public graphs are imported at setup. Catalog publication,
native install/recovery approvals, save load/export, and rollback use their real
guest services and physical graphical input. No game state is patched.
"""
import argparse,base64,hashlib,json,os,socket,struct,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import capsule,federation,library_peer,network,nodes,projects,project_vault,releases
from creator_journey import Journey,require,rendered_text
from library_game_save import Guest,preserve_failure
from library_journey import appcall,wait
from library_native_resume import instances
from native_responsive import NativeResponsive
from crate_game import state,app

def pick_project(node,name,head):
 """Select a presented named root and verify its exact displayed commitment."""
 wait(lambda:rendered_text(node.ui.frame(),12,10,20)=='TRUSTED PROJECT OPEN',180,'native trusted Project chooser')
 frame=node.ui.frame();rows=[rendered_text(frame,32,107+i*12,32).rstrip() for i in range(16)];target=rows.index(name);selected=next(i for i in range(16) if rendered_text(frame,16,107+i*12,1)=='>')
 while selected!=target:
  selected=(selected+1)%len([x for x in rows if x]);node.ui.press(108);wait(lambda:rendered_text(node.ui.frame(),16,107+selected*12,1)=='>',60,'actual named Project selection')
 for index,x in enumerate((12,114,216,318)):
  expected=f'{int.from_bytes(bytes.fromhex(head)[index*8:index*8+8],"little"):016x}';require(rendered_text(node.ui.frame(),x,338,16)==expected,'presented Project head differs from selected signed edition')
 # The trusted modal arms physical input only after its presented redraw.
 time.sleep(.5);node.ui.press(28)

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,required=True);p.add_argument('--packages',type=Path,required=True);p.add_argument('--editions',type=Path,default=ROOT/'build/campaign005/game-secure-editions');p.add_argument('--vault',type=Path,required=True);p.add_argument('--vault-key',type=Path,required=True);p.add_argument('--public',type=Path,default=ROOT/'build/campaign005/publisher.pub');p.add_argument('--keep-running',action='store_true');p.add_argument('--output',type=Path,required=True);a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);image=out/'platform.bin';image.write_bytes(a.image.read_bytes());image_id=hashlib.sha256(image.read_bytes()).hexdigest();guests=[];report={'image':image_id,'checks':[],'limitations':['canonical selected public release graphs explicitly imported through Objects; separate remote graph journey covers network transfer','explicit development encrypted backing; no physical durability or rollback freshness claim'],'vault':str(a.vault.resolve()),'packages':[]}
 def passed(label,**facts):
  report['checks'].append(dict(check=label,result='passed',**facts));(out/'journey.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS',label,flush=True)
 editions=[]
 for index in (1,2):
  archive=json.loads((a.editions/f'game{index}-closure.json').read_text());pkg=a.editions/f'game{index}/crate-workshop.ltrel';editions.append((archive,pkg,releases.inspect(pkg.read_bytes())))
 fedkey=out/'federation.pem';fedpub=out/'federation.pub';capsule.generate_key(fedkey,fedpub);fid=hashlib.sha256(releases.public_modulus(fedpub)).digest();identity=hashlib.sha256(os.urandom(32)).digest();private=out/'provider.pem';public=out/'provider.pub';capsule.generate_key(private,public);probe=socket.socket();probe.bind(('127.0.0.1',0));port=probe.getsockname()[1];probe.close();description=out/'registry.service';details=network.create_description(private,identity,'127.0.0.1:'+str(port),'library-registry',description);credentials=[out/'personal.credential',out/'registry.credential'];network.provision(*credentials,identity,bytes.fromhex(details['server_id']),bytes.fromhex(details['service_id']))
 def install(node,path):
  raw=path.read_bytes();info=releases.inspect(raw)
  with node.client() as c:instance=nodes.start_package(c,nodes.approved_package(path,a.public,info['release_id'],info['rights']),raw)
  report['packages'].append(dict(guest=node.base.name,release=info['release_id'],sha256=hashlib.sha256(raw).hexdigest(),rights=info['rights']));return instance
 def graph(c,archive):return projects.import_records(c,archive['selected'],[dict(r,payload=base64.b64decode(r['payload'])) for r in archive['nodes']])[0]['cap']
 try:
  registry=Guest('registry',out,image);personal=Guest('personal',out,image,a.vault.resolve());guests.extend([registry,personal]);reg=install(registry,a.packages/'library-registry.ltrel');peer=install(registry,a.packages/'library-peer.ltrel');verifier=install(personal,a.packages/'library-registry.ltrel')
  for node,instance in [(registry,reg),(personal,verifier)]:
   with node.client() as c:federation.configure(c,instance,fedpub,'consumer',allowed_rights=8191)
  with personal.client() as c:
   project_vault.unlock(c,a.vault_key.read_bytes());before=c.request(202,struct.pack('<8Q',202,0,3,0,0,0,0,1));require(struct.unpack_from('<Q',before,16)[0]==192,'selected pre-existing approved game save not found');prior_sha=before[64:96].hex();c.request(10,bytes.fromhex(editions[0][2]['project_id'])+releases.public_modulus(a.public))
  def admit(index):
   archive,pkg,info=editions[index]
   with registry.client() as c:
    root=graph(c,archive);federation.call(c,reg,3,data=bytes.fromhex(info['project_id'])+releases.public_modulus(a.public));federation.call(c,reg,2,h=c.objects(27,root,reg,25)[0][1]);decision=federation.sign_once(c,reg,fedkey,'consumer',8191);require(decision['listing']==5,'canonical native+consumer release not admitted')
   with personal.client() as c:
    root=graph(c,archive);shell=struct.unpack_from('<Q',c.request(2),4*32)[0];c.objects(27,root,shell,127)
   return decision
  first=admit(0)
  with registry.client() as c:network.configure(c,credentials[1],description,slot=0);wait(lambda:network.call(c,13,slot=0,allow_error=True)[0][0]==0,60,'registry listen')
  with personal.client() as c:network.configure(c,credentials[0],description,slot=0)
  j=Journey(argparse.Namespace(output=personal.base/'native-actions',public=a.public,image=image));j.socket=personal.socket;j.graphics=personal.graphics;j.ui=personal.ui;j.image=image_id;libinfo,lib=j.trust_stage(a.packages/'library-native.ltrel','library-native');report['packages'].append(libinfo)
  with personal.client() as c:c.request(184,struct.pack('<Q',lib));appcall(c,lib,700,data=fid)
  def word(offset):
   with personal.client() as c:return struct.unpack_from('<Q',appcall(c,lib,701)[1],offset)[0]
  def row(index,offset,count):
   with personal.client() as c:return appcall(c,lib,703,index,offset,count)[1]
  def current():
   with personal.client() as c:return state(c,game)
  def library_surface():return rendered_text(personal.ui.frame(),520,34,16)==f'{lib:016x}' and rendered_text(personal.ui.frame(),12,58,13)=='LEMMA LIBRARY'
  def trusted():return rendered_text(personal.ui.frame(),16,16,7)=='TRUSTED'
  def focus_library():
   NativeResponsive(personal,game,lib).focus_library()
  def select(index):
   focus_library()
   while word(8)!=index:
    personal.ui.press(108 if word(8)<index else 103);wait(lambda:word(8)==index,60,'native Library edition row selection')
  personal.ui.press(60);personal.ui.press(2);personal.ui.press(28)
  def authenticated():
   with personal.client() as c:return network.status(c,0)['endpoint_authenticated']
  wait(authenticated,300,'native selected Registry authentication')
  with registry.client() as c:library_peer.call(c,peer,400,0,1,1,0,16777216,100000,identity+bytes.fromhex(details['service_id'])+fid)
  personal.ui.press(59);personal.ui.press(16);wait(lambda:word(16)==1,300,'first canonical listed edition')
  def native_install(index):
   archive,pkg,info=editions[index];personal.ui.press(62);personal.ui.press(23);pick_project(personal,archive['selected'][0]['name'],archive['selected'][0]['head']);wait(lambda:rendered_text(personal.ui.frame(),16,12,8)=='SIGNED P',300,'native executable release approval');(out/f'game{index+1}-approval.ppm').write_bytes(personal.ui.frame().ppm());personal.ui.press(28)
   def matching():
    with personal.client() as c:
     active=c.request(29,bytes.fromhex(info['project_id']))
     if active[160:192].hex()!=info['release_id']:return None
    matches=instances(personal,795)
    for instance in matches:
     with personal.client() as c:
      s=state(c,instance)
     if s['generation']==index+1:return instance
   result=wait(matching,180,'actual approved generation installed/running');NativeResponsive(personal,result,lib).focus_library();personal.ui.press(36);wait(lambda:word(168)==result,60,'J exact selected executable binding');return result
  game=native_install(0)
  def recover_load(label):
   focus_library();personal.ui.press(49);wait(trusted,300,label+' native N recovery approval');personal.ui.press(28);wait(library_surface,300,label+' approved recovery panel dismissed');wait(lambda:word(176)==61,300,label+' selected typed save recovered');personal.ui.press(38);wait(lambda:current()['won']==1 and current()['moves']==2,120,label+' compatible save actually loaded')
  recover_load('generation1');passed('Library installs canonical generation1 and N/Enter/L restores the previously approved save',release=editions[0][2]['release_id'],state=current(),save_sha256=prior_sha,admission=first)
  second=admit(1);focus_library();personal.ui.press(16);wait(lambda:word(16)==2,300,'actually newly published generation2 discovered')
  require(row(1,1280,32).hex()==editions[1][2]['release_id'],'second Library consumer does not bind exact new executable');select(1);game=native_install(1);require(current()['generation']==2 and current()['won']==0,'new generation did not start fresh before selected recovery');recover_load('generation2');passed('newly admitted Library generation2 installs with separate approval and loads compatible prior progress',release=editions[1][2]['release_id'],parent=editions[1][2]['parent'],state=current(),prior_save_sha256=prior_sha,admission=second)
  personal.ui.press(37)
  def snapshot():
   raw=row(1,96,8);return struct.unpack('<Q',raw)[0]
  save=wait(snapshot,60,'generation2 K typed snapshot')
  with personal.client() as c:
   exported=app(c,game,502)[0];require(exported[0]==0,'exact current snapshot inspection denied');raw=c.read_object(exported[1])
  require(len(raw)==192 and struct.unpack_from('<Q',raw,80)[0]==2,'new selected snapshot does not bind producer2');new_sha=hashlib.sha256(raw).hexdigest();personal.ui.press(48);wait(trusted,300,'generation2 B save approval');personal.ui.press(28);wait(library_surface,300,'generation2 B approval panel dismissed');wait(lambda:word(176)==17,300,'generation2 explicitly approved selected save commit')
  with personal.client() as c:
   inventory=c.request(202,struct.pack('<8Q',202,0,3,0,0,0,0,1));require(inventory[64:96].hex()==new_sha,'new save did not commit exact selected bytes');catalog=[]
   for slot in range(16):
    try:rec=c.request(13,struct.pack('<Q',slot))
    except ValueError:continue
    if len(rec)==512:catalog.append(rec)
  chosen=next(i for i,record in enumerate(catalog) if record[160:192].hex()==editions[0][2]['release_id']);personal.ui.chord(56,67);wait(lambda:rendered_text(personal.ui.frame(),8,8,7)=='TRUSTED',180,'native generation controls')
  for index in range(chosen):
   old=personal.ui.frame().digest;personal.ui.press(108);personal.ui.wait_frame(old);time.sleep(.4)
  time.sleep(.5);(out/'rollback-selection.ppm').write_bytes(personal.ui.frame().ppm());personal.ui.press(48)
  def rolled_back():
   with personal.client() as c:return c.request(29,bytes.fromhex(editions[0][2]['project_id']))[160:192].hex()==editions[0][2]['release_id']
  wait(rolled_back,180,'explicit native rollback selects actual previous package');personal.ui.press(1);wait(lambda:rendered_text(personal.ui.frame(),520,34,16)!=f'{0:016x}',60,'native generation panel dismissed');select(0)
  game=next(instance for instance in instances(personal,795) if state_inspect(personal,instance)['generation']==1);personal.ui.press(36);wait(lambda:word(168)==game,60,'J rebind compatible rollback generation1');recover_load('rollback generation1');require(current()['generation']==1,'Library did not bind actual old executable');(out/'rolled-back-compatible-save.ppm').write_bytes(personal.ui.frame().ppm());passed('explicit native rollback and Library N/Enter/L load the approved producer2 save without deleting coherent progress',rolled_back=editions[0][2]['release_id'],approved_producer=2,state=current(),save_sha256=new_sha,prior_save_sha256=prior_sha,schema=1,pack_compatible=True)
 except BaseException as e:
  preserve_failure(guests,out,e)
  if a.keep_running:guests=[]
  raise
 finally:
  for guest in reversed(guests):guest.stop()

def state_inspect(node,instance):
 with node.client() as c:return state(c,instance)
if __name__=='__main__':main()
