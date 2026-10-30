"""Finish a preserved remotely acquired Game session after its optional mod check.

Uses only the live provider/publication, native Library input and public status.
No recipient archive or Game resource import is provided by this continuation.
"""
import argparse,base64,hashlib,json,struct,sys,time,traceback
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import federation,library_peer,network,projects,releases
from creator_journey import require,rendered_text
from crate_game import state as game_state,app as game_call
from library_journey import appcall,wait
from library_native_resume import Existing,instances
from native_responsive import NativeResponsive

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--base',type=Path,required=True);p.add_argument('--editions',type=Path,default=ROOT/'build/campaign005/game-secure-editions');p.add_argument('--public',type=Path,default=ROOT/'build/campaign005/publisher.pub');p.add_argument('--keep-running',action='store_true');a=p.parse_args();out=a.base.resolve();base=out/'s';personal=Existing(out/'p2',True);source=Existing(base/'provider');report=json.loads((out/'journey.json').read_text());provider=report['provider'];image_id=hashlib.sha256((out/'platform.bin').read_bytes()).hexdigest();reg=provider['packages']['library-registry']['instance'];peer=provider['packages']['library-peer']['instance'];lib=instances(personal,1919)[0];game=instances(personal,795)[0];success=False;editions=[];first_save=next(x['save_sha256']for x in report['checks']if x.get('producer')==1)
 for i in (1,2):
  archive=json.loads((a.editions/f'game{i}-closure.json').read_text());path=a.editions/f'game{i}/crate-workshop.ltrel';editions.append((archive,path,releases.inspect(path.read_bytes(),releases.public_modulus(a.public))))
 def passed(label,**facts):
  report['checks'].append(dict(check=label,result='passed',**facts));(out/'journey.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS',label,flush=True)
 fid=hashlib.sha256(releases.public_modulus(base/'federation.pub')).digest()
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
 try:
  require(current()['generation']==1 and current()['won']==1 and current()['moves']==2,'preserved remotely acquired Game/save state differs')
  archive,_,info=editions[1]
  with source.client()as c:
   records=[dict(r,payload=base64.b64decode(r['payload']))for r in archive['nodes']];root=projects.import_records(c,archive['selected'],records)[0]['cap'];federation.call(c,reg,2,h=c.objects(27,root,reg,25)[0][1]);decision=federation.sign_once(c,reg,base/'federation.pem','consumer',8191);require(decision['listing']==5 and decision['release_id']==info['release_id'],'actual second native+consumer admission differs')
  scope(1,archive['selected'][0]['head'],root);focus_library();personal.ui.press(16);wait(lambda:word(16)==2,300,'native Q discovers newly admitted generation2');require(row(1,1280,32).hex()==info['release_id'],'new consumer does not bind exact executable');select(1);personal.ui.press(30);wait(lambda:struct.unpack('<Q',row(1,8,8))[0]!=0,60,'metadata-only Add second edition');old_game=game;install(1);require(current()['generation']==2 and not current()['won'],'new Game did not start separately');recover('actually newly admitted/downloaded generation2 loads compatible approved prior save',first_save);second_save=save(1,2)
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
  (out/'generation-error.txt').write_text(traceback.format_exc());print(traceback.format_exc(),flush=True)
  try:(out/'generation-failure.ppm').write_bytes(personal.ui.frame().ppm())
  except Exception:pass
  raise
 finally:
  if success or not a.keep_running:
   personal.stop();source.stop()
  elif personal.ui:personal.ui.close()
if __name__=='__main__':main()
