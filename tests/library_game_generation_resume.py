"""Finish an identified live native update/rollback after a picker test timing issue."""
import argparse,hashlib,json,struct,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import federation,releases
from creator_journey import require,rendered_text
from crate_game import state,app
from library_journey import appcall,wait
from library_native_resume import Existing,instances
from library_game_generations import pick_project
from native_responsive import NativeResponsive

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--base',type=Path,required=True);p.add_argument('--editions',type=Path,required=True);a=p.parse_args();out=a.base.resolve();personal=Existing(out/'personal',True);registry=Existing(out/'registry');lib=instances(personal,1919)[0];report=json.loads((out/'journey.json').read_text());editions=[]
 for index in (1,2):
  archive=json.loads((a.editions/f'game{index}-closure.json').read_text());pkg=a.editions/f'game{index}/crate-workshop.ltrel';editions.append((archive,pkg,releases.inspect(pkg.read_bytes())))
 def passed(label,**facts):
  report['checks'].append(dict(check=label,result='passed',**facts));(out/'journey.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS',label,flush=True)
 def word(offset):
  with personal.client() as c:return struct.unpack_from('<Q',appcall(c,lib,701)[1],offset)[0]
 def row(index,offset,count):
  with personal.client() as c:return appcall(c,lib,703,index,offset,count)[1]
 def current():
  with personal.client() as c:return state(c,game)
 def focus_library():NativeResponsive(personal,game,lib).focus_library()
 def library_surface():return rendered_text(personal.ui.frame(),520,34,16)==f'{lib:016x}' and rendered_text(personal.ui.frame(),12,58,13)=='LEMMA LIBRARY'
 def trusted():return rendered_text(personal.ui.frame(),16,16,7)=='TRUSTED'
 def recover_load(label):
  focus_library();personal.ui.press(49);wait(trusted,300,label+' native N recovery approval');time.sleep(.5);personal.ui.press(28);wait(library_surface,300,label+' approved recovery panel dismissed');wait(lambda:word(176)==61,300,label+' selected typed save recovered');personal.ui.press(38);wait(lambda:current()['won']==1 and current()['moves']==2,120,label+' compatible save actually loaded')
 try:
  require(word(16)==2 and word(8)==1,'live selected actual second consumer differs');require(row(1,1280,32).hex()==editions[1][2]['release_id'],'selected consumer executable differs');pick_project(personal,editions[1][0]['selected'][0]['name'],editions[1][0]['selected'][0]['head']);wait(lambda:rendered_text(personal.ui.frame(),16,12,8)=='SIGNED P',300,'native generation2 executable approval');(out/'game2-approval.ppm').write_bytes(personal.ui.frame().ppm());time.sleep(.5);personal.ui.press(28)
  def matching():
   matches=instances(personal,795)
   for instance in matches:
    with personal.client() as c:s=state(c,instance)
    if s['generation']==2:return instance
  game=wait(matching,180,'actual approved generation2 process');focus_library();personal.ui.press(36);wait(lambda:word(168)==game,60,'J exact selected executable generation2');require(current()['won']==0,'new generation silently inherited progress');recover_load('generation2');passed('newly admitted Library generation2 installs with separate approval and loads compatible prior progress',release=editions[1][2]['release_id'],parent=editions[1][2]['parent'],state=current(),prior_save_sha256=report['checks'][0]['save_sha256'],resumed_picker_test_with_exact_presented_head=True)
  personal.ui.press(37);save=wait(lambda:struct.unpack('<Q',row(1,96,8))[0],60,'K native generation2 snapshot')
  with personal.client() as c:
   exported=app(c,game,502)[0];require(exported[0]==0,'current exact snapshot inspection denied');raw=c.read_object(exported[1])
  require(len(raw)==192 and struct.unpack_from('<Q',raw,80)[0]==2,'actual new save does not bind producer2');new_sha=hashlib.sha256(raw).hexdigest();personal.ui.press(48);wait(trusted,300,'B native generation2 save approval');time.sleep(.5);personal.ui.press(28);wait(library_surface,300,'B generation2 selected commit and modal dismissal');wait(lambda:word(176)==17,300,'B approved producer2 save complete')
  with personal.client() as c:
   inventory=c.request(202,struct.pack('<8Q',202,0,3,0,0,0,0,1));require(inventory[64:96].hex()==new_sha,'approved producer2 save differs');catalog=[]
   for slot in range(16):
    try:rec=c.request(13,struct.pack('<Q',slot))
    except ValueError:continue
    if len(rec)==512:catalog.append(rec)
  chosen=next(i for i,record in enumerate(catalog) if record[160:192].hex()==editions[0][2]['release_id']);personal.ui.chord(56,67);wait(lambda:rendered_text(personal.ui.frame(),8,8,7)=='TRUSTED',180,'native trusted generation controls')
  for index in range(chosen):
   old=personal.ui.frame().digest;personal.ui.press(108);personal.ui.wait_frame(old);time.sleep(.5)
  (out/'rollback-selection.ppm').write_bytes(personal.ui.frame().ppm());time.sleep(.5);personal.ui.press(48)
  def rolled_back():
   with personal.client() as c:return c.request(29,bytes.fromhex(editions[0][2]['project_id']))[160:192].hex()==editions[0][2]['release_id']
  wait(rolled_back,180,'actual trusted rollback selects previous executable');personal.ui.press(1);focus_library();personal.ui.press(103);wait(lambda:word(8)==0,60,'native prior consumer edition selected')
  game=next(instance for instance in instances(personal,795) if inspect(personal,instance)['generation']==1);personal.ui.press(36);wait(lambda:word(168)==game,60,'J exact rollback executable binding');recover_load('rollback generation1');require(current()['generation']==1,'wrong executable after rollback');NativeResponsive(personal,game,lib).focus_game();wait(lambda:rendered_text(personal.ui.frame(),280,280,29)=='SOLVED - choose another level',60,'actual rollback game win rendered');(out/'rolled-back-compatible-save.ppm').write_bytes(personal.ui.frame().ppm());passed('explicit native rollback and Library N/Enter/L load approved producer2 save without deleting coherent progress',rolled_back=editions[0][2]['release_id'],approved_producer=2,state=current(),save_sha256=new_sha,prior_save_sha256=report['checks'][0]['save_sha256'],schema=1,pack_compatible=True);personal.stop();registry.stop()
 finally:
  if personal.ui:personal.ui.close()
def inspect(node,instance):
 with node.client() as c:return state(c,instance)
if __name__=='__main__':main()
