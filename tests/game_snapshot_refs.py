"""Actual Game1.4 snapshots retire cached references and preserve old readers.

A held immutable reader must stay byte-exact while more than eight newly allocated
captures after native state changes succeed. Temporary inspection references are explicitly
released through Objects47; no private memory or game state setters are used.
"""
import argparse,hashlib,json,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import releases
from creator_journey import Journey,require
from crate_game import app,state
from library_journey import wait


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,required=True);p.add_argument('--game',type=Path,required=True);p.add_argument('--public',type=Path,default=ROOT/'build/campaign005/publisher.pub');p.add_argument('--snapshots',type=int,default=40);p.add_argument('--output',type=Path,required=True);a=p.parse_args();require(8<a.snapshots<=128,'snapshot count must exceed old eight-record quota and remain bounded');a.output=a.output.resolve();a.output.mkdir(exist_ok=False);j=Journey(a);success=False;info=releases.inspect(a.game.read_bytes(),releases.public_modulus(a.public));require(info['version']=='1.4.0' and info['parent']=='3a56b13d0e211adf25e66d05c09dedc48506c84cb4fe328af8295b3460be7779','unexpected actual save-reference successor');samples=[]
 try:
  j.boot(False)
  # Canonical native publication identity differs from the logical game ID.
  # Trust the exact signed publication, then approve via physical F12/Enter.
  with j.client()as c:c.request(10,bytes.fromhex(info['project_id'])+releases.public_modulus(a.public));c.stage(a.game)
  old=j.ui.frame().digest;j.ui.press(88);j.ui.wait_frame(old)
  import time
  time.sleep(.5);j.ui.press(28)
  def approved():
   with j.client()as c:
    rows=c.request(2);found=[struct.unpack_from('<Q',rows,i)[0]for i in range(7*32,len(rows),32)if struct.unpack_from('<Q',rows,i+16)[0]==795 and 0<struct.unpack_from('<Q',rows,i+8)[0]<5]
    if not found:return None
    require(len(found)==1,'ambiguous approved native Game');require(c.request(29,bytes.fromhex(info['project_id']))[160:192].hex()==info['release_id'],'native approval selected another release');return found[0]
  game=wait(approved,180,'physical exact native Game approval');j.wait_text(8,56,'CRATE WORKSHOP');j.ui.press(32);j.ui.press(32)
  def current():
   with j.client()as c:return state(c,game)
  wait(lambda:current()['moves']==2 and current()['won']==1,60,'actual first native puzzle win')
  with j.client()as c:
   fields,_=app(c,game,502);require(fields[0]==0,'first actual save export failed');held=fields[1];original=c.read_object(held);require(len(original)==192 and struct.unpack_from('<Q',original,80)[0]==2,'first selected save schema/producer differs');baseline=c.objects(10)[0]
  cached=current()['save']
  for i in range(a.snapshots):
   j.ui.press(19);wait(lambda:current()['moves']==0 and not current()['won'],60,'actual native reset')
   if i%2:j.ui.press(32);wait(lambda:current()['moves']==1,60,'actual native one-push board')
   with j.client()as c:
    fields,_=app(c,game,502);require(fields[0]==0,'new native snapshot hit the old owner-record leak');temporary=fields[1];payload=c.read_object(temporary);after=state(c,game);require(after['save']!=cached,'changed board reused its previous cached save');cached=after['save'];require(c.read_object(held)==original,'retiring cached owner destroyed an existing reader');c.objects(47,temporary);require(c.objects(10)[0][1:4]==baseline[1:4],'temporary snapshot inspection references accumulated');samples.append(dict(index=i,moves=after['moves'],save_sha256=hashlib.sha256(payload).hexdigest(),bytes=len(payload),old_reader_still_exact=True))
   # Unchanged state reuses its immutable cached owner; even repeated exported
   # inspection grants return to the same count once released.
   with j.client()as c:
    fields,_=app(c,game,502);require(fields[0]==0 and state(c,game)['save']==cached,'unchanged board did not reuse cached snapshot');c.objects(47,fields[1]);require(c.objects(10)[0][1:4]==baseline[1:4],'unchanged snapshot inspection reference accumulated')
  with j.client()as c:
   require(c.read_object(held)==original,'old reader changed after all later snapshots');c.objects(47,held)
   try:c.objects(5,held)
   except ValueError as error:stale=str(error)
   else:raise AssertionError('released held reference remained usable')
   fields,_=app(c,game,502);require(fields[0]==0,'retiring old reader damaged current snapshot');current_payload=c.read_object(fields[1]);c.objects(47,fields[1]);final=c.objects(10)[0]
  (a.output/'snapshot-history.ppm').write_bytes(j.ui.frame().ppm());result=dict(schema=1,result='passed',image_sha256=hashlib.sha256(a.image.read_bytes()).hexdigest(),game_release=info['release_id'],native_parent=info['parent'],game_instance=game,snapshot_count=a.snapshots,unique_save_payloads=len({x['save_sha256']for x in samples}),unchanged_snapshot_reuses=a.snapshots,preserved_reader_sha256=hashlib.sha256(original).hexdigest(),preserved_reader_bytes=len(original),released_reader_denial=stale,initial_caller_stats=list(baseline),final_caller_stats=list(final),snapshots=samples,current_snapshot_sha256=hashlib.sha256(current_payload).hexdigest(),actual_native_input=True,private_memory_access=False,retention=False,scope='native Game cached owner reference and scoped immutable readers; Library K/N quota flow has separate evidence')
  (a.output/'result.json').write_text(json.dumps(result,indent=2)+'\n');print('PASS actual native snapshot owner retirement and preserved reader',a.snapshots,info['release_id'],flush=True);j.stop();success=True
 finally:
  if not success:j.stop(hard=True)
if __name__=='__main__':main()
