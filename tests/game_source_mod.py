"""Actual signed graph Source resource changes the native game's board rules."""
import argparse,base64,hashlib,json,struct,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import projects,releases
from crate_game import app,state
from creator_journey import Journey,require

def main():
 p=argparse.ArgumentParser();p.add_argument('--game',required=True,type=Path);p.add_argument('--public',required=True,type=Path);p.add_argument('--archive',required=True,type=Path);p.add_argument('--output',required=True,type=Path);a=p.parse_args();a.output=a.output.resolve();j=Journey(a)
 try:
  j.boot(False);info=releases.inspect(a.game.read_bytes());publication=bytes.fromhex(info['project_id'])
  with j.client() as c:c.request(10,publication+releases.public_modulus(a.public));c.stage(a.game)
  old=j.ui.frame().digest;j.ui.press(88);j.ui.wait_frame(old);time.sleep(.5);j.ui.press(28);j.wait_text(8,56,'CRATE WORKSHOP')
  with j.client() as c:
   table=c.request(2);game=next(struct.unpack_from('<Q',table,i)[0] for i in range(7*32,len(table),32) if struct.unpack_from('<Q',table,i+16)[0]==795 and struct.unpack_from('<Q',table,i+8)[0]<5)
   archived=json.loads(a.archive.read_text());records=[dict(record,payload=base64.b64decode(record['payload'])) for record in archived['nodes']];root=projects.import_records(c,archived['selected'],records)[0]['cap']
   head=c.objects(24,root)[0][1];entries=projects.decode_manifest(c.read_object(head));identity=next(identity for name,kind,identity in entries if name=='assets/near-goal.ltlevels' and kind==10);resource=projects.resolve(c,root,identity);grant=c.objects(6,resource,game,1)[0][1]
   require(app(c,game,501,grant)[0][0]==0,'selected signed Source mod denied')
  j.ui.press(32);deadline=time.monotonic()+30
  while True:
   with j.client() as c:actual=state(c,game)
   if actual['won']:break
   if time.monotonic()>deadline:raise TimeoutError('graph resource did not change native gameplay')
   time.sleep(.1)
  require(actual['moves']==1,'signed Source mod did not move target');j.wait_text(280,280,'SOLVED - choose another level');frame=j.ui.frame();(a.output/'source-mod.ppm').write_bytes(frame.ppm())
  j.passed('explicit scoped signed graph Source changes actual native gameplay',release=info['release_id'],source_node=identity,resource_kind=10,pack_sha256=actual['pack'],moves=actual['moves'],state=actual,frame=frame.digest,retained=False)
  j.stop()
 finally:
  if j.proc and j.proc.poll() is None:j.stop(hard=True)
if __name__=='__main__':main()
