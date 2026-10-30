"""Native game input, scoped mods/saves, malformed rejection and generation parity.

Uses presented framebuffer pixels, hardware keyboard input, and public Objects /
app protocols only. No game buffer, code, private memory or fixture state writes.
"""
import argparse,hashlib,json,struct,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import live,project_vault,releases
from creator_journey import Journey,require,rendered_text

def app(c,instance,op,h=0):
 raw=c.request(150,struct.pack('<Q8Q',instance,op,h,0,0,0,0,0,1))
 require(len(raw)>=64,'short game response');return struct.unpack_from('<8Q',raw),raw[64:]
def state(c,instance):
 fields,data=app(c,instance,500);require(fields[0]==0 and len(data)==96,'game inspection failed')
 boxes,player,save,notice=struct.unpack_from('<4Q',data,64)
 return dict(generation=fields[1],level=fields[2],moves=fields[3],completed=fields[4],won=fields[5],undo=fields[6],game=data[:32].hex(),pack=data[32:64].hex(),boxes=boxes,player=player,save=save,notice=notice)
def scoped(c,instance,data):
 original=c.import_object(data,2);return c.objects(6,original,instance,1)[0][1]

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path);p.add_argument('--game',type=Path,required=True);p.add_argument('--game-v2',type=Path,required=True);p.add_argument('--public',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--vault',type=Path);p.add_argument('--vault-key',type=Path);p.add_argument('--issuer-boundary',action='store_true');a=p.parse_args();a.output=a.output.resolve();j=Journey(a)
 def trust_game(path):
  info=releases.inspect(path.read_bytes());publication=bytes.fromhex(info['project_id'])
  with j.client() as c:
   before={struct.unpack_from('<Q',c.request(2),i)[0] for i in range(7*32,12*32,32)}
   c.request(10,publication+releases.public_modulus(a.public));c.stage(path)
  old=j.ui.frame().digest;j.ui.press(88);j.ui.wait_frame(old);time.sleep(.5);j.ui.press(28);time.sleep(2)
  with j.client() as c:
   active=c.request(29,publication);require(active[160:192].hex()==info['release_id'],'GUI exact game release activation')
   processes=c.request(2);running=[struct.unpack_from('<4Q',processes,i) for i in range(7*32,len(processes),32)]
   running=[row for row in running if 0<row[1]<5 and row[0] not in before];require(len(running)==1,'new native game did not start')
  return info,running[0][0]
 def current(instance):
  with j.client() as c:return state(c,instance)
 def press(code,instance,predicate):
  j.ui.press(code);deadline=time.monotonic()+30
  while True:
   s=current(instance)
   if predicate(s):return s
   if time.monotonic()>deadline:raise TimeoutError(('native key did not change expected state',code,s))
   time.sleep(.1)
 def screenshot(name):
  frame=j.ui.frame();(a.output/name).write_bytes(frame.ppm());return frame.digest
 try:
  j.boot(bool(a.vault));first,game=trust_game(a.game);j.wait_text(8,56,'CRATE WORKSHOP')
  start=current(game);require(start['moves']==0 and start['player']==26 and start['won']==0,'initial original board differs')
  press(32,game,lambda s:s['moves']==1);solved=press(32,game,lambda s:s['won']==1)
  require(solved['boxes']==536870912 and solved['completed']==1,'actual pushed crate or completion differs')
  j.wait_text(280,280,'SOLVED - choose another level')
  j.passed('original native level solved with actual keyboard and rendered win',release=first['release_id'],state=solved,frame=screenshot('level1-solved.ppm'))
  undo=press(22,game,lambda s:s['moves']==1 and not s['won']);require(undo['boxes']==268435456,'undo did not restore box')
  press(19,game,lambda s:s['moves']==0 and s['player']==26)
  press(4,game,lambda s:s['level']==2)
  for code in (30,17,31,32,32,17):j.ui.press(code);time.sleep(.15)
  deadline=time.monotonic()+30
  while not current(game)['won']:
   if time.monotonic()>deadline:raise TimeoutError(('level3 actual keyboard sequence failed',current(game)))
   time.sleep(.1)
  j.passed('multiple original levels, undo, reset and level selection',state=current(game),frame=screenshot('level3-solved.ppm'))
  press(2,game,lambda s:s['level']==0 and not s['won'])
  with j.client() as c:
   mod=(ROOT/'resources/crate-workshop/near-goal.ltlevels').read_bytes();grant=scoped(c,game,mod);require(app(c,game,501,grant)[0][0]==0,'valid scoped mod denied')
  modified=press(32,game,lambda s:s['won']==1);require(modified['moves']==1 and modified['pack']==hashlib.sha256(mod).hexdigest(),'mod bytes did not affect gameplay')
  j.passed('scoped level-pack changes real gameplay from two pushes to one',state=modified,frame=screenshot('data-mod-solved.ppm'))
  with j.client() as c:
   fields,_=app(c,game,502);require(fields[0]==0,'game save export failed');saved=fields[1];save=c.read_object(saved)
   require(len(save)==192 and save[48:80]==bytes.fromhex(modified['pack']),'save does not bind actual pack')
   before=state(c,game)
   if a.issuer_boundary:
    require(app(c,game,503,before['save'])[0][0]!=0,'caller reused game-owned numeric save handle without issuing a read scope')
    require(state(c,game)['boxes']==before['boxes'],'issuer rejection changed progress')
   malformed=bytearray(mod);struct.pack_into('<Q',malformed,48,9)
   require(app(c,game,501,scoped(c,game,malformed))[0][0]!=0,'oversized pack count accepted')
   after=state(c,game);require(after['boxes']==before['boxes'] and after['pack']==before['pack'],'invalid pack changed current gameplay')
   for offset,value in [(8,2),(80,3),(88,99),(104,0),(112,64)]:
    invalid=bytearray(save);struct.pack_into('<Q',invalid,offset,value)
    require(app(c,game,503,scoped(c,game,invalid))[0][0]!=0,'malformed/incompatible save accepted')
   wrong=bytearray(save);wrong[48]^=1
   require(app(c,game,503,scoped(c,game,wrong))[0][0]!=0,'wrong-pack save accepted')
   require(state(c,game)['boxes']==before['boxes'],'save rejection overwrote valid progress')
  j.passed('typed bounded saves reject malformed versions, positions, counts and pack identity',save_sha256=hashlib.sha256(save).hexdigest(),save_bytes=len(save),retained=False)
  second,new_game=trust_game(a.game_v2);require(current(new_game)['generation']==2,'second artifact did not visibly change generation')
  with j.client() as c:
   require(app(c,new_game,501,scoped(c,new_game,mod))[0][0]==0,'v2 mod denied')
   require(app(c,new_game,503,c.objects(6,saved,new_game,1)[0][1])[0][0]==0,'compatible v1 save denied by v2')
   v2=state(c,new_game);require(v2['won']==1 and v2['moves']==1,'v2 did not recover progress')
   v2_save=app(c,new_game,502)[0][1];raw=c.read_object(v2_save);require(struct.unpack_from('<Q',raw,80)[0]==2,'new save does not name v2 producer')
  # Rollback is a real trusted lifecycle action, separate from selecting a save.
  j.ui.chord(56,67);time.sleep(.5);j.ui.press(48);time.sleep(.5);j.ui.press(1)
  with j.client() as c:
   active=c.request(29,bytes.fromhex(first['project_id']));require(active[160:192].hex()==first['release_id'],'explicit rollback did not restore generation1 package')
   require(app(c,game,503,c.objects(6,v2_save,game,1)[0][1])[0][0]==0,'rollback generation refused compatible v2 save')
   require(state(c,game)['won']==1,'rollback lost progress')
  j.passed('real second game generation and explicit native rollback preserve compatible progress',release2=second['release_id'],parent=second['parent'],v2_state=v2,rolled_back=first['release_id'],v2_save_sha256=hashlib.sha256(raw).hexdigest())
  if a.vault:
   require(a.vault_key is not None,'vault key needed for explicit test retain')
   with j.client() as c:
    project_vault.unlock(c,a.vault_key.read_bytes());retained=c.request(203,struct.pack('<Q',v2_save));require(struct.unpack_from('<Q',retained)[0]==0,'approved exact save retain failed')
   j.passed('explicit selected save retained through existing encrypted Objects-vault',sha256=hashlib.sha256(raw).hexdigest())
   j.stop();j.boot(True)
   with j.client() as c:
    project_vault.unlock(c,a.vault_key.read_bytes());fresh=c.request(207);require(struct.unpack_from('<Q',fresh)[0]==0,'save recovery failed');restored=struct.unpack_from('<Q',fresh,8)[0];require(c.read_object(restored)==raw,'recovered save bytes differ')
    try:c.objects(5,v2_save)
    except ValueError:pass
    else:raise AssertionError('old save capability survived restart')
   _,fresh_game=trust_game(a.game)
   with j.client() as c:
    require(app(c,fresh_game,501,scoped(c,fresh_game,mod))[0][0]==0,'fresh mod not accepted')
    require(app(c,fresh_game,503,c.objects(6,restored,fresh_game,1)[0][1])[0][0]==0,'fresh save read grant not accepted')
    require(state(c,fresh_game)['won']==1,'approved restart save not played')
   j.passed('restart recovers exact approved save with fresh authority and compatible rollback game',frame=screenshot('recovered-save.ppm'))
  j.stop()
 finally:
  if j.proc and j.proc.poll() is None:j.stop(hard=True)
if __name__=='__main__':main()
