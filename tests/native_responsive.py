"""Observed game/input and Objects service progress during real content jobs.

This helper consumes the test's existing guest/UI connection. It never opens a
second QMP connection, edits guest memory, or treats a paused transfer as work.
An overlap check passes only if the same authoritative job is active both
before and after the completed native input and unrelated Objects request.
"""
import hashlib,struct,time
from pathlib import Path
import releases
from creator_journey import require,rendered_text
from crate_game import state
from library_journey import appcall,wait


class NativeResponsive:
 def __init__(self,node,game,library):
  self.node=node;self.game=game;self.library=library;self.observations=[]

 @classmethod
 def install(cls,node,package,public,library):
  package=Path(package);raw=package.read_bytes();info=releases.inspect(raw)
  with node.client() as c:
   before=c.request(2);known={struct.unpack_from('<Q',before,i)[0] for i in range(0,len(before),32)}
   c.request(10,bytes.fromhex(info['project_id'])+releases.public_modulus(public));c.stage(package)
  node.ui.press(88)
  wait(lambda:rendered_text(node.ui.frame(),16,12,8)=='SIGNED P',180,'responsive game trusted approval')
  node.ui.press(28)
  def running():
   with node.client() as c:
    table=c.request(2)
    for i in range(7*32,len(table),32):
     instance,phase,rights,_=struct.unpack_from('<4Q',table,i)
     if instance not in known and 0<phase<5 and rights==795:return instance
  game=wait(running,180,'responsive native game installed')
  result=cls(node,game,library);result.release=info['release_id'];result.focus_game();return result

 def current(self):
  with self.node.client() as c:return state(c,self.game)

 def focus(self,x,y,title):
  target=self.game if title=='CRATE WORKSHOP' else self.library
  expected=f'{target:016x}'
  for _ in range(6):
   frame=self.node.ui.frame();current=rendered_text(frame,520,34,16)
   if current==expected:
    wait(lambda:rendered_text(self.node.ui.frame(),x,y,len(title))==title,60,'focused native surface repaint: '+title);return
   self.node.ui.chord(56,15)
   wait(lambda:rendered_text(self.node.ui.frame(),520,34,16)!=current,30,'trusted focus incarnation changed')
  raise AssertionError('native focus missing: '+title)

 def focus_game(self):self.focus(8,56,'CRATE WORKSHOP')
 def focus_library(self):self.focus(12,58,'LEMMA LIBRARY')

 def hash_status(self,index=0):
  with self.node.client() as c:
   fields,data=appcall(c,self.library,708,index)
   if fields[0]!=0 and not data:return dict(status=fields[0],operation=0,state=0,progress=0,total=0,error=0,kind=0,schema=1)
   require(fields[0]==0 and len(data)==64,'Library708 must return the exact scoped Content304 result')
   result=struct.unpack('<8Q',data)
   return dict(status=result[0],operation=result[1],state=result[2],progress=result[3],total=result[4],error=result[5],kind=result[6],schema=result[7],progress_unit='SHA256 blocks' if result[6]==1 else 'manifest index entries',total_unit='stored chunk bytes; not cursor bound')

 def persistence_status(self):
  with self.node.client() as c:
   raw=c.request(241,struct.pack('<8Q',241,0,3,0,0,0,0,1));require(len(raw)==80,'short actual Vault241')
   fields=struct.unpack('<10Q',raw)
   return dict(status=fields[0],operation=fields[1],state=fields[2],progress=fields[3],total=fields[4],generation=fields[5],error=fields[6],schema=fields[7])

 def attempt(self,label,snapshot,key=32,expect_moves=1,active_state=2):
  """Return the measurements; never label a missed active interval a pass."""
  before=snapshot();started=time.monotonic()
  if before['status']!=0 or before['state']!=active_state:return None
  self.node.ui.press(key)
  played=wait(lambda:(s if (s:=self.current())['moves']==expect_moves else None),45,'actual game input during '+label)
  payload=('independent Objects read during '+label+' '+str(started)).encode()
  with self.node.client() as c:
   h=c.import_object(payload,2);actual=c.read_object(h);c.objects(8,h)
  require(actual==payload,'unrelated Objects request returned different bytes')
  after=snapshot()
  same=before['operation']==after['operation']
  active=after['status']==0 and after['state']==active_state
  observed=dict(work=label,before=before,after=after,same_operation=same,active_after=active,game=played,objects_sha256=hashlib.sha256(actual).hexdigest(),seconds=time.monotonic()-started,overlap_passed=same and active)
  self.observations.append(observed);return observed

 def hashing(self,seconds=900,index=0):
  self.focus_game();deadline=time.monotonic()+seconds
  while time.monotonic()<deadline:
   before=self.hash_status(index)
   if before['status']==0 and before['state']==2:
    if self.current()['moves']!=0:self.node.ui.press(19);wait(lambda:self.current()['moves']==0,30,'reset between responsiveness attempts')
    result=self.attempt('content integrity validation',lambda:self.hash_status(index))
    if result and result['overlap_passed']:return result
   time.sleep(.05)
  raise TimeoutError('no observed input/Objects completion inside one active integrity job; observations='+repr(self.observations))

 def persisting(self,seconds=300):
  self.focus_game()
  if self.current()['moves']!=1:
   self.node.ui.press(19);wait(lambda:self.current()['moves']==0,30,'persistence game reset');self.node.ui.press(32);wait(lambda:self.current()['moves']==1,30,'first real push')
  wait(lambda:self.persistence_status()['state']==1,seconds,'actual active selected-content persistence')
  result=self.attempt('encrypted selected content persistence',self.persistence_status,expect_moves=2,active_state=1)
  require(result is not None and result['overlap_passed'],'persistence completed outside observed input/Objects interval: '+repr(result))
  require(result['game']['won']==1,'second native push did not solve the real game')
  return result
