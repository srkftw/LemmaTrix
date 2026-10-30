"""Concurrent native Objects import jobs, scoped validation and atomic commit.

The test package is an ordinary127-right caller forwarding public Objects IPC.
The host supplies opaque fixture records and observes actual returned bytes;
validation, scheduling, capabilities and publication execute in the Lean guest.
"""
import argparse,base64,hashlib,json,struct,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import nodes,projects,releases
from crate_game import state
from creator_journey import Journey,require
from library_journey import wait


class Actor:
 def __init__(self,client,instance):self.client=client;self.instance=instance
 def objects(self,op,h=0,a=0,b=0,c=0,d=0,e=0,data=b''):
  inner=struct.pack('<8Q',op,h,a,b,c,d,e,1)+data
  raw=self.client.request(150,struct.pack('<Q8Q',self.instance,900,len(inner),0,0,0,0,0,1)+inner)
  if len(raw)<64:raise ValueError('short Objects response')
  fields=struct.unpack_from('<8Q',raw)
  if fields[0]:raise ValueError('Objects status'+str(fields[0]))
  return fields,raw[64:]
 def import_object(self,data,kind=1,parent=0):
  h=self.objects(1,parent,len(data),kind,1,data=hashlib.sha256(data).digest())[0][1]
  for offset in range(0,len(data),512):self.objects(2,h,offset,data=data[offset:offset+512])
  return self.objects(3,h,data=hashlib.sha256(data).digest())[0][1]
 def read_object(self,h,export=False):
  n=self.objects(5,h)[0][2]
  return b''.join(self.objects(14 if export else 4,h,p,min(512,n-p))[1]for p in range(0,n,512))


def record(kind,payload):
 return dict(kind=kind,payload=payload,id=projects.canonical_node(kind,payload),parent='00'*32)


def graph(name,seed,edges=1,extra=()):
 payload=bytes((i*17+seed)%251 for i in range(65536))
 blob=record(10,payload)
 manifest=record(11,projects.manifest([(f'file{i:02}.bin',10,blob['id'])for i in range(edges)]+list(extra)))
 return [dict(name=name,head=manifest['id'])],[blob,manifest]


def stage(actor,selected,records):
 entries=b''
 for root in selected:
  name=root['name'].encode();entries+=struct.pack('<2Q',0,len(name))+bytes.fromhex(root['head'])+name.ljust(80,b'\0')
 h=actor.objects(35,a=len(selected),b=len(records),c=sum(len(r['payload'])for r in records),data=entries)[0][1]
 for i,r in enumerate(records):
  raw=r['payload'];ids=bytes.fromhex(r['id'])+bytes.fromhex(r.get('parent','00'*32))+hashlib.sha256(raw).digest()
  actor.objects(36,h,i,r['kind'],len(raw),r.get('schema',1),data=ids)
  for offset in range(0,len(raw),512):actor.objects(37,h,i,offset,data=raw[offset:offset+512])
 return h


def denied(call,status=None):
 try:call()
 except ValueError as error:
  if status is not None:require(str(error)=='Objects status'+str(status),'unexpected denial '+str(error))
  return str(error)
 raise AssertionError('operation unexpectedly authorized')


def detail(actor,h):
 fields,data=actor.objects(45,h,1)
 require(len(data)==64,'missing bounded progress detail')
 return fields,struct.unpack('<8Q',data)


def terminal(actor,h,seconds=180):
 def inspect():
  f,data=actor.objects(45,h)
  return (f,data)if f[2]>=4 else None
 return wait(inspect,seconds,'native async import terminal result')


def root(actor,name,payload=b'ordinary concurrent commit'):
 blob,bid=projects.node(actor,payload,10)
 manifest,head=projects.node(actor,projects.manifest([('note.txt',10,bid)]),11)
 encoded=name.encode()
 return actor.objects(22,manifest,0,len(encoded),data=bytes(32)+encoded.ljust(64,b'\0'))[0][1]


def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--image',type=Path,required=True);p.add_argument('--harness',type=Path,default=ROOT/'build/live/apps/import-harness.bin')
 p.add_argument('--game',type=Path,default=ROOT/'build/campaign005/game-secure-editions/game1/crate-workshop.ltrel')
 p.add_argument('--archive',type=Path,default=ROOT/'build/campaign005/game-secure-editions/game1-closure.json')
 p.add_argument('--key',type=Path,default=ROOT/'build/campaign005/publisher.pem');p.add_argument('--public',type=Path,default=ROOT/'build/campaign005/publisher.pub')
 p.add_argument('--output',type=Path,required=True);p.add_argument('--keep-on-failure',action='store_true');a=p.parse_args();a.output=a.output.resolve();a.output.mkdir(exist_ok=False)
 j=Journey(argparse.Namespace(image=a.image,output=a.output/'guest',public=a.public));checks=[];success=False;identities=[]
 def passed(label,**facts):
  checks.append(dict(check=label,result='passed',**facts));print('PASS',label,flush=True)
  (a.output/'progress.json').write_text(json.dumps(dict(image=j.image,checks=checks),indent=2)+'\n')
 def install(c,name):
  raw,_=releases.make(a.harness,name,'1.0.0',127,a.key,profile=2,license='NOASSERTION');path=a.output/(name+'.ltrel');path.write_bytes(raw)
  info=releases.inspect(raw);who=nodes.start_package(c,nodes.approved_package(path,a.public,info['release_id'],127),raw)
  identities.append(dict(instance=who,release=info['release_id'],binary_sha256=hashlib.sha256(a.harness.read_bytes()).hexdigest()));return Actor(c,who)
 try:
  j.boot(False)
  game_info=releases.inspect(a.game.read_bytes())
  with j.client()as c:c.request(10,bytes.fromhex(game_info['project_id'])+releases.public_modulus(a.public));c.stage(a.game)
  old=j.ui.frame().digest;j.ui.press(88);j.ui.wait_frame(old);time.sleep(.5);j.ui.press(28)
  def running():
   with j.client()as c:
    table=c.request(2)
    return next((struct.unpack_from('<Q',table,i)[0]for i in range(7*32,len(table),32)if struct.unpack_from('<Q',table,i+16)[0]==795 and 0<struct.unpack_from('<Q',table,i+8)[0]<5),None)
  game=wait(running,120,'trusted secure native game');j.wait_text(8,56,'CRATE WORKSHOP')
  with j.client()as c:
   actor=install(c,'import-owner');other=install(c,'import-other')
   selected,records=graph('async-a',3,edges=32);h=stage(actor,selected,records)
   selected_b,records_b=graph('async-b',7);hb=stage(actor,selected_b,records_b)
   actor.objects(44,h,10001);actor.objects(44,hb,10002)
   trace=[]
   def hashing():
    f,d=detail(actor,h);fb,db=detail(actor,hb);trace.append(dict(a=list(f),ad=list(d),b=list(fb),bd=list(db)))
    return (f,d,fb,db)if f[6]==2 and d[1]>=8 and fb[6]==2 and db[1]>=8 else None
   before=wait(hashing,120,'two private SHA cursors in flight')
   denied(lambda:other.objects(45,h),3);denied(lambda:c.objects(45,h),3)
   unrelated=c.import_object(b'unrelated request completes during real hash validation',2)
   require(c.read_object(unrelated)==b'unrelated request completes during real hash validation','unrelated Objects bytes changed')
   j.ui.press(32)
   def moved():return state(c,game)if state(c,game)['moves']==1 else None
   actual_game=wait(moved,30,'actual native input during hashing')
   after=detail(actor,h)
   require(after[0][2]==2 and after[0][6]==2 and after[1][1]>before[1][1],'hash was not actually active across input/Objects work')
   passed('two independent job hashes advance while actual Game input and unrelated Objects request complete',before=trace[-1],after=dict(fields=list(after[0]),detail=list(after[1])),game=actual_game,unrelated_sha256=hashlib.sha256(c.read_object(unrelated)).hexdigest())
   # Pause after the first node is typed; its immutable staged bytes must stay
   # invisible even though another transaction presents its exact content ID.
   def sealed():
    f,d=detail(actor,h)
    return (f,d)if d[5]>=1 and f[2]==2 else None
   wait(sealed,120,'first staged typed node');actor.objects(46,h,1)
   attack_selected,attack_records=graph('scope-leak',11,extra=[('private.bin',10,records[0]['id'])])
   attack=stage(other,attack_selected,attack_records);other.objects(44,attack,10003)
   failure,_=terminal(other,attack);require(failure[2]==6 and failure[5]==2,'foreign staged dependency became visible')
   other.objects(46,attack,4)
   actor.objects(46,h,2)
   done,data=terminal(actor,h);done_b,data_b=terminal(actor,hb)
   require(done[2]==done_b[2]==4 and len(data)==len(data_b)==8,'concurrent imports did not publish complete roots')
   require(actor.objects(45,h)==(done,data),'lost reply re-query changed committed root handle')
   require(actor.objects(44,h,10001)==(done,data),'idempotent submit changed committed effect')
   denied(lambda:actor.objects(44,h,90099),2)
   roots_before=projects.roots(actor);require({r['name']for r in roots_before}=={'async-a','async-b'},'partial/foreign root became public')
   root_a=struct.unpack('<Q',data)[0]
   head,files=projects.snapshot(actor,root_a);require(head==selected[0]['head'] and len(files)==32 and all(x==records[0]['payload']for x in files.values()),'committed selected closure bytes differ')
   actor.objects(46,h,4);actor.objects(46,hb,4)
   passed('foreign transaction cannot resolve typed private stages; final publication and lost-reply queries are exact',denial_state=list(failure),roots=roots_before,checked_payload_sha256=hashlib.sha256(records[0]['payload']).hexdigest())
   # Freeze and cancellation use the same actual hash path, not a synthetic job.
   selected,records=graph('cancelled',19,edges=32);hc=stage(actor,selected,records);actor.objects(44,hc,10004)
   actor.objects(46,hc,1);frozen=detail(actor,hc);time.sleep(.15);require(detail(actor,hc)==frozen,'paused hash cursor advanced')
   denied(lambda:actor.objects(37,hc,0,0,data=b'x'),7);denied(lambda:actor.objects(38,hc),7)
   actor.objects(46,hc,2)
   wait(lambda:detail(actor,hc)[1][1]>=8,60,'resumed real hash cursor')
   def checked_payload():
    f,d=detail(actor,hc)
    return (f,d)if f[2]==2 and d[5]>=1 else None
   wait(checked_payload,120,'verified payload before cancellation');actor.objects(46,hc,1)
   verified=actor.objects(43,hc,0,0,512)[1];require(verified==records[0]['payload'][:512],'checked stage bytes differ before cancellation')
   actor.objects(46,hc,3)
   denied(lambda:actor.objects(43,hc,0,0,512),3)
   cleaning,cleaning_detail=detail(actor,hc);require(cleaning[2]==5 and cleaning[6]==90,'cancelled record was not denied during active bounded cleanup')
   cancelled,_=terminal(actor,hc);require(cancelled[2]==5,'cancel did not become terminal')
   require('cancelled'not in {r['name']for r in projects.roots(actor)},'cancelled job published a root');actor.objects(46,hc,4)
   passed('pause freezes actual hash state, resume advances, cancel never publishes and staged writes/legacy commit are frozen',cancelled=list(cancelled),verified_stage_sha256=hashlib.sha256(verified).hexdigest(),cancelled_read_denied_during_cleanup=dict(fields=list(cleaning),detail=list(cleaning_detail)))
   # Both roots were valid under the begin-time quota. A separate ordinary
   # commit consumes capacity after submission; the final two-root effect fails.
   selected,records=graph('quota-first',23)
   second=record(11,projects.manifest([('second.bin',10,records[0]['id'])]));records.append(second);selected.append(dict(name='quota-second',head=second['id']))
   hq=stage(actor,selected,records);actor.objects(44,hq,10005);actor.objects(46,hq,1)
   extra=root(actor,'quota-racer');actor.objects(46,hq,2)
   quota,_=terminal(actor,hq);require(quota[2]==6 and quota[5]==4,'final quota race did not fail atomically')
   names={r['name']for r in projects.roots(actor)};require(names=={'async-a','async-b','quota-racer'},'quota race partially published roots');actor.objects(46,hq,4)
   actor.objects(28,extra)
   passed('final quota recheck rejects both selected roots atomically after concurrent ordinary publication',terminal=list(quota),visible_names=sorted(names))
   # A committed dependency is visible only through the exact current read
   # grant captured by the job. Revocation between hash quanta invalidates it.
   private=c.import_object(b'private dependency with a narrowly delegated read',10);_,private_ids=c.objects(21,private)
   delegated=c.objects(6,private,other.instance,1)[0][1]
   selected,records=graph('revoked-dependency',29,extra=[('private.bin',10,private_ids[:32].hex())])
   hr=stage(other,selected,records);other.objects(44,hr,10006)
   wait(lambda:detail(other,hr)[0][6]==2 and detail(other,hr)[1][1]>=8,60,'captured dependency witness then active hash')
   other.objects(46,hr,1);c.objects(7,private,delegated);other.objects(46,hr,2)
   revoked,_=terminal(other,hr);require(revoked[2]==6,'revoked dependency grant was reused');other.objects(46,hr,4)
   passed('revoked exact dependency witness is rejected between quanta',terminal=list(revoked))
   # This is the existing current signed Game graph, including all Release
   # commitments, canonical source/evidence and actual multi-blob binary bytes.
   release_actor=install(c,'import-release-owner');archive=json.loads(a.archive.read_text());records=[dict(r,payload=base64.b64decode(r['payload']))for r in archive['nodes']]
   started=time.monotonic();imported=projects.import_records(release_actor,archive['selected'],records)
   selected_root=imported[0]['cap'];require(release_actor.objects(29,selected_root)[1][:32].hex()==archive['selected'][0]['head'],'current Release root head changed')
   expected={r['id']:r for r in records};actual={};cursor=0
   while True:
    f,ids=release_actor.objects(26,selected_root,cursor)
    if not f[1]:break
    cursor=f[3];raw=release_actor.read_object(f[1]);identity=ids[:32].hex()
    require(identity in expected and raw==expected[identity]['payload'] and ids[32:64].hex()==expected[identity]['parent'],'async Release import returned substituted bytes')
    actual[identity]=hashlib.sha256(raw).hexdigest()
   require(set(actual)==set(expected),'async Release import omitted dependencies')
   passed('current secure Game Release imports through the asynchronous public adapter with every node byte checked',head=archive['selected'][0]['head'],nodes=len(actual),payload_bytes=sum(len(r['payload'])for r in records),elapsed_seconds=time.monotonic()-started,node_payload_sha256=actual)
  result=dict(schema=1,result='passed',image_sha256=j.image,game_release=game_info['release_id'],packages=identities,checks=checks,private_job_context_bytes=4*8192,hash_blocks_per_quantum=8,legacy_synchronous_operations=[38,43],limitations=['raw38 and raw43 compatibility paths remain synchronous; current SDK and LibraryFetch use44/45/46','host forwards explicit public fixture records; no memory patching or internal job-state setters'])
  (a.output/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2));success=True
 finally:
  if success or not a.keep_on_failure:j.stop(hard=True)


if __name__=='__main__':main()
