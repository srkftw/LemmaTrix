"""Native Feed retention must commit signed outbox before required-route failure.

Uses ordinary graphical controls, public profile export and read-only opaque
backing metadata. Never exports/decrypts an author seed or account record.
"""
import argparse,hashlib,json,os,resource,struct,sys,time,traceback
from pathlib import Path
from types import SimpleNamespace as NS
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import feed,releases
from messenger_journey import Guest,PUB,wait,screenshot

BODY='Retained review: keep this exact signed publication pending until an explicitly selected private route is available. Recovery must preserve its sequence, author and commitment.'

def status(g,op=791):
 raw=g.client.request(150,struct.pack('<Q8Q',g.ui,op,0,0,0,0,0,0,1))
 return struct.unpack_from('<8Q',raw),raw[64:]

def roots(backing):
 rows=[]
 with backing.open('rb')as disk:
  for i in range(2):
   disk.seek((5396000+i)*512);head=disk.read(512)
   magic,version,domain,generation,length=struct.unpack_from('<5Q',head)
   row=dict(slot=i,magic=hex(magic),version=version,domain=domain,generation=generation,bytes=length,header_sha256=hashlib.sha256(head).hexdigest())
   if magic==0x315243455246544c and 256<=length<=32768:
    disk.seek((5396002+(generation%2)*65)*512);cipher=disk.read(length+16)
    row['cipher_commitment_valid']=hashlib.sha256(cipher).digest()==head[64:96]
   rows.append(row)
 return rows

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,required=True);p.add_argument('--packages',type=Path,required=True);p.add_argument('--identity',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--repair-live',type=Path,help='recover the preserved failing actor/backing with newly admitted account/UI packages');p.add_argument('--stop-on-failure',action='store_true');a=p.parse_args()
 out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);image=out/'guest.bin';image.write_bytes(a.image.read_bytes())
 packages={name:(a.identity if name=='identity'else a.packages/(name+'.ltrel'))for name in('identity','feed-account','feed')}
 for name,path in packages.items():copy=out/(name+'.ltrel');copy.write_bytes(path.read_bytes());packages[name]=copy
 prior=a.repair_live.resolve()if a.repair_live else None
 backing=(prior or out)/'personal.img';wanted=5396132*512;soft,hard=resource.getrlimit(resource.RLIMIT_FSIZE)
 if soft!=resource.RLIM_INFINITY and soft<wanted:resource.setrlimit(resource.RLIMIT_FSIZE,(wanted,hard))
 if not prior:
  fd=os.open(backing,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
  try:os.ftruncate(fd,wanted)
  finally:os.close(fd)
 objects_key=(prior/'objects-unlock.key').read_bytes()if prior else os.urandom(32)
 feed_key=(prior/'feed-unlock.key').read_bytes()if prior else os.urandom(32)
 if not prior:
  for name,key in(('objects-unlock.key',objects_key),('feed-unlock.key',feed_key)):
   fd=os.open(out/name,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
   try:os.write(fd,key)
   finally:os.close(fd)
 report=dict(schema=1,image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),packages={n:dict(release_id=releases.inspect(f.read_bytes())['release_id'],package_sha256=hashlib.sha256(f.read_bytes()).hexdigest())for n,f in packages.items()},checks=[],observations=[],authority='Native author creation, signing, retention and recovery only; host observes public profile plus ciphertext commitments, without decrypting account records.',whole_store_freshness_anchor=False)
 if prior:
  previous=json.loads((prior/'failure.json').read_text());assert previous['image_sha256']==report['image_sha256']
  g=Guest('retained-outbox','qemu',prior,prior/'guest.bin',graphical=True,vault=backing).attach(None)
  report['repair_of']=dict(path=str(prior),failure_sha256=hashlib.sha256((prior/'failure.json').read_bytes()).hexdigest(),same_native_actor=True,same_encrypted_backing=True)
 else:g=Guest('retained-outbox','qemu',out,image,graphical=True,vault=backing).start()
 started=time.monotonic();complete=False;stage='native identity'
 def save():
  report['elapsed_seconds']=time.monotonic()-started;(out/'progress.json').write_text(json.dumps(report,indent=2)+'\n')
 def record(label,**values):report['checks'].append(dict(check=label,result='pass',**values));save();print('PASS',label,values,flush=True)
 def condition(predicate,label):
  last=[None]
  def poll():
   current=status(g)
   if current[0]!=last[0]:
    last[0]=current[0];report['observations'].append(dict(stage=label,status=list(current[0]),seconds=time.monotonic()-started));save();print('UI',label,current[0],flush=True)
   return current if predicate(current[0])else None
  return wait(poll,300,label)
 def export(label):
  g.device.press(59);wait(lambda:status(g)[0][2]==5,60,'native retention panel');before=status(g,793)[0][1]
  g.device.press(66);wait(lambda:status(g,793)[0][1]not in(0,before),180,'native fresh approved portable profile')
  f,_=status(g,794);assert f[0]==0
  raw=g.client.read_object(f[1]);assert len(raw)==2048 and struct.unpack_from('<2Q',raw)==(0x3154524f5046544c,1)
  result=dict(sequence=struct.unpack_from('<Q',raw,24)[0],public=raw[32:64].hex(),event=raw[128:160].hex(),generation=struct.unpack_from('<Q',raw,160)[0],sha256=hashlib.sha256(raw).hexdigest(),roots=roots(backing))
  (out/(label+'-public-profile.bin')).write_bytes(raw);report[label]=result;save();g.device.press(1);return result
 try:
  if prior:
   for instance in(previous['personal']['ui'],previous['personal']['owner']):g.client.request(26,struct.pack('<Q',instance))
  home=hashlib.sha256(b'Native retained outbox home').hexdigest();peer=hashlib.sha256(b'Native retained outbox selected peer').hexdigest()
  personal=feed.start(g.client,NS(identity=packages['identity'],owner=packages['feed-account'],ui=packages['feed'],public=PUB,federation=home,peer=peer));g.ui=personal['ui'];g.owner=personal['owner'];report['personal']=personal
  g.device.chord(56,15);time.sleep(.2)
  unlocked=g.client.request(200,struct.pack('<8Q',200,0,3,0,0,0,0,1)+objects_key);assert struct.unpack_from('<Q',unlocked)[0]==0
  if prior:
   pending=previous['before-lock'];report['before-lock']=pending;record('preserved failing actor has original two committed encrypted roots',roots=roots(backing))
  else:
   g.device.press(60);_,public=condition(lambda f:f[1]==1,'native scoped Feed author');pub=public[:32].hex();record('native scoped author created',public=pub)
   g.client.request(179,struct.pack('<2Q',g.owner,1));g.device.press(59);g.device.textASCII(feed_key.hex(),delay=.04);g.device.press(63)
   condition(lambda f:f[4]==46,'native explicit identity retention');initial_roots=roots(backing);assert max(r['generation']for r in initial_roots)==1
   record('explicit native retained identity commits first encrypted account record',roots=initial_roots)
   g.device.press(1);g.device.press(61);g.device.textASCII(BODY,delay=.035);condition(lambda f:f[3]==len(BODY),'native ordinary compose');g.device.press(62);condition(lambda f:f[2]==9,'native exact content preview');g.device.press(63)
   stage='signed pending before network';condition(lambda f:f[5]==8 and f[6]==14,'required mode1 unavailable after retained signing')
   pending=export('before-lock');assert pending['sequence']==1 and pending['public']==pub and pending['event']!='00'*32,pending
   assert max(r['generation']for r in pending['roots'])>=2,pending
   record('exact signed outbox and sequence commit before unavailable route',**pending)
  for cycle in(1,2):
   stage='native lock/recover cycle'+str(cycle)
   g.device.press(59)
   if not prior or cycle!=1:g.device.press(64);condition(lambda f:f[1]==0,'native lock cycle'+str(cycle))
   old_generation=max(r['generation']for r in roots(backing));g.client.request(179,struct.pack('<2Q',g.owner,1))
   g.device.press(61);g.device.textASCII(feed_key.hex(),delay=.04);g.device.press(63)
   condition(lambda f:f[1]==1 and f[5]==8 and max(r['generation']for r in roots(backing))>old_generation,'native fresh-grant recovery commits cycle'+str(cycle))
   g.device.press(1);restored=export('recovered-'+str(cycle));assert restored['sequence']==pending['sequence']and restored['public']==pending['public']and restored['event']==pending['event'],restored
   assert restored['generation']>pending['generation'],restored
   record('native recovery preserves exact signed pending event and creates fresh identity authority',cycle=cycle,**restored)
  report['frame']=screenshot(g,'retained-pending');report['result']='pass';complete=True;save();(out/'evidence.json').write_text(json.dumps(report,indent=2)+'\n')
 except BaseException as error:
  report.update(result='failure-preserved-native-actor',stage=stage,error=repr(error),traceback=traceback.format_exc(),roots=roots(backing),socket=str(g.path),graphics=str(g.graphics),pid=g.process.pid)
  save();(out/'failure.json').write_text(json.dumps(report,indent=2)+'\n');raise
 finally:
  if complete or a.stop_on_failure:g.stop()
  else:
   if g.client:g.client.close()
   if g.device:g.device.close()
   if g.log:g.log.close()

if __name__=='__main__':main()
