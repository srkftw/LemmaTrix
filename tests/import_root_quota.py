"""Publication rechecks ordinary root quota across overlapping transactions."""
import argparse,hashlib,json,os,signal,struct,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import live,projects,releases
from forge_journey import wait

class Actor:
 def __init__(self,client,instance):self.client,self.instance=client,instance
 def objects(self,op,h=0,a=0,b=0,c=0,d=0,e=0,data=b''):
  raw=self.client.request(150,struct.pack('<Q8Q',self.instance,op,h,a,b,c,d,e,1)+data)
  assert len(raw)>=64
  fields=struct.unpack_from('<8Q',raw)
  if fields[0]:raise ValueError(f'Objects status{fields[0]}')
  return fields,raw[64:]

def denied(call,code):
 try:call()
 except ValueError as error:assert str(error)==f'Objects status{code}',str(error)
 else:raise AssertionError('ordinary import exceeded its publication quota')

def stage(actor,prefix,count):
 source=(prefix+' source').encode();source_id=projects.canonical_node(10,source)
 manifest=projects.manifest([('Main.lean',10,source_id)]);head=projects.canonical_node(11,manifest)
 roots=[dict(name=f'{prefix}-{i}',head=head) for i in range(count)]
 entries=b''.join(struct.pack('<2Q',0,len(r['name']))+bytes.fromhex(head)+r['name'].encode().ljust(80,b'\0') for r in roots)
 transaction=actor.objects(35,a=count,b=2,c=len(source)+len(manifest),data=entries)[0][1]
 # Dependency order is deliberately reversed; Objects owns validation order.
 for ordinal,(kind,identity,payload) in enumerate(((11,head,manifest),(10,source_id,source))):
  actor.objects(36,transaction,ordinal,kind,len(payload),data=bytes.fromhex(identity)+bytes(32)+hashlib.sha256(payload).digest())
  for offset in range(0,len(payload),512):actor.objects(37,transaction,ordinal,offset,data=payload[offset:offset+512])
 return transaction,roots,len(source)+len(manifest)

def main():
 p=argparse.ArgumentParser();p.add_argument('--image',required=True,type=Path);p.add_argument('--output',required=True,type=Path);p.add_argument('--binary',type=Path,default=ROOT/'build/live/apps/import-quota-probe.bin');p.add_argument('--key',type=Path,default=ROOT/'build/signed-forge-journey-2/publisher.pem');p.add_argument('--public',type=Path,default=ROOT/'build/signed-forge-journey-2/publisher.pub');a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
 package=a.output/'probe.ltrel';raw,manifest=releases.make(a.binary,'import-quota-probe','0.4.0',127,a.key,profile=2);package.write_bytes(raw);Path(str(package)+'.manifest.json').write_text(json.dumps(manifest,sort_keys=True,separators=(',',':')))
 sock=a.output/'portal.sock';log=(a.output/'guest.log').open('wb');process=subprocess.Popen([str(ROOT/'lt'),'run','--image',str(a.image.resolve()),'--socket',str(sock)],cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,start_new_session=True);client=None
 report=dict(image=hashlib.sha256(a.image.read_bytes()).hexdigest(),backend='qemu',probe_rights=127,project_compilations=0,checks=[])
 def passed(label,**fields):report['checks'].append(dict(check=label,result='pass',**fields));print('PASS',label,flush=True)
 try:
  wait(sock.exists,'quota test guest boot',60);client=live.Client(sock,timeout=60);client.request(10,releases.project('import-quota-probe')+releases.public_modulus(a.public));slot,_=client.install(package);instance=struct.unpack_from('<Q',client.request(25,struct.pack('<Q',slot)),8)[0];actor=Actor(client,instance)
  assert actor.objects(10)[0][1:3]==(0,0)
  first,first_roots,first_bytes=stage(actor,'first',4);second,second_roots,second_bytes=stage(actor,'second',4)
  assert not projects.roots(actor);assert actor.objects(10)[0][1:3]==(4,first_bytes+second_bytes)
  fields,caps=actor.objects(38,first);assert fields[1]==4 and len(caps)==32
  actual=projects.roots(actor);assert [(r['name'],r['head']) for r in actual]==[(r['name'],r['head']) for r in first_roots]
  denied(lambda:actor.objects(38,second),4);denied(lambda:actor.objects(40,second),3)
  assert projects.roots(actor)==actual;assert actor.objects(10)[0][1:3]==(2,first_bytes)
  for root in actual:assert actor.objects(29,root['cap'])[1][:32].hex()==root['head']
  passed('overlapping four-root stages cannot publish eight roots; second stage abort preserves all first roots',actor=instance,first_transaction=first,second_transaction=second,roots=len(actual),remaining_records=2,remaining_bytes=first_bytes)
  denied(lambda:stage(actor,'over-limit',1),4);assert actor.objects(10)[0][1:3]==(2,first_bytes)
  actor.objects(28,actual[0]['cap']);denied(lambda:actor.objects(29,actual[0]['cap']),3)
  third,third_roots,third_bytes=stage(actor,'continued',1);actor.objects(38,third)
  remaining=projects.roots(actor);assert len(remaining)==4 and {r['name'] for r in remaining}=={r['name'] for r in first_roots[1:]+third_roots};assert actor.objects(10)[0][1:3]==(4,first_bytes+third_bytes)
  passed('rejected stage reclaims records and transaction capacity; explicit root removal permits continued import',roots=len(remaining),records=4,bytes=first_bytes+third_bytes)
  report['result']='pass'
 except BaseException as error:report.update(result='fail',error=repr(error));raise
 finally:
  (a.output/'evidence.json').write_text(json.dumps(report,indent=2)+'\n')
  if client:
   try:client.request(70)
   except (OSError,EOFError,ValueError):pass
   client.close()
  try:process.wait(timeout=10)
  except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait()
  log.close()
if __name__=='__main__':main()
