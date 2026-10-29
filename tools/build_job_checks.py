"""Focused running-service lifecycle check; no compiler/signing repetition.

Success completions reuse an already produced real native artifact under explicit
management/builder authority. Controlled request assertions exercise job lifetime,
not source-to-binary correctness or a newly executed host compilation.
"""
import argparse,hashlib,json,struct
from pathlib import Path
import live,projects


def request(client,operation,identity=0):
 raw=client.request(160,struct.pack('<8Q',operation,identity,0,0,0,0,0,1))
 if len(raw)<64:raise AssertionError('short BuildJobs response')
 fields=struct.unpack_from('<8Q',raw)
 if fields[0]:raise ValueError('BuildJobs status'+str(fields[0]))
 return fields,raw


def rejects(action,status):
 try:action()
 except ValueError as error:
  if 'status'+str(status) not in str(error):raise
 else:raise AssertionError('unexpected accepted service transition')


def check(client,root,result_path):
 artifact=json.loads(Path(result_path).read_text())
 if artifact.get('status')!='ok':raise ValueError('an actual prior successful artifact is required')
 binary=Path(artifact['artifact']['path']).read_bytes()
 binary_hash=hashlib.sha256(binary).hexdigest()
 if binary_hash!=artifact['artifact']['sha256']:raise ValueError('prior native artifact bytes changed')
 process=client.request(2);service=struct.unpack_from('<Q',process,5*32)[0]
 manifest=projects.resolve(client,root,artifact['source_root'])
 name='build-lifetime-check'
 alias=client.objects(22,manifest,0,len(name),data=bytes(32)+name.encode().ljust(64,b'\0'))[0][1]
 delegated=client.objects(27,alias,service,73)[0][1]
 jobs=[];completed=[]
 def queue():
  fields,raw=request(client,1,delegated);identity=fields[1];jobs.append(identity)
  assert fields[2]==1 and len(raw)==192 and raw[64:96].hex()==artifact['source_root']
  return fields,raw
 def finish(queued,success):
  fields,raw=queued;identity=fields[1]
  diagnostic=b'' if success else b'Main.lean:1:1: controlled lifecycle failure assertion'
  body=struct.pack('<8Q',3,identity,fields[3],2 if success else 3,0,2,len(diagnostic),1)
  body+=raw[64:96]+(bytes.fromhex(binary_hash) if success else bytes(32))+hashlib.sha256(b'lifecycle-request:'+str(identity).encode()).digest()+raw[128:160]+diagnostic
  answer=client.request(160,body);status,returned,state=struct.unpack_from('<3Q',answer)
  assert status==0 and returned==identity and state==(2 if success else 3)
  completed.append(identity)
  return struct.unpack_from('<8Q',answer)
 try:
  first=queue();first_response=finish(first,True);first_id=first_response[1]
  for _ in range(4):
   finish(queue(),False)
   assert request(client,4,first_id)[0][2]==2
  latest=queue();latest_response=finish(latest,True);latest_id=latest_response[1]
  for _ in range(2):
   finish(queue(),False)
   assert request(client,4,latest_id)[0][2]==2
  rejects(lambda:request(client,4,first_id),3)
  rejects(lambda:client.objects(21,first_response[6]),3)
  # Fill the other three slots with pending jobs. The latest success and every
  # queued immutable input must remain intact when a fifth slot is requested.
  pending=[queue() for _ in range(3)]
  rejects(lambda:request(client,1,delegated),4)
  assert request(client,4,latest_id)[0][2]==2
  for fields,_ in pending:assert request(client,4,fields[1])[0][2]==1
  for queued in pending:finish(queued,False)
  assert request(client,4,latest_id)[0][2]==2
  return dict(checks=['more than four completed success/error iterations recycle bounded old jobs','queued/failing builds preserve most recent successful result','obsolete unrooted Build handle and recycled job ID are revoked','three pending jobs plus newest success exhaust four slots without eviction'],completed_jobs=len(completed),artifact_sha256=binary_hash,source_root=artifact['source_root'],scope='controlled explicit builder/management assertions over a prior real artifact; no new compiler execution or signature')
 finally:
  for identity in reversed(jobs):
   try:request(client,5,identity)
   except ValueError:pass
  client.objects(28,alias)


def main(argv=None):
 p=argparse.ArgumentParser(description='Bounded BuildJobs lifetime check on an existing guest')
 p.add_argument('--socket',type=Path,required=True);p.add_argument('--root',type=int,required=True);p.add_argument('--artifact-result',type=Path,required=True);p.add_argument('--output',type=Path)
 args=p.parse_args(argv);client=live.Client(args.socket)
 try:
  result=check(client,args.root,args.artifact_result)
  if args.output:args.output.write_text(json.dumps(result,indent=2)+'\n')
  print(json.dumps(result,indent=2))
 finally:client.close()
 return 0
if __name__=='__main__':raise SystemExit(main())
