"""Key-free executor bridge for guest-admitted RemoteBuild-v1 jobs.

Admission, exact-root authority, quote/approval and job state stay in Lean. This
worker discloses its Lean/LLVM sandbox bootstrap and never signs a publication.
"""
import argparse,hashlib,json,struct,time
from pathlib import Path
import build_jobs,live,network,projects

def inspect(client,instance):
 raw=client.request(150,struct.pack('<Q',instance)+struct.pack('<8Q',54,0,0,0,0,0,0,1))
 if len(raw)!=704 or struct.unpack_from('<Q',raw)[0]:raise ValueError('native RemoteBuild inspection unavailable')
 q=struct.unpack_from('<32Q',raw,64)
 return {'role':q[0],'state':q[4],'local_job':q[6],'job_service':q[7],'result_root':q[12],'error':q[14],'artifact_hash':raw[192:224].hex(),'artifact_root':raw[224:256].hex(),'source_root':raw[320:352].hex(),'project_id':raw[352:384].hex(),'toolchain_id':raw[384:416].hex(),'provider_id':raw[416:448].hex(),'request_id':raw[480:512].hex(),'contract':raw[448:704]}

def ingest_inspect(client,instance):
 raw=client.request(150,struct.pack('<Q',instance)+struct.pack('<8Q',63,0,0,0,0,0,0,1))
 if len(raw)!=320 or struct.unpack_from('<Q',raw)[0]:raise ValueError('native source ingestion inspection unavailable')
 q=struct.unpack_from('<8Q',raw,64)
 return {'phase':q[0],'provider_role':q[1],'deadline_local_turn':q[2],'nodes':q[3],'bytes':q[4],'error':q[5],'rejected_messages':q[6],'request_id':raw[128:160].hex(),'source_root':raw[160:192].hex(),'project_id':raw[192:224].hex(),'toolchain_id':raw[224:256].hex(),'source_upload_grants_execution':False}

def configure(client,instance,credentials,role,provider_role="builder"):
 side,material=network.load_credentials(credentials)
 own=material[:32] if side==1 else material[32:64]
 compiler=bytes.fromhex(build_jobs.compiler_identity())
 raw=client.request(150,struct.pack('<Q',instance)+struct.pack('<8Q',50,0,('client','builder','verifier').index(role)+1,2 if provider_role=='builder' else 3,0,0,0,1)+own+compiler)
 if len(raw)!=64 or struct.unpack_from('<Q',raw)[0]:raise ValueError('native RemoteBuild configuration denied')
 return dict(instance=instance,role=role,identity=own.hex(),toolchain_id=compiler.hex(),terms='voluntary zero-price; CPU60s/wall120s/output64KiB; no payment/confidential execution')

def upload_artifact(client,result):
 artifact=result.get('artifact',{});raw=Path(artifact['path']).read_bytes();session=result['guest_session']
 if not 0<len(raw)<=65536 or hashlib.sha256(raw).hexdigest()!=artifact['sha256']:raise ValueError('remote output exceeds approved64KiB or changed after build')
 base=dict(h=session['job_id'],a=session['job_service'])
 def call(op,b=0,data=b'',allow_committed=False):
  packet=struct.pack('<8Q',op,base['h'],base['a'],b,0,0,0,1)+data
  out=client.request(160,packet)
  if len(out)!=64 or struct.unpack_from('<Q',out)[0] not in ((0,6) if allow_committed else (0,)):raise ValueError(f'guest artifact return op{op} rejected')
  return out
 begin=call(8,len(raw),bytes.fromhex(result['source_root'])+bytes.fromhex(artifact['sha256'])+bytes.fromhex(result['toolchain_id']),True)
 if struct.unpack_from('<Q',begin)[0]==6:
  call(10);return {'bytes':len(raw),'sha256':artifact['sha256'],'guest_committed':True,'idempotent_existing':True}
 for offset in range(0,len(raw),512):call(9,offset,raw[offset:offset+512])
 call(10)
 return {'bytes':len(raw),'sha256':artifact['sha256'],'guest_committed':True}

def execute_once(client,instance,output):
 authority=inspect(client,instance)
 if authority['role'] not in (2,3) or authority['state']!=2 or not authority['local_job']:return None
 raw=projects.queued_build(client)
 if raw is None:return None
 job=projects.frozen_build(client,raw)
 if job['job_id']!=authority['local_job'] or job['job_service']!=authority['job_service'] or job['source_root']!=authority['source_root'] or job['project_id']!=authority['project_id'] or job['toolchain_id']!=authority['toolchain_id']:raise ValueError('queued executor request differs from guest-approved remote contract; no source exported')
 current,files=projects.snapshot(client,job['source_root_capability'],job['source_root'])
 if current!=authority['source_root']:raise ValueError('approved immutable source root changed')
 directory=Path(output)/authority['provider_id'][:16]/authority['request_id'];directory.mkdir(parents=True,exist_ok=True)
 result=build_jobs.build_source_snapshot(files,module='Main',entry='Main.main',profile=job['runtime_profile'],jobid=job['job_id'],rootid=job['source_root'],outputdir=directory,output_limit=65536)
 if result.get('toolchain_id')!=job['toolchain_id']:raise ValueError('executor toolchain differs from guest-approved lock')
 result['guest_session']={k:job[k] for k in ('job_service','job_id','source_root_capability','project_name','project_id','live_root_binding','requester','delegator','recipe')}
 result['delivered']=False
 result['remote_contract']={k:authority[k] for k in ('role','provider_id','request_id','source_root','project_id','toolchain_id')}
 result['remote_contract'].update(schema=1,terms='zero-price',cpu_seconds=60,wall_seconds=120,output_bytes=65536,confidential=False,independent_hardware=False,operator_independence=False)
 if result['status']=='ok' and result['artifact']['bytes']>65536:
  result['status']='error';result['diagnostic_text']='remote result exceeds approved64KiB output';result.pop('artifact',None)
 # A cancellation/replacement while compiling cannot attach this result.
 still=inspect(client,instance)
 if any(still[k]!=authority[k] for k in ('state','local_job','job_service','source_root','project_id','toolchain_id','provider_id','request_id')):
  result['delivered']=False;result['remote_result']='cancelled or replaced; no late attachment';projects.save_build(result,directory);return result
 projects.save_build(result,directory)
 projects.complete_build(client,result)
 projects.save_build(result,directory)
 if result['status']=='ok':result['remote_artifact']=upload_artifact(client,result)
 projects.save_build(result,directory)
 return result

def compare(builder_path,verifier_path):
 a=json.loads(Path(builder_path).read_text());b=json.loads(Path(verifier_path).read_text())
 for r,role in [(a,2),(b,3)]:
  if r.get('status')!='ok' or r.get('remote_contract',{}).get('role')!=role or not r.get('remote_artifact',{}).get('guest_committed'):raise ValueError('both results must be actual guest-approved completed builds with committed artifact bytes')
 for key in ('source_root','toolchain_id','recipe','runtime_profile'):
  if a[key]!=b[key]:raise ValueError('verification inputs/recipe differ: '+key)
 if a['remote_contract']['provider_id']==b['remote_contract']['provider_id']:raise ValueError('builder and verifier identities must be distinct')
 actual=[]
 for result in [a,b]:
  binary=Path(result['artifact']['path']).read_bytes()
  if hashlib.sha256(binary).hexdigest()!=result['artifact']['sha256']:raise ValueError('artifact bytes changed since execution')
  actual.append(binary)
 match=actual[0]==actual[1]
 return {'schema':1,'kind':'actual-separate-rebuild','source_root':a['source_root'],'toolchain_id':a['toolchain_id'],'builder':a['remote_contract']['provider_id'],'verifier':b['remote_contract']['provider_id'],'builder_artifact':hashlib.sha256(actual[0]).hexdigest(),'verifier_artifact':hashlib.sha256(actual[1]).hexdigest(),'bytes_equal':match,'result':'match' if match else 'mismatch','isolation':'separate namespace-isolated Lean/LLVM executions on this development host','independent_hardware':False,'independent_operators':False,'publisher_signature':'not supplied by this computation evidence'}

def main(argv=None):
 p=argparse.ArgumentParser(description='Guest-authorized capped remote build/verifier executor')
 sub=p.add_subparsers(dest='command',required=True)
 q=sub.add_parser('configure');q.add_argument('--socket',type=Path,required=True);q.add_argument('--instance',type=int,required=True);q.add_argument('--credentials',type=Path,required=True);q.add_argument('--role',choices=('client','builder','verifier'),required=True);q.add_argument('--provider-role',choices=('builder','verifier'),default='builder')
 for command in ('inspect','ingestion'):
  q=sub.add_parser(command);q.add_argument('--socket',type=Path,required=True);q.add_argument('--instance',type=int,required=True)
 q=sub.add_parser('worker');q.add_argument('--socket',type=Path,required=True);q.add_argument('--instance',type=int,required=True);q.add_argument('--output',type=Path,required=True);q.add_argument('--once',action='store_true');q.add_argument('--poll-interval',type=float,default=.5)
 q=sub.add_parser('compare');q.add_argument('--builder',type=Path,required=True);q.add_argument('--verifier',type=Path,required=True);q.add_argument('--output',type=Path)
 a=p.parse_args(argv)
 if a.command=='compare':
  result=compare(a.builder,a.verifier)
  if a.output:a.output.write_text(json.dumps(result,indent=2)+'\n')
 else:
  while True:
   c=live.Client(a.socket)
   try:result=configure(c,a.instance,a.credentials,a.role,a.provider_role) if a.command=='configure' else inspect(c,a.instance) if a.command=='inspect' else ingest_inspect(c,a.instance) if a.command=='ingestion' else execute_once(c,a.instance,a.output)
   finally:c.close()
   if a.command!='worker' or result is not None or a.once:break
   time.sleep(max(.1,min(a.poll_interval,10)))
  if isinstance(result,dict):result={k:v for k,v in result.items() if k!='contract'}
 print(json.dumps(result,indent=2));return 0

if __name__=='__main__':raise SystemExit(main())
