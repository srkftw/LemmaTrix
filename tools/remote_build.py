"""Key-free executor bridge for guest-admitted RemoteBuild-v1 jobs.

Admission, exact-root authority, quote/approval and job state stay in Lean. This
worker discloses its Lean/LLVM sandbox bootstrap and never signs a publication.
"""
import argparse,hashlib,json,struct,time
from pathlib import Path
import build_jobs,live,network,projects,content,service_jobs,nodes,capsule,server_store,inventory

def inspect(client,instance):
 raw=client.request(150,struct.pack('<Q',instance)+struct.pack('<8Q',54,0,0,0,0,0,0,1))
 if len(raw)!=704 or struct.unpack_from('<Q',raw)[0]:raise ValueError('native RemoteBuild inspection unavailable')
 q=struct.unpack_from('<32Q',raw,64)
 return {'role':q[0],'state':q[4],'local_job':q[6],'job_service':q[7],'result_root':q[12],'artifact_content':q[13],'error':q[14],'artifact_hash':raw[192:224].hex(),'artifact_root':raw[224:256].hex(),'source_root':raw[320:352].hex(),'project_id':raw[352:384].hex(),'toolchain_id':raw[384:416].hex(),'provider_id':raw[416:448].hex(),'request_id':raw[480:512].hex(),'contract':raw[448:704]}

def artifact_inspect(client,instance):
 raw=client.request(150,struct.pack('<Q8Q',instance,64,0,0,0,0,0,0,1))
 if len(raw)!=384 or struct.unpack_from('<Q',raw)[0]:raise ValueError('native generic artifact inspection unavailable')
 q=struct.unpack_from('<8Q',raw)
 return dict(content_handle=q[1],phase=q[2],format=q[3],chunk=q[4],chunk_offset=q[5],retries=q[6],peer=raw[64:96].hex(),service=raw[96:128].hex(),manifest=raw[128:384])

def export_artifact(client,instance,destination):
 info=inspect(client,instance);state=artifact_inspect(client,instance)
 if state['phase']!=10:raise ValueError('generic artifact is not completely verified; inspect artifact for buffering/failure progress')
 fields,_=build_call(client,26,instance)
 handle=fields[1];api=content.api(client)
 metadata,manifest=api.objects(306,handle)
 if metadata[2]!=2:raise ValueError('selected artifact content is incomplete')
 total=metadata[4];digest=hashlib.sha256()
 try:
  with Path(destination).open('xb') as output:
   for offset in range(0,total,512):
    _,part=api.objects(307,handle,offset,min(512,total-offset));output.write(part);digest.update(part)
  if digest.hexdigest()!=info['artifact_hash']:
   Path(destination).unlink();raise ValueError('exported artifact differs from its exact build result')
 finally:api.objects(309,handle)
 return dict(path=str(destination),bytes=total,sha256=digest.hexdigest(),native_selected_scope=True,execution_approved=False)

def build_call(client,op,job,a=0,data=b''):
 raw=client.request(160,struct.pack('<8Q',op,job,a,0,0,0,0,1)+data)
 if len(raw)<64:raise ValueError(f'native build artifact operation{op} returned a short response')
 if struct.unpack_from('<Q',raw)[0]:raise ValueError(f'native build artifact operation{op} rejected with status {struct.unpack_from("<Q",raw)[0]}')
 return struct.unpack_from('<8Q',raw),raw[64:]

def durable_operation(client,instance,authority,job,config_path):
 config=json.loads(Path(config_path).read_text());nodes.validate_package(config)
 if config.get('role')!=('builder' if authority['role']==2 else 'verifier'):raise ValueError('operator configuration does not name this provider role')
 if not config.get('network_description'):raise ValueError('durable build policy requires its pinned signed service description')
 side,material=network.load_credentials(Path(config['credentials']))
 own=material[:32] if side==1 else material[32:64]
 if own.hex()!=authority['provider_id']:raise ValueError('operator credentials differ from native approved provider')
 public,descriptor,_=network.load_description(Path(config['network_description']))
 if hashlib.sha256(Path(config['network_description']).read_bytes()).hexdigest()!=config['network_description_sha256']:raise ValueError('operator signed service description changed')
 peer=artifact_inspect(client,instance)['peer']
 policy=hashlib.sha256(bytes.fromhex(peer+authority['toolchain_id'])).hexdigest()
 canonical=service_jobs.terms(authority['request_id'],peer,authority['source_root'],policy,
  'builder' if authority['role']==2 else 'verifier',config.get('service_policy_generation',1),262144,
  config.get('build_attempts',2),config.get('build_work_quanta',2),hashlib.sha256(descriptor).hexdigest(),True)
 service_jobs.call(client,280)
 slot=service_jobs.submit(client,16,canonical)
 state=service_jobs.inspect(client,slot)
 if state['state']=='complete':return config,slot,state
 if state['state'] in ('cancelled','paused','failed','exhausted'):raise ValueError('retained build policy requires explicit retry or remains terminal: '+state['state'])
 service_jobs.call(client,282,slot,job['job_service'])
 fields,_=build_call(client,15,job['job_id'])
 if fields[5]:
  current=service_jobs.inspect(client,slot)
  if current['attempts']<=fields[6]:raise ValueError('this execution attempt was already claimed; resolve its result or explicitly retry the retained service job before repeating computation')
  build_call(client,19,job['job_id'])
 else:build_call(client,13,job['job_id'],slot)
 return config,slot,None

def source_namespace(config,operation,requester,source_root):
 return hashlib.sha256(b'LT-FrozenBuildSource-v1\0'+bytes.fromhex(config['namespace']+requester+operation+source_root)).digest()

def retain_source(client,authority,job,config):
 requester=artifact_inspect(client,job['requester'])['peer']
 namespace=source_namespace(config,authority['request_id'],requester,authority['source_root'])
 server_store.call(client,230)
 grant=server_store.call(client,231,job['job_service'],3 if authority['role']==2 else 4,1048576,namespace)[0][1]
 try:
  build_call(client,27,job['job_id'],grant)
  deadline=time.monotonic()+120
  while time.monotonic()<deadline:
   fields,_=build_call(client,31,job['job_id'],100)
   if fields[1]==2:return dict(namespace=namespace.hex(),source_root=authority['source_root'],bundle_bytes=fields[3],native_committed=True,format='ServerStore frozen source bundle2',checkpoint=1)
   if fields[1]==3:raise ValueError(f'native frozen source retention failed: {fields[4]}')
  raise TimeoutError('frozen source retention remains queryable; execution has not started')
 finally:server_store.call(client,239,grant)

def recover_source(client,config_path,slot):
 config=json.loads(Path(config_path).read_text());nodes.validate_package(config)
 service_jobs.call(client,280);record=service_jobs.inspect(client,slot)
 if record is None or record['role'] not in ('builder','verifier'):raise ValueError('select an existing retained build/verifier operation')
 namespace=source_namespace(config,record['operation'],record['requester'],record['input_root'])
 # A queued native build authority response names the actual current service;
 # management process inventory provides its fresh incarnation after reboot.
 service=struct.unpack_from('<Q',client.request(2),5*32)[0]
 server_store.call(client,230)
 grant=server_store.call(client,231,service,3 if record['role']=='builder' else 4,1048576,namespace)[0][1]
 try:
  build_call(client,29,slot,grant)
  deadline=time.monotonic()+120
  while time.monotonic()<deadline:
   fields,_=build_call(client,31,0,100)
   if fields[1]==8:
    return dict(source_root=record['input_root'],fresh_root=fields[5],native_recovered=True,namespace=namespace.hex(),execution='not resumed; interrupted compilers require a separately permitted new attempt',old_grants_restored=False)
   if fields[1]==9:raise ValueError(f'native frozen source recovery failed: {fields[4]}')
  raise TimeoutError('frozen source recovery remains queryable')
 finally:server_store.call(client,239,grant)

def recover_result(client,config_path,slot,destination):
 """Recover one native terminal result without restoring a Forge incarnation."""
 config=json.loads(Path(config_path).read_text());nodes.validate_package(config)
 service_jobs.call(client,280);record=service_jobs.inspect(client,slot)
 if record is None or record['state']!='complete' or record['role'] not in ('builder','verifier'):
  raise ValueError('select a completed retained build/verifier operation')
 namespace=inventory.identity(config['namespace']);owner=struct.unpack_from('<Q',client.request(2),32)[0]
 selected=None
 for item in range(16):
  try:fields,binding=inventory.call(client,261,2,item,data=namespace)
  except ValueError:continue
  if fields[2]==2 and binding[256:288].hex()==record['result_root']:
   if selected is not None:raise ValueError('ambiguous retained result selection')
   selected=(item,fields,binding)
 if selected is None:raise ValueError('completed result is unavailable in this approved operator namespace')
 item,fields,binding=selected
 if fields[4]!=record['result_bytes'] or struct.unpack_from('<Q',binding,40)[0]!=2:
  raise ValueError('retained result length/format differs from the terminal operation')
 permit=inventory.permit(client,2,item,fields[4],owner,namespace,bytes.fromhex(record['result_root']))
 opened,_=inventory.open_item(client,permit,owner,int.from_bytes(bytes.fromhex(record['operation'])[:8],'little')|1)
 handle=opened[1]
 try:
  exported=inventory.export(client,handle,Path(destination))
  if exported['sha256']!=binding[64:96].hex():
   Path(destination).rename(Path(destination).with_name(Path(destination).name+'.invalid'))
   raise ValueError('recovered artifact differs from its committed raw-byte identity')
 finally:content.api(client).objects(309,handle)
 return dict(operation=record['operation'],terminal=record,artifact=exported,
             source_root=record['input_root'],fresh_read_authority=True,
             duplicate_computation=False,duplicate_publication=False,old_grants_restored=False)

def upload_generic_artifact(client,result,instance,config=None,artifact_slot=0):
 artifact=result['artifact'];raw=Path(artifact['path']).read_bytes();session=result['guest_session']
 if not 0<len(raw)<=262144 or hashlib.sha256(raw).hexdigest()!=artifact['sha256']:raise ValueError('generic artifact differs from the approved bounded build result')
 manifest,chunks,proofs=content.commitments(raw,content_id=bytes.fromhex(artifact['sha256']),provenance=bytes.fromhex(result['source_root']),format_id=2)
 owner=struct.unpack_from('<Q',client.request(2),32)[0]
 provider=bytes.fromhex(result['remote_contract']['provider_id']);federation=hashlib.sha256(b'LT-BuildResultNamespace-v1\0'+provider).digest()
 permit=0
 if config:
  namespace=bytes.fromhex(config['namespace'])
  packet=struct.pack('<8Q',260,2,artifact_slot,len(raw),owner,3,0,1)+namespace+content.sha(manifest)
  response=client.request(260,packet)
  if len(response)!=64 or struct.unpack_from('<Q',response)[0]:raise ValueError('explicit indexed artifact retention permit denied; provision indexed purpose2 backing')
  permit=struct.unpack_from('<Q',response,8)[0]
 api=content.api(client)
 operation=int.from_bytes(bytes.fromhex(result['remote_contract']['request_id'])[:8],'little')|1
 fields,_=api.objects(300,a=operation,b=len(raw),c=3,d=permit,data=manifest+content.sha(manifest)+provider+federation)
 handle=fields[1]
 for index,(part,proof) in enumerate(zip(chunks,proofs)):content.ingest_chunk(api,handle,index,part,proof)
 fields,_=api.objects(310,handle)
 if fields[1]!=handle:
  content.wait_job(api,fields[1]);api.objects(305,fields[1],4)
 # Bind durable retrieval before publishing a reader to the normal protocol.
 if config:
  peer=artifact_inspect(client,instance)['peer']
  _,descriptor,_=network.load_description(Path(config['network_description']))
  manifest_sha=content.sha(manifest).hex()
  operation=hashlib.sha256(b'LT-BuildResultRetrieval-v1\0'+bytes.fromhex(result['remote_contract']['request_id'])+content.sha(manifest)).hexdigest()
  policy=hashlib.sha256(b'LT-RetrievalPolicy-v1\0'+bytes.fromhex(config['namespace']+peer)).hexdigest()
  canonical=service_jobs.terms(operation,peer,manifest_sha,policy,'retrieval',config.get('service_policy_generation',1),len(raw)*2,32,1000000,hashlib.sha256(descriptor).hexdigest(),True)
  serving=service_jobs.submit(client,16,canonical)
  service_jobs.call(client,282,serving,session['job_service'])
  response=client.request(150,struct.pack('<Q8Q',instance,65,0,serving,0,0,0,0,1))
  if len(response)!=64 or struct.unpack_from('<Q',response)[0]:raise ValueError('native artifact serving contract binding denied')
 build_call(client,12,session['job_id'],handle)
 for _ in range(1024):
  fields,_=build_call(client,15,session['job_id'])
  if fields[2]==2:break
  if fields[2]>=3:raise ValueError('guest generic artifact whole-byte SHA256 differs from the actual compiler result')
 else:raise TimeoutError('generic artifact verification remains inspectable; timeout does not undo publication')
 if config:build_call(client,14,session['job_id'])
 return dict(bytes=len(raw),sha256=artifact['sha256'],manifest_sha256=content.sha(manifest).hex(),content_handle=handle,
  guest_committed=True,generic_format=2,retained=bool(permit),namespace=config['namespace'] if config else None,
  slot=artifact_slot if config else None,whole_byte_hash_checked=True)

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
 return dict(instance=instance,role=role,identity=own.hex(),toolchain_id=compiler.hex(),terms='voluntary zero-price; CPU60s/wall120s/output256KiB; generic content return; settlement unavailable')

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

def execute_once(client,instance,output,operator_config=None,artifact_slot=0,receipt_key=None):
 authority=inspect(client,instance)
 if authority['role'] not in (2,3) or authority['state']!=2 or not authority['local_job']:return None
 # Select this approved request rather than whichever other client queued first.
 raw=client.request(160,struct.pack('<8Q',7,authority['local_job'],0,0,0,0,0,1))
 if len(raw)<64:raise ValueError('short exact build authority response')
 if struct.unpack_from('<Q',raw)[0]:return None
 if len(raw)!=256:raise ValueError('invalid exact frozen build authority response')
 job=projects.frozen_build(client,raw)
 if job['job_id']!=authority['local_job'] or job['job_service']!=authority['job_service'] or job['source_root']!=authority['source_root'] or job['project_id']!=authority['project_id'] or job['toolchain_id']!=authority['toolchain_id']:raise ValueError('queued executor request differs from guest-approved remote contract; no source exported')
 config=None;durable_slot=None
 if operator_config:
  config,durable_slot,existing=durable_operation(client,instance,authority,job,operator_config)
  if existing:return dict(status='existing-terminal-result',durable_job=existing,duplicate_computation=False,publication='existing committed generic artifact; use service-jobs inspect and indexed item open')
 source_retention=retain_source(client,authority,job,config) if config else None
 if receipt_key:
  if config is None:raise ValueError('qualified durable receipt signing requires an explicit operator configuration')
  public,_,_=network.load_description(Path(config['network_description']))
  if capsule.modulus(receipt_key)!=public:raise ValueError('receipt signer differs from the selected signed provider service description')
  accepted_receipt=service_jobs.sign(client,durable_slot,receipt_key)
 else:accepted_receipt=None
 current,files=projects.snapshot(client,job['source_root_capability'],job['source_root'])
 if current!=authority['source_root']:raise ValueError('approved immutable source root changed')
 directory=Path(output)/authority['provider_id'][:16]/authority['request_id'];directory.mkdir(parents=True,exist_ok=True)
 output_limit=struct.unpack_from('<Q',authority['contract'],200)[0]
 result=build_jobs.build_source_snapshot(files,module='Main',entry='Main.main',profile=job['runtime_profile'],jobid=job['job_id'],rootid=job['source_root'],outputdir=directory,output_limit=output_limit)
 if result.get('toolchain_id')!=job['toolchain_id']:raise ValueError('executor toolchain differs from guest-approved lock')
 result['guest_session']={k:job[k] for k in ('job_service','job_id','source_root_capability','project_name','project_id','live_root_binding','requester','delegator','recipe')}
 result['delivered']=False
 result['remote_contract']={k:authority[k] for k in ('role','provider_id','request_id','source_root','project_id','toolchain_id')}
 result['remote_contract'].update(schema=2,terms='zero-price',cpu_seconds=60,wall_seconds=120,output_bytes=output_limit,confidential=False,independent_hardware=False,operator_independence=False,settlement='unavailable',durable_job_slot=durable_slot)
 if source_retention:result['source_retention']=source_retention
 if accepted_receipt:result['accepted_service_receipt']=accepted_receipt
 # A cancellation/replacement while compiling cannot attach this result.
 still=inspect(client,instance)
 if any(still[k]!=authority[k] for k in ('state','local_job','job_service','source_root','project_id','toolchain_id','provider_id','request_id')):
  result['delivered']=False;result['remote_result']='cancelled or replaced; no late attachment';projects.save_build(result,directory);return result
 projects.save_build(result,directory)
 projects.complete_build(client,result)
 projects.save_build(result,directory)
 if result['status']=='ok':result['remote_artifact']=upload_generic_artifact(client,result,instance,config,artifact_slot)
 elif durable_slot is not None:build_call(client,16,job['job_id'],1)
 if receipt_key:result['terminal_service_receipt']=service_jobs.sign(client,durable_slot,receipt_key)
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
 q=sub.add_parser('artifact');q.add_argument('--socket',type=Path,required=True);q.add_argument('--instance',type=int,required=True)
 q=sub.add_parser('export');q.add_argument('--socket',type=Path,required=True);q.add_argument('--instance',type=int,required=True);q.add_argument('--output',type=Path,required=True)
 q=sub.add_parser('result');q.add_argument('--socket',type=Path,required=True);q.add_argument('--slot',type=int,required=True,help='opaque ServiceJobs allocation handle')
 q=sub.add_parser('recover-source');q.add_argument('--socket',type=Path,required=True);q.add_argument('--operator-config',type=Path,required=True);q.add_argument('--slot',type=int,required=True,help='opaque ServiceJobs allocation handle')
 q=sub.add_parser('recover-result');q.add_argument('--socket',type=Path,required=True);q.add_argument('--operator-config',type=Path,required=True);q.add_argument('--slot',type=int,required=True,help='opaque ServiceJobs allocation handle');q.add_argument('--output',type=Path,required=True)
 q=sub.add_parser('worker');q.add_argument('--socket',type=Path,required=True);q.add_argument('--instance',type=int,required=True);q.add_argument('--output',type=Path,required=True);q.add_argument('--once',action='store_true');q.add_argument('--poll-interval',type=float,default=.5);q.add_argument('--operator-config',type=Path);q.add_argument('--artifact-slot',type=int,choices=range(16),default=0);q.add_argument('--receipt-key',type=Path)
 q=sub.add_parser('compare');q.add_argument('--builder',type=Path,required=True);q.add_argument('--verifier',type=Path,required=True);q.add_argument('--output',type=Path)
 a=p.parse_args(argv)
 if a.command=='compare':
  result=compare(a.builder,a.verifier)
  if a.output:a.output.write_text(json.dumps(result,indent=2)+'\n')
 else:
  while True:
   c=live.Client(a.socket)
   try:
    if a.command=='configure':result=configure(c,a.instance,a.credentials,a.role,a.provider_role)
    elif a.command=='inspect':result=inspect(c,a.instance)
    elif a.command=='ingestion':result=ingest_inspect(c,a.instance)
    elif a.command=='artifact':
     result=artifact_inspect(c,a.instance);result['manifest']=result['manifest'].hex()
    elif a.command=='export':result=export_artifact(c,a.instance,a.output)
    elif a.command=='result':
     service_jobs.call(c,280);result=service_jobs.inspect(c,a.slot)
    elif a.command=='recover-source':result=recover_source(c,a.operator_config,a.slot)
    elif a.command=='recover-result':result=recover_result(c,a.operator_config,a.slot,a.output)
    else:
     notification,_=build_call(c,32,a.instance,100)
     result=execute_once(c,a.instance,a.output,a.operator_config,a.artifact_slot,a.receipt_key) if notification[1] else None
   finally:c.close()
   if a.command!='worker' or a.once:break
   if result is not None:
    print(json.dumps({k:v for k,v in result.items() if k!='contract'},indent=2),flush=True)
  if isinstance(result,dict):result={k:v for k,v in result.items() if k!='contract'}
 print(json.dumps(result,indent=2));return 0

if __name__=='__main__':raise SystemExit(main())
