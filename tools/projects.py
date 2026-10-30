"""Explicit guest graph import/export and host bootstrap job boundary."""
import argparse,hashlib,json,struct,sys,time
from pathlib import Path,PurePosixPath
import live
MAGIC=0x31464e4d544c

def safe_name(name):
 p=PurePosixPath(name)
 if not name or len(name.encode())>80 or p.is_absolute() or any(x in ('','.','..') for x in name.split('/')) or any(ord(c)<33 or ord(c)>126 or c in '\\:' for c in name):raise ValueError('canonical relative ASCII project name required')
 return name

def node(client,data,kind,parent=0):
 h=client.import_object(data,kind,parent)
 fields,ids=client.objects(21,h)
 if len(ids)!=64:raise ValueError('node identity response missing')
 return h,ids[:32].hex()

def manifest(entries,detail=b''):
 body=struct.pack('<4Q',MAGIC,1,len(entries),len(detail))
 for name,kind,identity in sorted(entries):
  encoded=safe_name(name).encode();body+=struct.pack('<2Q',kind,len(encoded))+bytes.fromhex(identity)+encoded.ljust(80,b'\0')
 return body+detail

def decode_manifest(data):
 if len(data)<32:raise ValueError('short manifest')
 magic,version,count,detail=struct.unpack_from('<4Q',data)
 if magic!=MAGIC or version not in (1,2) or count>32 or len(data)!=32+count*128+detail:raise ValueError('invalid manifest')
 entries=[]
 for i in range(count):
  entry=data[32+i*128:160+i*128];kind,n=struct.unpack_from('<2Q',entry)
  if not 0<n<=80:raise ValueError('name bound')
  name=safe_name(entry[48:48+n].decode('ascii'))
  if entry[48+n:]!=bytes(80-n):raise ValueError('noncanonical padding')
  entries.append((name,kind,entry[16:48].hex()))
 if entries!=sorted(entries) or len({x[0] for x in entries})!=len(entries):raise ValueError('manifest ordering')
 return entries

def canonical_node(kind,payload,parent='00'*32,schema=1):
 return hashlib.sha256(struct.pack('<4Q',0x3145444f4e544c,1,kind,schema)+hashlib.sha256(payload).digest()+bytes.fromhex(parent)).hexdigest()

def import_records(client,selected,records):
 """Opaque import adapter: the guest derives dependency order and publication."""
 entries=b''
 for root in selected:
  name=safe_name(root['name']).encode('ascii')
  if len(name)>63:raise ValueError('root name exceeds63bytes')
  entries+=struct.pack('<2Q',0,len(name))+bytes.fromhex(root['head'])+name.ljust(80,b'\0')
 transaction=client.objects(35,a=len(selected),b=len(records),c=sum(len(r['payload']) for r in records),data=entries)[0][1]
 try:
  for ordinal,record in enumerate(records):
   payload=record['payload']
   metadata=bytes.fromhex(record['id'])+bytes.fromhex(record.get('parent','00'*32))+hashlib.sha256(payload).digest()
   client.objects(36,transaction,ordinal,record['kind'],len(payload),record.get('schema',1),data=metadata)
   for offset in range(0,len(payload),512):client.objects(37,transaction,ordinal,offset,data=payload[offset:offset+512])
  try:
   client.objects(44,transaction,transaction)
  except ValueError as error:
   if str(error)!='Objects status7':raise
   fields,data=client.objects(38,transaction)
  else:
   deadline=time.monotonic()+900
   while True:
    job,data=client.objects(45,transaction)
    if job[2]==4:
     fields=(0,len(data)//8);client.objects(46,transaction,4);break
    if job[2]>=5:
     client.objects(46,transaction,4)
     raise ValueError('async import failed state'+str(job[2])+' reason'+str(job[5]))
    if time.monotonic()>=deadline:raise TimeoutError('async import '+str(transaction)+' remains queryable; deadline is not rollback')
    time.sleep(.01)
  if fields[1]!=len(selected) or len(data)!=8*len(selected):raise ValueError('native importer returned incomplete root set')
  return [dict(root,cap=cap) for root,cap in zip(selected,struct.unpack('<'+'Q'*len(selected),data))]
 except BaseException:
  try:client.objects(39,transaction)
  except (OSError,ValueError,EOFError):pass
  raise

def project_identity(client,root):
 fields,data=client.objects(34,root)
 if len(data)!=128:raise ValueError('logical project identity response missing')
 return data[96:128].hex()

def roots(client,include_identity=False):
 answer=[];cursor=0
 while cursor<64:
  f,data=client.objects(23,a=cursor)
  if not f[1]:break
  answer.append(dict(cap=f[1],name=data[32:32+f[2]].decode(),head=data[:32].hex()))
  if include_identity:answer[-1]['project_id']=project_identity(client,f[1])
  if f[3]<=cursor:raise ValueError('root cursor did not advance')
  cursor=f[3]
 return answer

def resolve(client,root,identity):return client.objects(25,root,data=bytes.fromhex(identity))[0][1]
def snapshot(client,root,head=None):
 h=client.objects(24,root)[0][1] if head is None else resolve(client,root,head)
 f,ids=client.objects(21,h);identity=ids[:32].hex()
 files={}
 for name,kind,member in decode_manifest(client.read_object(h)):
  if kind!=10:continue
  handle=resolve(client,root,member)
  files[name]=client.read_object(handle,True)
 return identity,files

def queued_build(client):
 raw=client.request(160,struct.pack('<8Q',2,0,0,0,0,0,0,1))
 if len(raw)<64:raise ValueError('short build queue response')
 status=struct.unpack_from('<Q',raw)[0]
 if status==6:return None
 if status or len(raw)!=256:raise ValueError('invalid queued build job')
 return raw

def frozen_build(client,raw):
 f=struct.unpack_from('<8Q',raw)
 job=dict(job_id=f[1],job_service=f[3],source_root_capability=f[4],runtime_profile=f[5],source_root=raw[64:96].hex(),toolchain_id=raw[128:160].hex(),project_id=raw[160:192].hex(),live_root_binding=struct.unpack_from('<Q',raw,192)[0],requester=struct.unpack_from('<Q',raw,200)[0],delegator=struct.unpack_from('<Q',raw,208)[0],recipe=struct.unpack_from('<Q',raw,216)[0])
 if not job['job_id'] or not job['job_service'] or not job['source_root_capability'] or job['runtime_profile']!=2:raise ValueError('incompatible graphical build job')
 meta,data=client.objects(29,job['source_root_capability'])
 if meta[2]>63 or meta[5]!=1 or data[:32].hex()!=job['source_root'] or meta[7]!=job['live_root_binding'] or job['recipe']!=1 or job['requester']!=job['delegator'] or project_identity(client,job['source_root_capability'])!=job['project_id']:raise ValueError('queued job does not identify its immutable frozen root')
 job['project_name']=data[32:32+meta[2]].decode('ascii')
 return job

def compile_frozen(job,files,outputdir):
 import build_jobs
 result=build_jobs.build_source_snapshot(files,module='Main',entry='Main.main',profile=job['runtime_profile'],jobid=job['job_id'],rootid=job['source_root'],outputdir=outputdir)
 if result.get('toolchain_id')!=job['toolchain_id']:raise ValueError('guest frozen compiler/toolchain commitment differs; build result not returned')
 result['guest_session']={k:job[k] for k in ('job_service','job_id','source_root_capability','project_name','project_id','live_root_binding','requester','delegator','recipe')}
 result['delivered']=False
 return result

def save_build(result,outputdir):
 outputdir=Path(outputdir);outputdir.mkdir(parents=True,exist_ok=True)
 (outputdir/'job.result.json').write_text(json.dumps(result,indent=2)+'\n')

def build_bridge(client,outputdir,module='Main',entry='Main.main',defer_result=False):
 if module!='Main' or entry!='Main.main':raise ValueError('graphical jobs freeze the fixed Main.main recipe')
 raw=queued_build(client)
 if raw is None:raise ValueError('no queued build job')
 job=frozen_build(client,raw)
 actual,files=snapshot(client,job['source_root_capability'],job['source_root'])
 if actual!=job['source_root']:raise ValueError('frozen source root mismatch')
 result=compile_frozen(job,files,outputdir)
 if not defer_result:complete_build(client,result)
 save_build(result,outputdir)
 return result

def complete_build(client,result):
 session=result['guest_session'];jobid=int(session['job_id']);service=int(session['job_service']);profile=int(result['runtime_profile']);head=result['source_root']
 located=result.get('diagnostics',[])
 diagnostic=(f"{located[0]['path']}:{located[0]['line']}:{located[0]['column']}: {located[0]['message']}" if located else result.get('diagnostic_text',''))
 diag=diagnostic.encode('utf-8')[:512]
 # Preserve only complete UTF-8 in the guest display diagnostic bound.
 diag=diag.decode('utf-8','ignore').encode('utf-8')
 artifact=result.get('artifact',{}).get('sha256','00'*32)
 payload=struct.pack('<8Q',3,jobid,service,2 if result['status']=='ok' else 3,0,profile,len(diag),1)+bytes.fromhex(head)+bytes.fromhex(artifact)+bytes.fromhex(result['request_digest'])+bytes.fromhex(result['toolchain_id'])+diag
 accepted=client.request(160,payload)
 if len(accepted)<128 or struct.unpack_from('<Q',accepted)[0]:raise ValueError('guest rejected stale/wrong source build response')
 result['delivered']=True
 return accepted

def publish_result(result_path,key,name,version,output,parent=None,*,client=None,rights=768,attach_root=None,authority_root=None):
 import releases,packaging as pkg
 if client is None:raise ValueError('publishing requires the current guest connection for referenced Build/Evidence content')
 r=json.loads(Path(result_path).read_text())
 if r['status']!='ok':raise ValueError('cannot publish failed build')
 artifact=Path(r['artifact']['path']);binary=artifact.read_bytes()
 if hashlib.sha256(binary).hexdigest()!=r['artifact']['sha256']:raise ValueError('build artifact changed after result')
 session=r.get('guest_session',{})
 if authority_root is None:raise ValueError('publishing requires an explicitly selected live root capability')
 selected_binding=client.objects(29,authority_root)[0][7]
 selected_identity=project_identity(client,authority_root)
 if not {'job_service','job_id','source_root_capability'}<=session.keys():raise ValueError('current guest job authority is absent; imported build assertions cannot manufacture it')
 authority_raw=client.request(160,struct.pack('<8Q',7,session['job_id'],0,0,0,0,0,1))
 if len(authority_raw)!=256:raise ValueError('native job authority response missing')
 actual_authority=frozen_build(client,authority_raw)
 if any(session.get(field)!=actual_authority[field] for field in ('job_service','job_id','source_root_capability','project_id','live_root_binding','requester','delegator','recipe')) or selected_binding!=actual_authority['live_root_binding'] or selected_identity!=actual_authority['project_id']:raise ValueError('selected live root/requester differs from canonical guest job authority')
 job_request=struct.pack('<8Q',6,session['job_id'],0,0,0,0,0,1)
 raw=client.request(160,job_request)
 if len(raw)<128:raise ValueError('guest Build/Evidence response is missing')
 jf=struct.unpack_from('<8Q',raw)
 if jf[0] or jf[3]!=session['job_service'] or raw[64:96].hex()!=r['source_root'] or raw[96:128].hex()!=r['artifact']['sha256']:raise ValueError('guest job/source/output commitments differ from selected build')
 build_handle,evidence_handle=jf[6],jf[7]
 if not build_handle or not evidence_handle:raise ValueError('guest Build/Evidence records unavailable')
 _,build_ids=client.objects(21,build_handle);_,evidence_ids=client.objects(21,evidence_handle)
 source_handle=client.objects(24,session['source_root_capability'])[0][1]
 _,source_ids=client.objects(21,source_handle)
 if source_ids[:32].hex()!=r['source_root']:raise ValueError('frozen source changed')
 source_payload=client.read_object(source_handle)
 source_entries=decode_manifest(source_payload)
 # Every source member is explicitly resolved under the frozen job scope before
 # it can enter a published snapshot. Session handles stay in local job state.
 for _,kind,identity in source_entries:
  if kind==10:resolve(client,session['source_root_capability'],identity)
 # Fork provenance is validated in Objects. Its explicitly chosen publisher
 # must also be checked before the bootstrap signer sees a request, rather than
 # relying only on later Release graph rejection.
 publisher_id=hashlib.sha256(releases.capsule.modulus(key)).digest()
 origin=source_handle
 for _ in range(64):
  origin_meta,origin_ids=client.objects(21,origin)
  if origin_meta[4]!=11:raise ValueError('canonical signing origin is not a Manifest')
  if origin_meta[5]==2 or origin_ids[32:64]==bytes(32):
   origin_entries=decode_manifest(client.read_object(origin));break
  origin=resolve(client,session['source_root_capability'],origin_ids[32:64].hex())
 else:raise ValueError('canonical signing origin exceeds bounded ancestry')
 for _,kind,identity in origin_entries:
  if kind==15:
   lineage=client.read_object(resolve(client,session['source_root_capability'],identity))
   if len(lineage)!=208 or struct.unpack_from('<Q',lineage,32)[0]!=0x314b524f46544c or lineage[144:176]!=publisher_id:
    raise ValueError('selected signing key is not the publisher authorized by this canonical Fork lineage')
 records=[dict(path=m['path'],sha256=m['sha256'],size=m['bytes']) for m in r['source_files']]
 evidence=[dict(kind='host-sandbox-build',job_id=r['job_id'],source_root=r['source_root'],request_digest=r['request_digest'],toolchain_id=r['toolchain_id'],binary_sha256=r['artifact']['sha256'],source_to_binary='unverified')]
 envelope,signed_manifest=releases.make(artifact,name,version,rights,key,parent=parent,license='NOASSERTION',evidence=evidence,profile=r['runtime_profile'],source_records_override=records,logical_project_id=session['project_id'])
 # Signing and writing the explicit package are distinct from graph admission,
 # publisher trust, install approval and local execution.
 pkg.write_new(Path(output),envelope);pkg.write_new(Path(str(output)+'.manifest.json'),pkg.canonical(signed_manifest))
 chunks=[]
 for i,offset in enumerate(range(0,len(binary),65536)):
  _,identity=node(client,binary[offset:offset+65536],10)
  chunks.append((f'code/chunk-{i:04d}.bin',10,identity))
 binary_manifest,binary_id=node(client,manifest(chunks,pkg.canonical({'schema':1,'bytes':len(binary),'sha256':r['artifact']['sha256']})),11)
 canonical_manifest=pkg.canonical(signed_manifest)
 canonical_sources=pkg.canonical(signed_manifest['sources'])
 canonical_evidence=pkg.canonical(signed_manifest['evidence'])
 canonical_license=pkg.canonical({'license':signed_manifest['license'],'distribution_authority':'explicit local author declaration'})
 detail=struct.pack('<8Q',0x31544e43524c544c,1,768,len(canonical_manifest),len(canonical_sources),len(canonical_evidence),len(canonical_license),0)+envelope[:768]+canonical_manifest+canonical_sources+canonical_evidence+canonical_license
 release_entries=[('build',12,build_ids[:32].hex()),('code',11,binary_id),('evidence',14,evidence_ids[:32].hex()),('source',11,r['source_root'])]
 release_handle,release_node_id=node(client,manifest(release_entries,detail),13)
 published_entries=[entry for entry in source_entries if entry[1]==10]
 if any(path=='release.ltrel' for path,_,_ in published_entries):raise ValueError('source name release.ltrel conflicts with explicit release attachment')
 published_entries.append(('release.ltrel',13,release_node_id))
 snapshot_detail=pkg.canonical({'schema':1,'kind':'published-project-snapshot','source_root':r['source_root'],'release_node':release_node_id,'signed_release':envelope[160:192].hex()})
 # The caller can request an exact CAS attachment. A build of A never overwrites
 # intervening edits B: a separately named published snapshot is created instead.
 attached=False;root=0;expected=bytes(32);ancestry=0
 if attach_root is not None:
  _,meta=client.objects(29,attach_root)
  if meta[:32].hex()==r['source_root']:
   root=attach_root;expected=meta[:32];ancestry=client.objects(24,root)[0][1];attached=True
 snapshot,snapshot_id=node(client,manifest(published_entries,snapshot_detail),11,ancestry)
 snapshot_name=(next(x['name'] for x in roots(client) if x['cap']==root) if attached else f'{name}-release-{version}')
 encoded=safe_name(snapshot_name).encode('ascii')
 if len(encoded)>63:raise ValueError('published snapshot name exceeds63bytes')
 try:rf,_=client.objects(22,snapshot,root,len(encoded),data=expected+encoded.ljust(64,b'\0'))
 except ValueError:
  if not attached:raise
  # Preserve a concurrent edit rather than retrying a changed expected head.
  snapshot,snapshot_id=node(client,manifest(published_entries,snapshot_detail),11)
  encoded=f'{name}-release-{version}'.encode('ascii')
  if len(encoded)>63:raise ValueError('published snapshot name exceeds63bytes')
  rf,_=client.objects(22,snapshot,0,len(encoded),data=bytes(32)+encoded.ljust(64,b'\0'));attached=False
 published_root=rf[1]
 processes=client.request(2)
 shell=struct.unpack_from('<Q',processes,128)[0] if len(processes)>=160 else 0
 shell_root=client.objects(27,published_root,shell,127)[0][1] if shell else 0
 result=releases.inspect(envelope,manifest=signed_manifest)
 result['content']={'release_node':release_node_id,'release_handle':release_handle,'binary_manifest':binary_id,'build_node':build_ids[:32].hex(),'evidence_node':evidence_ids[:32].hex(),'source_root':r['source_root'],'snapshot_root':published_root,'snapshot_head':snapshot_id,'snapshot_name':encoded.decode('ascii'),'shell_root_capability':shell_root,'attached_to_selected_root':attached,'guest_present_commitments_checked':True,'publisher_signature':'requires Launcher verification under current local trust','installed':False}
 Path(str(output)+'.content.json').write_text(json.dumps({'schema':1,'session_only':True,'release_handle':release_handle,'release_id':envelope[160:192].hex(),'snapshot_head':snapshot_id},indent=2)+'\n')
 return result

def failed_job(job,message):
 # A rejected scope or unavailable bootstrap is an attributable failed result,
 # never a compilation claim or permission to sign its input.
 request={'schema':1,'recipe':'lemmatrix-worker-rejection-1','job_id':str(job['job_id']),'source_root':job['source_root'],'runtime_profile':2,'toolchain_id':job['toolchain_id'],'diagnostic':message}
 return {**request,'status':'error','diagnostics':[],'diagnostic_text':message[:512],
  'request_digest':hashlib.sha256(b'LT-BUILD-JOB-REJECTION-1\0'+json.dumps(request,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
  'guest_session':{k:job[k] for k in ('job_service','job_id','source_root_capability','project_name','project_id','live_root_binding','requester','delegator','recipe')},'delivered':False,'compiled':False}

def version_tuple(value):
 import re
 if not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)',value):raise ValueError('canonical major.minor.patch version required')
 fields=tuple(map(int,value.split('.')))
 if max(fields)>0xffffffff:raise ValueError('version exceeds32-bit bound')
 return fields

def next_version(value):
 fields=list(value)
 for i in (2,1,0):
  if fields[i]<0xffffffff:fields[i]+=1;return tuple(fields)
  fields[i]=0
 raise ValueError('release version space exhausted')

def current_release(client,name,publication_id=None):
 import releases
 try:raw=client.request(29,bytes.fromhex(publication_id) if publication_id else releases.project(name))
 except ValueError as error:
  if str(error)=='guest rejected command29, status1':return None
  raise
 if len(raw)!=512 or raw[128:160]!=(bytes.fromhex(publication_id) if publication_id else releases.project(name)):raise ValueError('current active release identity mismatch')
 return {'release_id':raw[160:192].hex(),'version':struct.unpack_from('<3Q',raw,72)}

def serve(socket,project,sign_key,output,version='0.1.0',poll_interval=.5,*,root,requester=None):
 import releases
 releases.project(project)
 if not sign_key.is_file():raise ValueError('explicit publisher signing key does not exist')
 # Key parsing stays in the publisher process, before any untrusted elaboration.
 import capsule
 publisher_id=hashlib.sha256(capsule.modulus(sign_key)).hexdigest()
 approved_client=live.Client(socket,timeout=30)
 try:
  selected=next((item for item in roots(approved_client,include_identity=True) if item['cap']==root),None)
  if selected is None:raise ValueError('explicit selected live root capability is unavailable')
  binding=approved_client.objects(29,root)[0][7]
  if not requester:raise ValueError('explicit authorized requester is required')
 finally:approved_client.close()
 authority=dict(root=root,project_id=selected['project_id'],live_root_binding=binding,requester=requester,publisher_id=publisher_id,recipe=1,rights=768)
 publication_id=releases.publication(selected['project_id'],publisher_id).hex()
 counter=version_tuple(version);output=Path(output).resolve();output.mkdir(parents=True,exist_ok=True)
 delay=max(.1,min(float(poll_interval),5.0));backoff=delay
 def report(event,**fields):print(json.dumps(dict(event=event,project=project,**fields),sort_keys=True),flush=True)
 report('ready',authority=authority,publication_id=publication_id,recipe='Main.main/profile2',rights=768,signing='explicit host key, outside compilation sandbox',approval='F12 review required')
 try:
  while True:
   client=None;job=None
   try:
    client=live.Client(socket,timeout=240);raw=queued_build(client)
    if raw is None:
     client.close();client=None;time.sleep(delay);continue
    job=frozen_build(client,raw)
    directory=output/('session-'+str(job['job_service']))/('job-'+str(job['job_id']))
    directory.mkdir(parents=True,exist_ok=True)
    if any(job[field]!=authority[field] for field in ('project_id','live_root_binding','requester','recipe')):
     result=failed_job(job,'Publisher worker scope denied: canonical identity, selected live root, requester or recipe differs. No source exported or signed.')
     complete_build(client,result);save_build(result,directory)
     report('rejected',job=job['job_id'],reason=result['diagnostic_text']);continue
    actual,files=snapshot(client,job['source_root_capability'],job['source_root'])
    if actual!=job['source_root']:raise ValueError('frozen source root mismatch')
    client.close();client=None
    report('building',job=job['job_id'],source_root=job['source_root'])
    result=compile_frozen(job,files,directory)
    client=live.Client(socket,timeout=240)
    complete_build(client,result);save_build(result,directory)
    if result['status']!='ok':
     report('diagnostic',job=job['job_id'],source_root=job['source_root'],status=result['status'],diagnostics=result.get('diagnostics',[]),message=result.get('diagnostic_text','')[:2048]);continue
    # The selected live capability must remain valid through the signing instant.
    if client.objects(29,root)[0][7]!=binding or project_identity(client,root)!=authority['project_id']:raise ValueError('selected live root authority was revoked or replaced')
    active=current_release(client,project,publication_id)
    selected=max(counter,next_version(active['version'])) if active else counter
    parent=active['release_id'] if active else None
    release_path=directory/('release-'+'.'.join(map(str,selected))+'.ltrel')
    # CAS attachment is optional. A completed build of A does not replace head B.
    current=next((r for r in roots(client) if r['cap']==root and r['head']==job['source_root']),None)
    published=publish_result(directory/'job.result.json',sign_key,project,'.'.join(map(str,selected)),release_path,parent,client=client,rights=768,attach_root=current['cap'] if current else None,authority_root=root)
    counter=next_version(selected)
    report('published',job=job['job_id'],source_root=job['source_root'],release=published['release_id'],version=published['version'],parent=parent,path=str(release_path),installed=False)
    staged=client.stage(release_path)
    if staged['release_id']!=published['release_id']:raise ValueError('staged release differs from signed result')
    report('staged',job=job['job_id'],source_root=job['source_root'],release=published['release_id'],version=published['version'],parent=parent,path=str(release_path),signature_verified=staged['guest_signature_verified'],material_checked=staged.get('guest_material_commitments_checked',False),installed=False,approval='Review F12, then physical Enter')
    backoff=delay
   except (EOFError,OSError,ValueError,RuntimeError) as error:
    # A disconnected/stale job cannot be signed or silently rebound to a new
    # session. Bootstrap failures leave an attributable failed job when possible.
    if job is not None:
     try:
      if client:client.close()
      client=live.Client(socket,timeout=30)
      failed=failed_job(job,'Bootstrap worker failed: '+str(error));complete_build(client,failed);save_build(failed,directory)
     except (EOFError,OSError,ValueError,RuntimeError):pass
    report('error',job=job['job_id'] if job else None,message=str(error)[:2048]);time.sleep(backoff);backoff=min(backoff*2,5.0)
   finally:
    if client:client.close()
 except KeyboardInterrupt:report('stopped')
 return 0

def main(argv=None):
 p=argparse.ArgumentParser(description='Canonical guest Project roots; explicit byte import/export')
 p.add_argument('--socket',type=Path,required=True);s=p.add_subparsers(dest='cmd',required=True)
 s.add_parser('list')
 a=s.add_parser('serve',help='explicit persistent sandbox build and scoped publisher worker; never auto-approves');a.add_argument('--project',required=True);a.add_argument('--sign-key',type=Path,required=True);a.add_argument('--output',type=Path,required=True);a.add_argument('--version',default='0.1.0');a.add_argument('--poll-interval',type=float,default=.5);a.add_argument('--root',type=int,required=True);a.add_argument('--requester',type=int,required=True)
 a=s.add_parser('build');a.add_argument('--output',type=Path,required=True);a.add_argument('--module',default='Main');a.add_argument('--entry',default='Main.main');a.add_argument('--defer-result',action='store_true')
 a=s.add_parser('complete');a.add_argument('result',type=Path)
 a=s.add_parser('publish');a.add_argument('result',type=Path);a.add_argument('--sign-key',type=Path,required=True);a.add_argument('--name',required=True);a.add_argument('--version',required=True);a.add_argument('--parent');a.add_argument('--rights',type=lambda x:int(x,0),default=768);a.add_argument('--attach-root',type=int);a.add_argument('--root',type=int,required=True);a.add_argument('--output',type=Path,required=True)
 a=s.add_parser('import');a.add_argument('directory',type=Path);a.add_argument('--name',required=True);a.add_argument('--root',type=int,default=0);a.add_argument('--expected')
 a=s.add_parser('export');a.add_argument('--root',type=int,required=True);a.add_argument('--head');a.add_argument('--output',type=Path,required=True)
 a=s.add_parser('share');a.add_argument('--root',type=int,required=True);a.add_argument('--to',type=int,required=True);a.add_argument('--rights',type=int,default=127)
 args=p.parse_args(argv)
 if args.cmd=='serve':return serve(args.socket,args.project,args.sign_key,args.output,args.version,args.poll_interval,root=args.root,requester=args.requester)
 client=live.Client(args.socket)
 try:
  if args.cmd=='build':print(json.dumps(build_bridge(client,args.output,args.module,args.entry,args.defer_result),indent=2))
  elif args.cmd=='complete':
   result=json.loads(args.result.read_text());complete_build(client,result);args.result.write_text(json.dumps(result,indent=2)+'\n');print(result['source_root'])
  elif args.cmd=='publish':print(json.dumps(publish_result(args.result,args.sign_key,args.name,args.version,args.output,args.parent,client=client,rights=args.rights,attach_root=args.attach_root,authority_root=args.root),indent=2))
  elif args.cmd=='list':print(json.dumps(roots(client,include_identity=True),indent=2))
  elif args.cmd=='share':print(client.objects(27,args.root,args.to,args.rights)[0][1])
  elif args.cmd=='import':
   directory=args.directory.resolve();entries=[];total=0;records=[]
   paths=sorted(x for x in directory.rglob('*') if x.is_file())
   if not 1<=len(paths)<=24:raise ValueError('project requires1..24members')
   for path in paths:
    if path.is_symlink() or not path.resolve().is_relative_to(directory):raise ValueError('symlink source denied')
    relative=safe_name(path.relative_to(directory).as_posix());data=path.read_bytes();total+=len(data)
    if total>1048576 or len(data)>65536:raise ValueError('project import exceeds bounded profile')
    identity=canonical_node(10,data);records.append(dict(kind=10,id=identity,payload=data));entries.append((relative,10,identity))
   if args.root:
    # Editing a live root remains its explicit expected-head transition. New
    # external project imports always use the native transaction below.
    for record in records:node(client,record['payload'],10)
    parent=client.objects(24,args.root)[0][1]
    h,identity=node(client,manifest(entries),11,parent)
    name=safe_name(args.name).encode();expected=bytes.fromhex(args.expected) if args.expected else bytes(32)
    f,_=client.objects(22,h,args.root,len(name),data=expected+name.ljust(64,b'\0'));cap=f[1]
   else:
    payload=manifest(entries);identity=canonical_node(11,payload)
    # Deliberately offer the root first: ordering is not a host responsibility.
    records.insert(0,dict(kind=11,id=identity,payload=payload))
    cap=import_records(client,[dict(name=args.name,head=identity)],records)[0]['cap']
   process=client.request(2);shell=struct.unpack_from('<Q',process,4*32)[0]
   client.objects(27,cap,shell,127)
   print(json.dumps(dict(root=cap,head=identity,name=args.name,members=len(entries),bytes=total),indent=2))
  elif args.cmd=='export':
   identity,files=snapshot(client,args.root,args.head)
   args.output.mkdir(parents=True,exist_ok=False)
   for name,data in files.items():
    path=args.output/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
   (args.output/'project.snapshot.json').write_text(json.dumps(dict(schema=1,head=identity,members=[dict(path=n,sha256=hashlib.sha256(b).hexdigest(),size=len(b)) for n,b in sorted(files.items())]),indent=2)+'\n')
   print(identity)
 finally:client.close()
 return 0
if __name__=='__main__':sys.exit(main())
