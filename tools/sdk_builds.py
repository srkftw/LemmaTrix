"""Complete SDK attempt publication and compiler-free saved-result inspection."""
import json,os,re,shutil,stat,sys,tempfile
from pathlib import Path
import build_jobs as jobs
import public_sdk as sdk
RECEIPT_LIMIT=1024*1024
REQUEST_FIELDS=('schema','recipe','job_id','source_root','snapshot_digest','module','entry','runtime_profile','sdk_digest','output_limit')
SDK_FIELDS=('sdk_content_id','dependency_lock_id','dependency_releases','dependency_sources')

class PublicationError(RuntimeError):
 def __init__(self,result,error):
  super().__init__('build attempt ended with status '+result['status']+'; output publication failed: '+str(error));self.result=result

def _source_records(entries):
 sdk.require(isinstance(entries,list)and 0<len(entries)<=jobs.MAX_FILES,'invalid saved source manifest')
 names=[];total=0
 for entry in entries:
  sdk.require(isinstance(entry,dict)and set(entry)=={'path','bytes','sha256'},'invalid saved source record')
  name=sdk.relative(entry['path']);names.append(name)
  sdk.require(type(entry['bytes'])is int and 0<=entry['bytes']<=jobs.MAX_INPUT and sdk.identity(entry['sha256']),'invalid saved source size/hash')
  sdk.require(not name.endswith('.lean')or entry['bytes']<=sdk.MAX_SOURCE,'saved Lean source exceeds bound');total+=entry['bytes']
 sdk.require(names==sorted(set(names))and total<=jobs.MAX_INPUT,'saved source manifest is not a bounded canonical closure')
 return entries

def _inspect(directory):
 raw=sdk._sdk_member(directory,'build-result.json',RECEIPT_LIMIT)
 def invalid(value):raise ValueError('invalid saved JSON constant: '+value)
 result=json.loads(raw,object_pairs_hook=jobs._unique_object,parse_constant=invalid)
 sdk.require(isinstance(result,dict)and result.get('schema')==1 and result.get('recipe')==jobs.RECIPE,'unsupported saved build receipt')
 sdk.require(result.get('status')in ('ok','error','unavailable'),'saved build is not terminal')
 profile=result.get('runtime_profile');limit=result.get('output_limit')
 sdk.require(type(profile)is int and profile in (0,1,2)and type(limit)is int and (limit==0 if profile==0 else 0<limit<=(65536 if profile==1 else 262144)),'invalid saved runtime profile/output limit')
 sdk.require(isinstance(result.get('job_id'),str)and re.fullmatch('[A-Za-z0-9_-]{1,96}',result['job_id']),'invalid saved job identity')
 for name in ('source_root','snapshot_digest','sdk_digest','request_digest','evidence_digest'):
  sdk.require(sdk.identity(result.get(name)),'invalid saved commitment: '+name)
 if profile==0:sdk.require(result.get('module')is None and result.get('entry')is None,'source-only receipt has an executable entry')
 else:sdk.require(all(isinstance(result.get(n),str)and sdk.MODULE.fullmatch(result[n])for n in ('module','entry')),'invalid saved executable entry')
 sources=_source_records(result.get('source_files'))
 sdk.require(jobs.sha(b'LT-SOURCE-SNAPSHOT-1\0'+jobs.canonical(sources))==result['snapshot_digest'],'saved source snapshot commitment mismatch')
 request={name:result[name]for name in REQUEST_FIELDS}
 if any(name in result for name in SDK_FIELDS):
  sdk.require(all(name in result for name in SDK_FIELDS),'incomplete saved SDK request')
  sdk.require(sdk.identity(result['sdk_content_id'])and sdk.identity(result['dependency_lock_id']),'invalid saved SDK/lock identity')
  releases=result['dependency_releases'];sdk.require(isinstance(releases,list)and len(releases)<=sdk.MAX_DEPENDENCIES and all(sdk.identity(x)for x in releases)and len(set(releases))==len(releases),'invalid saved dependency releases')
  if result['dependency_sources']:_source_records(result['dependency_sources'])
  else:sdk.require(result['dependency_sources']==[],'invalid saved dependency source manifest')
  request.update({name:result[name]for name in SDK_FIELDS})
 if 'toolchain_id'in result:
  sdk.require(sdk.identity(result['toolchain_id']),'invalid saved worker identity');request['toolchain_id']=result['toolchain_id']
 if 'toolchain_descriptor'in result:
  sdk.require(isinstance(result['toolchain_descriptor'],dict)and jobs.sha(jobs.canonical(result['toolchain_descriptor']))==result.get('toolchain_descriptor_sha256'),'saved toolchain descriptor commitment mismatch')
 sdk.require(jobs.sha(b'LT-BUILD-JOB-1\0'+jobs.canonical(request))==result['request_digest'],'saved build request commitment mismatch')
 sdk.require(jobs.seal_result(dict(result))['evidence_digest']==result['evidence_digest'],'saved build evidence commitment mismatch')
 artifact=None
 if result['status']=='ok'and profile:
  artifact=result.get('artifact');sdk.require(isinstance(artifact,dict)and type(artifact.get('bytes'))is int and 0<artifact['bytes']<=limit and sdk.identity(artifact.get('sha256')),'invalid saved artifact declaration')
  # The receipt's path is historical metadata, never an instruction to open it.
  binary=sdk._sdk_member(directory,'app.bin',limit,artifact['bytes']);sdk.require(jobs.sha(binary)==artifact['sha256'],'saved artifact hash mismatch')
 else:
  sdk.require('artifact'not in result,'failed/source-only receipt declares a successful artifact')
  try:os.stat('app.bin',dir_fd=directory,follow_symlinks=False)
  except FileNotFoundError:pass
  else:raise ValueError('failed/source-only build must not contain app.bin')
  if result['status']=='ok':sdk.require(result.get('source_only')is True and result.get('facet')=='DevelopmentArtifact','invalid source-only completion')
 return result,artifact

def inspect_saved(directory,project_files=None):
 with sdk._sdk_directory(directory)as selected:result,artifact=_inspect(selected)
 if project_files is not None:
  snapshot,records=jobs.source_commitment(project_files)
  sdk.require(snapshot==result['snapshot_digest']and records==result['source_files'],'saved build belongs to a different project snapshot; keep it as the earlier build and use a fresh output for current source')
 return dict(schema=1,status='consistent',build_status=result['status'],snapshot_digest=result['snapshot_digest'],request_digest=result['request_digest'],evidence_digest=result['evidence_digest'],worker_id=result.get('toolchain_id'),artifact=None if artifact is None else dict(member='app.bin',bytes=artifact['bytes'],sha256=artifact['sha256']),current_project='matches'if project_files is not None else'not compared',assurance='Internal consistency only; hashes do not authenticate a publisher or prove source-to-binary correctness.')

def build_attempt(files,*,outputdir,toolchain_manifest=None):
 destination=Path(os.path.abspath(outputdir));result=None
 with sdk._sdk_directory(destination.parent,create=True)as parent:
  try:os.stat(destination.name,dir_fd=parent,follow_symlinks=False)
  except FileNotFoundError:pass
  else:raise ValueError('build output already exists; preserve it and choose a fresh --output directory')
  name=Path(tempfile.mkdtemp(prefix='.lt-sdk-build-',dir='/proc/self/fd/'+str(parent))).name
  stage=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=parent);owned=os.fstat(stage)
  def owns_stage():
   try:current=os.stat(name,dir_fd=parent,follow_symlinks=False)
   except FileNotFoundError:return False
   return stat.S_ISDIR(current.st_mode)and(current.st_dev,current.st_ino)==(owned.st_dev,owned.st_ino)
  try:
   lock=sdk.validate_lock(json.loads(files['lemma.lock.json']));snapshot,_=jobs.source_commitment(files)
   result,binary=jobs._compile_source_snapshot(files,module=lock['module'],entry=lock['entry'],profile=lock['profile'],jobid='sdk-'+snapshot[:24],rootid=snapshot,outputdir=destination,toolchain_manifest=toolchain_manifest)
   jobs.seal_result(result)
   try:
    selected=Path('/proc/self/fd/'+str(stage));encoded=jobs.canonical(result)+b'\n'
    sdk.require(len(encoded)<=RECEIPT_LIMIT,'saved build receipt exceeds 1MiB')
    if binary is not None:(selected/'app.bin').write_bytes(binary)
    (selected/'build-result.json').write_bytes(encoded)
    _inspect(stage)
    sdk.require(owns_stage(),'build staging directory changed before publication')
    sdk._rename_sdk(parent,name,destination.name)
   except (OSError,ValueError)as error:raise PublicationError(result,error)from error
  finally:
   active=sys.exception()
   try:
    if owns_stage():shutil.rmtree(name,dir_fd=parent)
   except FileNotFoundError:pass
   except OSError:
    if active is None:raise
   finally:os.close(stage)
 return result
