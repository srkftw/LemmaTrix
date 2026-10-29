"""Exact source snapshot compilation in an OS-enforced, key-free build sandbox."""
import base64,hashlib,json,os,re,shutil,signal,subprocess,sys,tempfile
from pathlib import Path,PurePosixPath
import driver
ROOT=driver.ROOT
MAX_FILES=128;MAX_INPUT=4*1024*1024
SDK_MODULES=['Guest.Primitives','Guest.Structured','Guest.Effects','Guest.LiveSDK','Guest.NetworkSDK','Guest.LiveMemory','Guest.Keyboard','Guest.Raster']
RECIPE='lemmatrix-lean-rv64-structured-2'

def sha(data):return hashlib.sha256(data).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()
def safe_name(name):
 if not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_./-]{0,127}',name):raise ValueError('invalid project-relative path')
 p=PurePosixPath(name)
 if str(p)!=name or any(v in ('','..','.') for v in p.parts) or p.is_absolute():raise ValueError('noncanonical project-relative path')
 if p.parts[0] in ('Guest','Compiler','runtime'):raise ValueError('project shadows reserved SDK namespace')
 return name

def source_commitment(files):
 if not files or len(files)>MAX_FILES or sum(len(v) for v in files.values())>MAX_INPUT:raise ValueError('source snapshot exceeds128 files/4MiB')
 manifest=[]
 for name,data in sorted(files.items()):
  safe_name(name)
  if not isinstance(data,bytes):raise ValueError('snapshot members must be bytes')
  manifest.append({'path':name,'bytes':len(data),'sha256':sha(data)})
 return sha(b'LT-SOURCE-SNAPSHOT-1\0'+canonical(manifest)),manifest

def _modules(files):
 # Reuse the dependency parser used by the incremental builder, without running
 # project code. Imports may resolve only to supplied modules or the fixed SDK
 # and public Lean toolchain modules. Core imports remain sandboxed execution.
 import live_build
 modules={name[:-5].replace('/','.') : data for name,data in files.items() if name.endswith('.lean')}
 for name in modules:
  if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*',name):raise ValueError('Lean module path is invalid')
 ordered=[];active=set()
 def visit(name):
  if name in ordered:return
  if name in active:raise ValueError('cyclic project import')
  active.add(name)
  # Parser takes a read_text source object, so no temporary untrusted path needed.
  class Source:
   def read_text(self):return modules[name].decode('utf-8')
  for dependency in live_build.imports(Source()):
   if dependency in modules:visit(dependency)
   elif dependency.startswith('Guest.') and dependency not in SDK_MODULES:raise ValueError('import is outside approved SDK closure: '+dependency)
   elif dependency.startswith(('Compiler.','Examples.')):raise ValueError('import is outside snapshot closure: '+dependency)
  active.remove(name);ordered.append(name)
 for name in sorted(modules):visit(name)
 return ordered

def _toolchain():
 names=['lean','clang','ld.lld','llvm-objcopy']
 tools={name:str(Path(driver.tool(name)).resolve()) for name in names}
 for name,path in tools.items():
  version=subprocess.run([path,'--version'],capture_output=True,text=True,check=True,timeout=10).stdout
  expected=driver.LOCK['lean' if name=='lean' else 'llvm']
  if expected not in version:raise RuntimeError(name+' version differs from pinned toolchain '+expected)
 roots=set()
 for executable in [*tools.values(),str(Path(sys.executable).resolve())]:
  parts=Path(executable).parts
  if len(parts)<4 or parts[1:3]!=('nix','store'):raise RuntimeError('build sandbox requires a declared immutable toolchain closure; this host tool is not in the Nix store: '+executable)
  roots.add(str(Path(*parts[:4])))
 query=shutil.which('nix-store')
 if not query:raise RuntimeError('nix-store is required to resolve the exact readonly toolchain closure')
 closure=subprocess.run([query,'-qR',*sorted(roots)],capture_output=True,text=True,check=True,timeout=20).stdout.splitlines()
 if not closure or any(not p.startswith('/nix/store/') or not Path(p).is_dir() for p in closure):raise RuntimeError('invalid toolchain closure')
 return tools,sorted(set(closure))

def _diagnostics(text,manifest,rootid):
 ids={f['path']:f['sha256'] for f in manifest};records=[]
 for line in text.splitlines():
  m=re.match(r'(?:/input/)?([^:\n]+\.lean):(\d+):(\d+):\s*(.*)',line)
  if m and m[1] in ids:records.append({'path':m[1],'line':int(m[2]),'column':int(m[3]),'source_id':ids[m[1]],'source_root':rootid,'message':m[4][:2048]})
  if len(records)>=32:break
 return records

def compiler_identity():
 sdk_files=[ROOT/(n.replace('.','/')+'.lean') for n in SDK_MODULES]+[ROOT/'Compiler/Main.lean',ROOT/'runtime/primitives.S',ROOT/'runtime/app.ld',ROOT/'runtime/app2.ld',ROOT/'tools/build_sandbox_runner.py',ROOT/'tools/build_jobs.py']
 entries={str(p.relative_to(ROOT)):p.read_bytes() for p in sdk_files}
 sdk_digest=sha(canonical([{'path':name,'sha256':sha(data)} for name,data in entries.items()]))
 tools,closure=_toolchain()
 return sha(canonical({'lock':driver.LOCK,'closure':closure,'tools':tools,'sdk_digest':sdk_digest,'recipe':RECIPE}))

def build_source_snapshot(files,*,entry,module,profile,jobid,rootid,outputdir,output_limit=None):
 """Build only frozen files. The caller must obtain them from an authorized root.
    Returns a bounded attributable result; publisher signing is a separate API.
 """
 files=dict(files)
 if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*',entry) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*',module):raise ValueError('invalid module/entry')
 if profile not in (1,2):raise ValueError('unsupported runtime profile')
 profile_limit=262144 if profile==2 else 65536
 output_limit=profile_limit if output_limit is None else output_limit
 if not isinstance(output_limit,int) or not 0<output_limit<=profile_limit:raise ValueError('output byte limit exceeds runtime profile')
 if not re.fullmatch('[0-9a-f]{64}',rootid):raise ValueError('source root must be a stable256-bit identity')
 if not re.fullmatch('[A-Za-z0-9_-]{1,96}',str(jobid)):raise ValueError('invalid build job identity')
 snapshot,manifest=source_commitment(files);modules=_modules(files)
 if module not in modules:raise ValueError('entry module absent from snapshot')
 sdk_files=[ROOT/(n.replace('.','/')+'.lean') for n in SDK_MODULES]+[ROOT/'Compiler/Main.lean',ROOT/'runtime/primitives.S',ROOT/'runtime/app.ld',ROOT/'runtime/app2.ld',ROOT/'tools/build_sandbox_runner.py',ROOT/'tools/build_jobs.py']
 sdk_entries={str(p.relative_to(ROOT)):p.read_bytes() for p in sdk_files}
 sdk_digest=sha(canonical([{'path':name,'sha256':sha(data)} for name,data in sdk_entries.items()]))
 request={'schema':1,'recipe':RECIPE,'job_id':str(jobid),'source_root':rootid,'snapshot_digest':snapshot,'module':module,'entry':entry,'runtime_profile':profile,'sdk_digest':sdk_digest,'output_limit':output_limit}
 result={**request,'request_digest':sha(b'LT-BUILD-JOB-1\0'+canonical(request)),'status':'unavailable','diagnostics':[],'diagnostic_text':'','source_files':manifest}
 outputdir=Path(outputdir);outputdir.mkdir(parents=True,exist_ok=True)
 try:tools,closure=_toolchain()
 except (OSError,RuntimeError,subprocess.SubprocessError) as error:
  result['diagnostic_text']=str(error);return result
 result['toolchain_id']=sha(canonical({'lock':driver.LOCK,'closure':closure,'tools':tools,'sdk_digest':sdk_digest,'recipe':RECIPE}))
 request['toolchain_id']=result['toolchain_id'];result['request_digest']=sha(b'LT-BUILD-JOB-1\0'+canonical(request))
 unshare=shutil.which('unshare')
 if not unshare:result['diagnostic_text']='unshare is unavailable; untrusted builds are disabled';return result
 with tempfile.TemporaryDirectory(prefix='lt-build-') as temporary:
  stage=Path(temporary);inputs=stage/'input';sdk=stage/'sdk';newroot=stage/'root'
  inputs.mkdir();sdk.mkdir();newroot.mkdir()
  for name,data in files.items():
   p=inputs/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
  for relative,data in sdk_entries.items():
   p=sdk/relative;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
  uid_tasks=0
  for proc in Path('/proc').iterdir():
   if not proc.name.isdigit():continue
   try:
    status=(proc/'status').read_text()
    uid=re.search(r'^Uid:\s+(\d+)',status,re.M);threads=re.search(r'^Threads:\s+(\d+)',status,re.M)
    if uid and threads and int(uid[1])==os.getuid():uid_tasks+=int(threads[1])
   except (OSError,ValueError):pass
  uid_limit=max(uid_tasks+64,128)
  cfg={'uid_process_limit':uid_limit,'root':str(newroot),'input':str(inputs),'sdk':str(sdk),'closure':closure,'tools':tools,'sdk_modules':SDK_MODULES,'modules':modules,'module':module,'entry':entry,'profile':profile,'output_limit':output_limit}
  config=stage/'config.json';config.write_bytes(canonical(cfg))
  command=[unshare,'--user','--map-root-user','--mount','--net','--pid','--fork',str(Path(sys.executable).resolve()),str(ROOT/'tools/build_sandbox_runner.py'),str(config)]
  # No inherited environment, stdin, credentials or directory descriptors.
  with tempfile.TemporaryFile() as transport:
   process=subprocess.Popen(command,cwd='/',env={'PATH':''},stdin=subprocess.DEVNULL,stdout=transport,stderr=transport,close_fds=True,start_new_session=True)
   try:process.wait(timeout=120)
   except subprocess.TimeoutExpired:
    os.killpg(process.pid,signal.SIGKILL);process.wait();result['status']='error';result['diagnostic_text']='sandbox build exceeded120 seconds';return result
   transport.seek(0);wire=transport.read(1024*1024+1)
  if len(wire)>1024*1024:result['status']='error';result['diagnostic_text']='sandbox result exceeded1MiB';return result
  try:reply=json.loads(wire)
  except (UnicodeDecodeError,json.JSONDecodeError):
   result['diagnostic_text']='sandbox setup or transport failed: '+wire[:2048].decode('utf-8','replace');return result
  result['steps']=reply.get('steps',[])[:256]
  result['status']=reply.get('status','error') if reply.get('status') in ('ok','error','unavailable') else 'error'
  text=str(reply.get('diagnostics',''))[:65536];result['diagnostic_text']=text;result['diagnostics']=_diagnostics(text,manifest,rootid)
  result['sandbox']={'ready':reply.get('sandbox_ready',False),'user_namespace':True,'mount_namespace':True,'network_namespace':True,'pid_namespace':True,'readonly_input':True,'work_bytes':128*1024*1024,'temp_bytes':16*1024*1024,'address_space_bytes':16*1024*1024*1024,'cpu_seconds':60,'artifact_output_bytes':output_limit,'artifact_file_limit_enforced':True,'uid_process_limit':uid_limit,'additional_uid_tasks':64,'signer_present':False}
  if result['status']=='ok':
   try:binary=base64.b64decode(reply['binary_base64'],validate=True)
   except (ValueError,KeyError):result['status']='error';result['diagnostic_text']='invalid sandbox artifact transport';return result
   if not 0<len(binary)<=output_limit:result['status']='error';result['diagnostic_text']='artifact exceeds resource profile';return result
   path=outputdir/'app.bin';path.write_bytes(binary)
   result['artifact']={'path':str(path),'sha256':sha(binary),'bytes':len(binary)}
 result['evidence_digest']=sha(b'LT-BUILD-EVIDENCE-1\0'+canonical({k:v for k,v in result.items() if k!='artifact'}))
 (outputdir/'build-result.json').write_bytes(canonical(result)+b'\n')
 return result
