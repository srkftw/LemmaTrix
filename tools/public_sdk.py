"""Versioned public SDK and finite, offline source dependency resolution.

Only content-addressed, verified SDK/dependency bytes enter the build sandbox.
The public namespace is an API boundary; guest brokers remain the authority.
"""
import base64,ctypes,hashlib,json,os,re,shutil,stat,sys,tempfile
from contextlib import contextmanager
from pathlib import Path,PurePosixPath
import driver
ROOT=driver.ROOT
VERSION='0.1.0'
MANIFEST=ROOT/'sdk/manifest.json'
CACHE=ROOT/'build/sdk-cache'
DEPENDENCIES=ROOT/'build/dependency-cache'
RECIPE='lemmatrix-lean-rv64-structured-2'
MAX_FILES=128;MAX_BYTES=4*1024*1024;MAX_SOURCE=128*1024;MAX_DEPENDENCIES=16
SDK_MANIFEST_LIMIT=256*1024
MODULE=re.compile(r'[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\Z')
RESERVED={'Guest','Lemma','Compiler','Init','Lean','Std','runtime','sdk'}
RECIPE_FILES=['Compiler/Main.lean','runtime/primitives.S','runtime/app.ld','runtime/app2.ld','tools/build_sandbox_runner.py']
CLIENTS={'Guest.Primitives','Guest.Structured','Guest.Effects','Guest.LiveSDK','Guest.NetworkSDK','Guest.LiveMemory','Guest.Keyboard','Guest.Raster','Guest.WaitSDK','Guest.ProjectSDK','Guest.ServerSDK','Guest.AppIntentSDK'}
PUBLIC=['Lemma.Types','Lemma.UI','Lemma.Objects','Lemma.Net','Lemma.Identity','Lemma.Social','Lemma.Messenger','Lemma.Library','Lemma.Forge','Lemma.Server','Lemma.Proof','Lemma.Wallet']

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()
def sha(data):return hashlib.sha256(data).hexdigest()
def require(test,message):
 if not test:raise ValueError(message)
def identity(value):return isinstance(value,str) and re.fullmatch('[0-9a-f]{64}',value) is not None

def relative(name,*,reserved=True):
 require(isinstance(name,str) and re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_./-]{0,127}',name) is not None,'invalid project-relative path')
 p=PurePosixPath(name)
 require(str(p)==name and not p.is_absolute() and all(x not in ('','.','..') for x in p.parts),'noncanonical project-relative path')
 if name.endswith('.lean'):
  module=name[:-5].replace('/','.')
  require(MODULE.fullmatch(module) is not None and name==module.replace('.','/')+'.lean','Lean source must use a canonical module path: '+name)
 # Both SDK clients and the toolchain stdlib have immutable module roots.
 # Inspect the namespace as well as the directory: e.g. Lean.lean and the
 # noncanonical Lemma.UI.lean must never shadow those roots in an app/dependency.
 require(not reserved or p.parts[0].split('.')[0] not in RESERVED,'project shadows reserved SDK/toolchain namespace')
 return name

def records(files,*,reserved=True):
 require(bool(files) and len(files)<=MAX_FILES and sum(len(x) for x in files.values())<=MAX_BYTES,'source closure exceeds 128 files/4MiB')
 result=[]
 for name,data in sorted(files.items()):
  relative(name,reserved=reserved);require(isinstance(data,bytes),'source members must be bytes')
  require(not name.endswith('.lean') or len(data)<=MAX_SOURCE,'Lean source exceeds 128KiB: '+name)
  if name.endswith('.lean'):
   require(MODULE.fullmatch(name[:-5].replace('/','.')) is not None,'Lean module path is invalid: '+name)
   data.decode('utf-8')
  result.append({'path':name,'bytes':len(data),'sha256':sha(data)})
 return result

class Source:
 def __init__(self,data):self.data=data
 def read_text(self):return self.data.decode('utf-8')

def imports(data):
 # The same lexer is used by the incremental image build. Header modules are
 # normalized ASCII names; quoted/escaped identifiers fail before elaboration.
 import live_build
 text=live_build.without_comments(Source(data).read_text())
 result=[]
 for match in re.finditer(r'^\s*(?:public\s+)?import\s+([^\n]+)',text,re.M):
  names=match[1].split()
  require(bool(names) and all(MODULE.fullmatch(n) for n in names),'import must use normalized ASCII module names')
  result.extend(names)
 return result

def order(files,external=()):
 modules={n[:-5].replace('/','.'):d for n,d in files.items() if n.endswith('.lean')}
 require(len(modules)==sum(n.endswith('.lean') for n in files),'module mapping collision')
 ordered=[];active=set();external=set(external)
 def visit(name):
  if name in ordered:return
  require(name not in active,'cyclic source dependency at '+name);active.add(name)
  for dependency in imports(modules[name]):
   if dependency in modules:visit(dependency)
   elif dependency in external:pass
   elif dependency.split('.')[0] in ('Init','Lean','Std'):pass
   else:raise ValueError('import is outside pinned source/SDK closure: '+dependency)
  active.remove(name);ordered.append(name)
 for name in sorted(modules):visit(name)
 return ordered

def current_manifest():
 with _sdk_directory(ROOT)as directory:
  return _sdk_manifest(directory,'sdk/manifest.json')

def validate_manifest(manifest):
 require(isinstance(manifest,dict) and manifest.get('schema')==1 and manifest.get('namespace')=='Lemma' and manifest.get('version')==VERSION,'unsupported SDK manifest/version')
 committed={k:v for k,v in manifest.items() if k!='content_id'}
 require(manifest.get('content_id')==sha(b'LT-PUBLIC-SDK-1\0'+canonical(committed)),'SDK manifest identity mismatch')
 entries=manifest.get('files',[])
 require(0<len(entries)<=128 and len({x['path'] for x in entries})==len(entries),'invalid SDK closure')
 require(manifest.get('public_modules')==PUBLIC,'unsupported public SDK exports')
 for x in entries:
  relative(x['path'],reserved=False);require(identity(x['sha256']) and type(x['bytes']) is int and 0<x['bytes']<=MAX_SOURCE,'invalid SDK member')
  name=x['path'][:-5].replace('/','.') if x['path'].endswith('.lean') else ''
  require(name in PUBLIC or name in CLIENTS,'SDK includes private implementation or nonmodule member')
 require([x['path'] for x in manifest.get('recipe_files',[])]==RECIPE_FILES,'SDK build recipe closure differs from supported version')
 for x in manifest['recipe_files']:
  require(identity(x.get('sha256'))and type(x.get('bytes'))is int and 0<x['bytes']<=(MAX_SOURCE if x['path'].endswith('.lean')else MAX_BYTES),'invalid SDK recipe member')
 require(len(entries)+len(manifest['recipe_files'])<=MAX_FILES and sum(x['bytes']for x in entries+manifest['recipe_files'])<=MAX_BYTES,'SDK closure exceeds 128 files/4MiB')
 return manifest

def generate_manifest():
 pending=list(PUBLIC);seen=set();files={}
 while pending:
  name=pending.pop()
  if name in seen:continue
  seen.add(name);require(MODULE.fullmatch(name) is not None,'invalid SDK module')
  path=name.replace('.','/')+'.lean';data=(ROOT/path).read_bytes();files[path]=data
  pending.extend(n for n in imports(data) if n.split('.')[0] not in ('Init','Lean','Std'))
 # Private implementations must never become transitive SDK members.
 require(all(n.startswith('Lemma.') or n in CLIENTS for n in seen),'SDK includes a private service implementation')
 manifest={'schema':1,'namespace':'Lemma','version':VERSION,'machine':'LT-Dev-v2','profiles':[1,2],'public_modules':PUBLIC,'modules':order(files),'files':records(files,reserved=False),'recipe_files':[{'path':n,'bytes':len((ROOT/n).read_bytes()),'sha256':sha((ROOT/n).read_bytes())} for n in RECIPE_FILES],'operations':{'UI':'ordinary caller surfaces/input/raster','Objects':'caller scoped objects; explicit selected grants','Net':'approved mode1 terminal request only','Identity':'caller incarnation; no key export or arbitrary signing','Social':'reviewed Feed intents','Messenger':'reviewed recipient intents','Library':'selected project inspection; native acquisition review','Forge':'selected source closure/fork/freeze','Server':'separately granted bounded store reads','Proof':'attributed evidence; no compiler correctness claim','Wallet':'unavailable'}}
 manifest['content_id']=sha(b'LT-PUBLIC-SDK-1\0'+canonical(manifest));MANIFEST.write_bytes(canonical(manifest)+b'\n')
 return manifest

@contextmanager
def _sdk_directory(path,create=False):
 # Reuse the anchored/no-follow approach used by the reviewed project reader.
 # Only selected path components are opened; no input tree is enumerated.
 path=Path(os.path.abspath(path));flags=os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW
 directory=os.open(path.anchor,flags)
 try:
  for component in path.parts[1:]:
   if create:
    try:os.mkdir(component,dir_fd=directory)
    except FileExistsError:pass
   child=os.open(component,flags,dir_fd=directory);os.close(directory);directory=child
  yield directory
 finally:os.close(directory)

def _sdk_member(directory,name,limit,expected=None):
 relative(name,reserved=False);parts=Path(name).parts;parent=os.dup(directory)
 def identity_of(info):return(info.st_dev,info.st_ino,info.st_mode,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
 try:
  for component in parts[:-1]:
   child=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=parent);os.close(parent);parent=child
  fd=os.open(parts[-1],os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
  try:
   opened=os.fstat(fd)
   require(stat.S_ISREG(opened.st_mode)and opened.st_size<=limit,'SDK input must be a bounded regular file: '+name)
   require(expected is None or opened.st_size==expected,'SDK input size differs from manifest: '+name)
   chunks=[];size=0
   while size<=opened.st_size:
    data=os.read(fd,min(65536,opened.st_size+1-size))
    if not data:break
    chunks.append(data);size+=len(data)
   current=os.stat(parts[-1],dir_fd=parent,follow_symlinks=False)
   require(size==opened.st_size and identity_of(os.fstat(fd))==identity_of(opened)and identity_of(current)==identity_of(opened),'SDK input changed during read: '+name)
   return b''.join(chunks)
  finally:os.close(fd)
 finally:os.close(parent)

def _sdk_manifest(directory,name='manifest.json'):
 def unique(pairs):
  result={}
  for key,value in pairs:
   require(key not in result,'duplicate SDK manifest key: '+key);result[key]=value
  return result
 return validate_manifest(json.loads(_sdk_member(directory,name,SDK_MANIFEST_LIMIT),object_pairs_hook=unique))

def _sdk_files(directory,manifest):
 files={}
 for record in manifest['files']:
  data=_sdk_member(directory,record['path'],MAX_SOURCE,record['bytes']);require(sha(data)==record['sha256'],'SDK member differs from pinned content: '+record['path']);files[record['path']]=data
 require(order(files)==manifest['modules'],'SDK transitive order differs from manifest')
 for record in manifest['recipe_files']:
  data=_sdk_member(directory,record['path'],MAX_BYTES,record['bytes']);require(sha(data)==record['sha256'],'SDK recipe differs from pinned content: '+record['path']);files[record['path']]=data
 return files

def _read_sdk(directory,manifest):
 validate_manifest(manifest)
 with _sdk_directory(directory)as selected:return _sdk_files(selected,manifest)

def capture_sdk(directory,manifest_path='manifest.json'):
 with _sdk_directory(directory)as selected:
  manifest=_sdk_manifest(selected,manifest_path);return manifest,_sdk_files(selected,manifest)

def _rename_sdk(parent,source,destination):
 # Linux is already the SDK build host contract. Never replace a racing target.
 library=ctypes.CDLL(None,use_errno=True);rename=getattr(library,'renameat2',None)
 require(rename is not None,'non-replacing SDK publication is unavailable')
 rename.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint];rename.restype=ctypes.c_int
 if rename(parent,os.fsencode(source),parent,os.fsencode(destination),1):
  error=ctypes.get_errno();raise OSError(error,os.strerror(error),destination)

def _publish_sdk(destination,manifest,files,allow_existing=False):
 # Freeze the captured map/manifest before any staging or existing-cache read.
 encoded=canonical(manifest)+b'\n';require(len(encoded)<=SDK_MANIFEST_LIMIT,'canonical SDK manifest exceeds bound')
 manifest=validate_manifest(json.loads(encoded));files=dict(files)
 require(set(files)=={x['path']for x in manifest['files']+manifest['recipe_files']},'SDK publication differs from declared closure')
 destination=Path(os.path.abspath(destination))
 def existing(parent):
  child=os.open(destination.name,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=parent)
  try:
   actual=_sdk_manifest(child);captured=_sdk_files(child,actual)
   require(actual==manifest and captured==files,'SDK cache collision')
  finally:os.close(child)
 with _sdk_directory(destination.parent,create=True)as parent:
  try:os.stat(destination.name,dir_fd=parent,follow_symlinks=False)
  except FileNotFoundError:pass
  else:
   require(allow_existing,'SDK destination already exists');existing(parent);return
  # /proc/self/fd anchors staging to the opened parent, even if renamed.
  name=Path(tempfile.mkdtemp(prefix='.lt-sdk-',dir='/proc/self/fd/'+str(parent))).name
  child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=parent);owned=os.fstat(child)
  def owns_stage():
   try:current=os.stat(name,dir_fd=parent,follow_symlinks=False)
   except FileNotFoundError:return False
   return stat.S_ISDIR(current.st_mode)and(current.st_dev,current.st_ino)==(owned.st_dev,owned.st_ino)
  try:
   stage=Path('/proc/self/fd/'+str(child))
   for relative_name,data in {**files,'manifest.json':encoded}.items():
    path=stage/relative_name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
   staged=_sdk_manifest(child);staged_files=_sdk_files(child,staged)
   require(staged==manifest and staged_files==files,'staged SDK differs from captured bytes')
   require(owns_stage(),'SDK staging directory changed before publication')
   try:_rename_sdk(parent,name,destination.name)
   except FileExistsError:
    require(allow_existing,'SDK destination already exists');existing(parent)
  finally:
   # After successful rename there is no stage to remove. Never roll back the
   # published destination, including if a later reporting operation fails.
   active=sys.exception()
   try:
    if owns_stage():shutil.rmtree(name,dir_fd=parent)
   except FileNotFoundError:pass
   except OSError:
    if active is None:raise
   finally:os.close(child)

def cache_sdk():
 manifest,files=capture_sdk(ROOT,'sdk/manifest.json');_publish_sdk(CACHE/manifest['content_id'],manifest,files,True)
 return manifest

def export_sdk(destination):
 manifest=cache_sdk();captured,files=capture_sdk(CACHE/manifest['content_id'])
 require(captured==manifest,'SDK cache manifest differs from installed SDK');_publish_sdk(destination,captured,files)
 return captured

def import_sdk(directory):
 manifest,files=capture_sdk(directory);_publish_sdk(CACHE/manifest['content_id'],manifest,files,True)
 return manifest

def resolve_sdk(pin=None):
 if pin is None:
  return capture_sdk(ROOT,'sdk/manifest.json')
 require(isinstance(pin,dict) and pin.get('version')==VERSION and identity(pin.get('content_id')),'invalid pinned SDK')
 directory=CACHE/pin['content_id']
 if not os.path.lexists(directory):
  # Only the exact installed SDK is eligible to populate a missing cache. An
  # older pin never silently changes to the checkout's current bytes.
  manifest=current_manifest()
  require(manifest['content_id']==pin['content_id'],'pinned SDK unavailable offline; import that exact SDK cache')
  cache_sdk()
 manifest,files=capture_sdk(directory);require(manifest['content_id']==pin['content_id']and manifest['version']==pin['version'],'SDK cache identity/version mismatch')
 return manifest,files

def dependency_document(envelope,manifest,public,sources):
 return {'schema':1,'format':'LT-SOURCE-DEPENDENCY-1','release':base64.b64encode(envelope).decode(),'manifest':manifest,'publisher_public':base64.b64encode(public).decode(),'sources':{n:base64.b64encode(d).decode() for n,d in sorted(sources.items())}}

def verify_dependency(document,*,publisher=None,release_id=None):
 import releases
 require(document.get('schema')==1 and document.get('format')=='LT-SOURCE-DEPENDENCY-1','unsupported source dependency carrier')
 require(len(canonical(document))<=6*1024*1024,'source dependency carrier exceeds 6MiB')
 envelope=base64.b64decode(document['release'],validate=True);public=base64.b64decode(document['publisher_public'],validate=True);manifest=document['manifest']
 info=releases.inspect(envelope,public,manifest)
 require(info['signature_verified'],'dependency publisher signature is unverified')
 require(publisher is None or info['publisher_key_id']==publisher,'dependency publisher differs from selected trust')
 require(release_id is None or info['release_id']==release_id,'dependency release differs from exact selected identity')
 facets=manifest.get('facets',[manifest.get('facet')]);require('DevelopmentArtifact' in facets,'dependency lacks source-only DevelopmentArtifact facet')
 require(info.get('size',0)==0,'source-only dependency must not require a dummy executable')
 files={relative(n):base64.b64decode(d,validate=True) for n,d in document['sources'].items()};records(files)
 actual=[{'path':n,'sha256':sha(d),'size':len(d)} for n,d in sorted(files.items())]
 require(actual==manifest.get('sources'),'dependency source commitment differs from actual bytes')
 exports=manifest.get('exports');require(isinstance(exports,list) and exports and exports==sorted(set(exports)),'dependency must declare canonical exported modules')
 require(all(isinstance(n,str) and MODULE.fullmatch(n) and n.split('.')[0] not in RESERVED for n in exports),'dependency has invalid/reserved exports')
 require(isinstance(manifest.get('license'),str) and bool(manifest['license']) and isinstance(manifest.get('provenance'),dict) and bool(manifest['provenance']),'dependency needs explicit license/provenance')
 lock=manifest.get('dependency_lock') or {'sdk':manifest.get('sdk'),'dependencies':manifest.get('dependencies',[])};require(isinstance(lock,dict) and isinstance(lock.get('sdk'),dict),'dependency must commit SDK/dependency lock')
 require(all(n.replace('.','/')+'.lean' in files for n in exports),'exported dependency module absent')
 return info,files,lock

def cache_dependency(document,*,publisher,release_id):
 info,files,lock=verify_dependency(document,publisher=publisher,release_id=release_id)
 directory=DEPENDENCIES/release_id;directory.mkdir(parents=True,exist_ok=True)
 encoded=canonical(document);target=directory/'source.json'
 if target.exists():require(target.read_bytes()==encoded,'dependency release cache collision')
 else:target.write_bytes(encoded)
 return {'release_id':info['release_id'],'publisher_key_id':info['publisher_key_id'],'content_id':sha(encoded),'exports':document['manifest']['exports'],'license':document['manifest']['license'],'provenance':document['manifest']['provenance'],'capabilities':document['manifest'].get('rights',0),'dependencies':lock.get('dependencies',[])}

def resolve_dependencies(pins,sdk,carriers=None):
 require(isinstance(pins,list) and len(pins)<=MAX_DEPENDENCIES,'dependency closure exceeds 16 releases')
 files={};modules=set();visited=set();active=set();ordered=[];allpins={p['release_id']:p for p in pins};carriers=carriers or {}
 require(len(allpins)==len(pins),'duplicate dependency release')
 def visit(pin):
  rid=pin.get('release_id');require(identity(rid) and identity(pin.get('content_id')) and identity(pin.get('publisher_key_id')),'invalid exact dependency pin')
  if rid in visited:return
  require(rid not in active,'cyclic dependency release closure');active.add(rid)
  path=DEPENDENCIES/rid/'source.json'
  raw=carriers.get('deps/'+rid+'.json')
  if raw is None:
   require(path.is_file(),'verified dependency unavailable offline: '+rid);raw=path.read_bytes()
  require(sha(raw)==pin['content_id'],'dependency carrier/cache differs from locked bytes')
  document=json.loads(raw);info,source,lock=verify_dependency(document,publisher=pin['publisher_key_id'],release_id=rid)
  require(lock.get('sdk')==sdk,'dependency SDK differs from app lock')
  require(pin.get('exports')==document['manifest']['exports'] and pin.get('license')==document['manifest']['license'] and pin.get('provenance')==document['manifest']['provenance'] and pin.get('capabilities')==document['manifest'].get('rights',0),'dependency declaration differs from locked review')
  children=lock.get('dependencies',[]);require(isinstance(children,list),'dependency lock children malformed')
  for child in children:
   require(child.get('release_id') in allpins and allpins[child['release_id']]==child,'dependency transitive pin absent/substituted');visit(child)
  for name,data in source.items():
   # Standard package metadata is committed and verified, but is not an app's
   # own root metadata. Keep its exact bytes under a release-scoped path.
   mapped='dependency-metadata/'+rid+'/'+name if name in ('lemma.project.json','lemma.lock.json') else name
   require(mapped not in files,'dependency file collision: '+mapped);files[mapped]=data
   if name.endswith('.lean'):
    module=name[:-5].replace('/','.');require(module not in modules,'dependency module collision: '+module);modules.add(module)
  active.remove(rid);visited.add(rid);ordered.append(rid)
 for pin in pins:visit(pin)
 records(files) if files else None
 return files,ordered

def validate_lock(lock):
 require(isinstance(lock,dict) and lock.get('schema')==1 and lock.get('recipe')==RECIPE,'unsupported SDK/dependency recipe lock')
 source_only=lock.get('facet')=='DevelopmentArtifact'
 require(lock.get('machine')=='LT-Dev-v2' and lock.get('profile') in ((0,) if source_only else (1,2)),'unsupported target profile')
 if source_only:require(lock.get('module') is None and lock.get('entry') is None,'source-only dependency has no executable entry')
 else:require(MODULE.fullmatch(lock.get('module','')) and MODULE.fullmatch(lock.get('entry','')),'invalid locked entry/module')
 require(lock.get('toolchain')=={k:driver.LOCK[k] for k in ('lean','llvm','isa','abi')},'locked toolchain differs from supported recipe')
 require(identity(lock.get('content_id')) and lock['content_id']==sha(b'LT-DEPENDENCY-LOCK-1\0'+canonical({k:v for k,v in lock.items() if k!='content_id'})),'dependency lock identity mismatch')
 return lock

def make_lock(*,module=None,entry=None,profile=0,dependencies=(),facet='NativeApplication'):
 manifest=cache_sdk();lock={'schema':1,'facet':facet,'sdk':{'version':VERSION,'content_id':manifest['content_id']},'dependencies':list(dependencies),'recipe':RECIPE,'toolchain':{k:driver.LOCK[k] for k in ('lean','llvm','isa','abi')},'machine':'LT-Dev-v2','profile':profile,'module':module,'entry':entry}
 lock['content_id']=sha(b'LT-DEPENDENCY-LOCK-1\0'+canonical(lock));validate_lock(lock);resolve_dependencies(lock['dependencies'],lock['sdk']);return lock

def resolve(files):
 records(files)
 require('lemma.lock.json' in files,'public SDK project requires lemma.lock.json; run ./lt sdk lock PROJECT')
 lock=validate_lock(json.loads(files['lemma.lock.json']));manifest,sdk=resolve_sdk(lock['sdk']);dependencies,release_order=resolve_dependencies(lock['dependencies'],lock['sdk'],files)
 require(not set(files)&set(dependencies),'dependency collides with project source/resource')
 records({**files,**dependencies})
 public=set(manifest['public_modules']);dependency_modules={n[:-5].replace('/','.') for n in dependencies if n.endswith('.lean')}
 # Every source is validated, including non-exported transitive modules. Apps
 # may import only the dependency's declared exports; dependency internals remain
 # available to that dependency, with no ambient filesystem/network resolver.
 exports={n for pin in lock['dependencies'] for n in pin['exports']}
 dep_order=order(dependencies,public) if dependencies else []
 app_order=order(files,public|exports)
 for name,data in {**files,**dependencies}.items():
  if name.endswith('.lean'):
   for imported in imports(data):
    require(not imported.startswith(('Guest.','Compiler.','Examples.')),'forbidden private import: '+imported)
 return lock,manifest,sdk,dependencies,dep_order,app_order
