"""Owned saved-build failure fixtures; fake only sandbox transport, no compiler jobs."""
import base64,errno,json,os,shutil,subprocess,sys,tempfile,time
from contextlib import contextmanager,ExitStack
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import build_jobs as jobs,public_sdk,sdk,sdk_builds as saved
PRIOR=ROOT/'docs/evidence/sdk-exact-transfer-20261116'
BINARY=b'owned synthetic build bytes'
GOOD=dict(status='ok',binary_base64=base64.b64encode(BINARY).decode(),diagnostics='',steps=[],sandbox_ready=True)

@contextmanager
def execution(reply=GOOD,*,mode=None,cleanup_error=False):
 original=subprocess.Popen;temporary=tempfile.TemporaryDirectory
 old=json.loads((PRIOR/'origin-build.stdout.json').read_bytes())
 resolved=jobs.ResolvedToolchain(jobs.canonical(old['toolchain_descriptor']),jobs.canonical(jobs.driver.LOCK),old['toolchain_manifest_sha256'])
 class Process:
  def __init__(self,**kwargs):
   self.pid=999999999;self.waits=0
   kwargs['stdout'].write(reply if isinstance(reply,bytes)else jobs.canonical(reply))
  def wait(self,timeout=None):
   self.waits+=1
   if mode=='timeout'and self.waits==1:assert timeout==120;raise subprocess.TimeoutExpired('owned fixture',120)
   return 7 if mode=='nonzero'else 0
 def popen(command,*args,**kwargs):
  if '--map-root-user'in command:
   if mode=='launch-error':raise OSError(errno.EIO,'owned launch failure')
   return Process(**kwargs)
  return original(command,*args,**kwargs)
 class Cleanup:
  def __new__(cls,*a,**k):
   if k.get('prefix')!='lt-build-':return temporary(*a,**k)
   return super().__new__(cls)
  def __init__(self,*a,**k):self.actual=temporary(*a,**k)
  def __enter__(self):return self.actual.__enter__()
  def __exit__(self,*args):self.actual.__exit__(*args);raise OSError(errno.EIO,'owned secondary execution cleanup failure')
 with ExitStack()as stack:
  stack.enter_context(patch.object(jobs,'resolve_toolchain',return_value=resolved))
  stack.enter_context(patch.object(subprocess,'Popen',popen))
  signals=stack.enter_context(patch.object(jobs.os,'killpg'))
  if cleanup_error:stack.enter_context(patch.object(tempfile,'TemporaryDirectory',Cleanup))
  yield
  if mode=='timeout':assert signals.call_count==1
  else:assert not signals.called

def main():
 started=time.monotonic();checks=[];files=sdk.read_project(ROOT/'examples/project-notes')
 def passed(label,**detail):checks.append(dict(check=label,result='pass',**detail))
 def refused(label,fn,kind=(ValueError,OSError,KeyError)):
  try:fn()
  except kind as error:passed(label,diagnostic=str(error));return error
  raise AssertionError('accepted '+label)
 def hashes(directory):return{p.name:public_sdk.sha(p.read_bytes())for p in directory.iterdir()if p.is_file()}
 with tempfile.TemporaryDirectory(prefix='lt-sdk-saved-')as owned:
  home=Path(owned);a=home/'A'
  with execution():result=saved.build_attempt(files,outputdir=a)
  assert result['status']=='ok'and(a/'app.bin').read_bytes()==BINARY
  assert json.loads((a/'build-result.json').read_bytes())==result
  baseline=hashes(a);passed('complete successful attempt publishes matching bytes and receipt together')
  b={**files,'Main.lean':files['Main.lean']+b'\ndef ownedBroken : UInt64 := missingOwnedSymbol\n'}
  for kind in ('A','empty-directory','file','symlink'):
   target=a if kind=='A'else home/kind
   if kind=='empty-directory':target.mkdir()
   elif kind=='file':target.write_bytes(b'unknown')
   elif kind=='symlink':target.symlink_to(a,target_is_directory=True)
   with patch.object(jobs,'_compile_source_snapshot',side_effect=AssertionError('producer entered on reused output')):
    refused('existing '+kind+' refused before producer work',lambda:saved.build_attempt(b,outputdir=target))
   assert hashes(a)==baseline
  cases=[('compiler-error',dict(status='error',diagnostics='Main.lean:3:7: error: owned missing symbol',steps=[],sandbox_ready=True),None,'error'),('unavailable',dict(status='unavailable',diagnostics='owned setup unavailable'),None,'unavailable'),('launch-error',GOOD,'launch-error','error'),('timeout',GOOD,'timeout','error'),('oversize-wire',b' '*((1<<20)+1),None,'error'),('invalid-json',b'owned short transport',None,'unavailable'),('wrong-json-shape',[],None,'error'),('wrong-steps-shape',dict(GOOD,steps=3),None,'error'),('nonzero-ok',GOOD,'nonzero','error'),('missing-binary',dict(status='ok'),None,'error'),('invalid-base64',dict(GOOD,binary_base64='!'),None,'error'),('oversize-binary',dict(GOOD,binary_base64=base64.b64encode(b'x'*262145).decode()),None,'error')]
  cases.extend(('nonstring-binary-'+label,dict(GOOD,binary_base64=value),None,'error')for label,value in [('null',None),('number',7),('list',[]),('object',{})])
  for label,reply,mode,status in cases:
   target=home/label
   with execution(reply,mode=mode):r=saved.build_attempt(b,outputdir=target)
   assert r['status']==status and not(target/'app.bin').exists()
   assert saved.inspect_saved(target,b)['build_status']==status and json.loads((target/'build-result.json').read_bytes())==r
   if label=='compiler-error':assert r['diagnostics'][0]['path']=='Main.lean'and r['diagnostics'][0]['line']==3
   assert hashes(a)==baseline;passed(label+' retains its own complete terminal receipt, no app and unchanged A')
  actual_temporary=tempfile.TemporaryDirectory
  def temporary_setup_failure(*args,**kwargs):
   if kwargs.get('prefix')=='lt-build-':raise OSError('owned temporary setup failure')
   return actual_temporary(*args,**kwargs)
  for label,changes in [('resolver-error',[(jobs,'resolve_toolchain',OSError('owned tool setup failure'))]),('temporary-setup-error',[(tempfile,'TemporaryDirectory',temporary_setup_failure)])]:
   target=home/label
   with execution(),ExitStack()as stack:
    for module,name,error in changes:stack.enter_context(patch.object(module,name,side_effect=error))
    r=saved.build_attempt(b,outputdir=target)
   assert r['status']in ('error','unavailable')and saved.inspect_saved(target)['artifact']is None
   passed(label+' early return retains terminal receipt')
  which=shutil.which
  with execution(),patch.object(shutil,'which',side_effect=lambda name:None if name=='unshare'else which(name)):
   r=saved.build_attempt(b,outputdir=home/'missing-unshare')
  assert r['status']=='unavailable'and saved.inspect_saved(home/'missing-unshare')['build_status']=='unavailable';passed('missing namespace tool retains unavailable receipt')
  for label,reply in [('success',GOOD),('compiler-error',cases[0][1])]:
   target=home/('execution-cleanup-'+label)
   with execution(reply,cleanup_error=True):r=saved.build_attempt(files,outputdir=target)
   assert r['status']==('ok'if label=='success'else'error')and'host_cleanup_error'in r
   if label=='compiler-error':assert 'owned missing symbol'in r['diagnostic_text']
   assert saved.inspect_saved(target)['build_status']==r['status'];passed('secondary execution cleanup preserves '+label+' completion/primary diagnostic')
  # Public source-only fixture uses the normal schema/lock and same producer.
  source=sdk.read_project(ROOT/'examples/notes-schema');lock=json.loads(source['lemma.lock.json']);assert lock['profile']==0
  for compatible in (True,False):
   target=home/('source-only-'+str(compatible))
   with execution(dict(status='ok',source_only=compatible,steps=[],diagnostics='')):r=saved.build_attempt(source,outputdir=target)
   assert r['status']==('ok'if compatible else'error')and not(target/'app.bin').exists()
   assert saved.inspect_saved(target)['artifact']is None
   passed('source-only '+('completion has no dummy executable'if compatible else'incompatible transport is a terminal error'))
  write=Path.write_bytes
  for member in ('app.bin','build-result.json'):
   target=home/('write-failure-'+member)
   def fail_write(path,data):
    if path.name==member:raise OSError(errno.EIO,'owned '+member+' publication failure')
    return write(path,data)
   with execution(),patch.object(Path,'write_bytes',fail_write):error=refused(member+' publication failure preserves completed build status',lambda:saved.build_attempt(files,outputdir=target),saved.PublicationError)
   assert error.result['status']=='ok'and not target.exists()and hashes(a)==baseline
  rename=public_sdk._rename_sdk;target=home/'race'
  def race(parent,stage,name):target.mkdir();(target/'keep').write_bytes(b'unknown racing destination');rename(parent,stage,name)
  with execution(),patch.object(public_sdk,'_rename_sdk',race):error=refused('racing output collision does not replace unknown target',lambda:saved.build_attempt(files,outputdir=target),saved.PublicationError)
  assert error.result['status']=='ok'and(target/'keep').read_bytes()==b'unknown racing destination'
  inspect=saved._inspect;replacements=[]
  def replace_stage(fd):
   r=inspect(fd);path=Path(os.readlink('/proc/self/fd/'+str(fd)))
   if path.name.startswith('.lt-sdk-build-'):
    path.rename(path.with_name(path.name+'-held'));path.mkdir();(path/'keep').write_bytes(b'replaced stage');replacements.append(path)
   return r
  with execution(),patch.object(saved,'_inspect',replace_stage):refused('replaced stage refuses publication and preserves replacement',lambda:saved.build_attempt(files,outputdir=home/'stage-replaced'),saved.PublicationError)
  assert(replacements[0]/'keep').read_bytes()==b'replaced stage'
  def fail_rename(*args):raise OSError(errno.EIO,'owned primary publication failure')
  remove=shutil.rmtree
  def fail_cleanup(*args,**kwargs):
   if kwargs.get('dir_fd')is not None:raise OSError(errno.EACCES,'owned secondary stage cleanup failure')
   return remove(*args,**kwargs)
  with execution(),patch.object(public_sdk,'_rename_sdk',fail_rename),patch.object(shutil,'rmtree',fail_cleanup):error=refused('stage cleanup retains primary publication error',lambda:saved.build_attempt(files,outputdir=home/'primary-error'),saved.PublicationError)
  assert error.__cause__.errno==errno.EIO
  def after_rename(*args):rename(*args);raise OSError(errno.EIO,'owned reporting failure after publication')
  target=home/'published-before-error'
  with execution(),patch.object(public_sdk,'_rename_sdk',after_rename):error=refused('post-publication reporting failure never removes completed output',lambda:saved.build_attempt(files,outputdir=target),saved.PublicationError)
  assert error.result['status']=='ok'and saved.inspect_saved(target)['build_status']=='ok'
  outside=home/'outside';outside.mkdir();marker=outside/'owned-marker';marker.write_bytes(b'outside owned marker');inode=(marker.stat().st_dev,marker.stat().st_ino)
  for kind in ('missing-receipt','short-receipt','duplicate-json','receipt-large','receipt-link','artifact-link','receipt-fifo','artifact-fifo','root-link','short-artifact','large-artifact','tamper','evidence','request','snapshot','descriptor','artifact-length','failed-with-artifact','source-only-with-artifact'):
   target=home/('bad-'+kind);shutil.copytree(a,target);receipt=target/'build-result.json';artifact=target/'app.bin';r=json.loads(receipt.read_bytes());oversize=None
   if kind=='missing-receipt':receipt.unlink()
   elif kind=='short-receipt':receipt.write_bytes(b'{')
   elif kind=='duplicate-json':receipt.write_bytes(b'{"schema":1,"schema":1}')
   elif kind in ('receipt-large','large-artifact'):
    chosen=receipt if kind=='receipt-large'else artifact
    with chosen.open('wb')as stream:stream.truncate((saved.RECEIPT_LIMIT if kind=='receipt-large' else 262144)+1)
    oversize=(chosen.stat().st_dev,chosen.stat().st_ino)
   elif kind in ('receipt-link','artifact-link','receipt-fifo','artifact-fifo'):
    chosen=receipt if kind.startswith('receipt')else artifact;chosen.unlink()
    if kind.endswith('link'):chosen.symlink_to(marker)
    else:os.mkfifo(chosen)
   elif kind=='root-link':
    selected=target;target=home/'selected-link';target.symlink_to(selected,target_is_directory=True)
   elif kind=='short-artifact':artifact.write_bytes(BINARY[:-1])
   elif kind=='tamper':artifact.write_bytes(bytes([BINARY[0]^1])+BINARY[1:])
   else:
    if kind=='evidence':r['evidence_digest']='00'*32
    elif kind=='request':r['request_digest']='00'*32;jobs.seal_result(r)
    elif kind=='snapshot':r['source_files'][0]['sha256']='00'*32;jobs.seal_result(r)
    elif kind=='descriptor':r['toolchain_descriptor']['owned-change']=True;jobs.seal_result(r)
    elif kind=='artifact-length':r['artifact']['bytes']=262145
    elif kind=='failed-with-artifact':r['status']='error';r.pop('artifact');jobs.seal_result(r)
    else:
     r=json.loads((home/'source-only-True/build-result.json').read_bytes())
    receipt.write_bytes(jobs.canonical(r))
   read=os.read
   def bounded(fd,size):
    info=os.fstat(fd);assert 0<size<=65536 and(info.st_dev,info.st_ino)!=inode
    assert oversize is None or(info.st_dev,info.st_ino)!=oversize,'oversize selected input was read'
    return read(fd,size)
   with patch.object(os,'read',bounded):refused(kind+' saved input refused with bounded selected reads',lambda:saved.inspect_saved(target))
   assert hashes(a)==baseline
  # Relocation and forged receipt paths must use only the two fixed members.
  relocated=home/'relocated';shutil.copytree(a,relocated);r=json.loads((relocated/'build-result.json').read_bytes());r['artifact']['path']=str(marker);(relocated/'build-result.json').write_bytes(jobs.canonical(r))
  (relocated/'ignored-link').symlink_to(outside,target_is_directory=True)
  with patch.object(jobs,'resolve_toolchain',side_effect=AssertionError('toolchain requested')),patch.object(subprocess,'Popen',side_effect=AssertionError('process requested')),patch.object(os,'scandir',side_effect=AssertionError('saved tree enumerated')):
   report=saved.inspect_saved(relocated,files);assert report['artifact']['sha256']==public_sdk.sha(BINARY)
   refused('A cannot be attributed to current B',lambda:saved.inspect_saved(relocated,b))
  passed('relocated saved output ignores historical/forged artifact paths and unselected symlinks; no process, discovery or enumeration')
  assert hashes(a)==baseline;passed('original A unchanged across all later error/publication/tamper checks')
 report=dict(schema=1,status='pass',checks=checks,real_compiler_jobs=0,transport='Only owned synthetic sandbox replies; public source/dependency parsing and commitment checks are real',seconds=round(time.monotonic()-started,3))
 print(json.dumps(report,indent=2))
if __name__=='__main__':main()
