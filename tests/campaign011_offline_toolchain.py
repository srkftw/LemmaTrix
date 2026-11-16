"""Focused offline descriptor validation and frozen worker identity."""
import argparse,contextlib,copy,dataclasses,hashlib,io,json,os,resource,sys,time
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools')]
import build_jobs,driver,live,sdk

def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def write(path,value):path.write_text(json.dumps(value,indent=2)+'\n')
def provenance(value):
 text='\n'.join(value['store_roots'])+'\n';value['provenance']=dict(kind='nix-store-qR',sha256=hashlib.sha256(text.encode()).hexdigest(),output=text)

def pure(fixture,out):
 out.mkdir();document=json.loads(fixture.read_text());selected=out/'selected.json';write(selected,document);checks=[];calls=[];original=build_jobs.subprocess.run
 def metadata_only(argv,*a,**kw):
  if len(argv)!=2 or argv[1]!='--version':raise AssertionError('unexpected compiler/query invocation: '+repr(argv))
  calls.append(list(map(str,argv)));return original(argv,*a,**kw)
 def refuse(label,value=None,raw=None,path=None):
  p=path or out/'invalid.json'
  if value is not None:write(p,value)
  if raw is not None:p.write_bytes(raw)
  try:build_jobs.resolve_toolchain(manifest=p)
  except(OSError,ValueError,RuntimeError)as e:checks.append(dict(check=label,result='refused',error=str(e)));return
  raise AssertionError('accepted '+label)
 with patch.object(build_jobs.subprocess,'run',metadata_only):
  tc=build_jobs.resolve_toolchain(manifest=selected);worker=build_jobs.compiler_identity(toolchain=tc)
  assert worker==build_jobs.compiler_identity(toolchain=tc);checks.append(dict(check='valid descriptor and stable worker identity',result='pass'))
  refuse('missing selected descriptor',path=out/'missing.json')
  with patch.dict(os.environ,{'LT_TOOLCHAIN_MANIFEST':''}):
   try:build_jobs.resolve_toolchain()
   except ValueError:checks.append(dict(check='explicitemptyselector no discovery',result='refused'))
   else:raise AssertionError('emptyselector accepted')
  refuse('malformed JSON',raw=b'{"schema":')
  refuse('duplicate JSON key',raw=b'{"schema":1,"schema":1}')
  for label,mutate in [
   ('duplicate roots',lambda v:v['store_roots'].append(v['store_roots'][0])),
   ('outside root',lambda v:v['store_roots'].__setitem__(0,'/tmp')),
   ('noncanonical nested root',lambda v:v['store_roots'].__setitem__(0,v['store_roots'][0]+'/..')),
   ('missing root',lambda v:v['store_roots'].__setitem__(0,'/nix/store/'+'0'*32+'-absent-offline-test')),
   ('tool hash mismatch',lambda v:v['tools']['lean'].__setitem__('sha256','00'*32)),
   ('tool version mismatch',lambda v:v['tools']['lean'].__setitem__('version','wrong version')),
   ('lock mismatch',lambda v:v.__setitem__('lock_sha256','00'*32)),
   ('configured tool mismatch',lambda v:v['tools']['lean'].__setitem__('path',v['tools']['clang']['path'])),
   ('unknown shape',lambda v:v.__setitem__('extra',True)),
   ('boolean schema',lambda v:v.__setitem__('schema',True)),
   ('provenance digest mismatch',lambda v:v['provenance'].__setitem__('sha256','00'*32)),
  ]:
   value=copy.deepcopy(document);mutate(value);refuse(label,value=value)
  value=copy.deepcopy(document);root=str(Path(*Path(value['tools']['python']['path']).parts[:4]));value['store_roots'].remove(root);provenance(value);refuse('required tool member absent',value=value)
  with patch.dict(os.environ,{'LT_LEAN':'/missing-configured-lean'}):refuse('no ambient fallback for missing configured tool',value=document)
  link=out/'symlink.json';link.symlink_to(selected);refuse('symlink descriptor',path=link)
  fifo=out/'fifo.json';os.mkfifo(fifo,0o600);refuse('FIFO descriptor nonblockingrefusal',path=fifo)
  refuse('oversized descriptor',raw=b' '* (build_jobs.MANIFEST_LIMIT+1))
  before=(tc.descriptor,tc.lock_json,tc.tools,tc.closure,worker)
  try:tc.descriptor=b'{}'
  except dataclasses.FrozenInstanceError:pass
  else:raise AssertionError('resolution mutable')
  view=tc.tools;view['lean']='/outside';selected.write_text('{}\n')
  with patch.object(build_jobs,'resolve_toolchain',side_effect=AssertionError('manifest reread')):
   assert (tc.descriptor,tc.lock_json,tc.tools,tc.closure,build_jobs.compiler_identity(toolchain=tc))==before
  checks.append(dict(check='manifest replacedafterresolution cannotchangeimmutableidentity/tools/mountviews',result='pass'))
 report=dict(status='PURE CHECKS PASS',checks=checks,metadata_commands=calls,real_sandbox_executions=0,worker_identity=worker,descriptor_commitment=tc.commitment,manifest_sha256=tc.manifest_sha256,descriptor=json.loads(tc.descriptor))
 write(out/'checks.json',report);return report

def selectors(fixture,out):
 """Exercise CLI selection and real resolution, stopping before compilation."""
 out.mkdir();project=out/'project';project.mkdir();source=ROOT/'docs/evidence/sdk-offline-workflow-20261116'
 for name in ['lemma.project.json','lemma.lock.json']:(project/name).write_bytes((source/name).read_bytes())
 (project/'Main.lean').write_bytes((source/'Main.corrected.lean').read_bytes())
 sdk.sdk.cache_sdk()
 malformed=out/'malformed.json';malformed.write_text('{"schema":')
 mismatch=out/'mismatch.json';value=json.loads(fixture.read_text());value['lock_sha256']='00'*32;write(mismatch,value)
 cases=[('flag overrides invalid environment',fixture,out/'missing-env.json',True),
        ('environment selected without flag',None,fixture,True),
        ('missing explicit flag refuses despite valid environment',out/'missing.json',fixture,False),
        ('malformed explicit flag refuses despite valid environment',malformed,fixture,False),
        ('mismatched explicit flag refuses despite valid environment',mismatch,fixture,False)]
 checks=[];calls=[];original_run=build_jobs.subprocess.run;original_resolve=build_jobs.resolve_toolchain
 def metadata_only(argv,*a,**kw):
  if len(argv)!=2 or argv[1]!='--version':raise AssertionError('unexpected compiler/query invocation: '+repr(argv))
  calls.append(list(map(str,argv)));return original_run(argv,*a,**kw)
 for index,(label,flag,environment,accept)in enumerate(cases):
  observed={}
  def resolve(*a,**kw):
   observed['manifest_argument']=str(kw['manifest'])if kw.get('manifest')is not None else None
   selected=original_resolve(*a,**kw)
   observed.update(manifest_sha256=selected.manifest_sha256,descriptor=selected.commitment)
   raise RuntimeError('selector-only probe stopped after resolution, before compilation')
  argv=['build',str(project),'--output',str(out/('probe-'+str(index)))]
  if flag is not None:argv+=['--toolchain-manifest',str(flag)]
  stream=io.StringIO()
  with patch.dict(os.environ,{'LT_TOOLCHAIN_MANIFEST':str(environment)}),patch.object(build_jobs.subprocess,'run',metadata_only),patch.object(build_jobs,'resolve_toolchain',resolve),contextlib.redirect_stdout(stream):
   code=sdk.main(argv)
  result=json.loads(stream.getvalue());assert code==1 and result['status']=='unavailable'and not result.get('artifact')
  assert observed['manifest_argument']==(str(flag)if flag is not None else None)
  assert ('descriptor'in observed)==accept
  if accept:assert observed['manifest_sha256']==digest(fixture)and result['diagnostic_text']=='selector-only probe stopped after resolution, before compilation'
  checks.append(dict(check=label,result='pass',resolved=accept,observation=observed,diagnostic=result['diagnostic_text']))
 report=dict(status='SELECTOR CHECKS PASS',checks=checks,metadata_commands=calls,real_sandbox_executions=0,scope='Real CLI and descriptor resolution; intentional stop before compilation, no simulated successful artifact')
 write(out/'checks.json',report);return report

def main():
 p=argparse.ArgumentParser();p.add_argument('--fixture',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--selectors-only',action='store_true');a=p.parse_args()
 if a.selectors_only:
  r=selectors(a.fixture,a.output);print(json.dumps(dict(status=r['status'],checks=len(r['checks']),real_sandbox_executions=0)));return
 r=pure(a.fixture,a.output)
 print(json.dumps(dict(status=r['status'],checks=len(r['checks']),worker=r['worker_identity'],descriptor=r['descriptor_commitment'])))
if __name__=='__main__':main()
