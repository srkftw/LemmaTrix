"""Focused public closure, real isolated build and architecture dispatch checks."""
import hashlib,json,sys,tempfile,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import build_jobs,driver,live,public_sdk,sdk
B=driver.BUILD/'public-sdk-checks'

def denied(fn,label):
 try:fn()
 except (ValueError,UnicodeDecodeError):return label
 raise AssertionError('accepted '+label)

def main():
 B.mkdir(parents=True,exist_ok=True);checks=[];started=time.monotonic()
 with tempfile.TemporaryDirectory(prefix='lt-public-project-') as temporary:
  directory=Path(temporary)/'ordinary-project';sdk.main(['init',str(directory),'--name','ordinary-project'])
  files=sdk.read_project(directory);preflight=sdk.check(files);lock=json.loads(files['lemma.lock.json'])
  before=public_sdk.resolve_sdk(lock['sdk'])
  original=public_sdk.current_manifest
  try:
   public_sdk.current_manifest=lambda:(_ for _ in ()).throw(AssertionError('cached SDK consulted checkout HEAD'))
   cached=public_sdk.resolve_sdk(lock['sdk']);assert before==cached
  finally:public_sdk.current_manifest=original
  checks.append('pinned cached SDK remains usable without consulting checkout HEAD')
  checks.append(denied(lambda:public_sdk.resolve_sdk({'version':'0.1.0','content_id':'11'*32}),'missing pinned SDK refuses HEAD substitution'))
  for path in ('Lemma/UI.lean','Guest/Identity.lean','Compiler/Main.lean','../escape.lean','App//Main.lean'):
   checks.append(denied(lambda:build_jobs.source_commitment({path:b'x'}),'reserved/noncanonical '+path))
  for source in (b'import Guest.Identity\ndef main (t : UInt64) := t\n',b'import Lemma.UI Guest.IdentitySDK\ndef main (t : UInt64) := t\n',b'import \xc2\xabGuest\xc2\xbb.Identity\ndef main (t : UInt64) := t\n'):
   checks.append(denied(lambda:public_sdk.resolve({**files,'Main.lean':source}),'private/escaped/multiple import denied'))
  checks.append(denied(lambda:public_sdk.order({'A.lean':b'import B\n','B.lean':b'import A\n'}),'source import cycle denied'))
  checks.append(denied(lambda:public_sdk.order({'A/B.lean':b'','A.B.lean':b''}),'normalized module collision denied'))
  checks.append(denied(lambda:public_sdk.records({'Main.lean':b'x'*(128*1024+1)}),'source byte bound enforced'))
  checks.append(denied(lambda:build_jobs.build_source_snapshot(files,module='Main',entry='Main.main',profile=1,jobid='wrong-profile',rootid='22'*32,outputdir=B/'wrong-profile'),'lock/profile substitution denied'))
  result=build_jobs.build_source_snapshot(files,module='Main',entry='Main.main',profile=2,jobid='public-real-build',rootid=hashlib.sha256(b'public-real-build').hexdigest(),outputdir=B/'valid')
  assert result['status']=='ok',result['diagnostic_text'];checks.append('ordinary public Lemma client compiled to actual freestanding RV64 bytes inside normal sandbox')
  broken={**files,'Main.lean':b'import Lemma.UI\nnamespace Main\ndef main (t : UInt64) : UInt64 := missingSymbol t\nend Main\n'}
  diagnostic=build_jobs.build_source_snapshot(broken,module='Main',entry='Main.main',profile=2,jobid='public-real-diagnostic',rootid=hashlib.sha256(b'public-real-diagnostic').hexdigest(),outputdir=B/'diagnostic')
  assert diagnostic['status']=='error' and any(d['path']=='Main.lean' and d['line']==3 for d in diagnostic['diagnostics']),diagnostic
  checks.append('real Lean type error returns location bound to exact frozen source')
 native=live.platform.machine
 try:
  live.platform.machine=lambda:'aarch64';assert live.args_for('aarch64','image')[0]==str(driver.BUILD/'lt-aarch64')
  live.platform.machine=lambda:'x86_64';assert 'qemu-aarch64' in live.args_for('aarch64','image')[0]
 finally:live.platform.machine=native
 checks.append('native ARM64 direct dispatch and explicit cross-architecture qemu dispatch')
 report={'schema':1,'status':'pass','host':'native x86-64 Linux','sdk':lock['sdk'],'dependency_lock_id':lock['content_id'],'artifact':result['artifact'],'toolchain_id':result['toolchain_id'],'snapshot_digest':result['snapshot_digest'],'checks':checks,'seconds':round(time.monotonic()-started,3),'limitations':['this component test does not establish native ARM hardware execution or the connected federation/user journey']}
 (B/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
