"""Reject source namespace substitution before invoking the isolated compiler."""
import hashlib,json,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import build_jobs,driver,public_sdk

def main():
 started=time.monotonic();checks=[]
 manifest_bytes=public_sdk.MANIFEST.read_bytes();manifest=public_sdk.current_manifest()
 assert manifest['content_id']=='3312ddcd277f401c377142b006bac6cf9aeefd8fa89f4d4c78f1fd5469caf533'
 def denied(fn,label):
  try:fn()
  except ValueError as error:checks.append({'check':label,'result':'pass','diagnostic':str(error)});return
  raise AssertionError('accepted '+label)
 # Each entrypoint validates the same paths: public project/dependency records
 # and the direct BuildJobs source snapshot path cannot disagree.
 paths=['Main.lean','App/Other.lean','templates/categories.v1.json','lemma.project.json','lemma.lock.json']
 for name in paths:
  assert public_sdk.relative(name)==name and build_jobs.safe_name(name)==name
 checks.append({'check':'canonical app modules and semantic resource names remain supported','result':'pass'})
 for root in ('Guest','Lemma','Compiler','Init','Lean','Std'):
  for name in (root+'.lean',root+'/Shadow.lean',root+'.Shadow.lean'):
   denied(lambda name=name:public_sdk.records({name:b'def substituted := true\n'}),'project/dependency refuses '+name)
   denied(lambda name=name:build_jobs.source_commitment({name:b'def substituted := true\n'}),'direct frozen snapshot refuses '+name)
 for name in ('App.Other.lean','App/Sub.Other.lean','App//Other.lean','App/../Other.lean','app-name.lean'):
  denied(lambda name=name:public_sdk.relative(name),'noncanonical module alias refuses '+name)
 lock=public_sdk.make_lock(module='Main',entry='Main.main',profile=2)
 files={'lemma.lock.json':public_sdk.canonical(lock),'Main.lean':b'import Init Lean Std\nimport Lemma.UI\nnamespace Main\ndef main (t : UInt64) : UInt64 := t\nend Main\n'}
 resolved=public_sdk.resolve(files)
 assert resolved[-1]==['Main']
 checks.append({'check':'pinned toolchain imports remain available without project-defined stdlib modules','result':'pass'})
 for name in ('Lean/Environment.lean','Std.lean','Lemma.UI.lean'):
  denied(lambda name=name:public_sdk.resolve({**files,name:b'namespace Substitution\nend Substitution\n'}),'public closure refuses toolchain or SDK shadow '+name)
 assert public_sdk.records({'Lemma/UI.lean':b'import Guest.LiveSDK\n'},reserved=False)
 cached_manifest,cached=public_sdk.resolve_sdk(lock['sdk'])
 assert cached_manifest==manifest and public_sdk.MANIFEST.read_bytes()==manifest_bytes
 checks.append({'check':'SDK cache, manifest, and 0.1.0 content identity remain byte-exact','result':'pass'})
 report={'schema':1,'result':'pass','scope':__doc__,'sdk':lock['sdk'],'sdk_manifest_sha256':hashlib.sha256(manifest_bytes).hexdigest(),'compiler_id':build_jobs.compiler_identity(),'checks':checks,'seconds':round(time.monotonic()-started,3),'limitations':['resolver boundary checks; existing native build/application evidence retains its original compiler identity']}
 destination=driver.BUILD/'sdk-namespace-boundaries';destination.mkdir(parents=True,exist_ok=True)
 (destination/'execution.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))

if __name__=='__main__':main()
