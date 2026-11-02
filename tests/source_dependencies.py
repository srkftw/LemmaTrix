"""Verify the real guest-signed Notes helper and offline fetched source closure."""
import argparse,base64,copy,hashlib,json,sys,tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import driver,public_sdk,sdk

def denied(fn,label):
 try:fn()
 except ValueError as error:return dict(check=label,diagnostic=str(error))
 raise AssertionError('accepted '+label)
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--project',type=Path,default=driver.ROOT/'examples/project-notes');p.add_argument('--output',type=Path,default=driver.BUILD/'source-dependency-checks');a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
 files=sdk.read_project(a.project);lock=json.loads(files['lemma.lock.json']);pin=lock['dependencies'][0];carrier_path='deps/'+pin['release_id']+'.json';document=json.loads(files[carrier_path])
 actual,source,_=public_sdk.verify_dependency(document,publisher=pin['publisher_key_id'],release_id=pin['release_id']);assert actual['facet']=='DevelopmentArtifact'and actual['size']==0
 checks=[dict(check='actual guest-native Ed25519 source-only helper signature/source/exports verified',release_id=actual['release_id'])]
 saved=public_sdk.DEPENDENCIES
 try:
  with tempfile.TemporaryDirectory(prefix='lt-empty-dependency-cache-')as cache:
   public_sdk.DEPENDENCIES=Path(cache)
   _,_,_,resolved,_,_=public_sdk.resolve(files)
   assert resolved['Notes/Schema.lean']==source['Notes/Schema.lean'];assert 'lemma.lock.json'not in resolved
   checks.append(dict(check='fetched frozen carrier resolves actual dependency with an empty local dependency cache'))
   metadata='dependency-metadata/'+pin['release_id']+'/lemma.lock.json';assert metadata in resolved
   checks.append(dict(check='library metadata keeps exact bytes under release scope without replacing app metadata'))
   damaged={**files,carrier_path:files[carrier_path][:-1]+b'!'}
   checks.append(denied(lambda:public_sdk.resolve(damaged),'carrier differs from exact locked bytes'))
 finally:public_sdk.DEPENDENCIES=saved
 wrong=copy.deepcopy(document);wrong['sources']['Notes/Schema.lean']=base64.b64encode(source['Notes/Schema.lean']+b'\n').decode()
 checks.append(denied(lambda:public_sdk.verify_dependency(wrong,publisher=pin['publisher_key_id'],release_id=pin['release_id']),'source substitution against real signed release'))
 bad_signature=copy.deepcopy(document);raw=bytearray(base64.b64decode(bad_signature['release']));raw[512]^=1;bad_signature['release']=base64.b64encode(raw).decode()
 checks.append(denied(lambda:public_sdk.verify_dependency(bad_signature,publisher=pin['publisher_key_id'],release_id=pin['release_id']),'tampered Ed25519 signature'))
 checks.append(denied(lambda:public_sdk.verify_dependency(document,publisher='00'*32,release_id=pin['release_id']),'wrong selected publisher'))
 checks.append(denied(lambda:public_sdk.resolve_dependencies(lock['dependencies'],{'version':'0.1.0','content_id':'00'*32},files),'dependency SDK substitution'))
 report=dict(schema=1,status='pass',project=str(a.project),sdk=lock['sdk'],dependency_lock_id=lock['content_id'],dependency_release_id=pin['release_id'],dependency_publisher_key_id=pin['publisher_key_id'],carrier_sha256=hashlib.sha256(files[carrier_path]).hexdigest(),source_sha256=hashlib.sha256(source['Notes/Schema.lean']).hexdigest(),checks=checks,limitations=['host dependency verification supplements native graph/signature admission','no host signature or guest approval is manufactured by this check'])
 (a.output/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
