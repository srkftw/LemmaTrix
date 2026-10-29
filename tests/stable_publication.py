"""Focused signed-envelope legacy/stable namespace compatibility checks."""
import hashlib,json,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import releases

def rejected(action):
 try:action()
 except ValueError:return
 raise AssertionError('invalid signed mapping accepted')

def check():
 key=ROOT/'tests/keys/development-rsa.pem'
 public=releases.public_modulus(ROOT/'tests/keys/development-rsa-public.pem')
 publisher=hashlib.sha256(public).hexdigest()
 with tempfile.TemporaryDirectory(prefix='lt-publication-boundary-') as directory:
  binary=Path(directory)/'code.bin';binary.write_bytes(bytes.fromhex('13000000'))
  legacy,legacy_manifest=releases.make(binary,'same-name','1.0.0',0,key)
  old=releases.inspect(legacy,public,legacy_manifest)
  assert old['identity_scheme']==0 and old['project_id']==releases.project('same-name').hex()
  logical='11'*32
  first,first_manifest=releases.make(binary,'same-name','1.0.0',0,key,logical_project_id=logical)
  alias,alias_manifest=releases.make(binary,'renamed-alias','1.0.0',0,key,logical_project_id=logical)
  other,other_manifest=releases.make(binary,'same-name','1.0.0',0,key,logical_project_id='22'*32)
  a=releases.inspect(first,public,first_manifest);b=releases.inspect(alias,public,alias_manifest);c=releases.inspect(other,public,other_manifest)
  assert a['project_id']==b['project_id']==releases.publication(logical,publisher).hex()
  assert c['project_id']!=a['project_id'] and legacy[128:160]!=first[128:160]
  rejected(lambda:releases.inspect(first,public,legacy_manifest))
  rejected(lambda:releases.inspect(legacy,public,first_manifest))
  corrupted=bytearray(first);corrupted[488]=0
  rejected(lambda:releases.inspect(bytes(corrupted),public,first_manifest))
  changed=dict(first_manifest,identity_mapping=dict(first_manifest['identity_mapping'],logical_project_id='22'*32))
  rejected(lambda:releases.inspect(first,public,changed))
  assert releases.inspect(legacy,public,legacy_manifest)==old
  return dict(checks=['legacy scheme0 retains alias-derived ID and original signed bytes','scheme3 derives publication namespace from canonical logical ID and publisher key','alias rename preserves namespace; same-name project substitution changes namespace','cross-schema manifests, scheme rewrite and changed mapping rejected'],legacy_release=old['release_id'],stable_release=a['release_id'],publication_id=a['project_id'])
if __name__=='__main__':print(json.dumps(check(),indent=2))
