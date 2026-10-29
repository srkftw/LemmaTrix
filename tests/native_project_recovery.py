import sys,subprocess,types,struct,json,hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import projects,project_vault,driver
from creator_retention import Session
from graph_importer import records
out=Path('build/networked-import-recovery-v2').resolve();out.mkdir(exist_ok=False)
image=Path('build/live/guest.bin').resolve();expected=hashlib.sha256(image.read_bytes()).hexdigest()
backing=out/'objects.img';keyfile=out/'objects.key'
subprocess.run(['./lt','vault-init',str(backing),'--sectors','24576','--key-out',str(keyfile)],check=True)
a=types.SimpleNamespace(output=out,image=image,expected_image=expected,backend='qemu')
s=Session(a,backing)
try:
 s.boot()
 with s.client() as c:
  project_vault.unlock(c,keyfile.read_bytes())
  roots,nodes=records('native-recovered')
  imported=projects.import_records(c,roots,nodes)[0]
  identity=projects.project_identity(c,imported['cap'])
  saved=project_vault.retain(c,[imported['cap']])
 s.stop();s.boot()
 with s.client() as c:
  project_vault.unlock(c,keyfile.read_bytes())
  result=project_vault.recover(c)
  cap=result['roots'][0]['cap']
  assert projects.project_identity(c,cap)==identity
  head,files=projects.snapshot(c,cap)
  assert head==roots[0]['head'] and sum(map(len,files.values()))>65536
  assert cap!=imported['cap']
  result.update(image=expected,checks=['native op217 recovery ordering/import/publication from encrypted backing','actual >64KiB source/resource available after fresh guest restart','fresh scoped capability and stable canonical identity'])
  (out/'evidence.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
finally:s.stop(hard=True)
