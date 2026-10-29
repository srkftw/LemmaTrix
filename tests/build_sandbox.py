"""Focused real namespace build/diagnostic and confinement checks."""
import hashlib,json,os,sys,tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import build_jobs
B=build_jobs.ROOT/'build/build-sandbox'

def build(files,name):
 return build_jobs.build_source_snapshot(files,entry='App.run',module='App.Main',profile=2,jobid=name,rootid=hashlib.sha256(name.encode()).hexdigest(),outputdir=B/name)

def main():
 B.mkdir(parents=True,exist_ok=True)
 good={'App/Helper.lean':b'import Guest.Structured\nnamespace App\n@[noinline] def compute (n : UInt64) : UInt64 := n*3+7\nend App\n',
       'App/Main.lean':b'import App.Helper\n#eval do\n  let data \xe2\x86\x90 IO.FS.readFile "/input/resource.txt"\n  if data != "selected resource\\n" then throw (IO.userError "wrong resource")\nnamespace App\ndef run (n : UInt64) : UInt64 := compute n\nend App\n',
       'resource.txt':b'selected resource\n'}
 valid=build(good,'valid')
 if valid['status']=='unavailable':raise RuntimeError('sandbox unavailable: '+valid['diagnostic_text'])
 assert valid['status']=='ok',valid['diagnostic_text']
 broken={**good,'App/Main.lean':b'import App.Helper\nnamespace App\ndef run (n : UInt64) : UInt64 := missingSymbol n\nend App\n'}
 diagnostics=build(broken,'diagnostic')
 assert diagnostics['status']=='error' and any(d['path']=='App/Main.lean' and d['line']==3 for d in diagnostics['diagnostics']),diagnostics
 with tempfile.TemporaryDirectory(prefix='lt-build-secret-') as temporary:
  secret=Path(temporary)/'publisher-private.txt';secret.write_text('never disclose this fixture')
  attack={**good,'App/Main.lean':('import App.Helper\n#eval IO.FS.readFile '+json.dumps(str(secret))+'\nnamespace App\ndef run (n : UInt64) : UInt64 := compute n\nend App\n').encode()}
  denied=build(attack,'host-read-denied')
  assert denied['status']=='error' and 'never disclose' not in denied['diagnostic_text'],denied
  assert 'No such file' in denied['diagnostic_text'] or 'no such file' in denied['diagnostic_text'],denied
 write_attack={**good,'App/Main.lean':b'import App.Helper\n#eval IO.FS.writeFile "/input/resource.txt" "overwrite"\nnamespace App\ndef run (n : UInt64) : UInt64 := compute n\nend App\n'}
 readonly=build(write_attack,'input-write-denied')
 assert readonly['status']=='error' and ('read-only' in readonly['diagnostic_text'].lower() or 'permission denied' in readonly['diagnostic_text'].lower()),readonly
 py=str(Path(sys.executable).resolve())
 code='import os,socket,sys; assert "LT_SANDBOX_SECRET" not in os.environ; s=socket.socket(); s.settimeout(1)\ntry: s.connect(("1.1.1.1",443))\nexcept OSError: sys.exit(0)\nsys.exit(9)'
 check='import App.Helper\n#eval do\n  let r ← IO.Process.output {cmd := '+json.dumps(py)+', args := #['+json.dumps('-c')+','+json.dumps(code)+']}\n  if r.exitCode != 0 then throw (IO.userError "network/environment confinement failed")\nnamespace App\ndef run (n : UInt64) : UInt64 := compute n\nend App\n'
 os.environ['LT_SANDBOX_SECRET']='not-inherited'
 network=build({**good,'App/Main.lean':check.encode()},'network-env-denied')
 del os.environ['LT_SANDBOX_SECRET']
 assert network['status']=='ok',network['diagnostic_text']
 for path in ['../escape.lean','App/../escape.lean','/absolute.lean','Guest/Primitives.lean','App//Main.lean']:
  try:build_jobs.source_commitment({path:b'x'})
  except ValueError:pass
  else:raise AssertionError('invalid path accepted:'+path)
 report={'schema':1,'environment':'native x86-64 Linux user/mount/network/PID namespaces and chroot','result':'pass','native_artifact':valid['artifact'],'exact_multimodule_resource_input':True,'located_real_diagnostic':True,'host_file_read_denied':True,'immutable_input_write_denied':True,'ambient_environment_denied':True,'outbound_network_denied':True,'canonical_path_rejections':True,'toolchain_id':valid['toolchain_id']}
 (B/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
