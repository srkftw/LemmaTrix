"""Owned inert producer/Lean doubles for normal core binding and cache controls."""
import contextlib,hashlib,io,json,os,sys,tempfile
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import driver,live_build,build_jobs

def main():
 checks=[]
 def passed(label,**details):checks.append(dict(check=label,result='pass',**details))
 with tempfile.TemporaryDirectory(prefix='lt-core-binding-')as temporary:
  root=Path(temporary);B=root/'build/live';guest=root/'Guest';guest.mkdir();B.mkdir(parents=True)
  prior={B/'guest.bin':b'owned prior image',B/'compiler.sha256':b'owned old identity',B/'old.module.sha256':b'owned cache',guest/'Old.olean':b'owned elaboration cache'}
  for p,data in prior.items():p.write_bytes(data)
  original_stdout=io.StringIO()
  for label,error,identity in [('resolver-os',OSError('owned explicit descriptor missing'),None),('resolver-runtime',RuntimeError('owned resolver failure'),None),('identity-os',None,OSError('owned compiler source missing')),('identity-runtime',None,RuntimeError('owned worker failure')),('zero',None,'00'*32),('short',None,'ab'),('malformed',None,'not hex'),('non-string',None,None)]:
   frozen=object();called=[]
   def resolve():
    called.append('resolve')
    if error:raise error
    return frozen
   def compiler(*,toolchain):
    assert toolchain is frozen;called.append('identity')
    if isinstance(identity,BaseException):raise identity
    return identity
   with patch.object(live_build,'ROOT',root),patch.object(live_build,'B',B),patch.object(build_jobs,'resolve_toolchain',resolve),patch.object(build_jobs,'compiler_identity',compiler),patch.object(driver,'validate_toolchain',side_effect=AssertionError('tool validation entered before binding')),patch.object(live_build,'compile_module',side_effect=AssertionError('producer entered')),patch.object(live_build,'artifact',side_effect=AssertionError('artifact producer entered')),contextlib.redirect_stdout(original_stdout):
    try:live_build.build(clean=True)
    except (OSError,RuntimeError,ValueError)as caught:
     if error:assert caught is error
     elif isinstance(identity,BaseException):assert caught is identity
    else:raise AssertionError('accepted '+label)
   assert all(p.read_bytes()==data for p,data in prior.items());assert 'LIVE IMAGE'not in original_stdout.getvalue();passed(label+' fails before producer/clean/output publication',order=called)
  # Also prove that a fresh output directory is not created by failed binding.
  fresh=root/'never-created'
  with patch.object(live_build,'B',fresh),patch.object(build_jobs,'resolve_toolchain',side_effect=OSError('owned missing descriptor')):
   try:live_build.build(clean=True)
   except OSError:pass
   else:raise AssertionError('resolver unexpectedly succeeded')
  assert not fresh.exists();passed('failed binding creates no fresh output directory')
  frozen=object();calls=[];identity='ab'*32
  def resolve():calls.append('resolve');return frozen
  def compiler(*,toolchain):assert toolchain is frozen;calls.append('identity');return identity
  def compile(module):calls.append('compile '+module)
  def artifact(module,entry,prefix,*args,**kwargs):
   calls.append('artifact '+prefix);p=B/(prefix+'.bin');p.write_bytes(b'\x13\0\0\0');return p
  captured=io.StringIO()
  with patch.object(live_build,'ROOT',root),patch.object(live_build,'B',B),patch.object(build_jobs,'resolve_toolchain',resolve),patch.object(build_jobs,'compiler_identity',compiler),patch.object(driver,'validate_toolchain',side_effect=lambda:calls.append('validate')),patch.object(live_build,'compile_module',compile),patch.object(live_build,'artifact',artifact),contextlib.redirect_stdout(captured):image=live_build.build(clean=True)
  data=image.read_bytes();assert data[0x200400:0x200420]==bytes.fromhex(identity);assert(B/'compiler.sha256').read_text()==identity+'\n';assert len(data)==0x600000 and calls[:3]==['resolve','identity','validate'];assert not(guest/'Old.olean').exists()and not(B/'old.module.sha256').exists();assert 'LIVE IMAGE '+hashlib.sha256(data).hexdigest()in captured.getvalue();passed('owned inert success embeds the exact once-resolved identity and only then reports image',synthetic_fixture=True,compiler_calls=calls.count('identity'))
  lean=root/'lean';lean.write_bytes(b'owned tool bytes; not executable');invocations=[]
  with patch.object(driver,'tool',return_value=str(lean)),patch.object(driver,'run',side_effect=lambda argv,**kw:invocations.append((argv,kw))):
   driver.lean(['-o','owned.olean','owned.lean']);driver.lean(['--run','Compiler/Main.lean','Guest.Owned','owned.S','Guest.Owned.main'])
  for argv,kw in invocations:assert argv[1:4]==list(driver.LEAN_OPTIONS)and kw['env']['LEAN_PATH']==str(driver.ROOT)
  passed('elaboration and Compiler/Main emission use identical finite supported controls',argv=[row[0]for row in invocations])
  live_build.lean_module_identity.cache_clear()
  with patch.object(driver,'tool',return_value=str(lean)):
   before=live_build.lean_module_identity();artifact_before=live_build.build_identity()
   with patch.object(driver,'LEAN_OPTIONS',('-j1','-s32768','-Dcompiler.extract_closed=false')):
    live_build.lean_module_identity.cache_clear();after=live_build.lean_module_identity();artifact_after=live_build.build_identity()
   assert before!=after and artifact_before!=artifact_after
  live_build.lean_module_identity.cache_clear();passed('effective controls change both elaboration and artifact cache identities')
  source=guest/'Owned.lean';source.write_text('def owned : UInt64 := 1\n');(root/'lean-toolchain').write_text('leanprover/lean4:v4.34.1\n');emitted=[]
  def emit(argv):emitted.append(argv);Path(argv[1]).write_bytes(b'owned inert olean stand-in')
  with patch.object(live_build,'ROOT',root),patch.object(live_build,'B',B),patch.object(driver,'tool',return_value=str(lean)),patch.object(driver,'lean',side_effect=emit):
   live_build.compile_module('Guest.Owned');live_build.compile_module('Guest.Owned');assert len(emitted)==1
   with patch.object(driver,'LEAN_OPTIONS',('-j1','-s32768','-Dcompiler.extract_closed=false')):
    live_build.lean_module_identity.cache_clear();live_build.compile_module('Guest.Owned')
   assert len(emitted)==2
  live_build.lean_module_identity.cache_clear();passed('module cache reuses equal controls and recompiles when effective controls change')
 report=dict(schema=1,status='pass',checks=checks,actual_compiler_or_guest_processes=0,scope='Only owned inert bytes/producer doubles. The synthetic 6MiB layout stand-in is not an executed or accepted core image.')
 print(json.dumps(report,indent=2))
if __name__=='__main__':main()
