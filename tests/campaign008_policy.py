"""Check live Campaign008 policy predicates and enumerate proof assumptions."""
import argparse,hashlib,json,os,re,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import driver,live_build
MODULES=('ServiceBindingPolicy','IdentityPolicy','MessengerStoragePolicy','NodeStoragePolicy',
         'MessengerPolicy','MessengerContactBinding','NetworkSDK','TorPolicy','NodeEnrollmentPolicy',
         'MessengerDelivery','Mailbox','VaultPolicy','ServiceJobs')

def main():
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,default=ROOT/'build/campaign008-policy-evidence.json');a=p.parse_args()
 sources={};names=[]
 for module in MODULES:
  path=ROOT/'Guest'/(module+'.lean');text=path.read_text()
  if re.search(r'^\s*(?:axiom\b|.*\b(?:sorry|admit)\b)',text,re.M):raise ValueError('unlisted proof assumption in '+str(path))
  live_build.compile_module('Guest.'+module)
  sources[str(path.relative_to(ROOT))]=hashlib.sha256(path.read_bytes()).hexdigest()
  names+=['Guest.'+module+'.'+n for n in re.findall(r'^theorem\s+(\w+)',text,re.M)]
 source=a.output.with_suffix('.lean');source.parent.mkdir(parents=True,exist_ok=True)
 source.write_text(''.join('import Guest.'+m+'\n' for m in MODULES)+''.join('#print axioms '+n+'\n' for n in names))
 env=dict(os.environ,LEAN_PATH=str(ROOT),PATH=str(Path(driver.tool('lean')).parent)+':'+os.environ['PATH'])
 result=subprocess.run([driver.tool('lean'),'-Dcompiler.extract_closed=false',str(source)],cwd=ROOT,env=env,check=True,capture_output=True,text=True)
 output=result.stdout+result.stderr;allowed={'propext','Quot.sound'}
 for listed in re.findall(r'depends on axioms:\s*\[([^\]]*)\]',output):
  if set(re.findall(r'[\w.]+',listed))-allowed:raise ValueError('unlisted theorem assumption: '+listed)
 if any("'"+name+"'" not in output for name in names):raise ValueError('missing proof inventory')
 report=dict(schema=1,result='pass',theorems=names,allowed_axioms=sorted(allowed),source_sha256=sources,output=output)
 a.output.write_text(json.dumps(report,indent=2)+'\n');print('PASS',len(names),'live policy theorems; only',sorted(allowed))
if __name__=='__main__':main()
