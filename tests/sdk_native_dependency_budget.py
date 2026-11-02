"""Check native queue accounting without compiling or creating signed releases."""
import json,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import sdk

def main():
 checks=[]
 def denied(releases,children,count):
  try:sdk.native_dependency_work(releases,children)
  except ValueError as error:
   assert 'needs '+str(count)+' dependency references' in str(error)
   checks.append({'check':'reject '+str(len(releases))+' unique releases requiring '+str(count)+' repeated references','diagnostic':str(error)})
  else:raise AssertionError('native queue overflow passed preflight')
 flat=[str(i)for i in range(16)]
 assert sdk.native_dependency_work(flat,{r:[]for r in flat})==16
 checks.append({'check':'sixteen flat references remain supported'})
 children={r:[]for r in flat};children['0']=['1'];denied(flat,children,17)
 chain=[str(i)for i in range(6)];denied(chain,{r:[str(int(r)+1)]if r!='5'else[]for r in chain},21)
 diamond={'a':['b','c'],'b':['d'],'c':['d'],'d':[]}
 assert sdk.native_dependency_work(list(diamond),diamond)==10
 checks.append({'check':'shared diamond child counts once per traversal, total10 rather than four unique releases'})
 # This is the ordinary CLI over the actual guest-signed helper carrier. The
 # synthetic DAGs above test arithmetic only and confer no dependency trust.
 actual=json.loads(subprocess.run([sys.executable,str(ROOT/'lt'),'sdk','check',str(ROOT/'examples/project-notes')],check=True,capture_output=True,text=True).stdout)
 assert actual['status']=='ok'and actual['native_dependency_references']==1 and actual['sdk']['content_id']=='3312ddcd277f401c377142b006bac6cf9aeefd8fa89f4d4c78f1fd5469caf533'
 checks.append({'check':'normal Project Notes preflight authenticates actual signed helper and reports one reference','sdk':actual['sdk'],'dependency_lock_id':actual['dependency_lock_id']})
 report={'schema':1,'result':'pass','command':'python3 tests/sdk_native_dependency_budget.py','checks':checks,'limitations':['Synthetic DAG declarations exercise the shipped accounting helper only. No synthetic release is signed, trusted or admitted.','The normal Notes check uses its existing genuine signed source dependency. No compilation or native network execution is claimed.']}
 out=ROOT/'build/sdk-native-dependency-budget';out.mkdir(parents=True,exist_ok=True);(out/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))

if __name__=='__main__':main()
