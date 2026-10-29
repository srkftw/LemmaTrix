"""Reject wrong publisher and copied live-root authority before bootstrap signing.

Needs the still-running guest that created a real successful native fork BuildJob.
The selected archive is public material, imported only into a fresh local root.
"""
import argparse,base64,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import live,projects

def main():
 p=argparse.ArgumentParser();p.add_argument('--socket',required=True,type=Path);p.add_argument('--result',required=True,type=Path);p.add_argument('--archive',required=True,type=Path);p.add_argument('--root-alias',required=True);p.add_argument('--key',required=True,type=Path);p.add_argument('--wrong-key',required=True,type=Path);p.add_argument('--output',required=True,type=Path);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
 c=live.Client(a.socket,timeout=120);checks=[]
 def denied(label,call,reason,path):
  try:call()
  except ValueError as e:
   assert reason in str(e),(label,str(e));assert not path.exists(),('signing produced output before authorization',path)
   checks.append(dict(check=label,result='pass',reason=str(e)));print('PASS',label,flush=True)
  else:raise AssertionError(label+' unexpectedly authorized signing')
 try:
  original=next(r for r in projects.roots(c) if r['name']==a.root_alias)
  logical=projects.project_identity(c,original['cap']);binding=c.objects(29,original['cap'])[0][7]
  wrong=a.output/'wrong-publisher.ltrel'
  denied('canonical Fork origin rejects a different publisher before signing',lambda:projects.publish_result(a.result,a.wrong_key,a.root_alias,'1.0.1',wrong,client=c,authority_root=original['cap']),'not the publisher authorized',wrong)
  archive=json.loads(a.archive.read_text());assert archive['project_id']==logical and archive['selected'][0]['head']==original['head']
  records=[dict(n,payload=base64.b64decode(n['payload'],validate=True)) for n in archive['nodes']]
  # Matching alias is deliberate: a display name must confer no signing power.
  # Roots already owned by another app may share an alias with this local import.
  selected=[dict(name=a.root_alias,head=original['head'])]
  copied=projects.import_records(c,selected,records)[0]['cap']
  assert projects.project_identity(c,copied)==logical and c.objects(29,copied)[0][7]!=binding
  dest=a.output/'copied-root.ltrel'
  denied('same-name reimport preserves identity but cannot reuse original live-root BuildJob signing authority',lambda:projects.publish_result(a.result,a.key,a.root_alias,'1.0.1',dest,client=c,authority_root=copied),'selected live root/requester differs',dest)
  (a.output/'evidence.json').write_text(json.dumps(dict(logical_project=logical,original_binding=binding,copied_binding=c.objects(29,copied)[0][7],checks=checks),indent=2)+'\n')
 finally:c.close()
if __name__=='__main__':main()
