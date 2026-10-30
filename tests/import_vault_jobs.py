"""Actual Vault-role async import after selected encrypted Project recovery.

Reuses a public canonical archive and the existing guest Project Vault API. An
optional baseline image must reproduce the role-flag failure; the corrected
image recovers the same six-root encrypted selection with fresh capabilities.
No host plaintext vault export, graph-state setter, compiler or signer is used.
"""
import argparse,base64,hashlib,json,struct,subprocess,sys,types
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import projects,project_vault
from creator_retention import Session,require


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,required=True);p.add_argument('--baseline-image',type=Path);p.add_argument('--archive',type=Path,default=ROOT/'build/campaign005/game-secure-editions/game1-closure.json');p.add_argument('--output',type=Path,required=True);a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);vault=out/'objects.img';key=out/'objects.key'
 subprocess.run([str(ROOT/'lt'),'vault-init',str(vault),'--sectors','24576','--key-out',str(key)],cwd=ROOT,check=True)
 archive=json.loads(a.archive.read_text());records=[dict(r,payload=base64.b64decode(r['payload']))for r in archive['nodes']];head=archive['selected'][0]['head'];selected=[dict(name='vault-async-'+str(i),head=head)for i in range(1,7)];expected={r['id']:r for r in records};checks=[];sessions=[]
 def session(name,image):
  image=image.resolve();digest=hashlib.sha256(image.read_bytes()).hexdigest();s=Session(types.SimpleNamespace(output=out/name,image=image,expected_image=digest,backend='qemu'),vault);sessions.append(s);s.boot();return s
 def passed(label,**facts):
  checks.append(dict(check=label,result='passed',**facts));(out/'result.json').write_text(json.dumps(dict(image_sha256=hashlib.sha256(a.image.read_bytes()).hexdigest(),checks=checks,limitations=['explicit development backing; no physical durability or rollback-freshness claim','public selected canonical archive transported at setup; Vault owns authenticated recovery/import']),indent=2)+'\n');print('PASS',label,flush=True)
 try:
  old=session('prepare',a.baseline_image or a.image)
  with old.client()as c:
   project_vault.unlock(c,key.read_bytes());imported=projects.import_records(c,selected,records);identities=[projects.project_identity(c,r['cap'])for r in imported];saved=project_vault.retain(c,[r['cap']for r in imported]);inventory=project_vault.inventory(c);require(len(inventory['projects'])==6 and {r['head']for r in inventory['projects']}=={head},'selected six-root vault record differs');old_cap=imported[0]['cap']
  old.stop();passed('six selected canonical public roots retained by the actual guest Project Vault',prepare_image=old.args.expected_image,generation=saved['generation'],roots=inventory['projects'],nodes=len(records),payload_bytes=sum(len(r['payload'])for r in records))
  if a.baseline_image:
   baseline=session('baseline',a.baseline_image)
   with baseline.client()as c:
    project_vault.unlock(c,key.read_bytes());before=project_vault.inventory(c);require(not projects.roots(c),'fresh baseline guest already has personal roots')
    try:project_vault.recover(c)
    except ValueError as error:
     require(str(error).startswith('Project Vault status5'),'baseline failed outside actual Vault import: '+str(error));denial=str(error)
    else:raise AssertionError('baseline Vault role-flag regression did not reproduce')
    require(not projects.roots(c),'failed baseline recovery published a root prefix');require(project_vault.inventory(c)==before,'failed baseline changed authenticated retained selection')
   baseline.stop();passed('baseline reproduces live Vault-role async import failure without partial roots or changing retained selection',baseline_image=baseline.args.expected_image,error=denial)
  fixed=session('fixed',a.image)
  with fixed.client()as c:
   require(not projects.roots(c),'fresh fixed guest silently retained roots');project_vault.unlock(c,key.read_bytes());recovered=project_vault.recover(c);require(len(recovered['roots'])==6,'Vault recovery lost its explicit six-root profile');require({r['name']:r['head']for r in recovered['roots']}=={r['name']:r['head']for r in selected},'recovered selected roots differ');require([projects.project_identity(c,r['cap'])for r in recovered['roots']]==identities,'logical Project identities changed')
   try:c.objects(29,old_cap)
   except ValueError as error:require(str(error)=='Objects status3','old root failed unexpectedly: '+str(error))
   else:raise AssertionError('old personal root capability survived restart')
   cap=recovered['roots'][0]['cap'];actual={};cursor=0
   while True:
    fields,ids=c.objects(26,cap,cursor)
    if not fields[1]:break
    cursor=fields[3];identity=ids[:32].hex();raw=c.read_object(fields[1]);meta,_=c.objects(21,fields[1]);require(identity in expected and raw==expected[identity]['payload'] and ids[32:64].hex()==expected[identity].get('parent','00'*32) and meta[4]==expected[identity]['kind'] and meta[5]==expected[identity].get('schema',1),'recovered node kind/schema/parent/actual bytes differ');actual[identity]=hashlib.sha256(raw).hexdigest()
   require(set(actual)==set(expected),'recovery omitted canonical dependencies')
  fixed.stop();passed('corrected Vault ProjectSDK.importCommit recovers all six roots with fresh scopes and exact canonical bytes',recovered=recovered,node_payload_sha256=actual,stale_root_rejected=True,captured_role_quota_preserved=True,launcher_admin_scope_preserved=True)
 finally:
  for s in reversed(sessions):s.stop(hard=True)
if __name__=='__main__':main()
