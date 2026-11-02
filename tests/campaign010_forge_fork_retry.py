"""Retry exact fork after inspecting the selected committed store namespace."""
import argparse,json,struct,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import federation,forge,server_store
from campaign010_forge_mux import archive,digest
from campaign010_forge_continue import attach,verify_closure
from campaign010_forge_final_provider import select
from forge_journey import wait
from forge_replication import save

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--state',type=Path,required=True);p.add_argument('--fork',type=Path,required=True);a=p.parse_args();base=a.state.parent;r=json.loads(a.state.read_text());failure=base/'final-provider-scope-failure.json'
 if not failure.exists():failure.write_text(json.dumps(r,indent=2)+'\n')
 provider,source=[attach(row)for row in r['actors']];nodes=[provider,source];item=archive(a.fork);began=time.monotonic();rec=json.loads((base/'operator-recovery.json').read_text());config=json.loads((base/'alpha-public-verifier.json').read_text());r.update(result='running',checks=[]);r.pop('error',None)
 def write():r['elapsed_seconds']=round(time.monotonic()-began,3);a.state.write_text(json.dumps(r,indent=2)+'\n')
 def passed(label,**kw):r['checks'].append(dict(check=label,result='pass',**kw));write();print('PASS',label,flush=True)
 try:
  for n,credential,role in [(provider,base/'source-provider-final/server.credential','registry'),(source,base/'source-provider-final/client.credential','client')]:
   with n.client()as c:
    grant=server_store.call(c,231,n.instance,2,1048576,digest('Campaign010 MUX project-notes-1.1.0 graph'))[0][1]if n is provider else 0
    forge.configure(c,n.instance,credential,role,'portable',grant)
  provider.focus(provider.instance);provider.ui.press(67);time.sleep(.5)
  def preview():
   q=provider.archive()
   if q['phase']==9:raise AssertionError(q)
   return q if q['phase']==4 else None
  shown=wait(preview,'exact actual Notes32 retained namespace inspection',180);assert shown['head']=='5e65e399196041a5048161c893984eccb2238807a010a757c2cc465a5c8cf2ef';provider.ui.press(67)
  wait(lambda:provider.archive()['phase']==8,'native selected Notes32 recovery',240)
  root=next(q for q in provider.roots()if q['head']==shown['head']);select(provider,root['name']);before_lease=provider.inspect()['metadata_grant'];provider.ui.press(62)
  wait(lambda:provider.inspect()['offered_nodes']==32,'strict17 exact32 offer',90)
  passed('final-image strict17 Forge recovers actual selected32-node store and offers complete closure',preview=shown,namespace=digest('Campaign010 MUX project-notes-1.1.0 graph').hex(),configuration_after_authentication=True,metadata_grant_before=before_lease,metadata_grant_after=provider.inspect()['metadata_grant'])
  select(source,item['root']['name']);source.ui.press(87)
  def decision(n,local=False):
   with n.client()as c:q=forge.federation_inspect(c,n.instance,local)
   return q if q['descriptor']['release_id']==item['release']and(q['local_phase']==2 if local else q['remote_phase']==2)else None
  remote=wait(lambda:decision(source),'same immutable fork admission retry',300);local=wait(lambda:decision(provider,True),'native exact fork acceptance',180);assert remote['classification']==2 and local['descriptor']['classification']==2
  exact=verify_closure(provider,item['doc']);provider.focus(provider.instance)
  with provider.client()as c:
   g=server_store.call(c,231,provider.instance,2,1048576,digest('Campaign010 MUX '+item['root']['name']+' graph'))[0][1];c.request(150,struct.pack('<Q8Q',provider.instance,61,0,g,0,0,0,0,1))
  retained=save(provider);passed('actual useful second-user fork native admission and24 exact network objects retained',release=item['release'],decision=remote,transfer=exact,retention=retained)
  with provider.client()as c:
   kept=federation.retain_native(c,provider.registry,rec['key_live_only'],Path(rec['credential_path']).read_bytes(),rec['namespace'],'consumer',895);federation.call(c,provider.registry,23);cursor=0
   while cursor<16:
    try:q,d=federation.call(c,provider.registry,6,h=cursor)
    except ValueError:break
    (base/('alpha2-'+d[128:160].hex()+'.admission')).write_bytes(d);cursor=q[3]
  rec['retained']=kept;(base/'operator-recovery.json').write_text(json.dumps(rec,indent=2)+'\n');r.update(result='pass',configuration=config);write()
 except BaseException as e:r.update(result='fail',error=repr(e));write();raise
 finally:
  for n in nodes:
   if n.ui:n.ui.close();n.ui=None
if __name__=='__main__':main()
