"""Fresh final-image provider, typed operator recovery and actual native fork publication.

Continue public immutable bytes from the preserved source. No publisher key is
exported and the prior uncertain request is retried with the same signed release.
"""
import argparse,json,os,socket,struct,sys,time,hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import capsule,federation,forge,identity,network,releases,server_store
from campaign010_forge_mux import MuxNode,archive,PUBLIC,digest
from campaign010_forge_continue import attach,stop,verify_closure
from forge_journey import wait
from forge_replication import save
from creator_journey import rendered_text

def select(n,name):
 before=n.inspect()['selected_root'];n.focus(n.instance)
 if rendered_text(n.ui.frame(),10,56,10,0x9fc6a5)=='FEDERATION':n.ui.press(59);time.sleep(.5)
 n.ui.press(60)
 def ready():
  frame=n.ui.frame();rows=[rendered_text(frame,32,107+i*12,len(name)+1).rstrip()for i in range(16)];return rows if name in rows else None
 rows=wait(ready,'exact named trusted scope picker',60)
 for _ in range(rows.index(name)):n.ui.press(108);time.sleep(.5)
 time.sleep(.5);n.ui.press(28)
 return wait(lambda:(s if(s:=n.inspect())['status']==1 and s['selected_root']!=before else None),'new exact selected-root delegation',90)

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for f in ('state','image','server-forge','identity','registry','fork'):p.add_argument('--'+f,type=Path,required=True)
 p.add_argument('--resume-fresh',type=int);a=p.parse_args();base=a.state.parent;old=json.loads(a.state.read_text());source=attach(old['live_actors'][1]);oldp=type('Stopped',(),{'ui':None,'client':lambda self: (_ for _ in ()).throw(OSError('already stopped'))})();rec=json.loads((base/'operator-recovery.json').read_text());configuration=json.loads((base/'alpha-public-verifier.json').read_text());os.environ['LT_GUEST_IMAGE']=str(a.image.resolve());out=base/'final-provider.json';report=dict(schema=1,result='running',checks=[],image=str(a.image.resolve()),image_sha256=hashlib.sha256(a.image.read_bytes()).hexdigest(),prior_uncertainty='Fork did not obtain native acceptance; retry exact immutable release after expired relationship replacement, no new publisher signature.');nodes=[];started=time.monotonic()
 def write():
  report.update(elapsed_seconds=round(time.monotonic()-started,3),actors=[dict(pid=n.proc.pid if hasattr(n,'proc')else n.pid,socket=str(n.sock),graphics=str(n.qmp),forge=getattr(n,'instance',None),registry=getattr(n,'registry',None))for n in nodes]);out.write_text(json.dumps(report,indent=2)+'\n')
 def passed(label,**kw):report['checks'].append(dict(check=label,result='pass',**kw));write();print('PASS',label,flush=True)
 try:
  stop(oldp)
  if a.resume_fresh:
   from graphical_devices import DeviceInput
   provider=object.__new__(MuxNode);provider.path=base/'provider-final-lease';provider.sock=provider.path/'portal.sock';provider.qmp=provider.path/'display.qmp';provider.ui=DeviceInput('qemu',provider.qmp);provider.pid=a.resume_fresh
  else:provider=MuxNode(base/'provider-final-lease',base/'provider.img')
  nodes=[provider,source];provider.install(a.server_forge,PUBLIC)
  with provider.client()as c:
   server_store.call(c,230);grant=server_store.call(c,231,provider.instance,2,1048576,digest('Campaign010 MUX project-notes-1.1.0 graph'))[0][1]
   service=identity.start(c,a.identity,PUBLIC);raw=a.registry.read_bytes();c.request(10,raw[128:160]+releases.public_key(PUBLIC));slot,_=c.install(a.registry);provider.registry=struct.unpack_from('<Q',c.request(25,struct.pack('<Q',slot)),8)[0]
   catalog=server_store.call(c,231,provider.registry,1,1048576,bytes.fromhex(rec['catalog_namespace']))[0][1]
   restored=federation.recover_native(c,provider.registry,Path(rec['credential_path']).read_bytes(),rec['namespace'],service['release'],releases.inspect(raw)['release_id'],store_grant=catalog)
   assert restored['public_key']==configuration['public_key']and restored['generation']>configuration['generation']and restored['recovered_catalog_records']>=2
   item=archive(a.fork);federation.call(c,provider.registry,3,data=item['publication']+item['publisher'])
  configuration.update(generation=restored['generation']);(base/'alpha-public-verifier.json').write_text(json.dumps(configuration,indent=2)+'\n');rec.update(key_live_only=restored['key'],public=configuration);(base/'operator-recovery.json').write_text(json.dumps(rec,indent=2)+'\n')
  with source.client()as c:
   c.request(26,struct.pack('<Q',source.instance));c.request(26,struct.pack('<Q',source.registry));network.call(c,14,slot=0)
   source.instance=struct.unpack_from('<Q',c.request(25,struct.pack('<Q',1)),8)[0];source.registry=struct.unpack_from('<Q',c.request(25,struct.pack('<Q',2)),8)[0]
  relation=base/'source-provider-final';relation.mkdir();key,pub=relation/'endpoint.pem',relation/'endpoint.pub';capsule.generate_key(key,pub);s=socket.socket();s.bind(('127.0.0.1',0));endpoint='127.0.0.1:'+str(s.getsockname()[1]);s.close();description=relation/'service.public';meta=network.create_description(key,digest('Campaign010 MUX source final'),endpoint,'forge',description)
  ck,sk=relation/'client.credential',relation/'server.credential';network.provision(ck,sk,bytes.fromhex(meta['client_id']),bytes.fromhex(meta['server_id']),bytes.fromhex(meta['service_id']))
  with provider.client()as c:network.configure(c,sk,description,slot=0);network.call(c,13,slot=0)
  with source.client()as c:network.configure(c,ck,description,slot=0);network.call(c,13,slot=0)
  write()
  def auth():
   states=[]
   for n in nodes:
    with n.client()as c:states.append(network.status(c,slot=0))
   return states if all(s['endpoint_authenticated']for s in states)else None
  peers=wait(auth,'fresh approved exact bulk relationship',180)
  with provider.client()as c:forge.configure(c,provider.instance,sk,'registry','portable',grant,peer_slot=0,stream=1);forge.federation_configure(c,provider.instance,configuration['federation_id'],3)
  with source.client()as c:forge.configure(c,source.instance,ck,peer_slot=0,stream=1);federation.configure_native_verifier(c,source.registry,configuration['public_key'],'consumer',allowed_rights=895,generation=configuration['generation']);forge.federation_configure(c,source.instance,configuration['federation_id'],3)
  # Recover only selected Notes namespace; this also exercises physical F4 and
  # the final-image strict op17 path before any source fork traffic.
  provider.focus(provider.instance);provider.ui.press(67);time.sleep(.5)
  def shown():
   value=provider.archive()
   if value['phase']==9:raise AssertionError(value)
   return value if value['phase']==4 else None
  preview=wait(shown,'exact selected Notes32 store inspection',180);assert preview['head']=='5e65e399196041a5048161c893984eccb2238807a010a757c2cc465a5c8cf2ef';provider.ui.press(67)
  wait(lambda:provider.archive()['phase']==8,'selected Notes32 native recovery',240)
  select(provider,next(row['name']for row in provider.roots()if row['head']==preview['head']));provider.ui.press(62)
  wait(lambda:provider.inspect()['offered_nodes']==32,'strict17 exact32 offer',90)
  passed('final-image strict lease Forge recovers selected32-node graph and offers it through owned17',recovery=restored,preview=preview,peers=peers,forge_bytes=261160)
  select(source,item['root']['name']);source.ui.press(87)
  def decision(n,local=False):
   with n.client()as c:r=forge.federation_inspect(c,n.instance,local)
   return r if r['descriptor']['release_id']==item['release']and(r['local_phase']==2 if local else r['remote_phase']==2)else None
  remote=wait(lambda:decision(source),'exact new publisher fork native federation decision',300);local=wait(lambda:decision(provider,True),'provider exact native fork decision',180)
  assert remote['classification']==2 and local['descriptor']['classification']==2
  transfer=verify_closure(provider,item['doc']);provider.focus(provider.instance)
  with provider.client()as c:
   grant=server_store.call(c,231,provider.instance,2,1048576,digest('Campaign010 MUX '+item['root']['name']+' graph'))[0][1];c.request(150,struct.pack('<Q8Q',provider.instance,61,0,grant,0,0,0,0,1))
  retained=save(provider);passed('actual useful fork republished through native admission and complete network bytes',release=item['release'],decision=remote,transfer=transfer,retention=retained)
  with provider.client()as c:
   retained=federation.retain_native(c,provider.registry,restored['key'],Path(rec['credential_path']).read_bytes(),rec['namespace'],'consumer',895);federation.call(c,provider.registry,23)
   cursor=0
   while cursor<16:
    try:q,d=federation.call(c,provider.registry,6,h=cursor)
    except ValueError:break
    (base/('alpha2-'+d[128:160].hex()+'.admission')).write_bytes(d);cursor=q[3]
  rec.update(retained=retained);(base/'operator-recovery.json').write_text(json.dumps(rec,indent=2)+'\n');report.update(result='pass',configuration=configuration);write()
 except BaseException as error:
  report.update(result='fail',error=repr(error));write()
  for n in nodes:
   try:(n.path/'final-provider-failure.ppm').write_bytes(n.ui.frame().ppm())
   except Exception:pass
  raise
 finally:
  for n in [oldp,*nodes]:
   if n.ui:n.ui.close();n.ui=None
if __name__=='__main__':main()
