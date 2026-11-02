"""Continue exact live MUX publication after a physically selected project.

No setup, graph import or author approval is repeated for Notes. A separately
exported real native fork may be selected for an additional actual publication.
"""
import argparse,json,os,struct,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import federation,forge,identity,network,projects,server_store
from campaign010_forge_mux import MuxNode,archive,Client,PUBLIC,digest
from campaign010_forge_continue import attach,fetch,verify_closure
from forge_journey import wait
from forge_replication import save
from graphical_devices import DeviceInput
from creator_journey import rendered_text

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for field in ('state','archive','forge','registry','image'):p.add_argument('--'+field,type=Path,required=True)
 p.add_argument('--fork',type=Path);a=p.parse_args();base=a.state.parent;report=json.loads(a.state.read_text());nodes=[attach(r)for r in report['live_actors']];provider,source=nodes;app=archive(a.archive);configuration=json.loads((base/'alpha-public-verifier.json').read_text());started=time.monotonic();phase='continue native selected32-node publication';os.environ['LT_GUEST_IMAGE']=str(a.image.resolve())
 def write():
  report.pop('error',None);report.update(result='running',phase=phase,continuation_elapsed_seconds=round(time.monotonic()-started,3),live_actors=[dict(pid=n.pid if hasattr(n,'pid')else n.proc.pid,socket=str(n.sock),graphics=str(n.qmp),forge=n.instance,registry=getattr(n,'registry',None),image=str(a.image.resolve()))for n in nodes]);a.state.write_text(json.dumps(report,indent=2)+'\n')
 def passed(label,**fields):report['checks'].append(dict(check=label,result='pass',**fields));write();print('PASS',label,flush=True)
 def decision(n,item,local=False):
  with n.client()as c:r=forge.federation_inspect(c,n.instance,local)
  return r if r['descriptor']['release_id']==item['release']and(r['local_phase']==2 if local else r['remote_phase']in(2,3))else None
 def publish(item):
  source.focus(source.instance);source.ui.press(87)
  accepted=wait(lambda:decision(source,item),'native exact MUX publication decision',300);local=wait(lambda:decision(provider,item,True),'provider native exactdecision',180)
  assert accepted['classification']==2 and local['descriptor']['classification']==2
  exact=verify_closure(provider,item['doc']);(base/(item['root']['name']+'-admission.json')).write_text(json.dumps(accepted,indent=2)+'\n')
  provider.focus(provider.instance)
  with provider.client()as c:
   grant=server_store.call(c,231,provider.instance,2,1048576,digest('Campaign010 MUX '+item['root']['name']+' graph'))[0][1];raw=c.request(150,struct.pack('<Q8Q',provider.instance,61,0,grant,0,0,0,0,1));assert struct.unpack_from('<Q',raw)[0]==0
  retained=save(provider);passed('actual signed '+item['root']['name']+' native admission and exact network closure retention',release=item['release'],transfer=exact,decision=accepted,retention=retained)
 def select(n,name):
  n.focus(n.instance);n.ui.press(60)
  def ready():
   f=n.ui.frame();rows=[rendered_text(f,32,107+i*12,len(name)+1).rstrip()for i in range(16)];return rows if name in rows else None
  rows=wait(ready,'native trusted project rows',60)
  for _ in range(rows.index(name)):n.ui.press(108);time.sleep(.5)
  time.sleep(.5);n.ui.press(28)
  wait(lambda:n.inspect()['status']==1,'native exact selected project delegation',90)
 try:
  assert source.inspect()['status']==1,'continue requires actual native selected root'
  assert any(r['head']==app['root']['head']for r in source.roots()),'selected public source is unavailable'
  write();publish(app)
  if a.fork:
   phase='native separately generated second-user fork publication';write();fork=archive(a.fork)
   with provider.client()as c:federation.call(c,provider.registry,3,data=fork['publication']+fork['publisher'])
   with source.client()as c:
    root=projects.import_records(c,fork['doc']['selected'],fork['rows'])[0]['cap'];shell=struct.unpack_from('<Q',c.request(2),4*32)[0];c.objects(27,root,shell,127)
   select(source,fork['root']['name']);publish(fork)
  phase='fresh reader32-object retrieval';write()
  from campaign010_forge_continue import stop
  stop(source);nodes.remove(source)
  with provider.client()as c:
   c.request(26,struct.pack('<Q',provider.instance));provider.instance=struct.unpack_from('<Q',c.request(25,struct.pack('<Q',1)),8)[0]
  reader=MuxNode(base/'reader');nodes.append(reader);reader.pid=reader.proc.pid
  import socket,capsule
  relation=base/'reader-provider';relation.mkdir();key,pub=relation/'endpoint.pem',relation/'endpoint.pub';capsule.generate_key(key,pub);probe=socket.socket();probe.bind(('127.0.0.1',0));endpoint='127.0.0.1:'+str(probe.getsockname()[1]);probe.close();description=relation/'service.public';meta=network.create_description(key,digest('Campaign010 MUX new reader'),endpoint,'forge',description)
  ck,sk=relation/'client.credential',relation/'server.credential';network.provision(ck,sk,bytes.fromhex(meta['client_id']),bytes.fromhex(meta['server_id']),bytes.fromhex(meta['service_id']))
  with provider.client()as c:network.configure(c,sk,description,slot=1);network.call(c,13,slot=1);forge.configure(c,provider.instance,sk,'seed','portable',peer_slot=1,stream=1);forge.federation_configure(c,provider.instance,configuration['federation_id'],3)
  with reader.client()as c:network.configure(c,ck,description,slot=0);network.call(c,13,slot=0)
  def authenticated():
   states=[]
   for n,slot in ((provider,1),(reader,0)):
    with n.client()as c:states.append(network.status(c,slot=slot))
   return states if all(s['endpoint_authenticated']for s in states)else None
  peers=wait(authenticated,'new selected v2 peers authenticate',180)
  reader.install(a.forge,PUBLIC)
  with reader.client()as c:
   forge.configure(c,reader.instance,ck,peer_slot=0,stream=1)
   import releases
   raw=a.registry.read_bytes();c.request(10,raw[128:160]+releases.public_key(PUBLIC));slot,_=c.install(a.registry);reader.registry=struct.unpack_from('<Q',c.request(25,struct.pack('<Q',slot)),8)[0]
   federation.configure_native_verifier(c,reader.registry,configuration['public_key'],'consumer',allowed_rights=895,generation=configuration['generation']);forge.federation_configure(c,reader.instance,configuration['federation_id'],3)
  write();root=next(r for r in provider.roots()if r['head']==app['root']['head']);select(provider,root['name']);provider.ui.press(62)
  wait(lambda:provider.inspect()['offered_nodes']==len(app['rows']),'native32-object exact offer',180)
  result=fetch(provider,reader,app['doc']);passed('fresh independent personal guest fetches every exact32-object successor through MUXv2',transfer=result,peers=peers)
  report['result']='pass';a.state.write_text(json.dumps(report,indent=2)+'\n')
 except BaseException as error:
  report.update(result='fail',error=repr(error));a.state.write_text(json.dumps(report,indent=2)+'\n')
  for n in nodes:
   try:(n.path/'continuation-failure.ppm').write_bytes(n.ui.frame().ppm())
   except Exception:pass
  raise
 finally:
  for n in nodes:
   if n.ui:n.ui.close();n.ui=None

if __name__=='__main__':main()
