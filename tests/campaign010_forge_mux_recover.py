"""Recover the actual MUX provider after the observed ordinary import quota fix.

Only its own retained helper graph/catalog and typed role7 seal restore. Source
objects remain in their original running guest. Live bindings and both selected
bulk relationships are created afresh through normal public interfaces.
"""
import argparse,json,struct,sys,time,os,socket
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import capsule,federation,forge,identity,network,releases,server_store
from campaign010_forge_mux import MuxNode,archive,Client,PUBLIC,digest
from campaign010_forge_continue import attach,stop
from forge_journey import wait

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for field in ('state','image','server-forge','identity','registry'):p.add_argument('--'+field,type=Path,required=True)
 a=p.parse_args();base=a.state.parent;report=json.loads(a.state.read_text());source_image=report['live_actors'][1]['image'];oldprovider,source=[attach(r)for r in report['live_actors']];recovery=json.loads((base/'operator-recovery.json').read_text());configuration=recovery['public'];os.environ['LT_GUEST_IMAGE']=str(a.image.resolve());nodes=[];began=time.monotonic()
 def write():
  report['live_actors']=[dict(pid=n.pid if hasattr(n,'pid')else n.proc.pid,socket=str(n.sock),graphics=str(n.qmp),forge=n.instance,registry=n.registry,image=str(a.image.resolve())if n is provider else source_image)for n in nodes];a.state.write_text(json.dumps(report,indent=2)+'\n')
 try:
  stop(oldprovider);provider=MuxNode(base/'provider-recovered',base/'provider.img');nodes=[provider,source]
  provider.install(a.server_forge,PUBLIC)
  with provider.client()as c:
   server_store.call(c,230);g=server_store.call(c,231,provider.instance,2,1048576,bytes.fromhex(recovery['helper_graph_namespace']))[0][1]
   service=identity.start(c,a.identity,PUBLIC);raw=a.registry.read_bytes();c.request(10,raw[128:160]+releases.public_key(PUBLIC));slot,_=c.install(a.registry);provider.registry=struct.unpack_from('<Q',c.request(25,struct.pack('<Q',slot)),8)[0]
   catalog=server_store.call(c,231,provider.registry,1,1048576,bytes.fromhex(recovery['catalog_namespace']))[0][1]
   restored=federation.recover_native(c,provider.registry,Path(recovery['credential_path']).read_bytes(),recovery['namespace'],service['release'],releases.inspect(raw)['release_id'],store_grant=catalog)
   assert restored['public_key']==configuration['public_key']and restored['generation']>configuration['generation']and restored['recovered_catalog_records']>0
   for path in (ROOT/'build/campaign010-notes-continuation-1/project-notes-1.1.0-graph.json',ROOT/'build/campaign010-notes-fork-2/project-notes-fork-graph.json'):
    item=archive(path);federation.call(c,provider.registry,3,data=item['publication']+item['publisher'])
  configuration.update(generation=restored['generation']);(base/'alpha-public-verifier.json').write_text(json.dumps(configuration,indent=2)+'\n')
  # Source has no signer or private session owner: close only its completed
  # Forge/public-verifier instances and reopen their already admitted releases.
  with source.client()as c:
   c.request(26,struct.pack('<Q',source.instance));c.request(26,struct.pack('<Q',source.registry));network.call(c,14,slot=0)
   source.instance=struct.unpack_from('<Q',c.request(25,struct.pack('<Q',1)),8)[0];source.registry=struct.unpack_from('<Q',c.request(25,struct.pack('<Q',2)),8)[0]
  relation=base/'source-provider-recovered';relation.mkdir();key,pub=relation/'endpoint.pem',relation/'endpoint.pub';capsule.generate_key(key,pub);probe=socket.socket();probe.bind(('127.0.0.1',0));endpoint='127.0.0.1:'+str(probe.getsockname()[1]);probe.close();description=relation/'service.public';meta=network.create_description(key,digest('Campaign010 MUX source'),endpoint,'forge',description)
  ck,sk=relation/'client.credential',relation/'server.credential';network.provision(ck,sk,bytes.fromhex(meta['client_id']),bytes.fromhex(meta['server_id']),bytes.fromhex(meta['service_id']))
  with provider.client()as c:network.configure(c,sk,description,slot=0);network.call(c,13,slot=0);forge.configure(c,provider.instance,sk,'registry','portable',g,peer_slot=0,stream=1);forge.federation_configure(c,provider.instance,configuration['federation_id'],3)
  with source.client()as c:network.configure(c,ck,description,slot=0);network.call(c,13,slot=0);forge.configure(c,source.instance,ck,peer_slot=0,stream=1);federation.configure_native_verifier(c,source.registry,configuration['public_key'],'consumer',allowed_rights=895,generation=configuration['generation']);forge.federation_configure(c,source.instance,configuration['federation_id'],3)
  def ready():
   for n in nodes:
    with n.client()as c:
     if not network.status(c,slot=0)['endpoint_authenticated']:return False
   return True
  wait(ready,'fresh source/provider bulk relationship after typed server recovery',180)
  preview=provider.recover(bytes.fromhex(recovery['helper_graph_namespace']),'11ef977f7e39766f819f334a5449f3703c16df3de8108ca324133e700328b5e1')
  source.focus(source.instance);MuxNode.select(source,'project-notes-1.1.0')
  report['checks'].append(dict(check='normal provider restart recovers only approved native operator seal, accepted catalog and own retained helper graph',result='pass',recovery=restored,helper_preview=preview,seconds=round(time.monotonic()-began,3),refreshed_image_sha256=__import__('hashlib').sha256(a.image.read_bytes()).hexdigest(),old_live_bindings_restored=False));report.update(result='ready-selected32-after-native-recovery',phase='exact32-node source selected with fresh authorization');report.pop('error',None);write();print('PASS typed operator/catalog/helper recovery and fresh source relationship',flush=True)
 except BaseException as exc:
  report.update(result='fail-recovery',error=repr(exc));
  if len(nodes)==2 and all(hasattr(n,'registry')for n in nodes):write()
  else:a.state.write_text(json.dumps(report,indent=2)+'\n')
  raise
 finally:
  for n in [oldprovider,source,*nodes]:
   if n.ui:n.ui.close();n.ui=None

if __name__=='__main__':main()
