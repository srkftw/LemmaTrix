"""Fetch the real source-only helper beside an existing routed Feed owner."""
import argparse,json,struct,sys,time,hashlib,socket
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import capsule,federation,forge,identity,network,server_store,releases
from campaign010_forge_continue import attach,fetch
from campaign010_forge_distribution import Client,digest
from campaign010_forge_mux import archive
from campaign010_forge_coexistence import snapshot
from campaign010_forge_final_provider import select
from graphical_devices import DeviceInput
from forge_journey import wait

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for f in('provider','personal','helper','configuration','descriptor','output'):p.add_argument('--'+f,type=Path,required=True)
 a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False);prior=json.loads(a.provider.read_text());pr=prior['actors'][0];cr=json.loads(a.personal.read_text());s=cr['session'];provider=attach(pr);personal=attach(dict(pid=s['pid'],socket=s['socket'],graphics=s['graphics'],forge=cr['forge'],registry=s['registry']));nodes=[provider,personal];item=archive(a.helper);config=json.loads(a.configuration.read_text());desc=a.descriptor.read_bytes();began=time.monotonic();r=dict(schema=1,result='running',checks=[],scope=__doc__,provider_image='fc991e1237ac5453331e87e6ed370293bbc60dd032d389c5b1a17151e8b7cd96',personal_image='b743de7abac5c508660a662041ef97ef3da7677bd7c33d9903123e9d8e5459ad')
 def write():r.update(elapsed_seconds=round(time.monotonic()-began,3),actors=[dict(pid=n.pid,socket=str(n.sock),graphics=str(n.qmp),forge=n.instance,registry=n.registry)for n in nodes]);(a.output/'execution.json').write_text(json.dumps(r,indent=2)+'\n')
 def restart(c,n,release):
  c.request(26,struct.pack('<Q',n))
  for index in range(16):
   try:h=c.request(13,struct.pack('<Q',index))
   except ValueError:continue
   if h[160:192].hex()==release:return struct.unpack_from('<Q',c.request(25,struct.pack('<Q',index+1)),8)[0]
  raise AssertionError('existing admitted service missing')
 try:
  with personal.client()as c:before=snapshot(c,s);old=c.request(29,releases.project('native-forge'));personal.instance=restart(c,personal.instance,old[160:192].hex());network.call(c,14,slot=0)
  with provider.client()as c:old=c.request(29,releases.project('native-forge'));provider.instance=restart(c,provider.instance,old[160:192].hex())
  relation=a.output/'selected-peer';relation.mkdir();key,pub=relation/'endpoint.pem',relation/'endpoint.pub';capsule.generate_key(key,pub);probe=socket.socket();probe.bind(('127.0.0.1',0));endpoint='127.0.0.1:'+str(probe.getsockname()[1]);probe.close();description=relation/'service.public';meta=network.create_description(key,digest('Campaign010 routed owner helper selection'),endpoint,'forge',description);ck,sk=relation/'client.credential',relation/'server.credential';network.provision(ck,sk,bytes.fromhex(meta['client_id']),bytes.fromhex(meta['server_id']),bytes.fromhex(meta['service_id']))
  with provider.client()as c:network.configure(c,sk,description,slot=1);network.call(c,13,slot=1)
  with personal.client()as c:network.configure(c,ck,description,slot=0);network.call(c,13,slot=0)
  def auth():
   for n,slot in((provider,1),(personal,0)):
    with n.client()as c:
     if not network.status(c,slot=slot)['endpoint_authenticated']:return False
   return True
  wait(auth,'explicit helper peer beside existing mode1 profile',180)
  with provider.client()as c:g=server_store.call(c,231,provider.instance,2,1048576,digest('Campaign010 MUX helper graph'))[0][1];forge.configure(c,provider.instance,sk,'seed','portable',g,peer_slot=1,stream=1);federation.call(c,provider.registry,11,data=desc+desc[320:352]);forge.federation_configure(c,provider.instance,config['federation_id'],3)
  with personal.client()as c:
   # Replace only the explicitly selected public-verifier incarnation. The
   # original accepted card retains its immutable Alpha1 decision separately.
   release=Path('build/campaign010-distribution-services/distribution-registry.ltrel').read_bytes()[160:192].hex();personal.registry=restart(c,personal.registry,release);federation.configure_native_verifier(c,personal.registry,config['public_key'],'consumer',allowed_rights=895,generation=config['generation']);federation.call(c,personal.registry,11,data=desc+desc[320:352]);forge.configure(c,personal.instance,ck,peer_slot=0,stream=1);forge.federation_configure(c,personal.instance,config['federation_id'],3)
  write();provider.focus(provider.instance);provider.ui.press(67);time.sleep(.5)
  shown=wait(lambda:(q if(q:=provider.archive())['phase']==4 else None),'own selected helper store inspection',180);assert shown['head']==item['root']['head'];provider.ui.press(67);wait(lambda:provider.archive()['phase']==8,'actual helper store recovery',180);select(provider,next(q['name']for q in provider.roots()if q['head']==item['root']['head']));provider.ui.press(62);wait(lambda:provider.inspect()['offered_nodes']==6,'actual source-only6 offer',90)
  transfer=fetch(provider,personal,item['doc'])
  with personal.client()as c:after=snapshot(c,s)
  assert before['route']==after['route']and before['profiles_body_hex']==after['profiles_body_hex']and before['feed_ui']==after['feed_ui'],'helper transfer changed routed owner/outbox/allowances'
  assert transfer['decision']['classification']==1
  personal.focus(personal.instance);personal.ui.press(64)
  wait(lambda:personal.inspect()['status']==2,'source-only helper refuses native application installation',30)
  with personal.client()as c:
   try:c.request(29,item['publication'])
   except ValueError:pass
   else:raise AssertionError('source-only helper became an executable application')
  r['source_only_execution_refused']=True
  r.update(result='pass',checks=[dict(check='actual separately published6-node source-only helper fetched while exact routedFeedowner/profile/outbox remain unchanged',result='pass',before=before,after=after,transfer=transfer,execution_authority=False)]);write();print('PASS actual helper6 fetch beside unchanged routedFeed owner',flush=True)
 except BaseException as e:r.update(result='fail',error=repr(e));write();raise
 finally:
  for n in nodes:
   if n.ui:n.ui.close();n.ui=None
if __name__=='__main__':main()
