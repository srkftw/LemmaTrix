"""Authenticate a bounded bulk peer beside an existing live three-hop Feed route."""
import argparse,hashlib,json,socket,struct,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import capsule,forge,identity,network,live
from campaign010_forge_distribution import Client,digest
from campaign010_forge_coexistence import snapshot
from forge_journey import wait

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--coexistence',type=Path,required=True);p.add_argument('--provider-state',type=Path,required=True);a=p.parse_args();report=json.loads(a.coexistence.read_text());session=report['session'];provider=json.loads(a.provider_state.read_text())['live_actors'][0];base=a.coexistence.parent;path=base/'selected-bulk-peer';path.mkdir();started=time.monotonic()
 key,pub=path/'endpoint.pem',path/'endpoint.pub';capsule.generate_key(key,pub);probe=socket.socket();probe.bind(('127.0.0.1',0));endpoint='127.0.0.1:'+str(probe.getsockname()[1]);probe.close();description=path/'service.public';meta=network.create_description(key,digest('Campaign010 same live routed Feed user'),endpoint,'forge',description)
 ck,sk=path/'client.credential',path/'server.credential';network.provision(ck,sk,bytes.fromhex(meta['client_id']),bytes.fromhex(meta['server_id']),bytes.fromhex(meta['service_id']))
 def write():a.coexistence.write_text(json.dumps(report,indent=2)+'\n')
 try:
  with Client(Path(session['socket']),timeout=300)as c:before=snapshot(c,session)
  with Client(Path(provider['socket']),timeout=300)as c:network.configure(c,sk,description,slot=2);network.call(c,13,slot=2)
  with Client(Path(session['socket']),timeout=300)as c:network.configure(c,ck,description,slot=0);network.call(c,13,slot=0);forge.configure(c,report['forge'],ck,peer_slot=0,stream=1)
  def ready():
   states=[]
   for who,slot in ((provider,2),(session,0)):
    with Client(Path(who['socket']),timeout=30)as c:states.append(network.status(c,slot=slot))
   return states if all(s['endpoint_authenticated']for s in states)else None
  actual=wait(ready,'actual explicit bulk peer authenticates alongside live native circuit',180)
  with Client(Path(session['socket']),timeout=300)as c:after=snapshot(c,session)
  assert before['route']==after['route']and before['route'][2]==3,'bulk open reset native circuit'
  assert before['profiles_body_hex']==after['profiles_body_hex'],'bulk open changed terminal relationship or lifetime totals'
  assert before['feed_ui']==after['feed_ui']and after['feed_ui'][5]in(6,7),'bulk open reset accepted Feed operation'
  report.update(result='pass-peer-preserves-routed-feed',bulk_peer=dict(provider=provider,provider_slot=2,client_slot=0,client_credentials=str(ck.resolve()),server_credentials=str(sk.resolve()),description=str(description.resolve()),stream=1,states=actual,elapsed_seconds=round(time.monotonic()-started,3)),before_peer=before,after_peer=after);write();print('PASS native Forge bulk peer coexists with unchanged live route, Feed terminal allowance and accepted operation',flush=True)
 except BaseException as error:report.update(result='fail-peer',error=repr(error));write();raise

if __name__=='__main__':main()
