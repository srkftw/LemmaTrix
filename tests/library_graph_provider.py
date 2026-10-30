"""Provision one explicit volatile public Game graph provider for native O/I.

Only this publisher/provider receives Project payload bytes. Already signed role
packages are reused; the Lean Registry admits the actual selected graph and the
Lean LibraryPeer serves only its selected scoped immutable head. The helper
leaves its identified provider running for library_graph_native.py.
"""
import argparse,base64,hashlib,json,os,socket,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import capsule,federation,library_peer,network,nodes,projects,releases
from library_journey import Node


def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--image',type=Path,required=True);p.add_argument('--packages',type=Path,required=True)
 p.add_argument('--archive',type=Path,default=ROOT/'build/campaign005/game-secure-editions/game1-closure.json')
 p.add_argument('--game',type=Path,default=ROOT/'build/campaign005/game-secure-editions/game1/crate-workshop.ltrel')
 p.add_argument('--public',type=Path,default=ROOT/'build/campaign005/publisher.pub');p.add_argument('--output',type=Path,required=True)
 a=p.parse_args();out=a.output.resolve();out.mkdir(exist_ok=False);image=out/'platform.bin';image.write_bytes(a.image.read_bytes())
 node=Node('provider',out,image);success=False;roles={}
 try:
  with node.client()as c:
   for name,rights in [('library-registry',2175),('library-peer',1025)]:
    path=a.packages/(name+'.ltrel');raw=path.read_bytes();info=releases.inspect(raw,releases.public_modulus(a.public))
    if info['rights']!=rights:raise ValueError('selected provider role capability mismatch')
    who=nodes.start_package(c,nodes.approved_package(path,a.public,info['release_id'],rights),raw)
    roles[name]=dict(instance=who,release=info['release_id'],executable_sha256=info['executable_sha256'])
   registry,peer=roles['library-registry']['instance'],roles['library-peer']['instance']
   fedkey,fedpub=out/'federation.pem',out/'federation.pub';capsule.generate_key(fedkey,fedpub)
   federation.configure(c,registry,fedpub,'consumer',allowed_rights=8191)
   archive=json.loads(a.archive.read_text());records=[dict(r,payload=base64.b64decode(r['payload']))for r in archive['nodes']]
   selected=projects.import_records(c,archive['selected'],records)[0]['cap'];game=releases.inspect(a.game.read_bytes())
   federation.call(c,registry,3,data=bytes.fromhex(game['project_id'])+releases.public_modulus(a.public))
   admitted=c.objects(27,selected,registry,25)[0][1];federation.call(c,registry,2,h=admitted)
   decision=federation.sign_once(c,registry,fedkey,'consumer',8191)
   if decision['listing']!=5:raise ValueError('Game did not receive actual consumer and executable admission')
   _,admission=federation.call(c,registry,6);head=admission[320:352]
   if head.hex()!=archive['selected'][0]['head']:raise ValueError('admission selected another Project')
   read=c.objects(27,selected,peer,1)[0][1]
   identity=hashlib.sha256(os.urandom(32)).digest();key,pub=out/'network.pem',out/'network.pub';capsule.generate_key(key,pub)
   probe=socket.socket();probe.bind(('127.0.0.1',0));port=probe.getsockname()[1];probe.close()
   description=out/'game.service';details=network.create_description(key,identity,'127.0.0.1:'+str(port),'library-seed',description)
   network.provision(out/'reader.credential',out/'provider.credential',identity,bytes.fromhex(details['server_id']),bytes.fromhex(details['service_id']))
   network.configure(c,out/'provider.credential',description,slot=1);network.call(c,13,slot=1)
   library_peer.call(c,peer,400,1,3,int.from_bytes(head[:8],'little')|1,read,16777216,100000,identity+bytes.fromhex(details['service_id'])+head)
  report=dict(result='ready',image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),packages=roles,game_release=game['release_id'],head=head.hex(),nodes=len(records),payload_bytes=sum(len(r['payload'])for r in records),process_id=node.proc.pid,public_project_volatile=True,recipient_payload_provisioned=False)
  (out/'provider.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2));success=True
 finally:
  if not success:node.stop()


if __name__=='__main__':main()
