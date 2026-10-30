"""A fresh headless Library acquires actual content from an existing seed guest.

The source is a running library_journey fixture. Repeating its authorized
reserve operation only retrieves its queryable idempotent local result; this
script never appends payload bytes into the replica. All acquisition crosses
Native LibraryPeer + Network-v2 and native Content validation.
"""
import argparse,contextlib,hashlib,json,os,socket,struct,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import capsule,content,federation,library_peer,live,network,nodes,releases
from library_journey import Node,appcall,wait

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--source',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--image',type=Path,default=ROOT/'build/live/guest.bin');parser.add_argument('--acquirer',type=Path,default=ROOT/'build/live/apps/library-acquirer.bin');parser.add_argument('--registry',type=Path,default=ROOT/'build/live/apps/registry-consumer-check.bin');parser.add_argument('--peer',type=Path,default=ROOT/'build/live/apps/library-peer.bin');parser.add_argument('--key',type=Path,default=ROOT/'build/campaign005/publisher.pem');parser.add_argument('--public',type=Path,default=ROOT/'build/campaign005/publisher.pub');parser.add_argument('--seconds',type=int,default=6);parser.add_argument('--timeout',type=int,default=2400);parser.add_argument('--keep-running',action='store_true',help='preserve the owned replica for diagnosis/retry, including after failure')
 args=parser.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False);source=args.source.resolve();image=out/'platform.bin';image.write_bytes(args.image.read_bytes());replica=None
 def package(binary,name,rights):
  raw,manifest=releases.make(binary,name,'1.0.0',rights,args.key,profile=2,license='NOASSERTION');path=out/(name+'.ltrel');path.write_bytes(raw);return path,releases.inspect(raw)
 def install(node,binary,name,rights):
  path,info=package(binary,name,rights);config=nodes.approved_package(path,args.public,info['release_id'],rights)
  with node.client() as c:return nodes.start_package(c,config,path.read_bytes()),info['release_id']
 @contextlib.contextmanager
 def connect_source(name):
  c=live.Client(source/name/'portal.sock',timeout=600)
  try:yield c
  finally:c.close()
 def find_peer(c):
  rows=c.request(2);matches=[struct.unpack_from('<4Q',rows,i) for i in range(7*32,len(rows),32) if struct.unpack_from('<Q',rows,i+16)[0]==1025 and 0<struct.unpack_from('<Q',rows,i+8)[0]<5]
  if len(matches)!=1:raise RuntimeError('expected one explicitly started LibraryPeer role')
  return matches[0][0]
 try:
  replica=Node('replica',out,image)
  verifier,verifier_release=install(replica,args.registry,'replica-verifier',2175)
  acquirer,acquirer_release=install(replica,args.acquirer,'replica-acquirer',1151)
  peer,peer_release=install(replica,args.peer,'replica-content-peer',1025)
  (out/'instances.json').write_text(json.dumps(dict(verifier=verifier,acquirer=acquirer,peer=peer),indent=2)+'\n')
  fedpublic=source/'federation.pub';fed_id=hashlib.sha256(releases.public_modulus(fedpublic)).digest();identity=hashlib.sha256(os.getrandom(32)).digest()
  with replica.client() as c:federation.configure(c,verifier,fedpublic,'consumer',allowed_rights=8191)
  # Both producer relationships occupy independent source guest contexts1.
  relationships=[]
  for slot,name,kind,key in [(0,'registry','library-registry',source/'network-role0.pem'),(1,'seed1','library-seed',source/'network-role1.pem')]:
   probe=socket.socket();probe.bind(('127.0.0.1',0));port=probe.getsockname()[1];probe.close();description=out/(name+'.service')
   detail=network.create_description(key,identity,f'127.0.0.1:{port}',kind,description);creds=[out/(name+'-client.credential'),out/(name+'-server.credential')]
   network.provision(*creds,identity,bytes.fromhex(detail['server_id']),bytes.fromhex(detail['service_id']))
   with connect_source(name) as c:
    remote=find_peer(c);network.configure(c,creds[1],description,slot=1);wait(lambda:network.call(c,13,slot=1,allow_error=True)[0][0]==0)
   with replica.client() as c:
    network.configure(c,creds[0],description,slot=slot);wait(lambda:network.call(c,13,slot=slot,allow_error=True)[0][0]==0)
   relationships.append((remote,detail))
  with replica.client() as c:wait(lambda:all(network.status(c,slot)['endpoint_authenticated'] for slot in (0,1)),300,'replication authentication')
  stereo=content.original_wave(args.seconds,2);manifest,_,_=content.commitments(stereo);manifest_id=hashlib.sha256(manifest).digest();stream=int.from_bytes(manifest_id[:8],'little')|1
  with connect_source('registry') as c:
   remote,detail=relationships[0];library_peer.call(c,remote,400,1,1,1,0,16777216,100000,identity+bytes.fromhex(detail['service_id'])+fed_id)
  with connect_source('seed1') as c:
   remote,detail=relationships[1];provider=bytes.fromhex(detail['server_id'])
   # Exact idempotent result query for the source operator's approved operation.
   existing,_,_,_=content.reserve(c,stereo,1001,provider,fed_id)
   wait(lambda:content.api(c).objects(306,existing)[0][2]==2,300,'source selected root publication')
   shared=content.api(c).objects(308,existing,remote)[0][1]
   library_peer.call(c,remote,400,1,2,stream,shared,16777216,100000,identity+bytes.fromhex(detail['service_id'])+manifest_id)
  with replica.client() as c:
   c.request(184,struct.pack('<Q',acquirer));q,_=appcall(c,acquirer,706,0,6029312,data=fed_id+content.COLLECTION)
   if q[0]:raise RuntimeError(('explicit replication policy rejected',q))
  started=time.monotonic()
  def state():
   with replica.client() as c:return appcall(c,acquirer,704,0,0,128)[1]
  def done():
   data=state();phase=struct.unpack_from('<Q',data)[0]
   (out/'latest-job.json').write_text(json.dumps(dict(words=list(struct.unpack('<16Q',data)),elapsed_seconds=time.monotonic()-started),indent=2)+'\n')
   if phase in (12,13,14):raise RuntimeError(('replication terminal failure',list(struct.unpack('<16Q',data))))
   return phase==10
  wait(done,args.timeout,'actual guest-to-guest headless replication')
  with replica.client() as c:
   # Catalog order is original mono then preferred stereo. The read handle is
   # newly shared to the operator solely for exact-byte evidence and serving.
   q,_=appcall(c,acquirer,705,1)
   if q[0]:raise RuntimeError(('replica read scope denied',q))
   copied=q[1];actual=hashlib.sha256()
   for offset in range(0,len(stereo),512):actual.update(content.api(c).objects(307,copied,offset,min(512,len(stereo)-offset))[1])
   assert actual.digest()==hashlib.sha256(stereo).digest(),'replica bytes differ'
   serving=content.api(c).objects(308,copied,peer)[0][1]
  # The new guest now serves its acquired chunks to a fresh authenticated
  # client relationship in personal context3; Library's contexts0..2 remain.
  private=out/'replica-network.pem';public=out/'replica-network.pub';capsule.generate_key(private,public)
  probe=socket.socket();probe.bind(('127.0.0.1',0));port=probe.getsockname()[1];probe.close()
  reader_identity=hashlib.sha256(os.getrandom(32)).digest();description=out/'replica-provider.service'
  detail=network.create_description(private,reader_identity,f'127.0.0.1:{port}','library-seed',description)
  reader_creds=out/'reader.credential';server_creds=out/'replica-server.credential';network.provision(reader_creds,server_creds,reader_identity,bytes.fromhex(detail['server_id']),bytes.fromhex(detail['service_id']))
  with replica.client() as c:
   network.configure(c,server_creds,description,slot=2);wait(lambda:network.call(c,13,slot=2,allow_error=True)[0][0]==0)
  with connect_source('personal') as reader:
   network.configure(reader,reader_creds,description,slot=3);wait(lambda:network.call(reader,13,slot=3,allow_error=True)[0][0]==0)
   wait(lambda:network.status(reader,3)['endpoint_authenticated'],300,'replica serving authentication')
   with replica.client() as c:library_peer.call(c,peer,400,2,2,stream,serving,8192,100000,reader_identity+bytes.fromhex(detail['service_id'])+manifest_id)
   grant=network.call(reader,2,a=3,b=3,c=8192,d=65536,e=100000,data=bytes.fromhex(detail['server_id'])+bytes.fromhex(detail['service_id'])+manifest_id+struct.pack('<QQ',2,stream),slot=3)[0][1]
   def read_remote(op,h=0,a=0):
    rid=7000+op;payload=struct.pack('<8Q',0x31524545504c544c,1,op,h,a,0,0,0)
    job=network.call(reader,3,grant,a=2,b=rid,data=payload,slot=3)[0][1]
    wait(lambda:network.call(reader,4,job,slot=3)[0][2]==3)
    def receive():
     f,data=network.call(reader,6,grant,slot=3,allow_error=True)
     if f[0]==6:return None
     assert f[0]==0 and f[3]==rid and len(data)>=64
     q=struct.unpack_from('<8Q',data);assert q[3]==0 and q[4]==rid,q
     return data[64:]
    return wait(receive)
   assert read_remote(3)==manifest,'replica served a substituted manifest'
   assert read_remote(4,0)==content.commitments(stereo)[2][0],'replica served an unauthenticated chunk path'
   assert read_remote(5,0,512)==stereo[:512],'replica failed to serve its acquired bytes'
   network.call(reader,14,slot=3)
  result=dict(image=hashlib.sha256(image.read_bytes()).hexdigest(),acquirer_release=acquirer_release,verifier_release=verifier_release,provider_release=peer_release,source='separately running seed1 native Content service',replica_guest='new independent guest',host_payload_ingestion=False,payload_bytes=len(stereo),chunks=(len(stereo)+4095)//4096,manifest_sha256=manifest_id.hex(),actual_sha256=actual.hexdigest(),elapsed_seconds=time.monotonic()-started,served_to_fresh_authenticated_client=True,served_manifest_proof_and_512_bytes=True,retention='volatile; no server backing persistence claimed')
  (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
 finally:
  if replica and not args.keep_running:replica.stop()
  elif replica:print('Replica intentionally preserved at '+str(replica.socket),flush=True)
if __name__=='__main__':main()
