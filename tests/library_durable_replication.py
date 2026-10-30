"""Native acquisition into two distinct retained, restartable seed stores.

Only the already published source has payloads at setup. Each recipient acquires
through Library/Noise, commits with ServerContent, and restarts through the normal
library-node operator path. Backing files are never copied between nodes.
"""
import argparse,contextlib,hashlib,json,os,signal,socket,struct,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import capsule,content,federation,library_node,library_peer,live,network,nodes,releases,server_content,server_store
from library_journey import Node,appcall,wait

MAGIC=0x31524545504c544c
class Existing:
 def __init__(self,path):self.base=Path(path);self.socket=self.base/'portal.sock'
 @contextlib.contextmanager
 def client(self):
  c=live.Client(self.socket,timeout=600)
  try:yield c
  finally:c.close()
 def stop(self):
  try:
   with self.client() as c:c.request(70)
  except EOFError:pass
  wait(lambda:not self.socket.exists(),60,'normal existing node stop')

def role(node,rights):
 with node.client() as c:raw=c.request(2)
 return next(struct.unpack_from('<Q',raw,i)[0] for i in range(7*32,len(raw),32) if struct.unpack_from('<Q',raw,i+16)[0]==rights and 0<struct.unpack_from('<Q',raw,i+8)[0]<5)
def endpoint():
 s=socket.socket();s.bind(('127.0.0.1',0));n=s.getsockname()[1];s.close();return f'127.0.0.1:{n}'
def relation(out,name,key,identity,kind):
 desc=out/(name+'.service');detail=network.create_description(key,identity,endpoint(),kind,desc);client=out/(name+'-client.credential');server=out/(name+'-server.credential');network.provision(client,server,identity,bytes.fromhex(detail['server_id']),bytes.fromhex(detail['service_id']));return dict(description=desc,client=client,server=server,detail=detail)
def existing_relation(out,name):
 desc=out/(name+'.service');_,d,_=network.load_description(desc)
 return dict(description=desc,client=out/(name+'-client.credential'),server=out/(name+'-server.credential'),detail=dict(client_id=d[64:96].hex(),server_id=d[96:128].hex(),service_id=hashlib.sha256(d).hexdigest()))
def provision(node,credential,description,slot):
 with node.client() as c:
  network.configure(c,credential,description,slot=slot);wait(lambda:network.call(c,13,slot=slot,allow_error=True)[0][0]==0,300,'open selected relationship')
def source_scope(node,peer,slot,rel,root,selected=0):
 _,d,_=network.load_description(rel['description'])
 with node.client() as c:
  if selected: selected=content.api(c).objects(308,selected,peer)[0][1]
  library_peer.call(c,peer,402,slot)
  return library_peer.call(c,peer,400,slot,2 if selected else 1, int.from_bytes(root[:8],'little')|1 if selected else 1,selected,16777216,100000,d[64:96]+hashlib.sha256(d).digest()+root)
def wait_auth(node,slots):
 with node.client() as c:wait(lambda:all(network.status(c,s)['endpoint_authenticated'] for s in slots),600,'authenticated selected peers')
def install(node,path,public):
 raw=path.read_bytes();info=releases.inspect(raw)
 with node.client() as c:return nodes.start_package(c,nodes.approved_package(path,public,info['release_id'],info['rights']),raw)
def startup_json(path):
 try:
  raw=path.read_text();at=raw.index('{');value,_=json.JSONDecoder().raw_decode(raw[at:]);return value if value.get('recovered') else None
 except (FileNotFoundError,ValueError,json.JSONDecodeError):return None

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);p.add_argument('--catalog',type=Path,required=True);p.add_argument('--image',type=Path,default=ROOT/'build/live/guest.bin');p.add_argument('--output',type=Path,required=True);p.add_argument('--public',type=Path,default=ROOT/'build/campaign005/publisher.pub');p.add_argument('--catalog-pid',type=int,required=True);p.add_argument('--resume-index',type=int,choices=(0,1));p.add_argument('--recover-index',type=int,choices=(0,1));p.add_argument('--serving-package',type=Path);a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=a.resume_index is not None or a.recover_index is not None);source=a.source.resolve();catalog_path=a.catalog.resolve();image=out/'platform.bin';image.write_bytes(a.image.read_bytes()) if a.resume_index is None and a.recover_index is None else None;source_node=Existing(source/'replica');catalog=Existing(catalog_path/'registry');source_instances=json.loads((source/'instances.json').read_text());srcpeer=source_instances['peer'];srcacq=source_instances['acquirer'];catpeer=None
 fedpublic=catalog_path/'federation.pub';fid=hashlib.sha256(releases.public_modulus(fedpublic)).digest();raw=content.original_wave(6,2);manifest,_,proofs=content.commitments(raw);mid=hashlib.sha256(manifest).digest();stream=int.from_bytes(mid[:8],'little')|1;report=json.loads((out/'result.json').read_text())['checks'] if (a.resume_index is not None or a.recover_index is not None) and (out/'result.json').exists() else [];initial=[];recovered=[]
 packages=dict(verifier=source/'replica-verifier.ltrel',acquirer=source/'replica-acquirer.ltrel',peer=source/'replica-content-peer.ltrel')
 serving_package=(a.serving_package or packages['peer']).resolve()
 def record(label,**facts):
  report.append(dict(check=label,result='passed',**facts));(out/'result.json').write_text(json.dumps(dict(image=hashlib.sha256(image.read_bytes()).hexdigest(),source_image=json.loads((source/'result.json').read_text())['image'],manifest_sha256=mid.hex(),payload_bytes=len(raw),packages={name:releases.inspect(path.read_bytes())['release_id'] for name,path in packages.items()},serving_release=releases.inspect(serving_package.read_bytes())['release_id'],checks=report),indent=2)+'\n');print('PASS',label,facts,flush=True)
 def instances_file(name,**values):(out/(name+'-instances.json')).write_text(json.dumps(values,indent=2)+'\n')
 # Three distinct logical clients: two acquirers and a fresh read-only verifier.
 if a.resume_index is None and a.recover_index is None:
  identities=[hashlib.sha256(os.getrandom(32)).digest() for _ in range(3)]
  # Serve current verified source root with fresh relationship, no re-ingestion.
  with source_node.client() as c:source_read=appcall(c,srcacq,705,1)[0][1]
  upstream=relation(out,'upstream',source/'replica-network.pem',identities[0],'library-seed')
  provision(source_node,upstream['server'],upstream['description'],3);source_scope(source_node,srcpeer,3,upstream,mid,source_read)
  serve=[]
  for i in range(2):
   key=out/f'seed{i+1}.pem';public=out/f'seed{i+1}.pub';capsule.generate_key(key,public)
   rels=[relation(out,f'seed{i+1}-reader',key,identities[2],'library-seed')]
   if i==0:rels.insert(0,relation(out,'seed1-next-seed',key,identities[1],'library-seed'))
   serve.append(rels)
 else:
  upstream=existing_relation(out,'upstream')
  serve=[[existing_relation(out,'seed1-next-seed'),existing_relation(out,'seed1-reader')],[existing_relation(out,'seed2-reader')]]
  identities=[network.load_credentials(upstream['client'])[1][:32],network.load_credentials(serve[0][0]['client'])[1][:32],network.load_credentials(serve[0][1]['client'])[1][:32]]
 for index in range((a.recover_index if a.recover_index is not None else a.resume_index) or 0,2):
  name='seed'+str(index+1);store=out/(name+'.store')
  namespace=hashlib.sha256(('explicit campaign005 retained '+name).encode()).digest()
  if a.recover_index==index:
   assert store.exists() and not (out/name/'portal.sock').exists()
   assert any(x['check']==name+' purpose2 native retention committed its own backing' for x in report)
   print(name,'RECOVER PREVIOUS COMPLETE COMMIT; no payload re-import',flush=True)
  else:
   resuming=a.resume_index==index
   if resuming:
    node=Existing(out/name);instances=json.loads((out/(name+'-instances.json')).read_text());verifier=instances['verifier'];acquirer=instances['acquirer'];peer=instances['peer'];print(name,'RESUME CURRENT NATIVE JOB; no payload re-import',flush=True)
   else:
    server_store.provision(store,True);node=Node(name,out,image,server_store=store)
    verifier=install(node,packages['verifier'],a.public);acquirer=install(node,packages['acquirer'],a.public);peer=install(node,packages['peer'],a.public);instances_file(name,verifier=verifier,acquirer=acquirer,peer=peer)
    with node.client() as c:federation.configure(c,verifier,fedpublic,'consumer',allowed_rights=8191)
   initial.append(node)
   if not resuming:
    # Resume only the metadata node for the bounded initial signed catalog.
    os.kill(a.catalog_pid,signal.SIGCONT);catpeer=role(catalog,1025)
    catrel=relation(out,name+'-catalog',catalog_path/'network-role0.pem',identities[index],'library-registry');provision(catalog,catrel['server'],catrel['description'],2);provision(node,catrel['client'],catrel['description'],0);wait_auth(node,[0]);source_scope(catalog,catpeer,2,catrel,fid)
    srcrel=upstream if index==0 else serve[0][0]
    provision(node,srcrel['client'],srcrel['description'],1);wait_auth(node,[0,1])
    if index==0:
     # Reuse the root only after the new authenticated relationship is current.
     # Prior completed test scopes have no reason to retain pending work.
     with source_node.client() as c:
      for slot in range(4):library_peer.call(c,srcpeer,402,slot)
      source_read=appcall(c,srcacq,705,1)[0][1]
     scope=source_scope(source_node,srcpeer,3,upstream,mid,source_read)[0][1]
     with source_node.client() as c:wait(lambda:library_peer.call(c,srcpeer,401,scope)[0][2]==1,300,'fresh source read authority ready before acquisition')
    with node.client() as c:
     c.request(184,struct.pack('<Q',acquirer));appcall(c,acquirer,706,0,6029312,data=fid+content.COLLECTION)
   started=time.monotonic();last=-1
   while True:
    with node.client() as c:f,j=appcall(c,acquirer,704,0,0,128)
    q=list(struct.unpack('<16Q',j));(out/(name+'-job.json')).write_text(json.dumps(dict(words=q,elapsed_seconds=time.monotonic()-started),indent=2)+'\n')
    if q[7]//65536!=last:last=q[7]//65536;print(name,'ACQUIRE',q[0],q[7],flush=True)
    if q[0]==10:break
    if q[0] in (12,13,14):raise RuntimeError((name,'acquisition',q))
    if time.monotonic()-started>2400:raise TimeoutError(name+' acquisition remains inspectable')
    time.sleep(.15)
   record(name+' native headless Library acquired and validated selected stereo edition',bytes=q[7],chunks=q[4],seconds_in_current_observation=time.monotonic()-started,elapsed_since_role_setup_seconds=time.time()-(out/(name+'-instances.json')).stat().st_mtime,resumed_observation=resuming,source='verified volatile replica4' if index==0 else 'restarted retained seed1',host_payload_ingestion=False)
   os.kill(a.catalog_pid,signal.SIGSTOP)
   namespace=hashlib.sha256(('explicit campaign005 retained '+name).encode()).digest()
   with node.client() as c:
    selected=appcall(c,acquirer,705,1)[0][1];owner=struct.unpack_from('<Q',c.request(2),32)[0];grant=server_content.permit(c,owner,namespace,mid,len(raw),0);retained=server_content.retain(c,grant,selected,7000+index);fields,stored=server_content.call(c,255,grant);assert stored==manifest and fields[3]==len(raw);server_content.call(c,256,grant)
   record(name+' purpose2 native retention committed its own backing',backing=str(store),namespace=namespace.hex(),generation=retained['generation'],bytes=retained['bytes'],personal_vault=False,backing_copied=False)
   node.stop();initial.remove(node)
  config=dict(schema=1,role='library-seed',**nodes.approved_package(serving_package,a.public,releases.inspect(serving_package.read_bytes())['release_id'],1025),server_store=str(store),archives=[library_node.archive(0,namespace.hex(),mid.hex(),len(raw))],relationships=[library_node.relationship(i,rel['server'],rel['description'],16777216,100000) for i,rel in enumerate(serve[index])],storage_policy='explicit purpose2 selected original content; intentional operator plaintext',service_policy='zero-price direct encrypted bulk',restored_authority='none; fresh grants')
  cfg=out/(name+'.json');library_node.write_config(cfg,config);portal=out/(name+'-recovered.sock');logpath=out/(name+'-recovered.log');log=logpath.open('wb');process=subprocess.Popen([str(ROOT/'lt'),'library-node','run',str(cfg),'--socket',str(portal),'--image',str(image)],cwd=ROOT,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,start_new_session=True);recovered.append((process,portal,log));info=wait(lambda:startup_json(logpath),900,name+' normal library-node recovery');assert info['recovered'][0]['bytes']==len(raw);record(name+' normal library-node restart recovered selected content under fresh authority',instance=info['instance'],image=info['image_sha256'],generation=info['recovered'][0]['generation'],bytes=info['recovered'][0]['bytes'],old_handles_reused=False)
 # Publisher's seeding and acquisition packages stop before either retained
 # server is read again. Original source guests remain quiesced.
 with source_node.client() as c:
  c.request(26,struct.pack('<Q',srcpeer));c.request(26,struct.pack('<Q',srcacq))
  for slot in range(4):network.call(c,14,slot=slot,allow_error=True)
 record('original volatile publisher packages stopped before retained reads',publisher_instances=[srcpeer,srcacq])
 for index in range(2):
  rel=serve[index][-1];provision(source_node,rel['client'],rel['description'],index);wait_auth(source_node,[index]);_,d,_=network.load_description(rel['description'])
  with source_node.client() as c:
   g=network.call(c,2,a=3,b=3,c=16384,d=65536,e=100000,data=d[96:128]+hashlib.sha256(d).digest()+mid+struct.pack('<QQ',2,stream),slot=index)[0][1];counter=0
   def request(op,h=0,a=0):
    nonlocal counter
    counter+=1;rid=9000+counter;payload=struct.pack('<8Q',MAGIC,1,op,h,a,0,0,0);job=network.call(c,3,g,a=2,b=rid,data=payload,slot=index)[0][1];wait(lambda:network.call(c,4,job,slot=index)[0][2]==3)
    def got():
     f,b=network.call(c,6,g,slot=index,allow_error=True)
     if f[0]==6:return None
     assert f[0]==0 and f[3]==rid and len(b)>=64;q=struct.unpack_from('<8Q',b);assert q[3]==0 and q[4]==rid;return b[64:]
    return wait(got,300,'retained seed response')
   assert request(3)==manifest;assert request(4,0)==proofs[0];assert request(4,len(proofs)-1)==proofs[-1]
   for offset in (0,4096,len(raw)-512):assert request(5,offset,512)==raw[offset:offset+512]
   network.call(c,14,slot=index)
  record('seed'+str(index+1)+' served its own recovered manifest, two authentic proofs and exact remote ranges after publisher shutdown',offsets=[0,4096,len(raw)-512],fresh_session=True,backing=str(out/('seed'+str(index+1)+'.store')))
 print('DURABLE REPLICATION COMPLETE; recovered seeds intentionally remain running',flush=True)
if __name__=='__main__':main()
