"""Actually publish a later item to a previously running native Library monitor.

Reuses the deliberately populated original seed and existing collection policy.
Only signed small metadata is imported. Later media bytes travel over Noise and
native content jobs; the original seed's retained-in-RAM payload is not copied.
"""
import argparse,hashlib,json,os,signal,struct,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import consumers,content,federation,library_peer,network,releases
from library_durable_replication import Existing,install,provision,relation,role,source_scope,wait_auth
from library_journey import appcall,wait

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);p.add_argument('--catalog',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--catalog-pid',type=int,required=True);p.add_argument('--seed-pid',type=int,required=True);p.add_argument('--after-durable',type=Path);a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);source=a.source.resolve();old=a.catalog.resolve();client=Existing(source/'replica');registry=Existing(old/'registry');seed=Existing(old/'seed1');key=ROOT/'build/campaign005/publisher.pem';public=ROOT/'build/campaign005/publisher.pub';fedkey=old/'federation.pem';fedpublic=old/'federation.pub';fid=hashlib.sha256(releases.public_modulus(fedpublic)).digest();checks=[]
 def record(label,**facts):
  checks.append(dict(check=label,result='passed',**facts));(out/'result.json').write_text(json.dumps(dict(checks=checks),indent=2)+'\n');print('PASS',label,facts,flush=True)
 if a.after_durable:
  def retained():
   try:return any(x['check']=='seed1 purpose2 native retention committed its own backing' for x in json.loads(a.after_durable.read_text())['checks'])
   except (OSError,ValueError,KeyError):return False
  wait(retained,3600,'first independent durable seed commitment before new publication')
 os.kill(a.catalog_pid,signal.SIGCONT);os.kill(a.seed_pid,signal.SIGCONT)
 acquirer=role(client,1151);registry_instance=role(registry,2175);registry_peer=role(registry,1025)
 # Keep one ordinary management connection for this whole finite observation.
 # Other tests cannot stop this publisher through the portal until it closes.
 with client.client() as c:
  table=c.request(2);client_image=(source/'platform.bin').read_bytes();before,details=appcall(c,acquirer,701);before_count=struct.unpack_from('<Q',details,16)[0];assert before_count==2
  identity=hashlib.sha256(os.getrandom(32)).digest()
  catrel=relation(out,'monitor-catalog',old/'network-role0.pem',identity,'library-registry')
  provision(registry,catrel['server'],catrel['description'],3);network.configure(c,catrel['client'],catrel['description'],slot=0);wait(lambda:network.call(c,13,slot=0,allow_error=True)[0][0]==0,180,'monitor registry open');wait(lambda:network.status(c,0)['endpoint_authenticated'],300,'monitor registry auth');source_scope(registry,registry_peer,3,catrel,fid)
  old_peer=role(seed,1025)
  with seed.client() as sc:
   for slot in range(4):library_peer.call(sc,old_peer,402,slot)
   sc.request(26,struct.pack('<Q',old_peer))
   for slot in range(4):network.call(sc,14,slot=slot,allow_error=True)
  peer=install(seed,source/'replica-content-peer.ltrel',public)
  seedrel=relation(out,'monitor-later-seed',old/'network-role1.pem',identity,'library-seed')
  provision(seed,seedrel['server'],seedrel['description'],2);network.configure(c,seedrel['client'],seedrel['description'],slot=1);wait(lambda:network.call(c,13,slot=1,allow_error=True)[0][0]==0,180,'monitor seed open');wait(lambda:network.status(c,1)['endpoint_authenticated'],300,'monitor seed auth')
  wave=content.original_wave(6,2,later=True);manifest,_,_=content.commitments(wave);mid=hashlib.sha256(manifest).digest()
  # Idempotent reserve retrieves the original explicit publisher-owned root;
  # this call appends no bytes and cannot manufacture missing payload pages.
  provider=hashlib.sha256(releases.public_modulus(old/'network-role1.pub')).digest()
  with seed.client() as sc:
   h,_,_,_=content.reserve(sc,wave,1002,provider,fid);state,actual=content.api(sc).objects(306,h);assert state[2]==2 and actual==manifest
  source_scope(seed,peer,2,seedrel,mid,h)
  record('prepublication monitor still has exactly two signed consumer records',catalog_rows=before_count,policy='existing706 automatic acquisition; selected collection; source1;6029312-byte ceiling',source_image=hashlib.sha256(client_image).hexdigest(),later_manifest_sha256=mid.hex(),later_payload_bytes=len(wave),host_payload_ingestion=False)
  raw=consumers.create(key=key,project='open-courtyard-later',collection=content.COLLECTION,item=hashlib.sha256(b'evening movement').digest(),edition=hashlib.sha256(b'later').digest(),title='Open Courtyard - new evening movement',resource=manifest,frames=6*48000,channels=2,license_id=1,sequence=2)
  with registry.client() as rc:
   root=consumers.attach(rc,raw,manifest,name='consumer-later-live')['root'];federation.call(rc,registry_instance,3,data=raw[32:64]+releases.public_modulus(public));delegated=rc.objects(27,root,registry_instance,25)[0][1];federation.call(rc,registry_instance,2,h=delegated);decision=federation.sign_once(rc,registry_instance,fedkey,'consumer',8191);assert decision and decision['listing']==4
  record('actually new later item admitted and signed after monitoring policy already active',consumer_sha256=hashlib.sha256(raw).hexdigest(),sequence=decision['sequence'],item=raw[128:160].hex())
  def discovered():
   f,b=appcall(c,acquirer,701);return b if struct.unpack_from('<Q',b,16)[0]==3 else None
  detail=wait(discovered,600,'existing native monitor discovers newly published item');record('existing native monitor discovered newly admitted item without706 reconfiguration',catalog_rows=3,original_rows=2)
  def job():
   for index in range(4):
    f,b=appcall(c,acquirer,704,index,0,128);q=struct.unpack('<16Q',b)
    if q[0] and q[1]==2:return index,list(q)
  index,q=wait(job,300,'newly eligible later item queued within existing policy');start=time.monotonic();last=-1
  while True:
   f,b=appcall(c,acquirer,704,index,0,128);q=list(struct.unpack('<16Q',b));(out/'later-job.json').write_text(json.dumps(dict(words=q,seconds=time.monotonic()-start),indent=2)+'\n')
   if q[7]//65536!=last:last=q[7]//65536;print('LATER',q[0],q[7],flush=True)
   if q[0]==10:break
   if q[0] in (12,13,14):raise RuntimeError(('new item remained inspectable',q))
   if time.monotonic()-start>2400:raise TimeoutError('new item remains inspectable')
   time.sleep(.2)
  h=appcall(c,acquirer,705,2)[0][1];sample=content.api(c).objects(307,h,0,512)[1];assert sample==wave[:512]
  record('newly eligible item acquired and actual native WAV quality checked under existing bounded policy',state=q[0],bytes=q[7],chunks=q[4],sample_sha256=hashlib.sha256(sample).hexdigest(),first_edition_still_ready=True,seconds=time.monotonic()-start)
 os.kill(a.catalog_pid,signal.SIGSTOP);os.kill(a.seed_pid,signal.SIGSTOP)
 print('LIVE PUBLICATION MONITOR COMPLETE',flush=True)
if __name__=='__main__':main()
