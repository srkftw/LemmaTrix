"""Actual Library input/monitoring cannot move acquisition consent between collections.

Three genuine signed/admitted records feed an ordinary Lean fixture importing
Library.input/approvePolicy/monitorDecision. It owns metadata and a real paused
Content job. Test events enter the actual input function, not guest memory.
"""
import argparse,contextlib,hashlib,json,os,signal,struct,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import capsule,consumers,content,federation,live,nodes,releases
from library_journey import wait


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,required=True);p.add_argument('--binary',type=Path,required=True);p.add_argument('--registry',type=Path,required=True)
 p.add_argument('--key',type=Path,default=ROOT/'build/campaign005/publisher.pem');p.add_argument('--public',type=Path,default=ROOT/'build/campaign005/publisher.pub');p.add_argument('--output',type=Path,required=True)
 a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);sock=out/'portal.sock';log=(out/'guest.log').open('wb');client=None;proc=None;checks=[]
 try:
  command=list(map(str,[ROOT/'lt','run','--backend','qemu','--image',a.image,'--socket',sock]));proc=subprocess.Popen(command,cwd=ROOT,stdout=log,stderr=log,start_new_session=True);wait(sock.exists,90,'guest boot');client=live.Client(sock,timeout=180)
  def start(path):
   raw=path.read_bytes();info=releases.inspect(raw);instance=nodes.start_package(client,nodes.approved_package(path,a.public,info['release_id'],info['rights']),raw);return instance,info
  registry,reginfo=start(a.registry);fedkey=out/'federation.pem';fedpub=out/'federation.pub';capsule.generate_key(fedkey,fedpub);fid=hashlib.sha256(releases.public_modulus(fedpub)).digest();federation.configure(client,registry,fedpub,'consumer',allowed_rights=8191)
  collections=[hashlib.sha256(b'approved collection A').digest(),hashlib.sha256(b'monitor-only collection B').digest()]
  wave=content.original_wave(.001,2);manifest,chunks,proofs=content.commitments(wave);records=[];descriptors=[]
  for i,collection in enumerate([collections[0],collections[0],collections[1]]):
   record=consumers.create(key=a.key,project='collection-consent-'+str(i),collection=collection,item=hashlib.sha256(('original item'+str(i)).encode()).digest(),edition=hashlib.sha256(('original edition'+str(i)).encode()).digest(),title='Original collection boundary '+str(i),resource=manifest,frames=48,channels=2,license_id=1)
   root=consumers.attach(client,record,manifest,name='consent-record-'+str(i))['root'];federation.call(client,registry,3,data=record[32:64]+releases.public_modulus(a.public));federation.call(client,registry,2,h=client.objects(27,root,registry,25)[0][1]);decision=federation.sign_once(client,registry,fedkey,'consumer',8191);assert decision['listing']==4
   fields,descriptor=federation.call(client,registry,6,h=i);assert len(descriptor)==768 and fields[2]==i
   records.append(record);descriptors.append(descriptor)
  raw,_=releases.make(a.binary,'library-collection-consent-probe','1.0.0',1919,a.key,profile=2,license='NOASSERTION');package=out/'library-collection-consent-probe.ltrel';package.write_bytes(raw);instance,probeinfo=start(package);client.request(184,struct.pack('<Q',instance))
  def call(op,h=0,a=0,b=0,data=b''):
   raw=client.request(150,struct.pack('<Q8Q',instance,op,h,a,b,0,0,0,1)+data);assert len(raw)>=64
   return struct.unpack_from('<8Q',raw),raw[64:]
  def decode(answer):
   q,data=answer;assert q[0]==0 and len(data)==552,answer
   return dict(selected=q[1],monitoring=q[2],automatic=q[3],generation=q[4],sources=q[5],charged=q[6],approval_row=q[7],collection=data[:32].hex(),approval_open=struct.unpack_from('<Q',data,32)[0],jobs=[list(struct.unpack_from('<16Q',data,40+i*128))for i in range(4)])
  def press(code):return decode(call(942,code))
  def state():return decode(call(946))
  def monitor():return decode(call(948))
  def frozen(index):
   data=b''.join(call(945,index,offset,min(512,2048-offset))[1]for offset in range(0,2048,512));return data[64:120]+data[512:2048]
  for i,(descriptor,record) in enumerate(zip(descriptors,records)):
   metadata=descriptor+record
   for offset in range(0,1536,512):assert call(940,i,offset,512,metadata[offset:offset+512])[0][0]==0
  decode(call(941));press(34);approved=press(28);assert approved['automatic']==1 and approved['generation']==1 and approved['collection']==collections[0].hex() and approved['jobs'][0][0]==1
  queued=monitor();assert queued['jobs'][1][0]==1 and queued['jobs'][1][1]==1,'actual monitor did not enqueue the other approved A item'
  provider=hashlib.sha256(b'explicit volatile provider A').digest();binding=manifest+hashlib.sha256(manifest).digest()+provider+fid
  paused=decode(call(943,data=binding+proofs[0]+wave[:64]));assert paused['jobs'][0][0]==11 and call(944)[0][2]==3
  before=[frozen(i)for i in range(2)];old_operation=paused['jobs'][0][10]
  off=press(31);same=press(31);assert off['monitoring']==0 and same['monitoring']==1 and same['automatic']==1 and same['generation']==1 and same['jobs'][0][0]==11 and same['jobs'][1][0]==1
  press(108);press(108);switched=press(31)
  assert switched['selected']==2 and switched['collection']==collections[1].hex() and switched['monitoring']==1 and switched['automatic']==0 and switched['generation']==2 and switched['sources']==0 and switched['charged']==0 and switched['approval_row']==0
  assert [j[0]for j in switched['jobs'][:2]]==[14,14] and all(frozen(i)==before[i]for i in range(2)),'retirement changed frozen old identities or left old work live'
  assert call(944)[0][0]==3 and call(947)[0][0]==1,'old paused job/acquisition authority survived collection switch'
  for _ in range(3):blocked=monitor();assert blocked['automatic']==0 and [j[0]for j in blocked['jobs'][:2]]==[14,14]
  checks.append(dict(check='same-collection S preserves approved A; S to B retires paused/queued A, preserves frozen identities and enables monitoring only',result='passed',before=paused,after=switched,old_metadata_binding_sha256=[hashlib.sha256(x).hexdigest()for x in before],old_content_job_status=3,old_acquisition_begin_status=1,monitor_attempts_without_acquisition=3))
  dialog=press(32);assert dialog['approval_open']==1 and dialog['approval_row']==3 and dialog['automatic']==0
  held=press(103);assert held['selected']==2 and held['approval_row']==3,'input retargeted pending D consent'
  approved_b=press(28);assert approved_b['automatic']==1 and approved_b['collection']==collections[1].hex() and approved_b['generation']==3 and approved_b['jobs'][0][0]==1 and approved_b['jobs'][0][1]==2 and approved_b['jobs'][0][8]==3 and approved_b['jobs'][0][10]!=old_operation
  press(103);press(103);returned=press(31);assert returned['collection']==collections[0].hex() and returned['automatic']==0 and returned['generation']==4 and returned['approval_row']==0 and returned['jobs'][0][0]==14
  assert monitor()['automatic']==0
  press(34);fresh_a=press(28);assert fresh_a['automatic']==1 and fresh_a['generation']==5 and fresh_a['jobs'][0][0]==1 and fresh_a['jobs'][0][1] in (0,1) and fresh_a['jobs'][0][8]==5 and fresh_a['jobs'][0][10]!=old_operation
  checks.append(dict(check='D binds B approval before Enter despite attempted selection change; returning A cannot revive consent and requires fresh G',result='passed',D_pending=dialog,D_input_blocked=held,D_approved_B=approved_b,returned_A_monitor_only=returned,fresh_G_approved_A=fresh_a))
  result=dict(schema=1,result='passed',backend='qemu',image_sha256=hashlib.sha256(a.image.read_bytes()).hexdigest(),library_source_sha256=hashlib.sha256((ROOT/'Guest/Library.lean').read_bytes()).hexdigest(),probe_sha256=hashlib.sha256(a.binary.read_bytes()).hexdigest(),probe_release=probeinfo['release_id'],registry_release=reginfo['release_id'],collections=[x.hex()for x in collections],consumer_records=[hashlib.sha256(x).hexdigest()for x in records],checks=checks,command=command,scope='actual Library input/approval/monitor/retire functions with native signed Registry records and a real paused Content job owned by the ordinary fixture',limitations=['test events invoke actual input handler from an ordinary Lean fixture; not physical graphical G/S/D evidence','fixture initializes only its own metadata rows through public SDK-created immutable Objects; no host guest-memory mutation','no network transfer, personal backing, Game, playback or complete campaign acceptance claimed'])
  (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
 finally:
  if client:
   with contextlib.suppress(EOFError,OSError,ValueError):client.request(70)
   client.close()
  if proc and proc.poll() is None:
   try:proc.wait(20)
   except subprocess.TimeoutExpired:os.killpg(proc.pid,signal.SIGTERM);proc.wait(10)
  log.close()


if __name__=='__main__':main()
