"""Measure normal Library policy acquisition through final native publication.

Uses the existing original six-second recording and three isolated guests. Only
the approved producer imports source bytes; the recipient uses the actual signed
catalog, collection policy, peer protocol, chunk validator, and WAV consumer.
This measures a volatile production transfer, not durable replication/playback.
"""
import argparse,sys,os,json,time,struct,hashlib,socket
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import capsule,consumers,content,federation,library_peer,live,network,nodes,releases
from library_journey import Node,appcall,wait
preparation_started=time.monotonic()
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--output',type=Path,required=True)
p.add_argument('--image',type=Path,default=ROOT/'build/live/guest.bin')
p.add_argument('--acquirer',type=Path,default=ROOT/'build/live/apps/library-acquirer006.bin')
p.add_argument('--peer',type=Path,default=ROOT/'build/live/apps/library-peer.bin')
p.add_argument('--registry',type=Path,default=ROOT/'build/live/apps/registry-current006.bin')
p.add_argument('--service-grant',type=int,choices=(16777216,134217728),default=134217728,help='signed Library descriptor grant ceiling;16MiB selects compatible schema2')
p.add_argument('--producer-unit',type=int,choices=(512,928),default=928,help='authorized producer preload IPC unit;512 supports the original image')
p.add_argument('--key',type=Path,default=ROOT/'build/campaign005/publisher.pem')
p.add_argument('--public',type=Path,default=ROOT/'build/campaign005/publisher.pub')
a=p.parse_args()
out=a.output.resolve()
if len(os.fsencode(out/'personal/portal.sock'))>107:raise ValueError('use a shorter output path for the UNIX management socket')
out.mkdir(parents=True,exist_ok=False)
image=out/'platform.bin';image.write_bytes(a.image.read_bytes());binary=out/'acquirer.bin';binary.write_bytes(a.acquirer.read_bytes());peerbin=out/'peer.bin';peerbin.write_bytes(a.peer.read_bytes());key=a.key;public=a.public;guests=[]
regbin=out/'registry.bin';regbin.write_bytes(a.registry.read_bytes())
def package(path,name,rights):
 raw,_=releases.make(path,name,'1.0.0',rights,key,profile=2,license='NOASSERTION');p=out/(name+'.ltrel');p.write_bytes(raw);return p
def install(n,p):
 raw=p.read_bytes();i=releases.inspect(raw)
 with n.client() as c:return nodes.start_package(c,nodes.approved_package(p,public,i['release_id'],i['rights']),raw)
def preload(c,raw,operation,provider,federation_id):
 client=content.api(c);h,manifest,chunks,proofs=content.reserve(client,raw,operation,provider,federation_id)
 for index,(part,proof) in enumerate(zip(chunks,proofs)):
  fields,_=client.objects(301,h,index,data=proof);job=fields[1]
  if job==0 and fields[2]==4:continue
  for offset in range(0,len(part),a.producer_unit):client.objects(302,job,offset,data=part[offset:offset+a.producer_unit])
  client.objects(303,job);content.wait_job(client,job);client.objects(305,job,4)
 fields,_=client.objects(310,h)
 if fields[1]!=h:content.wait_job(client,fields[1]);client.objects(305,fields[1],4)
 return h,manifest
def profile(n):
 with n.client() as c:
  f,data=network.call(c,16,slot=0,allow_error=True)
 if f[0] or len(data)!=96:return None
 return dict(zip(('context_switch_ticks','seal_ticks','open_ticks','pump_ticks','context_switches','seal_attempts','open_attempts','pump_turns','rpc_calls','bounded_waits','no_progress_waits','burst_limit_yields'),struct.unpack('<12Q',data)))
def relationship(name,role,server,client,slot,root,selected=0):
 private=out/(name+'.pem');pub=out/(name+'.pub');capsule.generate_key(private,pub);s=socket.socket();s.bind(('127.0.0.1',0));port=s.getsockname()[1];s.close();desc=out/(name+'.service');detail=network.create_description(private,identity,f'127.0.0.1:{port}',role,desc,max_grant=a.service_grant);cl=out/(name+'-client.credential');se=out/(name+'-server.credential');network.provision(cl,se,identity,bytes.fromhex(detail['server_id']),bytes.fromhex(detail['service_id']))
 with server.client() as c:network.configure(c,se,desc,slot=0);wait(lambda:network.call(c,13,slot=0,allow_error=True)[0][0]==0)
 with client.client() as c:network.configure(c,cl,desc,slot=slot);wait(lambda:network.call(c,13,slot=slot,allow_error=True)[0][0]==0);wait(lambda:network.status(c,slot)['endpoint_authenticated'],300,'authentication')
 with server.client() as c:
  selected=content.api(c).objects(308,selected,server_peer[name])[0][1] if selected else 0
  library_peer.call(c,server_peer[name],400,0,2 if selected else 1,int.from_bytes(root[:8],'little')|1 if selected else 1,selected,16777216,100000,identity+bytes.fromhex(detail['service_id'])+root)
 return detail
try:
 regpkg=package(regbin,'performance-registry',2175);acqpkg=package(binary,'performance-acquirer',1151);peerpkg=package(peerbin,'performance-peer',1025)
 personal=Node('personal',out,image);registry=Node('registry',out,image);seed=Node('seed',out,image);guests=[personal,registry,seed]
 reg=install(registry,regpkg);local=install(personal,regpkg);acq=install(personal,acqpkg);server_peer=dict(registry=install(registry,peerpkg),seed=install(seed,peerpkg))
 fk=out/'federation.pem';fp=out/'federation.pub';capsule.generate_key(fk,fp);fid=hashlib.sha256(releases.public_modulus(fp)).digest()
 for n,inst in [(registry,reg),(personal,local)]:
  with n.client() as c:federation.configure(c,inst,fp,'consumer',allowed_rights=8191)
 wave=content.original_wave(6,2);m,_,_=content.commitments(wave);mid=hashlib.sha256(m).digest();identity=hashlib.sha256(os.getrandom(32)).digest()
 record=consumers.create(key=key,project='open-courtyard-stereo',collection=content.COLLECTION,item=hashlib.sha256(b'Open Courtyard first original recording').digest(),edition=hashlib.sha256(b'stereo').digest(),title='Open Courtyard - lossless stereo',resource=m,frames=6*48000,channels=2,license_id=1,sequence=1)
 with registry.client() as c:
  root=consumers.attach(c,record,m,name='original-consumer')['root'];federation.call(c,reg,3,data=record[32:64]+releases.public_modulus(public));delegated=c.objects(27,root,reg,25)[0][1];federation.call(c,reg,2,h=delegated);assert federation.sign_once(c,reg,fk,'consumer',8191)['listing']==4
 relationship('registry','library-registry',registry,personal,0,fid)
 # Bootstrap only the selected provider. The recipient receives content only
 # through the unmodified production Library policy/job protocol.
 with seed.client() as c:source,_=preload(c,wave,1001,hashlib.sha256(b'authorized-source').digest(),fid)
 relationship('seed','library-seed',seed,personal,1,mid,source)
 with personal.client() as c:c.request(184,struct.pack('<Q',acq))
 diagnostics_before={n.name:profile(n) for n in guests}
 preparation_seconds=time.monotonic()-preparation_started
 started=time.monotonic()
 with personal.client() as c:assert appcall(c,acq,706,0,6029312,data=fid+content.COLLECTION)[0][0]==0
 print('STARTED',flush=True)
 def done():
  with personal.client() as c:
   data=appcall(c,acq,704,0,0,128)[1];words=list(struct.unpack('<16Q',data));stats=content.api(c).objects(312)[0]
  elapsed=time.monotonic()-started;(out/'progress.json').write_text(json.dumps(dict(words=words,elapsed=elapsed,stats=list(stats)),indent=2))
  if words[0] in (12,13,14):raise RuntimeError(('job terminal',words))
  return words[0]==10
 wait(done,3000,'production acquisition and native validate/publish')
 elapsed=time.monotonic()-started
 with personal.client() as c:
  f,_=appcall(c,acq,705,0);h=f[1]
  first=content.api(c).objects(307,h,0,512)[1];last=content.api(c).objects(307,h,len(wave)-128,128)[1];assert first==wave[:512] and last==wave[-128:]
 diagnostics_after={n.name:profile(n) for n in guests}
 stats=json.loads((out/'progress.json').read_text())['stats']
 result=dict(network_diagnostics_before=diagnostics_before,network_diagnostics_after=diagnostics_after,image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),acquirer_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),peer_sha256=hashlib.sha256(peerbin.read_bytes()).hexdigest(),registry_release_sha256=hashlib.sha256(regpkg.read_bytes()).hexdigest(),registry_binary_sha256=hashlib.sha256(regbin.read_bytes()).hexdigest(),payload_bytes=len(wave),payload_sha256=hashlib.sha256(wave).hexdigest(),manifest_sha256=mid.hex(),elapsed_seconds=elapsed,preparation_seconds=preparation_seconds,preparation_scope='guest startup, signed package installation and admission, relationships, authorized producer bootstrap; recipient gets no preload',payload_bytes_per_second=len(wave)/elapsed,includes='policy submit,metadata discovery,transfer,per-chunk integrity,complete validation and publication,consumer WAV parse',content_stats=stats,backend='QEMU RV64',cache_bytes=stats[2]*4096,resident_payload_bytes=stats[1]*4096,network_context_banks_bytes=4*65536,network_per_context_copied_bytes=17832 if diagnostics_after['personal'] is not None else None,limitations=['same-host separate local guests, not independent administration','volatile content path; no durable inventory claim','host management completion inspections use existing120ms bounded test wait','concurrent developer work is not controlled; no universal throughput claim'])
 (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result),flush=True)
finally:
 for n in reversed(guests):n.stop()
