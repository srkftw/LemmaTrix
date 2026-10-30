"""Real signed consumer metadata through Native Registry -> LibraryPeer -> Noise.

Host setup signs explicitly selected original metadata and role packages. Query,
consumer admission, snapshot authorization and serving execute inside guests.
"""
import hashlib,json,os,signal,socket,struct,subprocess,sys,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import capsule,consumers,content,federation,library_peer,live,network,nodes,releases
MAGIC=0x31524545504c544c

def wait(check,seconds=300):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  value=check()
  if value:return value
  time.sleep(.04)
 raise TimeoutError('native Library peer deadline')

def run():
 with tempfile.TemporaryDirectory(prefix='lt-library-peer-') as tmp:
  base=Path(tmp);processes=[];clients=[];logs=[]
  try:
   for i,backend in enumerate(('qemu','x86_64')):
    path=base/f'{i}.sock';log=(base/f'{i}.log').open('wb');logs.append(log)
    processes.append(subprocess.Popen([str(ROOT/'lt'),'run','--backend',backend,'--socket',str(path),'--network-mux'],stdout=log,stderr=subprocess.STDOUT,cwd=ROOT,start_new_session=True))
    wait(path.exists,90);clients.append(live.Client(path,timeout=180))
   client,server=clients
   keys={}
   for role in ('package','publisher','federation','network'):
    private=base/f'{role}.pem';public=base/f'{role}.pub';capsule.generate_key(private,public);keys[role]=(private,public)
   def install(binary,name,rights):
    raw,manifest=releases.make(binary,name,'1.0.0',rights,keys['package'][0],profile=2,license='NOASSERTION')
    package=base/f'{name}.ltapp';package.write_bytes(raw);identity=releases.inspect(raw)['release_id']
    config=nodes.approved_package(package,keys['package'][1],identity,rights)
    return nodes.start_package(server,config,raw),identity
   registry,registry_release=install(ROOT/'build/live/apps/registry-consumer-check.bin','library-registry-check',2175)
   peer,peer_release=install(ROOT/'build/live/apps/library-peer.bin','library-peer-check',1024)
   configured=federation.configure(server,registry,keys['federation'][1],'consumer',allowed_rights=768)
   wave=content.original_wave(1,2);manifest,_,_=content.commitments(wave)
   raw=consumers.create(key=keys['publisher'][0],project='original-library-peer-audio',collection=content.COLLECTION,item=hashlib.sha256(b'one original item').digest(),edition=hashlib.sha256(b'lossless stereo').digest(),title='Open Courtyard: stereo edition',resource=manifest,frames=48000,channels=2,license_id=1)
   imported=consumers.attach(server,raw,manifest,name='consumer-metadata')
   modulus=releases.public_modulus(keys['publisher'][1])
   federation.call(server,registry,3,data=raw[32:64]+modulus)
   delegated=server.objects(27,imported['root'],registry,25)[0][1]
   admission=federation.call(server,registry,2,h=delegated)[0]
   assert admission[1]==1,('consumer admission pending',admission)
   signed=federation.sign_once(server,registry,keys['federation'][0],'consumer',allowed_rights=768);assert signed and signed['listing']==4,signed
   fields,descriptor=federation.call(server,registry,6);assert len(descriptor)==768
   expected=descriptor+raw
   probe=socket.socket();probe.bind(('127.0.0.1',0));port=probe.getsockname()[1];probe.close()
   identity=hashlib.sha256(os.getrandom(32)).digest();description=base/'registry.service'
   service=network.create_description(keys['network'][0],identity,f'127.0.0.1:{port}','library-registry',description)
   credentials=[base/'client.credential',base/'server.credential'];network.provision(*credentials,identity,bytes.fromhex(service['server_id']),bytes.fromhex(service['service_id']))
   root=bytes.fromhex(configured['federation_id']);service_id=bytes.fromhex(service['service_id'])
   library_peer.call(server,peer,400,0,1,23,0,32768,100000,identity+service_id+root)
   pending,_=library_peer.call(server,peer,401,0);assert pending[2]==2,'offline approved policy was discarded'
   for index in (1,0):
    network.configure(clients[index],credentials[index],description,slot=0)
    wait(lambda:network.call(clients[index],13,slot=0,allow_error=True)[0][0]==0)
   wait(lambda:all(network.status(c,0)['endpoint_authenticated'] for c in clients))
   wait(lambda:library_peer.call(server,peer,401,0)[0][2]==1)
   grant=network.call(client,2,a=3,b=3,c=32768,d=65536,e=100000,data=bytes.fromhex(service['server_id'])+service_id+root+struct.pack('<QQ',2,23),slot=0)[0][1]
   counter=0
   def request(op,h=0,a=0,b=0):
    nonlocal counter
    counter+=1;rid=counter
    payload=struct.pack('<8Q',MAGIC,1,op,h,a,b,0,0)
    job=network.call(client,3,grant,a=2,b=rid,data=payload,slot=0)[0][1]
    wait(lambda:network.call(client,4,job,slot=0)[0][2]==3)
    def receive():
     f,data=network.call(client,6,grant,slot=0,allow_error=True)
     if f[0]==6:return None
     assert f[0]==0 and f[3]==rid and len(data)>=64,(f,data)
     q=struct.unpack_from('<8Q',data);assert q[:3]==(MAGIC,1,op) and q[4]==rid,q
     return q,data[64:]
    return wait(receive)
   q,data=request(1);assert q[3]==0 and q[5]==1536 and not data,q
   snapshot=q[6];received=bytearray()
   for offset in range(0,1536,640):
    q,data=request(2,snapshot,offset,min(640,1536-offset));assert q[3]==0 and q[6]==snapshot,q;received.extend(data)
   assert bytes(received)==expected,'native peer metadata differs from original signed bytes'
   q,_=request(2,snapshot+1,0,64);assert q[3]==3,'stale snapshot admitted'
   q,_=request(5,0,64);assert q[3]==1,'registry role served seed range'
   q,_=request(1,16);assert q[3]==6,'catalog termination not bounded'
   # Reauthentication changes epochs and destroys prior grants/snapshots. The
   # original explicit operator policy can mint fresh bounded authority itself.
   network.call(server,14,slot=0)
   for index in (1,0):
    network.configure(clients[index],credentials[index],description,slot=0)
    wait(lambda:network.call(clients[index],13,slot=0,allow_error=True)[0][0]==0)
   wait(lambda:all(network.status(c,0)['endpoint_authenticated'] for c in clients))
   wait(lambda:library_peer.call(server,peer,401,0)[0][2]==1)
   grant=network.call(client,2,a=3,b=3,c=32768,d=65536,e=100000,data=bytes.fromhex(service['server_id'])+service_id+root+struct.pack('<QQ',2,23),slot=0)[0][1]
   q,_=request(2,snapshot,0,64);assert q[3]==3,'old epoch snapshot survived reauthentication'
   q,_=request(1);assert q[3]==0,'fresh operator-policy authority did not serve'
   library_peer.call(server,peer,402,0);assert library_peer.call(server,peer,401,0)[0][2]==0,'explicit revoke preserved automatic renewal'
   return dict(registry_package=registry_release,peer_package=peer_release,consumer_sha256=hashlib.sha256(raw).hexdigest(),metadata_bytes=len(received),metadata_sha256=hashlib.sha256(received).hexdigest(),metadata_only=True,payload_transferred=False,stale_snapshot='denied before and after epoch change',wrong_role_range='denied',operator_policy='configured offline, freshly granted after authentication and epoch recovery, explicitly revoked',source='actual native Registry consumer admission and signed publisher record',backends=['QEMU RV64','native x86-64 assembly'])
  finally:
   for c in clients:
    try:c.request(70)
    except (EOFError,OSError,ValueError):pass
    c.close()
   for p in processes:
    try:p.wait(5)
    except subprocess.TimeoutExpired:
     os.killpg(p.pid,signal.SIGTERM)
     try:p.wait(5)
     except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait()
   for log in logs:log.close()
if __name__=='__main__':print(json.dumps(run(),indent=2))
