"""Three independent native clients share one unattended relay/terminal service.

The controller installs/configures actors and submits component RPCs. It neither
moves client handoffs nor interprets ciphertext nor commits mailbox state. These
public ciphertext/capability fixtures qualify shared ownership, not Messenger UI.
"""
import argparse, hashlib, json, os, signal, socket, struct, subprocess, sys, time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import server_store
import onion_route as route, identity, live, messenger, releases

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--image',type=Path,default=ROOT/'build/live/guest.bin')
 p.add_argument('--network',type=Path,default=ROOT/'build/live/network-shared-check.bin')
 p.add_argument('--mailbox',type=Path,default=ROOT/'build/live/apps/mailbox-shared-check.bin')
 p.add_argument('--output',type=Path,default=ROOT/'build/native-shared-terminal')
 p.add_argument('--backend',choices=('qemu','x86_64'),default='qemu')
 a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
 frozen=bytearray(a.image.read_bytes());network=a.network.read_bytes()
 assert len(network)<=393216
 frozen[0x340000:0x3a0000]=bytes(393216);frozen[0x340000:0x340000+len(network)]=network
 struct.pack_into('<Q',frozen,0x200000+6*32,len(network))
 image=a.output/'guest.bin';image.write_bytes(frozen)
 signer=a.output/'identity.ltrel';raw,_=releases.make(ROOT/'build/live/apps/identity.bin','identity','1.0.0',0,ROOT/'tests/keys/development-rsa.pem',profile=2);signer.write_bytes(raw)
 package=a.output/'mailbox.ltrel';raw,_=releases.make(a.mailbox,'mailbox','1.0.0',2048,ROOT/'tests/keys/development-rsa.pem',profile=2);package.write_bytes(raw)
 backing=a.output/'operator.img'
 if backing.exists():backing.unlink()
 server_store.provision(backing)
 clients=[];processes=[];logs=[];checks=[];started=time.monotonic();timings={}
 try:
  for i in range(7):
   base=a.output/f'node{i}';base.mkdir(exist_ok=True);path=base/'portal.sock';path.unlink(missing_ok=True)
   log=(base/'guest.log').open('wb');logs.append(log)
   command=[ROOT/'lt','run','--backend',a.backend,'--image',image,'--socket',path,'--network-mux']
   if i==6:command+=['--server-store',backing]
   processes.append(subprocess.Popen(list(map(str,command)),cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,start_new_session=True))
   route.wait(path.exists,90);c=live.Client(path,timeout=600);c.request(1);clients.append(c)
   if i>=3:
    # Only node signer operations are needed by this component. Keep the
    # baseline-image checkpoint independent from the new Feed signer ABI.
    operations=identity.OPERATIONS;identity.OPERATIONS=tuple(range(400,410))
    try:identity.start(c,signer,ROOT/'tests/keys/development-rsa-public.pem')
    finally:identity.OPERATIONS=operations
  certs=[]
  for i in range(3,7):
   probe=socket.socket();probe.bind(('127.0.0.1',0));port=probe.getsockname()[1];probe.close()
   cert,_=route.create(clients[i],f'127.0.0.1:{port}',f'Campaign009 independent native operator{i}',7 if i<6 else 8)
   certs.append(cert);(a.output/f'node{i}.certificate').write_bytes(cert)
   print('created operator',i,flush=True)
  for c in clients[:3]:
   for slot,cert in enumerate(certs):route.enroll(c,slot,cert)
  for i in range(3,6):route.enroll(clients[i],0,certs[i-2])
  mc=clients[6];service,sid=messenger.install(mc,package,ROOT/'tests/keys/development-rsa-public.pem',2048);launcher=messenger.launcher(mc)
  for op in (440,441):messenger.bind(mc,3,service,launcher,op,sid)
  native_network=next(row[0] for row in identity.instances(mc) if row[0]&255==6)
  messenger.bind(mc,3,service,native_network,441,sid)
  server_store.call(mc,230);ns=hashlib.sha256(b'Campaign009 shared native mailbox namespace').digest()
  grant=server_store.call(mc,231,service,2,1048576,ns)[0][1];messenger.invoke(mc,3,440,a=grant)
  capabilities=[]
  for i in range(3):
   recipient=hashlib.sha256(f'shared native recipient{i}'.encode()).digest();deposit=hashlib.sha256(f'component deposit{i}'.encode()).digest();fetch=hashlib.sha256(f'component fetch{i}'.encode()).digest()
   capabilities.append((recipient,deposit,fetch))
   f,_=messenger.invoke(mc,3,440,h=1,a=1048576,b=128,data=recipient+hashlib.sha256(deposit).digest()+hashlib.sha256(fetch).digest(),allowed_status=(0,6))
   while f[0]==6:f,_=messenger.invoke(mc,3,441,h=4,allowed_status=(0,6))
  for c in clients[3:]:route.route(c,30)
  begin=time.monotonic()
  for c in clients[:3]:route.route(c,31)
  for i,c in enumerate(clients[:3]):
   route.wait(lambda c=c:route.route(c,32)[0][2]==3,300)
   route.route(c,38,h=3,a=17+i,b=messenger.launcher(c),c=1048576,d=1024)
   def terminal_ready(c=c):
    f,pin=route.route(c,41)
    if f[3]:raise AssertionError(('terminal failure',f))
    return pin if f[1]==1 and f[2]==3 else None
   assert route.wait(terminal_ready,240)==hashlib.sha256(certs[3]).digest()
   print('independently admitted client',i,flush=True)
  timings['three_client_setup_seconds']=time.monotonic()-begin
  print('allthree independentcontexts simultaneouslyadmitted',flush=True)
  checks.append('three independent native clients concurrently admitted through same3relays and mailbox; no stop/listen handoff')
  serials=[0,0,0];rpc_timings=[]
  def rpc(i,action,a=0,b=0,c=0,data=b'',timeout=120):
   began=time.monotonic();serials[i]+=1;serial=serials[i];client=clients[i]
   route.route(client,39,h=serial,data=struct.pack('<8Q',441,action,a,b,c,0,0,1)+data)
   def collect():
    f,answer=route.route(client,40,h=serial,allow_error=True)
    if f[0]==6:return None
    assert f[0]==0,(i,f,answer)
    return answer
   answer=route.wait(collect,timeout)
   rpc_timings.append(dict(client=i,action=action,seconds=time.monotonic()-began,status=struct.unpack_from('<Q',answer)[0]))
   print('routedRPC',i,action,rpc_timings[-1],flush=True)
   return struct.unpack_from('<8Q',answer),answer[64:]
  for i in range(3):assert rpc(i,4)[0][0]==0
  # A deliberately incomplete upload must not monopolize the native mailbox.
  payloads=[(f'Native shared client{i} opaque ciphertext.\n'.encode()*41) for i in range(3)]
  commitments=[hashlib.sha256(b).digest() for b in payloads]
  requests=[hashlib.sha256(f'Campaign009 stable exact request{i}'.encode()).digest() for i in range(3)]
  handles=[]
  for i in range(3):
   recipient,deposit,_=capabilities[i]
   f,_=rpc(i,1,len(payloads[i]),1,data=recipient+deposit+requests[i]+commitments[i]);assert f[0]==0,(i,f);handles.append(f[1])
  assert len(set(handles))==3
  for i in range(3):
   recipient,deposit,_=capabilities[i]
   f,_=rpc(i,2,handles[i],0,data=recipient+deposit+payloads[i][:512]);assert f[0]==0,(i,f)
  checks.append('three distinct native upload stages coexist; firstclient deliberately stalls after512bytes')
  # The same Network caller cannot use another terminal generation's stage even
  # with the same recipient bearer capability (capability alone is insufficient).
  recipient,deposit,_=capabilities[0]
  f,_=rpc(1,2,handles[0],512,data=recipient+deposit+payloads[0][512:1024]);assert f[0] in (2,3),f
  checks.append('cross-client append with correct recipient bearer but foreign terminal context is denied')
  begin=time.monotonic()
  for i in (1,2):
   recipient,deposit,fetch=capabilities[i]
   for offset in range(512,len(payloads[i]),512):
    f,_=rpc(i,2,handles[i],offset,data=recipient+deposit+payloads[i][offset:offset+512]);assert f[0]==0,(i,f)
   f,_=rpc(i,3,handles[i],data=recipient+deposit);assert f[0] in (0,6),(i,f)
   while f[0]==6:f,_=rpc(i,4,handles[i],data=recipient+deposit)
   assert f[0]==0,(i,f)
   f,_=rpc(i,1,len(payloads[i]),1,data=recipient+deposit+requests[i]+commitments[i]);assert f[0]==0 and f[1]==handles[i],(i,f)
   body=bytearray()
   for offset in range(0,len(payloads[i]),512):
    f,chunk=rpc(i,5,handles[i],offset,512,data=recipient+fetch);assert f[0]==0,(i,f);body.extend(chunk)
   assert bytes(body)==payloads[i]
  timings['two_clients_commit_and_read_while_other_stalled_seconds']=time.monotonic()-begin
  checks.append('two otherclients durably commit, retry exact request without duplicate, and fetch checked ciphertext while firstupload stalls')
  os.killpg(processes[0].pid,signal.SIGTERM);processes[0].wait(timeout=10);clients[0].close()
  for i in (1,2):assert rpc(i,4)[0][0]==0
  checks.append('dropping stalled client leaves both unrelated terminal sessions usable')
  # A separately started guest arrives after disconnect, with no operator
  # listener intervention or reuse of a dead client's transport generation.
  base=a.output/'replacement';base.mkdir(exist_ok=True);path=base/'portal.sock';path.unlink(missing_ok=True)
  log=(base/'guest.log').open('wb');logs.append(log)
  command=[ROOT/'lt','run','--backend',a.backend,'--image',image,'--socket',path,'--network-mux']
  processes.append(subprocess.Popen(list(map(str,command)),cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,start_new_session=True))
  route.wait(path.exists,90);replacement=live.Client(path,timeout=600);replacement.request(1);clients[0]=replacement;serials[0]=0
  for slot,cert in enumerate(certs):route.enroll(replacement,slot,cert)
  route.route(replacement,31);route.wait(lambda:route.route(replacement,32)[0][2]==3,300)
  route.route(replacement,38,h=3,a=29,b=messenger.launcher(replacement),c=1048576,d=1024)
  route.wait(lambda:route.route(replacement,41)[0][2]==3,240)
  assert rpc(0,4)[0][0]==0
  recipient,deposit,_=capabilities[0]
  assert rpc(0,2,handles[0],512,data=recipient+deposit+payloads[0][512:1024])[0][0]in(2,3)
  for i in (1,2):assert rpc(i,4)[0][0]==0
  checks.append('independently arriving replacement client admitted by same running operators; dead context cannot resume staging and unrelated clients remain usable')
  report=dict(schema=1,result='pass',image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),network_sha256=hashlib.sha256(network).hexdigest(),network_bytes=len(network),mailbox_sha256=hashlib.sha256(a.mailbox.read_bytes()).hexdigest(),backend=a.backend,clients=3,relay_link_slots=12,bulk_link_slots=4,terminal_contexts=16,mailbox_stages=4,stage_bytes=8192,checks=checks,timings=timings,rpc_timings=rpc_timings,total_seconds=time.monotonic()-started,limitations='Native infrastructure component evidence. Public capability/ciphertext fixtures; this does not exercise Messenger UI, Feed, signed receipts, Forge, independent operators or hostile-network assurance.')
  (a.output/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2),flush=True)
 except BaseException as error:
  (a.output/'failure.json').write_text(json.dumps(dict(schema=1,error=repr(error),checks_completed=checks,timings=timings,rpc_timings=locals().get('rpc_timings',[]),image_sha256=hashlib.sha256(image.read_bytes()).hexdigest()),indent=2)+'\n');raise
 finally:
  for c in clients:
   try:c.close()
   except OSError:pass
  for process in processes:
   if process.poll() is None:os.killpg(process.pid,signal.SIGTERM)
  for process in processes:
   try:process.wait(timeout=10)
   except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait()
  for log in logs:log.close()
if __name__=='__main__':main()
