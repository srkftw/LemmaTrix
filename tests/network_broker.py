"""Actual isolated service6 Noise exchange; administration only provisions scopes.

Normal Forge actions are verified separately. No graph data is copied between
hosts here: the payload must travel through two independently running guests.
"""
import argparse,hashlib,json,os,socket,struct,subprocess,sys,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import live,network

def wait_until(predicate,seconds=90):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  result=predicate()
  if result:return result
  time.sleep(.04)
 raise TimeoutError('bounded broker operation did not complete')

def run_pair(client_backend,server_backend,size=4097):
 with tempfile.TemporaryDirectory(prefix='lt-network-') as td:
  directory=Path(td);socks=[directory/'client.sock',directory/'server.sock'];logs=[];processes=[];clients=[]
  pin_client=hashlib.sha256(os.getrandom(32)).digest();pin_server=hashlib.sha256(os.getrandom(32)).digest();service=hashlib.sha256(b'lt-forge-service-v1').digest();root=hashlib.sha256(b'explicit frozen test root').digest()
  creds=[directory/'client.credential',directory/'server.credential']
  network.provision(*creds,pin_client,pin_server,service)
  port_probe=socket.socket();port_probe.bind(('127.0.0.1',0));port=port_probe.getsockname()[1];port_probe.close();endpoint=f'127.0.0.1:{port}'
  try:
   for i,backend in [(1,server_backend),(0,client_backend)]:
    log=(directory/f'guest{i}.log').open('wb');logs.append(log)
    args=[str(ROOT/'lt'),'run','--backend',backend,'--socket',str(socks[i]),'--network-listen' if i==1 else '--network',endpoint]
    processes.append(subprocess.Popen(args,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT))
   for path in socks:wait_until(path.exists)
   clients=[live.Client(path,timeout=90) for path in socks]
   print("configure server",flush=True);network.configure(clients[1],creds[1]);print("configure client",flush=True);network.configure(clients[0],creds[0]);print("waiting Noise",flush=True)
   def authenticated():
    statuses=[network.status(c) for c in clients]
    if not hasattr(authenticated,'last') or time.monotonic()-authenticated.last>5:
     print('Noise state',statuses,flush=True);authenticated.last=time.monotonic()
    return all(status['endpoint_authenticated'] for status in statuses)
   wait_until(authenticated,300)
   grants=[]
   for i,c in enumerate(clients):
    peer=pin_server if i==0 else pin_client
    # Unsupported privacy modes and substituted peer pins fail before I/O.
    for bad_mode,pin,expected in [(1,peer,7),(3,bytes(32),2)]:
     f,_=network.call(c,2,a=3,b=bad_mode,c=262144,d=65536,e=100000,data=pin+service+root+struct.pack('<Q',1),allow_error=True)
     assert f[0]==expected,(bad_mode,f)
    f,_=network.call(c,2,a=3,b=3,c=max(size*3,8192),d=65536,e=100000,data=peer+service+root+struct.pack('<Q',1));grants.append(f[1])
   # Fill the bounded inbox, drain low slots, refill them while older high
   # slots remain. Physical slot reuse must not reorder the authenticated stream.
   bursts=[('fifo-'+str(i)).encode() for i in range(6)]
   def enqueue_bytes(chunk):
    f,_=network.call(clients[0],3,grants[0],a=1,data=chunk)
    wait_until(lambda:network.call(clients[0],4,f[1])[0][2]==3)
   for chunk in bursts[:4]:enqueue_bytes(chunk)
   wait_until(lambda:network.status(clients[1])['inbox_records']==4)
   first=[network.call(clients[1],6,grants[1])[1] for _ in range(2)]
   assert first==bursts[:2],('initial FIFO order',first)
   for chunk in bursts[4:]:enqueue_bytes(chunk)
   wait_until(lambda:network.status(clients[1])['inbox_records']==4)
   rest=[network.call(clients[1],6,grants[1])[1] for _ in range(4)]
   assert rest==bursts[2:],('reused inbox slots reordered records',rest)
   payload=bytes((i*179+23)%256 for i in range(size));received=bytearray()
   for offset in range(0,len(payload),700):
    chunk=payload[offset:offset+700]
    f,_=network.call(clients[0],3,grants[0],a=1,data=chunk);job=f[1]
    wait_until(lambda:network.call(clients[0],4,job)[0][2]==3)
    def receive():
     f,data=network.call(clients[1],6,grants[1],allow_error=True)
     if f[0]==6:return None
     assert f[0]==0,f
     return data
    received.extend(wait_until(receive))
   assert received==payload,'actual peer record bytes differ'
   # Reverse traffic uses the independently derived directional key.
   reply=b'seed receipt for '+hashlib.sha256(payload).hexdigest().encode()
   f,_=network.call(clients[1],3,grants[1],a=1,data=reply);job=f[1]
   wait_until(lambda:network.call(clients[1],4,job)[0][2]==3)
   def reverse():
    f,data=network.call(clients[0],6,grants[0],allow_error=True)
    if f[0]==6:return None
    assert f[0]==0,f
    return data
   assert wait_until(reverse)==reply
   network.call(clients[0],8,grants[0])
   f,_=network.call(clients[0],3,grants[0],a=1,data=b'denied',allow_error=True);assert f[0]==3
   return {'client_backend':client_backend,'server_backend':server_backend,'guest_image_sha256':hashlib.sha256((ROOT/'build/live/guest.bin').read_bytes()).hexdigest(),'profile':'Noise_NNpsk0_25519_ChaChaPoly_SHA256','payload_bytes':len(received),'payload_sha256':hashlib.sha256(received).hexdigest(),'bidirectional_authenticated_records':'pass','bounded_inbox_slot_reuse_preserves_FIFO':'pass','denied_privacy_mode_wrong_peer_stale_grant':'pass','scope':'actual guest broker transport; no application/graph acceptance claim'}
  except BaseException:
   for log in logs:log.flush()
   for path in directory.glob('guest*.log'):print(path.name,path.read_text(errors='replace')[-4000:],file=sys.stderr)
   raise
  finally:
   for client in clients:client.close()
   for process in processes:
    if process.poll() is None:process.terminate()
   for process in processes:
    try:process.wait(timeout=5)
    except subprocess.TimeoutExpired:process.kill();process.wait()
   for log in logs:log.close()

def main():
 p=argparse.ArgumentParser();p.add_argument('--client-backend',choices=('qemu','x86_64','aarch64'),default='qemu');p.add_argument('--server-backend',choices=('qemu','x86_64','aarch64'),default='x86_64');p.add_argument('--bytes',type=int,default=4097);a=p.parse_args()
 report=run_pair(a.client_backend,a.server_backend,a.bytes);path=ROOT/'build/network-broker-evidence.json';path.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
