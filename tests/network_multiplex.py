"""Three live authenticated guest relationships over independent TCP endpoints.

Uses the normal run/management portal. No guest memory writes or shared socket
replacements. Transport-only assertions are separate from consumer admission.
"""
import argparse,hashlib,json,os,socket,struct,subprocess,sys,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import capsule,live,network

def wait(check,seconds=300):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  result=check()
  if result:return result
  time.sleep(.04)
 raise TimeoutError('bounded multi-peer condition did not complete')

def run(client_backend='qemu',server_backend='x86_64',library_profile=False):
 operation=2 if library_profile else 1
 with tempfile.TemporaryDirectory(prefix='lt-multi-peer-') as tmp:
  base=Path(tmp);processes=[];clients=[];logs=[];records=[]
  try:
   for index,backend in enumerate((client_backend,server_backend)):
    path=base/f'{index}.sock';log=(base/f'{index}.log').open('wb');logs.append(log)
    processes.append(subprocess.Popen([str(ROOT/'lt'),'run','--backend',backend,'--socket',str(path),'--network-mux'],cwd=ROOT,stdout=log,stderr=subprocess.STDOUT))
    wait(path.exists,90);clients.append(live.Client(path,timeout=180))
   for slot in range(3):
    probe=socket.socket();probe.bind(('127.0.0.1',0));port=probe.getsockname()[1];probe.close()
    key=base/f'role{slot}.pem';pub=base/f'role{slot}.pub';capsule.generate_key(key,pub)
    identity=hashlib.sha256(os.getrandom(32)).digest();description=base/f'peer{slot}.service'
    details=network.create_description(key,identity,f'127.0.0.1:{port}',('library-registry' if slot==0 else 'library-seed') if library_profile else ('registry' if slot==0 else 'forge'),description)
    creds=[base/f'client{slot}.credential',base/f'server{slot}.credential']
    network.provision(*creds,identity,bytes.fromhex(details['server_id']),bytes.fromhex(details['service_id']))
    records.append((identity,bytes.fromhex(details['server_id']),bytes.fromhex(details['service_id'])))
    for index in (1,0):
     network.configure(clients[index],creds[index],description,slot=slot)
     wait(lambda:network.call(clients[index],13,slot=slot,allow_error=True)[0][0]==0)
    print('opened independent slot',slot,flush=True)
   def authenticated():return all(network.status(c,slot)['endpoint_authenticated'] for c in clients for slot in range(3))
   wait(authenticated,600)
   roots=[hashlib.sha256(b'explicit immutable scope'+bytes([i])).digest() for i in range(3)]
   grants=[[],[]]
   for index,c in enumerate(clients):
    for slot,(client_id,server_id,service_id) in enumerate(records):
     peer=server_id if index==0 else client_id
     f,_=network.call(c,2,a=3,b=3,c=32768,d=8192,e=100000,data=peer+service_id+roots[slot]+struct.pack('<QQ',operation,0x1000+slot),slot=slot)
     grants[index].append(f[1])
     # A response must not ambiguously select another owner/operation grant.
     f,_=network.call(c,2,a=2,b=3,c=32768,d=8192,e=100000,data=peer+service_id+roots[slot]+struct.pack('<QQ',operation,0x1000+slot),slot=slot,allow_error=True)
     assert f[0]==4,('duplicate response scope admitted',slot,f)
   f,_=network.call(clients[0],6,grants[0][1],slot=2,allow_error=True);assert f[0]==3,'cross-context local handle accepted'
   payloads=[bytes((j*179+slot)%256 for j in range(4097)) for slot in range(3)]
   received=[bytearray() for _ in range(3)]
   for offset in range(0,4097,700):
    jobs=[]
    for slot in range(3):
     f,_=network.call(clients[0],3,grants[0][slot],a=operation,b=offset+1,data=payloads[slot][offset:offset+700],slot=slot);jobs.append(f[1])
    for slot in range(3):
     wait(lambda:network.call(clients[0],4,jobs[slot],slot=slot)[0][2]==3)
     def take():
      f,data=network.call(clients[1],6,grants[1][slot],slot=slot,allow_error=True)
      if f[0]==6:return None
      assert f[0]==0 and f[3]==offset+1,('authenticated request binding',f)
      return data
     received[slot].extend(wait(take))
   assert received==payloads,'cross-session bytes or order mismatch'
   before=[network.status(clients[0],i) for i in range(3)]
   network.call(clients[1],14,slot=1)
   wait(lambda:not network.status(clients[0],1)['endpoint_authenticated'])
   assert network.status(clients[0],0)['endpoint_authenticated'] and network.status(clients[0],2)['endpoint_authenticated'],'unrelated relationship lost'
   f,_=network.call(clients[0],3,grants[0][1],a=operation,b=99,data=b'stale',slot=1,allow_error=True);assert f[0]==3,'lost epoch kept old grant'
   # Existing unrelated grants and their sessions survive the close.
   f,_=network.call(clients[0],3,grants[0][2],a=operation,b=999,data=b'surviving seed',slot=2)
   wait(lambda:network.call(clients[0],4,f[1],slot=2)[0][2]==3)
   def surviving():
    f,data=network.call(clients[1],6,grants[1][2],slot=2,allow_error=True)
    return data if f[0]==0 else None
   assert wait(surviving)==b'surviving seed'
   return {'client_backend':client_backend,'server_backend':server_backend,'connections':3,'service_operation':operation,'public_description_schema':2 if library_profile else 1,'separate_endpoints':True,'bytes_per_connection':4097,'payload_sha256':[hashlib.sha256(p).hexdigest() for p in payloads],'surviving_sessions':[0,2],'stale_epoch_grant':'denied','request_binding':'authenticated','duplicate_receive_scope':'denied','consumer_admission':'not tested by this transport component check'}
  finally:
   for c in clients:c.close()
   for p in processes:p.terminate()
   for p in processes:
    try:p.wait(5)
    except subprocess.TimeoutExpired:p.kill();p.wait()
   for log in logs:log.close()

if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('--client-backend',default='qemu');parser.add_argument('--server-backend',default='x86_64');parser.add_argument('--library-profile',action='store_true');args=parser.parse_args()
 print(json.dumps(run(args.client_backend,args.server_backend,args.library_profile),indent=2))
