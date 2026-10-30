"""Three live authenticated guest relationships over independent TCP endpoints.

Uses the normal run/management portal. No guest memory writes or shared socket
replacements. Transport-only assertions are separate from consumer admission.
"""
import argparse,hashlib,json,os,signal,socket,struct,subprocess,sys,tempfile,time
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

def run(client_backend='qemu',server_backend='x86_64',library_profile=False,image=None,restart_check=False):
 image=Path(image or ROOT/'build/live/guest.bin').resolve()
 image_id=hashlib.sha256(image.read_bytes()).hexdigest()
 operation=2 if library_profile else 1
 with tempfile.TemporaryDirectory(prefix='lt-multi-peer-') as tmp:
  base=Path(tmp);processes=[];clients=[];logs=[];records=[]
  try:
   for index,backend in enumerate((client_backend,server_backend)):
    path=base/f'{index}.sock';log=(base/f'{index}.log').open('wb');logs.append(log)
    processes.append(subprocess.Popen([str(ROOT/'lt'),'run','--backend',backend,'--image',str(image),'--socket',str(path),'--network-mux'],cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,start_new_session=True))
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
   first_jobs=[]
   for offset in range(0,4097,700):
    jobs=[]
    for slot in range(3):
     f,_=network.call(clients[0],3,grants[0][slot],a=operation,b=offset+1,data=payloads[slot][offset:offset+700],slot=slot);jobs.append(f[1])
    if offset==0:first_jobs=jobs[:]
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
   restart_result='not requested'
   if restart_check:
    old_grant=grants[0][0];old_job=first_jobs[0]
    try:clients[0].request(70)
    except EOFError:pass
    clients[0].close();processes[0].wait(15)
    path=base/'fresh.sock';log=(base/'fresh.log').open('wb');logs.append(log)
    processes.append(subprocess.Popen([str(ROOT/'lt'),'run','--backend',client_backend,'--image',str(image),'--socket',str(path),'--network-mux'],cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,start_new_session=True))
    wait(path.exists,90);clients[0]=live.Client(path,timeout=180)
    network.configure(clients[0],base/'client0.credential',base/'peer0.service',slot=0)
    wait(lambda:network.call(clients[0],13,slot=0,allow_error=True)[0][0]==0)
    wait(lambda:network.status(clients[0],0)['endpoint_authenticated'],600)
    client_id,server_id,service_id=records[0]
    f,_=network.call(clients[0],2,a=3,b=3,c=32768,d=8192,e=100000,data=server_id+service_id+roots[0]+struct.pack('<QQ',operation,0x1000),slot=0)
    fresh_grant=f[1];assert fresh_grant!=old_grant,'cross-boot grant numeric alias'
    f,_=network.call(clients[0],3,fresh_grant,a=operation,b=1001,data=b'fresh selected authority',slot=0)
    fresh_job=f[1];assert fresh_job!=old_job,'cross-boot job numeric alias'
    wait(lambda:network.call(clients[0],4,fresh_job,slot=0)[0][2]==3)
    for op,h in ((6,old_grant),(4,old_job)):
     f,_=network.call(clients[0],op,h,slot=0,allow_error=True);assert f[0]==3,('old authority resolved after fresh allocation',op,f)
    restart_result=dict(old_grant=old_grant,fresh_grant=fresh_grant,old_job=old_job,fresh_job=fresh_job,stale_after_new_allocation='denied',fresh_job_state='completed')
   return {'image':image_id,'client_backend':client_backend,'server_backend':server_backend,'connections':3,'service_operation':operation,'public_description_schema':2 if library_profile else 1,'separate_endpoints':True,'bytes_per_connection':4097,'payload_sha256':[hashlib.sha256(p).hexdigest() for p in payloads],'surviving_sessions':[0,2],'stale_epoch_grant':'denied','request_binding':'authenticated','duplicate_receive_scope':'denied','fresh_boot_authority':restart_result,'consumer_admission':'not tested by this transport component check'}
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

if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('--client-backend',default='qemu');parser.add_argument('--server-backend',default='x86_64');parser.add_argument('--library-profile',action='store_true');parser.add_argument('--image',type=Path);parser.add_argument('--restart-check',action='store_true');parser.add_argument('--output',type=Path);args=parser.parse_args()
 result=run(args.client_backend,args.server_backend,args.library_profile,args.image,args.restart_check)
 if args.output:args.output.write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps(result,indent=2))
