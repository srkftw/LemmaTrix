"""Two or three authenticated guest relationships over separate TCP endpoints.

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

def run(client_backend='qemu',server_backend='x86_64',library_profile=False,image=None,restart_check=False,connections=3,payload_bytes=4097):
 if connections not in (2,3) or not 1<=payload_bytes<=4097:raise ValueError('select two/three relationships and1..4097 bytes')
 if restart_check and connections!=3:raise ValueError('restart check uses the full three-relationship profile')
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
   for slot in range(connections):
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
   def authenticated():return all(network.status(c,slot)['endpoint_authenticated'] for c in clients for slot in range(connections))
   wait(authenticated,600)
   roots=[hashlib.sha256(b'explicit immutable scope'+bytes([i])).digest() for i in range(connections)]
   grants=[[],[]]
   for index,c in enumerate(clients):
    for slot,(client_id,server_id,service_id) in enumerate(records):
     peer=server_id if index==0 else client_id
     f,_=network.call(c,2,a=3,b=3,c=32768,d=8192,e=100000,data=peer+service_id+roots[slot]+struct.pack('<QQ',operation,0x1000+slot),slot=slot)
     grants[index].append(f[1])
     # A response must not ambiguously select another owner/operation grant.
     f,_=network.call(c,2,a=2,b=3,c=32768,d=8192,e=100000,data=peer+service_id+roots[slot]+struct.pack('<QQ',operation,0x1000+slot),slot=slot,allow_error=True)
     assert f[0]==4,('duplicate response scope admitted',slot,f)
   paused=connections-2;active=connections-1
   f,_=network.call(clients[0],6,grants[0][paused],slot=active,allow_error=True);assert f[0]==3,'cross-context local handle accepted'
   payloads=[bytes((j*179+slot)%256 for j in range(payload_bytes)) for slot in range(connections)]
   received=[bytearray() for _ in range(connections)]
   first_jobs=[]
   for offset in range(0,payload_bytes,700):
    jobs=[]
    for slot in range(connections):
     f,_=network.call(clients[0],3,grants[0][slot],a=operation,b=offset+1,data=payloads[slot][offset:offset+700],slot=slot);jobs.append(f[1])
    if offset==0:first_jobs=jobs[:]
    for slot in range(connections):
     wait(lambda:network.call(clients[0],4,jobs[slot],slot=slot)[0][2]==3)
     def take():
      f,data=network.call(clients[1],6,grants[1][slot],slot=slot,allow_error=True)
      if f[0]==6:return None
      assert f[0]==0 and f[3]==offset+1,('authenticated request binding',f)
      return data
     received[slot].extend(wait(take))
   assert received==payloads,'cross-session bytes or order mismatch'
   # Fill one relationship's four-record inbox and leave that consumer paused.
   # Further opaque data must exert per-channel backpressure while a different
   # authenticated relationship still completes an actual content record.
   for index in range(8):
    f,_=network.call(clients[0],3,grants[0][paused],a=operation,b=9000+index,data=b'paused consumer'+bytes(685),slot=paused)
    wait(lambda:network.call(clients[0],4,f[1],slot=paused)[0][2]==3)
   f,_=network.call(clients[0],3,grants[0][active],a=operation,b=9100,data=b'progress beside paused consumer',slot=active)
   wait(lambda:network.call(clients[0],4,f[1],slot=active)[0][2]==3)
   def beside_paused():
    fields,data=network.call(clients[1],6,grants[1][active],slot=active,allow_error=True)
    return data if fields[0]==0 else None
   assert wait(beside_paused)==b'progress beside paused consumer','paused peer blocked an unrelated relationship'
   network.call(clients[1],14,slot=paused)
   wait(lambda:not network.status(clients[0],paused)['endpoint_authenticated'])
   assert all(network.status(clients[0],i)['endpoint_authenticated'] for i in range(connections) if i!=paused),'unrelated relationship lost'
   f,_=network.call(clients[0],3,grants[0][paused],a=operation,b=99,data=b'stale',slot=paused,allow_error=True);assert f[0]==3,'lost epoch kept old grant'
   # Existing unrelated grants and their sessions survive the close.
   f,_=network.call(clients[0],3,grants[0][active],a=operation,b=999,data=b'surviving seed',slot=active)
   wait(lambda:network.call(clients[0],4,f[1],slot=active)[0][2]==3)
   def surviving():
    f,data=network.call(clients[1],6,grants[1][active],slot=active,allow_error=True)
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
   return {'image':image_id,'client_backend':client_backend,'server_backend':server_backend,'connections':connections,'service_operation':operation,'public_description_schema':struct.unpack_from('<Q',network.load_description(base/'peer0.service')[1],8)[0],'separate_endpoints':True,'bytes_per_connection':payload_bytes,'payload_sha256':[hashlib.sha256(p).hexdigest() for p in payloads],'paused_consumer_independent_progress':True,'stalled_records':8,'stalled_records_stage':'provider device accepted; paused consumer not drained, not client integrity acceptance','surviving_sessions':[i for i in range(connections) if i!=paused],'stale_epoch_grant':'denied','request_binding':'authenticated','duplicate_receive_scope':'denied','fresh_boot_authority':restart_result,'consumer_admission':'not tested by this transport component check'}
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
 parser=argparse.ArgumentParser();parser.add_argument('--client-backend',default='qemu');parser.add_argument('--server-backend',default='x86_64');parser.add_argument('--library-profile',action='store_true');parser.add_argument('--image',type=Path);parser.add_argument('--restart-check',action='store_true');parser.add_argument('--connections',type=int,choices=(2,3),default=3);parser.add_argument('--bytes',type=int,default=4097);parser.add_argument('--output',type=Path);args=parser.parse_args()
 result=run(args.client_backend,args.server_backend,args.library_profile,args.image,args.restart_check,args.connections,args.bytes)
 if args.output:args.output.write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps(result,indent=2))
