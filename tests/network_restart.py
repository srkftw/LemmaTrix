"""Broker-restart stale local grant/job generation check through normal IPC."""
import hashlib,os,socket,struct,subprocess,sys,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import live,network

def main():
 with tempfile.TemporaryDirectory(prefix='lt-network-restart-') as tmp:
  base=Path(tmp);portal=base/'portal.sock';probe=socket.socket();probe.bind(('127.0.0.1',0));port=probe.getsockname()[1];probe.close()
  log=(base/'transport.log').open('wb');process=subprocess.Popen([str(ROOT/'lt'),'run','--backend','qemu','--socket',str(portal),'--network-listen',f'127.0.0.1:{port}'],stdout=log,stderr=subprocess.STDOUT,cwd=ROOT);client=None
  try:
   end=time.monotonic()+90
   while not portal.exists():
    if process.poll() is not None:raise RuntimeError('guest boot failed')
    if time.monotonic()>end:raise TimeoutError('guest boot')
    time.sleep(.03)
   client=live.Client(portal,timeout=180);pins=[hashlib.sha256(os.getrandom(32)).digest() for _ in range(4)];credentials=[base/'client',base/'server'];network.provision(*credentials,*pins[:3]);root=pins[3]
   def provision():
    network.configure(client,credentials[0]);grant=network.call(client,2,a=1,b=3,c=8192,d=8192,e=100000,data=pins[1]+pins[2]+root+struct.pack('<Q',1))[0][1]
    job=network.call(client,3,grant,a=1,data=b'only queued until authenticated')[0][1]
    return grant,job
   old_grant,old_job=provision();processes=client.request(2);broker=struct.unpack_from('<Q',processes,6*32)[0]
   client.request(33,struct.pack('<Q',broker));new_grant,new_job=provision()
   assert old_grant!=new_grant and old_job!=new_job,'broker restart aliased local authority'
   assert old_grant!=old_job and new_grant!=new_job,'grant/job handle namespaces alias'
   f,_=network.call(client,3,old_grant,a=1,data=b'stale',allow_error=True);assert f[0]==3,('old grant named new authority',f)
   f,_=network.call(client,4,old_job,allow_error=True);assert f[0]==3,('old job named new completion',f)
   network.call(client,5,new_job)
   print('broker restart keeps old grant/job IDs stale; type and incarnation namespaces: PASS')
  finally:
   if client:client.close()
   process.terminate()
   try:process.wait(5)
   except subprocess.TimeoutExpired:process.kill();process.wait()
   log.close()
if __name__=='__main__':main()
