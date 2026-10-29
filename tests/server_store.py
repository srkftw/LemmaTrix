"""Real purpose2 guest transactions, >64KiB recovery and interrupted publication."""
import hashlib,json,os,signal,struct,subprocess,sys,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'));import live,server_store

class Node:
 def __init__(self,disk,directory,readonly=False):
  self.sock=directory/('readonly.sock' if readonly else 'node.sock');self.sock.unlink(missing_ok=True)
  self.log=(directory/('readonly.log' if readonly else 'node.log')).open('ab')
  args=[str(ROOT/'lt'),'run','--socket',str(self.sock),'--server-store',str(disk)]
  if readonly:args+=['--server-store-readonly']
  self.process=subprocess.Popen(args,cwd=ROOT,stdout=self.log,stderr=subprocess.STDOUT,start_new_session=True)
  deadline=time.monotonic()+75
  while not self.sock.exists():
   if self.process.poll() is not None:raise RuntimeError('node startup failed '+str(self.process.returncode))
   if time.monotonic()>deadline:raise TimeoutError('node startup timeout')
   time.sleep(.03)
  self.client=live.Client(self.sock,timeout=180)
  self.launcher=struct.unpack_from('<Q',self.client.request(2),32)[0]
 def stop(self,crash=False):
  if self.client:
   if not crash:
    try:self.client.request(70)
    except EOFError:pass
   self.client.close();self.client=None
  if self.process.poll() is None:
   if crash:os.killpg(self.process.pid,signal.SIGKILL)
   try:self.process.wait(timeout=8)
   except subprocess.TimeoutExpired:os.killpg(self.process.pid,signal.SIGKILL);self.process.wait()
  self.log.close();self.sock.unlink(missing_ok=True)

def call(c,op,h=0,a=0,b=0,data=b'',status=0):
 raw=c.request(op,struct.pack('<8Q',op,h,a,b,0,0,0,1)+data)
 assert len(raw)>=64,(op,len(raw))
 fields=struct.unpack_from('<8Q',raw)
 assert fields[0]==status,(op,fields,status)
 return fields,raw[64:]

def grant(node,namespace):
 call(node.client,230)
 return call(node.client,231,node.launcher,2,1048576,namespace)[0][1]

def publish(node,h,payload):
 call(node.client,232,h,len(payload),data=hashlib.sha256(payload).digest())
 for offset in range(0,len(payload),512):call(node.client,233,h,offset,data=payload[offset:offset+512])
 return call(node.client,234,h)[0][1]

def retrieve(node,h,payload):
 _,row=call(node.client,236,h)
 assert len(row)==512 and struct.unpack_from('<Q',row,32)[0]==len(payload)
 assert row[80:112]==hashlib.sha256(payload).digest()
 received=bytearray()
 for offset in range(0,len(payload),512):received+=call(node.client,237,h,offset,min(512,len(payload)-offset))[1]
 assert received==payload,'guest-validated stored bytes differ'
 return struct.unpack_from('<Q',row,24)[0]

def main():
 with tempfile.TemporaryDirectory(prefix='lt-server-store-') as td:
  directory=Path(td);disk=directory/'server.img';server_store.provision(disk)
  payload=bytes((i*179+23)%256 for i in range(70001));namespace=hashlib.sha256(b'explicit seed test role').digest()
  node=None
  try:
   node=Node(disk,directory);h=grant(node,namespace)
   assert publish(node,h,payload)==1;assert retrieve(node,h,payload)==1
   # Cancellation never publishes the inactive bank.
   call(node.client,232,h,len(payload),data=hashlib.sha256(payload).digest())
   for offset in range(0,4096,512):call(node.client,233,h,offset,data=payload[offset:offset+512])
   call(node.client,235,h);assert retrieve(node,h,payload)==1
   # A real inactive-bank page reaches the attached block device before crash.
   changed=bytes(x^0x5a for x in payload)
   call(node.client,232,h,len(changed),data=hashlib.sha256(changed).digest())
   for offset in range(0,8192,512):call(node.client,233,h,offset,data=changed[offset:offset+512])
   assert disk.read_bytes()[64*512:64*512+4096]==changed[:4096], 'fault point never reached actual inactive bank'
   node.stop(crash=True);node=None
   node=Node(disk,directory);call(node.client,230)
   call(node.client,236,h,status=1)
   new_h=grant(node,namespace)
   assert retrieve(node,new_h,payload)==1
   assert publish(node,new_h,changed)==2;assert retrieve(node,new_h,changed)==2
   node.stop();node=None
   node=Node(disk,directory);h=grant(node,namespace);assert retrieve(node,h,changed)==2
   node.stop();node=None
   before=hashlib.sha256(disk.read_bytes()).hexdigest()
   node=Node(disk,directory,readonly=True);h=grant(node,namespace)
   assert retrieve(node,h,changed)==2
   call(node.client,232,h,1048577,data=bytes(32),status=1)
   call(node.client,232,h,8192,data=hashlib.sha256(changed[:8192]).digest())
   for offset in range(0,4096,512):call(node.client,233,h,offset,data=changed[offset:offset+512],status=6 if offset==3584 else 0)
   assert retrieve(node,h,changed)==2
   node.stop();node=None
   assert hashlib.sha256(disk.read_bytes()).hexdigest()==before,'read-only backing changed'
   report={'backend':'qemu','guest_image_sha256':hashlib.sha256((ROOT/'build/live/guest.bin').read_bytes()).hexdigest(),'payload_bytes':len(payload),'sha256':hashlib.sha256(payload).hexdigest(),'generations':2,'restart_fresh_grant':'passed','cancel_preserves_previous':'passed','interrupted_inactive_bank_preserves_previous':'passed','committed_restart_exact_bytes':'passed','read_only_write_failure_preserves_previous':'passed','oversize_quota':'rejected','scope':'actual Lean server-store transactions through Launcher public frames; administrative setup and fault injection'}
   print(json.dumps(report,indent=2));(ROOT/'build/server-store-evidence.json').write_text(json.dumps(report,indent=2)+'\n')
  except BaseException:
   for path in directory.glob('*.log'):print(path.read_text(errors='replace')[-5000:],file=sys.stderr)
   raise
  finally:
   if node:node.stop(crash=True)
if __name__=='__main__':main()
