"""Native kernel async IPC: interleaved UI RPCs, revocation and cancellation."""
import argparse,contextlib,hashlib,json,os,signal,struct,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools')]
import live,messenger,releases,nodes
ERROR=2**64-1

def main():
 p=argparse.ArgumentParser();p.add_argument('--image',type=Path,required=True);p.add_argument('--backend',choices=['qemu','x86_64','aarch64'],default='qemu');p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 folder=a.output.resolve();folder.mkdir(parents=True,exist_ok=False);image=folder/'guest.bin';image.write_bytes(a.image.read_bytes());sock=folder/'guest.sock';log=(folder/'guest.log').open('wb');c=proc=None;checks=[]
 def call(who,op):return struct.unpack_from('<8Q',c.request(150,struct.pack('<Q8Q',who,op,0,0,0,0,0,0,1)))
 def passed(n):checks.append(n);print('PASS',n,flush=True)
 try:
  proc=subprocess.Popen([str(ROOT/'lt'),'run','--backend',a.backend,'--image',str(image),'--socket',str(sock)],cwd=ROOT,stdout=log,stderr=log,start_new_session=True)
  deadline=time.monotonic()+360
  while not sock.exists():
   if proc.poll() is not None or time.monotonic()>deadline:raise RuntimeError('guest startup failure')
   time.sleep(.05)
  c=live.Client(sock,timeout=600)
  def install(name):
   raw,_=releases.make(ROOT/f'build/live/apps/{name}.bin',name,'1.0.0',0,ROOT/'tests/keys/development-rsa.pem',profile=2,license='NOASSERTION');path=folder/(name+'.ltrel');path.write_bytes(raw);info=releases.inspect(raw);who=nodes.start_package(c,nodes.approved_package(path,ROOT/'tests/keys/development-rsa-public.pem',info['release_id'],0),raw);return who,bytes.fromhex(info['release_id'])
  owner,sid=install('async-owner');client,cid=install('async-client');generation=messenger.bind(c,2,owner,client,420,sid,cid)
  token=call(client,900)[1];assert 0<token<ERROR
  # The caller can answer independent management RPCs while its service sleeps.
  first=call(client,901);assert first[1] in (0,64)
  for _ in range(4):assert len(c.request(2))==384
  deadline=time.monotonic()+120
  while True:
   f=call(client,901)
   if f[1]:break
   if time.monotonic()>deadline:raise TimeoutError('completion')
   time.sleep(.05)
  assert f[1:3]==(64,0),f
  passed('nonblocking submit and completion coexist with independent caller RPCs; owner131 authenticates async token')
  assert call(client,901)[1]==ERROR
  passed('completion is collected once; stale token denied')
  assert call(client,900)[1]<ERROR
  assert call(client,902)[1]==0
  assert call(client,901)[1]==ERROR
  passed('cancellation clears request and denies stale collection')
  # Wait for the cancelled service operation to leave its wait before requeue.
  time.sleep(1.2)
  assert call(client,900)[1]<ERROR
  c.request(173,struct.pack('<4Q',2,client,420,generation))
  assert call(client,901)[1]==ERROR
  passed('binding revocation cancels queued or executing request and clears completion')
  generation=messenger.bind(c,2,owner,client,420,sid,cid)
  assert generation>0
  assert call(client,900)[1]<ERROR
  c.request(26,struct.pack('<Q',owner))
  assert call(client,901)[1]==ERROR
  passed('service teardown denies outstanding token under same caller')
  report=dict(schema=1,image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),backend=a.backend,checks=checks,result='passed',bounds=dict(outstanding_per_caller=1,completion_bytes=1024,exact_binding_generation=True))
  (folder/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
 finally:
  if c:c.close()
  if proc and proc.poll()is None:os.killpg(proc.pid,signal.SIGTERM);proc.wait(20)
  log.close()
if __name__=='__main__':main()
