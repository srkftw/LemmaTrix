"""Committed native ServerStore reads during an admitted partial write."""
import argparse,hashlib,json,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import server_store as store
from messenger_journey import Guest

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--backend',choices=['qemu','x86_64','aarch64'],default='qemu');a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
 backing=a.output/'operator.img';store.provision(backing);g=Guest('store',a.backend,a.output,a.image.resolve(),store=backing).start();checks=[]
 try:
  c=g.client;store.call(c,230);print('native mounted',flush=True);launcher=struct.unpack_from('<Q',c.request(2),32)[0]
  grants=[store.call(c,231,launcher,6,32768,hashlib.sha256(('interleaved namespace'+str(i)).encode()).digest())[0][1] for i in range(2)]
  initial=(ROOT/'Guest/ServerSDK.lean').read_bytes();new=(ROOT/'Guest/ServerStore.lean').read_bytes()
  def write(h,body):
   store.call(c,232,h,len(body),data=hashlib.sha256(body).digest())
   for offset in range(0,len(body),512):store.call(c,233,h,offset,data=body[offset:offset+512])
   return store.call(c,234,h)[0][1]
  write(grants[0],initial);write(grants[1],initial);print('two native committed namespaces',flush=True)
  store.call(c,232,grants[0],len(new),data=hashlib.sha256(new).digest())
  for offset in range(0,len(new),512):
   store.call(c,233,grants[0],offset,data=new[offset:offset+512])
   # Same namespace keeps serving its old committed generation; another
   # namespace read must not replace the writer's partial page or index.
   for h in grants:
    assert store.call(c,237,h,0,min(512,len(initial)))[1]==initial[:512]
  generation=store.call(c,234,grants[0])[0][1];assert generation==2,generation
  restored=b''.join(store.call(c,237,grants[0],off,min(512,len(new)-off))[1] for off in range(0,len(new),512));assert restored==new
  checks.append('same and independent namespace reads preserve partial writer page, page hashes, commit and exact bytes')
  assert store.call(c,237,grants[1],0,512)[1]==initial[:512]
  checks.append('other namespace committed generation remains unchanged')
  g.stop();g.start();c=g.client;store.call(c,230)
  launcher=struct.unpack_from('<Q',c.request(2),32)[0]
  fresh=store.call(c,231,launcher,6,32768,hashlib.sha256(b'interleaved namespace0').digest())[0][1]
  restored=b''.join(store.call(c,237,fresh,off,min(512,len(new)-off))[1] for off in range(0,len(new),512));assert restored==new
  checks.append('role6 namespaces recover after operator restart with fresh grants and exact committed bytes')
  report=dict(schema=1,backend=a.backend,aarch64_emulated=a.backend=='aarch64',image_sha256=hashlib.sha256(a.image.read_bytes()).hexdigest(),checks=checks,committed_bytes=len(new),generation=generation)
  (a.output/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2),flush=True)
 except BaseException as e:
  (a.output/'failure.json').write_text(json.dumps(dict(error=repr(e),checks=checks,image_sha256=hashlib.sha256(a.image.read_bytes()).hexdigest()),indent=2)+'\n');raise
 finally:g.stop()
if __name__=='__main__':main()
