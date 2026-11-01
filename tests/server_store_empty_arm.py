"""Small installed AArch64 namespace/IPC/device regression (qemu-aarch64)."""
import argparse,hashlib,json,struct,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import server_store
from messenger_journey import Guest

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    a.output.mkdir(exist_ok=False,parents=True);backing=a.output/'server.img';server_store.provision(backing)
    began=time.monotonic();g=Guest('storage','aarch64',a.output,a.image.resolve(),store=backing).start();checks=[]
    try:
        c=g.client;server_store.call(c,230);who=struct.unpack_from('<Q',c.request(2),32)[0]
        namespaces=[hashlib.sha256(('installed arm empty namespace'+str(i)).encode()).digest()for i in range(8)]
        old=[server_store.call(c,231,who,6,32768,n)[0][1]for n in namespaces]
        new=[server_store.call(c,231,who,6,32768,n)[0][1]for n in namespaces]
        assert len(set(old+new))==16
        checks.append('actual purpose2 backing mounts; all eight role6 namespaces renew without occupying extra slots')
        for h in old:
            raw=c.request(238,struct.pack('<8Q',238,h,0,0,0,0,0,1));assert struct.unpack_from('<Q',raw)[0]==1
        checks.append('old native handles are denied after fresh generation through actual installed IPC')
        report=dict(schema=1,result='pass',backend='aarch64',emulated=True,image_sha256=hashlib.sha256(a.image.read_bytes()).hexdigest(),checks=checks,elapsed_seconds=time.monotonic()-began,scope='native installed kernel/Launcher/Vault and opaque block adapter; no claim of full installed Feed or Messenger')
        (a.output/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2),flush=True)
    except BaseException as e:
        (a.output/'failure.json').write_text(json.dumps(dict(error=repr(e),checks=checks),indent=2)+'\n');raise
    finally:g.stop()
if __name__=='__main__':main()
