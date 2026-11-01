"""Native eight-namespace permits survive exact consumer replacement.

The tested owner is the real installed federation package before configuration.
No host storage mutation follows opaque provisioning; all grants use Launcher.
"""
import argparse, hashlib, json, struct, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'tools'), str(ROOT/'tests')]
import feed, messenger, server_store as store
from messenger_journey import Guest, PUB

def refused(c,op,h=0,a=0,b=0,data=b'',status=1):
    raw=c.request(op,struct.pack('<8Q',op,h,a,b,0,0,0,1)+data)
    assert struct.unpack_from('<Q',raw)[0]==status,(op,raw[:64].hex())

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--image',type=Path,required=True)
    p.add_argument('--release',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    backing=a.output/'operator.img';store.provision(backing)
    g=Guest('operator','qemu',a.output,a.image.resolve(),store=backing).start()
    checks=[]
    try:
        c=g.client;store.call(c,230)
        owner,_=messenger.install(c,a.release,PUB,3072)
        ns=[hashlib.sha256(('native empty namespace'+str(i)).encode()).digest()for i in range(8)]
        old=[store.call(c,231,owner,6,131072,n)[0][1]for n in ns]
        renewed=[store.call(c,231,owner,6,131072,n)[0][1]for n in ns]
        assert len(set(old+renewed))==16
        checks.append('all eight uncommitted namespaces can be repermitted without consuming extra slots; every handle is fresh')
        for h in old:refused(c,239,h)
        checks.append('superseded handles cannot revoke renewed grants')
        c.request(26,struct.pack('<Q',owner))
        fresh,_=feed.install_or_launch(c,a.release,PUB,3072)
        assert fresh!=owner
        current=[store.call(c,231,fresh,6,131072,n)[0][1]for n in ns]
        assert len(set(old+renewed+current))==24
        for h in renewed:refused(c,239,h)
        checks.append('dead exact consumer grants are reclaimed and replacement receives fresh handles for all eight namespaces')
        refused(c,231,fresh,6,131072,hashlib.sha256(b'ninth namespace').digest(),status=4)
        checks.append('ninth distinct live namespace is refused at finite capacity')
        c.request(26,struct.pack('<Q',fresh));launcher=messenger.launcher(c)
        store.call(c,231,launcher,6,131072,hashlib.sha256(b'new purpose after consumer death').digest())
        checks.append('empty namespace slots are reusable after consumer death without restarting storage')
        report=dict(schema=1,result='pass',checks=checks,image_sha256=hashlib.sha256(a.image.read_bytes()).hexdigest())
        (a.output/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2),flush=True)
    except BaseException as e:
        (a.output/'failure.json').write_text(json.dumps(dict(error=repr(e),checks=checks),indent=2)+'\n');raise
    finally:g.stop()
if __name__=='__main__':main()
