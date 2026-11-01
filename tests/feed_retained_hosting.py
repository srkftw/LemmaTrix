"""Prepare a native retained author for the connected hosting-migration journey.

Only public package/pin configuration, explicit native input and opaque unlock
credentials cross the host adapter. Native Identity owns the Feed author seed.
The controller exits while the guest, account owner and selected backing remain.
"""
from __future__ import annotations
import argparse,hashlib,json,os,resource,struct,sys,time
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import feed,identity,releases
import onion_route as route
from messenger_journey import Guest,PUB,wait

def status(g,op=791):
    raw=g.client.request(150,struct.pack('<Q8Q',g.ui,op,0,0,0,0,0,0,1))
    return struct.unpack_from('<8Q',raw),raw[64:]

def secret(path):
    descriptor=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    try:os.write(descriptor,os.urandom(32))
    finally:os.close(descriptor)
    return path.read_bytes()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--image',type=Path,required=True);p.add_argument('--packages',type=Path,required=True)
    p.add_argument('--operators',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();out=a.output.resolve();out.mkdir(exist_ok=False,parents=True)
    frozen=out/'guest.bin';frozen.write_bytes(a.image.read_bytes())
    backing=out/'personal.img';wanted=5396132*512
    soft,hard=resource.getrlimit(resource.RLIMIT_FSIZE)
    if soft!=resource.RLIM_INFINITY and soft<wanted:resource.setrlimit(resource.RLIMIT_FSIZE,(wanted,hard))
    descriptor=os.open(backing,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    try:os.ftruncate(descriptor,wanted)
    finally:os.close(descriptor)
    objects_key=secret(out/'objects-unlock.key');feed_key=secret(out/'feed-unlock.key')
    packages={name:(a.packages/(name+'.ltrel')).resolve()for name in ('identity','feed-account','feed')}
    alpha=hashlib.sha256(b'Campaign009 federation alpha').hexdigest()
    beta=hashlib.sha256(b'Campaign009 federation beta').hexdigest()
    g=Guest('retained','qemu',out,frozen,graphical=True,vault=backing).start()
    record=dict(schema=1,image_sha256=hashlib.sha256(frozen.read_bytes()).hexdigest(),
                packages={name:dict(path=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),release_id=releases.inspect(path.read_bytes())['release_id'])for name,path in packages.items()},
                home=alpha,peer=beta,backing=str(backing),socket=str(g.path),graphics=str(g.graphics),pid=g.process.pid,
                private_author_seed_exported=False,unlock_credentials='explicit local test unlock authority; not Feed signing seeds',checks=[])
    started=time.monotonic()
    try:
        selected=feed.start(g.client,SimpleNamespace(identity=packages['identity'],owner=packages['feed-account'],ui=packages['feed'],public=PUB,federation=alpha,peer=beta))
        g.ui=selected['ui'];g.owner=selected['owner'];record['personal']=selected
        for slot,node in enumerate((1,2,3,4)):
            certificate=(a.operators/f'node{node}.certificate').read_bytes()
            route.enroll(g.client,slot,certificate)
        g.device.chord(56,15);time.sleep(.2);g.device.press(60)
        fields,public=wait(lambda:(lambda v:v if v[0][1]else None)(status(g)),180,'native retained Alpha scoped author')
        assert public[32:64].hex()==alpha and public[64:96].hex()==beta
        record['public_key']=public[:32].hex();record['checks'].append('native UI F2 created Alpha-scoped author independently from Messenger/node keys')
        raw=g.client.request(200,struct.pack('<8Q',200,0,3,0,0,0,0,1)+objects_key)
        assert struct.unpack_from('<Q',raw)[0]==0
        g.client.request(179,struct.pack('<2Q',g.owner,1))
        g.device.press(59);g.device.textASCII(feed_key.hex(),delay=.04);g.device.press(63)
        wait(lambda:status(g,793)[0][6]==1,180,'native retained Alpha record commit')
        g.device.press(1)
        record['checks'].append('explicit native Objects-domain3 approval and masked Feed credential committed typed retained identity before any publication')
        record['result']='prepared';record['prepare_seconds']=time.monotonic()-started
        record['publication_accepted']=False;record['hosting_migration_complete']=False
        print('PREPARED',g.path,'public',record['public_key'],flush=True)
    except BaseException as error:
        record['result']='failure';record['error']=repr(error);record['processes']=identity.instances(g.client);record['native_events']=g.client.events.decode('ascii','replace')
        raise
    finally:
        (out/'prepared.json').write_text(json.dumps(record,indent=2)+'\n')
        if g.client:g.client.close()
        if g.device:g.device.close()
        if g.log:g.log.close()

if __name__=='__main__':main()
