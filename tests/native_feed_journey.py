"""Native Feed UI publishes through shared routed service and native replica.

Controllers configure public node certificates/packages and send ordinary input.
No host event signing, social database, replication loop, or policy result file.
"""
import argparse,hashlib,json,os,signal,socket,struct,sys,time
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import feed,identity,live,releases,server_store,network
from messenger_journey import Guest,PUB,SIGN,wait
from graphical_devices import DeviceInput
import onion_route as route

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,default=ROOT/'build/live/guest.bin');p.add_argument('--output',type=Path,default=ROOT/'build/native-feed-journey');p.add_argument('--keep',action='store_true');p.add_argument('--packages',type=Path,required=True);a=p.parse_args()
    out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
    image=out/'guest.bin';image.write_bytes(a.image.read_bytes())
    packages={}
    for name,rights in [('identity',0),('feed-account',1024),('feed',799),('feed-federation',3072)]:
        path=(a.packages/(name+'.ltrel')).resolve();raw=path.read_bytes();info=releases.inspect(raw)
        if info['rights']!=rights or struct.unpack_from('<Q',raw,400)[0]!=2:raise ValueError('wrong native signed Feed bundle package '+name)
        packages[name]=path
    feds=[hashlib.sha256(b'Campaign009 federation alpha').digest(),hashlib.sha256(b'Campaign009 federation beta').digest()]
    actors=[];checks=[];timings={};observed_ui=[];started=time.monotonic()
    try:
        for i in range(6):
            store=None
            if i>=4:
                store=out/f'operator{i}.img'
                if store.exists():store.unlink()
                server_store.provision(store)
            backend='qemu'
            actor=Guest(f'node{i}',backend,out,image,graphical=(i==0),store=store).start();actors.append(actor)
            if i!=0:identity.start(actor.client,packages['identity'],PUB)
        certs=[]
        for i in range(1,6):
            probe=socket.socket();probe.bind(('127.0.0.1',0));port=probe.getsockname()[1];probe.close()
            cert,pin=route.create(actors[i].client,f'127.0.0.1:{port}',f'Campaign009 native Feed independent operator{i}',7 if i<=3 else 16)
            certs.append(cert);(out/f'node{i}.certificate').write_bytes(cert)
            print('created native operator',i,flush=True)
        for slot,cert in enumerate(certs[:4]):route.enroll(actors[0].client,slot,cert)
        route.enroll(actors[1].client,0,certs[1]);route.enroll(actors[2].client,0,certs[2]);route.enroll(actors[3].client,0,certs[3])
        route.enroll(actors[4].client,0,certs[4]);route.enroll(actors[5].client,0,certs[3])
        services=[]
        for offset,i in enumerate((4,5)):
            config=SimpleNamespace(release=packages['feed-federation'],identity=packages['identity'],public=PUB,namespace=hashlib.sha256(f'Campaign009 Feed store{i}'.encode()).hexdigest(),federation=feds[offset].hex(),peer=feds[1-offset].hex(),moderator=None,events=64,bytes=917504,policy=1)
            services.append(feed.federation_start(actors[i].client,config));print('native Feed service ready',i,services[-1]['instance'],flush=True)
        personal=feed.start(actors[0].client,SimpleNamespace(identity=packages['identity'],owner=packages['feed-account'],ui=packages['feed'],public=PUB,federation=feds[0].hex(),peer=feds[1].hex()))
        for actor in actors[1:]:route.route(actor.client,30)
        # Listener setup precedes explicit bulk selection on both federations.
        scope=hashlib.sha256(b'Campaign009 explicitly approved Feed replication scope').hexdigest()
        probe=socket.socket();probe.bind(('127.0.0.1',0));bulk_endpoint=f'127.0.0.1:{probe.getsockname()[1]}';probe.close()
        for index,(i,side) in enumerate(((4,'server'),(5,'client'))):
            info=feed.replication(actors[i].client,SimpleNamespace(peer=0,side=side,slot=0,scope=scope,endpoint=bulk_endpoint,bytes=16777216,rate=65536,lifetime=100000))
            print('native replication relationship',i,info,flush=True)
        route.route(actors[0].client,31)
        wait(lambda:route.route(actors[0].client,32)[0][2]==3,300,'native Feed three-hop circuit')
        owner=personal['owner'];ui=personal['ui']
        route.route(actors[0].client,38,h=3,a=21,b=owner,c=1048576,d=4096)
        wait(lambda:route.route(actors[0].client,41)[0][2]==3,240,'native Feed protected terminal')
        checks.append('native Feed client uses selected three-hop route and authenticated role16 terminal; native mode3 replica separately approved')
        c=actors[0].client;device=actors[0].device
        def ui_status():
            raw=c.request(150,struct.pack('<Q8Q',ui,791,0,0,0,0,0,0,1));f=struct.unpack_from('<8Q',raw);observed_ui.append(dict(seconds=time.monotonic()-started,status=list(f)));del observed_ui[:-64];return f,raw[64:]
        device.click(400,140);device.press(60);time.sleep(.2)
        wait(lambda:ui_status()[0][1]!=0,120,'native Feed scoped identity creation')
        device.press(30);time.sleep(.2) # Explicit home+selected peer audience.
        body='Our group is testing the native Feed release. The approved peer federation may receive this post.'
        device.press(61);device.textASCII(body,delay=.035)
        wait(lambda:ui_status()[0][3]==len(body),120,'native draft input complete')
        device.press(62);time.sleep(.2);device.press(63)
        def accepted():
            ui_status()
            f,_=feed.invoke(actors[4].client,491,action=8)
            return f if f[1]>=1 else None
        state=wait(accepted,300,'native Feed UI publication committed');timings['first_ui_commit_seconds']=time.monotonic()-started
        print('native Feed UI committed',state,flush=True)
        checks.append('ordinary native UI gesture creates native scoped identity and signed post; content and index commit before accepted')
        def replicated():
            f,_=feed.invoke(actors[5].client,491,action=8)
            return f if f[1]>=1 else None
        replica=wait(replicated,300,'native original signed event replication');timings['first_replica_seconds']=time.monotonic()-started
        af,ar=feed.invoke(actors[4].client,491,action=5,handle=0);bf,br=feed.invoke(actors[5].client,491,action=5,handle=0)
        assert ar==br,(af,bf)
        checks.append('second native federation commits exact original signed480-byte event and content under explicit peer and signed audience')
        report=dict(schema=1,result='pass',image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),packages={name:releases.inspect(path.read_bytes()) for name,path in packages.items()},checks=checks,timings=timings,services=services,first_event_id=ar[:32].hex(),original_signed_bytes_preserved=True,backend_roles=[g.backend for g in actors],total_seconds=time.monotonic()-started,limitations='Initial connected Feed checkpoint; full multiuser Messenger/Forge/moderation/retention campaign remains separate pending work.')
        (out/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
    except BaseException as error:
        (out/'failure.json').write_text(json.dumps(dict(schema=1,error=repr(error),checks_completed=checks,timings=timings,observed_ui=observed_ui,image_sha256=hashlib.sha256(image.read_bytes()).hexdigest()),indent=2)+'\n');raise
    finally:
        if not a.keep:
            for actor in reversed(actors):actor.stop()
if __name__=='__main__':main()
