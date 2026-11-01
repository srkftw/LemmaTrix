"""Continue a preserved native Feed journey without resetting its operators.

Package replacement, public service selection, and physical input are host
controls. Native guests own keys, event creation, commits, and replication.
"""
import argparse, hashlib, json, os, socket, struct, sys, time
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import feed,identity,messenger,releases
from messenger_journey import Guest,PUB,wait
import onion_route as route

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--attach',type=Path,required=True);p.add_argument('--packages',type=Path,required=True)
    p.add_argument('--replace-apps',action='store_true');a=p.parse_args()
    out=a.attach.resolve();packages={n:(a.packages/(n+'.ltrel')).resolve() for n in ('identity','feed-account','feed','feed-federation')}
    feds=[hashlib.sha256(b'Campaign009 federation alpha').digest(),hashlib.sha256(b'Campaign009 federation beta').digest()]
    actors=[Guest('node'+str(i),'qemu',out,out/'guest.bin',graphical=i==0).attach(None) for i in range(6)]
    manifest=out/'continuation.json';state=json.loads(manifest.read_text()) if manifest.exists() else {}
    def save():manifest.write_text(json.dumps(state,indent=2)+'\n')
    started=time.monotonic();observed=[]
    try:
        if a.replace_apps:
            if 'replacement_services' not in state:
                services=[]
                for offset,i in enumerate((4,5)):
                    old=messenger.endpoint(actors[i].client,6,490)
                    _,public=feed.invoke(actors[i].client,490,action=9)
                    moderator=public[64:96]
                    key=out/f'operator{i}.unlock'
                    if not key.exists():
                        fd=os.open(key,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
                        try:os.write(fd,os.urandom(32))
                        finally:os.close(fd)
                    feed.invoke(actors[i].client,490,action=7,data=key.read_bytes(),allowed=(0,6))
                    wait(lambda:feed.invoke(actors[i].client,490,action=6,allowed=(0,6))[0][0]==0,120,'native moderator sealed commit')
                    actors[i].client.request(26,struct.pack('<Q',old))
                    config=SimpleNamespace(release=packages['feed-federation'],identity=packages['identity'],public=PUB,namespace=hashlib.sha256(f'Campaign009 Feed store{i}'.encode()).hexdigest(),federation=feds[offset].hex(),peer=feds[1-offset].hex(),moderator=moderator.hex(),recover_key=key,events=64,bytes=917504,policy=1)
                    services.append(feed.federation_start(actors[i].client,config))
                    print('native moderator and federation recovered after package replacement',i,services[-1],flush=True)
                    state.setdefault('replaced_operator_steps',[]).append(i);save()
                state['replacement_services']=services;save()
            if 'personal' not in state:
                for row in identity.instances(actors[0].client):
                    if row[2] in (1024,799) and row[1] in (1,2,3,4):actors[0].client.request(26,struct.pack('<Q',row[0]))
                state['personal']=feed.start(actors[0].client,SimpleNamespace(identity=packages['identity'],owner=packages['feed-account'],ui=packages['feed'],public=PUB,federation=feds[0].hex(),peer=feds[1].hex()));save()
                print('native personal packages replaced',state['personal'],flush=True)
        if 'personal' not in state:raise ValueError('first continuation requires --replace-apps')
        if not state.get('listeners'):
            for actor in actors[1:]:route.route(actor.client,30)
            state['listeners']=True;save();print('native listeners running',flush=True)
        if not state.get('replication'):
            probe=socket.socket();probe.bind(('127.0.0.1',0));endpoint=f'127.0.0.1:{probe.getsockname()[1]}';probe.close()
            scope=hashlib.sha256(b'Campaign009 explicitly approved Feed replication scope').hexdigest()
            state['bulk_endpoint']=endpoint;save()
            state['replication']=[]
            for i,side in ((4,'server'),(5,'client')):
                info=feed.replication(actors[i].client,SimpleNamespace(peer=0,side=side,slot=0,scope=scope,endpoint=endpoint,bytes=16777216,rate=65536,lifetime=100000))
                state['replication'].append(info);save();print('native approved replication',i,info,flush=True)
        owner=state['personal']['owner'];ui=state['personal']['ui'];c=actors[0].client;device=actors[0].device
        if not state.get('route'):
            route.route(c,31);wait(lambda:route.route(c,32)[0][2]==3,180,'native three-hop route')
            route.route(c,38,h=3,a=21,b=owner,c=1048576,d=4096)
            wait(lambda:route.route(c,41)[0][2]==3,180,'native Feed terminal')
            state['route']=True;save();print('native protected Feed terminal ready',flush=True)
        def ui_status():
            raw=c.request(150,struct.pack('<Q8Q',ui,791,0,0,0,0,0,0,1));f=struct.unpack_from('<8Q',raw)
            diagnostic=struct.unpack_from('<8Q',raw,160) if len(raw)>=224 else None
            entry=dict(seconds=time.monotonic()-started,status=list(f),diagnostics=diagnostic)
            if not observed or observed[-1]['status']!=entry['status'] or observed[-1]['diagnostics']!=entry['diagnostics']:
                print('native UI',entry,flush=True);observed.append(entry)
            return f,raw[64:]
        if not ui_status()[0][1]:
            device.chord(56,15);time.sleep(.2);device.press(60)
            wait(lambda:ui_status()[0][1]!=0,180,'native scoped Feed author')
        if not state.get('post_submitted'):
            device.press(30);time.sleep(.2)
            body='Our group is testing the native Feed release. The approved peer federation may receive this post.'
            device.press(61);device.textASCII(body,delay=.035)
            wait(lambda:ui_status()[0][3]==len(body),120,'native draft complete')
            device.press(62);wait(lambda:ui_status()[0][2]==9,120,'native exact content preview')
            device.press(63);state['post_submitted']=True;save()
        def accepted():
            ui_status();f,_=feed.invoke(actors[4].client,491,action=8);return f if f[1]>=1 else None
        result=wait(accepted,300,'native UI signed post durable acceptance');state['accepted']=list(result);save();print('PASS native UI durable post',result,flush=True)
        def replicated():
            f,_=feed.invoke(actors[5].client,491,action=8)
            if f[1]>=1:return f
            print('native replica progress',feed.invoke(actors[4].client,490,action=3)[0],feed.invoke(actors[5].client,490,action=3)[0],flush=True)
            return None
        replica=wait(replicated,300,'original signed post native replication')
        af,ar=feed.invoke(actors[4].client,491,action=5);bf,br=feed.invoke(actors[5].client,491,action=5)
        assert ar==br,(af,bf)
        report=dict(schema=1,result='pass',image_sha256=hashlib.sha256((out/'guest.bin').read_bytes()).hexdigest(),state=state,event_id=ar[:32].hex(),original_signed_bytes_preserved=True,observed_ui=observed,total_seconds=time.monotonic()-started,backends=['qemu']*6,limits='One UI author, one post, native selected peer replication; larger connected acceptance remains separate.')
        (out/'checkpoint.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS original native signed post committed on second federation',replica,flush=True)
    except BaseException as error:
        (out/'continuation-failure.json').write_text(json.dumps(dict(error=repr(error),state=state,observed_ui=observed),indent=2)+'\n');raise
    finally:
        for g in actors:
            if g.client:g.client.close()
            if g.device:g.device.close()
        # The admitted native services intentionally survive this controller.
if __name__=='__main__':main()
