"""Focused native Feed UI: actual input, scoped signing, exact retry and no fallback.

This is a local UI refusal/recovery check, not the federated acceptance journey.
The host only packages native code and supplies physical input/display adapters.
"""
from __future__ import annotations
import argparse,hashlib,json,struct,sys,time,os,resource
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import feed,messenger,releases
from messenger_journey import Guest,wait,screenshot,PUB,SIGN


def ui(g,operation=791):
    raw=g.client.request(150,struct.pack('<Q8Q',g.ui,operation,0,0,0,0,0,0,1))
    return struct.unpack_from('<8Q',raw),raw[64:]


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--image',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--backend',choices=('qemu','x86_64','aarch64'),default='qemu')
    p.add_argument('--retention',action='store_true')
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    image=a.output/'guest.bin';image.write_bytes(a.image.read_bytes());a.image=image
    packages={}
    # Use existing compiled artifacts so a qualification controller cannot
    # silently rebuild a different common image or native application.
    for name,rights in [('identity',0),('feed-account',1024),('feed',799)]:
        binary=ROOT/'build/live/apps'/(name+'.bin')
        raw,_=releases.make(binary,'ui-check-'+name,'0.9.0',rights,SIGN,profile=2)
        path=a.output/(name+'.ltrel');path.write_bytes(raw);packages[name]=path
    federation=hashlib.sha256(b'Feed native UI selected home').hexdigest()
    peer=hashlib.sha256(b'Feed native UI selected permitted peer').hexdigest()
    checks=[]
    backing=None
    if a.retention:
        backing=a.output/'personal.img'
        wanted=5396132*512;soft,hard=resource.getrlimit(resource.RLIMIT_FSIZE)
        if soft!=resource.RLIM_INFINITY and soft<wanted:resource.setrlimit(resource.RLIMIT_FSIZE,(wanted,hard))
        fd=os.open(backing,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        try:os.ftruncate(fd,5396132*512)
        finally:os.close(fd)
    g=Guest('personal',a.backend,a.output,a.image.resolve(),graphical=True,vault=backing).start()
    def passed(label,**values):
        checks.append(dict(check=label,result='pass',**values));print('PASS',label,flush=True)
    def state(predicate,label):
        last=[None]
        def check():
            value=ui(g)
            if value[0]!=last[0]:print('UI',label,list(value[0]),flush=True);last[0]=value[0]
            return value if predicate(value[0]) else None
        try:return wait(check,300,label)
        except BaseException:
            (a.output/'failure.json').write_text(json.dumps(dict(stage=label,last_state=last[0]),indent=2)+'\n')
            raise
    try:
        result=feed.start(g.client,SimpleNamespace(identity=packages['identity'],owner=packages['feed-account'],ui=packages['feed'],public=PUB,federation=federation,peer=peer))
        g.ui=result['ui'];g.owner=result['owner'];g.device.chord(56,15);time.sleep(.2)
        g.device.press(60)
        fields,public=state(lambda f:f[1]==1,'native scoped Feed identity')
        assert any(public[:32]) and public[32:64].hex()==federation and public[64:96].hex()==peer,(fields,public.hex())
        passed('native graphical gesture creates separately scoped Feed identity',public_key=public[:32].hex())
        original_public=public[:32]
        if a.retention:
            objects_key=os.urandom(32);feed_key=os.urandom(32)
            # Explicit backing/domain consent is separate from Feed identity.
            unlocked=g.client.request(200,struct.pack('<8Q',200,0,3,0,0,0,0,1)+objects_key)
            assert struct.unpack_from('<Q',unlocked)[0]==0
            g.client.request(179,struct.pack('<2Q',g.owner,1))
            g.device.press(59);g.device.textASCII(feed_key.hex(),delay=.04);g.device.press(63)
            wait(lambda:ui(g,793)[0][6]==1,300,'native selected Feed record commit')
            passed('native Feed retention explicitly commits typed identity metadata with sealed key in Objects domain3')
            g.device.press(64);state(lambda f:f[1]==0,'retention lock revokes accessible author')
            g.device.press(61);g.device.textASCII(feed_key.hex(),delay=.04);g.device.press(63)
            denied,_=state(lambda f:f[1]==0 and f[6]==1,'lock revokes selected Feed retention grant')
            passed('native lock rejects recovery until fresh explicit storage authorization',state=list(denied))
            g.client.request(179,struct.pack('<2Q',g.owner,1))
            g.device.press(63)
            recovered,public=state(lambda f:f[1]==1,'native Feed sealed recovery after lock')
            assert public[:32]==original_public,(public.hex(),original_public.hex())
            passed('fresh explicit native recovery preserves Feed public identity after lock and new storage consent',public_key=public[:32].hex())
            # Public portable state contains neither a seed nor sealed key.
            g.device.press(66)
            exported=wait(lambda:(lambda f:f[1] if f[1] else None)(ui(g,793)[0]),120,'native public portable Objects object')
            raw=g.client.request(150,struct.pack('<Q8Q',g.ui,794,0,0,0,0,0,0,1));share=struct.unpack_from('<Q',raw,8)[0]
            portable=g.client.read_object(share)
            assert len(portable)==2048 and struct.unpack_from('<Q',portable)[0]==0x3154524f5046544c
            assert feed_key not in portable and objects_key not in portable and portable[32:64]==original_public
            passed('explicit native public portable export creates scoped immutable Objects object without keys or sealed private identity',sha256=hashlib.sha256(portable).hexdigest(),bytes=len(portable))
            (a.output/'approved-public-profile.bin').write_bytes(portable)
            g.device.press(1)
        g.device.press(30) # Explicit home + permitted peer audience.
        time.sleep(.1);g.device.press(61)
        text='Project updates keep original signatures and explicit audiences.\nReply to discuss the exact release before adding or forking it.'
        g.device.textASCII(text,delay=.03)
        state(lambda f:f[2]==1 and f[3]==len(text),'native compose input')
        g.device.press(62);state(lambda f:f[2]==9,'exact publication preview')
        g.device.press(63)
        failure,_=state(lambda f:f[5]==8 and f[6]==14,'required-mode1 refusal')
        passed('native signing and staged publication report unavailable when required route is absent; no direct fallback',state=list(failure))
        g.device.press(61)
        refused,_=state(lambda f:f[2]==0 and f[4]==13,'uncertain outbox blocks new draft')
        passed('signed uncertain publication remains an exact retry; new draft does not replace it',state=list(refused))
        frame=screenshot(g,'unavailable')
        g.device.press(59);g.device.press(64) # F12 then F6: lock.
        locked,_=state(lambda f:f[1]==0,'native Feed lock')
        passed('native lock clears publishing identity independently from Objects or Messenger',state=list(locked),frame_sha256=frame)
        if a.retention:
            g.stop()
            g=Guest('destination',a.backend,a.output,a.image.resolve(),graphical=True).start()
            result=feed.start(g.client,SimpleNamespace(identity=packages['identity'],owner=packages['feed-account'],ui=packages['feed'],public=PUB,federation=peer,peer=federation))
            g.ui=result['ui'];g.owner=result['owner'];g.device.chord(56,15);time.sleep(.2)
            candidate=g.client.import_object(portable,6)
            delegated=g.client.objects(6,candidate,g.ui,1)[0][1]
            raw=g.client.request(150,struct.pack('<Q8Q',g.ui,792,delegated,0,0,0,0,0,1))
            assert struct.unpack_from('<Q',raw)[0]==0
            g.device.press(59);g.device.press(67)
            state(lambda f:f[4]==50,'explicit native portable profile import')
            g.device.press(1);g.device.press(60)
            restored,new_public=state(lambda f:f[1]==1,'new destination identity admission')
            assert new_public[:32]!=original_public and new_public[32:64].hex()==peer
            passed('with original personal guest offline, approved public Objects state imports under a freshly authorized destination-scoped identity',source_public=original_public.hex(),destination_public=new_public[:32].hex(),linked_identity_claim=False)
        report=dict(schema=1,backend=a.backend,aarch64_emulated=a.backend=='aarch64',image_sha256=hashlib.sha256(a.image.read_bytes()).hexdigest(),checks=checks,
                    packages={n:dict(sha256=hashlib.sha256(v.read_bytes()).hexdigest(),release_id=releases.inspect(v.read_bytes())['release_id'])for n,v in packages.items()},
                    limitations=['No connected federation or successful publication is claimed by this focused refusal check.','Retention and public portability are qualified only when --retention is selected.','Whole backing replacement lacks an external freshness anchor.'])
        (a.output/'evidence.json').write_text(json.dumps(report,indent=2)+'\n')
    finally:g.stop()

if __name__=='__main__':main()
