"""Continue native Feed with long text, concurrent readers, follows, and reply.

All content is entered through the native graphical application's input device.
The controller observes public native statuses and compares committed bytes.
"""
import argparse,hashlib,json,struct,sys,time,concurrent.futures
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import feed,identity,releases,onion_route as route
from messenger_journey import Guest,PUB,wait,screenshot

def ui(g,op=791):
    raw=g.client.request(150,struct.pack('<Q8Q',g.ui,op,0,0,0,0,0,0,1))
    return struct.unpack_from('<8Q',raw),raw[64:]

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--attach',type=Path,required=True);p.add_argument('--packages',type=Path,required=True);a=p.parse_args()
    out=a.attach.resolve();statefile=out/'continuation.json';state=json.loads(statefile.read_text());bundle=a.packages.resolve();checks=[];times={};started=time.monotonic();allactors=[]
    feds=[state['personal']['federation'],state['personal']['selected_peer']]
    def attach(i,graphical=False):
        g=Guest('node'+str(i),'qemu',out,out/'guest.bin',graphical=graphical).attach(None);allactors.append(g);return g
    author=attach(0,True);author.ui=state['personal']['ui'];author.owner=state['personal']['owner'];alpha=attach(4);beta=attach(5);exitrelay=attach(3)
    def accepted(n):return feed.invoke(alpha.client,491,action=8)[0][1]>=n
    def replicated(n):return feed.invoke(beta.client,491,action=8)[0][1]>=n
    def body_from(g,event_id,length):
        chunks=[]
        for offset in range(0,length,512):
            _,payload=feed.invoke(g.client,491,action=6,offset=offset,count=min(512,length-offset),data=event_id)
            chunks.append(payload)
        return b''.join(chunks)
    def publish(g,text,key=61):
        wait(lambda:ui(g)[0][5] in(0,6,7),180,'native previous publication reconciled')
        g.device.press(key);wait(lambda:ui(g)[0][2] in(1,6,7),60,'native compose mode')
        g.device.textASCII(text,delay=.035)
        wait(lambda:ui(g)[0][3]==len(text),120,'native complete ordinary text input')
        g.device.press(62);wait(lambda:ui(g)[0][2]==9,60,'native content preview');g.device.press(63)
    def newclient(i,home):
        record=state.get('clients',{}).get(str(i))
        if record:
            g=Guest('node'+str(i),'qemu',out,out/'guest.bin',graphical=True).attach(None)
        else:
            g=Guest('node'+str(i),'qemu',out,out/'guest.bin',graphical=True).start()
            for slot,j in enumerate((1,2,3,4+home)):route.enroll(g.client,slot,(out/f'node{j}.certificate').read_bytes())
            record=feed.start(g.client,SimpleNamespace(identity=bundle/'identity.ltrel',owner=bundle/'feed-account.ltrel',ui=bundle/'feed.ltrel',public=PUB,federation=feds[home],peer=feds[1-home]))
            route.route(g.client,31);wait(lambda:route.route(g.client,32)[0][2]==3,240,'independent client circuit')
            route.route(g.client,38,h=3,a=21+i,b=record['owner'],c=1048576,d=4096);wait(lambda:route.route(g.client,41)[0][2]==3,240,'independent protected Feed terminal')
            state.setdefault('clients',{})[str(i)]=record;statefile.write_text(json.dumps(state,indent=2)+'\n')
        allactors.append(g);g.ui=record['ui'];g.owner=record['owner'];g.device.chord(56,15);time.sleep(.2)
        if not ui(g)[0][1]:g.device.press(60);wait(lambda:ui(g)[0][1]!=0,180,'independent scoped author')
        print('native independent client admitted',i,record,flush=True);return g
    try:
        # The same exit relay admits FeedB while existing FeedA circuits stay up.
        if not state.get('exit_peer_beta'):
            route.enroll(exitrelay.client,1,(out/'node5.certificate').read_bytes());state['exit_peer_beta']=True;statefile.write_text(json.dumps(state,indent=2)+'\n')
        longtext=('Release review should record the exact project root, the original publisher signature, and the admission policy used by each federation. A Feed card helps collaborators find that evidence, but the post author does not become the project maintainer. Before adding a release to Library or forking its source, each person still checks the current local decision and chooses the existing project action.\n\n'
                  'Our group keeps discussion scoped to the two selected federations. Replies carry their causal parent and the same explicit audience choice. The receiving operator can apply its own moderation policy while preserving the original signed event. A local block remains a personal choice even when an appeal reverses an operator decision. Reports stay with their intended federation and are not copied into the public timeline.\n\n'
                  'Longer project notes need checked chunked access rather than a truncated preview. If a transfer pauses, another client should still send Messenger text, inspect a project, and continue ordinary input. After a restart, a committed event should be served from the operator backing, and an uncertain publication should retry its exact signed commitment. These are the practical boundaries this release review is exercising.')
        assert len(longtext)>1024
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            reader_job=pool.submit(newclient,6,1)
            if not state.get('long_post'):
                publish(author,longtext);wait(lambda:accepted(2),240,'native long post durable');wait(lambda:replicated(2),240,'native long post replicated');state['long_post']=dict(bytes=len(longtext),sha256=hashlib.sha256(longtext.encode()).hexdigest());statefile.write_text(json.dumps(state,indent=2)+'\n');print('PASS native useful long post',state['long_post'],flush=True)
            reader=reader_job.result()
        _,longrow=feed.invoke(alpha.client,491,action=5,handle=1)
        assert body_from(alpha,longrow[:32],len(longtext))==longtext.encode()
        assert body_from(beta,longrow[:32],len(longtext))==longtext.encode()
        times['long_and_second_client_seconds']=time.monotonic()-started;checks.append('Useful long post exceeds one native payload and is committed/replicated while a second independent client joins')
        # Read the original author post using native signature and full-body hash
        # validation before the GUI renders it, then follow and reply natively.
        reader.device.press(104);wait(lambda:ui(reader)[0][4]==15,180,'native cross federation read complete')
        selected=ui(reader,795)[1];assert len(selected)==512 and selected[:32].hex()==json.loads((out/'checkpoint.json').read_text())['event_id']
        reader.device.press(65);wait(lambda:ui(reader)[0][4]==17,120,'native local follow');reader.device.press(30);time.sleep(.3)
        if not state.get('reply'):
            publish(reader,'I read the original release discussion from the other federation. Keep the signed root and current admission separate from this reply.',64)
            wait(lambda:feed.invoke(beta.client,491,action=8)[0][1]>=3,240,'native reply durable on beta');wait(lambda:accepted(3),240,'native reply replicated to alpha');state['reply']=True;statefile.write_text(json.dumps(state,indent=2)+'\n')
        checks.append('Independent native client reads permitted cross federation post, follows its author locally, and replies across signed audience')
        third=newclient(7,0)
        for g in(author,reader,third):assert route.route(g.client,41)[0][2]==3
        checks.append('Three independent personal Feed clients remain concurrently admitted; two share same relay path and destination alpha without operator handoffs')
        author.device.press(104);wait(lambda:ui(author)[0][4]==15,180,'original author still reads while other clients admitted')
        images={g.name:screenshot(g,'community')for g in(author,reader,third)}
        report=dict(schema=1,result='pass',image_sha256=hashlib.sha256((out/'guest.bin').read_bytes()).hexdigest(),packages={n:releases.inspect((bundle/(n+'.ltrel')).read_bytes())['release_id']for n in('identity','feed-account','feed','feed-federation')},checks=checks,times=times,long_post=state['long_post'],frames=images,clients={k:v for k,v in state['clients'].items()},scope='Local all-QEMU connected continuation; moderation, project action and full contention remain separately pending.')
        (out/'community.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2),flush=True)
    except BaseException as error:
        (out/'community-failure.json').write_text(json.dumps(dict(error=repr(error),checks=checks,times=times,state=state),indent=2)+'\n');raise
    finally:
        for g in allactors:
            if g.client:g.client.close()
            if g.device:g.device.close()
if __name__=='__main__':main()
