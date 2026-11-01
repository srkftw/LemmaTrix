"""Continue the live common-image campaign with native project/account actions.

Run project and ephemeral before migrate. Select migrate only after connected
moderation and restart checks finish. Native code signs, stores and publishes;
the controller supplies public configuration, explicit unlocks and real input.
"""
from __future__ import annotations
import argparse,hashlib,json,os,struct,sys,time,traceback
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import feed
import feed_project_controls as project
from native_community_campaign import attach_campaign,feed_ui,focus_application,select_feed_route
from messenger_journey import PUB,wait,screenshot

CARD='This exact signed release is available for independent local review. Inspect its current admission before creating a new project lineage.'
MOVED='The original federation is offline. I recovered my explicitly retained publishing identity and reconciled the original signed project discussion through this willing federation before publishing this update.'


def secret(path):
    if not path.exists():
        fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        try:os.write(fd,os.urandom(32))
        finally:os.close(fd)
    value=path.read_bytes()
    if len(value)!=32:raise ValueError('explicit unlock credential32 required')
    return value


def rows(g):
    cursor=0
    for _ in range(65):
        f,p=feed.invoke(g.client,491,action=5,handle=cursor,allowed=(0,6))
        if f[0]==6:return
        assert len(p)==512 and f[1]>cursor,(f,len(p))
        yield f,p
        cursor=f[1]
    raise RuntimeError('native committed index exceeded declared64 rows')


def match(g,author,kind,content_hash):
    return next((p for _,p in rows(g)if p[144:176]==author and struct.unpack_from('<Q',p,208)[0]==kind and p[256:288]==content_hash),None)


def read_body(g,event):
    total=struct.unpack_from('<Q',event,288)[0];assert total<=16384
    result=[]
    for offset in range(0,total,512):
        _,chunk=feed.invoke(g.client,491,action=6,offset=offset,count=min(512,total-offset),data=event[:32]);result.append(chunk)
    body=b''.join(result)
    assert len(body)==total and hashlib.sha256(body).digest()==event[256:288]
    return body


def export_public(g):
    prior=feed_ui(g,793)[0][1]
    g.device.press(59);g.device.press(66)
    wait(lambda:feed_ui(g,793)[0][1]not in(0,prior),180,'explicit native public account export')
    shared,_=project.ui_call(g,g.feed_ui,794);data=g.client.read_object(shared[1])
    assert len(data)==2048 and struct.unpack_from('<Q',data)[0]==0x3154524f5046544c
    g.device.press(1)
    return data


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--attach',type=Path,required=True)
    parser.add_argument('--stage',choices=('project','migrate','ephemeral'),required=True)
    parser.add_argument('--person',choices=('alice','bob'),default='bob')
    parser.add_argument('--feed-packages',type=Path,help='exact frozen bundle required for ephemeral relaunch')
    parser.add_argument('--alpha-offline-approved',action='store_true',help='select only after connected moderation/restart checks finish')
    a=parser.parse_args();out=a.attach.resolve();evidence=out/('feed-'+a.stage+'-account.json');began=time.monotonic()
    report=dict(schema=1,stage=a.stage,checks=[],result='running')
    with attach_campaign(out)as campaign:
        state=campaign.state;actors=campaign.actors;report['configuration']=state['configuration']
        g=actors[a.person];g.ui=g.feed_ui
        alpha,beta=actors['alpha'],actors['beta'];relays=[actors['relay'+str(i)]for i in(1,2,3)]
        person=state['personal'][a.person]['feed'];home=person['federation'];peer=person['selected_peer']
        original=alpha if home==state['actors']['alpha']['feed']['federation']else beta
        destination=beta if original is alpha else alpha
        def save():evidence.write_text(json.dumps(report,indent=2)+'\n')
        def passed(label,**details):
            report['checks'].append(dict(check=label,result='pass',**details));save();print('PASS',label,flush=True)
        try:
            if a.stage=='project':
                select_feed_route(g,original,relays)
                author=feed_ui(g)[1][:32];assert any(author)
                backing=out/(g.name+'.img');assert backing.stat().st_size>=5396132*512
                objects_key=secret(out/(g.name+'.feed-objects-unlock'));feed_key=secret(out/(g.name+'.feed-author-unlock'))
                raw=g.client.request(200,struct.pack('<8Q',200,0,3,0,0,0,0,1)+objects_key);assert struct.unpack_from('<Q',raw)[0]==0
                g.client.request(179,struct.pack('<2Q',g.feed_owner,1))
                g.device.press(59);g.device.press(60);g.device.textASCII(feed_key.hex(),delay=.04);g.device.press(63)
                wait(lambda:feed_ui(g,793)[0][6]==1,180,'explicit native account retention before project publication')
                g.device.press(1)
                passed('native Feed identity retention explicitly selected in Objects domain3 before further publication',author=author.hex(),separate_from_messenger_domain2=True)
                project_dir=out/'feed-project-action'
                record=project.prepare(g,g.feed_ui,project_dir)if not (project_dir/'project.json').exists()else json.loads((project_dir/'project.json').read_text())
                def committed():
                    return next((p for _,p in rows(original)if p[144:176]==author and struct.unpack_from('<Q',p,208)[0]==3 and p[368:400].hex()==record['root']['head']),None)
                def publish_wait():return wait(committed,600,'native signed project card committed before action')
                existing=committed()
                if existing is None:
                    action=project.publish_and_fork(g,g.feed_ui,record,publish_wait=publish_wait,card_text=CARD)
                else:
                    g.device.press(104)
                    for _ in range(64):
                        wait(lambda:feed_ui(g)[0][4]in(15,16,40),180,'native complete timeline row')
                        _,chosen=feed_ui(g,795)
                        if chosen[:32]==existing[:32]:break
                        g.device.press(28)
                    else:raise RuntimeError('actual project card unavailable in selected native timeline')
                    action=project.inspect_and_fork(g,g.feed_ui,record,chosen)
                card=wait(committed,120,'original project card remains committed')
                replica=wait(lambda:next((p for _,p in rows(destination)if p[:32]==card[:32]),None),600,'original project card replicates')
                assert card==replica
                body=read_body(destination,replica)
                assert body.startswith(b'LT-CARD1 ') and body[1545:1546]==b'\n'
                original_descriptor=bytes.fromhex(body[9:1545].decode('ascii'))
                assert hashlib.sha256(original_descriptor).hexdigest()==record['descriptor_sha256']
                passed('native project card opens original Registry verification and completes useful normal Library Fork',action=action,replicated_event=card[:32].hex(),bytes=len(body),metadata_sha256=record['descriptor_sha256'],execution_consent=False)
                report['project']=record;report['card']=dict(id=card[:32].hex(),author=author.hex(),body_sha256=hashlib.sha256(body).hexdigest(),bytes=len(body));save()
                refused=project.revoke_and_refuse(g,g.feed_ui,record)
                passed('current native release revocation refuses the valid old card at the action boundary',refusal=refused)
                public=export_public(g)
                assert public[32:64]==author and public[128:160]==card[:32]
                passed('approved public export includes exact retained publication reference without signing seed or sealed key',bytes=len(public),sequence=struct.unpack_from('<Q',public,24)[0],public_sha256=hashlib.sha256(public).hexdigest())
                (out/(g.name+'.approved-feed-profile')).write_bytes(public)
            elif a.stage=='migrate':
                if not a.alpha_offline_approved:raise ValueError('finish connected moderation/restart before selecting the original federation offline')
                prior=json.loads((out/'feed-project-account.json').read_text());assert prior['result']=='pass'
                author=bytes.fromhex(prior['card']['author']);old_event=bytes.fromhex(prior['card']['id'])
                old_record=next(p for _,p in rows(destination)if p[:32]==old_event);old_body=read_body(destination,old_record)
                original.stop()
                passed('original hosting federation explicitly offline while willing replica retains original signed project metadata',event=old_event.hex(),body_sha256=hashlib.sha256(old_body).hexdigest(),original=original.name,replica=destination.name)
                select_feed_route(g,destination,relays)
                g.device.press(59);g.device.press(64)
                wait(lambda:feed_ui(g)[0][1]==0,120,'native account lock clears current author authority')
                g.client.request(179,struct.pack('<2Q',g.feed_owner,1))
                g.device.press(61);g.device.textASCII(secret(out/(g.name+'.feed-author-unlock')).hex(),delay=.04);g.device.press(63)
                wait(lambda:feed_ui(g)[0][1]==1 and feed_ui(g)[0][5]==8 and feed_ui(g,793)[0][6]==1,180,'complete retained author recovery with original federation offline')
                assert feed_ui(g)[1][:32]==author
                g.device.press(1);g.device.press(63)
                wait(lambda:feed_ui(g)[0][5]in(6,7),900,'signed bounded native author reconciliation and exact original retry')
                public=export_public(g)
                assert public[32:64]==author and public[128:160]==old_event and struct.unpack_from('<Q',public,160)[0]>1
                passed('fresh native recovery preserves scoped author and exact prior publication through selected willing federation',public=author.hex(),generation=struct.unpack_from('<Q',public,160)[0],sequence=struct.unpack_from('<Q',public,24)[0],exact_event=old_event.hex(),no_original_server_permission=True)
                g.device.press(61);g.device.textASCII(MOVED,delay=.035)
                wait(lambda:feed_ui(g)[0][3]==len(MOVED),180,'complete native hosting-move publication input')
                g.device.press(62);wait(lambda:feed_ui(g)[0][2]==9,60,'native exact move publication preview');g.device.press(63)
                event=wait(lambda:match(destination,author,1,hashlib.sha256(MOVED.encode()).digest()),600,'native new publication after fresh hosting authorization')
                assert event[304:336].hex()==home and event[336:368].hex()==peer
                assert read_body(destination,event)==MOVED.encode()
                passed('same retained federation-scoped author publishes a new checked event at willing second host while original remains offline',event=event[:32].hex(),sequence=struct.unpack_from('<Q',event,216)[0],original_still_offline=original.process.poll()is not None,new_identity_link_claim=False)
            else:
                if a.feed_packages is None:raise ValueError('--feed-packages required for exact ephemeral relaunch')
                ephemeral=actors['charlie'];focus_application(ephemeral,'feed')
                before=feed_ui(ephemeral)[1][:32];assert any(before)
                assert any(p[144:176]==before for _,p in rows(beta))
                for who in(ephemeral.feed_ui,ephemeral.feed_owner):ephemeral.client.request(26,struct.pack('<Q',who))
                configured=state['personal']['charlie']['feed']
                paths={name:a.feed_packages/(name+'.ltrel')for name in('identity','feed-account','feed')}
                selected=feed.start(ephemeral.client,SimpleNamespace(identity=paths['identity'],owner=paths['feed-account'],ui=paths['feed'],public=PUB,federation=configured['federation'],peer=configured['selected_peer']))
                ephemeral.feed_owner=selected['owner'];ephemeral.feed_ui=selected['ui']
                wait(lambda:feed_ui(ephemeral)[0][1]==0,120,'fresh ephemeral native process has no author identity')
                assert not any(feed_ui(ephemeral)[1][:32])
                assert any(p[144:176]==before for _,p in rows(beta))
                passed('no-vault Feed author is absent after native process replacement while approved published copies remain at replica',prior_public=before.hex(),current_identity_present=False,recipient_publication_retained=True)
                state['personal']['charlie']['feed']=selected
                (out/'native-actors.json').write_text(json.dumps(state,indent=2)+'\n')
            report['frame']=screenshot(g,'feed-'+a.stage);report['result']='pass';report['seconds']=time.monotonic()-began;save()
        except BaseException as error:
            report.update(result='failure-preserved-native-actors',error=repr(error),traceback=traceback.format_exc(),seconds=time.monotonic()-began)
            try:report['native_ui']=list(feed_ui(g)[0]);report['native_events']=g.client.events.decode('ascii','replace')
            except BaseException as inspection:report['inspection_error']=repr(inspection)
            save();raise

if __name__=='__main__':main()
