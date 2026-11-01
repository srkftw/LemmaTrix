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
import feed,identity,projects
import feed_project_controls as project
from native_community_campaign import attach_campaign,feed_ui,focus_application,select_feed_route
from messenger_journey import PUB,wait,screenshot

CARD='This exact signed release is available for independent local review. Inspect its current admission before creating a new project lineage.'
MOVED='The original federation is offline. I recovered my explicitly retained publishing identity and reconciled the original signed project discussion through this willing federation before publishing this update.'


def secret(path,*,create=True):
    if not path.exists():
        if not create:raise ValueError('original explicit unlock credential is missing; refusing to replace it')
        fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        try:os.write(fd,os.urandom(32))
        finally:os.close(fd)
    value=path.read_bytes()
    if len(value)!=32:raise ValueError('explicit unlock credential32 required')
    return value


def focus_feed(g):
    # A preview probe inside the retention panel would toggle its preferences
    # choice. Escape first, on each real Alt-Tab candidate, before using F4.
    for _ in range(4):
        g.device.press(1,delay=.1);g.device.press(62,delay=.1)
        selected=feed_ui(g)[0][2]==9
        g.device.press(1,delay=.1)
        if selected:return
        g.device.chord(56,15);time.sleep(.2)
    raise RuntimeError('native Feed focus unavailable after ordinary input')


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
    focus_feed(g)
    prior=feed_ui(g,793)[0][1]
    g.device.press(59);g.device.press(66)
    wait(lambda:feed_ui(g,793)[0][1]not in(0,prior),180,'explicit native public account export')
    shared,_=project.ui_call(g,g.feed_ui,794);data=g.client.read_object(shared[1])
    assert len(data)==2048 and struct.unpack_from('<Q',data)[0]==0x3154524f5046544c
    g.device.press(1)
    return data


def settle_exact(g,operator,observed):
    """A query timeout can conservatively mark an accepted outbox uncertain.

    The ordinary F5 action retries its original commitment. This never creates
    another post, alters author intent, or directs an operator to hand off.
    """
    current=wait(lambda:(lambda f:f if f[5]in(0,6,7,8)else None)(feed_ui(g)[0]),600,'previous native publication reaches an inspectable state')
    if current[5]!=8:return
    prior=export_public(g);event_id=prior[128:160]
    if not any(event_id)or struct.unpack_from('<Q',prior,24)[0]==0:raise ValueError('uncertain native author has no exact prior event to retry')
    observed(dict(check='query/route uncertainty observed before native exact retry',status=list(current),event_id=event_id.hex()))
    g.device.press(63)
    wait(lambda:feed_ui(g)[0][5]in(6,7),900,'native F5 exact outbox retry without a replacement publication')
    f,_=feed.invoke(operator.client,491,action=4,data=event_id)
    assert f[2]>=2
    after=export_public(g)
    assert after[32:64]==prior[32:64]and after[128:160]==event_id and after[24:32]==prior[24:32]
    observed(dict(check='native exact retry reconciles original commitment after query/route uncertainty',event_id=event_id.hex(),status=list(feed_ui(g)[0]),duplicate_publication=False))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--attach',type=Path,required=True)
    parser.add_argument('--stage',choices=('project','migrate','ephemeral'),required=True)
    parser.add_argument('--person',choices=('alice','bob'),default='bob')
    parser.add_argument('--feed-packages',type=Path,help='exact frozen bundle required for ephemeral relaunch')
    parser.add_argument('--alpha-offline-approved',action='store_true',help='select only after connected moderation/restart checks finish')
    a=parser.parse_args();out=a.attach.resolve();evidence=out/('feed-'+a.stage+'-account.json');began=time.monotonic()
    initial=json.loads((out/'native-actors.json').read_text());person=initial['personal'][a.person]['feed']
    original_name='alpha'if person['federation']==initial['actors']['alpha']['feed']['federation']else'beta'
    report=json.loads(evidence.read_text())if evidence.exists()else dict(schema=1,stage=a.stage,person=a.person,checks=[],observations=[],checkpoints={})
    if report['stage']!=a.stage or report.get('person',a.person)!=a.person or report.get('configuration',initial['configuration'])!=initial['configuration']:raise ValueError('continuation provenance changed')
    if report.get('result')=='pass':
        print('Previously completed stage retained at',evidence,'; no duplicate native action');return
    attempts=report.setdefault('attempts',[])
    if evidence.exists():
        archived=evidence.with_name(evidence.stem+'.attempt-'+str(len(attempts))+'.json')
        archived.write_bytes(evidence.read_bytes())
    attempt=dict(started_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),result='running');attempts.append(attempt);report['result']='running'
    checkpoint=report.setdefault('checkpoints',{})
    skip=(original_name,)if a.stage=='migrate'and checkpoint.get('offline_intent')and not(out/(original_name+'.sock')).exists()else()
    with attach_campaign(out,skip=skip)as campaign:
        state=campaign.state;actors=campaign.actors;report['configuration']=state['configuration'];report['person']=a.person
        g=actors[a.person];g.ui=g.feed_ui
        alpha,beta=actors.get('alpha'),actors.get('beta');relays=[actors['relay'+str(i)]for i in(1,2,3)]
        person=state['personal'][a.person]['feed'];home=person['federation'];peer=person['selected_peer']
        original=actors.get(original_name);destination=actors['beta'if original_name=='alpha'else'alpha']
        def save():project.write_record(evidence,report)
        def observed(value):report.setdefault('observations',[]).append(value);save()
        def passed(label,**details):
            report['checks'].append(dict(check=label,result='pass',**details));save();print('PASS',label,flush=True)
        save()
        try:
            if a.stage=='project':
                focus_feed(g)
                select_feed_route(g,original,relays)
                settle_exact(g,original,observed)
                author=feed_ui(g)[1][:32];assert any(author)
                backing=out/(g.name+'.img');assert backing.stat().st_size>=5396132*512
                already_retained=feed_ui(g,793)[0][6]==1
                may_create=not already_retained and not checkpoint.get('retention_intent')
                objects_key=secret(out/(g.name+'.feed-objects-unlock'),create=may_create);feed_key=secret(out/(g.name+'.feed-author-unlock'),create=may_create)
                checkpoint['retention_intent']=dict(author=author.hex(),owner=g.feed_owner);save()
                if feed_ui(g,793)[0][6]!=1:
                    raw=g.client.request(200,struct.pack('<8Q',200,0,3,0,0,0,0,1)+objects_key);assert struct.unpack_from('<Q',raw)[0]==0
                    g.client.request(179,struct.pack('<2Q',g.feed_owner,1))
                    focus_feed(g);g.device.press(59);g.device.press(60);g.device.textASCII(feed_key.hex(),delay=.04);g.device.press(63)
                    wait(lambda:feed_ui(g,793)[0][6]==1,180,'explicit native account retention before project publication')
                    g.device.press(1)
                if not checkpoint.get('retained'):
                    passed('native Feed identity retention explicitly selected in Objects domain3 before further publication',author=author.hex(),separate_from_messenger_domain2=True)
                    checkpoint['retained']=True;save()
                project_dir=out/'feed-project-action'
                candidates=[r[0]for r in identity.instances(g.client)if r[1]in(1,2,3,4)and r[2]==2175]
                if len(candidates)!=1:raise ValueError('expected one existing personal Registry; no extra service will be launched')
                existing=dict(instance=candidates[0],admission_key=str((out/'registry-federation.pem').resolve()),admission_public=str((out/'registry-federation.pub').resolve()),
                              federation=state['project']['federation'],release_id=state['project']['decision']['release_id'],sequence=state['project']['decision']['sequence'])
                record=project.prepare(g,g.feed_ui,project_dir,existing=existing)if not (project_dir/'project.json').exists()else json.loads((project_dir/'project.json').read_text())
                if not project.live_instance(g.client,record['registry']):raise ValueError('existing personal Registry was replaced; explicit authority recovery required')
                def committed():
                    return next((p for _,p in rows(original)if p[144:176]==author and struct.unpack_from('<Q',p,208)[0]==3 and p[368:400].hex()==record['root']['head']),None)
                def publish_wait():return wait(committed,600,'native signed project card committed before action')
                existing=committed()
                if existing is None:
                    action=project.publish_and_fork(g,g.feed_ui,record,publish_wait=publish_wait,card_text=CARD)
                else:
                    focus_feed(g)
                    chosen=project.select_event(g,g.feed_ui,existing[:32])
                    action=project.inspect_and_fork(g,g.feed_ui,record,chosen)
                card=wait(committed,120,'original project card remains committed')
                replica=wait(lambda:next((p for _,p in rows(destination)if p[:32]==card[:32]),None),600,'original project card replicates')
                assert card==replica
                body=read_body(destination,replica)
                assert body.startswith(b'LT-CARD1 ') and body[1545:1546]==b'\n'
                original_descriptor=bytes.fromhex(body[9:1545].decode('ascii'))
                assert hashlib.sha256(original_descriptor).hexdigest()==record['descriptor_sha256']
                visible=project.show_fork_in_picker(g,g.feed_ui,record,action)
                passed('native project card opens original Registry verification and completes useful normal Library Fork',action=action,replicated_event=card[:32].hex(),bytes=len(body),metadata_sha256=record['descriptor_sha256'],execution_consent=False)
                passed('new independent local lineage is visible in the normal trusted Library/Forge project picker',visible=visible,second_fork_requested=False)
                report['project']=record;report['card']=dict(id=card[:32].hex(),author=author.hex(),body_sha256=hashlib.sha256(body).hexdigest(),bytes=len(body));save()
                refused=project.revoke_and_refuse(g,g.feed_ui,record)
                passed('current native release revocation refuses the valid old card at the action boundary',refusal=refused)
                settle_exact(g,original,observed)
                public=export_public(g)
                assert public[32:64]==author and public[128:160]==card[:32]
                passed('approved public export includes exact retained publication reference without signing seed or sealed key',bytes=len(public),sequence=struct.unpack_from('<Q',public,24)[0],public_sha256=hashlib.sha256(public).hexdigest())
                (out/(g.name+'.approved-feed-profile')).write_bytes(public)
            elif a.stage=='migrate':
                if not a.alpha_offline_approved:raise ValueError('finish connected moderation/restart before selecting the original federation offline')
                prior=json.loads((out/'feed-project-account.json').read_text());assert prior['result']=='pass'
                assert prior['configuration']==state['configuration']and prior.get('person',a.person)==a.person
                author=bytes.fromhex(prior['card']['author']);old_event=bytes.fromhex(prior['card']['id'])
                old_record=next(p for _,p in rows(destination)if p[:32]==old_event);old_body=read_body(destination,old_record)
                assert hashlib.sha256(old_body).hexdigest()==prior['card']['body_sha256']
                if original is not None:
                    checkpoint['offline_intent']=True;checkpoint['original']=original_name;save()
                    original.stop()
                assert not(out/(original_name+'.sock')).exists()
                if not checkpoint.get('offline'):
                    passed('original hosting federation explicitly offline while willing replica retains original signed project metadata',event=old_event.hex(),body_sha256=hashlib.sha256(old_body).hexdigest(),original=original_name,replica=destination.name)
                    checkpoint['offline']=True;save()
                focus_feed(g)
                select_feed_route(g,destination,relays)
                public=export_public(g)
                recovered=public[32:64]==author and struct.unpack_from('<Q',public,160)[0]>1 and feed_ui(g,793)[0][6]==1
                if not recovered:
                    if feed_ui(g)[0][1]!=0:
                        g.device.press(59);g.device.press(64)
                        wait(lambda:feed_ui(g)[0][1]==0,120,'native account lock clears current author authority')
                    g.client.request(179,struct.pack('<2Q',g.feed_owner,1))
                    focus_feed(g);g.device.press(59);g.device.press(61)
                    g.device.textASCII(secret(out/(g.name+'.feed-author-unlock'),create=False).hex(),delay=.04);g.device.press(63)
                    wait(lambda:feed_ui(g)[0][1]==1 and feed_ui(g)[0][5]==8 and feed_ui(g,793)[0][6]==1,180,'complete retained author recovery with original federation offline')
                assert feed_ui(g)[1][:32]==author
                focus_feed(g)
                settle_exact(g,destination,observed)
                public=export_public(g)
                event=match(destination,author,1,hashlib.sha256(MOVED.encode()).digest())
                assert public[32:64]==author and public[128:160]in(old_event,event[:32]if event else old_event)and struct.unpack_from('<Q',public,160)[0]>1
                if not checkpoint.get('recovered'):
                    passed('fresh native recovery preserves scoped author and exact prior publication through selected willing federation',public=author.hex(),generation=struct.unpack_from('<Q',public,160)[0],sequence=struct.unpack_from('<Q',public,24)[0],exact_event=old_event.hex(),no_original_server_permission=True)
                    checkpoint['recovered']=True;save()
                if event is None:
                    focus_feed(g);g.device.press(61)
                    wait(lambda:feed_ui(g)[0][2]==1 and feed_ui(g)[0][3]==0,120,'native fresh move publication draft')
                    g.device.textASCII(MOVED,delay=.035)
                    wait(lambda:feed_ui(g)[0][3]==len(MOVED),180,'complete native hosting-move publication input')
                    g.device.press(62);wait(lambda:feed_ui(g)[0][2]==9,60,'native exact move publication preview')
                    checkpoint['move_intent']=dict(author=author.hex(),content_sha256=hashlib.sha256(MOVED.encode()).hexdigest());save()
                    g.device.press(63)
                    event=wait(lambda:match(destination,author,1,hashlib.sha256(MOVED.encode()).digest()),600,'native new publication after fresh hosting authorization')
                assert event[304:336].hex()==home and event[336:368].hex()==peer
                assert read_body(destination,event)==MOVED.encode()
                passed('same retained federation-scoped author publishes a new checked event at willing second host while original remains offline',event=event[:32].hex(),sequence=struct.unpack_from('<Q',event,216)[0],original_still_offline=not(out/(original_name+'.sock')).exists(),new_identity_link_claim=False)
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
            report['frame']=screenshot(g,'feed-'+a.stage);report['result']='pass';report['seconds']=time.monotonic()-began;attempt.update(result='pass',seconds=report['seconds']);save()
        except BaseException as error:
            report.update(result='failure-preserved-native-actors',error=repr(error),traceback=traceback.format_exc(),seconds=time.monotonic()-began)
            attempt.update(result='failure',error=repr(error),seconds=report['seconds'])
            try:report['native_ui']=list(feed_ui(g)[0]);report['native_events']=g.client.events.decode('ascii','replace')
            except BaseException as inspection:report['inspection_error']=repr(inspection)
            save();raise

if __name__=='__main__':main()
