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
import feed,federation,identity,projects
import feed_project_controls as project
from native_community_campaign import attach_campaign,feed_ui,focus_application,select_feed_route
from native_community_policy_restart import approved_synchronous_beta_admin,check_replication_lease
from messenger_journey import PUB,wait,screenshot,net

CARD='This exact signed release is available for independent local review. Inspect its current admission before creating a new project lineage.'
MOVED='The original federation is offline. I recovered my explicitly retained publishing identity and reconciled the original signed project discussion through this willing federation before publishing this update.'
CORRECTION='Correction to my review note: a federation policy decision controls local visibility, while the original project publisher signature and current technical admission remain separate checks.'
TOMBSTONE='I withdraw this review note after publishing its correction. The author history remains signed, and recipients or external copies may retain earlier content.'


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


def export_public(g,include_preferences=None):
    focus_feed(g)
    prior=feed_ui(g,793)[0][1]
    g.device.press(59);wait(lambda:feed_ui(g)[0][2]==5,90,'native retention and portable-state panel')
    if include_preferences is not None:
        selected=int(include_preferences)
        if feed_ui(g,793)[0][5]!=selected:g.device.press(62)
        wait(lambda:feed_ui(g,793)[0][5]==selected,90,'explicit native portable preference selection')
    # Entering the panel produced a fresh notice30; successful publication of
    # this explicit export produces45. A byte-identical immutable export may
    # retain the same reference, so a changed handle alone is not completion.
    g.device.press(66)
    def published():
        status,diagnostic=feed_ui(g);reference=feed_ui(g,793)[0][1]
        observer=getattr(g,'project_observer',None)
        if observer is not None:observer('native explicit public account export',reference=reference)
        if status[4]==12 and project.complete_read(g,g.feed_ui):
            raise RuntimeError(('native public export refused',list(status)))
        return reference if reference!=0 and (reference!=prior or status[4]==45)and project.complete_read(g,g.feed_ui)else None
    wait(published,180,'explicit native public account export')
    shared,_=project.ui_call(g,g.feed_ui,794);data=g.client.read_object(shared[1])
    assert len(data)==2048 and struct.unpack_from('<Q',data)[0]==0x3154524f5046544c
    g.device.press(1)
    return data


def preference_bits(profile,subject):
    assert len(profile)==2048 and struct.unpack_from('<Q',profile,16)[0]==1
    return next((struct.unpack_from('<Q',profile,offset+8)[0]for offset in range(256,1792,48)
                 if struct.unpack_from('<Q',profile,offset)[0]==1 and profile[offset+16:offset+48]==subject),0)


def save_approved_profile(path,profile):
    fd=os.open(path,os.O_CREAT|os.O_TRUNC|os.O_WRONLY,0o600)
    try:os.fchmod(fd,0o600);os.write(fd,profile)
    finally:os.close(fd)


def retained_generation(backing):
    generations=[0]
    with backing.open('rb')as source:
        for slot in(0,1):
            source.seek((5396000+slot)*512);header=source.read(512)
            if len(header)!=512:continue
            magic,version,domain,generation,length=struct.unpack_from('<5Q',header)
            if magic==0x315243455246544c and version==1 and domain==3 and 256<=length<=32768:generations.append(generation)
    return max(generations)


def selected_feed_route(g,destination,relays,observed):
    route,_=net(g,32);terminal,pin=net(g,41)
    if route[2]==3 and terminal[2]==3 and pin==hashlib.sha256(destination.certificate).digest():
        observed(dict(check='reuse currently authenticated selected Feed relationship',route=list(route),terminal=list(terminal),destination=destination.name,pin=pin.hex(),budgets_reset=False))
        return
    select_feed_route(g,destination,relays)


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
    def reconciled():
        status=feed_ui(g)[0]
        observer=getattr(g,'project_observer',None)
        if observer is not None:observer('native exact outbox reconciliation',event_id=event_id.hex())
        return status[5]in(6,7)
    wait(reconciled,900,'native F5 exact outbox retry without a replacement publication')
    f,_=feed.invoke(operator.client,491,action=4,data=event_id)
    assert f[2]>=2
    after=export_public(g)
    assert after[32:64]==prior[32:64]and after[128:160]==event_id and after[24:32]==prior[24:32]
    observed(dict(check='native exact retry reconciles original commitment after query/route uncertainty',event_id=event_id.hex(),status=list(feed_ui(g)[0]),duplicate_publication=False))


def application_checkpoint(out,state):
    """Accept only the explicitly released partial campaign, without upgrading it."""
    path=out/'application-checkpoint-release.json';released=json.loads(path.read_text())
    assert released['result']=='application-checkpoint-released'
    assert released['configuration']==state['configuration']
    assert released['controller_stopped']and released['portals_released']and released['all_nine_running']
    assert released['event_count']==17==len(state['events'])
    assert released['event_ids']=={key:event['id']for key,event in state['events'].items()}
    assert all(released['passed'].get(key)for key in('three-feed','long-read','follow-reply'))
    return dict(path=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                qualification='partial application checkpoint; contention/reconnect not run',
                reserved_history_keys=['ordinary','long','review-13'],editable_review='review-2')


def author_actions(g,original,destination,state,author,out,observed,defer_replication=False,application_release=None):
    """Use the shipped E/T controls on one disposable own review, once each."""
    history_path=out/'reconnect-progress.json'
    if application_release is None:
        history=json.loads(history_path.read_text())
        if history.get('configuration')!=state['configuration']or not history.get('done',{}).get('history-read'):
            raise ValueError('Charlie must finish the exact common-image history read before author edits/tombstones')
    path=out/'feed-author-actions.json'
    journal=json.loads(path.read_text())if path.exists()else None
    if journal is None:
        key,event=('review-2',state['events']['review-2'])if application_release else next((key,event)for key,event in state['events'].items()if key.startswith('review-')and event['author']==author.hex()and event['kind']==1)
        assert event['author']==author.hex()and event['kind']==1
        target=bytes.fromhex(event['id'])
        original_row=next(p for _,p in rows(original)if p[:32]==target)
        replica_row=next(p for _,p in rows(destination)if p[:32]==target)
        assert original_row==replica_row and hashlib.sha256(original_row[32:]).hexdigest()==event['signed_sha256']
        assert hashlib.sha256(read_body(original,original_row)).hexdigest()==event['content_sha256']
        journal=dict(schema=1,configuration=state['configuration'],review_key=key,author=author.hex(),target=event['id'],original=original_row.hex(),
                     original_content_sha256=event['content_sha256'],actions={})
        if application_release:journal['application_checkpoint_release']=application_release
        else:journal['history_evidence_sha256']=hashlib.sha256(history_path.read_bytes()).hexdigest()
        project.write_record(path,journal)
    assert journal['configuration']==state['configuration']and journal['author']==author.hex()
    target=bytes.fromhex(journal['target']);original_row=bytes.fromhex(journal['original'])
    assert len(original_row)==512 and original_row[:32]==target and original_row[144:176]==author and struct.unpack_from('<Q',original_row,208)[0]==1
    def lookup(operator,kind,text):
        found=[p for _,p in rows(operator)if p[144:176]==author and struct.unpack_from('<Q',p,208)[0]==kind
               and p[400:432]==target and p[256:288]==hashlib.sha256(text.encode()).digest()]
        if len(found)>1:raise AssertionError('duplicate visible author action for the same exact intent')
        return found[0]if found else None
    for kind,key,text in((4,18,CORRECTION),(5,20,TOMBSTONE)):
        label='edit'if kind==4 else'tombstone'
        intent=dict(kind=kind,target=target.hex(),content_sha256=hashlib.sha256(text.encode()).hexdigest(),bytes=len(text))
        action=journal['actions'].setdefault(label,dict(intent=intent))
        assert action['intent']==intent
        project.write_record(path,journal)
        committed=lookup(original,kind,text)
        if committed is None:
            settle_exact(g,original,observed)
            focus_feed(g);chosen=project.select_event(g,g.feed_ui,target);assert chosen==original_row
            # An unsigned partial draft is recreated from the same saved intent.
            # Signed uncertainty is reconciled above before any compose gesture.
            g.device.press(key)
            wait(lambda:feed_ui(g)[0][2]==1 and feed_ui(g)[0][3]==0,120,'native own '+label+' draft')
            g.device.textASCII(text,delay=.035)
            wait(lambda:feed_ui(g)[0][3]==len(text),180,'complete native '+label+' content')
            g.device.press(62);wait(lambda:feed_ui(g)[0][2]==9,60,'exact native '+label+' preview')
            action['previewed']=True;project.write_record(path,journal)
            g.device.press(63)
            retries=[0,time.monotonic()]
            def accepted():
                result=lookup(original,kind,text)
                if result:return result
                observer=getattr(g,'project_observer',None)
                if observer is not None:observer('native author '+label+' publication',target=target.hex())
                f=feed_ui(g)[0]
                if f[2]==9 and f[3]==len(text)and f[4]in(12,14)and f[5]in(0,6,7)and retries[0]<8 and time.monotonic()-retries[1]>=3:
                    g.device.press(63);retries[:]=[retries[0]+1,time.monotonic()]
                return None
            committed=wait(accepted,600,'native signed author '+label+' committed')
        action['event']=committed[:32].hex();action['durably_accepted']=True;project.write_record(path,journal)
        def replicated():
            result=lookup(destination,kind,text)
            if result:return result
            observer=getattr(g,'project_observer',None)
            if observer is not None:observer('native author '+label+' replication',event=committed[:32].hex())
            phase=feed.invoke(original.client,490,action=3)[0]
            if phase[1]==6:raise RuntimeError(('native replication explicitly stopped',original.name,list(phase),committed[:32].hex()))
            return None
        replica=lookup(destination,kind,text)if defer_replication else wait(replicated,600,'original signed author '+label+' replicates')
        assert (replica is None or committed==replica)and hashlib.sha256(committed[32:]).digest()==committed[:32]
        assert committed[224:256]==target and committed[400:432]==target and committed[304:368]==original_row[304:368]
        assert read_body(original,committed)==text.encode()
        if replica is not None:assert read_body(destination,replica)==text.encode()
        if 'event'in action:assert action['event']==committed[:32].hex()
        action.update(event=committed[:32].hex(),signed_sha256=hashlib.sha256(committed[32:]).hexdigest(),replicated=replica is not None)
        for operator in((original,destination)if replica is not None else(original,)):
            row=next((f,p)for f,p in rows(operator)if p[:32]==target)
            assert row[1]==original_row
            if kind==4 and lookup(operator,5,TOMBSTONE)is None:
                assert hashlib.sha256(read_body(operator,row[1])).hexdigest()==journal['original_content_sha256']
            else:
                assert row[0][5]==0
                refused,_=feed.invoke(operator.client,491,action=6,count=1,data=target,allowed=(1,));assert refused[0]==1
        action['verified']=True;project.write_record(path,journal)
    return dict(target=target.hex(),review_key=journal['review_key'],original_signed_sha256=hashlib.sha256(original_row[32:]).hexdigest(),
                edit=journal['actions']['edit'],tombstone=journal['actions']['tombstone'],original_signed_bytes_unchanged=True,
                ordinary_original_body_refused_on_both_federations=all(a.get('replicated')for a in journal['actions'].values()),erasure_claim=False)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--attach',type=Path,required=True)
    parser.add_argument('--stage',choices=('project','migrate','ephemeral'),required=True)
    parser.add_argument('--person',choices=('alice','bob'),default='bob')
    parser.add_argument('--feed-packages',type=Path,help='exact frozen bundle required for ephemeral relaunch')
    parser.add_argument('--alpha-offline-approved',action='store_true',help='select only after connected moderation/restart checks finish')
    parser.add_argument('--local-project-only',action='store_true',help='preserve measured replication failure while completing unaffected native project actions; never a full pass')
    parser.add_argument('--application-checkpoint',action='store_true',help='run strict project actions after the explicit partial 17-event release, preserving later history-read targets')
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
        report.setdefault('attempt_archives',[]).append(dict(path=str(archived),sha256=hashlib.sha256(archived.read_bytes()).hexdigest()))
    for historical in('error','traceback','native_ui','native_events','inspection_error'):report.pop(historical,None)
    attempt=dict(started_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),result='running');attempts.append(attempt);report['result']='running'
    checkpoint=report.setdefault('checkpoints',{})
    release=None
    if a.application_checkpoint:
        assert a.stage=='project'and not a.local_project_only
        release=application_checkpoint(out,initial)
        report['application_checkpoint_release']=release
    elif a.stage=='project':
        completed=json.loads((out/'reconnect-progress.json').read_text())
        assert initial['done'].get('cancel')and completed.get('result')=='pass'and completed.get('done',{}).get('ephemeral'),'finish the full Charlie continuation before acquiring project/UI control'
        assert completed['configuration']==initial['configuration']
    skip=(original_name,)if a.stage=='migrate'and checkpoint.get('offline_intent')and not(out/(original_name+'.sock')).exists()else()
    with attach_campaign(out,skip=skip)as campaign,approved_synchronous_beta_admin(campaign)as control_marker:
        state=campaign.state;actors=campaign.actors;report['configuration']=state['configuration'];report['person']=a.person
        g=actors[a.person];g.ui=g.feed_ui
        alpha,beta=actors.get('alpha'),actors.get('beta');relays=[actors['relay'+str(i)]for i in(1,2,3)]
        person=state['personal'][a.person]['feed'];home=person['federation'];peer=person['selected_peer']
        original=actors.get(original_name);destination=actors['beta'if original_name=='alpha'else'alpha']
        def save():project.write_record(evidence,report)
        def observed(value):report.setdefault('observations',[]).append(value);save()
        def passed(label,**details):
            report['checks'].append(dict(check=label,result='pass',**details));save();print('PASS',label,flush=True)
        last_progress=[0.0]
        def progress(stage,**details):
            now=time.monotonic()
            if now-last_progress[0]<10:return
            last_progress[0]=now
            fields,diagnostic=feed_ui(g)
            value=dict(stage=stage,ui=list(fields),diagnostics=list(struct.unpack_from('<8Q',diagnostic,96)),route=list(net(g,32)[0]),terminal=list(net(g,41)[0]),**details)
            observed(value);print('Native progress',json.dumps(value),flush=True)
        g.project_observer=progress
        if control_marker is not None:report['management_control_boundary']=control_marker
        save()
        try:
            if a.stage=='project':
                if not checkpoint.get('replication_lease_checked'):
                    leases=checkpoint.setdefault('replication_lease_checks',{})
                    for name in('alpha','beta'):
                        if name in leases:continue
                        check=check_replication_lease(actors[name],state['actors'][name],state['bulk_endpoint'])
                        if check['renewed']:
                            project.write_record(out/'native-actors.json',state)
                            if(out/'continuations.json').exists():
                                public=json.loads((out/'continuations.json').read_text());public['actors'][name]=state['actors'][name]
                                project.write_record(out/'continuations.json',public)
                        leases[name]=check;save()
                    passed('one explicit project-stage replication lease check preserves the same durable policy and charged retry authority',operators=list(leases.values()),per_post_keepalive=False)
                    checkpoint['replication_lease_checked']=True;save()
                focus_feed(g)
                selected_feed_route(g,original,relays,observed)
                settle_exact(g,original,observed)
                author=feed_ui(g)[1][:32];assert any(author)
                backing=out/(g.name+'.img');assert backing.stat().st_size>=5396132*512
                already_retained=feed_ui(g,793)[0][6]==1
                may_create=not already_retained and not checkpoint.get('retention_intent')
                objects_key=secret(out/(g.name+'.feed-objects-unlock'),create=may_create);feed_key=secret(out/(g.name+'.feed-author-unlock'),create=may_create)
                selection=dict(identity=True,exact_signed_outbox=True,local_follows_blocks=True,unpublished_drafts=False,cached_content=False,history=False)
                checkpoint['retention_intent']=dict(author=author.hex(),owner=g.feed_owner,selection=selection);save()
                if feed_ui(g,793)[0][6]!=1 or not checkpoint.get('retention_preferences'):
                    raw=g.client.request(200,struct.pack('<8Q',200,0,3,0,0,0,0,1)+objects_key);assert struct.unpack_from('<Q',raw)[0]==0
                    g.client.request(179,struct.pack('<2Q',g.feed_owner,1))
                    focus_feed(g);g.device.press(59);wait(lambda:feed_ui(g)[0][2]==5,90,'native retention panel')
                    g.device.press(60)
                    if feed_ui(g,793)[0][5]!=1:g.device.press(62)
                    wait(lambda:feed_ui(g,793)[0][5]==1,90,'native optional follows and blocks retention approval')
                    generation=retained_generation(backing)
                    g.device.textASCII(feed_key.hex(),delay=.04);g.device.press(63)
                    wait(lambda:feed_ui(g,793)[0][6]==1 and feed_ui(g)[0][4]==46 and project.complete_read(g,g.feed_ui)and retained_generation(backing)>generation,180,'complete native account retention commit before project publication')
                    g.device.press(1)
                    checkpoint['retention_generation']=retained_generation(backing)
                    checkpoint['retention_preferences']=True;save()
                if not checkpoint.get('retained'):
                    passed('native Feed identity retention explicitly selected in Objects domain3 before further publication',author=author.hex(),separate_from_messenger_domain2=True,selection=selection,opaque_root_generation=checkpoint['retention_generation'])
                    checkpoint['retained']=True;save()
                author_scope='local'if a.local_project_only else'replicated'
                if checkpoint.get('author_actions')not in(True,'replicated',author_scope):
                    result=author_actions(g,original,destination,state,author,out,observed,defer_replication=a.local_project_only,application_release=release)
                    passed('native author edit and tombstone preserve signed history and refuse the withdrawn body',qualification=author_scope,**result)
                    checkpoint['author_actions']=author_scope;save()
                settle_exact(g,original,observed)
                project_dir=out/'feed-project-action'
                inventory=identity.instances(g.client)
                ordinary=[r for r in inventory if r[1]in(1,2,3,4)and 7<=(r[0]&255)<15]
                candidates=[r[0]for r in ordinary if r[2]==2175]
                if len(candidates)!=1:raise ValueError('expected one existing personal Registry; no extra service will be launched')
                required=[*state['personal'][a.person]['messenger'].values(),person['identity'],g.feed_owner,g.feed_ui,candidates[0]]
                assert all(any(r[0]==who for r in ordinary)for who in required)and len(ordinary)<=7
                if not checkpoint.get('ordinary_capacity'):
                    passed('existing native Messenger, Feed and selected Registry coexist with a free ordinary application slot',live_ordinary_instances=[dict(instance=r[0],rights=r[2])for r in ordinary],capacity=8,free_slots=8-len(ordinary),registry_reused=True,messenger_stopped=False)
                    checkpoint['ordinary_capacity']=True;save()
                existing=dict(instance=candidates[0],admission_key=str((out/'registry-federation.pem').resolve()),admission_public=str((out/'registry-federation.pub').resolve()),
                              federation=state['project']['federation'],release_id=state['project']['decision']['release_id'],sequence=state['project']['decision']['sequence'])
                if release and not checkpoint.get('original_admission_verified'):
                    # This earlier application checkpoint precedes Messenger's
                    # routed Forge inspection. Verify the same original public
                    # admission in the already configured native Registry.
                    source=actors['mailbox'];registries=[r[0]for r in identity.instances(source.client)if r[1]in(1,2,3,4)and 7<=(r[0]&255)<15 and r[2]==2175]
                    assert len(registries)==1
                    cursor=0;descriptor=None
                    for _ in range(16):
                        fields,value=federation.call(source.client,registries[0],6,h=cursor)
                        if value[320:352].hex()==state['project']['root']and value[128:160].hex()==existing['release_id']:
                            descriptor=value;break
                        cursor=fields[3]
                    assert descriptor is not None and len(descriptor)==768
                    assert descriptor[288:320].hex()==existing['federation']and struct.unpack_from('<Q',descriptor,48)[0]==existing['sequence']
                    fields,verified=federation.call(g.client,candidates[0],11,data=descriptor+bytes.fromhex(state['project']['root']))
                    assert fields[1]==2 and verified==descriptor
                    passed('existing native Registry verifies exact original signed release evidence before the early application checkpoint',source_registry=registries[0],selected_registry=candidates[0],descriptor_sha256=hashlib.sha256(descriptor).hexdigest(),routed_forge_qualified=False,new_registry_created=False,signature_rewritten=False)
                    checkpoint['original_admission_verified']=True;save()
                record=project.prepare(g,g.feed_ui,project_dir,existing=existing)if not (project_dir/'project.json').exists()else json.loads((project_dir/'project.json').read_text())
                if not project.live_instance(g.client,record['registry']):raise ValueError('existing personal Registry was replaced; explicit authority recovery required')
                def committed():
                    return next((p for _,p in rows(original)if p[144:176]==author and struct.unpack_from('<Q',p,208)[0]==3 and p[368:400].hex()==record['root']['head']),None)
                def publish_wait():
                    retries=[0,time.monotonic()]
                    def accepted():
                        result=committed()
                        if result:return result
                        progress('native project-card publication',root=record['root']['head'])
                        f,d=feed_ui(g)
                        if f[2]==9 and f[3]==1546+len(CARD)and f[6]==4 and f[5]in(0,6,7)and struct.unpack_from('<Q',d,104)[0]==0 and time.monotonic()-retries[1]>=3:
                            if retries[0]>=16:raise RuntimeError(('native project-card owner remains busy',list(f)))
                            g.device.press(63);retries[:]=[retries[0]+1,time.monotonic()]
                    return wait(accepted,600,'native signed project card committed before action')
                def approve_before_local_fork(chosen):
                    if not a.local_project_only:return
                    approved=out/(g.name+'.pre-fork-approved-feed-profile')
                    if approved.exists():return
                    public=export_public(g,include_preferences=True)
                    if not preference_bits(public,bytes.fromhex(record['project_id']))&4:
                        focus_feed(g);g.device.press(65)
                        wait(lambda:feed_ui(g)[0][4]==17 and project.complete_read(g,g.feed_ui),180,'native stable project follow before old-image graph quota')
                        public=export_public(g,include_preferences=True)
                    assert preference_bits(public,bytes.fromhex(record['project_id']))&4
                    assert public[128:160]==chosen[:32]
                    save_approved_profile(approved,public)
                    observed(dict(check='explicit public profile exported before old-image graph allocation',native_export=True,profile_sha256=hashlib.sha256(public).hexdigest(),preferences_sha256=hashlib.sha256(public[256:1792]).hexdigest(),retained_generation=retained_generation(backing)))
                    focus_feed(g)
                existing=committed()
                if existing is None:
                    action=project.publish_and_fork(g,g.feed_ui,record,publish_wait=publish_wait,card_text=CARD)
                else:
                    focus_feed(g)
                    chosen=project.select_event(g,g.feed_ui,existing[:32])
                    approve_before_local_fork(chosen)
                    action=project.inspect_and_fork(g,g.feed_ui,record,chosen)
                card=wait(committed,120,'original project card remains committed')
                def replica_card():return next((p for _,p in rows(destination)if p[:32]==card[:32]),None)
                replica=replica_card()if a.local_project_only else wait(replica_card,600,'original project card replicates')
                assert replica is None or card==replica
                body=read_body(destination,replica)if replica is not None else read_body(original,card)
                assert body.startswith(b'LT-CARD1 ') and body[1545:1546]==b'\n'
                original_descriptor=bytes.fromhex(body[9:1545].decode('ascii'))
                assert hashlib.sha256(original_descriptor).hexdigest()==record['descriptor_sha256']
                visible=project.show_fork_in_picker(g,g.feed_ui,record,action)
                try:public=export_public(g,include_preferences=True)
                except RuntimeError as error:
                    approved=out/(g.name+'.pre-fork-approved-feed-profile')
                    if not a.local_project_only or not str(error).startswith("('native public export refused'")or not approved.exists():raise
                    public=approved.read_bytes()
                    observed(dict(check='old-image post-Fork public export remains refused by mixed-class Objects quota',native_ui=list(feed_ui(g)[0]),error=repr(error),approved_before_fork_profile_sha256=hashlib.sha256(public).hexdigest(),post_fork_export_qualified=False))
                    g.device.press(1)
                project_id=bytes.fromhex(record['project_id'])
                if not preference_bits(public,project_id)&4:
                    focus_feed(g);project.select_event(g,g.feed_ui,card[:32]);g.device.press(65)
                    wait(lambda:feed_ui(g)[0][4]==17 and project.complete_read(g,g.feed_ui),180,'native follow of the selected stable project')
                    public=export_public(g,include_preferences=True)
                assert preference_bits(public,project_id)&4
                passed('explicit native preference selection retains and exports a local stable-project follow',project=record['project_id'],preference_bytes=1536,preference_sha256=hashlib.sha256(public[256:1792]).hexdigest(),automatically_published=False)
                passed('native project card opens original Registry verification and completes useful normal Library Fork',action=action,durably_accepted_event=card[:32].hex(),replicated_event=card[:32].hex()if replica is not None else None,bytes=len(body),metadata_sha256=record['descriptor_sha256'],execution_consent=False)
                passed('new independent local lineage is visible in the normal trusted Library/Forge project picker',visible=visible,second_fork_requested=False)
                report['project']=record;report['card']=dict(id=card[:32].hex(),author=author.hex(),body_sha256=hashlib.sha256(body).hexdigest(),bytes=len(body),replicated=replica is not None);save()
                refused=project.revoke_and_refuse(g,g.feed_ui,record)
                passed('current native release revocation refuses the valid old card at the action boundary',refusal=refused)
                settle_exact(g,original,observed)
                try:public=export_public(g,include_preferences=True)
                except RuntimeError as error:
                    approved=out/(g.name+'.pre-fork-approved-feed-profile')
                    if not a.local_project_only or not str(error).startswith("('native public export refused'")or not approved.exists():raise
                    public=approved.read_bytes();g.device.press(1)
                    observed(dict(check='old-image quota still refuses a post-action public export',error=repr(error),approved_before_fork_profile_sha256=hashlib.sha256(public).hexdigest(),post_action_export_qualified=False))
                assert public[32:64]==author and public[128:160]==card[:32]
                assert struct.unpack_from('<Q',public,16)[0]==1 and preference_bits(public,project_id)&4
                assert not any(public[168:256])and not any(public[1792:])
                passed('approved public export includes exact retained publication reference and selected preferences without signing seed or sealed key',bytes=len(public),sequence=struct.unpack_from('<Q',public,24)[0],public_sha256=hashlib.sha256(public).hexdigest(),fields=['schema','explicit preference selection','sequence','author public key','home scope','selected peer scope','last signed event reference','public key generation','selected local preferences'],preference_sha256=hashlib.sha256(public[256:1792]).hexdigest(),sealed_private_key_included=False)
                save_approved_profile(out/(g.name+'.approved-feed-profile'),public)
                if a.local_project_only:
                    import network
                    report['pending_replication']=dict(qualification='local native actions completed; selected-federation replication remains unqualified in this identified trial',operators={name:dict(replication=list(feed.invoke(actors[name].client,490,action=3)[0]),network_context0=list(network.call(actors[name].client,7,slot=0)[0]))for name in('alpha','beta')})
            elif a.stage=='migrate':
                if not a.alpha_offline_approved:raise ValueError('finish connected moderation/restart before selecting the original federation offline')
                prior=json.loads((out/'feed-project-account.json').read_text());assert prior['result']=='pass'
                assert prior['configuration']==state['configuration']and prior.get('person',a.person)==a.person
                author=bytes.fromhex(prior['card']['author']);old_event=bytes.fromhex(prior['card']['id'])
                old_record=next(p for _,p in rows(destination)if p[:32]==old_event);old_body=read_body(destination,old_record)
                assert hashlib.sha256(old_body).hexdigest()==prior['card']['body_sha256']
                approved_path=out/(g.name+'.move-approved-feed-profile')
                if not approved_path.exists():save_approved_profile(approved_path,export_public(g,include_preferences=True))
                approved=approved_path.read_bytes();assert approved[32:64]==author
                approved_hash=hashlib.sha256(approved).hexdigest()
                if 'approved_profile_sha256'in checkpoint:assert checkpoint['approved_profile_sha256']==approved_hash
                checkpoint['approved_profile_sha256']=approved_hash;save()
                project_id=bytes.fromhex(prior['project']['project_id']);assert preference_bits(approved,project_id)&4
                blocked_author=bytes.fromhex(state['personal']['alice'if a.person=='bob'else'bob']['feed_public'])
                block_was_selected=bool(preference_bits(approved,blocked_author)&2)
                if original is not None:
                    checkpoint['offline_intent']=True;checkpoint['original']=original_name;save()
                    original.stop()
                assert not(out/(original_name+'.sock')).exists()
                if not checkpoint.get('offline'):
                    passed('original hosting federation explicitly offline while willing replica retains original signed project metadata',event=old_event.hex(),body_sha256=hashlib.sha256(old_body).hexdigest(),original=original_name,replica=destination.name)
                    checkpoint['offline']=True;save()
                if not checkpoint.get('offline_original_publisher_read'):
                    reconnect=json.loads((out/'reconnect-progress.json').read_text());assert reconnect['done']['ephemeral']
                    replaced=next(check for check in reconnect['checks']if 'old_owner'in check and 'new_owner'in check)
                    assert replaced['old_owner']!=replaced['new_owner']==state['personal']['charlie']['feed']['owner']
                    discussion=state['events']['long'];assert discussion['author']==state['personal']['charlie']['feed_public']
                    committed=next(p for _,p in rows(destination)if p[:32].hex()==discussion['id'])
                    assert hashlib.sha256(committed[32:]).hexdigest()==discussion['signed_sha256']
                    body=read_body(destination,committed);assert hashlib.sha256(body).hexdigest()==discussion['content_sha256']
                    passed('willing replica serves original checked long discussion with home federation offline and original no-vault author owner gone',event=discussion['id'],bytes=len(body),signed_sha256=discussion['signed_sha256'],content_sha256=discussion['content_sha256'],original_owner=replaced['old_owner'],fresh_ephemeral_owner=replaced['new_owner'],original_host_offline=not(out/(original_name+'.sock')).exists())
                    checkpoint['offline_original_publisher_read']=True;save()
                focus_feed(g)
                selected_feed_route(g,destination,relays,observed)
                public=export_public(g,include_preferences=True)
                recovered=public[32:64]==author and struct.unpack_from('<Q',public,160)[0]>1 and feed_ui(g,793)[0][6]==1
                if not recovered:
                    if feed_ui(g)[0][1]!=0:
                        g.device.press(59);g.device.press(64)
                        wait(lambda:feed_ui(g)[0][1]==0,120,'native account lock clears current author authority')
                    g.client.request(179,struct.pack('<2Q',g.feed_owner,1))
                    focus_feed(g);g.device.press(59);g.device.press(61)
                    if feed_ui(g,793)[0][5]!=1:g.device.press(62)
                    g.device.textASCII(secret(out/(g.name+'.feed-author-unlock'),create=False).hex(),delay=.04);g.device.press(63)
                    wait(lambda:feed_ui(g)[0][1]==1 and feed_ui(g)[0][5]==8 and feed_ui(g,793)[0][6]==1,180,'complete retained author recovery with original federation offline')
                assert feed_ui(g)[1][:32]==author
                focus_feed(g)
                settle_exact(g,destination,observed)
                public=export_public(g,include_preferences=True)
                assert public[256:1792]==approved[256:1792]and preference_bits(public,project_id)&4
                if block_was_selected:assert preference_bits(public,blocked_author)&2
                passed('native recovery restores exactly the explicitly approved local preferences independently of federation policy',preference_bytes=1536,preference_sha256=hashlib.sha256(public[256:1792]).hexdigest(),stable_project_follow=True,previously_selected_local_block=block_was_selected,local_block_preserved=True if block_was_selected else None,complete_graph_published=False)
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
            report['frame']=screenshot(g,'feed-'+a.stage);report['result']='partial-native-project-complete'if a.local_project_only else'pass';report['seconds']=time.monotonic()-began;attempt.update(result=report['result'],seconds=report['seconds']);save()
        except BaseException as error:
            report.update(result='failure-preserved-native-actors',error=repr(error),traceback=traceback.format_exc(),seconds=time.monotonic()-began)
            attempt.update(result='failure',error=repr(error),seconds=report['seconds'])
            try:report['native_ui']=list(feed_ui(g)[0]);report['native_events']=g.client.events.decode('ascii','replace')
            except BaseException as inspection:report['inspection_error']=repr(inspection)
            save();raise

if __name__=='__main__':main()
