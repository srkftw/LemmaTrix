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
import feed,federation,identity,projects,releases
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
    shared,_=project.ui_call(g,g.feed_ui,794)
    if shared[0]!=0 or shared[1]==0:raise ValueError(('native approved public export capability refused',list(shared)))
    try:data=g.client.read_object(shared[1])
    finally:g.client.objects(47,shared[1])
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


def import_public_preferences(g,profile,checkpoint,save,observed):
    """Import approved public state through Objects and an explicit native F9."""
    proof=checkpoint.setdefault('public_preferences_import',{})
    assert len(profile)==2048 and struct.unpack_from('<Q',profile,16)[0]==1
    expected=hashlib.sha256(profile).hexdigest()
    if 'approved_sha256'in proof:assert proof['approved_sha256']==expected
    proof['approved_sha256']=expected;save()
    focus_feed(g)
    before,identity_fields=feed_ui(g)
    assert before[1]==0 and not any(identity_fields[:32]),'public import must use the existing empty no-vault account'
    if not proof.get('imported'):
        handle=g.client.import_object(profile,kind=6)
        try:
            delegated=g.client.objects(6,handle,g.feed_ui,1)[0][1]
            staged,_=project.ui_call(g,g.feed_ui,792,delegated)
            assert staged[0]==0
        finally:g.client.objects(47,handle)
        g.device.press(59);g.device.press(67)
        project.wait_native(g,lambda:feed_ui(g)[0][4]==50 and project.complete_read(g,g.feed_ui),180,'explicit native public preference import without author credentials')
        proof.update(imported=True,owner=g.feed_owner,ui=g.feed_ui);save()
    exported=export_public(g,include_preferences=True)
    assert exported[256:1792]==profile[256:1792]
    assert not any(exported[24:64])and not any(exported[128:168]),'public profile must not create a signing identity, sequence or signed outbox'
    status,public=feed_ui(g)
    assert status[1]==0 and not any(public[:32])
    proof.update(reexport_sha256=hashlib.sha256(exported).hexdigest(),preference_sha256=hashlib.sha256(exported[256:1792]).hexdigest(),
        author_present=False,key_generation=0,sequence=0,signing_seed_or_seal_imported=False,moderator_authority_imported=False,
        identity_created=False,network_relationship_created=False,frame=screenshot(g,'approved-public-preferences-import'))
    save();observed(dict(check='approved public Objects profile imports selected preferences into the existing empty no-vault account without author or moderator credentials',**proof))
    return proof


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



def retained_pair_packages(bundle,old_releases,*,relaunch=False):
    paths={name:bundle/(name+'.ltrel')for name in('identity','feed-account','feed','feed-federation')}
    modulus=releases.public_modulus(PUB)
    selected={name:releases.inspect(path.read_bytes(),modulus)for name,path in paths.items()}
    for name in('identity','feed-federation'):
        assert selected[name]['release_id']==old_releases[name],name+' must remain the exact existing service release'
    changed=False
    for name,versions,rights in(('feed-account',('0.9.2','0.9.3'),1024),('feed',('0.9.3','0.9.4'),799)):
        info=selected[name]
        assert info['project']==name and info['rights']==rights
        if relaunch or info['release_id']==old_releases[name]:
            assert info['release_id']==old_releases[name],'relaunch requires the exact already admitted release'
        else:
            assert info['version']in versions
            assert info['parent']==old_releases[name]and info['release_id']!=old_releases[name],'normal exact-parent upgrade required'
            changed=True
    assert relaunch or changed,'upgrade requires at least one strictly newer component; use exact relaunch for unchanged packages'
    return paths,{name:dict(release_id=info['release_id'],parent=info['parent'],version=info['version'],
                           code_sha256=info['executable_sha256'],
                           package_sha256=hashlib.sha256(paths[name].read_bytes()).hexdigest())for name,info in selected.items()}


def successor_packages(bundle,old_releases):
    return retained_pair_packages(bundle,old_releases)


def check_admitted_pair(client,paths,packages,old_releases,*,relaunch):
    """Read current native hashes/versions before ordinary process replacement."""
    for name in('identity','feed-account','feed'):
        raw=paths[name].read_bytes();info=releases.inspect(raw)
        current=client.request(14,bytes.fromhex(info['project_id']))
        assert len(current)==128 and current[64:96].hex()==old_releases[name],name+' differs from the exact current native release'
        for index in range(16):
            try:header=client.request(13,struct.pack('<Q',index))
            except ValueError as error:
                if str(error)!='guest rejected command13, status1':raise
                continue
            if len(header)==512 and header[160:192].hex()==old_releases[name]:
                if relaunch or name=='identity'or packages[name]['release_id']==old_releases[name]:
                    assert header==raw[:512],name+' current native header/hash differs from the selected exact package'
                else:
                    assert tuple(map(int,packages[name]['version'].split('.')))>struct.unpack_from('<3Q',header,72),'normal upgrade requires a strictly newer component version'
                break
        else:raise ValueError(name+' has no exact current native catalog entry')


def upgrade_retained_pair(g,campaign,bundle,checkpoint,save,*,relaunch=False):
    """Normal ordinary-package replacement after a completed explicit lock."""
    state=campaign.state;out=campaign.output
    current=state['personal'][g.name]['feed'];active=dict(state['configuration']['feed'])
    for name,field in(('feed-account','owner_release'),('feed','ui_release')):
        if field in current:active[name]=current[field]
    key='ordinary_relaunch'if relaunch else'ordinary_upgrade'
    intent=checkpoint.setdefault(key,dict(old=current,old_releases=active))
    paths,packages=retained_pair_packages(bundle,intent['old_releases'],relaunch=relaunch)
    if 'packages'in intent:assert intent['packages']==packages,'successor package provenance changed on resume'
    intent['packages']=packages;save()
    if not intent.get('stopped'):
        check_admitted_pair(g.client,paths,packages,intent['old_releases'],relaunch=relaunch)
        intent['exact_current_native_catalog_verified']=True;save()
    old=intent['old']
    if not intent.get('locked'):
        focus_feed(g);g.device.press(59);g.device.press(64)
        project.wait_native(g,lambda:feed_ui(g)[0][1]==0 and feed_ui(g)[0][4]==36 and project.complete_read(g,g.feed_ui),120,'explicit lock before normal retained Feed package upgrade')
        intent['locked']=True;save()
    if not intent.get('stopped'):
        net(g,42);net(g,35)
        for who in(old['ui'],old['owner']):
            if project.live_instance(g.client,who):g.client.request(26,struct.pack('<Q',who))
        intent['stopped']=True;save()
    if 'new'not in intent:
        intent['new']=feed.start(g.client,SimpleNamespace(identity=paths['identity'],owner=paths['feed-account'],ui=paths['feed'],public=PUB,
                federation=old['federation'],peer=old['selected_peer']));save()
    fresh=intent['new'];g.feed_owner,g.feed_ui=fresh['owner'],fresh['ui'];g.ui=g.feed_ui
    assert fresh['owner']!=old['owner']and fresh['ui']!=old['ui']and fresh['identity']==old['identity']
    state['personal'][g.name]['feed']=dict(fresh,owner_release=packages['feed-account']['release_id'],ui_release=packages['feed']['release_id'])
    ledger='ordinary_package_relaunches'if relaunch else'ordinary_package_upgrades'
    state.setdefault(ledger,{})[g.name]=dict(stage='retained hosting move',old_owner=old['owner'],old_ui=old['ui'],
        new_owner=fresh['owner'],new_ui=fresh['ui'],packages=packages,authority_reused=False,image_unchanged=True)
    project.write_record(out/'native-actors.json',state)
    if(out/'continuations.json').exists():
        public=json.loads((out/'continuations.json').read_text());public['personal'][g.name]=state['personal'][g.name]
        public[ledger]=state[ledger];project.write_record(out/'continuations.json',public)
    intent['actor_ledger_updated']=True;save()
    return intent


def select_local_block_marker(g,author):
    """Use real chronological controls; a local marker has no event reference."""
    focus_feed(g)
    for _ in range(4):
        g.device.press(15)
        try:choice=wait(lambda:(lambda f:f if f[4]in(27,28)else None)(feed_ui(g)[0]),5,'native chronological filter choice')
        except TimeoutError:continue
        if choice[4]==27:break
    else:raise RuntimeError('native chronological filter choice unavailable')
    g.device.press(104);time.sleep(3);first_pending=True;first_retries=0
    for _ in range(64):
        def ready():
            fields,payload=feed_ui(g,795)
            observer=getattr(g,'project_observer',None)
            if observer is not None:observer('native local-block pagination',selected=payload[:32].hex())
            complete=project.complete_read(g,g.feed_ui)
            status=feed_ui(g)[0]
            if complete and not any(payload[:32])and payload[144:176]!=author and status[6]in(4,9,12,14):return dict(unavailable=list(status))
            return payload if complete and(any(payload[:32])or payload[144:176]==author)else None
        row=wait(ready,300,'native chronological signed row or author-only local block marker')
        if isinstance(row,dict):
            if first_pending:
                if first_retries>=8:raise RuntimeError(('native First remains unavailable',row))
                first_retries+=1;g.device.press(104);time.sleep(3);continue
            if getattr(g,'project_observer',None):g.project_observer('native unavailable row; ordinary Next',status=row['unavailable'])
            project.advance_row(g,g.feed_ui,bytes(512));continue
        first_pending=False
        if row[144:176]==author:
            assert not any(row[:144])and not any(row[176:]),'blocked marker must contain only its public author'
            assert feed_ui(g)[0][4]==16
            return row
        project.advance_row(g,g.feed_ui,row)
    raise AssertionError('expected selected local block was absent from native timeline')


def check_upgraded_local_block(g,state,approved,checkpoint,save,observed):
    """Explicit unblock/reblock restores approved private preferences exactly."""
    author=bytes.fromhex(state['personal']['alice'if g.name=='bob'else'bob']['feed_public'])
    if not preference_bits(approved,author)&2:raise ValueError('the connected moderation stage must leave its explicitly selected local block effective')
    record=checkpoint.setdefault('upgraded_local_block',{});save()
    profile=export_public(g,True)
    if not record.get('unblocked'):
        if preference_bits(profile,author)&2:
            select_local_block_marker(g,author)
            record['unblock_intent']=True;save();g.device.press(66)
            project.wait_native(g,lambda:feed_ui(g)[0][4]==51 and project.complete_read(g,g.feed_ui),180,'new native UI explicitly unblocks the filtered public author')
        else:assert record.get('unblock_intent'),'unexpected preference change before explicit unblock'
        profile=export_public(g,True);assert not preference_bits(profile,author)&2
        record.update(unblocked=True,unblocked_profile_sha256=hashlib.sha256(profile).hexdigest());save()
    if not record.get('restored'):
        if not preference_bits(profile,author)&2:
            focus_feed(g)
            if feed_ui(g,795)[1][144:176]!=author:
                reply=state['events']['reply'];assert reply['author']==author.hex()
                project.select_event(g,g.feed_ui,bytes.fromhex(reply['id']))
            record['reblock_intent']=True;save();g.device.press(66)
            project.wait_native(g,lambda:feed_ui(g)[0][4]==18 and project.complete_read(g,g.feed_ui),180,'new native UI explicitly restores the same local block')
        else:assert record.get('reblock_intent'),'unblock result was replaced outside the saved explicit action'
        profile=export_public(g,True);assert profile[256:1792]==approved[256:1792]
        record.update(restored=True,restored_preference_sha256=hashlib.sha256(profile[256:1792]).hexdigest());save()
    if not record.get('next_progress'):
        # A retained completed marker may belong to a later event by the same
        # author. Re-establish chronology through an accepted First gesture,
        # then test ordinary Next without assuming one particular successor.
        select_local_block_marker(g,author)
        record['marker_frame']=screenshot(g,'upgraded-local-block-marker');save()
        marker=feed_ui(g,795)[1]
        steps=[]
        for _ in range(16):
            # Distinct filtered rows deliberately share an all-zero event ID.
            # Wait after the ordinary gesture instead of treating that ID as
            # a request/completion token.
            g.device.press(28);time.sleep(3)
            def next_completed():
                fields,payload=feed_ui(g,795);status=feed_ui(g)[0]
                if not project.complete_read(g,g.feed_ui):return None
                if any(payload[:32]):
                    if status[4]==40:return dict(hidden_event=payload[:32].hex())
                    return payload if status[4]==15 else None
                if status[4]==16 and payload[144:176]==author:return dict(blocked=True)
                if status[6]in(4,9,12,14):return dict(refused=list(status))
                return None
            selected=project.wait_native(g,next_completed,180,'new native UI advances beyond a blocked row to a permitted discussion')
            if isinstance(selected,dict):
                steps.append(selected);time.sleep(3);marker=bytes(512);continue
            assert selected[144:176]!=author and selected[:32]!=marker[:32]
            next_id=selected[:32];break
        else:raise RuntimeError('bounded native Next did not reach a permitted signed row')
        record['next_navigation']=steps
        record.update(next_progress=True,next_event=next_id.hex(),next_frame=screenshot(g,'upgraded-after-local-block'));save()
    observed(dict(check='new native UI local block reveals only public author, explicitly unblocks/reblocks and browses beyond it',
                  blocked_author=author.hex(),**record,complete_preference_graph_published=False))
    return record



def choose_move_audience(g,checkpoint,save):
    """A newly launched UI needs its own explicit audience choice."""
    expected='Audience: home plus selected peer federation'
    home='Audience: home federation only'
    focus_feed(g)
    def audience():
        frame=g.device.frame()
        if frame is None:return None
        # Surface-local y324 is presented below the native compositor chrome.
        # Locate the literal visible footer; do not infer or toggle intent
        # from a blank patch at the unshifted surface coordinate.
        for y in range(300,frame.height-7):
            if project.rendered_text(frame,14,y,9,foreground=0x8cdec6)!='Audience:':continue
            value=project.rendered_text(frame,14,y,44,foreground=0x8cdec6).rstrip()
            if value in(home,expected):return value
        return None
    selected=wait(audience,180,'native completed audience footer after retained UI recovery')
    if selected==home:
        checkpoint['move_audience_intent']='home plus selected peer federation';save()
        g.device.press(30)
    wait(lambda:audience()==expected and project.complete_read(g,g.feed_ui),180,'explicit native home and willing peer audience before move preview')
    checkpoint['move_audience']=dict(label=expected,frame=screenshot(g,'move-approved-peer-audience'),
        source='ordinary native A control and completed rendered footer; no account field setter')
    save()


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


def ephemeral_author_history(out,state,completed):
    """Keep the retired publishing author distinct from the fresh owner."""
    path=out/'no-vault-public-ledger.json';ledger=json.loads(path.read_text())
    person=state['personal']['charlie'];fresh=person['feed']
    replaced=next(check for check in completed['checks']if 'old_owner'in check and 'new_owner'in check)
    assert ledger['schema']==2 and ledger['result']=='pass'
    assert ledger['image_sha256']==state['configuration']['image_sha256']
    assert ledger['reconnect_sha256']==hashlib.sha256((out/'reconnect-progress.json').read_bytes()).hexdigest()
    assert ledger['completed_native_checks']==replaced and replaced['result']=='pass'
    assert replaced['old_owner']!=replaced['new_owner']==fresh['owner']==ledger['current_feed_owner']
    assert fresh['ui']==ledger['current_feed_ui']
    assert ledger['current_feed_identity_present']is False and ledger['current_feed_public']is None
    assert person['current_feed_identity_present']is False and person['current_feed_public']is None
    historical=person['historical_feed_public']
    assert historical==ledger['historical_feed_public']==state['events']['long']['author']
    return dict(historical_author=historical,old_owner=replaced['old_owner'],fresh_owner=fresh['owner'],
                fresh_ui=fresh['ui'],ledger_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                classification='completed no-vault observation; historical author is not the fresh owner identity')


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
            phase=feed.invoke(original.client,490,action=3)[0]
            observer=getattr(g,'project_observer',None)
            if observer is not None:observer('native author '+label+' replication',event=committed[:32].hex(),replication=list(phase))
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
    parser.add_argument('--feed-packages',type=Path,help='exact frozen bundle required for ephemeral or retained same-release relaunch')
    parser.add_argument('--upgrade-feed-packages',type=Path,help='normal per-component exact reuse or parent-linked Account0.9.2/UI0.9.3/0.9.4 retained migration upgrade')
    parser.add_argument('--relaunch-retained-feed',action='store_true',help='normally relaunch the exact current --feed-packages account/UI during retained migration')
    parser.add_argument('--alpha-offline-approved',action='store_true',help='select only after connected moderation/restart checks finish')
    parser.add_argument('--local-project-only',action='store_true',help='preserve measured replication failure while completing unaffected native project actions; never a full pass')
    parser.add_argument('--application-checkpoint',action='store_true',help='run strict project actions after the explicit partial 17-event release, preserving later history-read targets')
    a=parser.parse_args();
    if a.upgrade_feed_packages is not None and a.stage!='migrate':raise ValueError('ordinary Feed upgrade is part of the explicit retained migration stage only')
    if a.relaunch_retained_feed and(a.stage!='migrate'or a.feed_packages is None or a.upgrade_feed_packages is not None):raise ValueError('retained same-release relaunch requires migrate and --feed-packages, without --upgrade-feed-packages')
    out=a.attach.resolve();evidence=out/('feed-'+a.stage+'-account.json');began=time.monotonic()
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
    if checkpoint.get('ordinary_relaunch')and a.upgrade_feed_packages is not None:raise ValueError('preserve the selected exact-current retained relaunch on resume')
    if checkpoint.get('ordinary_upgrade')and a.relaunch_retained_feed:raise ValueError('preserve the selected parent-linked retained upgrade on resume')
    release=None
    if a.application_checkpoint:
        assert a.stage=='project'and not a.local_project_only
        release=application_checkpoint(out,initial)
        report['application_checkpoint_release']=release
    elif a.stage=='project':
        completed=json.loads((out/'reconnect-progress.json').read_text())
        assert initial['done'].get('cancel')and completed.get('result')=='pass'and completed.get('done',{}).get('ephemeral'),'finish the full Charlie continuation before acquiring project/UI control'
        assert completed['configuration']==initial['configuration']
    elif a.stage=='migrate':
        if not a.alpha_offline_approved:raise ValueError('finish connected moderation/restart before selecting the original federation offline')
        completed=json.loads((out/'reconnect-progress.json').read_text())
        assert completed.get('result')=='pass'and completed.get('done',{}).get('ephemeral'),'finish original publisher ephemerality before taking its home federation offline'
        assert completed['configuration']==initial['configuration']
        report['original_author_ephemerality']=ephemeral_author_history(out,initial,completed)
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
            value=dict(observed_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),stage=stage,ui=list(fields),diagnostics=list(struct.unpack_from('<8Q',diagnostic,96)),route=list(net(g,32)[0]),terminal=list(net(g,41)[0]),**details)
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
                        wait(lambda:feed_ui(g)[0][4]in(18,68)and project.complete_read(g,g.feed_ui),180,'native stable project follow before old-image graph quota')
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
                def replica_card():
                    result=next((p for _,p in rows(destination)if p[:32]==card[:32]),None)
                    if result is None:
                        phase=feed.invoke(original.client,490,action=3)[0]
                        progress('native original project-card replication',event=card[:32].hex(),replication=list(phase))
                        if phase[1]==6:raise RuntimeError(('native project-card replication explicitly stopped',list(phase),card[:32].hex()))
                    return result
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
                    wait(lambda:feed_ui(g)[0][4]in(18,68)and project.complete_read(g,g.feed_ui),180,'native follow of the selected stable project')
                    observed(dict(check='native project-follow completion notice',notice=feed_ui(g)[0][4],legacy_kind4_label=feed_ui(g)[0][4]==18))
                    public=export_public(g,include_preferences=True)
                assert preference_bits(public,project_id)&4
                save_approved_profile(out/(g.name+'.approved-feed-profile'),public)
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
                prior_event=approved[128:160]
                prior_row=next(p for _,p in rows(destination)if p[:32]==prior_event)
                assert prior_row[144:176]==author and prior_row[304:368]==approved[64:128]
                assert struct.unpack_from('<Q',prior_row,216)[0]==struct.unpack_from('<Q',approved,24)[0]
                assert struct.unpack_from('<Q',prior_row,64)[0]<=struct.unpack_from('<Q',approved,160)[0]
                report['approved_prior_commitment']=dict(event=prior_event.hex(),sequence=struct.unpack_from('<Q',approved,24)[0],signed_sha256=hashlib.sha256(prior_row[32:]).hexdigest(),original_card=old_event.hex())
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
                    history=report['original_author_ephemerality']
                    discussion=state['events']['long'];assert discussion['author']==history['historical_author']
                    committed=next(p for _,p in rows(destination)if p[:32].hex()==discussion['id'])
                    assert hashlib.sha256(committed[32:]).hexdigest()==discussion['signed_sha256']
                    body=read_body(destination,committed);assert hashlib.sha256(body).hexdigest()==discussion['content_sha256']
                    passed('willing replica serves original checked long discussion with home federation offline and original no-vault author owner gone',event=discussion['id'],bytes=len(body),signed_sha256=discussion['signed_sha256'],content_sha256=discussion['content_sha256'],original_owner=history['old_owner'],fresh_ephemeral_owner=history['fresh_owner'],historical_author=history['historical_author'],no_vault_ledger_sha256=history['ledger_sha256'],original_host_offline=not(out/(original_name+'.sock')).exists())
                    checkpoint['offline_original_publisher_read']=True;save()
                backing=out/(g.name+'.img')
                if 'recovery_intent'not in checkpoint:
                    checkpoint['recovery_intent']=dict(previous_key_generation=struct.unpack_from('<Q',approved,160)[0],
                        previous_root_generation=retained_generation(backing),original_host_offline=True,
                        selected_preference_sha256=hashlib.sha256(approved[256:1792]).hexdigest())
                    save()
                lifecycle=None
                if a.upgrade_feed_packages is not None:
                    upgrade=upgrade_retained_pair(g,campaign,a.upgrade_feed_packages.resolve(),checkpoint,save)
                    lifecycle=upgrade
                    if not checkpoint.get('upgrade_recorded'):
                        passed('explicit native lock and parent-linked ordinary Feed upgrade replace only this retained personal UI/account with fresh process authority',**upgrade)
                        checkpoint['upgrade_recorded']=True;save()
                elif a.relaunch_retained_feed:
                    lifecycle=upgrade_retained_pair(g,campaign,a.feed_packages.resolve(),checkpoint,save,relaunch=True)
                    if not checkpoint.get('relaunch_recorded'):
                        passed('explicit native lock and exact-current ordinary Feed relaunch replace only this retained personal UI/account with fresh process authority',**lifecycle)
                        checkpoint['relaunch_recorded']=True;save()
                elif checkpoint.get('ordinary_upgrade'):raise ValueError('resume the selected exact successor bundle with --upgrade-feed-packages')
                elif checkpoint.get('ordinary_relaunch'):raise ValueError('resume the selected exact current bundle with --relaunch-retained-feed and --feed-packages')
                focus_feed(g)
                selected_feed_route(g,destination,relays,observed)
                public=export_public(g,include_preferences=True)if feed_ui(g)[0][1]else None
                recovery=checkpoint['recovery_intent']
                recovered=(public is not None and public[32:64]==author
                    and struct.unpack_from('<Q',public,160)[0]>recovery['previous_key_generation']
                    and retained_generation(backing)>recovery['previous_root_generation']and feed_ui(g,793)[0][6]==1)
                if not recovered:
                    if feed_ui(g)[0][1]!=0:
                        g.device.press(59);g.device.press(64)
                        project.wait_native(g,lambda:feed_ui(g)[0][1]==0 and feed_ui(g)[0][4]==36 and project.complete_read(g,g.feed_ui),120,'completed native account lock clears current author authority')
                    g.client.request(179,struct.pack('<2Q',g.feed_owner,1))
                    focus_feed(g);g.device.press(59);g.device.press(61)
                    if feed_ui(g,793)[0][5]!=1:g.device.press(62)
                    g.device.textASCII(secret(out/(g.name+'.feed-author-unlock'),create=False).hex(),delay=.04);g.device.press(63)
                    # The immediate recovery notice46 is superseded by the
                    # normal status poll's reconciliation notice12. Require
                    # durable/current state, rather than a transient label.
                    project.wait_native(g,lambda:feed_ui(g)[0][1]==1 and feed_ui(g)[0][5]==8
                        and feed_ui(g,793)[0][6]==1 and project.complete_read(g,g.feed_ui)
                        and retained_generation(backing)>recovery['previous_root_generation'],180,'complete retained author recovery and fresh reseal with original federation offline')
                assert feed_ui(g)[1][:32]==author
                if 'recovery_root_generation'not in checkpoint:
                    checkpoint['recovery_root_generation']=retained_generation(backing);save()
                focus_feed(g)
                settle_exact(g,destination,observed)
                public=export_public(g,include_preferences=True)
                assert public[64:128]==approved[64:128]
                assert struct.unpack_from('<Q',public,160)[0]>recovery['previous_key_generation']
                assert public[256:1792]==approved[256:1792]and preference_bits(public,project_id)&4
                if block_was_selected:assert preference_bits(public,blocked_author)&2
                passed('native recovery restores exactly the explicitly approved local preferences independently of federation policy',preference_bytes=1536,preference_sha256=hashlib.sha256(public[256:1792]).hexdigest(),stable_project_follow=True,previously_selected_local_block=block_was_selected,local_block_preserved=True if block_was_selected else None,complete_graph_published=False)
                if lifecycle is not None and lifecycle['packages']['feed']['version']in('0.9.3','0.9.4')and lifecycle['packages']['feed-account']['version']in('0.9.2','0.9.3'):
                    check_upgraded_local_block(g,state,approved,checkpoint,save,observed)
                event=match(destination,author,1,hashlib.sha256(MOVED.encode()).digest())
                assert public[32:64]==author and public[128:160]in(prior_event,event[:32]if event else prior_event)and struct.unpack_from('<Q',public,160)[0]>1
                if not checkpoint.get('recovered'):
                    passed('fresh native recovery preserves scoped author and exact prior publication through selected willing federation',public=author.hex(),generation=struct.unpack_from('<Q',public,160)[0],sequence=struct.unpack_from('<Q',public,24)[0],exact_event=prior_event.hex(),original_card=old_event.hex(),no_original_server_permission=True)
                    checkpoint['recovered']=True;save()
                if event is None:
                    choose_move_audience(g,checkpoint,save)
                    focus_feed(g);g.device.press(61)
                    wait(lambda:feed_ui(g)[0][2]==1 and feed_ui(g)[0][3]==0,120,'native fresh move publication draft')
                    g.device.textASCII(MOVED,delay=.035)
                    wait(lambda:feed_ui(g)[0][3]==len(MOVED),180,'complete native hosting-move publication input')
                    g.device.press(62);wait(lambda:feed_ui(g)[0][2]==9,60,'native exact move publication preview')
                    intent=dict(author=author.hex(),home=home,peer=peer,kind=1,content_sha256=hashlib.sha256(MOVED.encode()).hexdigest())
                    if 'move_intent'in checkpoint:assert checkpoint['move_intent']==intent
                    else:checkpoint['move_root_before']=retained_generation(backing)
                    checkpoint['move_intent']=intent;save()
                    g.device.press(63)
                    retries=[0,time.monotonic()]
                    def accepted_move():
                        found=match(destination,author,1,hashlib.sha256(MOVED.encode()).digest())
                        progress('native new publication after fresh hosting authorization')
                        fields,diagnostic=feed_ui(g)
                        if found is not None and fields[5]in(6,7)and project.complete_read(g,g.feed_ui):return found
                        if fields[5]==8:raise RuntimeError(('hosting publication requires exact native reconciliation',list(fields)))
                        if fields[2]==9 and fields[3]==len(MOVED)and fields[6]==4 and fields[5]in(0,6,7)and struct.unpack_from('<Q',diagnostic,104)[0]==0 and time.monotonic()-retries[1]>=3:
                            if retries[0]>=8:raise RuntimeError(('native hosting publication remains busy',list(fields)))
                            g.device.press(63);retries[:]=[retries[0]+1,time.monotonic()]
                        return None
                    event=wait(accepted_move,600,'native new publication after fresh hosting authorization')
                assert event[304:336].hex()==home and event[336:368].hex()==peer
                assert struct.unpack_from('<Q',event,216)[0]>struct.unpack_from('<Q',approved,24)[0]
                assert struct.unpack_from('<Q',event,64)[0]>struct.unpack_from('<Q',approved,160)[0]
                assert read_body(destination,event)==MOVED.encode()
                move_status=feed_ui(g)[0]
                durable,_=feed.invoke(destination.client,491,action=4,data=event[:32])
                passed('same retained federation-scoped author publishes a new checked event at willing second host while original remains offline',event=event[:32].hex(),sequence=struct.unpack_from('<Q',event,216)[0],original_still_offline=not(out/(original_name+'.sock')).exists(),new_identity_link_claim=False,ui_publication_phase=move_status[5],destination_publication_state=durable[2],replication_claim=move_status[5]==7,replication_limit='durable acceptance does not imply acknowledgement from the offline original federation')
                settle_exact(g,destination,observed)
                after=export_public(g,include_preferences=True)
                assert after[32:128]==public[32:128]and after[128:160]==event[:32]and after[256:1792]==approved[256:1792]
                assert struct.unpack_from('<Q',after,24)[0]==struct.unpack_from('<Q',event,216)[0]
                assert struct.unpack_from('<Q',event,64)[0]<=struct.unpack_from('<Q',after,160)[0]
                assert retained_generation(backing)>recovery['previous_root_generation']
                if 'move_root_before'in checkpoint:assert retained_generation(backing)>checkpoint['move_root_before']
                save_approved_profile(out/(g.name+'.migrated-approved-feed-profile'),after)
                passed('native approved export after hosting move preserves exact new outbox reference and selected preferences',profile_sha256=hashlib.sha256(after).hexdigest(),preference_sha256=hashlib.sha256(after[256:1792]).hexdigest(),opaque_root_generation=retained_generation(backing),sealed_private_key_included=False)
                portable=import_public_preferences(actors['charlie'],after,checkpoint,save,observed)
                passed('explicit portable public preferences restore on an empty account without transferring publishing or moderation authority',**portable)
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
