"""Recover an approved author around a normal signed Feed UI upgrade.

The account owner pins its UI incarnation. Replacing both ordinary processes
therefore uses its explicit lock, retained record, fresh grants and authenticated
history reconciliation. Operators and other personal clients remain running.
"""
from __future__ import annotations
import argparse,hashlib,json,struct,sys,time,traceback
from pathlib import Path
from types import SimpleNamespace as NS
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import feed,identity,releases
from messenger_journey import PUB,net,wait
from native_community_campaign import attach_campaign,feed_ui
from native_feed_project_account import export_public,focus_feed,retained_generation,secret,selected_feed_route,settle_exact


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--attach',type=Path,required=True)
    p.add_argument('--feed-packages',type=Path,required=True)
    p.add_argument('--ui-package',type=Path,required=True)
    p.add_argument('--person',default='bob')
    p.add_argument('--resume',action='store_true')
    a=p.parse_args();out=a.attach.resolve();path=out/'feed-fork-ui-upgrade.json'
    if path.exists()and not a.resume:raise ValueError('use --resume to preserve exact upgrade progress')
    raw=a.ui_package.read_bytes();info=releases.inspect(raw)
    assert info['project']=='feed'and info['version']=='0.9.1'and info['rights']==799
    report=json.loads(path.read_text())if path.exists()else dict(schema=1,person=a.person,package=dict(**info,sha256=hashlib.sha256(raw).hexdigest()),done={})
    assert report['package']['sha256']==hashlib.sha256(raw).hexdigest()
    correction=out/'feed-fork-generation-original.json'
    if report.get('before',{}).get('expected',{}).get('key_generation')==4 and correction.exists():
        native=json.loads(correction.read_text());event=bytes.fromhex(native['event'])
        assert len(event)==512 and hashlib.sha256(event[32:]).digest()==event[:32]and event[:32].hex()==report['before']['expected']['event']
        generation=struct.unpack_from('<Q',event,64)[0]
        report['before']['expected']['key_generation']=generation
        report.setdefault('controller_corrections',[]).append(dict(field='original canonical key generation',previous=4,current=generation,source=correction.name,reason='returned payload56 is signing purpose; payload64 is generation'))
    def save():path.write_text(json.dumps(report,indent=2)+'\n')
    def observed(value):
        report.setdefault('observations',[]).append(value);save();print(json.dumps(value),flush=True)
    began=time.monotonic();save()
    with attach_campaign(out,graphical=(a.person,),skip=tuple(n for n in('relay1','relay2','relay3','mailbox','alpha','beta','alice','bob','charlie')if n!=a.person))as c:
        g=c.actors[a.person];old=c.state['personal'][a.person]['feed'];done=report['done']
        last_observed=[0.0]
        def progress(stage,**extra):
            if time.monotonic()-last_observed[0]<10:return
            last_observed[0]=time.monotonic();status,diagnostic=feed_ui(g)
            observed(dict(stage=stage,ui=list(status),diagnostics=list(struct.unpack_from('<8Q',diagnostic,96)),**extra))
        g.project_observer=progress
        try:
            if 'before'not in report:
                try:
                    profile=export_public(g,True)
                    expected=dict(public=profile[32:64].hex(),home=profile[64:96].hex(),peer=profile[96:128].hex(),sequence=struct.unpack_from('<Q',profile,24)[0],event=profile[128:160].hex(),key_generation=struct.unpack_from('<Q',profile,160)[0])
                except RuntimeError as error:
                    if not str(error).startswith("('native public export refused'"):raise
                    # This identified old image counts freshly forked graph
                    # nodes against the ordinary export quota. Preserve its
                    # actual refusal; public signed-card data is sufficient
                    # to compare retained identity/outbox after recovery.
                    f,event=feed_ui(g,795);status,public=feed_ui(g)
                    assert len(event)==512 and any(event[:32])and hashlib.sha256(event[32:]).digest()==event[:32]
                    assert event[144:176]==public[:32]and struct.unpack_from('<Q',event,208)[0]==3
                    expected=dict(public=event[144:176].hex(),home=event[304:336].hex(),peer=event[336:368].hex(),sequence=struct.unpack_from('<Q',event,216)[0],event=event[:32].hex(),key_generation=struct.unpack_from('<Q',event,64)[0])
                    report['old_export_refusal']=dict(error=repr(error),ui=list(status),native_signed_card_sha256=hashlib.sha256(event).hexdigest(),qualification='old mixed-class quota; no successful public export is claimed');profile=None
                assert feed_ui(g,793)[0][6]==1
                report['before']=dict(owner=g.feed_owner,ui=g.feed_ui,profile=profile.hex()if profile is not None else None,expected=expected,route=list(net(g,32)[0]),terminal=list(net(g,41)[0]),retained_generation=retained_generation(out/(a.person+'.img')))
                assert info['parent']==c.state['configuration']['feed']['feed'];save()
            before=report['before'];profile=bytes.fromhex(before['profile'])if before['profile']is not None else None;expected=before['expected']
            if not done.get('locked'):
                focus_feed(g);g.device.press(59);g.device.press(64)
                wait(lambda:feed_ui(g)[0][1]==0,120,'native account lock clears old publishing authority')
                done['locked']=True;save()
            if not done.get('stopped'):
                net(g,42);net(g,35)
                for who in(before['ui'],before['owner']):
                    if any(row[0]==who and row[1]in(1,2,3,4)for row in identity.instances(g.client)):
                        g.client.request(26,struct.pack('<Q',who))
                done['stopped']=True;save()
            if 'new'not in report:
                report['new']=feed.start(g.client,NS(identity=a.feed_packages/'identity.ltrel',owner=a.feed_packages/'feed-account.ltrel',ui=a.ui_package,public=PUB,federation=old['federation'],peer=old['selected_peer']));save()
            new=report['new'];g.feed_owner,g.feed_ui=new['owner'],new['ui']
            assert g.feed_owner!=before['owner']and g.feed_ui!=before['ui']and new['identity']==old['identity']
            c.state['personal'][a.person]['feed']=dict(new,ui_release=info['release_id'])
            c.state.setdefault('ordinary_package_upgrades',{})[a.person]=dict(path=path.name,ui_release=info['release_id'],old_owner=before['owner'],old_ui=before['ui'])
            (out/'native-actors.json').write_text(json.dumps(c.state,indent=2)+'\n')
            public=json.loads((out/'continuations.json').read_text());public['personal'][a.person]['feed']=c.state['personal'][a.person]['feed'];(out/'continuations.json').write_text(json.dumps(public,indent=2)+'\n')
            if not done.get('recovered'):
                raw=g.client.request(200,struct.pack('<8Q',200,0,3,0,0,0,0,1)+secret(out/(a.person+'.feed-objects-unlock'),create=False));assert struct.unpack_from('<Q',raw)[0]==0
                g.client.request(179,struct.pack('<2Q',g.feed_owner,1))
                focus_feed(g);g.device.press(59);g.device.press(61)
                if feed_ui(g,793)[0][5]!=1:g.device.press(62)
                g.device.textASCII(secret(out/(a.person+'.feed-author-unlock'),create=False).hex(),delay=.04);g.device.press(63)
                wait(lambda:feed_ui(g)[0][1]==1 and feed_ui(g)[0][5]==8 and feed_ui(g,793)[0][6]==1,180,'fresh typed retained recovery is visibly reconciliation-required')
                g.device.press(1);done['recovered']=True;save()
            # The owner changed. Its old terminal ownership is never revived.
            # Route configuration is the same public approved peer material.
            if not done.get('route'):
                from messenger_journey import Guest
                records=c.state['actors'];peers=[]
                for name in('relay1','relay2','relay3','alpha'):
                    record=records[name];peer=NS(name=name,certificate=(out/(name+'.certificate')).read_bytes())
                    peers.append(peer)
                selected_feed_route(g,peers[3],peers[:3],observed);done['route']=True;save()
            # Reconcile only through the author's currently selected native
            # service. The controller compares public commitments afterward.
            if not done.get('reconciled'):
                alpha_record=c.state['actors']['alpha']
                from messenger_journey import Guest
                alpha=Guest('alpha',alpha_record['backend'],out,out/'guest.bin').attach(None)
                try:settle_exact(g,alpha,observed)
                finally:alpha.client.close()
                done['reconciled']=True;save()
            after=export_public(g,True)
            assert after[32:64].hex()==expected['public']and after[64:96].hex()==expected['home']and after[96:128].hex()==expected['peer']
            assert after[128:160].hex()==expected['event']and struct.unpack_from('<Q',after,24)[0]==expected['sequence']
            if profile is not None:assert after[256:1792]==profile[256:1792]
            assert struct.unpack_from('<Q',after,160)[0]>expected['key_generation']
            assert retained_generation(out/(a.person+'.img'))>before['retained_generation']
            if 'error'in report:
                report.setdefault('prior_failures',[]).append({name:report.pop(name)for name in('error','traceback','native_ui','native_portable','native_events','inspection_error')if name in report})
            report.update(result='pass',after=dict(owner=g.feed_owner,ui=g.feed_ui,profile_sha256=hashlib.sha256(after).hexdigest(),public=after[32:64].hex(),sequence=struct.unpack_from('<Q',after,24)[0],event=after[128:160].hex(),key_generation=struct.unpack_from('<Q',after,160)[0],preferences_sha256=hashlib.sha256(after[256:1792]).hexdigest(),retained_generation=retained_generation(out/(a.person+'.img'))),seconds=time.monotonic()-began)
            save();print(json.dumps(report['after']),flush=True)
        except BaseException as error:
            report.update(result='failure-preserved-native-actors',error=repr(error),traceback=traceback.format_exc(),seconds=time.monotonic()-began)
            try:report['native_ui']=list(feed_ui(g)[0]);report['native_portable']=list(feed_ui(g,793)[0]);report['native_events']=g.client.events.decode('ascii','replace')
            except BaseException as inspection:report['inspection_error']=repr(inspection)
            save();raise


if __name__=='__main__':main()
