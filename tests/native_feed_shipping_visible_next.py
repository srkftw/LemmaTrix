import hashlib,json,sys,time,struct
from pathlib import Path
sys.path[:0]=['tools','tests']
from native_community_campaign import attach_campaign,feed_ui
from native_feed_project_account import check_upgraded_local_block,export_public
import feed_project_controls as project
from messenger_journey import net
out=Path('build/campaign009-connected-v7'); path=out/'feed-shipping-final-visible-next.json'; source=out/'feed-shipping-final.json'; d=json.loads(source.read_text());assert d['result']=='pass'
record=dict(schema=1,result='running',reader_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),checks=[],observations=[],checkpoints={'upgraded_local_block':dict(unblocked=True,restored=True)})
def save():project.write_record(path,record)
def observed(v):record['observations'].append(v);save();print(json.dumps(v),flush=True)
save();start=time.monotonic()
with attach_campaign(out,skip=('alpha',))as campaign:
    g=campaign.actors['bob'];last=[0.0]
    def progress(stage,**fields):
        if time.monotonic()-last[0]<10:return
        last[0]=time.monotonic();f,p=feed_ui(g);observed(dict(stage=stage,ui=list(f),diagnostics=list(struct.unpack_from('<8Q',p,96)),terminal=list(net(g,41)[0]),**fields))
    g.project_observer=progress
    approved=(out/'bob.feed-shipping-final.approved-feed-profile').read_bytes()
    before=export_public(g,True);assert before[256:1792]==approved[256:1792]
    checked=check_upgraded_local_block(g,campaign.state,approved,record['checkpoints'],save,observed)
    status=feed_ui(g)[0];selected=feed_ui(g,795)[1]
    assert status[4]==15 and selected[:32].hex()==checked['next_event']
    after=export_public(g,True);assert after==before
    record['checks'].append(dict(check='ordinary NativeNext passes blocked and withdrawn markers to checked readable body without changing author/outbox/preferences',result='pass',selected_event=selected[:32].hex(),native_status=list(status),pref_sha256=hashlib.sha256(after[256:1792]).hexdigest(),public_profile_sha256=hashlib.sha256(after).hexdigest()))
    record.update(result='pass',seconds=time.monotonic()-start);save()
print(path,hashlib.sha256(path.read_bytes()).hexdigest(),flush=True)
