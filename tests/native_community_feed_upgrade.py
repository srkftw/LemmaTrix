"""Replace the two unused Feed account owners before community publication.

This is an ordinary native application lifecycle continuation. The common image,
operators, backing and Messenger applications remain live. Each replaced
personal client rebuilds only its own route under the same approved peers.
The only new package is the corrected Feed account owner. Public provenance
records the superseded unused identities; no author key or event is imported.
"""
import argparse,hashlib,json,struct,sys,time,traceback
from datetime import datetime,timezone
from pathlib import Path
from types import SimpleNamespace as NS
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import feed,releases
from messenger_journey import PUB,net,wait
from native_community_campaign import attach_campaign,feed_ui,focus_application

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--attach',type=Path,required=True);p.add_argument('--feed-packages',type=Path,required=True);p.add_argument('--resume',action='store_true');a=p.parse_args()
 out=a.attach.resolve();ledger=out/'feed-prepublication-upgrade.json';mainstate=out/'native-actors.json'
 assert a.resume or not ledger.exists(),'use --resume to preserve exact lifecycle progress'
 before=json.loads(mainstate.read_text());assert not before['events'],'this repair is only for an unpublished community'
 selected={name:releases.inspect((a.feed_packages/(name+'.ltrel')).read_bytes())['release_id']for name in('identity','feed-account','feed','feed-federation')}
 previous=before['configuration']['feed']
 if not a.resume:
  assert all(selected[name]==previous[name]for name in('identity','feed','feed-federation')),'only the account owner may change'
  assert selected['feed-account']!=previous['feed-account'],'corrected account release required'
  snapshot=out/'native-actors-before-status-wire-fix.json';assert not snapshot.exists();snapshot.write_bytes(mainstate.read_bytes())
  state=dict(schema=1,result='pending',started_time_utc=datetime.now(timezone.utc).isoformat(),prior_state_sha256=hashlib.sha256(snapshot.read_bytes()).hexdigest(),prior_failure_sha256=hashlib.sha256((out/'failure-before-status-wire-fix.json').read_bytes()).hexdigest(),old_feed_releases=previous,new_feed_releases=selected,done={},personal={},operations='Native26 stops only unused personal Feed UI/owner; normal admission/relaunch creates current grants; Native42/35/31/38 rebuilds only that personal route and terminal under unchanged approved peers. No operator stop, listen or reset.',authority_reused=False)
 else:
  state=json.loads(ledger.read_text());assert state['new_feed_releases']==selected
  assert previous in(state['old_feed_releases'],selected),'unexpected package selection during explicit upgrade'
 started=time.monotonic();stage='attach unpublished native actors'
 def save():ledger.write_text(json.dumps(state,indent=2)+'\n')
 save()
 with attach_campaign(out,graphical=('alice','charlie'))as campaign:
  assert not campaign.state['done'].get('replication'),'no publication or replication may have started'
  actors=campaign.actors
  def empty():
   observations={}
   for name in('alpha','beta'):
    fields,_=feed.invoke(actors[name].client,491,action=8)
    assert fields[1]==0,(name,fields);observations[name]=list(fields)
   return observations
  try:
   state.setdefault('before_federations',empty());save()
   for name in('charlie','alice'):
    g=actors[name];old=campaign.state['personal'][name]['feed'];entry=state['personal'].setdefault(name,dict(old=old))
    stage='normal native Feed application replacement '+name
    if not entry.get('stopped'):
     retained,_=feed_ui(g,793);assert retained[6]==0,'retained accounts require their explicit recovery workflow'
     fields,public=feed_ui(g);entry['superseded_ui_status']=list(fields);entry['superseded_ui_public']=public[:96].hex()
     net(g,42);net(g,35)
     for instance in(old['ui'],old['owner']):g.client.request(26,struct.pack('<Q',instance))
     entry['stopped']=True;save()
    if 'new'not in entry:
     entry['new']=feed.start(g.client,NS(identity=a.feed_packages/'identity.ltrel',owner=a.feed_packages/'feed-account.ltrel',ui=a.feed_packages/'feed.ltrel',public=PUB,federation=old['federation'],peer=old['selected_peer']));save()
    fresh=entry['new'];g.feed_owner,g.feed_ui=fresh['owner'],fresh['ui']
    assert fresh['owner']!=old['owner']and fresh['ui']!=old['ui'],'dead IPC handles must not revive'
    assert fresh['identity']==old['identity'],'the existing native signer process must remain independently scoped'
    if not entry.get('identity'):
     focus_application(g,'feed');g.device.press(60)
     def identified():
      fields,public=feed_ui(g)
      return public if fields[1]!=0 and len(public)>=96 and public[:32]!=bytes(32)else None
     public=wait(identified,300,'corrected native status returns actual Feed public identity')
     assert public[32:64].hex()==old['federation']and public[64:96].hex()==old['selected_peer'],'native scoped identity differs from selected federation'
     entry['identity']=public.hex();save()
    if not entry.get('audience'):
     public=bytes.fromhex(entry['identity'])
     assert not entry.get('audience_intent'),'interrupted physical audience gesture requires explicit review, not a blind second toggle'
     entry['audience_intent']=True;save();g.device.press(30)
     def audience_settled():
      fields,payload=feed_ui(g);action,pending=struct.unpack_from('<2Q',payload,96)
      return fields[1]!=0 and payload[:32]==public[:32]and(pending==0 or action==0)
     wait(audience_settled,120,'new identity explicitly chooses home and peer audience')
     entry['audience']=True;save()
    if not entry.get('terminal'):
     # A circuit has one terminal BEGIN in the current protocol. A new NK
     # consumer therefore needs a new personal circuit; an old remote ready
     # context must never receive an unrelated fresh handshake on its stream.
     net(g,31)
     def ready():
      fields,_=net(g,32)
      if fields[1]==0 and fields[3]!=0:raise RuntimeError((name,'existing approved route failed',list(fields)))
      return fields if fields[2]==3 else None
     route=wait(ready,900,'same approved peers admit a fresh personal circuit')
     net(g,38,h=3,a=21,b=g.feed_owner,cword=8388608,d=65536)
     def admitted():
      fields,_=net(g,41);return fields if fields[2]==3 else None
     terminal=wait(admitted,600,'fresh owner terminal on approved personal circuit')
     entry.update(terminal=list(terminal),route=list(route));save()
    state['done'][name]=True;save();print('PASS native unused Feed owner/UI replaced, actual public identity and current terminal verified',name,flush=True)
   state['after_federations']=empty()
   for name,entry in state['personal'].items():
    campaign.state['personal'][name]['feed']=entry['new'];campaign.state['personal'][name]['feed_public']=entry['identity'][:64]
    campaign.state['done']['feed-route-'+name]=True
   campaign.state['configuration']['feed']=selected
   campaign.state['feed_prepublication_upgrade']=dict(path=ledger.name,old_account=state['old_feed_releases']['feed-account'],new_account=selected['feed-account'],prior_state_sha256=state['prior_state_sha256'],image_unchanged=True,events_before=0,events_after=0)
   sidecar=out/'registry-input-provenance.json'
   if sidecar.exists():campaign.state['registry_input_provenance']=json.loads(sidecar.read_text())
   mainstate.write_text(json.dumps(campaign.state,indent=2)+'\n')
   state.update(result='pass',completed_time_utc=datetime.now(timezone.utc).isoformat(),elapsed_seconds=time.monotonic()-started,native_image_sha256=campaign.state['configuration']['image_sha256']);save()
  except BaseException as error:
   state.update(result='failure-preserved-native-actors',stage=stage,error=repr(error),traceback=traceback.format_exc(),elapsed_seconds=time.monotonic()-started);save();raise

if __name__=='__main__':main()
