"""Continue the same community with route refusal, uncertain retry and amnesia.

Authoring uses native graphical input. The fault adapter pauses opaque output
on one exact Charlie connection; operators, other clients and native replication
continue independently. Public exports contain event references, never keys.
"""
import argparse,hashlib,json,socket,struct,sys,time,traceback
from pathlib import Path
from types import SimpleNamespace as NS
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import feed,releases,messenger
from messenger_journey import PUB,net,wait,screenshot
from native_community_campaign import attach_campaign,feed_ui,focus_application,select_feed_route

def service(client,operation,action=0,handle=0,offset=0,count=0,data=b'',allowed=(0,)):
 # A bounded native control request through the same exact service binding.
 # Synchronous150 avoids leaving an unreturned admin async token if this
 # resumable observer is interrupted while a submit response is in transit.
 target=messenger.endpoint(client,6,operation)
 raw=client.request(150,struct.pack('<Q8Q',target,operation,action,handle,offset,count,0,0,1)+data)
 fields=struct.unpack_from('<8Q',raw)
 if fields[0]not in allowed:raise ValueError(('native service refusal',list(fields)))
 return fields,raw[64:]

def read_borrowed_object(client,handle):
 # UI794 shares a distinct read cap with Launcher. Release only that borrowed
 # reference, so repeated observations do not keep the UI's old exports alive.
 try:return client.read_object(handle)
 finally:client.objects(47,handle)

def timeline_rows(client):
 cursor=0
 for _ in range(65):
  fields,body=service(client,491,action=5,handle=cursor,allowed=(0,6))
  if fields[0]==6:return
  assert len(body)==512 and hashlib.sha256(body[32:]).digest()==body[:32]
  assert cursor<fields[1]<=64,fields
  cursor=fields[1]
  yield fields,body
 raise RuntimeError('native bounded timeline has no termination')

UNAVAILABLE='This review note was signed while the required private route was unavailable. Reconnect must publish the exact pending author sequence and event commitment without direct fallback.'
UNCERTAIN=('Release review: a signed community note and a project release make different promises. A note records its author, intended federations, content commitment and causal references. The release must still pass the normal publisher signature and current admission checks before an action in Forge or Library. ' 'The service should preserve an accepted note across a lost connection and report uncertainty honestly to its author. An exact retry should retrieve the existing commitment instead of spending a fresh publication allowance or creating another visible row. Other readers and conversations should continue while that author reconnects. ' 'This review also asks operators to keep finite transport and storage terms visible. Expiry must require explicit approved renewal, and a failed or exhausted request must stay within its own context. Those limits make a small voluntary project community practical without granting a post permission to execute code or changing another federation policy.')

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--attach',type=Path,required=True);p.add_argument('--feed-packages',type=Path,required=True);p.add_argument('--resume',action='store_true');a=p.parse_args()
 out=a.attach.resolve();path=out/'reconnect-progress.json'
 state=json.loads(path.read_text())if a.resume else dict(schema=1,done={},checks=[])
 assert a.resume or not path.exists(),'use --resume to preserve the original observations'
 started=time.monotonic();stage='attach completed native community'
 def save():path.write_text(json.dumps(state,indent=2)+'\n')
 def record(key,label,**extra):state['done'][key]=True;state['checks'].append(dict(check=label,result='pass',**extra));save();print('PASS',label,extra,flush=True)
 with attach_campaign(out,graphical=('charlie',))as campaign:
  actors=campaign.actors;charlie=actors['charlie'];alpha=actors['alpha'];beta=actors['beta'];relays=[actors['relay'+str(i)]for i in(1,2,3)];alice,bob=actors['alice'],actors['bob']
  assert campaign.state['done'].get('cancel'),'core must complete and release Charlie before this continuation'
  configuration=campaign.state['configuration'];state['configuration']=configuration
  assert all(releases.inspect((a.feed_packages/(name+'.ltrel')).read_bytes())['release_id']==configuration['feed'][name]for name in('identity','feed-account','feed')),'continuation requires the exact common-run packages'
  def peers():
   statuses=[list(net(g,41)[0])for g in(alice,bob)]
   assert all(f[2]==3 for f in statuses),statuses
   return statuses
  def fault(op,epoch=None):
   command=dict(op=op,slot=0)
   if epoch is not None:command['epoch']=epoch
   s=socket.socket(socket.AF_UNIX);s.settimeout(10);s.connect(str(out/'charlie-fault.sock'));s.sendall(json.dumps(command).encode()+b'\n');raw=b''
   while b'\n'not in raw:raw+=s.recv(4096)
   s.close();answer=json.loads(raw);assert answer['ok'],answer;return answer['channel']
  def lookup(g,text=None,event_id=None):
   rows=[]
   for f,body in timeline_rows(g.client):
    author=body[32+112:32+144]==bytes.fromhex(campaign.state['personal']['charlie']['feed_public'])
    if event_id is not None and body[:32]==event_id:rows.append(body)
    elif event_id is None and author and(text is None or body[32+224:32+256]==hashlib.sha256(text.encode()).digest()):rows.append(body)
   return rows
  def stats():
   rows=lookup(alpha)
   return dict(author_events=len(rows),author_content_bytes=sum(struct.unpack_from('<Q',row,32+256)[0]for row in rows))
  def export(label):
   charlie.device.press(59);wait(lambda:feed_ui(charlie)[0][2]==5,120,'native profile panel');old=feed_ui(charlie,793)[0][1];charlie.device.press(66)
   wait(lambda:feed_ui(charlie,793)[0][1]not in(0,old),180,'native explicit public profile export')
   f,_=feed_ui(charlie,794);assert f[0]==0;raw=read_borrowed_object(charlie.client,f[1])
   assert len(raw)==2048 and struct.unpack_from('<3Q',raw)==(0x3154524f5046544c,1,0),'public-only profile expected'
   result=dict(sequence=struct.unpack_from('<Q',raw,24)[0],public=raw[32:64].hex(),event=raw[128:160].hex(),generation=struct.unpack_from('<Q',raw,160)[0],sha256=hashlib.sha256(raw).hexdigest())
   (out/(label+'-public-profile.bin')).write_bytes(raw);return result
  last_ui=None
  def observe(label):
   nonlocal last_ui
   f,body=feed_ui(charlie);pending=struct.unpack_from('<Q',body,104)[0];view=(tuple(f),pending)
   if view!=last_ui:print('Native Feed',label,list(f),'pending',pending,flush=True);last_ui=view
   return f,pending
  def exact_retry(label):
   for attempt in range(3):
    wait(lambda:observe(label)[1]==0,120,'native exact retry UI idle')
    charlie.device.press(63)
    end=time.monotonic()+3
    while time.monotonic()<end:
     f,pending=observe(label)
     if f[5]!=8:return
     if f[6]not in(0,12,14):raise RuntimeError(('native exact retry refused',list(f)))
     time.sleep(.1)
   raise RuntimeError(('native exact retry did not start after three explicit gestures',list(observe(label)[0])))
  def receipt(label,timeout=600):
   refreshes=0;last_refresh=0
   def complete():
    nonlocal refreshes,last_refresh
    f,pending=observe(label)
    if f[5]==8:raise RuntimeError(('native publication explicitly requires reconciliation',label,list(f)))
    if f[5]==6 and pending==0 and refreshes<3 and time.monotonic()-last_refresh>=20:
     # The native automatic receipt poll is finite. A user may explicitly
     # refresh the same commitment after the approved replica has caught up.
     charlie.device.press(19);refreshes+=1;last_refresh=time.monotonic()
     print('Native receipt refresh',label,refreshes,flush=True)
    return f[5]==7
   wait(complete,timeout,label)
   wait(lambda:struct.unpack_from('<Q',feed_ui(charlie)[1],104)[0]==0,120,'native completed publication UI request collected')
  def visible(operator,event_id,label):
   f,pending=observe(label)
   if f[5]==8:raise RuntimeError(('native publication explicitly requires reconciliation',label,list(f)))
   return lookup(operator,event_id=event_id)
  def compose(text):
   focus_application(charlie,'feed');wait(lambda:feed_ui(charlie)[0][5]in(0,6,7),180,'native prior publication settled')
   charlie.device.press(61);wait(lambda:feed_ui(charlie)[0][2]==1,120,'native ordinary compose');charlie.device.textASCII(text,delay=.035)
   wait(lambda:feed_ui(charlie)[0][3]==len(text),180,'native complete review input');charlie.device.press(62);wait(lambda:feed_ui(charlie)[0][2]==9,120,'native exact review preview');charlie.device.press(63)
  try:
   peers()
   stage='history exceeds native committed-read working page'
   if not state['done'].get('history-read'):
    events=campaign.state['events'];footprint=sum((event['bytes']+511)//512*512 for event in events.values())
    assert footprint>4096,'core history must exceed the one verified ServerStore read page'
    selected=['ordinary','long',next(reversed(events))];checked=[]
    for key in selected:
     event=events[key];event_id=bytes.fromhex(event['id'])
     for operator in(alpha,beta):
      rows=lookup(operator,event_id=event_id);assert len(rows)==1
      assert hashlib.sha256(rows[0][32:]).hexdigest()==event['signed_sha256']
      body=[]
      for offset in range(0,event['bytes'],512):
       _,part=service(operator.client,491,action=6,offset=offset,count=min(512,event['bytes']-offset),data=event_id);body.append(part)
      original=b''.join(body);assert len(original)==event['bytes']and hashlib.sha256(original).hexdigest()==event['content_sha256']
      checked.append(dict(operator=operator.name,event=event['id'],bytes=len(original),content_sha256=event['content_sha256']))
    record('history-read','native committed storage serves earliest and latest original signed bodies beyond its one verified read page on both federations',events=len(events),padded_content_bytes=footprint,server_store_read_page_bytes=4096,segment_writer_workspace_bytes=131072,reads=checked,unrelated_sessions=peers())
   stage='reconcile prior accepted publication after own backfill timeout'
   if not state['done'].get('unavailable')and(not state['done'].get('ready')or feed_ui(charlie)[0][5]==8):
    prior=list(feed_ui(charlie)[0])
    if prior[5]==8:
     # A bounded backfill timeout may conservatively require reconciliation
     # of the retained last publication. Use its ordinary native exact retry;
     # never clear the warning or substitute a newly authored event.
     known=export('prior-backfill');charlie.device.press(1)
     assert len(lookup(alpha,event_id=bytes.fromhex(known['event'])))==1
     before=stats();select_feed_route(charlie,alpha,relays);exact_retry('prior accepted publication')
     receipt('native prior accepted commitment and replication receipt reconciliation')
     assert stats()==before
     net(charlie,42);net(charlie,35)
     record('ready','accepted publication uncertainty reconciles the exact original through its replication receipt before route closure or new composition',prior_ui=prior,profile=known,author_usage=before,unrelated_sessions=peers())
    else:record('ready','prior publication is settled before required-route refusal test',prior_ui=prior,unrelated_sessions=peers())
   stage='required-mode1 route refusal'
   if not state['done'].get('unavailable'):
    assert net(charlie,41)[0][2]==0 and not lookup(alpha,text=UNAVAILABLE)
    compose(UNAVAILABLE);wait(lambda:feed_ui(charlie)[0][5]==8 and feed_ui(charlie)[0][6]==14,180,'native required mode1 unavailable')
    assert not lookup(alpha,text=UNAVAILABLE)and not lookup(beta,text=UNAVAILABLE)
    state['pending']=export('unavailable');assert state['pending']['event']!='00'*32;charlie.device.press(1)
    record('unavailable','required mode1 failure remains visible; signed pending event is absent from both federations and no direct fallback occurs',profile=state['pending'],unrelated_sessions=peers())
   if not state['done'].get('reconnected'):
    if net(charlie,41)[0][2]!=3:select_feed_route(charlie,alpha,relays)
    if observe('exact pending publication')[0][5]==8:exact_retry('exact pending publication')
    event=wait(lambda:visible(alpha,bytes.fromhex(state['pending']['event']),'exact pending acceptance'),600,'same native pending event accepted after explicit approved reconnect')
    replica=wait(lambda:visible(beta,bytes.fromhex(state['pending']['event']),'exact pending replication'),600,'same pending event native replication');assert event==replica and len(event)==1
    receipt('native accepted reconciliation result and original replication receipt')
    record('reconnected','fresh approved route publishes exactly the original pending event, author and sequence',event=state['pending']['event'],unrelated_sessions=peers())
   stage='finite terminal allowance refusal and reuse'
   if not state['done'].get('allowance'):
    select_feed_route(charlie,alpha,relays,budget=1,attempts=1);charlie.device.press(104)
    wait(lambda:feed_ui(charlie)[0][6]==14,180,'native finite terminal allowance refusal');limited=list(net(charlie,41)[0]);assert limited[2]==3 and limited[4]==1 and limited[5]==1,limited
    before=peers();select_feed_route(charlie,alpha,relays);charlie.device.press(104);wait(lambda:feed_ui(charlie)[0][4]==15,600,'fresh context reads after bounded allowance refusal')
    record('allowance','one exhausted terminal allowance refuses its own request; a fresh selected context reuses resources while other admitted sessions continue',limited_context=limited,unrelated_sessions=before)
   stage='reconcile accepted publication after bounded query refusal'
   if not state['done'].get('cut')and not state['done'].get('allowance-reconciled'):
    # A refused query conservatively leaves a publication warning. Resolve it
    # using the exact accepted author commitment before composing another event.
    known=export('quota-publication');charlie.device.press(1)
    assert known['event']==state['pending']['event']and known['sequence']==state['pending']['sequence'],known
    assert len(lookup(alpha,event_id=bytes.fromhex(known['event'])))==1
    before=stats();prior=list(observe('query refusal publication gate')[0])
    if prior[5]==8:exact_retry('query refusal publication gate')
    receipt('native exact accepted publication reconciliation after query refusal')
    assert stats()==before
    record('allowance-reconciled','native publication gate preserves or reconciles the exact accepted commitment after a bounded query refusal without a new event or renewed author allowance',prior_ui=prior,exact_retry_requested=prior[5]==8,profile=known,author_usage=before,unrelated_sessions=peers())
   stage='publication response lost around durable native acceptance'
   if not state['done'].get('cut'):
    compose(UNCERTAIN)
    seen_new=False
    def pending():
     nonlocal seen_new
     f,ui_pending=observe('new publication commit fault window')
     # F5 prepares and signs asynchronously. The prior publication's cached
     # phase7 is not the new event's acceptance. Observe actual new progress.
     if f[5]in(0,1,2,3,4,5):seen_new=True
     if f[5]==8:raise RuntimeError(('new publication refused before fault',list(f)))
     if seen_new and f[5]in(6,7):raise RuntimeError('new acceptance arrived before fault window; no response-loss claim')
     return f if f[5]in(4,5)else None
    observed=wait(pending,180,'native submitted commit before final acceptance result');channel=fault('status');fault('pause',channel['epoch'])
    row=wait(lambda:lookup(alpha,text=UNCERTAIN),600,'native operator commits event while exact author output is paused');assert len(row)==1
    assert feed_ui(charlie)[0][5]not in(6,7),'acceptance response arrived before paused poll; refusal to inflate response-loss claim'
    state['cut_profile']=export('uncertain');state['accepted_row']=row[0].hex();state['accepted_budget']=stats();state['paused_epoch']=channel['epoch'];save()
    assert state['cut_profile']['event']==row[0][:32].hex()
    charlie.device.press(1);net(charlie,42);net(charlie,35)
    wait(lambda:feed_ui(charlie)[0][5]==8,180,'native missing receipt reconciliation required')
    record('cut','operator commits exact signed event while author cannot obtain final receipt; only that circuit is disconnected',pending_ui=list(observed),profile=state['cut_profile'],accepted_budget=state['accepted_budget'],unrelated_sessions=peers())
   if not state['done'].get('retry'):
    if net(charlie,41)[0][2]!=3:select_feed_route(charlie,alpha,relays)
    if observe('lost acceptance exact retry')[0][5]==8:exact_retry('lost acceptance exact retry')
    rows=lookup(alpha,event_id=bytes.fromhex(state['cut_profile']['event']));assert rows==[bytes.fromhex(state['accepted_row'])]
    replica=wait(lambda:visible(beta,bytes.fromhex(state['cut_profile']['event']),'exact committed replica'),600,'authorized replica serves exact original event');assert replica==rows
    receipt('native exact event retry reconciles durable acceptance and original replication receipt')
    after=stats();assert after==state['accepted_budget'],(state['accepted_budget'],after)
    profile=export('reconciled');charlie.device.press(1);assert profile['event']==state['cut_profile']['event']and profile['sequence']==state['cut_profile']['sequence']
    record('retry','exact retry has one visible publication and unchanged committed author event/byte usage; original signed bytes remain on both federations',profile=profile,budget=after,unrelated_sessions=peers())
   stage='no-vault native process death and fresh application authority'
   if not state['done'].get('ephemeral'):
    net(charlie,42);net(charlie,35)
    old_owner,old_ui=charlie.feed_owner,charlie.feed_ui
    for instance in(old_ui,old_owner):charlie.client.request(26,struct.pack('<Q',instance))
    selected=campaign.state['personal']['charlie']['feed'];bundle=a.feed_packages
    fresh=feed.start(charlie.client,NS(identity=bundle/'identity.ltrel',owner=bundle/'feed-account.ltrel',ui=bundle/'feed.ltrel',public=PUB,federation=selected['federation'],peer=selected['selected_peer']))
    charlie.feed_owner,charlie.feed_ui=fresh['owner'],fresh['ui'];assert charlie.feed_owner!=old_owner and charlie.feed_ui!=old_ui
    f,public=feed_ui(charlie);assert f[1]==0 and public[:96]==bytes(96),(f,public[:96])
    assert lookup(beta,event_id=bytes.fromhex(state['cut_profile']['event']))==[bytes.fromhex(state['accepted_row'])]
    personal=campaign.state['personal']['charlie']
    personal.update(feed=fresh,historical_feed_public=personal['feed_public'],current_feed_identity_present=False,current_feed_public=None)
    (out/'native-actors.json').write_text(json.dumps(campaign.state,indent=2)+'\n')
    record('ephemeral','no-vault author process death removes local publishing state; freshly admitted owner/UI has no identity while authorized replica keeps deliberately published copies',old_owner=old_owner,new_owner=charlie.feed_owner,historical_feed_public=personal['historical_feed_public'],current_feed_identity_present=False,current_feed_public=None,unrelated_sessions=peers())
   state.update(result='pass',elapsed_seconds=time.monotonic()-started,frame=screenshot(charlie,'fresh-ephemeral-feed'),limits=['One-host local integration; no independent administration or physical hardware claim.','Ciphertext output pause after the native commit request was submitted demonstrates missing final acceptance receipt; it does not decrypt or interpret network traffic.','Committed event/byte allowance is compared exactly; no claim that all transport or retry work is free.','Full relay-capacity saturation remains qualified by the separate native paired-resource fixture; this continuation exercises actual per-session allowance refusal and reuse.'])
   save();(out/'reconnect.json').write_text(json.dumps(state,indent=2)+'\n')
  except BaseException as error:
   state.update(result='failure-preserved-native-community',stage=stage,error=repr(error),traceback=traceback.format_exc(),elapsed_seconds=time.monotonic()-started);save();(out/'reconnect-failure.json').write_text(json.dumps(state,indent=2)+'\n');raise

if __name__=='__main__':main()
