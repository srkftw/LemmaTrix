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
import feed,releases
from messenger_journey import PUB,net,wait,screenshot
from native_community_campaign import attach_campaign,feed_ui,focus_application,select_feed_route

UNAVAILABLE='This review note was signed while the required private route was unavailable. Reconnect must publish the exact pending author sequence and event commitment without direct fallback.'
UNCERTAIN='The federation committed this release-review note while its author could not receive the acceptance result. Reconciliation must preserve this exact original signature and avoid a duplicate publication.'

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
   rows=[];cursor=0
   for _ in range(64):
    f,body=feed.invoke(g.client,491,action=5,handle=cursor,allowed=(0,6))
    if f[0]==6:return rows
    assert len(body)==512 and hashlib.sha256(body[32:]).digest()==body[:32]
    cursor=f[1]
    author=body[32+112:32+144]==bytes.fromhex(campaign.state['personal']['charlie']['feed_public'])
    if event_id is not None and body[:32]==event_id:rows.append(body)
    elif author and(text is None or body[32+224:32+256]==hashlib.sha256(text.encode()).digest()):rows.append(body)
   raise RuntimeError('native bounded timeline has no termination')
  def stats():
   rows=lookup(alpha)
   return dict(author_events=len(rows),author_content_bytes=sum(struct.unpack_from('<Q',row,32+256)[0]for row in rows))
  def export(label):
   charlie.device.press(59);wait(lambda:feed_ui(charlie)[0][2]==5,120,'native profile panel');old=feed_ui(charlie,793)[0][1];charlie.device.press(66)
   wait(lambda:feed_ui(charlie,793)[0][1]not in(0,old),180,'native explicit public profile export')
   f,_=feed_ui(charlie,794);assert f[0]==0;raw=charlie.client.read_object(f[1])
   assert len(raw)==2048 and struct.unpack_from('<3Q',raw)==(0x3154524f5046544c,1,0),'public-only profile expected'
   result=dict(sequence=struct.unpack_from('<Q',raw,24)[0],public=raw[32:64].hex(),event=raw[128:160].hex(),generation=struct.unpack_from('<Q',raw,160)[0],sha256=hashlib.sha256(raw).hexdigest())
   (out/(label+'-public-profile.bin')).write_bytes(raw);return result
  def compose(text):
   focus_application(charlie,'feed');wait(lambda:feed_ui(charlie)[0][5]in(0,6,7),180,'native prior publication settled')
   charlie.device.press(61);wait(lambda:feed_ui(charlie)[0][2]==1,120,'native ordinary compose');charlie.device.textASCII(text,delay=.035)
   wait(lambda:feed_ui(charlie)[0][3]==len(text),180,'native complete review input');charlie.device.press(62);wait(lambda:feed_ui(charlie)[0][2]==9,120,'native exact review preview');charlie.device.press(63)
  try:
   peers()
   stage='required-mode1 route refusal'
   if not state['done'].get('unavailable'):
    assert net(charlie,41)[0][2]==0 and not lookup(alpha,text=UNAVAILABLE)
    compose(UNAVAILABLE);wait(lambda:feed_ui(charlie)[0][5]==8 and feed_ui(charlie)[0][6]==14,180,'native required mode1 unavailable')
    assert not lookup(alpha,text=UNAVAILABLE)and not lookup(beta,text=UNAVAILABLE)
    state['pending']=export('unavailable');assert state['pending']['event']!='00'*32;charlie.device.press(1)
    record('unavailable','required mode1 failure remains visible; signed pending event is absent from both federations and no direct fallback occurs',profile=state['pending'],unrelated_sessions=peers())
   if not state['done'].get('reconnected'):
    select_feed_route(charlie,alpha,relays);charlie.device.press(63)
    event=wait(lambda:lookup(alpha,event_id=bytes.fromhex(state['pending']['event'])),600,'same native pending event accepted after explicit approved reconnect')
    replica=wait(lambda:lookup(beta,event_id=bytes.fromhex(state['pending']['event'])),600,'same pending event native replication');assert event==replica and len(event)==1
    wait(lambda:feed_ui(charlie)[0][5]in(6,7),180,'native accepted reconciliation result')
    record('reconnected','fresh approved route publishes exactly the original pending event, author and sequence',event=state['pending']['event'],unrelated_sessions=peers())
   stage='finite terminal allowance refusal and reuse'
   if not state['done'].get('allowance'):
    select_feed_route(charlie,alpha,relays,budget=1,attempts=1);charlie.device.press(104)
    wait(lambda:feed_ui(charlie)[0][6]==14,180,'native finite terminal allowance refusal');limited=list(net(charlie,41)[0]);assert limited[2]==3 and limited[4]==1 and limited[5]==1,limited
    before=peers();select_feed_route(charlie,alpha,relays);charlie.device.press(104);wait(lambda:feed_ui(charlie)[0][4]==15,600,'fresh context reads after bounded allowance refusal')
    record('allowance','one exhausted terminal allowance refuses its own request; a fresh selected context reuses resources while other admitted sessions continue',limited_context=limited,unrelated_sessions=before)
   stage='publication response lost around durable native acceptance'
   if not state['done'].get('cut'):
    compose(UNCERTAIN)
    def pending():
     f=feed_ui(charlie)[0]
     if f[5]in(6,7):raise RuntimeError('acceptance arrived before fault window; no response-loss claim')
     return f if f[5]==5 else None
    observed=wait(pending,180,'native commit pending before final acceptance result');channel=fault('status');fault('pause',channel['epoch'])
    row=wait(lambda:lookup(alpha,text=UNCERTAIN),600,'native operator commits event while exact author output is paused');assert len(row)==1
    assert feed_ui(charlie)[0][5]not in(6,7),'acceptance response arrived before paused poll; refusal to inflate response-loss claim'
    state['cut_profile']=export('uncertain');state['accepted_row']=row[0].hex();state['accepted_budget']=stats();state['paused_epoch']=channel['epoch'];save()
    assert state['cut_profile']['event']==row[0][:32].hex()
    charlie.device.press(1);net(charlie,42);net(charlie,35)
    wait(lambda:feed_ui(charlie)[0][5]==8,180,'native missing receipt reconciliation required')
    record('cut','operator commits exact signed event while author cannot obtain final receipt; only that circuit is disconnected',pending_ui=list(observed),profile=state['cut_profile'],accepted_budget=state['accepted_budget'],unrelated_sessions=peers())
   if not state['done'].get('retry'):
    select_feed_route(charlie,alpha,relays);charlie.device.press(63);wait(lambda:feed_ui(charlie)[0][5]in(6,7),600,'native exact event retry reconciles durable acceptance')
    rows=lookup(alpha,event_id=bytes.fromhex(state['cut_profile']['event']));assert rows==[bytes.fromhex(state['accepted_row'])]
    replica=wait(lambda:lookup(beta,event_id=bytes.fromhex(state['cut_profile']['event'])),600,'authorized replica serves exact original event');assert replica==rows
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
    campaign.state['personal']['charlie']['feed']=fresh;(out/'native-actors.json').write_text(json.dumps(campaign.state,indent=2)+'\n')
    record('ephemeral','no-vault author process death removes local publishing state; freshly admitted owner/UI has no identity while authorized replica keeps deliberately published copies',old_owner=old_owner,new_owner=charlie.feed_owner,unrelated_sessions=peers())
   state.update(result='pass',elapsed_seconds=time.monotonic()-started,frame=screenshot(charlie,'fresh-ephemeral-feed'),limits=['One-host local integration; no independent administration or physical hardware claim.','Ciphertext output pause demonstrates lost final acceptance receipt; it does not decrypt or interpret network traffic.','Committed event/byte allowance is compared exactly; no claim that all transport or retry work is free.','Full relay-capacity saturation remains qualified by the separate native paired-resource fixture; this continuation exercises actual per-session allowance refusal and reuse.'])
   save();(out/'reconnect.json').write_text(json.dumps(state,indent=2)+'\n')
  except BaseException as error:
   state.update(result='failure-preserved-native-community',stage=stage,error=repr(error),traceback=traceback.format_exc(),elapsed_seconds=time.monotonic()-started);save();(out/'reconnect-failure.json').write_text(json.dumps(state,indent=2)+'\n');raise

if __name__=='__main__':main()
