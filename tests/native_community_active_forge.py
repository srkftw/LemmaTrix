"""Repeat real routed Forge while one fresh Feed request remains active.

Uses the existing nine native actors and an already received genuine project
reference. The UI must expose fresh work before completion; a cached view alone
cannot pass. Only Charlie's selected route and opaque fault epoch are changed.
"""
import argparse,hashlib,json,socket,sys,time,traceback
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from messenger_journey import net,wait
from messenger_product_journey import ui_public
from native_community_campaign import attach_campaign,feed_ui,focus_application,select_feed_route

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--attach',type=Path,required=True);a=p.parse_args()
 out=a.attach.resolve();path=out/'active-forge.json';assert not path.exists(),'preserve the prior active-Forge episode'
 state=dict(schema=1,checks=[],started_monotonic=time.monotonic(),controller_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest());stage='attach same native community'
 def save():path.write_text(json.dumps(state,indent=2)+'\n')
 with attach_campaign(out,graphical=('charlie','bob'))as campaign:
  assert campaign.state['done'].get('cancel'),'complete the original scoped cleanup first'
  state['configuration']=campaign.state['configuration'];state['core_evidence_sha256']=hashlib.sha256((out/'evidence.json').read_bytes()).hexdigest()
  charlie,bob=campaign.actors['charlie'],campaign.actors['bob'];alpha=campaign.actors['alpha'];relays=[campaign.actors['relay'+str(i)]for i in(1,2,3)]
  def peers():
   f=[list(net(campaign.actors[n],41)[0])for n in('alice','bob')];assert all(x[2]==3 for x in f),f;return f
  def fault(op,epoch=None):
   request=dict(op=op,slot=0)
   if epoch is not None:request['epoch']=epoch
   sock=socket.socket(socket.AF_UNIX);sock.settimeout(10);sock.connect(str(out/'charlie-fault.sock'));sock.sendall(json.dumps(request).encode()+b'\n');raw=b''
   while b'\n'not in raw:raw+=sock.recv(4096)
   sock.close();reply=json.loads(raw);assert reply['ok'],reply;return reply['channel']
  try:
   state['unrelated_before']=peers();stage='fresh selected Charlie Feed route'
   select_feed_route(charlie,alpha,relays)
   focus_application(bob,'messenger');wait(lambda:ui_public(bob,783)[0][6]==0,180,'native Messenger UI idle before fresh inspection')
   state['bob_before']=list(net(bob,41)[0]);assert state['bob_before'][2]==3
   stage='pause one fresh native Feed backfill'
   channel=fault('status');state['epoch']=channel['epoch'];fault('pause',state['epoch'])
   charlie.device.press(104);wait(lambda:fault('status')['pending_bytes']>0,120,'fresh opaque Feed request pending')
   started=time.monotonic();state['stall_before']=dict(channel=fault('status'),terminal=list(net(charlie,41)[0]));save()
   assert state['stall_before']['terminal'][2]==3
   stage='ordinary native F1 submits new routed Forge request'
   bob.device.press(59)
   busy=wait(lambda:(f if(f:=ui_public(bob,785)[0])[5]in(1,2)else None),30,'fresh native Forge work rather than cached display');state['fresh_busy_fields']=list(busy);save()
   project=campaign.state['project'];expected=bytes.fromhex(project['root']+project['federation'])
   def verified():
    fields,reference=ui_public(bob,785)
    if fields[5]!=0:return None
    assert fields[1:5]==(6,2,0,project['decision']['sequence'])and reference==expected,(fields,reference.hex())
    remaining=list(net(bob,41)[0]);assert remaining[2]==3
    if remaining[4]>=state['bob_before'][4]or remaining[5]>=state['bob_before'][5]:return None
    return dict(fields=list(fields),bob_after=remaining,reference=reference.hex())
   state['verified']=wait(verified,90,'fresh routed Forge response and native finite request/byte consumption')
   state['elapsed_stall_seconds']=time.monotonic()-started;state['stall_after']=dict(channel=fault('status'),terminal=list(net(charlie,41)[0]));save()
   channel=state['stall_after']['channel'];assert channel['epoch']==state['epoch']and channel['connected']and channel['tx_paused']and channel['pending_bytes']>0,channel
   assert state['stall_after']['terminal'][2]==3,'finite native cleanup happened before this fresh active-terminal checkpoint'
   stage='cancel and retire only Charlie owned epoch'
   charlie.device.press(1);wait(lambda:feed_ui(charlie)[0][2]==0,120,'native input cancellation')
   current=fault('status');assert current['epoch']==state['epoch']and current['connected']and current['tx_paused'],current
   fault('resume',state['epoch']);net(charlie,42);net(charlie,35);state['unrelated_after']=peers()
   state.update(result='pass',checks=['ordinary native F1 exposed fresh in-flight Forge work before its verified completion','native terminal byte and request allowances both decreased while exact original release/admission fields were returned','same fresh Feed transport epoch remained paused with pending bytes and authenticated terminal phase3 at Forge completion','native cancellation and only Charlie route teardown preserved unrelated Alice/Bob phase3'],limits=['One-host mixed QEMU/native-x86 integration; x86 executes the RV64 guest through its native interpreter.','Budget consumption plus UI busy-to-complete and exact reference evidence establish a fresh existing consumer request; this does not decrypt captured transport.','The original longer episode separately records terminal reclamation, without asserting it remained active there.'])
   save();print(json.dumps(state,indent=2),flush=True)
  except BaseException as error:
   state.update(result='failure-preserved-native-community',stage=stage,error=repr(error),traceback=traceback.format_exc());save();raise

if __name__=='__main__':main()
