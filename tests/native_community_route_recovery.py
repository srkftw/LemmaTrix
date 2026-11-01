"""Recover explicitly selected personal coordinators after a scoped route loss.

Normal parent-linked process lifecycle preserves existing session owners.
The failed episode remains separate; this never claims continuous admission.
"""
import argparse,hashlib,json,socket,struct,sys,time,traceback
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import messenger,releases
from types import SimpleNamespace as NS
from messenger_journey import PUB,net,role,route,wait,inspect,send_ui
from messenger_product_journey import close_route,publication,ui_public
from native_community_campaign import attach_campaign,feed_ui,focus_application,select_feed_route
TEXT='The same approved private session can send after explicit recovery of its selected route.'
REPLY='This native reply confirms recovery without resetting the shared operator or replacing the private session.'

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--attach',type=Path,required=True);p.add_argument('--recover',choices=('alice','bob'),action='append',required=True);p.add_argument('--delivery',type=Path,required=True);p.add_argument('--resume',action='store_true');a=p.parse_args()
 out=a.attach.resolve();path=out/'selected-route-recovery.json'
 assert a.resume or not path.exists(),'preserve the previous recovery episode'
 state=json.loads(path.read_text())if a.resume else dict(schema=1,result='running',recoveries={},checks=[])
 state.setdefault('controller_segments',[]).append(dict(controller_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),started_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),resumed=a.resume,prior_record_sha256=hashlib.sha256(path.read_bytes()).hexdigest()if path.exists()else None))
 started=time.monotonic();stage='attach same native community'
 def save():path.write_text(json.dumps(state,indent=2)+'\n')
 with attach_campaign(out,graphical=('alice','bob','charlie'))as c:
  actors=c.actors;alice,bob,charlie=(actors[n]for n in('alice','bob','charlie'));mailbox=actors['mailbox'];alpha=actors['alpha'];relays=[actors['relay'+str(i)]for i in(1,2,3)]
  state['configuration']=c.state['configuration']
  failure=(out/'reconnect-failure.json').read_bytes();preserved=out/'reconnect-first-peer-failure.json'
  if preserved.exists():assert preserved.read_bytes()==failure
  else:preserved.write_bytes(failure)
  state['prior_failure_sha256']=hashlib.sha256(failure).hexdigest();state['prior_failure_snapshot']=preserved.name
  snapshot=out/'reconnect-controller-1.py'
  controller=(ROOT/'tests/native_community_reconnect.py').read_bytes()
  if snapshot.exists():assert snapshot.read_bytes()==controller
  else:snapshot.write_bytes(controller)
  configuration_hash=hashlib.sha256(json.dumps(c.state['configuration'],sort_keys=True).encode()).hexdigest()
  def persist():
   assert hashlib.sha256(json.dumps(c.state['configuration'],sort_keys=True).encode()).hexdigest()==configuration_hash
   (out/'native-actors.json').write_text(json.dumps(c.state,indent=2)+'\n');save()
  def phase(label):
   nonlocal stage
   stage=label;state['stage']=label;save();print('STAGE',label,flush=True)
  def peers():
   f=[list(net(g,41)[0])for g in(alice,bob)];assert all(x[2]==3 for x in f),f;return f
  def fault(op,epoch=None):
   request=dict(op=op,slot=0)
   if epoch is not None:request['epoch']=epoch
   sock=socket.socket(socket.AF_UNIX);sock.settimeout(10);sock.connect(str(out/'charlie-fault.sock'));sock.sendall(json.dumps(request).encode()+b'\n');raw=b''
   while b'\n'not in raw:raw+=sock.recv(4096)
   sock.close();answer=json.loads(raw);assert answer['ok'],answer;return answer['channel']
  def received(g,text):
   f,_=role(g,2,420)
   for cursor in range(1,f[4]+1):
    fields,body=role(g,2,429,h=cursor,allow=(3,))
    if fields[0]==0 and body==text.encode():return list(fields)
  def message(g,target,text):
   focus_application(g,'messenger');before=inspect(g)[0];assert before[2]==0 and before[3]==0
   began=time.monotonic();serial,_=send_ui(g,text);answer=wait(lambda:received(target,text),600,'actual native recovered-session plaintext')
   return dict(serial=serial,prior_serial=before[6],seconds=time.monotonic()-began,text_sha256=hashlib.sha256(text.encode()).hexdigest(),recipient=answer)
  try:
   package=a.delivery.resolve();raw=package.read_bytes();info=releases.inspect(raw)
   assert info['version']=='0.8.2'and info['rights']==1024
   assert info['parent']==c.state['configuration']['messenger']['delivery'],'normal successor must name the exact initial0.8.1 parent'
   copied=out/'delivery-recovery-0.8.2.ltrel'
   if copied.exists():assert copied.read_bytes()==raw
   else:copied.write_bytes(raw)
   package=copied;state['package']=dict(path=str(package),sha256=hashlib.sha256(raw).hexdigest(),**info)
   for name in dict.fromkeys(a.recover):
    g=actors[name];phase(name+' explicit parent-linked coordinator recovery')
    entry=state['recoveries'].get(name,{})
    if entry.get('new_delivery'):
     assert a.resume and g.delivery==entry['new_delivery']
     assert messenger.endpoint(g.client,4,464)==g.delivery
     assert g.client.request(14,bytes.fromhex(info['project_id']))[64:96].hex()==info['release_id']
     assert g.owner==entry['session_owner']and g.ui==entry['ui']
     recovery=json.loads((out/'personal-network-recovery.json').read_text())
     assert name=='alice'and recovery['new_network']==g.network and recovery['delivery']==g.delivery
     assert net(g,32)[0][1]==0,'resume must not reset a partially admitted current route'
     entry['personal_network_recovery_sha256']=hashlib.sha256((out/'personal-network-recovery.json').read_bytes()).hexdigest()
     phase(name+' resumed selected route after identified personal Network recovery')
    else:
     focus_application(g,'messenger');wait(lambda:ui_public(g,783)[0][6]==0,180,'old local UI request collected')
     before_public=role(g,2,422)[1];old=g.delivery
     entry=dict(old_delivery=old,session_owner=g.owner,ui=g.ui,owner_public_sha256=hashlib.sha256(before_public).hexdigest(),router_before=list(net(g,32)[0]),terminal_before=list(net(g,41)[0]),delivery_before=list(role(g,4,464,a=2)[0]),previous_release=info['parent'],successor_release=info['release_id'],upstream_loss_cause='unknown; prior public observations preserve the scoped loss')
     entry['upstream_loss_cause']='unknown; prior public observations preserve the scoped loss'if entry['router_before'][1]==0 else'no router loss observed; local coordinator receive failure only'
     state['recoveries'][name]=entry;save()
     close_route(g);g.client.request(26,struct.pack('<Q',old))
     active=g.client.request(14,bytes.fromhex(info['project_id']));assert active[64:96].hex()==info['parent']
     result=messenger.delivery_start(g.client,NS(release=package,public=PUB,ui=g.ui,ui_release=out/'ui.ltrel',owner_release=out/'owner.ltrel'))
     new=result['delivery'];assert new!=old and result['owner']==g.owner and result['ui']==g.ui
     assert g.client.request(14,bytes.fromhex(info['project_id']))[64:96].hex()==info['release_id']
     g.delivery=new
     assert role(g,2,422)[1]==before_public,'the existing session owner and public device must remain unchanged'
     c.state['personal'][name]['messenger']['delivery']=new;entry.update(new_delivery=new,normal_parent_linked_admission=True,session_owner_ui_unchanged=True)
     c.state.setdefault('current_runtime_packages',{}).setdefault('messenger_by_person',{})[name]=dict(c.state['configuration']['messenger'],delivery=info['release_id'])
     c.state.setdefault('local_service_recoveries',[]).append(dict(component='messenger.delivery',person=name,old_instance=old,new_instance=new,release=info['release_id'],owner=g.owner,ui=g.ui,image_sha256=c.state['configuration']['image_sha256'],previous_release=info['parent'],kind='explicit parent-linked coordinator replacement; no operator reset'))
     persist();phase(name+' unchanged approved Mailbox route')
    route(g,[r.certificate for r in relays],mailbox);wait(lambda:publication(g),600,'same-owner native prekey publication')
    entry.update(router_after=list(net(g,32)[0]),terminal_after=list(net(g,41)[0]),coordinator_counters=list(role(g,4,464,a=5)[0]));persist()
   state['before_stall']=peers();state['coordinator_counters_before']={g.name:list(role(g,4,464,a=5)[0])for g in(alice,bob)};phase('fresh selected Charlie Feed backfill')
   select_feed_route(charlie,alpha,relays);channel=fault('status');fault('pause',channel['epoch']);charlie.device.press(104);wait(lambda:fault('status')['pending_bytes']>0,120,'native opaque backfill pending')
   held=time.monotonic();state['stall_before']=dict(channel=fault('status'),terminal=list(net(charlie,41)[0]));assert state['stall_before']['terminal'][2]==3;save()
   phase('actual recovered private-session text and reply')
   state['text']=message(alice,bob,TEXT);save();state['reply']=message(bob,alice,REPLY);save()
   state['stall_after']=dict(channel=fault('status'),terminal=list(net(charlie,41)[0]),elapsed_seconds=time.monotonic()-held);save();current=state['stall_after']['channel']
   assert current['epoch']==channel['epoch']and current['connected']and current['tx_paused']and current['pending_bytes']>0
   assert state['stall_after']['terminal'][2]==3,'finite native reclamation happened before the repeated checkpoint'
   charlie.device.press(1);wait(lambda:feed_ui(charlie)[0][2]==0,120,'native backfill input cancellation');fault('resume',channel['epoch']);close_route(charlie)
   state['coordinator_counters_after']={g.name:list(role(g,4,464,a=5)[0])for g in(alice,bob)}
   after=peers()
   for i,g in enumerate((alice,bob)):
    before_counter=state['coordinator_counters_before'][g.name];after_counter=state['coordinator_counters_after'][g.name]
    assert after_counter[1]<=512 and after_counter[2]>=before_counter[2]and after_counter[6]>=before_counter[6]
    assert after[i][4]<=state['before_stall'][i][4]and after[i][5]<=state['before_stall'][i][5],'native parent allowances must remain spent'
   for obsolete in('error','traceback'):state.pop(obsolete,None)
   state.update(result='pass',elapsed_seconds=time.monotonic()-started,unrelated_after=after,checks=['explicit parent-linked coordinator lifecycle retains each approved private session owner and UI','fresh selected personal routes use unchanged peer certificates and required mode1','new native text and reply decrypt while one independent authenticated Feed request remains paused','only Charlie own cancellation follows; shared operators are never reset'],limits=['The preceding scoped Alice link loss remains unexplained and continuous admission is not claimed across recovery.','A local coordinator receive failure and finite allowance require explicit personal lifecycle recovery; this does not reset durable mailbox/event budgets or authorize a new peer.','This episode is separate from the already completed original text/reply and routed Forge checks.'])
   save();print(json.dumps(state,indent=2),flush=True)
  except BaseException as error:
   state.update(result='failure-preserved-native-community',stage=stage,error=repr(error),traceback=traceback.format_exc(),elapsed_seconds=time.monotonic()-started);save();raise
if __name__=='__main__':main()
