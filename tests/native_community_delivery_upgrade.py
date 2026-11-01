"""Replace only Delivery, then repeat native Messenger/Forge on the same guests.

The initial common-image configuration stays immutable. This continuation uses
normal parent-linked package admission, fresh exact bindings and personal route
selection; it never replaces a session owner, operator, backing or private key.
"""
import argparse,hashlib,json,socket,struct,sys,time,traceback
from pathlib import Path
from types import SimpleNamespace as NS
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import federation,identity,messenger,releases
from messenger_journey import PUB,net,role,route,wait,inspect,send_ui
from messenger_product_journey import close_route,publication,ui_public
from messenger_routed_project import send_reference
from native_community_campaign import attach_campaign,feed_ui,focus_application,select_destination,select_feed_route
TEXT='Native Delivery0.8.1 text keeps the existing private session while a separate Feed backfill is paused.'
REPLY='Native Delivery0.8.1 reply confirms that the replaced coordinator preserves the same approved contact and session.'

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--attach',type=Path,required=True);p.add_argument('--delivery',type=Path,required=True);a=p.parse_args()
 out=a.attach.resolve();path=out/'delivery-upgrade.json';assert not path.exists(),'preserve the prior upgrade; inspect an interrupted stage before further work'
 package=a.delivery.resolve();info=releases.inspect(package.read_bytes());initial=json.loads((out/'native-actors.json').read_text())['configuration']
 assert info['version']=='0.8.1'and info['rights']==1024
 assert info['parent']==initial['messenger']['delivery'],'normal upgrade must name the exact current Delivery predecessor'
 configuration_sha=hashlib.sha256(json.dumps(initial,sort_keys=True).encode()).hexdigest()
 progress=dict(schema=1,result='running',configuration=initial,configuration_sha256=configuration_sha,controller_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),package=dict(path=str(package),sha256=hashlib.sha256(package.read_bytes()).hexdigest(),**info),checks=[],upgrades={})
 started=time.monotonic();stage='attach same native actors'
 def save():path.write_text(json.dumps(progress,indent=2)+'\n')
 def passed(label,**extra):progress['checks'].append(dict(check=label,result='pass',**extra));save();print('PASS',label,extra,flush=True)
 def phase(label):
  nonlocal stage
  stage=label;progress['stage']=stage;save();print('STAGE',label,flush=True)
 with attach_campaign(out,graphical=('alice','bob','charlie'))as campaign:
  actors=campaign.actors;alice,bob,charlie=(actors[n]for n in('alice','bob','charlie'));mailbox=actors['mailbox'];alpha=actors['alpha'];relays=[actors['relay'+str(i)]for i in(1,2,3)]
  assert campaign.state['configuration']==initial
  def persist_runtime():
   assert hashlib.sha256(json.dumps(campaign.state['configuration'],sort_keys=True).encode()).hexdigest()==configuration_sha
   (out/'native-actors.json').write_text(json.dumps(campaign.state,indent=2)+'\n')
  def peers():
   states=[list(net(g,41)[0])for g in(alice,bob)];assert all(f[2]==3 for f in states),states;return states
  def fault(op,epoch=None):
   command=dict(op=op,slot=0)
   if epoch is not None:command['epoch']=epoch
   sock=socket.socket(socket.AF_UNIX);sock.settimeout(10);sock.connect(str(out/'charlie-fault.sock'));sock.sendall(json.dumps(command).encode()+b'\n');raw=b''
   while b'\n'not in raw:raw+=sock.recv(4096)
   sock.close();answer=json.loads(raw);assert answer['ok'],answer;return answer['channel']
  def received(g,text):
   f,_=role(g,2,420)
   for cursor in range(1,f[4]+1):
    fields,body=role(g,2,429,h=cursor,allow=(3,))
    if fields[0]==0 and body==text.encode():return list(fields)
   return None
  def ordinary_message(g,target,text,reference=False):
   focus_application(g,'messenger');before=inspect(g)[0];assert before[2]==0 and before[3]==0
   began=time.monotonic()
   if reference:old,serial,_,_=send_reference(g,text);assert old==before[6]
   else:serial,_=send_ui(g,text)
   result=wait(lambda:received(target,text),600,'new native recipient plaintext')
   return dict(serial=serial,prior_serial=before[6],seconds=time.monotonic()-began,text_sha256=hashlib.sha256(text.encode()).hexdigest(),recipient=result)
  def stall(label):
   phase('fresh selected Charlie route for '+label);select_feed_route(charlie,alpha,relays)
   channel=fault('status');fault('pause',channel['epoch']);charlie.device.press(104)
   wait(lambda:fault('status')['pending_bytes']>0,120,'actual opaque Feed backfill pending')
   state=dict(epoch=channel['epoch'],started=time.monotonic(),channel=fault('status'),terminal=list(net(charlie,41)[0]));assert state['terminal'][2]==3
   progress[label+'_stall']=state;save();return state
  def observe_stall(held):
   channel=fault('status');terminal=list(net(charlie,41)[0])
   assert channel['epoch']==held['epoch']and channel['connected']and channel['tx_paused']and channel['pending_bytes']>0
   assert terminal[2]==3,('finite native cleanup occurred before this checkpoint',terminal)
   return dict(channel=channel,terminal=terminal,seconds=time.monotonic()-held['started'])
  def close_stall(held):
   charlie.device.press(1);wait(lambda:feed_ui(charlie)[0][2]==0,120,'native query input cancellation')
   current=fault('status');assert current['epoch']==held['epoch']
   if current['tx_paused']:fault('resume',held['epoch'])
   close_route(charlie);return peers()
  try:
   phase('ordinary parent-linked Delivery replacement')
   for g in(alice,bob):
    focus_application(g,'messenger');wait(lambda g=g:ui_public(g,783)[0][6]==0,180,'old native UI request collected')
    personal=campaign.state['personal'][g.name]['messenger'];old=personal['delivery'];owner,ui=personal['owner'],personal['ui']
    assert messenger.endpoint(g.client,2,434)==owner
    prior_state=role(g,2,420)[0];assert prior_state[1]==1,'existing retained session owner must remain unlocked'
    _,public=role(g,2,422);identity=public[32:64].hex()
    active=g.client.request(14,bytes.fromhex(info['project_id']));assert active[64:96].hex()==info['parent']
    entry=dict(old_delivery=old,owner=owner,ui=ui,public_device_identity=identity,prior_owner_status=list(prior_state));progress['upgrades'][g.name]=entry;save()
    # Close only this personal route, then retire its old ordinary coordinator.
    close_route(g);g.client.request(26,struct.pack('<Q',old));entry['old_delivery_stopped']=True;save()
    result=messenger.delivery_start(g.client,NS(release=package,public=PUB,ui=ui,ui_release=out/'ui.ltrel',owner_release=out/'owner.ltrel'))
    assert result['owner']==owner and result['ui']==ui and result['delivery']!=old
    assert messenger.endpoint(g.client,4,464)==result['delivery']
    assert g.client.request(14,bytes.fromhex(info['project_id']))[64:96].hex()==info['release_id']
    _,after_public=role(g,2,422);assert after_public[32:64].hex()==identity
    g.delivery=result['delivery'];personal['delivery']=g.delivery
    runtime=campaign.state.setdefault('current_runtime_packages',{}).setdefault('messenger',dict(initial['messenger']));runtime['delivery']=info['release_id']
    entry.update(new_delivery=g.delivery,current_delivery_release=info['release_id'],exact_new_bindings=True,owner_ui_unchanged=True)
    campaign.state.setdefault('package_upgrade_audit',[]).append(dict(component='messenger.delivery',person=g.name,old_release=info['parent'],new_release=info['release_id'],old_instance=old,new_instance=g.delivery,owner=owner,ui=ui,image_sha256=initial['image_sha256'],normal_parent_linked_admission=True))
    persist_runtime();save();print('Native Delivery upgraded',g.name,entry,flush=True)
   for g in(alice,bob):
    phase(g.name+' new Delivery authenticated Mailbox route');select_destination(g,mailbox.certificate);route(g,[r.certificate for r in relays],mailbox);wait(lambda g=g:publication(g),600,'same-owner native prekey publication')
   passed('only Delivery packages and their exact caller grants were replaced; retained session owners/UI/contacts kept their identities',upgrades=progress['upgrades'],unrelated_operators='All nine original Network incarnations checked by attach; no operator restart/stop/listen.')
   held=stall('message');phase('new native text and reply with authenticated paused Feed transfer')
   sent=ordinary_message(alice,bob,TEXT);answered=ordinary_message(bob,alice,REPLY)
   passed('new Delivery text and reply decrypt through the real shared Mailbox while fresh Charlie terminal remains authenticated and paused',text=sent,reply=answered,stall=observe_stall(held),sessions=peers())
   close_stall(held)
   phase('Alice independent current public Registry view for genuine project inspection')
   project=campaign.state['project']
   def registry_instance(g):
    rows=[row[0]for row in identity.instances(g.client)if row[2]==2175 and 0<row[1]<5];assert len(rows)==1,(g.name,rows);return rows[0]
   _,original_descriptor=federation.call(mailbox.client,registry_instance(mailbox),6)
   assert original_descriptor[320:352].hex()==project['root']and struct.unpack_from('<Q',original_descriptor,48)[0]==project['decision']['sequence']
   bob_registry=registry_instance(bob);_,bob_known=federation.call(bob.client,bob_registry,6)
   assert bob_known[320:352].hex()==project['root']and struct.unpack_from('<Q',bob_known,16)[0]==3 and struct.unpack_from('<Q',bob_known,48)[0]>project['decision']['sequence'],'Bob known superseding revocation must remain effective'
   progress['registry_before']=dict(remote_original_sha256=hashlib.sha256(original_descriptor).hexdigest(),bob_known_sha256=hashlib.sha256(bob_known).hexdigest(),bob_known_sequence=struct.unpack_from('<Q',bob_known,48)[0],bob_known_classification=3)
   registry_package=out/'registry.ltrel';registry_info=releases.inspect(registry_package.read_bytes());registry,_=messenger.install(alice.client,registry_package,PUB,2175)
   config=federation.configure(alice.client,registry,out/'registry-federation.pub','portable')
   # This verifier starts with no cached decision. Bob's known revocation is not
   # removed, copied away, or bypassed. The unchanged remote issuer still serves
   # its original signed sequence1; this records Alice's independent knowledge.
   empty=alice.client.request(150,struct.pack('<Q8Q',registry,6,0,0,0,0,0,0,1));assert struct.unpack_from('<Q',empty)[0]==6
   progress['alice_registry']=dict(instance=registry,release=registry_info['release_id'],configuration=config,initial_catalog_status=6,known_remote_sequence=campaign.state['project']['decision']['sequence'],scope='Independent fresh verifier; no fresh knowledge of Bob local revocation, no global latest assertion.')
   campaign.state['personal']['alice']['registry']=dict(instance=registry,release=registry_info['release_id']);persist_runtime();save()
   project=campaign.state['project'];reference='LT-PROJECT1 '+project['root']+' '+project['federation']+' 1'
   reference_message=ordinary_message(bob,alice,reference,True)
   held=stall('forge');phase('fresh native routed Forge through new Alice Delivery')
   focus_application(alice,'messenger');wait(lambda:ui_public(alice,783)[0][6]==0,180,'native Messenger UI idle');before=list(net(alice,41)[0]);alice.device.press(59)
   busy=wait(lambda:(f if(f:=ui_public(alice,785)[0])[5]in(1,2)else None),30,'fresh native Forge request')
   expected=bytes.fromhex(project['root']+project['federation'])
   def verified():
    fields,material=ui_public(alice,785)
    if fields[5]!=0:return None
    assert fields[1:5]==(6,2,0,project['decision']['sequence'])and material==expected,(fields,material.hex())
    after=list(net(alice,41)[0]);assert after[2]==3
    return dict(fields=list(fields),reference=material.hex(),before=before,after=after)if after[4]<before[4]and after[5]<before[5]else None
   result=wait(verified,90,'fresh exact signed project response under Alice known policy')
   _,cached_descriptor=federation.call(alice.client,registry,6);assert cached_descriptor==original_descriptor,'Native verifier must cache the original signed bytes unchanged'
   _,bob_after=federation.call(bob.client,bob_registry,6);assert bob_after==bob_known,'Alice inspection cannot rewrite Bob known revocation'
   result['native_cached_signed_descriptor_sha256']=hashlib.sha256(cached_descriptor).hexdigest()
   result['bob_superseding_revocation_unchanged']=True
   passed('new Delivery completes a fresh routed Forge signature/admission inspection under Alice independent permitted view while Charlie terminal3 stays paused',reference_message=reference_message,verified=result,stall=observe_stall(held),execution_approved=False,policy_scope=progress['alice_registry']['scope'])
   after=close_stall(held)
   progress.update(result='pass',elapsed_seconds=time.monotonic()-started,unrelated_sessions_after=after,initial_configuration_unchanged=True,limits=['Same690 image and original independent operators/backings; only ordinary Delivery parent-linked package/grants changed.','Prior core text/reply/Forge records remain attributed to old0.8.0 Delivery; these new gestures are separately attributed to0.8.1.','Alice verifies the remote issuer original signed sequence1 under her independently configured knowledge. Bob known sequence2 revocation is not undone; this is not a global-current or no-revocation claim.','No execution, new release signing, host social event, allowance refill or operator handoff occurs.'])
   save()
  except BaseException as error:
   progress.update(result='failure-preserved-native-community',stage=stage,error=repr(error),traceback=traceback.format_exc(),elapsed_seconds=time.monotonic()-started);save();raise
 print(json.dumps(progress,indent=2))
if __name__=='__main__':main()
