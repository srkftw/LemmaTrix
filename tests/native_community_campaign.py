"""Common-image native Feed, Messenger and Forge on nine concurrent guests.

Only public configuration, signed packages, real input/display and opaque
adapters are controlled here. Native guests author, sign, commit and replicate.
Use --resume only while these exact native actors remain running.
"""
import argparse,base64,contextlib,hashlib,json,socket,struct,subprocess,sys,time,traceback
from datetime import datetime,timezone
from pathlib import Path
from types import SimpleNamespace as NS
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import capsule,feed,federation,identity,messenger,projects,releases,server_store
from messenger_journey import Guest,PUB,SIGN,net,role,wait,wait_ui,inspect,screenshot,public_node,mailbox_start,enroll,enroll_mailbox,approve_ui,route,send_ui
from messenger_product_journey import prepare_personal,publication,ui_public,close_route
from messenger_routed_project import send_reference

SHORT='The project group is reviewing a signed release through native Feed. Our selected peer federation may receive this discussion.'
LONG=('A release review begins with the exact immutable project root and the original publisher signature. A Feed author can point the group to that evidence, but posting a card does not make that person a project maintainer. Each reader must still inspect current admission and choose an existing local project action. Technical admission, authorship, moderation and execution consent remain separate decisions.\n\n'
      'Our discussion is shared only with the two federations selected in the native audience control. A replica preserves original signed bytes and checks the content commitment before accepting them. Replies keep a causal parent and an explicit scope. Following an author remains a local preference; the complete follow list and federation membership are not published with a post. A local block also remains effective when a federation changes its moderation decision.\n\n'
      'Long review notes need bounded chunk access rather than a truncated preview. If one reader pauses a transfer, another person should still exchange Messenger text and inspect an existing project. A committed event should survive operator restart, while an uncertain publication retries the same signed commitment. This connected run checks those practical boundaries using native guests, independent personal keys and separately initialized operator backing.')
REPLY='I read the original discussion through the other federation. Preserve its signed project evidence and our selected audience when following up.'
MSG='native common-image text while independent Feed backfill stalls'
ANSWER='native common-image reply while independent Feed backfill stalls'
REVIEW_NOTES=(
 'Inspect the publisher fingerprint against the original release evidence before treating a project card as an invitation to collaborate.',
 'Check current revocation at the action boundary. A valid old discussion post cannot make a revoked project release eligible for a new local action.',
 'Keep the selected federation policy version visible beside the admission result so a later reader can distinguish technical approval from moderation.',
 'After a lost publication response, retry the retained signed event commitment. A repeated network response must not create a second visible post.',
 'Retain the minimum publishing identity only after explicit approval, and reconcile its generation before allowing an older backup to publish again.',
 'Private drafts and cached history are optional retention choices. Published copies at willing recipient servers are a separate deliberate consequence.',
 'Following this release discussion remains a local preference. Sharing a post with a peer federation does not publish the reader complete follow list.',
 'A report should reach its intended federation moderators through the native service and should not become globally readable timeline content.',
 'An appeal reversal changes the federation decision. It must not silently remove a personal block that a reader still chooses to keep.',
 'Read every checked chunk of a long review before displaying it as verified content. A short preview alone does not establish the complete body hash.',
 'Inter-operator bulk replication has its own explicitly approved transport relationship and finite resource allowance, separate from personal privacy requirements.',
 'If a required three-hop client route fails, show unavailable. A direct socket or an unapproved peer would not satisfy the same user request.',
 'Operators should advertise finite event, byte and work limits, return a useful exhaustion result, and keep unrelated admitted clients making progress.',
 'Forwarding original signed bytes preserves authorship. The receiving federation separately decides whether to admit or moderate the permitted material.'
)

def feed_ui(g,operation=791):
 raw=g.client.request(150,struct.pack('<Q8Q',g.feed_ui,operation,0,0,0,0,0,0,1))
 return struct.unpack_from('<8Q',raw),raw[64:]

def circuit_ready(g):
 fields,_=net(g,32)
 if fields!=getattr(g,'community_circuit_status',None):
  print('Native Feed circuit',g.name,list(fields),flush=True);g.community_circuit_status=fields
 if fields[1]==0 and fields[3]!=0:raise RuntimeError((g.name,'native route failed',list(fields)))
 return fields[2]==3

def terminal_ready(g):
 fields,_=net(g,41)
 if fields!=getattr(g,'community_terminal_status',None):
  print('Native Feed terminal',g.name,list(fields),flush=True);g.community_terminal_status=fields
 if fields[2]==4:raise RuntimeError((g.name,'native terminal failed',list(fields)))
 return fields[2]==3

def focus_application(g,which):
 # Real keyboard gestures probe a new mode transition. Messenger F4 opens its
 # contact input; Tab closes it without canceling an accepted message. Feed F4
 # opens a preview; Escape closes it. Never press F4 in Feed retention mode,
 # where that same key explicitly selects optional private-state retention.
 def mode():return feed_ui(g)[0][2]if which=='feed'else inspect(g)[0][2]
 def observed(predicate):
  try:wait(predicate,2,g.name+' graphical focus transition');return True
  except TimeoutError:return False
 for _ in range(4):
  if feed_ui(g)[0][2]==5:
   g.device.press(1,delay=.1)
   if not observed(lambda:feed_ui(g)[0][2]==0):g.device.chord(56,15);continue
  if mode()!=0:
   g.device.press(1 if which=='feed'else 15,delay=.1)
   if not observed(lambda:mode()==0):
    # When a stale Messenger modal belongs to the other window, undo the
    # focused Feed window's local Tab filter toggle before cycling focus.
    if which=='messenger':g.device.press(15,delay=.1)
    g.device.chord(56,15);continue
  g.device.press(62,delay=.1)
  if observed(lambda:mode()==(9 if which=='feed'else 2)):
   g.device.press(1 if which=='feed'else 15,delay=.1)
   wait(lambda:mode()==0,120,g.name+' native focus probe closed');return
  # The other application received F4; close its corresponding harmless view.
  g.device.press(15 if which=='feed'else 1,delay=.1)
  g.device.chord(56,15);time.sleep(.2)
 raise RuntimeError((g.name,'native graphical focus unavailable',which))

@contextlib.contextmanager
def attach_campaign(output,graphical=('alice','bob','charlie'),skip=()):
 """Attach the same live actors for connected native product continuations.

 The state contains public configuration and ephemeral native handles. A
 restarted guest must be recovered/re-authorized explicitly by its operator;
 this helper refuses to resurrect handles from a prior Network incarnation.
 """
 out=Path(output).resolve();state=json.loads((out/'native-actors.json').read_text())
 assert hashlib.sha256((out/'guest.bin').read_bytes()).hexdigest()==state['configuration']['image_sha256']
 actors={}
 try:
  for name,record in state['actors'].items():
   if name in skip:continue
   g=Guest(name,record['backend'],out,out/'guest.bin',graphical=name in graphical).attach(None)
   actors[name]=g
   assert g.network==record['network'],'explicit native recovery required for restarted '+name
   certificate=out/(name+'.certificate')
   if certificate.exists():g.certificate=certificate.read_bytes();g.pin=hashlib.sha256(g.certificate).digest()
   personal=state['personal'].get(name,{})
   if 'feed'in personal:g.feed_owner=personal['feed']['owner'];g.feed_ui=personal['feed']['ui']
   if 'messenger'in personal:
    g.owner=personal['messenger']['owner'];g.ui=personal['messenger']['ui'];g.delivery=personal['messenger']['delivery']
  yield NS(output=out,state=state,actors=actors)
 finally:
  for g in actors.values():
   if g.device:g.device.close()
   if g.client:g.client.close()

def select_destination(g,certificate):
 """Explicitly revoke a different selected destination before approving it.

 Ordinary enrollment continues refusing an unexpected identity replacement.
 This transition is used only after a personal route has been closed for an
 explicit application/destination choice; operator peer policies are untouched.
 """
 prior,material=net(g,25,h=3,allow=(3,))
 transition=None
 if prior[0]==0 and prior[2]==1 and material[:480]!=certificate:
  transition=dict(previous_certificate_sha256=hashlib.sha256(material[:480]).hexdigest(),selected_certificate_sha256=hashlib.sha256(certificate).hexdigest(),operations=[24,22,23],scope='explicit personal destination slot3; no operator policy change')
  net(g,24,h=3)
 enroll(g,3,certificate)
 if transition:
  path=g.out/(g.name+'.destination-selections.json');records=json.loads(path.read_text())if path.exists()else[]
  records.append(transition);path.write_text(json.dumps(records,indent=2)+'\n')

def select_feed_route(g,destination,relays,*,budget=8388608,attempts=65536):
 """Explicit personal destination selection; operators keep serving peers."""
 close_route(g)
 for slot,relay in enumerate(relays):enroll(g,slot,relay.certificate)
 select_destination(g,destination.certificate)
 observed=[0.0]
 def ready(terminal=False):
  fields,_=net(g,41 if terminal else 32)
  now=time.monotonic()
  if now-observed[0]>=10:
   observed[0]=now;print('Native selected Feed '+('terminal'if terminal else'circuit'),g.name,list(fields),flush=True)
  if terminal and fields[2]==4:raise RuntimeError((g.name,'native terminal failed',list(fields)))
  if not terminal and fields[1]==0 and fields[3]!=0:raise RuntimeError((g.name,'native route failed',list(fields)))
  return fields[2]==3
 net(g,31);wait(ready,900,g.name+' selected Feed circuit')
 net(g,38,h=3,a=21,b=g.feed_owner,cword=budget,d=attempts)
 wait(lambda:ready(True),600,g.name+' selected Feed terminal')
 focus_application(g,'feed')

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--image',type=Path,required=True);p.add_argument('--feed-packages',type=Path,required=True)
 p.add_argument('--messenger-ready',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
 p.add_argument('--mailbox',type=Path);p.add_argument('--delivery',type=Path)
 p.add_argument('--registry',type=Path,default=ROOT/'build/live/apps/native-registry.bin')
 p.add_argument('--public-graph',type=Path,default=ROOT/'build/signed-forge-journey-2/published-closure.json')
 p.add_argument('--publisher',type=Path,default=ROOT/'build/signed-forge-journey-2/publisher.pub')
 p.add_argument('--mixed',action='store_true',help='relay2 uses the native x86_64 RV64 interpreter; both federation services remain QEMU')
 p.add_argument('--history-events',type=int,default=17,choices=range(3,18),help='meaningful UI-authored discussion events, distributed below each author16-event allowance')
 p.add_argument('--replication-auto-renew',action='store_true',help='explicitly approve native rolling leases within the same durable finite replication total')
 p.add_argument('--prior-attempt',type=Path,help='read-only evidence chain for a superseded campaign; never copies native backing or authority')
 p.add_argument('--resume',action='store_true');p.add_argument('--stop-on-exit',action='store_true')
 a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=a.resume)
 statefile=out/'native-actors.json';image=out/'guest.bin'
 if not a.resume:image.write_bytes(a.image.read_bytes())
 assert hashlib.sha256(image.read_bytes()).digest()==hashlib.sha256(a.image.read_bytes()).digest(),'resume requires the same common image'
 fp={n:(a.feed_packages/(n+'.ltrel')).resolve()for n in ('identity','feed-account','feed','feed-federation')}
 manifest=json.loads(a.messenger_ready.read_text());mp={}
 for n in ('identity','owner','ui','delivery','mailbox'):
  source=fp['identity']if n=='identity'else a.mailbox if n=='mailbox'and a.mailbox else a.delivery if n=='delivery'and a.delivery else Path(manifest[n])
  target=out/(n+'.ltrel')
  if not a.resume:target.write_bytes(source.read_bytes())
  assert target.read_bytes()==source.read_bytes(),'resume package changed: '+n
  mp[n]=(target,releases.inspect(target.read_bytes()))
 expected=dict(image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),feed={n:releases.inspect(f.read_bytes())['release_id']for n,f in fp.items()},messenger={n:r['release_id']for n,(_,r)in mp.items()},mixed=a.mixed,history_events=a.history_events)
 if a.replication_auto_renew:expected['replication_auto_renew']=True
 state=json.loads(statefile.read_text())if a.resume else dict(schema=1,configuration=expected,done={},actors={},personal={},events={},checks=[])
 assert state['configuration']==expected,'resume selections changed'
 if not a.resume and a.prior_attempt:
  prior=a.prior_attempt.resolve();state['prior_attempt']=dict(path=str(prior),files={name:hashlib.sha256((prior/name).read_bytes()).hexdigest()for name in('mixed-failure-segment.json','route-failure-observations.json','native-actors.json')},authority_reused=False)
 controller=Path(__file__).read_bytes();segments=state.setdefault('controller_segments',[])
 snapshot=out/('controller-'+str(len(segments)+1)+'.py');snapshot.write_bytes(controller)
 segments.append(dict(git_head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),controller_sha256=hashlib.sha256(controller).hexdigest(),controller_snapshot=snapshot.name,started_time_utc=datetime.now(timezone.utc).isoformat(),prior_failure_sha256=hashlib.sha256((out/'failure.json').read_bytes()).hexdigest()if a.resume and(out/'failure.json').exists()else None))
 statefile.write_text(json.dumps(state,indent=2)+'\n')
 actors=[];byname={};started=time.monotonic();stage='native topology'
 feds=[hashlib.sha256(b'Campaign009 common alpha').hexdigest(),hashlib.sha256(b'Campaign009 common beta').hexdigest()]
 def save():statefile.write_text(json.dumps(state,indent=2)+'\n')
 def continuation():
  # No seeds, unlock material, private draft contents or host social database.
  # These references let separate acceptance continuations observe and operate
  # the same native community, rather than launch unrelated fixture topologies.
  public=dict(schema=1,configuration=expected,actors=state['actors'],personal=state['personal'],events=state['events'],project=state.get('project'),federations=feds,bulk_endpoint=state.get('bulk_endpoint'),helpers=dict(module='tests/native_community_campaign.py',attach='attach_campaign',personal_feed_destination='select_feed_route',graphical_focus='focus_application'),pending_connected_steps=['native project-card Add/Fork with current revocation','federation report/decision/appeal and independent local block','operator restart and replication recovery','approved account retention/portability with original federation offline'],authority='Public configuration and live native handles only; all actions, signatures, persistence and policy decisions remain native.')
  (out/'continuations.json').write_text(json.dumps(public,indent=2)+'\n')
 def record(key,label,**extra):
  observation=dict(check=label,result='pass',**extra)
  state['checks'].append(observation);state['done'][key]=True;save();print('PASS',label,flush=True)
 def actor(name,personal=False,fault=False,store=False):
  backend='x86_64'if a.mixed and name=='relay2'else'qemu'
  backing=out/(name+'.img')
  kwargs=dict(graphical=personal,vault=backing if personal and name!='charlie'else None,store=backing if store else None,network_fault_control=out/'charlie-fault.sock'if fault else None)
  g=Guest(name,backend,out,image,**kwargs)
  if name in state['actors']:
   g.attach(out);assert g.network==state['actors'][name]['network'],'native actor incarnation changed; live handles cannot recover it'
  else:
   if personal and name!='charlie':feed.main(['vault-init',str(backing)])
   if store:server_store.provision(backing)
   g.start();state['actors'][name]=dict(network=g.network,backend=backend);save()
  actors.append(g);byname[name]=g
  cert=out/(name+'.certificate')
  if cert.exists():g.certificate=cert.read_bytes();g.pin=hashlib.sha256(g.certificate).digest()
  return g
 def focus(g,which):focus_application(g,which)
 def fault(op,epoch=None):
  c=dict(op=op,slot=0)
  if epoch is not None:c['epoch']=epoch
  s=socket.socket(socket.AF_UNIX);s.settimeout(10);s.connect(str(out/'charlie-fault.sock'));s.sendall(json.dumps(c).encode()+b'\n');raw=b''
  while b'\n'not in raw:raw+=s.recv(4096)
  s.close();v=json.loads(raw);assert v['ok'],v;return v
 def observe_stall(label,require_paused=False,require_transport=False):
  channel=fault('status')['channel'];terminal=list(net(charlie,41)[0]);expected=state['stall']['epoch']
  paused=channel['epoch']==expected and channel['connected']and channel['tx_paused']
  alive=paused and terminal[2]==3
  observation=dict(stage=label,elapsed_seconds=time.monotonic()-state['stall']['began_monotonic'],channel=channel,terminal=terminal,original_epoch_transport_paused=paused,original_epoch_still_paused=alive)
  state.setdefault('stall_observations',[]).append(observation);save()
  print('Native stalled Feed',label,json.dumps(observation),flush=True)
  if require_paused and not alive:raise RuntimeError(('finite native cleanup ended the stalled context before this contention checkpoint; work remains preserved',observation))
  if require_transport and(not paused or channel['pending_bytes']==0 or terminal[2]not in(0,3)):
   raise RuntimeError(('original stalled transport is no longer pending or has unexpected native state; preserve this epoch',observation))
  return observation
 def match(g,pub,kind,text,parent=None):
  digest=hashlib.sha256(text.encode()).digest();cursor=0
  for _ in range(64):
   f,body=feed.invoke(g.client,491,action=5,handle=cursor,allowed=(0,6))
   if f[0]==6:return None
   assert len(body)==512
   event=body[32:];cursor=f[1]
   if event[112:144]==pub and struct.unpack_from('<Q',event,176)[0]==kind and event[224:256]==digest:
    assert struct.unpack_from('<Q',event,256)[0]==len(text)
    if parent is not None:assert event[192:224]==parent
    assert hashlib.sha256(event).digest()==body[:32]
    return body
  raise RuntimeError('bounded native timeline exhausted during exact event lookup')
 def publish(g,key,text,kind=1,parent=None,home=0):
  cached=state['events'].get(key)
  pub=feed_ui(g)[1][:32]
  existing=match((alpha,beta)[home],pub,kind,text,parent)
  if not existing:
   last=[None]
   def publication_state():
    fields=feed_ui(g)[0]
    if fields!=last[0]:print('Native Feed publication',g.name,key,list(fields),flush=True);last[0]=fields
    if fields[5]==8:raise RuntimeError((g.name,key,'native publication requires exact reconciliation',list(fields)))
    return fields
   focus(g,'feed');wait(lambda:publication_state()[5]in(0,6,7),600,'native previous Feed publication settled')
   g.device.press(61 if kind==1 else 64);wait(lambda:feed_ui(g)[0][2]in(1,6,7),120,'native Feed compose')
   g.device.textASCII(text,delay=.035);wait(lambda:feed_ui(g)[0][3]==len(text),300,'native complete Feed input')
   g.device.press(62);wait(lambda:feed_ui(g)[0][2]==9,120,'native exact content preview');g.device.press(63)
   retries=[0,time.monotonic()]
   def committed():
    row=match((alpha,beta)[home],pub,kind,text,parent)
    if row:return row
    current=publication_state()
    if current[2]==9 and current[4]in(12,14)and current[5]in(0,6,7)and current[3]==len(text)and retries[0]<8 and time.monotonic()-retries[1]>=3:
     g.device.press(63);retries[:]=[retries[0]+1,time.monotonic()]
    return None
   existing=wait(committed,600,'exact native signed Feed event durably committed')
  assert existing[32+272:32+304]==bytes.fromhex(feds[home]) and existing[32+304:32+336]==bytes.fromhex(feds[1-home]),'signed audience was not explicitly selected'
  replica=wait(lambda:match((alpha,beta)[1-home],pub,kind,text,parent),600,'exact original Feed event native replication')
  assert existing==replica
  event=dict(id=existing[:32].hex(),author=pub.hex(),kind=kind,bytes=len(text),content_sha256=hashlib.sha256(text.encode()).hexdigest(),signed_sha256=hashlib.sha256(existing[32:]).hexdigest())
  if cached:assert cached==event
  state['events'][key]=event;save();return existing
 def body_from(g,event_id,length):
  parts=[]
  for offset in range(0,length,512):
   _,payload=feed.invoke(g.client,491,action=6,offset=offset,count=min(512,length-offset),data=event_id);parts.append(payload)
  return b''.join(parts)
 def received(g,text):
  f,_=role(g,2,420)
  for cursor in range(1,f[4]+1):
   f,body=role(g,2,429,h=cursor,allow=(3,))
   if f[0]==0 and body==text.encode():return f
  return None
 def msg_select(g):
  record=state['personal'][g.name]['messenger'];g.owner=record['owner'];g.ui=record['ui'];g.delivery=record['delivery']
 def send_once(g,recipient,key,text,reference=False):
  if received(recipient,text):return
  focus(g,'messenger');before=inspect(g)[0]
  intent=state.setdefault('message_intents',{}).setdefault(key,dict(prior_serial=before[6],text_sha256=hashlib.sha256(text.encode()).hexdigest()))
  assert intent['text_sha256']==hashlib.sha256(text.encode()).hexdigest();save()
  began=time.monotonic()
  if before[6]>intent['prior_serial']:
   # A controller response loss never creates another message. The native
   # owner's retained exact message receives an explicit ordinary GUI retry.
   if before[4]!=19:g.device.press(65,delay=.1)
   wait_ui(g,lambda f:f[6]>intent['prior_serial']and f[4]==19,'existing native exact-message acceptance')
   serial=inspect(g)[0][6]
  else:
   # A partially delivered keyboard stream has not submitted a native message.
   for _ in range(before[3]):g.device.press(14,delay=.01)
   if reference:_,serial,_,_=send_reference(g,text)
   else:serial,_=send_ui(g,text)
  state[key]=dict(serial=serial,seconds=time.monotonic()-began);save()
  wait(lambda:received(recipient,text),600,'native authenticated recipient content')
 try:
  mailbox=actor('mailbox',store=True)
  relays=[actor('relay'+str(i),store=True)for i in(1,2,3)]
  alpha=actor('alpha',store=True);beta=actor('beta',store=True)
  alice=actor('alice',personal=True);bob=actor('bob',personal=True);charlie=actor('charlie',personal=True,fault=True)
  for g,kind in[(mailbox,8),*((g,7)for g in relays),(alpha,16),(beta,16)]:
   if not state['done'].get('node-'+g.name):public_node(g,mp,kind);state['done']['node-'+g.name]=True;save()
  if not state['done'].get('mailbox'):mailbox_start(mailbox,mp);record('mailbox','native durable Mailbox and receipt authority configured')
  else:mailbox.mailbox=messenger.endpoint(mailbox.client,3,440)
  certs=[g.certificate for g in relays]
  if not state['done'].get('peers'):
   enroll(relays[0],0,certs[1]);enroll(relays[1],0,certs[2])
   for slot,g in enumerate((mailbox,alpha,beta)):enroll(relays[2],slot,g.certificate)
   enroll(alpha,0,beta.certificate);enroll(beta,0,alpha.certificate)
   record('peers','public approved relay and destination policies configured independently')
  for i,g in enumerate((alpha,beta)):
   if not state['done'].get('federation-'+g.name):
    config=NS(release=fp['feed-federation'],identity=fp['identity'],public=PUB,namespace=hashlib.sha256(('Campaign009 common store '+g.name).encode()).hexdigest(),federation=feds[i],peer=feds[1-i],moderator=None,events=64,bytes=917504,policy=1)
    state['actors'][g.name]['feed']=feed.federation_start(g.client,config);record('federation-'+g.name,'native federation '+g.name+' owns its independent backing, policy and moderator')
  for g in (alice,bob):
   personal=state['personal'].setdefault(g.name,{})
   if 'messenger'not in personal:
    invitation=prepare_personal(g,mp,mailbox.pin,hashlib.sha256(('Campaign009 common explicit Messenger retention '+g.name).encode()).digest())
    personal['messenger']=dict(owner=g.owner,ui=g.ui,delivery=g.delivery);personal['invitation']=invitation.hex();save()
   else:msg_select(g)
  if not state['done'].get('contacts'):
   approve_ui(alice,bytes.fromhex(state['personal']['bob']['invitation']));approve_ui(bob,bytes.fromhex(state['personal']['alice']['invitation']))
   for g in(alice,bob):_,authority=role(g,2,434,a=10);enroll_mailbox(mailbox,authority)
   record('contacts','two native graphical Messenger identities retain separate domain2 state and approve certified contacts')
  if not state['done'].get('registry'):
   archive=json.loads(a.public_graph.read_text());root=bytes.fromhex(archive['selected'][0]['head']);records=[dict(n,payload=base64.b64decode(n['payload'],validate=True))for n in archive['nodes']]
   key,pub=out/'registry-federation.pem',out/'registry-federation.pub';capsule.generate_key(key,pub);fed=hashlib.sha256(releases.public_modulus(pub)).digest()
   raw,_=releases.make(a.registry,'campaign009-common-registry','0.9.0',2175,SIGN,profile=2);package=out/'registry.ltrel';package.write_bytes(raw)
   for g in(mailbox,bob):registry,_=messenger.install(g.client,package,PUB,2175);g.registry=registry;federation.configure(g.client,registry,pub,'portable')
   actual=projects.import_records(mailbox.client,archive['selected'],records)[0]['cap'];modulus=releases.public_modulus(a.publisher)
   pid=releases.publication(archive['project_id'],hashlib.sha256(modulus).hexdigest());federation.call(mailbox.client,mailbox.registry,3,data=pid+modulus)
   cap=mailbox.client.objects(27,actual,mailbox.registry,25)[0][1];_,decision=federation.call(mailbox.client,mailbox.registry,2,h=cap);assert len(decision)==512
   signed=federation.sign_once(mailbox.client,mailbox.registry,key,'portable');net(mailbox,46,h=mailbox.registry,data=fed)
   state['project']=dict(root=root.hex(),federation=fed.hex(),decision=signed);record('registry','actual existing signed project admitted through native Registry with disclosed existing RSA bootstrap')
  if not state['done'].get('listeners'):
   for g in(*relays,mailbox,alpha,beta):net(g,30)
   record('listeners','native operators listen once and replenish their own bounded admission')
  stage='three personal Feed admissions'
  for g,home in((charlie,0),(alice,1),(bob,0)):
   personal=state['personal'].setdefault(g.name,{})
   if 'feed'not in personal:
    personal['feed']=feed.start(g.client,NS(identity=fp['identity'],owner=fp['feed-account'],ui=fp['feed'],public=PUB,federation=feds[home],peer=feds[1-home]));save()
   g.feed_ui=personal['feed']['ui'];g.feed_owner=personal['feed']['owner']
   if not state['done'].get('feed-route-'+g.name):
    for slot,certificate in enumerate([*certs,(alpha,beta)[home].certificate]):enroll(g,slot,certificate)
    net(g,31);wait(lambda g=g:circuit_ready(g),900,g.name+' native Feed circuit')
    net(g,38,h=3,a=21,b=g.feed_owner,cword=8388608,d=65536);wait(lambda g=g:terminal_ready(g),600,g.name+' authenticated Feed terminal')
    state['done']['feed-route-'+g.name]=True;save()
   if not feed_ui(g)[0][1]:
    focus(g,'feed');g.device.press(60);wait(lambda g=g:feed_ui(g)[0][1]!=0,300,g.name+' scoped Feed identity')
    g.device.press(30)
    def audience_settled(g=g):
     fields,payload=feed_ui(g);action,pending=struct.unpack_from('<2Q',payload,96)
     # A submits native action18; submit/completion replace its transient
     # notice23. A later status read may already be pending after it settles.
     # Exact home/peer bytes remain mandatory in the signed-event assertion.
     return fields[1]!=0 and(pending==0 or action==0)
    wait(audience_settled,120,'native audience selection request settled')
   def actual_public(g=g):
    fields,payload=feed_ui(g)
    return payload[:96]if fields[1]!=0 and len(payload)>=96 and payload[:32]!=bytes(32)else None
   public=wait(actual_public,120,g.name+' actual scoped public identity')
   assert public[32:64]==bytes.fromhex(feds[home])and public[64:96]==bytes.fromhex(feds[1-home])
   personal['feed_public']=public[:32].hex();save()
  if not state['done'].get('three-feed'):
   assert all(net(g,41)[0][2]==3 for g in(charlie,alice,bob));record('three-feed','three independent Feed clients concurrently admitted; two share alpha and all share relays without operator handoff')
  if not state['done'].get('replication'):
   probe=socket.socket();probe.bind(('127.0.0.1',0));endpoint='127.0.0.1:'+str(probe.getsockname()[1]);probe.close()
   scope=hashlib.sha256(b'Campaign009 common explicitly approved replication').hexdigest();state['bulk_endpoint']=endpoint;save()
   for g,side in((alpha,'server'),(beta,'client')):
    state['actors'][g.name]['replication']=feed.replication(g.client,NS(peer=0,side=side,slot=0,scope=scope,endpoint=endpoint,bytes=16777216,rate=65536,lifetime=100000,auto_renew=a.replication_auto_renew));save()
   record('replication','native signed enrollment derives separately approved inter-operator mode3 relationship; personal traffic still requires mode1')
  stage='native signed Feed community'
  first=publish(charlie,'ordinary',SHORT);longrow=publish(charlie,'long',LONG)
  assert len(LONG)>1024 and body_from(alpha,longrow[:32],len(LONG))==LONG.encode()and body_from(beta,longrow[:32],len(LONG))==LONG.encode()
  if not state['done'].get('long-read'):
   focus(bob,'feed');bob.device.press(104);wait(lambda:feed_ui(bob)[0][4]==15,600,'native first chronological post')
   assert feed_ui(bob,795)[1]==first
   bob.device.press(28);wait(lambda:feed_ui(bob)[0][4]==15 and feed_ui(bob,795)[1]==longrow,600,'native full long-body read and validation')
   bob.device.press(109);screenshot(bob,'native-long-review')
   record('long-read','independent native Feed reader paginates chronologically and validates the useful multi-payload long post before displaying it',event=longrow[:32].hex(),bytes=len(LONG))
  if not state['done'].get('follow-reply'):
   focus(alice,'feed');alice.device.press(104);wait(lambda:feed_ui(alice)[0][4]==15,600,'native cross-federation signed read')
   assert feed_ui(alice,795)[1]==first
   alice.device.press(65);wait(lambda:feed_ui(alice)[0][4]==17,180,'native local follow')
   publish(alice,'reply',REPLY,kind=2,parent=first[:32],home=1)
   record('follow-reply','native ordinary and useful long post preserve original signed bytes across two operators; independent reader follows locally and replies across permitted scope',events=state['events'])
  if not state['done'].get('history'):
   for index,note in enumerate(REVIEW_NOTES[:a.history_events-3]):
    g,home=((charlie,0),(alice,1),(bob,0))[index%3]
    publish(g,'review-'+str(index),note,home=home)
   # The native UI has one selected event/body; the service has a committed
   #64-row index and bounded segment cache, not a sixteen-entry Registry feed.
   assert match(alpha,bytes.fromhex(state['events']['ordinary']['author']),1,SHORT)==first
   assert match(beta,bytes.fromhex(state['events']['long']['author']),1,LONG)==longrow
   record('history','meaningful discussion continues beyond the native UI single resident row; original history remains paginated and body commitments remain readable',events=len(state['events']),ui_resident_events=1,service_committed_index_bound=64,body_segment_cache_bytes=131072)
  stage='Messenger admission while independent Feed client remains admitted'
  for g in(alice,bob):
   msg_select(g)
   if not state['done'].get('messenger-route-'+g.name):
    focus(g,'messenger');close_route(g);select_destination(g,mailbox.certificate);route(g,certs,mailbox);wait(lambda g=g:publication(g),600,g.name+' native prekey publication')
    state['done']['messenger-route-'+g.name]=True;save()
  if not state['done'].get('stalled'):
   focus(charlie,'feed');paused=fault('status')['channel'];fault('pause',paused['epoch']);charlie.device.press(104)
   wait(lambda:fault('status')['channel']['pending_bytes']>0,120,'opaque stalled native Feed backfill request')
   state['stall']=dict(epoch=paused['epoch'],began_monotonic=time.monotonic(),ui=list(feed_ui(charlie)[0]));record('stalled','native Feed backfill waits on one exact paused opaque transport epoch while two independent Messenger clients share mailbox')
  stage='native Messenger text and reply during Feed stall'
  if not state['done'].get('messenger'):
   observe_stall('before Messenger',True)
   send_once(alice,bob,'message',MSG);send_once(bob,alice,'reply',ANSWER)
   observe_stall('Messenger text and reply completed',True)
   record('messenger','native graphical text and reply decrypt through shared Mailbox while Feed transport remains paused',text=state.get('message'),reply=state.get('reply'),stalled_feed_ui=list(feed_ui(charlie)[0]))
  stage='actual routed Forge during Feed stall'
  project=state['project'];text='LT-PROJECT1 '+project['root']+' '+project['federation']+' 1'
  send_once(alice,bob,'project_message',text,True)
  if not state['done'].get('forge')or not state.get('forge_verified_fields'):
   if not state.get('forge_verified_fields')and inspect(bob)[0][2]!=6:
    focus(bob,'messenger')
    state.setdefault('forge_roots_before',projects.roots(bob.client));save()
    # The global selected-reference view is populated by F1 itself. The
    # decrypted body was checked above; native F1 requires its parsed contact
    # history record before it can enter inspection mode and expose that view.
    for _ in range(8):
     if ui_public(bob,783)[0][6]==0:bob.device.press(59,delay=.15)
     time.sleep(.3)
     if ui_public(bob,785)[0][1]==6:break
    else:raise TimeoutError('native graphical project inspection selection')
   roots_before=state['forge_roots_before']
   def verified():
    f,selected=ui_public(bob,785)
    if f[1]!=6 or f[5]!=0:return None
    assert f[2]==2 and f[3]==0 and f[4]==project['decision']['sequence']and selected==bytes.fromhex(project['root']+project['federation']),(f,selected)
    return f
   # A resumed observer consumes the completed native operation already saved
   # before its prior strict terminal-liveness assertion, without replaying it.
   result=state.get('forge_verified_fields')or wait(verified,900,'native existing routed Forge signature/admission');assert projects.roots(bob.client)==roots_before
   state['forge_verified_fields']=list(result)
   stalled=observe_stall('routed Forge completion observed',require_transport=True)
   interpretation=dict(original_paused_transport_remains_pending=True,terminal_active_at_observation=stalled['terminal'][2]==3,terminal_reclamation_cause='not directly observed; elapsed native deadline or owner cancellation is inferred'if stalled['terminal'][2]==0 else None,predicate='Messenger requires the original authenticated terminal at completion; Forge requires the same paused transport epoch and pending bytes, and permits the independent terminal to have been reclaimed (user G stalled/disconnected work).')
   record('forge','actual received reference completes existing routed Forge inspection while the independent Feed transfer remains paused, including after its terminal was reclaimed',verified_fields=list(result),execution_approved=False,stall=stalled,interpretation=interpretation)
  stage='native cancellation and independent cleanup'
  if not state['done'].get('cancel'):
   before_cancel=observe_stall('before native input cancellation')
   charlie.device.press(1);wait(lambda:feed_ui(charlie)[0][2]==0,120,'native Feed input cancellation while link paused')
   before=[list(net(g,41)[0])for g in(alice,bob)];cleanup=observe_stall('owned cleanup')
   if cleanup['original_epoch_transport_paused']:fault('resume',state['stall']['epoch'])
   else:
    channel=cleanup['channel']
    assert not channel['connected'],('unexpected replacement or unpaused connection; preserve it instead of resuming or stopping a stale epoch',cleanup)
    state['stall']['ended_before_cleanup']=dict(before_input_cancel=before_cancel,after_input_cancel=cleanup);save()
   net(charlie,42);net(charlie,35)
   assert all(net(g,41)[0][2]==3 for g in(alice,bob));record('cancel','native Feed cancellation and circuit disconnect preserve both unrelated authenticated Messenger sessions',other_sessions=before,stalled_seconds=time.monotonic()-state['stall']['began_monotonic'],before_input_cancel=before_cancel,cleanup=cleanup)
  continuation()
  replication_runtime={}
  if a.replication_auto_renew:
   for g in(alpha,beta):
    lease,_=feed.invoke(g.client,490,action=13);budget,policy=feed.invoke(g.client,490,action=12)
    assert lease[1]==2 and lease[3]!=2,(g.name,lease)
    replication_runtime[g.name]=dict(lease=list(lease),budget=list(budget),policy_hash=policy.hex(),host_lease_renewals=0)
  frames={g.name:screenshot(g,'common-community')for g in(alice,bob)}
  for g in(charlie,alice,bob):
   public=feed_ui(g)[1][:32].hex();assert public!='00'*32 and public==state['personal'][g.name]['feed_public']
   assert any(event['author']==public for event in state['events'].values()),'each displayed author must match a real original signed event'
  report=dict(schema=1,result='pass',configuration=expected,checks=state['checks'],events=state['events'],actors=state['actors'],frames=frames,elapsed_seconds=time.monotonic()-started,controller_segments=state['controller_segments'],replication_runtime=replication_runtime,feed_prepublication_upgrade=state.get('feed_prepublication_upgrade'),registry_input_provenance=state.get('registry_input_provenance'),capacity=dict(transport_channels=16,onion_channels=12,relay_complete_routes_bound=6,observed_simultaneous_personal_clients=3,bulk_channels=4,terminal_banks=16,mailbox_stages=4,mailbox_stage_bytes=8192),limits=['One-host local integration; native x86_64 is an RV64 interpreter when selected.','This connected segment covers signed Feed discussion/replication and Messenger/Forge contention. Project-card Add/Fork, moderation/appeals, restart/retention/migration and refusal cases require their separately recorded connected continuations.','Existing project/Registry RSA package bootstrap remains disclosed; no new Feed-author, moderator or replication private key is held by the host.','Classical native crypto does not qualify Tor interoperability, post-quantum security, independent administration, hostile-government resilience or physical hardware.'])
  (out/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2),flush=True)
 except BaseException as error:
  save();continuation();(out/'failure.json').write_text(json.dumps(dict(schema=1,result='failed-preserved-native-actors',stage=stage,error=repr(error),traceback=traceback.format_exc(),configuration=expected,checks=state['checks'],elapsed_seconds=time.monotonic()-started),indent=2)+'\n');raise
 finally:
  for g in actors:
   if a.stop_on_exit:g.stop()
   else:
    if g.device:g.device.close()
    if g.client:g.client.close()
    if g.log:g.log.close()
if __name__=='__main__':main()
