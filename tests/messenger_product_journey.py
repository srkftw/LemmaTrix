"""Current product journey: graphical clients, native prekeys, receipts, three relays.

This orchestration imports no session keys and interprets no ciphertext. Explicit
public enrollment, opaque adapters and physical input gestures are its boundary.
"""
from __future__ import annotations
import argparse,contextlib,hashlib,json,os,resource,struct,sys,time,traceback
from pathlib import Path
from messenger_journey import *

def record_binding(g,role_number,service,caller,operation,sid,cid=bytes(32),prior=0):
 generation=messenger.bind(g.client,role_number,service,caller,operation,sid,cid,prior)
 assert generation!=ERR,'native exact binding denied'
 path=g.out/(g.name+'.bindings.json')
 records=json.loads(path.read_text()) if path.exists() else {}
 records[f'{role_number}:{caller}:{operation}']=dict(role=role_number,service=service,caller=caller,operation=operation,generation=generation,service_release=sid.hex(),caller_release=cid.hex())
 path.write_text(json.dumps(records,indent=2)+'\n')
 return generation

def ui_public(g,operation):
 raw=g.client.request(150,struct.pack('<Q8Q',g.ui,operation,0,0,0,0,0,0,1))
 return struct.unpack_from('<8Q',raw),raw[64:]

def prepare_personal(g,packages,mailpin,key,*,recover=False):
 g.owner,sid=install(g,packages,'owner',0)
 g.ui,uid=install(g,packages,'ui',packages['ui'][1]['rights'])
 launcher=messenger.launcher(g.client)
 for op in (420,421,422,429,431,432,433,434):record_binding(g,2,g.owner,launcher,op,sid)
 for op in range(420,436):record_binding(g,2,g.owner,g.ui,op,sid,uid)
 g.client.request(150,struct.pack('<Q8Q',g.ui,781,0,0,0,0,0,0,1)+FED)
 g.device.chord(56,15);time.sleep(.3)
 if recover:unlock_ui(g,key,1)
 else:
  g.device.press(60);wait_ui(g,lambda f:f[4]==41,'graphical native device creation')
  role(g,2,434,a=13,data=mailpin)
  # Exactly three temporary signer grants fit alongside the24 UI/owner grants.
  signer,signer_sid=install(g,packages,'identity',0)
  try:
   for operation in (400,405,402):identity.bind(g.client,signer,launcher,signer_sid,bytes(32),operation)
   _,bundle=role(g,2,422)
   fields,_=identity.invoke(g.client,400,a=2,data=bundle[192:224]+SCOPE)
   subject=bundle[32:64]+bundle[192:224]+bundle[224:256]
   generation=struct.unpack_from('<Q',bundle,16)[0]
   body=struct.pack('<4Q',identity.CONTACT_MAGIC,1,generation,1)+bundle[32:64]+bundle[224:256]+hashlib.sha256(subject).digest()
   permit,_=identity.invoke(g.client,405,h=fields[1],a=launcher,b=1,c=128,data=hashlib.sha256(body).digest())
   _,cert=identity.invoke(g.client,402,h=permit[1],data=body)
   role(g,2,434,a=26,data=cert)
  finally:g.client.request(26,struct.pack('<Q',signer))
  unlock_ui(g,key,0)
 # The temporary signer is gone before eight coordinator grants fill the32.
 g.delivery,did=install(g,packages,'delivery',1024)
 for op in (427,428,434):record_binding(g,2,g.owner,g.delivery,op,sid,did)
 for op in range(460,464):record_binding(g,4,g.delivery,g.ui,op,did,uid)
 record_binding(g,4,g.delivery,launcher,464,did)
 _,invitation=role(g,2,434,a=27)
 assert len(invitation)==672
 (g.out/(g.name+'.invitation')).write_bytes(invitation)
 return invitation

def replace_personal_ui(g,packages,key):
 # Replace only applications. Existing non-networked session owner and native
 # backing remain intact; exact generation bindings are recreated by teardown.
 rows=identity.instances(g.client)
 try:
  g.owner=messenger.endpoint(g.client,2,420);g.delivery=messenger.endpoint(g.client,4,464)
  g.ui=next(row[0] for row in rows if row[2]==799 and 0<row[1]<5)
  active=g.client.request(14,bytes.fromhex(packages['ui'][1]['project_id']))
  if active[64:96]==bytes.fromhex(packages['ui'][1]['release_id']):
   state,_=role(g,2,420)
   if state[1]!=1 or state[5]!=1:unlock_ui(g,key,1)
   _,invitation=role(g,2,434,a=27);assert len(invitation)==672
   return invitation
 except (ValueError,StopIteration):pass
 for row in rows:
  if 0<row[1]<5 and row[2] in (799,1024):g.client.request(26,struct.pack('<Q',row[0]))
 try:g.owner=messenger.endpoint(g.client,2,420)
 except ValueError:
  for row in identity.instances(g.client):
   if row[0]&255>=7 and 0<row[1]<5 and row[2]==0:g.client.request(26,struct.pack('<Q',row[0]))
  g.owner,sid=install(g,packages,'owner',0)
  for op in (420,421,422,429,431,432,433,434):record_binding(g,2,g.owner,messenger.launcher(g.client),op,sid)
 else:sid=bytes.fromhex(packages['owner'][1]['release_id'])
 g.ui,uid=install(g,packages,'ui',799)
 for op in range(420,436):record_binding(g,2,g.owner,g.ui,op,sid,uid)
 g.delivery,did=install(g,packages,'delivery',1024)
 for op in (427,428,434):record_binding(g,2,g.owner,g.delivery,op,sid,did)
 for op in range(460,464):record_binding(g,4,g.delivery,g.ui,op,did,uid)
 record_binding(g,4,g.delivery,messenger.launcher(g.client),464,did)
 g.client.request(150,struct.pack('<Q8Q',g.ui,781,0,0,0,0,0,0,1)+FED)
 g.device.chord(56,15);time.sleep(.3)
 if role(g,2,420)[0][1]==1:lock_ui(g)
 unlock_ui(g,key,1)
 _,invitation=role(g,2,434,a=27);assert len(invitation)==672
 (g.out/(g.name+'.invitation')).write_bytes(invitation)
 return invitation

def publication(g):
 f,_=role(g,4,464,a=1)
 if f[2]:raise AssertionError((g.name,'public prekey publication failed',f))
 return f if f[1]==5 else None

def lock_ui(g):
 g.device.press(66,delay=.1)
 wait_ui(g,lambda f:f[4]==23,'graphical Messenger lock')
 wait(lambda:role(g,2,420)[0][1]==0,120,'native owner clears access')
 wait(lambda:ui_public(g,783)[0][6]==0,120,'broker clears protected capabilities')
 denied,_=role(g,2,429,h=1,allow=(5,));assert denied[0]==5

def close_route(g):
 net(g,42);net(g,35)

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--image',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
 p.add_argument('--ready-packages',type=Path,required=True,help='public exact release paths, created after final native package build')
 p.add_argument('--mailbox-fault-control',action='store_true',help='opt only the started mailbox adapter into output/mailbox-fault.sock for later opaque acceptance-cut checks')
 p.add_argument('--history-backup',action='store_true',help='after received import, actually lock Bob, copy his opaque backing and graphically recover before replying')
 p.add_argument('--mixed',action='store_true');p.add_argument('--stop-on-exit',action='store_true');p.add_argument('--attach-actors',action='store_true',help='reattach existing public actor portals and replace UI only after observed application fix');p.add_argument('--recover-actors',type=Path,help='restart actors from explicit native-encrypted backings in prior campaign directory');p.add_argument('--operators-running',action='store_true',help='reattach this exact directory after a host provisioning failure; preserve native enrolled operators')
 a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=a.operators_running or a.attach_actors)
 image=out/'guest.bin';image.write_bytes(a.image.read_bytes());actors=[];checks=[];began=time.monotonic();stage='native operator package build'
 report=dict(schema=2,result='running',image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),checks=checks,private_keys='all operational keys generated and retained inside native guest owners; host handles only opaque backing and public invitations',operator_independence=False,assurance='classical; one local operator; no Tor interoperability or global correlation assurance')
 def record(label,**values):
  checks.append(dict(check=label,result='pass',**values));(out/'progress.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS',label,flush=True)
 def actor(name,backend='qemu',personal=False):
  backing=out/(name+'.img')
  fault=out/'mailbox-fault.sock'if a.mailbox_fault_control and name=='mailbox'else None
  if a.attach_actors:
   g=Guest(name,backend,out,image,graphical=personal,vault=backing if personal else None,store=None if personal else backing,network_fault_control=fault)
   g.attach(out);actors.append(g);return g
  if a.recover_actors and backing.exists():
   assert backing.stat().st_size>0,'missing retained actor backing'
  elif personal:
   if backing.exists():
    assert backing.stat().st_size==0,'refuse overwrite of existing personal backing'
    backing.unlink()
   messenger.main(['vault-init',str(backing)])
  else:server_store.provision(backing)
  g=Guest(name,backend,out,image,graphical=personal,vault=backing if personal else None,store=None if personal else backing,network_fault_control=fault).start();actors.append(g);return g
 try:
  if a.attach_actors:
   previous_failure=out/'failure.json'
   if previous_failure.exists():
    saved=out/'failure-before-foreground-ui.json';saved.write_bytes(previous_failure.read_bytes());report['prior_adapter_failure']=str(saved)
   packages={name:(out/(name+'.ltrel'),releases.inspect((out/(name+'.ltrel')).read_bytes())) for name in ('identity','mailbox')}
   def attach_operator(name,backend='qemu'):
    g=actor(name,backend);g.certificate=(out/(name+'.certificate')).read_bytes();_,material=net(g,25,h=4)
    assert material[:480]==g.certificate and material[480:]==hashlib.sha256(g.certificate).digest()
    g.pin=material[480:];g.identity_package=packages['identity'][0];g.identity_service=identity.endpoint(g.client,400);g.identity_seed_retained=True
    return g
   mailbox=attach_operator('mailbox');mailbox.mailbox=messenger.endpoint(mailbox.client,3,441)
   relays=[attach_operator('relay'+str(i),'x86_64' if a.mixed and i==2 else 'qemu') for i in (1,2,3)]
  elif a.recover_actors:
   previous=a.recover_actors.resolve()
   report['recovered_campaign']=str(previous)
   packages={}
   for name in ('identity','mailbox'):
    path=out/(name+'.ltrel');path.write_bytes((previous/(name+'.ltrel')).read_bytes());packages[name]=(path,releases.inspect(path.read_bytes()))
   backing_size=max((previous/(name+'.img')).stat().st_size for name in ('mailbox','relay1','relay2','relay3','alice','bob'))
   soft,hard=resource.getrlimit(resource.RLIMIT_FSIZE)
   if soft!=resource.RLIM_INFINITY and soft<backing_size:
    assert hard==resource.RLIM_INFINITY or hard>=backing_size
    resource.setrlimit(resource.RLIMIT_FSIZE,(backing_size,hard))
   for name in ('mailbox','relay1','relay2','relay3','alice','bob'):
    subprocess.run(['cp','--reflink=auto','--sparse=always',str(previous/(name+'.img')),str(out/(name+'.img'))],check=True)
   mailbox=actor('mailbox');restore_operator(mailbox,previous);mailbox_start(mailbox,packages)
   relays=[]
   for i in (1,2,3):
    g=actor('relay'+str(i),'x86_64' if a.mixed and i==2 else 'qemu');restore_operator(g,previous);relays.append(g)
  elif a.operators_running:
   old_failure=json.loads((out/'failure.json').read_text())
   report['adapter_recovery']={'previous_failure':old_failure,'correction':'public vault-init provisions explicit backing with a backing-sized host file limit; no native key or mailbox state edited'}
   packages={name:(out/(name+'.ltrel'),releases.inspect((out/(name+'.ltrel')).read_bytes())) for name in ('identity','mailbox')}
   def attach_operator(name,backend='qemu'):
    fault=out/'mailbox-fault.sock'if a.mailbox_fault_control and name=='mailbox'else None
    g=Guest(name,backend,out,image,store=out/(name+'.img'),network_fault_control=fault).attach(out);actors.append(g)
    g.certificate=(out/(name+'.certificate')).read_bytes();_,material=net(g,25,h=4)
    assert material[:480]==g.certificate and material[480:]==hashlib.sha256(g.certificate).digest()
    g.pin=material[480:];g.identity_package=packages['identity'][0];g.identity_service=identity.endpoint(g.client,400);g.identity_seed_retained=True
    return g
   mailbox=attach_operator('mailbox');mailbox.mailbox=messenger.endpoint(mailbox.client,3,441)
   relays=[attach_operator('relay'+str(i),'x86_64' if a.mixed and i==2 else 'qemu') for i in (1,2,3)]
  else:
   packages={name:package(out,module,entry,name,rights) for name,module,entry,rights in [('identity','Guest.Identity','Guest.Identity.main',0),('mailbox','Guest.Mailbox','Guest.Mailbox.main',2048)]}
   stage='native sealed operator enrollment'
   mailbox=actor('mailbox');public_node(mailbox,packages,8);mailbox_start(mailbox,packages)
   relays=[]
   for i in (1,2,3):
    g=actor('relay'+str(i),'x86_64' if a.mixed and i==2 else 'qemu');public_node(g,packages,7);relays.append(g)
  certs=[g.certificate for g in relays];allcerts=[*certs,mailbox.certificate]
  assert len({c[112:144] for c in allcerts})==4
  assert len({c[224:256] for c in allcerts})==4
  assert len({c[256:288] for c in allcerts})==4
  if not a.operators_running and not a.attach_actors:
   enroll(relays[0],0,certs[1]);enroll(relays[1],0,certs[2]);enroll(relays[2],0,mailbox.certificate)
   listen_operators(relays,mailbox)
  record('four native operators independently generate, seal, and enroll actual public credentials',backends=[g.backend for g in relays],mailbox_pin=mailbox.pin.hex(),finite_receipt_authorization=65536)
  stage='await exact final product packages'
  wait(lambda:a.ready_packages.exists(),1800,'final product package identities')
  ready=json.loads(a.ready_packages.read_text())
  for name in ('owner','ui','delivery'):
   source=Path(ready[name]);path=out/(name+'.ltrel');path.write_bytes(source.read_bytes());packages[name]=(path,releases.inspect(path.read_bytes()))
  report['packages']={n:i for n,(_,i) in packages.items()}
  assert packages['owner'][1]['rights']==0 and packages['ui'][1]['rights']==799 and packages['delivery'][1]['rights']==1024
  stage='graphical personal creation certification and retention'
  ak=hashlib.sha256(b'Campaign008 disclosed Alice vault-unlock fixture').digest();bk=hashlib.sha256(b'Campaign008 disclosed Bob vault-unlock fixture').digest()
  alice=actor('alice',personal=True);ai=replace_personal_ui(alice,packages,ak) if a.attach_actors else prepare_personal(alice,packages,mailbox.pin,ak,recover=bool(a.recover_actors))
  bob=actor('bob',personal=True);bi=replace_personal_ui(bob,packages,bk) if a.attach_actors else prepare_personal(bob,packages,mailbox.pin,bk,recover=bool(a.recover_actors))
  # Resolve the exact installed releases from public native binding records.
  # A reattached actor may legitimately retain an older owner or coordinator.
  mapping_path=out/'actor-packages.json'
  previous_mapping=json.loads(mapping_path.read_text())if mapping_path.exists()else{}
  actor_packages={}
  for g in(alice,bob):
   binding_records=json.loads((out/(g.name+'.bindings.json')).read_text())
   owner_binding=binding_records[f'2:{g.ui}:420'];delivery_binding=binding_records[f'4:{g.ui}:460']
   assert owner_binding['service']==g.owner and delivery_binding['service']==g.delivery
   actual={'owner':owner_binding['service_release'],'ui':owner_binding['caller_release'],'delivery':delivery_binding['service_release']}
   actor_packages[g.name]={}
   for name,release_id in actual.items():
    candidates=[packages[name][0],Path(ready[name])]
    if name in previous_mapping.get(g.name,{}):candidates.append(Path(previous_mapping[g.name][name]))
    matches=[path.resolve()for path in candidates if path.exists()and releases.inspect(path.read_bytes())['release_id']==release_id]
    if not matches:raise ValueError(('exact installed public package path unavailable',g.name,name,release_id))
    actor_packages[g.name][name]=str(matches[0])
  mapping_path.write_text(json.dumps(actor_packages,indent=2)+'\n');report['actor_packages']=actor_packages
  assert ai[32:64]!=bi[32:64]
  record('two native messaging devices and scoped certificates recovered through actual graphical domain2 consent' if a.recover_actors else 'two real graphical F2 native messaging devices receive scoped public contact certificates and explicit graphical domain2 retention',invitation_bytes=len(ai),grants_per_personal=32)
  stage='graphical contact approval and native mailbox enrollment'
  afp=approve_ui(alice,bi);bfp=approve_ui(bob,ai)
  for g in (alice,bob):
   _,authority=role(g,2,434,a=10);enroll_mailbox(mailbox,authority)
  record('actual pointer approves certified imported device fingerprints and native separate deposit/fetch authority',alice_fingerprint=afp,bob_fingerprint=bfp)
  stage='recipient initial routed public prekey publication'
  setup=route(bob,certs,mailbox);pub=wait(lambda:publication(bob),240,'durable native public prekey publication')
  record('recipient publishes native signed prekey and one-time public prekey through authenticated three-relay terminal',route_setup_seconds=setup,publication_state=list(pub))
  lock_ui(bob);close_route(bob);reset_operators(relays,mailbox);bob.stop()
  record('recipient entire personal guest is offline before sender circuit and deposit')
  stage='graphical offline text through current product'
  setup=route(alice,certs,mailbox);wait(lambda:publication(alice),240,'sender prekey publication')
  message,seconds=send_ui(alice,'native offline message through three relays')
  record('graphical text uses durable native prekey claim before encryption and signed durable mailbox acceptance through three distinct relays',message=message,route_setup_seconds=setup,acceptance_seconds=seconds)
  stage='useful project attachment through graphical chunk path'
  cap,head,files=import_useful_project(alice)
  alice.device.press(87,delay=.15) # F11: trusted compositor selection.
  wait_ui(alice,lambda f:f[4]==76,'trusted attachment project picker')
  alice.device.press(28,delay=.15)
  last_transfer=[None]
  def uploaded():
   f=transfer_state(alice)
   if f!=last_transfer[0]:print('Alice transfer',f,flush=True);last_transfer[0]=f
   if f[1]==9:raise AssertionError(('native attachment failed',f,ui_public(alice,783)[0]))
   return f if f[1]==8 else None
  transfer=wait(uploaded,1800,'native useful chunk upload')
  record('real graphical F11 selects useful existing Objects project and streams encrypted bounded chunks',canonical_root=head,source_bytes=sum(map(len,files.values())),source_files=list(files),native_transfer=list(transfer))
  stage='actual mailbox restart and native protected recovery'
  lock_ui(alice);close_route(alice);reset_operators(relays,mailbox)
  mailbox.stop();mailbox.start();restore_operator(mailbox,out);mailbox_start(mailbox,packages);reset_operators(relays,mailbox)
  record('actual mailbox process and guest restart recovers ciphertext and same sealed native node and receipt identities')
  stage='recipient restart graphical recovery decrypt and reply'
  bob.start();restored=prepare_personal(bob,packages,mailbox.pin,bk,recover=True);assert restored==bi
  bob.device.press(1,delay=.1);wait_ui(bob,lambda f:f[2]==0 and f[5]==1,'recovered approved contact')
  setup=route(bob,certs,mailbox);wait(lambda:publication(bob),240,'recipient restart public prekey publication')
  wait_ui(bob,lambda f:f[4]==20,'routed recovered plaintext display')
  f,text=role(bob,2,429,h=1);assert text==b'native offline message through three relays'
  screenshot(bob,'received-after-restart')
  record('actual recipient restart plus graphical authorized recovery decrypts offline text and commits before delete',inbox_serial=f[1],route_setup_seconds=setup)
  # Both message and manifest must have committed before attachment import.
  def manifest():
   f,_=role(bob,2,420)
   return f if f[4]>=2 else None
  wait(manifest,300,'received attachment manifest')
  bob.device.click(400,385,delay=.15) # Explicit native footer import; F12 belongs to the compositor.
  last_import=[None]
  def imported():
   f=transfer_state(bob)
   if f!=last_import[0]:print('Bob transfer',f,flush=True);last_import[0]=f
   if f[1]==9:raise AssertionError(('native import failed',f,ui_public(bob,783)[0]))
   return f if f[1]==24 else None
  received=wait(imported,1800,'explicit graphical received project import')
  record('actual graphical pointer retrieves authenticates and explicitly imports useful project; ciphertext blobs acknowledged after Objects commit',native_transfer=list(received),expected_root=head)
  if a.history_backup:
   stage='explicit locked opaque recipient backup and graphical recovery'
   lock_ui(bob);close_route(bob);reset_operators(relays,mailbox)
   backup=out/'bob-history-backup.img'
   if backup.exists():raise FileExistsError('refuse replacing the preserved history source backing')
   size=bob.vault.stat().st_size;soft,hard=resource.getrlimit(resource.RLIMIT_FSIZE)
   if soft!=resource.RLIM_INFINITY and soft<size:
    assert hard==resource.RLIM_INFINITY or hard>=size
    resource.setrlimit(resource.RLIMIT_FSIZE,(size,hard))
   subprocess.run(['cp','--reflink=auto','--sparse=always',str(bob.vault),str(backup)],check=True)
   with backup.open('rb')as saved:os.fsync(saved.fileno())
   unlock_ui(bob,bk,1);bob.device.press(1,delay=.1)
   wait_ui(bob,lambda f:f[2]==0 and f[5]==1,'Bob recovered approved contact after locked backup')
   setup=route(bob,certs,mailbox);wait(lambda:publication(bob),240,'recipient prekey publication after locked backup')
   record('actual graphical F8 lock precedes opaque sparse history backup; actual F9 normal recovery and approved route precede reply',history_backup=str(backup),backing_bytes=backup.stat().st_size,route_setup_seconds=setup)
  message,seconds=send_ui(bob,'native routed reply after recovery')
  record('recovered recipient composes graphical routed reply with signed durable mailbox acceptance',message=message,acceptance_seconds=seconds)
  lock_ui(bob);close_route(bob);reset_operators(relays,mailbox)
  unlock_ui(alice,ak,1);alice.device.press(1,delay=.1)
  wait_ui(alice,lambda f:f[2]==0 and f[5]==1,'Alice recovered approved contact')
  setup=route(alice,certs,mailbox);wait_ui(alice,lambda f:f[4]==20,'routed reply display')
  f,text=role(alice,2,429,h=1);assert text==b'native routed reply after recovery'
  screenshot(alice,'routed-reply');record('original sender decrypts routed graphical reply after explicit domain2 lock and recovery',route_setup_seconds=setup,inbox_serial=f[1])
  report.update(result='passed-connected-product',elapsed_seconds=time.monotonic()-began,incomplete_acceptance=['connected interruption/failure matrix','routed conversation Forge request','old-backup import in connected run (separate native supported restore test exists)','ephemeral/Objects separation in connected run (separate native tests exist)'])
  (out/'evidence.json').write_text(json.dumps(report,indent=2)+'\n')
 except BaseException as error:
  report.update(result='failed-preserved-actors',stage=stage,error=repr(error),traceback=traceback.format_exc(),elapsed_seconds=time.monotonic()-began)
  (out/'failure.json').write_text(json.dumps(report,indent=2)+'\n');raise
 finally:
  if a.stop_on_exit:
   for g in reversed(actors):
    with contextlib.suppress(Exception):g.stop()
  else:
   for g in actors:
    if g.device:g.device.close()
    if g.client:g.client.close()

if __name__=='__main__':main()
