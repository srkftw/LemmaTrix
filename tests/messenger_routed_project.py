"""Conversation-selected existing Forge metadata through the Messenger broker.

Run --prepare-only while the central product campaign owns its portals. Execute
only after its operator explicitly hands off the preserved actors. This helper
never edits a backing, session, mailbox row or native application state. It uses
public project import, disclosed existing federation RSA bootstrap, native
management commands, and actual graphical input. Operational keys stay native.
"""
from __future__ import annotations
import argparse,base64,hashlib,json,struct,sys,time,traceback
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import capsule,federation,identity,messenger,projects,releases
from messenger_journey import Guest,net,role,wait,wait_ui,inspect,screenshot,route,reset_operators,unlock_ui,PUB,SIGN
from messenger_product_journey import lock_ui,close_route,ui_public,publication


def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare(args):
 out=args.output.resolve();out.mkdir(parents=True,exist_ok=True)
 graph=args.public_graph.resolve();archive=json.loads(graph.read_text())
 assert archive['schema']==1 and len(archive['selected'])==1
 root=bytes.fromhex(archive['selected'][0]['head'])
 records=[dict(record,payload=base64.b64decode(record['payload'],validate=True))for record in archive['nodes']]
 # These are the existing public canonical nodes, not a replacement catalog.
 assert len(root)==32 and any(record['kind']==13 for record in records)
 binary=args.registry_binary.resolve();package=out/'native-registry.ltrel'
 if not package.exists():
  raw,_=releases.make(binary,'messenger-existing-registry','0.8.0',2175,SIGN,profile=2,license='NOASSERTION');package.write_bytes(raw)
 info=releases.inspect(package.read_bytes());assert info['rights']==2175
 assert info['executable_sha256']==digest(binary),'refuse replacing the prepared Registry binary'
 key,pub=out/'federation.pem',out/'federation.pub'
 if not key.exists()and not pub.exists():capsule.generate_key(key,pub)
 if not key.exists()or not pub.exists():raise ValueError('incomplete explicit federation RSA bootstrap files')
 federation_id=hashlib.sha256(releases.public_modulus(pub)).digest()
 prepared=dict(schema=1,result='prepared-no-actors-contacted',registry_package=str(package),registry=info,
  public_graph=str(graph),public_graph_sha256=digest(graph),project_root=root.hex(),logical_project=archive['project_id'],
  publisher=str(args.publisher.resolve()),publisher_sha256=digest(args.publisher),federation=federation_id.hex(),
  source_nodes=len(records),source_bytes=sum(len(record['payload'])for record in records),
  host_authority='existing public project import and explicit native-decision RSA bootstrap only; no operational messaging keys')
 prior=out/'prepared.json'
 if prior.exists():assert json.loads(prior.read_text())==prepared,'prepared public input identity changed'
 else:prior.write_text(json.dumps(prepared,indent=2)+'\n')
 return out,archive,records,prepared


def current_packages(campaign):
 manifest=json.loads((campaign/'actor-packages.json').read_text())
 packages={}
 for actor in('alice','bob'):
  packages[actor]={}
  for name,rights in(('owner',0),('ui',799),('delivery',1024)):
   path=Path(manifest[actor][name]).resolve();info=releases.inspect(path.read_bytes())
   assert info['rights']==rights,(actor,name,info['rights'])
   packages[actor][name]=dict(path=str(path),sha256=digest(path),release=info)
 return packages


def validate_bindings(g,campaign,packages):
 records=json.loads((campaign/(g.name+'.bindings.json')).read_text())
 expected=[]
 for op in range(420,436):expected.append((2,g.owner,g.ui,op,'owner','ui'))
 for op in range(460,464):expected.append((4,g.delivery,g.ui,op,'delivery','ui'))
 for op in(427,428,434):expected.append((2,g.owner,g.delivery,op,'owner','delivery'))
 selected={}
 for role_number,service,caller,operation,service_name,caller_name in expected:
  key=f'{role_number}:{caller}:{operation}';record=records[key]
  assert all(record[field]==value for field,value in(('role',role_number),('service',service),('caller',caller),('operation',operation))),record
  assert record['generation']>0
  assert record['service_release']==packages[service_name]['release']['release_id'],record
  assert record['caller_release']==packages[caller_name]['release']['release_id'],record
  selected[key]=record
 return selected


def attach(campaign,out,name,personal,packages=None):
 config=campaign/(name+'.public-configuration.json')
 backend=json.loads(config.read_text())['backend']if config.exists()else'qemu'
 g=Guest(name,backend,campaign,campaign/'guest.bin',graphical=personal,
  vault=campaign/(name+'.img')if personal else None,store=None if personal else campaign/(name+'.img'))
 g.attach(campaign);g.out=out;g.client.journey_trace=out/(name+'.management-request.json')
 if personal:
  g.owner=messenger.endpoint(g.client,2,420);g.delivery=messenger.endpoint(g.client,4,464)
  ui_rights=packages['ui']['release']['rights']
  matches=[row[0]for row in identity.instances(g.client)if row[2]==ui_rights and 0<row[1]<5]
  assert len(matches)==1,(name,matches);g.ui=matches[0]
  g.binding_records=validate_bindings(g,campaign,packages)
 else:
  g.certificate=(campaign/(name+'.certificate')).read_bytes();_,material=net(g,25,h=4)
  assert material[:480]==g.certificate and material[480:]==hashlib.sha256(g.certificate).digest()
  g.pin=material[480:]
 return g


def send_reference(g,text):
 before,_=inspect(g);old_message=before[6]
 assert before[2]==0 and before[3]==0 and before[5]==1,('native conversation must be selected and empty',before)
 g.device.textASCII(text,delay=.08)
 wait_ui(g,lambda f:f[3]==len(text),'actual project-reference keyboard composition')
 began=time.monotonic()
 # A real repeated Enter is permitted only while the first admission has not
 # changed the visible serial. It never invokes the owner queue from the host.
 for attempt in range(8):
  state,_=inspect(g)
  if state[6]!=old_message:break
  if state[3]==len(text)and ui_public(g,783)[0][6]==0:g.device.press(28,delay=.15)
  end=time.monotonic()+3
  while time.monotonic()<end:
   state,_=inspect(g)
   if state[6]!=old_message:break
   time.sleep(.1)
  if state[6]!=old_message:break
 else:raise TimeoutError(('graphical new-message admission',old_message,state))
 state,_=wait_ui(g,lambda f:f[6]!=old_message,'new project-reference message serial')
 serial=state[6]
 for attempt in range(4):
  state,_=wait_ui(g,lambda f:f[6]==serial and f[4]in(19,21,27),'new-message signed mailbox acceptance')
  if state[4]==19:return old_message,serial,time.monotonic()-began,state
  if state[4]==21:raise RuntimeError(('required routed service unavailable',state,ui_public(g,783)[0]))
  if attempt==3:break
  g.device.press(65,delay=.15)
 raise RuntimeError(('bounded graphical exact-ciphertext retry did not settle',state))


def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--campaign',type=Path,required=True,help='preserved actual product actors; exclusive portal handoff required before execution')
 p.add_argument('--output',type=Path,required=True)
 p.add_argument('--registry-binary',type=Path,default=ROOT/'build/live/apps/native-registry.bin')
 p.add_argument('--public-graph',type=Path,default=ROOT/'build/signed-forge-journey-2/published-closure.json')
 p.add_argument('--publisher',type=Path,default=ROOT/'build/signed-forge-journey-2/publisher.pub')
 p.add_argument('--prepare-only',action='store_true')
 a=p.parse_args();out,archive,records,prepared=prepare(a)
 if a.prepare_only:print(json.dumps(prepared,indent=2));return
 campaign=a.campaign.resolve();baseline=json.loads((campaign/'evidence.json').read_text())
 assert baseline['result']=='passed-connected-product','central A–E must finish before exclusive actor handoff'
 assert baseline['image_sha256']==digest(campaign/'guest.bin')
 packages=current_packages(campaign);root=bytes.fromhex(prepared['project_root']);fed=bytes.fromhex(prepared['federation'])
 report=dict(schema=1,result='running',source_campaign=str(campaign),source_evidence_sha256=digest(campaign/'evidence.json'),
  image_sha256=baseline['image_sha256'],prepared=prepared,checks=[],limits='Local operators and host RSA federation bootstrap are disclosed. This does not qualify independent operators, Tor interoperability, traffic-correlation resistance, execution approval or public MVP completion.')
 actors=[];checks=report['checks'];began=time.monotonic();stage='exclusive actor attach'
 def record(label,**extra):
  checks.append(dict(check=label,result='pass',**extra));(out/'progress.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS',label,flush=True)
 try:
  mailbox=attach(campaign,out,'mailbox',False);actors.append(mailbox)
  relays=[]
  for name in('relay1','relay2','relay3'):
   g=attach(campaign,out,name,False);actors.append(g);relays.append(g)
  alice=attach(campaign,out,'alice',True,packages['alice']);actors.append(alice)
  bob=attach(campaign,out,'bob',True,packages['bob']);actors.append(bob)
  report['backends']={g.name:g.backend for g in actors}
  report['personal_instances']={g.name:dict(owner=g.owner,ui=g.ui,delivery=g.delivery)for g in(alice,bob)}
  report['personal_packages']=packages
  report['exact_personal_bindings']={g.name:g.binding_records for g in(alice,bob)}
  certs=[g.certificate for g in relays]
  stage='quiesce routed endpoints and configure existing native Registry'
  for g in(alice,bob):lock_ui(g);close_route(g)
  reset_operators(relays,mailbox)
  registries={}
  for g in(mailbox,bob):
   registry,sid=messenger.install(g.client,out/'native-registry.ltrel',PUB,2175)
   configuration=federation.configure(g.client,registry,out/'federation.pub','portable')
   assert configuration['federation_id']==fed.hex();registries[g.name]=registry
  bob_roots_before=projects.roots(bob.client)
  assert all(item['head']!=root.hex()for item in bob_roots_before),'recipient already has the public graph'
  actual=projects.import_records(mailbox.client,archive['selected'],records)[0]['cap']
  assert projects.project_identity(mailbox.client,actual)==archive['project_id']
  modulus=releases.public_modulus(a.publisher)
  publication_id=releases.publication(archive['project_id'],hashlib.sha256(modulus).hexdigest())
  federation.call(mailbox.client,registries['mailbox'],3,data=publication_id+modulus)
  delegated=mailbox.client.objects(27,actual,registries['mailbox'],25)[0][1]
  pending,decision=federation.call(mailbox.client,registries['mailbox'],2,h=delegated)
  assert len(decision)==512 and struct.unpack_from('<Q',decision,16)[0]==2
  signed=federation.sign_once(mailbox.client,registries['mailbox'],out/'federation.pem','portable')
  assert signed['listing']==2 and signed['root']==root.hex()
  _,descriptor=federation.call(mailbox.client,registries['mailbox'],6)
  assert len(descriptor)==768 and descriptor[320:352]==root
  record('existing native Registry evaluates actual existing signed public Forge closure; explicit RSA bootstrap signs only its immutable native decision',native_registries=registries,signed_admission=signed,descriptor_sha256=hashlib.sha256(descriptor).hexdigest(),recipient_graph_imported=False)
  def selected_terminal():net(mailbox,46,h=registries['mailbox'],data=fed)
  selected_terminal()
  stage='actual graphical end-to-end project reference send'
  ak=hashlib.sha256(b'Campaign008 disclosed Alice vault-unlock fixture').digest();bk=hashlib.sha256(b'Campaign008 disclosed Bob vault-unlock fixture').digest()
  unlock_ui(alice,ak,1);alice.device.press(1,delay=.15)
  wait_ui(alice,lambda f:f[2]==0 and f[5]==1,'recovered selected conversation')
  sender_setup=route(alice,certs,mailbox);wait(lambda:publication(alice),240,'native sender prekey publication')
  text='LT-PROJECT1 '+root.hex()+' '+fed.hex()+' 1';assert len(text)==143
  old_serial,serial,seconds,state=send_reference(alice,text)
  screenshot(alice,'project-reference-stored')
  record('actual graphical143byte project reference obtains a new message serial and signed routed mailbox acceptance',previous_message=old_serial,message=serial,route_setup_seconds=sender_setup,acceptance_seconds=seconds,native_ui=list(state))
  stage='recipient recovery routed decryption and real conversation F1 inspection'
  lock_ui(alice);close_route(alice);reset_operators(relays,mailbox);selected_terminal()
  unlock_ui(bob,bk,1);bob.device.press(1,delay=.15)
  wait_ui(bob,lambda f:f[2]==0 and f[5]==1,'recipient recovered conversation')
  old_inbox=role(bob,2,420)[0][4]
  recipient_setup=route(bob,certs,mailbox);wait(lambda:publication(bob),240,'recipient public prekey publication')
  def decrypted_reference():
   f,_=role(bob,2,420)
   if f[4]<=old_inbox:return None
   for cursor in range(old_inbox+1,f[4]+1):
    read,payload=role(bob,2,429,h=cursor,allow=(3,))
    if read[0]==0 and payload==text.encode():return read
   return None
  accepted=wait(decrypted_reference,900,'actual routed reference decryption')
  wait_ui(bob,lambda f:f[4]==20,'conversation reference displayed')
  screenshot(bob,'project-reference-received')
  began_request=time.monotonic()
  for attempt in range(8):
   if ui_public(bob,783)[0][6]==0:bob.device.press(59,delay=.15)
   time.sleep(.3)
   if ui_public(bob,785)[0][1]==6:break
  else:raise TimeoutError('actual graphical F1 selection was not admitted')
  def verified():
   f,chosen=ui_public(bob,785)
   state,_=inspect(bob)
   if state[4]==80:raise AssertionError(('native Forge verification failed',f,state))
   if state[4]!=79:return None
   assert f[1]==6 and f[2]==2 and f[3]==0 and f[4]==signed['sequence'] and f[5]==0 and f[6]==1,(f,state)
   assert chosen==root+fed
   return f
  verified_fields=wait(verified,900,'native Messenger selected Forge reference signature/federation/admission verification')
  screenshot(bob,'project-reference-native-forge-verified')
  assert projects.roots(bob.client)==bob_roots_before,'metadata request imported content without consent'
  record('actual conversation F1 invokes existing Forge federation consumer through the same three-relay broker; isolated native Registry verifies root federation signature policy and admission',inbox_serial=accepted[1],recipient_route_seconds=recipient_setup,routed_metadata_seconds=time.monotonic()-began_request,displayed_fields=list(verified_fields),selected_root=root.hex(),selected_federation=fed.hex(),recipient_content_imported=False,execution_approved=False)
  report.update(result='pass',elapsed_seconds=time.monotonic()-began);(out/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
 except BaseException as error:
  report.update(result='failed-preserved-actors',stage=stage,error=repr(error),traceback=traceback.format_exc(),elapsed_seconds=time.monotonic()-began)
  (out/'failure.json').write_text(json.dumps(report,indent=2)+'\n');raise
 finally:
  for g in actors:
   if g.device:g.device.close()
   if g.client:g.client.close()

if __name__=='__main__':main()
