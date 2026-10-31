"""Continue an actually stored native message without regenerating actor keys.

The prior driver stops and releases its public portals. This driver changes only
explicitly admitted applications, uses real GUI gestures, and moves opaque
backing files only for a user-authorized backup. No protocol state is hosted.
"""
from __future__ import annotations
import argparse,contextlib,hashlib,json,struct,sys,time,traceback
from pathlib import Path
from messenger_journey import *
from messenger_product_journey import ui_public,prepare_personal,publication,lock_ui,close_route,record_binding

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--campaign',type=Path,required=True);p.add_argument('--ready',type=Path,required=True);p.add_argument('--resume-uploaded',action='store_true');p.add_argument('--mixed-relay2',action='store_true');a=p.parse_args()
 out=a.campaign.resolve();ready=json.loads(a.ready.read_text());image=out/'guest.bin';actors=[];started=time.monotonic();stage='public actor attachment'
 report=json.loads((out/'progress.json').read_text());report['continuation']='native final packages after observed UI foreground/status fixes';report['result']='running';checks=report['checks']
 final={n:(Path(path),releases.inspect(Path(path).read_bytes())) for n,path in ready.items()}
 prior={n:(out/(n+'.ltrel'),releases.inspect((out/(n+'.ltrel')).read_bytes())) for n in ('owner','ui','delivery','identity','mailbox')}
 def record(label,**values):
  checks.append(dict(check=label,result='pass',**values));(out/'progress.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS',label,flush=True)
 def attach(name,personal=False):
  g=Guest(name,'qemu',out,image,graphical=personal,vault=out/(name+'.img') if personal else None,store=None if personal else out/(name+'.img')).attach(out);actors.append(g)
  if personal:
   g.owner=messenger.endpoint(g.client,2,420);g.delivery=messenger.endpoint(g.client,4,464)
   g.ui=next(row[0] for row in identity.instances(g.client) if row[2]==799 and 0<row[1]<5)
  else:
   g.certificate=(out/(name+'.certificate')).read_bytes();_,native=net(g,25,h=4)
   assert native[:480]==g.certificate and native[480:]==hashlib.sha256(g.certificate).digest()
   g.pin=native[480:];g.identity_package=final['identity'][0]
  return g
 def outcome_transfer(g,phase,label,seconds=1800):
  last=[None]
  def check():
   f=transfer_state(g)
   if f!=last[0]:print(g.name,'transfer',f,flush=True);last[0]=f
   if f[1]==9:raise RuntimeError((g.name,label,'native failure',f,ui_public(g,783)[0]))
   return f if f[1]==phase else None
  return wait(check,seconds,label)
 try:
  mailbox=attach('mailbox');mailbox.mailbox=messenger.endpoint(mailbox.client,3,441)
  relays=[attach('relay'+str(i)) for i in (1,2,3)];certs=[g.certificate for g in relays]
  alice=attach('alice',True);ak=hashlib.sha256(b'Campaign008 disclosed Alice vault-unlock fixture').digest();bk=hashlib.sha256(b'Campaign008 disclosed Bob vault-unlock fixture').digest()
  ai=(out/'alice.invitation').read_bytes();bi=(out/'bob.invitation').read_bytes()
  observed=transfer_state(alice);(out/'old-ui-picker-observation.json').write_text(json.dumps(dict(native_ui=list(inspect(alice)[0]),transfer=list(observed),scope='the original driver waited for an overwritten transient notice; native picker status is separate'),indent=2)+'\n')
  if observed[1]==1 and not a.resume_uploaded:alice.device.press(1,delay=.15);time.sleep(.5)
  stage='final graphical application admission on existing native owner'
  try:current=alice.client.request(14,bytes.fromhex(final['ui'][1]['project_id']))
  except ValueError:current=bytes(128)
  if current[64:96]!=bytes.fromhex(final['ui'][1]['release_id']):
   alice.client.request(26,struct.pack('<Q',alice.ui))
   alice.ui,uid=install(alice,final,'ui',799)
   sid=bytes.fromhex(prior['owner'][1]['release_id']);did=bytes.fromhex(prior['delivery'][1]['release_id'])
   for op in range(420,436):record_binding(alice,2,alice.owner,alice.ui,op,sid,uid)
   for op in range(460,464):record_binding(alice,4,alice.delivery,alice.ui,op,did,uid)
   alice.client.request(150,struct.pack('<Q8Q',alice.ui,781,0,0,0,0,0,0,1)+FED)
   alice.device.chord(56,15);time.sleep(.3);lock_ui(alice);unlock_ui(alice,ak,1)
   alice.device.press(1,delay=.15);wait_ui(alice,lambda f:f[2]==0 and f[5]==1,'recovered approved sender contact')
   close_route(alice);reset_operators(relays,mailbox);route(alice,certs,mailbox)
  else:uid=bytes.fromhex(final['ui'][1]['release_id'])
  actor_packages=dict(alice={n:str((final if n=='ui' else prior)[n][0].resolve()) for n in ('owner','ui','delivery')},bob={n:str(final[n][0].resolve()) for n in ('owner','ui','delivery')})
  (out/'actor-packages.json').write_text(json.dumps(actor_packages,indent=2)+'\n')
  report['package_transitions']=dict(sender_existing_owner=prior['owner'][1],sender_existing_delivery=prior['delivery'][1],final= {n:i for n,(_,i) in final.items()})
  record('final native GUI replaces only prior graphical application; existing owner keys and approved contacts recover through actual F8/F9',ui_release=uid.hex(),ui_executable=final['ui'][1]['executable_sha256'])
  if a.resume_uploaded:
   snapshot=json.loads((out/'selected-attachment.json').read_text());head=snapshot['root'];files=None
   sent=transfer_state(alice);assert sent[1]==8,('native sender completion required',sent)
   record('actual native completed useful attachment publication survives driver checkpoint',**snapshot,native_transfer=list(sent))
  else:
   stage='real useful source selection and bounded encrypted upload'
   cap,head,files=import_useful_project(alice)
   roots=projects.roots(alice.client);position=next(i for i,r in enumerate(roots) if r['cap']==cap)
   # The trusted compositor picker enumerates the explicitly delegated roots.
   alice.device.press(87,delay=.15);wait(lambda:transfer_state(alice)[1]==1,120,'real F11 trusted picker')
   screenshot(alice,'final-trusted-source-picker')
   for _ in range(position):alice.device.press(108,delay=.15)
   alice.device.press(28,delay=.15)
   sent=outcome_transfer(alice,8,'actual native useful project upload')
   assert sent[4]>65536 and sent[4]<=100352
   snapshot=dict(root=head,payload_bytes=sum(map(len,files.values())),bundle_bytes=sent[4],files={n:dict(bytes=len(v),sha256=hashlib.sha256(v).hexdigest()) for n,v in files.items()})
   (out/'selected-attachment.json').write_text(json.dumps(snapshot,indent=2)+'\n')
   screenshot(alice,'final-attachment-stored')
   record('actual F11 trusted selection streams useful native GUI and SDK source as encrypted authenticated chunks while recipient guest is offline',**snapshot,native_transfer=list(sent))
  if a.mixed_relay2:
   stage='same-credential relay backend migration'
   relay=relays[1];old_pin=relay.pin;relay.stop();relay.backend='x86_64';relay.start();restore_operator(relay,out)
   assert relay.pin==old_pin and relay.certificate==certs[1]
   enroll(relay,0,certs[2]);reset_operators(relays,mailbox)
   record('same native relay2 credentials and backing restart on native x86 assembly backend using identical common guest image',old_backend='qemu',new_backend='x86_64',pin=relay.pin.hex(),common_image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),applies_to='subsequent recipient fetch, attachment retrieval, reply and routed consumer')
  stage='actual mailbox restart with same protected operator identity'
  lock_ui(alice);close_route(alice);reset_operators(relays,mailbox)
  mailbox.stop();mailbox.network_fault_control=out/'mailbox-fault.sock';mailbox.start();restore_operator(mailbox,out);mailbox_start(mailbox,final);reset_operators(relays,mailbox)
  record('whole mailbox guest restarts and recovers same native sealed node and receipt keys, durable ciphertext, quotas and explicit finite receipt authority',mailbox_pin=mailbox.pin.hex())
  stage='actual personal guest restart and explicitly authorized recovery'
  bob=Guest('bob','qemu',out,image,graphical=True,vault=out/'bob.img').start();actors.append(bob)
  recovered=prepare_personal(bob,final,mailbox.pin,bk,recover=True);assert recovered==bi
  bob.device.press(1,delay=.15);wait_ui(bob,lambda f:f[2]==0 and f[5]==1,'recovered recipient approved contact')
  setup=route(bob,certs,mailbox);wait(lambda:publication(bob),240,'recipient public prekey republish')
  def text_ready():
   f,_=role(bob,2,420)
   return f if f[4]>=1 else None
  wait(text_ready,600,'authenticated committed native inbox')
  f,text=role(bob,2,429,h=1);assert text==b'native offline message through three relays'
  wait_ui(bob,lambda f:f[4]==20,'actual graphical plaintext presentation');screenshot(bob,'final-received-text')
  record('recipient guest restarts, recovers through actual graphical consent, decrypts offline routed text and commits before delete',inbox_serial=f[1],route_setup_seconds=setup)
  wait(lambda:role(bob,2,420)[0][4]>=2,600,'authenticated committed attachment manifest')
  stage='explicit graphical authenticated attachment import'
  # Only an explicit user pointer gesture admits import; repeat only while the
  # native transfer has not admitted an import and no foreground job is pending.
  until=time.monotonic()+60
  while time.monotonic()<until and transfer_state(bob)[1]<20:
   state=ui_public(bob,783)[0]
   if state[6]==0 or state[4] in (420,463):bob.device.click(400,385,delay=.15)
   time.sleep(.25)
  received=outcome_transfer(bob,24,'actual explicit native project import')
  manifest,_=role(bob,2,429,h=2)
  metadata,commitments=role(bob,2,434,h=manifest[5],a=5)
  assert metadata[2]==2 and metadata[3]==snapshot['bundle_bytes']
  actual_head=commitments[32:64].hex();assert actual_head==head
  screenshot(bob,'final-imported-project')
  record('actual graphical pointer fetches decrypts authenticates ordered chunks and explicitly commits exact useful Objects project before ciphertext deletion',native_transfer=list(received),canonical_root=actual_head,native_stream_integrity=True)
  # A lock flushes access and makes an opaque backup quiescent. The backup has
  # eligible history and predates the reply/fresh authority tests; no DB editing.
  lock_ui(bob);backup=out/'bob-history-backup.img'
  subprocess.run(['cp','--reflink=auto','--sparse=always',str(bob.vault),str(backup)],check=True)
  unlock_ui(bob,bk,1);bob.device.press(1,delay=.15);close_route(bob);reset_operators(relays,mailbox);route(bob,certs,mailbox)
  record('explicit graphical lock permits an opaque older history backup, followed by authorized normal recovery',backup=str(backup),backing_edited=False)
  stage='actual graphical routed reply'
  message,seconds=send_ui(bob,'native routed reply after recovery')
  record('recovered recipient composes actual graphical reply and verifies signed durable routed acceptance',message=message,acceptance_seconds=seconds)
  lock_ui(bob);close_route(bob);reset_operators(relays,mailbox)
  unlock_ui(alice,ak,1);alice.device.press(1,delay=.15);route(alice,certs,mailbox)
  wait(lambda:role(alice,2,420)[0][4]>=1,600,'original sender authenticated reply')
  f,reply=role(alice,2,429,h=1);assert reply==b'native routed reply after recovery'
  wait_ui(alice,lambda f:f[4]==20,'actual routed graphical reply presentation');screenshot(alice,'final-routed-reply')
  record('original sender explicitly recovers and decrypts actual routed reply',inbox_serial=f[1])
  report.update(result='passed-connected-product',continuation_seconds=time.monotonic()-started,incomplete_acceptance=['connected failure matrix and exact retry: separate F helper queued','conversation Forge handoff: separate G helper queued','history import and no-vault controls: H helper queued'])
  (out/'evidence.json').write_text(json.dumps(report,indent=2)+'\n')
 except BaseException as error:
  report.update(result='failed-preserved-actors',stage=stage,error=repr(error),traceback=traceback.format_exc(),continuation_seconds=time.monotonic()-started)
  (out/'continuation-failure.json').write_text(json.dumps(report,indent=2)+'\n');raise
 finally:
  for g in actors:
   if g.device:g.device.close()
   if g.client:g.client.close()

if __name__=='__main__':main()
