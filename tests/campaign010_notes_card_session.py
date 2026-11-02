"""Selected Notes recovery, fresh native Feed identity and a genuine project card.

This deliberately replaces the disposable sharing guest after its accepted
operations were recorded. Only selected retained graph roots are recovered.
The public Registry descriptor is verified natively; no operator key is used.
"""
import argparse,contextlib,hashlib,json,os,signal,struct,sys,time,traceback
from pathlib import Path
from types import SimpleNamespace as NS
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import feed,federation,identity,live,messenger,projects,project_vault
import onion_route as route
from campaign010_project_notes import NotesJourney,wait
from campaign010_notes_sharing import focus,pick,ui_call
from creator_journey import require

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--sharing',type=Path,required=True);p.add_argument('--image',type=Path,required=True)
 p.add_argument('--network',type=Path,required=True);p.add_argument('--historical',type=Path,required=True)
 p.add_argument('--output',type=Path,required=True);p.add_argument('--admission',type=Path,required=True)
 p.add_argument('--public-verifier',type=Path,required=True);p.add_argument('--registry',type=Path,required=True)
 a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
 prior=json.loads((a.sharing/'message-reconcile.json').read_bytes());old=prior['session']
 require(prior['result']=='pass-real-mailbox-acceptance-and-scoped-status','accepted original operations required')
 original=ROOT/'build/campaign010-notes-native-4';ready=json.loads((original/'ready.json').read_bytes())
 public=ROOT/'tests/keys/development-rsa-public.pem';boot=ROOT/'build/campaign010-native-bootstrap-current'
 args=NS(output=out/'personal',image=a.image,backend='qemu',vault=original/'objects.img',vault_key=original/'objects.key',network_mux=True)
 j=NotesJourney(args);report=dict(schema=1,result='running',checks=[],image_sha256=j.image,source_sharing=str(a.sharing.resolve()));began=time.monotonic();clients=[]
 def save():report['elapsed_seconds']=round(time.monotonic()-began,3);(out/'execution.json').write_text(json.dumps(report,indent=2)+'\n')
 def passed(label,**fields):report['checks'].append(dict(check=label,result='pass',**fields));save();print('PASS',label,flush=True)
 try:
  command=Path('/proc')/str(old['pid'])/'cmdline'
  require(command.exists()and b'lt\0run\0'in command.read_bytes(),'old disposable personal process changed')
  with contextlib.closing(live.Client(Path(old['socket']),timeout=90))as c:
   inventory=identity.instances(c)
   try:c.request(70)
   except EOFError:pass
  wait(lambda:not Path('/proc',str(old['pid']),'cmdline').exists()or not Path('/proc',str(old['pid']),'cmdline').read_bytes(),'old disposable personal shutdown',30)
  passed('completed disposable sharing guest shuts down after preserving actual accepted operation evidence',prior=hashlib.sha256((a.sharing/'message-reconcile.json').read_bytes()).hexdigest(),ordinary_before=[list(r)for r in inventory if r[0]&255>=7 and 0<r[1]<5])
  j.boot()
  report['session']=dict(socket=str(j.socket),graphics=str(j.graphics),pid=j.proc.pid,backend='qemu',image=str(a.image.resolve()));save()
  with j.client()as c:
   signer=identity.start(c,boot/'identity.ltrel',public)
   project_vault.unlock(c,args.vault_key.read_bytes());require(not projects.roots(c),'old live roots survived restart')
   saved=project_vault.inventory(c);selected=[i for i,x in enumerate(saved['projects'])if x['name']in('project-notes','project-notes-1.0.0')]
   require(len(selected)==2,'both explicitly retained roots required');recovered=project_vault.recover(c,selected)
   c.request(10,bytes.fromhex(ready['release']['project_id'])+(original/'project-notes.pub').read_bytes());c.stage(original/'project-notes.ltrel')
   root=next(x for x in recovered['roots']if x['name']=='project-notes-1.0.0');cap=projects.resolve(c,root['cap'],ready['release']['release_node'])
   require(struct.unpack_from('<Q',c.request(15,struct.pack('<Q',cap)),8)[0]==1,'fresh exact release material unavailable')
  j.ui.press(88);time.sleep(.6);j.ui.press(28);j.wait_text(14,152,'Title / ',0xdce9ec,timeout=60)
  pick(j,'project-notes',62);j.wait_text(16,134,'Release plan',0xa6d7b1)
  with j.client()as c:
   app=next(r[0]for r in identity.instances(c)if r[2]==895 and 0<r[1]<5)
   configured=feed.start(c,NS(identity=boot/'identity.ltrel',owner=ROOT/'build/campaign010-message-status-fix/feed-account.ltrel',ui=ROOT/'build/campaign010-intent-services-feed/feed.ltrel',public=public,federation=hashlib.sha256(b'Campaign009 common beta').hexdigest(),peer=hashlib.sha256(b'Campaign009 common alpha').hexdigest()))
   empty,_=ui_call(c,configured['ui'],791);require(empty[1]==0,'unselected prior Feed identity was restored')
  passed('only selected note/project recover with fresh handles; unretained Feed and Messenger authority do not return',recovered=recovered,app=app,feed_identity_present=empty[1],publisher_recovered=False,messenger_recovered=False)
  focus(j,'feed');j.ui.press(60)
  def created():
   with j.client()as c:f,p=ui_call(c,configured['ui'],791)
   return(f,p)if f[1]==1 and f[7]==1 else None
  status,body=wait(created,'fresh native ephemeral Feed author',180);author=body[:32].hex()
  passed('fresh native ephemeral Feed author is created after explicit local action',author=author,configuration=configured,identity=signer)
  with j.client()as c:
   registry,sid=messenger.install(c,a.registry,public,2175);pub=json.loads(a.public_verifier.read_bytes());descriptor=a.admission.read_bytes()
   config=federation.configure_native_verifier(c,registry,pub['public_key'],'consumer',allowed_rights=895,generation=pub['generation'])
   verified,body=federation.call(c,registry,11,data=descriptor+descriptor[320:352]);require(body==descriptor and verified[1]==2,'actual Alpha admission failed native verification')
   _,selected=federation.call(c,registry,6);require(selected==descriptor,'verified card not selected in catalog')
   ordinary=[list(r)for r in identity.instances(c)if r[0]&255>=7 and 0<r[1]<5]
   require(len(ordinary)==5,'unexpected ordinary lifecycle footprint')
  passed('public-only Registry verifies actual signed Alpha admission beside Notes and Feed within five ordinary slots',registry=registry,release=sid.hex(),ordinary=ordinary,configuration=config,descriptor_sha256=hashlib.sha256(descriptor).hexdigest(),operator_signing_authority=False)
  personal=live.Client(j.socket,timeout=600);clients.append(personal)
  certs=[(a.network/f'node{i}.certificate').read_bytes()for i in(1,2,3)];beta=(a.historical/'beta.certificate').read_bytes()
  for slot,cert in enumerate(certs+[beta]):route.enroll(personal,slot,cert)
  setup=time.monotonic();route.route(personal,31)
  def connected():
   f,_=route.route(personal,32);require(not f[3],('native route unavailable',f));return f if f[2]==3 else None
  state=wait(connected,'fresh personal uses actual current three-hop route',180)
  route.route(personal,38,h=3,a=91,b=configured['owner'],c=8388608,d=65536)
  def terminal():
   f,b=route.route(personal,49);r=struct.unpack_from('<8Q',b);require(r[4]!=4,('native terminal unavailable',r));return r if f[1]==1 and r[4]==3 else None
  selected=wait(terminal,'actual Feed provider relationship',120)
  passed('fresh selected Feed relationship authenticates through three current native relay guests',route=list(state),profile=list(selected),setup_seconds=time.monotonic()-setup,provider_pin=hashlib.sha256(beta).hexdigest())
  focus(j,'feed');j.ui.press(87)
  wait(lambda:ui_call(personal,configured['ui'],791)[0][2:5:2]==(1,33),'native Feed selects verified project card',90)
  caption='Project Notes 1.0: project documentation, release drafts and reviewed sharing. Inspect this release and its signed helper before installation.'
  j.ui.textASCII(caption,delay=.07);j.ui.press(62);wait(lambda:ui_call(personal,configured['ui'],791)[0][2]==9,'actual card preview',60)
  (out/'project-card-preview.ppm').write_bytes(j.ui.frame().ppm());j.ui.press(63)
  def accepted():
   f,_=ui_call(personal,configured['ui'],791)
   if f[5]==8:raise RuntimeError(('card outcome uncertain',f))
   return f if f[5]in(6,7)else None
  accepted_state=wait(accepted,'actual Feed provider accepts signed project card',180)
  # Public portable state exposes the last immutable signed event, never a seed.
  j.ui.press(59);wait(lambda:ui_call(personal,configured['ui'],791)[0][2]==5,'native public account export panel',45);j.ui.press(66)
  wait(lambda:ui_call(personal,configured['ui'],793)[0][1]!=0,'native public profile object export',120)
  shared,_=ui_call(personal,configured['ui'],794);require(shared[1]!=0,'public export capability missing')
  try:portable=personal.read_object(shared[1])
  finally:personal.objects(47,shared[1])
  require(len(portable)==2048 and any(portable[128:160]),'public event identity missing');(out/'feed-author.public-profile').write_bytes(portable);j.ui.press(1)
  report['session'].update(app=app,feed=configured,registry=registry,recovered=recovered)
  passed('physical preview and Feed publish author genuine immutable Notes project card',native_ui=list(accepted_state),event=portable[128:160].hex(),author=portable[32:64].hex(),sequence=struct.unpack_from('<Q',portable,24)[0],release=pub['release_id'],root=pub['root'],admission_federation=pub['federation_id'],social_federation=configured['federation'],caption=caption,installation_approved=False,execution_approved=False)
  report.update(result='pass-real-native-project-card',limits='Selected note/project recovery and fresh ephemeral social authority, actual public native Registry verification and routed Feed acceptance. Recipient discovery/inspection is separate. No publisher/operator/private social keys exported.');save()
 except BaseException as error:
  with contextlib.suppress(Exception):(out/'failure.ppm').write_bytes(j.ui.frame().ppm())
  report.update(result='failure-preserved-personal',error=repr(error),traceback=traceback.format_exc());save();raise
 finally:
  for c in clients:c.close()
  if j.ui:j.ui.close()
if __name__=='__main__':main()
