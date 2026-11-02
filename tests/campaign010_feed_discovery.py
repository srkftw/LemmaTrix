"""A disposable second personal session discovers the real Notes Feed card.

Use only after the original reader's ephemeral fork work is complete. A fresh
session imports no social identity, signing authority, graph or accepted record.
It retrieves the actual signed timeline and every body chunk over the normal
three-hop path, then native Feed verifies the card's independent admission.
"""
import argparse,contextlib,hashlib,json,struct,sys,time,traceback
from pathlib import Path
from types import SimpleNamespace as NS
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import feed,federation,identity,live,messenger,projects
import onion_route as route
import feed_project_controls as controls
from campaign010_project_notes import NotesJourney,wait
from campaign010_notes_sharing import focus,ui_call
from creator_journey import require
from graphical_devices import DeviceInput

def confirm_existing(a,out):
 report=json.loads((out/'execution.json').read_bytes());previous=(out/'execution.json').read_bytes()
 require(report['result']=='failure-preserved-reader'and report['error']=="AssertionError('native selected descriptor differs')",'only the preserved controller query-field assertion may continue here')
 prior=out/'execution-before-query-field-fix.json';require(not prior.exists(),'prior failure record already exists');prior.write_bytes(previous)
 selected=json.loads(a.card.read_bytes())['checks'][-1];configured=report['checks'][0]['feed'];registry=report['checks'][0]['registry'];session=report['session'];started=time.monotonic()
 device=DeviceInput('qemu',Path(session['graphics']));c=live.Client(Path(session['socket']),timeout=180)
 try:
  fields,_=ui_call(c,configured['ui'],791);require(fields[2]==8 and fields[4]==47,'native C inspection did not reach its verified project view')
  _,event=ui_call(c,configured['ui'],795);require(event[:32].hex()==selected['event'],'live native card selection changed')
  query,descriptor=federation.call(c,registry,6);classification=struct.unpack_from('<Q',descriptor,16)[0]
  require(classification==2 and descriptor[128:160].hex()==selected['release']and descriptor[320:352].hex()==selected['root'],'native signed admission differs')
  require(hashlib.sha256(descriptor).hexdigest()=='5c94d95cc7ef7c94c95cb1b35ccb674ad3627ac52d7ed00df25e5da95b9f8fe6','native verified admission bytes changed')
  require(not projects.roots(c),'Feed inspection granted graph authority');frame=device.frame();(out/'native-card-inspection-confirmed.ppm').write_bytes(frame.ppm())
  report['checks'].append(dict(check='physical C inspection independently verifies actual Alpha project admission; corrected public query field is sequence rather than classification',result='pass',native_ui=list(fields),query_header=list(query),classification=classification,decision_sequence=query[1],release=selected['release'],root=selected['root'],admission_sha256=hashlib.sha256(descriptor).hexdigest(),installation_approved=False,execution_approved=False))
  report['preserved_controller_failure']=dict(path=str(prior),sha256=hashlib.sha256(previous).hexdigest(),error=report.pop('error'),explanation='Registry query6 word1 is decision sequence. Classification is the signed descriptor word2, not that query-header field. Native C inspection and cached signature verification had already succeeded.')
  report.pop('traceback');report['confirmation_seconds']=time.monotonic()-started;report['session'].update(feed=configured,registry=registry)
  report.update(result='pass-real-second-user-feed-discovery',limits='Actual signed Feed timeline/body retrieval and physical native C public-admission verification. Corrected controller assertion reads the preserved existing native view/cache; it imports no accepted decision. No author/private publisher/graph restored, and no Feed install/execution approval claimed. Actual install/use/fork remains separately identified.')
  (out/'execution.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS actual native Feed discovery and verified C inspection, corrected public query-header assertion',flush=True)
 finally:c.close();device.close()

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
 p.add_argument('--card',type=Path,required=True);p.add_argument('--network',type=Path,required=True);p.add_argument('--historical',type=Path,required=True)
 p.add_argument('--registry',type=Path,required=True);p.add_argument('--public-verifier',type=Path,required=True);p.add_argument('--confirm-existing',action='store_true',help='read the preserved native inspection after correcting a controller query-field assertion')
 a=p.parse_args();out=a.output.resolve()
 if a.confirm_existing:return confirm_existing(a,out)
 out.mkdir(parents=True,exist_ok=False);card=json.loads(a.card.read_bytes());require(card['result']=='pass-real-native-project-card','actual accepted public card required')
 selected=card['checks'][-1];pub=json.loads(a.public_verifier.read_bytes());public=ROOT/'tests/keys/development-rsa-public.pem';boot=ROOT/'build/campaign010-native-bootstrap-current'
 j=NotesJourney(NS(output=out/'personal',image=a.image,backend='qemu',network_mux=True));c=None;report=dict(schema=1,result='running',checks=[],image_sha256=j.image,card_record_sha256=hashlib.sha256(a.card.read_bytes()).hexdigest());began=time.monotonic()
 def save():report['elapsed_seconds']=round(time.monotonic()-began,3);(out/'execution.json').write_text(json.dumps(report,indent=2)+'\n')
 def passed(label,**fields):report['checks'].append(dict(check=label,result='pass',**fields));save();print('PASS',label,flush=True)
 try:
  j.boot(vault=False);report['session']=dict(socket=str(j.socket),graphics=str(j.graphics),pid=j.proc.pid,backend='qemu',image=str(a.image.resolve()));save()
  c=live.Client(j.socket,timeout=600);identity.start(c,boot/'identity.ltrel',public)
  require(not projects.roots(c),'fresh reader unexpectedly holds graph roots')
  configured=feed.start(c,NS(identity=boot/'identity.ltrel',owner=ROOT/'build/campaign010-message-status-fix/feed-account.ltrel',ui=ROOT/'build/campaign010-intent-services-feed/feed.ltrel',public=public,federation=selected['social_federation'],peer=hashlib.sha256(b'Campaign009 common alpha').hexdigest()))
  status,_=ui_call(c,configured['ui'],791);require(status[1]==0,'fresh read-only Feed session created an author')
  registry,release=messenger.install(c,a.registry,public,2175)
  config=federation.configure_native_verifier(c,registry,pub['public_key'],'consumer',allowed_rights=895,generation=pub['generation'])
  try:federation.call(c,registry,6)
  except ValueError as error:require(str(error)=='native registry status6','unexpected empty catalog response')
  else:raise AssertionError('accepted admission was inserted before card retrieval')
  passed('fresh second personal session has no graph, installed Notes or social signing identity; only public verifier is configured',configuration=config,registry=registry,registry_release=release.hex(),feed=configured)
  certs=[(a.network/f'node{i}.certificate').read_bytes()for i in(1,2,3)];beta=(a.historical/'beta.certificate').read_bytes()
  for slot,cert in enumerate(certs+[beta]):route.enroll(c,slot,cert)
  setup=time.monotonic();route.route(c,31)
  def circuit():
   f,_=route.route(c,32);require(not f[3],('native route unavailable',f));return f if f[2]==3 else None
  state=wait(circuit,'second personal three-hop route',180)
  route.route(c,38,h=3,a=101,b=configured['owner'],c=8388608,d=65536)
  def terminal():
   f,b=route.route(c,49);r=struct.unpack_from('<8Q',b);require(r[4]!=4,('terminal unavailable',r));return r if f[1]==1 and r[4]==3 else None
  relationship=wait(terminal,'second personal selected Feed provider',120)
  passed('second personal session independently approves provider pin and establishes selected Feed relationship',route=list(state),profile=list(relationship),provider_pin=hashlib.sha256(beta).hexdigest(),setup_seconds=time.monotonic()-setup)
  focus(j,'feed');g=NS(client=c,device=j.ui,feed_ui=configured['ui'],out=out,name='reader')
  rows=[]
  def observe(label,**fields):
   if label=='native chronological row'and fields.get('selected')not in rows:
    rows.append(fields.get('selected'));report['timeline_rows']=rows;save()
  g.project_observer=observe
  event=controls.select_event(g,configured['ui'],bytes.fromhex(selected['event']))
  require(event[32+112:32+144].hex()==selected['author'],'actual selected signed author changed')
  require(struct.unpack_from('<Q',event,32+176)[0]==3,'actual selected event is not a project card')
  require(event[32+336:32+368].hex()==selected['root'],'actual selected card root changed')
  frame=j.ui.frame();(out/'native-card-discovery.ppm').write_bytes(frame.ppm())
  passed('physical chronological navigation retrieves exact native-verified signed card and complete committed body',event=selected['event'],author=selected['author'],selected_public_record_sha256=hashlib.sha256(event).hexdigest(),native_selection_states=len(rows),signed_selections=sum(x!='0'*64 for x in rows),root=selected['root'])
  j.ui.press(46)
  def inspected():
   f,_=ui_call(c,configured['ui'],791)
   if f[4]==65:raise RuntimeError(('native card admission unavailable',f))
   return f if f[2]==8 and f[4]==47 else None
  state=wait(inspected,'native Feed independently verifies exact project admission',180);(out/'native-card-inspection.ppm').write_bytes(j.ui.frame().ppm())
  classified,descriptor=federation.call(c,registry,6);require(struct.unpack_from('<Q',descriptor,16)[0]==2 and descriptor[128:160].hex()==selected['release'],'native selected descriptor differs')
  require(descriptor[320:352].hex()==selected['root'],'native card substituted release graph root');require(not projects.roots(c),'card discovery/inspection unexpectedly grants graph authority')
  passed('physical C inspects actual card provenance under independently verified Alpha admission; no install or execution consent implied',native_ui=list(state),release=selected['release'],root=selected['root'],admission_sha256=hashlib.sha256(descriptor).hexdigest(),classification=struct.unpack_from('<Q',descriptor,16)[0],installation_approved=False,execution_approved=False)
  report['session'].update(feed=configured,registry=registry);report.update(result='pass-real-second-user-feed-discovery',limits='Actual signed Feed timeline and body retrieval plus native public admission verification. This fresh disposable session does not restore the earlier reader publisher or claim installation from Feed alone; the separately identified reader/fork journey proves actual install/use/source change.');save()
 except BaseException as error:
  with contextlib.suppress(Exception):(out/'failure.ppm').write_bytes(j.ui.frame().ppm())
  report.update(result='failure-preserved-reader',error=repr(error),traceback=traceback.format_exc());save();raise
 finally:
  if c:c.close()
  if j.ui:j.ui.close()
if __name__=='__main__':main()
