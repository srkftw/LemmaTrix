"""Real Notes excerpt review, native three-hop Feed and Messenger acceptance.

The prior native profile run supplies its independently initialized current
relays. Existing separately retained service providers keep their keys/outboxes.
Only ordinary public provisioning, actual native input and public readbacks are
used. This controller never signs events, decrypts messages or writes guest RAM.
"""
import argparse,contextlib,hashlib,json,os,signal,struct,sys,time,traceback
from pathlib import Path
from types import SimpleNamespace as NS
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import feed,identity,live,messenger,onion_route as route
from campaign010_project_notes import NotesJourney,wait
from campaign010_notes_sharing import focus,ui_call
from creator_journey import rendered_text,require
from graphical_devices import DeviceInput

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--sharing',required=True,type=Path);p.add_argument('--network',required=True,type=Path);p.add_argument('--historical',required=True,type=Path);a=p.parse_args()
 out=a.sharing.resolve();ready=json.loads((out/'review-final.json').read_bytes());session=ready['session'];network=a.network.resolve();old=a.historical.resolve()
 require(ready['result']=='pass-real-native-reviews-awaiting-transport','both actual frozen owner reviews required')
 report=dict(schema=1,result='running',checks=[],timings={},session=session,previous_review_sha256=hashlib.sha256((out/'review-final.json').read_bytes()).hexdigest());started=time.monotonic();clients=[];j=None
 def save():report['elapsed_seconds']=time.monotonic()-started;(out/'social-route.json').write_text(json.dumps(report,indent=2)+'\n')
 def passed(label,**values):report['checks'].append(dict(check=label,result='pass',**values));save();print('PASS',label,flush=True)
 try:
  paused=json.loads((ROOT/'build/campaign010-paused-historical.json').read_bytes());resumed=[]
  for item in paused['processes']:
   if item['pid']not in(540928,540972,616462):continue
   base=Path('/proc')/str(item['pid']);require(base.exists(),'preserved actor exited')
   require((base/'stat').read_text().split()[21]==item['start'],'preserved actor PID reused')
   require((base/'cmdline').read_bytes().replace(b'\0',b' ').decode().strip()==item['command'].strip(),'preserved actor command changed')
   os.kill(item['pid'],signal.SIGCONT);resumed.append(item['pid'])
  # The profile journey is finished. Its unused personal and two test providers
  # can stop; its new relays remain alive for this actual continuation.
  for item in json.loads((network/'actors.json').read_bytes())['processes']:
   if item['node']in(0,4,5):
    with contextlib.suppress(ProcessLookupError):os.killpg(item['pid'],signal.SIGTERM)
  report['reused_historical_pids']=resumed;report['historical_image_sha256']=hashlib.sha256((old/'guest.bin').read_bytes()).hexdigest();report['relay_image_sha256']=hashlib.sha256((network/'guest.bin').read_bytes()).hexdigest();save()
  def attach(path):
   client=live.Client(path,timeout=600);clients.append(client);return client
  personal=attach(Path(session['socket']));relays=[attach(network/f'node{i}/portal.sock')for i in(1,2,3)];beta=attach(old/'beta.sock');mailbox=attach(old/'mailbox.sock')
  certs=[(network/f'node{i}.certificate').read_bytes()for i in(1,2,3)];beta_cert=(old/'beta.certificate').read_bytes();mail_cert=(old/'mailbox.certificate').read_bytes()
  for i,cert in enumerate(certs):route.enroll(personal,i,cert)
  for slot,cert in((3,beta_cert),(4,mail_cert)):route.enroll(personal,slot,cert)
  for slot,cert in((2,beta_cert),(3,mail_cert)):route.enroll(relays[2],slot,cert)
  for service in(beta,mailbox):
   state,_=route.route(service,32)
   if state[1]==0:route.route(service,30)
  began=time.monotonic();route.route(personal,31)
  def circuit():
   f,_=route.route(personal,32)
   require(not f[3],('native route unavailable',f));return f if f[2]==3 else None
  state=wait(circuit,'actual Notes personal three-hop route',180);report['timings']['three_hop_seconds']=time.monotonic()-began
  passed('recovered Notes personal uses independently initialized current native relays and existing approved provider pins',route=list(state),pins=[hashlib.sha256(c).hexdigest()for c in(certs+[beta_cert,mail_cert])])
  j=NotesJourney(NS(output=out/'personal',image=Path(session.get('image',ROOT/'build/campaign010-vault-recovery-current/guest.bin')),backend='qemu'));j.ui=DeviceInput('qemu',Path(session['graphics']))
  def profile(index):
   f,body=route.route(personal,49);row=struct.unpack_from('<8Q',body,index*128);return f,row
  def ready_profile(index):
   f,row=profile(index)
   require(row[4]!=4,('native terminal unavailable',index,row));return row if f[1]==index+1 and row[4]==3 else None
  began=time.monotonic();route.route(personal,38,h=3,a=81,b=session['feed']['owner'],c=8388608,d=65536);wait(lambda:ready_profile(0),'actual selected Feed relationship',120);report['timings']['feed_terminal_seconds']=time.monotonic()-began
  focus(j,'feed');require(ui_call(personal,session['feed']['ui'],791)[0][2]==11,'frozen Feed request changed')
  (out/'feed-final-content-review.ppm').write_bytes(j.ui.frame().ppm());began=time.monotonic();j.ui.press(63)
  def accepted_feed():
   f,_=ui_call(personal,session['feed']['ui'],791)
   print('Feed actual state',f,flush=True)
   if f[5]==8:raise RuntimeError(('native Feed outcome uncertain',f))
   return f if f[5]in(6,7)else None
  accepted=wait(accepted_feed,'actual Feed service accepts exact frozen excerpt',180);report['timings']['feed_acceptance_seconds']=time.monotonic()-began
  focus(j,'notes');j.ui.chord(42,64)
  frame=wait(lambda:(f if rendered_text(f:=j.ui.frame(),220,370,2,0xa6d7b1)in('04','05')else None),'app receives only its own Feed acceptance',45);(out/'app-own-feed-status.ppm').write_bytes(frame.ppm())
  passed('physical native Feed approval publishes exact Notes excerpt through real selected federation; app observes scoped acceptance',native_ui=list(accepted),app_status=rendered_text(frame,220,370,2,0xa6d7b1))
  _,authority=messenger.invoke(personal,2,434,a=10);require(len(authority)==96,'public mailbox authority96 required')
  enrolled,_=messenger.invoke(mailbox,3,440,h=1,a=8388608,b=65536,data=authority,allowed_status=(0,6))
  while enrolled[0]==6:enrolled,_=messenger.invoke(mailbox,3,441,h=4,allowed_status=(0,6))
  route.route(personal,38,h=4,a=82,b=session['delivery']['delivery'],c=8388608,d=65536);wait(lambda:ready_profile(1),'actual approved Messenger relationship',120)
  focus(j,'messenger');require(ui_call(personal,session['messenger']['ui'],782)[0][2]==8,'frozen recipient/content review changed')
  (out/'messenger-final-content-review.ppm').write_bytes(j.ui.frame().ppm());began=time.monotonic();j.ui.press(28)
  def accepted_message():
   focus(j,'notes');j.ui.chord(42,65);time.sleep(.15);frame=j.ui.frame();status=rendered_text(frame,260,370,2,0xa6d7b1)
   if status in('07','08'):raise RuntimeError(('native message failed or uncertain',status))
   return frame if status in('04','05')else None
  frame=wait(accepted_message,'actual Messenger mailbox accepts exact approved excerpt',240);report['timings']['messenger_acceptance_seconds']=time.monotonic()-began;(out/'app-own-messenger-status.ppm').write_bytes(frame.ppm())
  passed('physical native Messenger approval sends exact Notes excerpt to approved recipient through routed mailbox; app observes only own acceptance',app_status=rendered_text(frame,260,370,2,0xa6d7b1))
  report['result']='pass-real-feed-and-mailbox-acceptance';report['limits']='Actual Feed publication and mailbox acceptance, separate current relays and preserved providers. Recipient decryption/confirmation and genuine project-card discovery require their separately observed continuations.';save()
 except BaseException as error:
  with contextlib.suppress(Exception):(out/'social-route-failure.ppm').write_bytes(j.ui.frame().ppm())
  report.update(result='failure-preserved-operations',error=repr(error),traceback=traceback.format_exc());save();raise
 finally:
  if j and j.ui:j.ui.close()
  for c in clients:c.close()
if __name__=='__main__':main()
