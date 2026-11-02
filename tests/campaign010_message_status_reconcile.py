"""Normal Delivery update reconciles the existing committed Notes ciphertext."""
import argparse,contextlib,hashlib,json,struct,sys,time,traceback
from pathlib import Path
from types import SimpleNamespace as NS
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import identity,live,messenger,onion_route as route,releases
from campaign010_project_notes import NotesJourney,wait
from campaign010_notes_sharing import focus,ui_call
from creator_journey import rendered_text,require
from graphical_devices import DeviceInput

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--sharing',type=Path,required=True);p.add_argument('--delivery',type=Path,required=True);a=p.parse_args();out=a.sharing.resolve();r=json.loads((out/'review-final.json').read_bytes());s=r['session'];public=ROOT/'tests/keys/development-rsa-public.pem';info=releases.inspect(a.delivery.read_bytes())
 j=NotesJourney(NS(output=out/'personal',image=ROOT/'build/campaign010-vault-recovery-current/guest.bin',backend='qemu'));j.ui=DeviceInput('qemu',Path(s['graphics']));client=live.Client(Path(s['socket']),timeout=600);report=dict(schema=1,result='running',checks=[]);began=time.monotonic()
 def save():report['elapsed_seconds']=time.monotonic()-began;(out/'message-reconcile.json').write_text(json.dumps(report,indent=2)+'\n')
 def passed(label,**fields):report['checks'].append(dict(check=label,result='pass',**fields));save();print('PASS',label,flush=True)
 try:
  old=s['delivery']['delivery'];owner=s['messenger']['owner'];ui=s['messenger']['ui'];before=ui_call(client,ui,782)[0]
  require(before[4]==19 and before[6]==1,'existing actual mailbox acceptance/serial1 required')
  _,request_before=messenger.invoke(client,2,434,h=1,a=25);owner_before=messenger.invoke(client,2,420)[0]
  _,rows=route.route(client,49);old_row=struct.unpack_from('<8Q',rows,128)
  require(old_row[1]==old,'profile does not belong to exact replaced coordinator')
  client.request(26,struct.pack('<Q',old));staged=client.stage(a.delivery)
  j.ui.press(88);time.sleep(.8);(out/'delivery-update-review.ppm').write_bytes(j.ui.frame().ppm());j.ui.press(28)
  def active():return client.request(29,bytes.fromhex(info['project_id']))[160:192].hex()==info['release_id']
  wait(active,'normal native Delivery update activation',90)
  new=next(row[0]for row in identity.instances(client)if row[2]==1024 and row[0]!=s['feed']['owner']and 0<row[1]<5)
  sid=bytes.fromhex(info['release_id']);owner_sid=bytes.fromhex(s['messenger']['owner_release']);ui_sid=bytes.fromhex(releases.inspect((ROOT/'build/campaign010-intent-services-messenger/messenger.ltrel').read_bytes())['release_id'])
  for op in(427,428,434):messenger.bind(client,2,owner,new,op,owner_sid,sid)
  for op in range(460,464):messenger.bind(client,4,new,ui,op,sid,ui_sid)
  messenger.bind(client,4,new,owner,461,sid,owner_sid);messenger.bind(client,4,new,messenger.launcher(client),464,sid);messenger.invoke(client,4,464,h=owner)
  require(new!=old,'old coordinator incarnation revived')
  passed('physical native update replaces only Delivery; protected Session and its accepted outbox stay live',old_delivery=old,new_delivery=new,release=info['release_id'],parent=info['parent'],rights=info['rights'],owner=owner,outbox_serial=before[6])
  # Bind fresh live authority with exactly the previous remaining allowance.
  # This cannot renew the old profile's already consumed bytes or attempts.
  def vacancy():
   _,body=route.route(client,49);return struct.unpack_from('<Q',body,128)[0]==0
  wait(vacancy,'dead coordinator profile retires authenticated terminal',60)
  route.route(client,38,h=4,a=83,b=new,c=old_row[6],d=old_row[7])
  def selected():
   f,body=route.route(client,49);row=struct.unpack_from('<8Q',body,128)
   require(row[4]!=4,('new exact service unavailable',row));return row if f[1]==2 and row[4]==3 else None
  wait(selected,'fresh exact coordinator routed binding',120)
  focus(j,'messenger');j.ui.press(65)
  def accepted():
   f,_=ui_call(client,ui,782);delivery,_=messenger.invoke(client,4,464,a=4)
   return f if f[4]==19 and f[6]==1 and delivery[2]==11 else None
  wait(accepted,'existing ciphertext reconciles mailbox acceptance',180)
  focus(j,'notes');j.ui.chord(42,65)
  def own_status():
   f=j.ui.frame();return f if rendered_text(f,260,370,2,0xa6d7b1)=='04'else None
  frame=wait(own_status,'app scoped mailbox acceptance after exact result bridge',45);(out/'app-own-messenger-accepted.ppm').write_bytes(frame.ppm())
  _,request_after=messenger.invoke(client,2,434,h=1,a=25);owner_after=messenger.invoke(client,2,420)[0]
  require(request_before==request_after and owner_before[3]==owner_after[3]==1,'retry changed stable request or created a second outbox')
  passed('actual native retry preserves originating ciphertext operation and reports only app-owned mailbox acceptance',app_status='04',outboxes=owner_after[3],request_identity_sha256=hashlib.sha256(request_after).hexdigest(),remaining_budget_carried=list(old_row[6:8]))
  s['delivery'].update(delivery=new,delivery_release=info['release_id']);report.update(result='pass-real-mailbox-acceptance-and-scoped-status',session=s,limits='Mailbox acceptance is evidenced. Recipient confirmation is not claimed. Session stayed live; no protected seed, ratchet or app approval was exported/recovered.');save()
 except BaseException as error:
  with contextlib.suppress(Exception):(out/'message-reconcile-failure.ppm').write_bytes(j.ui.frame().ppm())
  report.update(result='failure-preserved-session-and-outbox',error=repr(error),traceback=traceback.format_exc());save();raise
 finally:client.close();j.ui.close()
if __name__=='__main__':main()
