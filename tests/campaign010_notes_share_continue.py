"""Continue preserved Notes owners using real app and trusted owner input."""
import argparse,contextlib,hashlib,json,struct,sys,time,traceback
from pathlib import Path
from types import SimpleNamespace as NS
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import live,messenger,identity
from campaign010_notes_sharing import focus,pick,ui_call
from campaign010_project_notes import NotesJourney,run_json,wait
from creator_journey import require,rendered_text
from graphical_devices import DeviceInput

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--session',type=Path,required=True);p.add_argument('--review-only',action='store_true');a=p.parse_args();out=a.session.resolve()
 previous=json.loads((out/'execution.json').read_bytes());session=previous['session']
 app=previous['checks'][0]['app'];configured=previous['checks'][1]['configured'];result=json.loads((out/'messenger-start.json').read_bytes())
 j=NotesJourney(NS(output=out/'personal',image=ROOT/'build/campaign010-vault-recovery-current/guest.bin',backend='qemu'));j.ui=DeviceInput('qemu',Path(session['graphics']))
 with j.client()as c:app=max(row[0]for row in identity.instances(c)if row[2]==895 and 0<row[1]<5)
 report=dict(schema=1,result='running',checks=[],previous=str(out/'execution.json'),session=dict(**session,app=app,feed=configured,messenger=result),limits='Real installed app and trusted native review. A frozen request is not publication or delivery evidence.')
 def save():(out/'review.json').write_text(json.dumps(report,indent=2)+'\n')
 def passed(label,**fields):report['checks'].append(dict(check=label,result='pass',**fields));save();print('PASS',label,flush=True)
 def fields(who,op):
  with j.client()as c:return ui_call(c,who,op)[0]
 def grant(role):
  focus(j,'notes');j.ui.chord(56,87)
  if role==2:j.ui.press(50)
  def displayed():
   frame=j.ui.frame()
   return frame if rendered_text(frame,16,44,16)==format(app,'016x')and rendered_text(frame,304,44,2)==format(role,'02x')and rendered_text(frame,16,248,4)=='0000'else None
  frame=wait(displayed,'trusted exact caller/service grant review',45);(out/('grant-'+str(role)+'.ppm')).write_bytes(frame.ppm());time.sleep(.5);j.ui.press(28);time.sleep(.4)
 try:
  if a.review_only:
   j.ui.press(1);time.sleep(.3)
   delivery=json.loads((out/'delivery-start.json').read_bytes());report['session']['delivery']=delivery
  else:
  # Correct the unpublished preparation scope through native Forget, then create
  # a new protected author for the actual selected existing federation.
   focus(j,'feed');j.ui.press(59);wait(lambda:fields(configured['ui'],791)[2]==5,'native Feed retention panel',30);j.ui.press(65)
   wait(lambda:fields(configured['ui'],791)[1]==0,'native forget clears unpublished author',90);j.ui.press(1)
   fed=hashlib.sha256(b'Campaign009 common beta').digest();peer=hashlib.sha256(b'Campaign009 common alpha').digest()
   with j.client()as c:ui_call(c,configured['ui'],790,fed+peer)
   j.ui.press(60);wait(lambda:fields(configured['ui'],791)[1]==1,'native author for selected actual federation',90)
   configured.update(federation=fed.hex(),selected_peer=peer.hex());passed('unpublished author forgotten and fresh native authority uses exact selected federation',federation=fed.hex(),peer=peer.hex())
   historical=ROOT/'build/campaign009-connected-v7';invitation=(historical/'bob.invitation').read_bytes();focus(j,'messenger')
   with j.client()as c:ui_call(c,result['ui'],780,invitation)
   wait(lambda:fields(result['ui'],782)[2]==1,'actual Bob fingerprint review',90);(out/'recipient-review.ppm').write_bytes(j.ui.frame().ppm());j.ui.press(63)
   wait(lambda:fields(result['ui'],782)[5]==1,'native recipient approval',90)
   passed('actual recipient public fingerprint approved by physical native Messenger control',recipient_slot=1)
   message_dir=ROOT/'build/campaign010-intent-services-messenger';current=ROOT/'build/campaign010-intent-services-current';public=ROOT/'tests/keys/development-rsa-public.pem'
   delivery=run_json([ROOT/'lt','messenger','--socket',j.socket,'delivery-start','--release',message_dir/'messenger-delivery.ltrel','--public',public,'--ui',result['ui'],'--ui-release',message_dir/'messenger.ltrel','--owner-release',current/'messenger-session.ltrel'],out/'delivery-start.json');report['session']['delivery']=delivery
  grant(5);focus(j,'notes');j.ui.press(64)
  wait(lambda:rendered_text(j.ui.frame(),220,370,2,0xa6d7b1)=='01','app own Feed intent pending',30)
  focus(j,'feed');j.ui.chord(42,87);wait(lambda:fields(configured['ui'],791)[2]==11,'trusted Feed immutable-content review',45)
  (out/'feed-excerpt-review.ppm').write_bytes(j.ui.frame().ppm());passed('ordinary Notes submits only its scoped Feed request; actual owner freezes selected excerpt before approval')
  grant(2);focus(j,'notes');j.ui.press(65)
  wait(lambda:rendered_text(j.ui.frame(),260,370,2,0xa6d7b1)=='01','app own Messenger intent pending',30)
  focus(j,'messenger');j.ui.chord(42,87);wait(lambda:fields(result['ui'],782)[2]==8,'trusted Messenger recipient/content review',45)
  (out/'messenger-excerpt-review.ppm').write_bytes(j.ui.frame().ppm());passed('ordinary Notes submits selected excerpt to approved recipient; actual owner freezes its separate request')
  report['result']='pass-real-native-reviews-awaiting-transport';save()
 except BaseException as error:
  with contextlib.suppress(Exception):(out/'review-failure.ppm').write_bytes(j.ui.frame().ppm())
  report.update(result='failure-preserved-operations',error=repr(error),traceback=traceback.format_exc());save();raise
 finally:j.ui.close()
if __name__=='__main__':main()
