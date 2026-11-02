"""Recover the real Notes user and prepare exact native sharing owners.

This continuation uses the original explicitly retained Objects backing and
public packages. It never restores publisher signing approval or live handles.
The separately recorded sharing steps use physical app/owner review controls.
"""
import argparse,contextlib,hashlib,json,os,signal,struct,sys,time,traceback
from pathlib import Path
from types import SimpleNamespace as NS
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import feed,identity,live,messenger,projects,project_vault,releases
from campaign010_project_notes import NotesJourney,run_json,wait
from creator_journey import rendered_text,require

def focus(j,name):
 color={'notes':0xdce9ec,'feed':0xe3ecf4,'messenger':0xdbe8ee}[name]
 title={'notes':'Project Notes','feed':'Feed','messenger':'Messenger'}[name]
 y=56 if name=='notes' else 60
 for _ in range(10):
  if rendered_text(j.ui.frame(),14,y,len(title),color)==title:return
  j.ui.chord(56,15);time.sleep(.35)
 raise TimeoutError('ordinary native focus '+name)

def pick(j,name,code):
 j.ui.press(code)
 def rows():
  frame=j.ui.frame();found=[rendered_text(frame,32,107+i*12,len(name)+1).rstrip()for i in range(16)]
  return found if name in found else None
 found=wait(rows,'native explicit root selection '+name,45)
 for _ in range(found.index(name)):j.ui.press(108,.08)
 j.ui.press(28);time.sleep(.5)

def ui_call(client,who,op,data=b''):
 raw=client.request(150,struct.pack('<Q8Q',who,op,0,0,0,0,0,0,1)+data)
 return struct.unpack_from('<8Q',raw),raw[64:]

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--prior',type=Path,required=True);p.add_argument('--image',type=Path,required=True)
 p.add_argument('--output',type=Path,required=True);p.add_argument('--historical',type=Path,required=True)
 a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
 prior=json.loads((a.prior/'execution.json').read_bytes());session=prior['session']
 require(prior['result']=='pass','successful selected retention/recovery required')
 original=ROOT/'build/campaign010-notes-native-4';ready=json.loads((original/'ready.json').read_bytes())
 boot=ROOT/'build/campaign010-native-bootstrap-current';public=ROOT/'tests/keys/development-rsa-public.pem'
 args=NS(output=out/'personal',image=a.image,backend='qemu',public=public,key=ROOT/'tests/keys/development-rsa.pem',vault=original/'objects.img',vault_key=original/'objects.key',network_mux=True)
 j=NotesJourney(args);began=time.monotonic();report=dict(schema=1,result='preparing',checks=[],source_session=str(a.prior),image_sha256=j.image,private_keys_exported=False)
 def save():report['elapsed_seconds']=round(time.monotonic()-began,3);(out/'execution.json').write_text(json.dumps(report,indent=2)+'\n')
 def passed(label,**fields):report['checks'].append(dict(check=label,result='pass',**fields));save();print('PASS',label,flush=True)
 try:
  # Exclusive handoff from the successful H continuation authorizes this restart.
  command=Path('/proc')/str(session['pid'])/'cmdline'
  require(command.exists()and b'lt\0run\0' in command.read_bytes(),'original personal process identity changed')
  os.killpg(session['pid'],signal.SIGTERM);time.sleep(.3);j.boot()
  j.trust_stage(boot/'native-editor.ltrel','native-editor');j.ui.press(1)
  with j.client()as c:
   signer=identity.start(c,boot/'identity.ltrel',public)
   project_vault.unlock(c,args.vault_key.read_bytes());require(not projects.roots(c),'old live roots survived restart')
   saved=project_vault.inventory(c);selection=[i for i,item in enumerate(saved['projects'])if item['name']in('project-notes','project-notes-1.0.0')]
   require(len(selection)==2,'exact selected note and application roots unavailable')
   recovered=project_vault.recover(c,selection)
   c.request(10,bytes.fromhex(ready['release']['project_id'])+(original/'project-notes.pub').read_bytes())
   c.stage(original/'project-notes.ltrel')
   root=next(item for item in recovered['roots']if item['name']=='project-notes-1.0.0')
   cap=projects.resolve(c,root['cap'],ready['release']['release_node'])
   material=c.request(15,struct.pack('<Q',cap));require(struct.unpack_from('<Q',material,8)[0]==1,'fresh exact release material required')
  j.ui.press(88);time.sleep(.5);j.ui.press(28);j.wait_text(14,152,'Title / ',0xdce9ec,timeout=45)
  pick(j,'project-notes',62);j.wait_text(16,134,'Release plan',0xa6d7b1)
  with j.client()as c:
   app=max(row[0]for row in identity.instances(c)if row[2]==895 and 0<row[1]<5)
  passed('same real selected note and signed application recover with fresh handles and opaque networking',recovered=recovered,app=app,release=ready['release']['release_id'],publisher_recovered=False)
  historical=a.historical.resolve();invitation=(historical/'bob.invitation').read_bytes();federation=invitation[192:224].hex()
  beta=(historical/'beta.certificate').read_bytes();mail=(historical/'mailbox.certificate').read_bytes()
  feed_dir=ROOT/'build/campaign010-intent-services-feed';message_dir=ROOT/'build/campaign010-intent-services-messenger';current=ROOT/'build/campaign010-intent-services-current'
  with j.client()as c:
   configured=feed.start(c,NS(identity=boot/'identity.ltrel',owner=current/'feed-account.ltrel',ui=feed_dir/'feed.ltrel',public=public,federation=hashlib.sha256(b'Campaign009 common beta').hexdigest(),peer=hashlib.sha256(b'Campaign009 common alpha').hexdigest()))
  focus(j,'feed');j.ui.press(60)
  def feed_created():
   with j.client()as c:f,_=ui_call(c,configured['ui'],791)
   return f if f[1]==1 and f[7]==1 else None
  wait(feed_created,'native Feed owner creates its own protected author',180)
  passed('Feed creates protected native author without replacing project Identity',configured=configured,identity=signer)
  result=run_json([ROOT/'lt','messenger','--socket',j.socket,'start','--owner',current/'messenger-session.ltrel','--ui',message_dir/'messenger.ltrel','--public',public],out/'messenger-start.json')
  with j.client()as c:ui_call(c,result['ui'],781,bytes.fromhex(federation))
  focus(j,'messenger');j.ui.press(60)
  def device_created():
   with j.client()as c:f,_=ui_call(c,result['ui'],782)
   return f if f[4]==41 else None
  wait(device_created,'native Messenger creates separate device',180)
  with j.client()as c:messenger.invoke(c,2,434,a=13,data=hashlib.sha256(mail).digest())
  run_json([ROOT/'lt','messenger','--socket',j.socket,'certify-contact','--identity-release',boot/'identity.ltrel','--public',public,'--scope',hashlib.sha256(b'Campaign010 Notes contact scope').hexdigest(),'--output',out/'personal.invitation'],out/'contact-certificate.json')
  with j.client()as c:ui_call(c,result['ui'],780,invitation)
  def candidate():
   with j.client()as c:f,pin=ui_call(c,result['ui'],782)
   return (f,pin)if f[2]==1 else None
  f,pin=wait(candidate,'actual recipient public fingerprint',90);(out/'recipient-review.ppm').write_bytes(j.ui.frame().ppm())
  j.ui.press(63)
  def approved():
   with j.client()as c:f,_=ui_call(c,result['ui'],782)
   return f if f[5]==1 else None
  wait(approved,'physical approved Messenger recipient',90)
  passed('Messenger independently creates native device and approves actual recipient fingerprint',owner=result['owner'],ui=result['ui'],recipient=pin.hex(),recipient_slot=1)
  delivery=run_json([ROOT/'lt','messenger','--socket',j.socket,'delivery-start','--release',message_dir/'messenger-delivery.ltrel','--public',public,'--ui',result['ui'],'--ui-release',message_dir/'messenger.ltrel','--owner-release',current/'messenger-session.ltrel'],out/'delivery-start.json')
  report.update(result='prepared-real-sharing-owners',session=dict(socket=str(j.socket),graphics=str(j.graphics),pid=j.proc.pid,app=app,release=ready['release']['release_id'],feed=configured,messenger=result,delivery=delivery,recovered=recovered,backend='qemu',image=str(a.image.resolve())),limits='Prepared installed app and native owner credentials. No Feed event or Messenger message is claimed published or delivered by preparation.');save()
 except BaseException as error:
  with contextlib.suppress(Exception):(out/'failure.ppm').write_bytes(j.ui.frame().ppm())
  report.update(result='failure-preserved-personal',error=repr(error),traceback=traceback.format_exc(),session=dict(socket=str(j.socket),graphics=str(j.graphics),pid=j.proc.pid if j.proc else None));save();raise
 finally:
  if j.ui:j.ui.close()
if __name__=='__main__':main()
