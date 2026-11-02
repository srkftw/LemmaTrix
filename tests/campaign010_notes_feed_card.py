"""Native Feed card from the actual independently signed Notes admission."""
import argparse,contextlib,hashlib,json,struct,sys,time,traceback
from pathlib import Path
from types import SimpleNamespace as NS
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import federation,identity,live,messenger
from campaign010_project_notes import NotesJourney,wait
from campaign010_notes_sharing import focus,ui_call
from creator_journey import require,rendered_text
from graphical_devices import DeviceInput

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--sharing',type=Path,required=True);p.add_argument('--admission',type=Path,required=True);p.add_argument('--public-verifier',type=Path,required=True);p.add_argument('--registry',type=Path,required=True);a=p.parse_args();out=a.sharing.resolve();s=json.loads((out/'message-reconcile.json').read_bytes())['session'];pub=json.loads(a.public_verifier.read_bytes());descriptor=a.admission.read_bytes();report=dict(schema=1,result='running',checks=[])
 j=NotesJourney(NS(output=out/'personal',image=ROOT/'build/campaign010-vault-recovery-current/guest.bin',backend='qemu'));j.ui=DeviceInput('qemu',Path(s['graphics']));client=live.Client(Path(s['socket']),timeout=600);began=time.monotonic()
 def save():report['elapsed_seconds']=time.monotonic()-began;(out/'feed-card.json').write_text(json.dumps(report,indent=2)+'\n')
 def passed(label,**fields):report['checks'].append(dict(check=label,result='pass',**fields));save();print('PASS',label,flush=True)
 try:
  inventory=identity.instances(client);desktop=next(row[0]for row in inventory if row[2]==895 and row[0]!=s['app']and 0<row[1]<5)
  for _ in range(10):
   if rendered_text(j.ui.frame(),8,51,6)=='EDITOR':break
   j.ui.chord(56,15);time.sleep(.35)
  else:raise TimeoutError('native workbench focus')
  j.ui.chord(56,67)
  wait(lambda:rendered_text(j.ui.frame(),4,318,1)=='>','native lifecycle exact focused workbench',45);time.sleep(.5);(out/'close-workbench-review.ppm').write_bytes(j.ui.frame().ppm());j.ui.press(31)
  wait(lambda:not any(row[0]==desktop and 0<row[1]<5 for row in identity.instances(client)),'ordinary native close frees one slot',45);j.ui.press(1)
  registry,sid=messenger.install(client,a.registry,ROOT/'tests/keys/development-rsa-public.pem',2175)
  config=federation.configure_native_verifier(client,registry,pub['public_key'],'consumer',allowed_rights=895,generation=pub['generation'])
  verified,body=federation.call(client,registry,11,data=descriptor+descriptor[320:352]);require(body==descriptor and verified[1]==2,'native verifier did not accept actual immutable Alpha admission')
  selected,body=federation.call(client,registry,6);require(body==descriptor,'actual verified admission is not catalog-selected')
  current=identity.instances(client);ordinary=[list(row)for row in current if row[0]&255>=7 and 0<row[1]<5];require(len(ordinary)==8,'bounded ordinary slot footprint differs')
  passed('normal lifecycle closes workbench; independent public-only verifier fits eight slots and verifies actual Alpha Notes admission',closed=desktop,registry=registry,registry_release=sid.hex(),ordinary=ordinary,configuration=config,descriptor_sha256=hashlib.sha256(descriptor).hexdigest(),signing_authority=False)
  focus(j,'feed');j.ui.press(87)
  def composing():
   f,_=ui_call(client,s['feed']['ui'],791);return f if f[2]==1 and f[4]==33 else None
  wait(composing,'native Feed selects actual verified project card',90)
  caption='Project Notes 1.0: project documentation, release drafts and reviewed sharing. Inspect this release and its signed helper before installation.'
  j.ui.textASCII(caption,delay=.05);j.ui.press(62)
  wait(lambda:ui_call(client,s['feed']['ui'],791)[0][2]==9,'actual project card content preview',45);(out/'genuine-project-card-preview.ppm').write_bytes(j.ui.frame().ppm());j.ui.press(63)
  def accepted():
   f,_=ui_call(client,s['feed']['ui'],791)
   if f[5]==8:raise RuntimeError(('native project-card outcome uncertain',f))
   return f if f[5]in(6,7)else None
  state=wait(accepted,'native Feed publishes genuine Notes project card',180)
  _,selected=ui_call(client,s['feed']['ui'],795)
  passed('physical Feed preview and publication author a genuine card for actual signed release/admission',native_ui=list(state),release=pub['release_id'],root=pub['root'],federation=pub['federation_id'],caption=caption,event=selected[:32].hex(),installation_approved=False,execution_approved=False)
  report.update(result='pass-real-native-project-card',session=dict(s,registry=registry),limits='This proves native card publication from an independently verified immutable admission. Feed authorship grants no publisher maintainership, installation or execution consent; second-user discovery is separate evidence.');save()
 except BaseException as error:
  with contextlib.suppress(Exception):(out/'feed-card-failure.ppm').write_bytes(j.ui.frame().ppm())
  report.update(result='failure-preserved-social-authority',error=repr(error),traceback=traceback.format_exc());save();raise
 finally:client.close();j.ui.close()
if __name__=='__main__':main()
