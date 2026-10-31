"""Native graphical Messenger retention, lock, recovery and history-import controls.

Only physical input, explicit public management authorization, public native
API observations and opaque whole-backing copies are used. This harness never
edits a snapshot, session record or mailbox. --history-backup must come from an
actual prior native conversation; it is not constructed by this test.
"""
from __future__ import annotations
import argparse,contextlib,hashlib,json,resource,struct,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
from messenger_journey import Guest,role,wait,wait_ui,screenshot,FED,PUB
import identity,messenger,releases

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',required=True,type=Path);p.add_argument('--ready-packages',required=True,type=Path);p.add_argument('--output',required=True,type=Path);p.add_argument('--history-backup',type=Path);p.add_argument('--history-personal',default='bob',choices=('alice','bob'));p.add_argument('--only-history',action='store_true');p.add_argument('--resume-local',type=Path,help='resume this helper prior opaque backing after adapter interruption');p.add_argument('--resume-history-actor',type=Path,help='exclusive reattach to this helper still-running history-only native actor after its old controller exited');p.add_argument('--history-ui-only',action='store_true',help='focused successful history-import form closure, actual PgDn render and F8 check only');a=p.parse_args()
 if a.only_history and not a.history_backup:p.error('--only-history requires an actual --history-backup')
 if a.resume_history_actor and not a.only_history:p.error('--resume-history-actor requires --only-history')
 if a.history_ui_only and not a.only_history:p.error('--history-ui-only requires --only-history')
 size=5396000*512;soft,hard=resource.getrlimit(resource.RLIMIT_FSIZE)
 if soft!=resource.RLIM_INFINITY and soft<size:
  if hard!=resource.RLIM_INFINITY and hard<size:raise RuntimeError('host file limit is below the explicitly selected complete personal backing')
  resource.setrlimit(resource.RLIMIT_FSIZE,(size,hard))
 out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);image=out/'guest.bin';image.write_bytes(a.image.read_bytes());ready=json.loads(a.ready_packages.read_text());packages={};checks=[];actors=[];began=time.monotonic()
 for name in ('owner','ui'):
  source=Path(ready[name]);path=out/(name+'.ltrel');path.write_bytes(source.read_bytes());packages[name]=(path,releases.inspect(path.read_bytes(),trusted_modulus=releases.public_modulus(PUB)))
 report=dict(schema=1,result='running',image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),packages={n:i for n,(_,i)in packages.items()},checks=checks,host_authority='opaque backing copy, explicit exact-owner domain authorization, public native API observations and physical graphical input only',limits='Local graphical retention component; routed conversation and attachment acceptance are recorded by the separate central campaign. Whole-backing substitution is not detected without an external freshness anchor.')
 def record(label,**extra):
  checks.append(dict(check=label,result='pass',**extra));(out/'progress.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS',label,flush=True)
 def invoke(g,op,expected=0,**kwargs):
  f,payload=role(g,2,op,allow=(()if expected==0 else(expected,)),**kwargs);assert f[0]==expected,(op,f);return f,payload
 def public_ui(g):
  raw=g.client.request(150,struct.pack('<Q8Q',g.ui,783,0,0,0,0,0,0,1));return struct.unpack_from('<8Q',raw)
 def owner_state(g):return invoke(g,420)[0]
 def start(name,backing=None):
  g=Guest(name,'qemu',out,image,graphical=True,vault=backing).start();actors.append(g)
  g.owner,sid=messenger.install(g.client,packages['owner'][0],PUB,0);g.ui,uid=messenger.install(g.client,packages['ui'][0],PUB,799);launcher=messenger.launcher(g.client)
  for op in (420,421,422,426,427,429,431,432,433,434,435):messenger.bind(g.client,2,g.owner,launcher,op,sid)
  for op in range(420,436):messenger.bind(g.client,2,g.owner,g.ui,op,sid,uid)
  g.client.request(150,struct.pack('<Q8Q',g.ui,781,0,0,0,0,0,0,1)+FED);g.device.chord(56,15);time.sleep(.3);return g
 def create(g):
  g.device.press(1,delay=.1);g.device.press(60,delay=.1);wait_ui(g,lambda f:f[4]==41,'graphical F2 device creation');return invoke(g,422)[1]
 def unlock(g,key,mode,success=True):
  g.client.request(174,struct.pack('<2Q',g.owner,1));g.device.press(67,delay=.1);g.device.press(59+mode,delay=.1);g.device.press(62,delay=.1);g.device.textASCII(key.hex(),delay=.06);g.device.press(28,delay=.1)
  if success:
   wait_ui(g,lambda f:f[4]in(34,64,20),'graphical F9 native domain unlock')
   state=owner_state(g);assert state[1]==(0 if mode==2 else 1) and state[5]==(0 if mode==2 else 1)
  else:
   wait(lambda:public_ui(g)[6]==0 and public_ui(g)[5]!=0,240,'native graphical recovery rejection')
   assert owner_state(g)[1]==0
 def lock(g):
  g.device.press(66,delay=.1);wait_ui(g,lambda f:f[4]==23 and f[3]==0 and f[5]==0,'graphical F8 accessible data cleared');assert owner_state(g)[1]==0;invoke(g,422,expected=5);invoke(g,429,h=1,expected=5);invoke(g,434,a=23,expected=5)
 def sparse(path):
  size=5396000*512;soft,hard=resource.getrlimit(resource.RLIMIT_FSIZE)
  if soft!=resource.RLIM_INFINITY and soft<size:resource.setrlimit(resource.RLIMIT_FSIZE,(size,hard))
  with path.open('xb')as f:f.truncate(size)
 try:
  if not a.only_history:
   backing=out/'new-personal.img';key=hashlib.sha256(b'public graphical controls domain2 unlock fixture').digest()
   if a.resume_local:
    subprocess.run(['cp','--reflink=auto','--sparse=always',str(a.resume_local.resolve()),str(backing)],check=True)
    g=start('retained',backing);unlock(g,key,1);original=invoke(g,422)[1]
    prior_ui=a.resume_local.resolve().parent/'ui.ltrel'
    report['adapter_recovery']=dict(source=str(a.resume_local.resolve()),correction='Observe committed native owner state and rendered completion, rather than transient last-operation field overwritten by periodic status checks; run the explicitly selected current graphical package',prior_ui_release=releases.inspect(prior_ui.read_bytes())['release_id']if prior_ui.exists()else None,current_ui_release=packages['ui'][1]['release_id'],new_messaging_identity_created=False)
   else:sparse(backing);g=start('retained',backing);original=create(g)
   objects=b'An independently authorized Objects record remains readable while Messenger is locked or forgotten.'
   handle=g.client.import_object(objects);objects_owner=next(row[0]for row in identity.instances(g.client)if row[0]&255==2)
   try:g.client.request(174,struct.pack('<2Q',objects_owner,1))
   except ValueError:pass
   else:raise AssertionError('Objects service obtained Messenger domain authority')
   if not a.resume_local:unlock(g,key,0)
   assert owner_state(g)[5]==1
   record('actual graphical F9 recovers the previously created independently authorized Messenger domain2 after an adapter interruption'if a.resume_local else'actual graphical F2 creates a native device and F9/create explicitly unlocks independently authorized Messenger domain2')
   lock(g);assert g.client.read_object(handle)==objects
   unlock(g,key,1);assert invoke(g,422)[1]==original and owner_state(g)[5]==1;screenshot(g,'recovered')
   record('actual graphical F8 clears access and F9/recover restores the same native device; Objects remains accessible and cannot obtain Messenger authority')
   g.device.press(1,delay=.1);g.device.press(68,delay=.1);wait_ui(g,lambda f:f[2]==4,'graphical forget confirmation');g.device.press(28,delay=.1);wait_ui(g,lambda f:f[4]==23,'graphical committed forget');assert owner_state(g)[1]==0 and g.client.read_object(handle)==objects
   unlock(g,key,1,False);invoke(g,429,h=1,expected=5);screenshot(g,'forgotten');record('actual graphical F10/Enter forget invalidates native durable roots; supported recovery fails and independent Objects record remains readable')
   g.stop()
   first=start('ephemeral-first');first_public=create(first);assert owner_state(first)[5]==0;lock(first);first.stop()
   second=start('ephemeral-restarted');invoke(second,422,expected=5);second_public=create(second);assert second_public[32:64]!=first_public[32:64]and owner_state(second)[5]==0;screenshot(second,'ephemeral');second.stop()
   record('normal graphical no-vault operation stays ephemeral; actual guest restart loses the prior native messaging identity and creates fresh authority')
  if a.history_backup:
   source=a.history_backup.resolve();backing=out/'older-history-import.img'
   if source.stat().st_size!=5396000*512:raise ValueError('history input must be an actual complete personal backing')
   key=hashlib.sha256(('Campaign008 disclosed '+a.history_personal.capitalize()+' vault-unlock fixture').encode()).digest()
   if a.resume_history_actor:
    previous=a.resume_history_actor.resolve();backing=previous/'older-history-import.img'
    g=Guest('history-import','qemu',previous,image,graphical=True,vault=backing).attach(previous);g.out=out;actors.append(g)
    g.owner=messenger.endpoint(g.client,2,420);g.ui=next(row[0]for row in identity.instances(g.client)if row[2]==799 and 0<row[1]<5)
    for name in ('owner','ui'):
     current=g.client.request(14,bytes.fromhex(packages[name][1]['project_id']));assert current[64:96]==bytes.fromhex(packages[name][1]['release_id'])
    report['adapter_recovery']=dict(previous_controller=str(previous),native_guest_restarted=False,history_reimported=False,reason='v3successfulmode2leftcredentialformopen; same native owner/copy reattached exclusively for an actual Esc then PgDn')
   else:
    subprocess.run(['cp','--reflink=auto','--sparse=always',str(source),str(backing)],check=True)
    g=start('history-import',backing);unlock(g,key,2)
   old_status=owner_state(g);assert old_status[1]==0 and old_status[4]>0
   f,text=invoke(g,429,h=1);assert text and len(text)<=512
   for op,kw in [(422,{}),(434,dict(a=23)),(435,dict(h=1)),(426,dict(h=1,a=4,data=b'nope'))]:invoke(g,op,expected=5,**kw)
   wait_ui(g,lambda state:state[4]==20,'native UI loads eligible recovered history')
   current=struct.unpack_from('<8Q',g.client.request(150,struct.pack('<Q8Q',g.ui,782,0,0,0,0,0,0,1)))
   if a.history_ui_only:assert current[2]==0,'successful native GUI history import left the credential form open'
   if current[2]==5:g.device.press(1,delay=.1);wait_ui(g,lambda state:state[2]==0,'actual Esc dismisses completed credential form')
   unselected=screenshot(g,'history-before-selection');g.device.press(109,delay=.1)
   wait_ui(g,lambda state:state[1]==1 and state[5]==0,'actual PgDn selects history without contact approval')
   selected=screenshot(g,'history-only');assert selected!=unselected,'history selection did not change the native rendered frame'
   history_state=owner_state(g)
   g.device.press(60,delay=.1)
   wait_ui(g,lambda state:state[4]==26,'actual F2 requires archival reconciliation before fresh authority')
   assert public_ui(g)[5]==12 and owner_state(g)==history_state
   same_fields,same_text=invoke(g,429,h=1);assert same_fields==f and same_text==text
   denied=screenshot(g,'history-create-denied')
   record('actual graphical F2 is denied with reconciliation while archival history remains readable and unchanged; explicit F8 is required before fresh device creation',owner_status=list(history_state),error=12,history_sha256=hashlib.sha256(text).hexdigest(),frame_sha256=denied)
   if a.history_ui_only:
    lock(g);record('successful actual graphical history import closes its credential form, PgDn renders eligible recovered history without approval, and F8 clears native access',source=str(source),history_frame_before=unselected,history_frame_selected=selected)
    report.update(result='pass',elapsed_seconds=time.monotonic()-began,incomplete_acceptance=[],scope='Focused changed GUI closure check; full same-copy retirement and fresh authority checks are recorded separately.');(out/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2));return
   lock(g);unlock(g,key,1,False);assert public_ui(g)[5]==13,'history import left old roots normally recoverable'
   for op,kw in [(422,{}),(434,dict(a=23)),(435,dict(h=1)),(426,dict(h=1,a=4,data=b'nope'))]:invoke(g,op,expected=5,**kw)
   new_bundle=create(g);assert owner_state(g)[2]==0 and owner_state(g)[5]==0
   old_invitation=source.parent/(a.history_personal+'.invitation')
   if old_invitation.exists():
    old_public=old_invitation.read_bytes();assert len(old_public)in(256,320,672)and new_bundle[32:64]!=old_public[32:64],'fresh graphical device reused the backup identity'
   invoke(g,426,h=1,a=4,data=b'nope',expected=8);invoke(g,434,a=27,expected=3);invoke(g,434,a=23,expected=8)
   unlock(g,key,0);lock(g);unlock(g,key,1);assert invoke(g,422)[1][32:64]==new_bundle[32:64]
   invoke(g,429,h=1,expected=3);invoke(g,434,a=23,expected=8)
   record('supported older whole-backing history import and actual PgDn selection render eligible native history; retired roots deny same-copy normal recovery and old send/retry/prekey/export authority, while graphical F2 plus explicit new-domain create/recover retain only fresh device authority',source=str(source),inbox_serial=f[1],history_sha256=hashlib.sha256(text).hexdigest(),history_frame_before=unselected,history_frame_selected=selected,retired_copy_recovery_error=13,new_identity_sha256=hashlib.sha256(new_bundle[32:64]).hexdigest())
   g.stop()
  report.update(result='pass',elapsed_seconds=time.monotonic()-began,incomplete_acceptance=[]if a.history_backup else['actual older conversation backup import awaits central campaign baseline']);(out/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
 except BaseException as error:
  report.update(result='failed',error=repr(error),elapsed_seconds=time.monotonic()-began);(out/'failure.json').write_text(json.dumps(report,indent=2)+'\n');raise
 finally:
  for g in reversed(actors):
   with contextlib.suppress(Exception):g.stop()
if __name__=='__main__':main()
