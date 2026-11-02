"""Continue a live real Notes creator: successor, GUI update/rollback, recovery.

The prior run keeps the original guest publisher alive. All source edits and
consequential release/install actions use real native device controls.
"""
import argparse,contextlib,hashlib,json,os,signal,struct,sys,time,traceback
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import identity,live,native_publisher,projects,project_vault
from campaign010_project_notes import NotesJourney,choose_project,run_json,wait
from creator_journey import require,rendered_text
from graphical_devices import DeviceInput

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--session',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--main-source',type=Path);a=p.parse_args()
 prior=a.session.resolve();record=json.loads((prior/'execution.json').read_bytes());require(record['result']=='pass','complete useful Notes run required')
 session=record['session'];ready=json.loads((prior/'ready.json').read_bytes());out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
 args=SimpleNamespace(output=prior/'personal',image=Path(session['image']),backend=session['backend'],public=ROOT/'tests/keys/development-rsa-public.pem',key=ROOT/'tests/keys/development-rsa.pem',vault=prior/'objects.img',vault_key=prior/'objects.key')
 j=NotesJourney(args);j.ui=DeviceInput(session['backend'],Path(session['graphics']));began=time.monotonic();evidence=dict(schema=1,result='running',image_sha256=hashlib.sha256(args.image.read_bytes()).hexdigest(),checks=[])
 def save():evidence['elapsed_seconds']=round(time.monotonic()-began,3);(out/'execution.json').write_text(json.dumps(evidence,indent=2)+'\n')
 def passed(label,**fields):evidence['checks'].append(dict(check=label,result='pass',**fields));save();print('PASS',label,flush=True)
 def head():return next(r['head']for r in j.roots()if r['cap']==session['source_root'])
 try:
  if a.main_source:
   # Public expected-head source import is a normal developer action. It stages
   # bytes as untrusted Sources; native Build/Evidence and review still follow.
   with j.client()as c:old_head,files=projects.snapshot(c,session['source_root'])
   imported_source=out/'import-source';imported_source.mkdir()
   files['Main.lean']=a.main_source.read_bytes()
   for name,data in files.items():path=imported_source/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
   imported=run_json([sys.executable,ROOT/'lt','project','--socket',j.socket,'import',imported_source,'--name','notes-source','--root',session['source_root'],'--expected',old_head],out/'source-update.json')
   for pin in json.loads(files['lemma.lock.json'])['dependencies']:
    run_json([sys.executable,ROOT/'lt','sdk','attach-dependency',imported_source/'deps'/(pin['release_id']+'.json'),'--socket',j.socket,'--root',session['source_root']],out/('source-dependency-'+pin['release_id']+'.json'))
   passed('normal expected-head source import stages responsive application implementation',source_sha256=hashlib.sha256(files['Main.lean']).hexdigest(),previous_source=old_head)
  # The ordinary Desktop remains a separate live process from Notes.
  j.ui.chord(56,15);time.sleep(.3);j.open_named_project('notes-source')
  for _ in range(4):j.ui.press(61)
  before=head();j.ui.press(102);j.ui.chord(29,30);j.ui.textASCII('1\n2\n',delay=.04);j.ui.press(62)
  successor_source=wait(lambda:(h if(h:=head())!=before else None),'native successor resource commit',60)
  require(j.snapshot(session['source_root'])[1]['templates.txt']==b'1\n2\n','actual successor resource differs')
  j.ui.press(63)
  result=run_json([sys.executable,ROOT/'lt','project','--socket',j.socket,'build','--output',out/'builder'],out/'builder-command.json');require(result['status']=='ok'and result['source_root']==successor_source,'successor build did not use exact new source')
  require(result['artifact']['sha256']!=ready['release']['executable_sha256'],'semantic resource change did not change actual executable')
  with j.client()as c:
   proposal=native_publisher.prepare(c,root=session['source_root'],publisher=session['publisher'],name='project-notes',version='1.1.0',license='MIT',parent=ready['release']['release_id'],result_path=out/'builder/job.result.json',output=out/'review')
  j.ui.chord(56,88);time.sleep(.5);(out/'trusted-successor-review.ppm').write_bytes(j.ui.frame().ppm());j.ui.press(28)
  def signed():
   with j.client()as c:value=native_publisher.inspect(c)
   require(value['phase']!=4,'native successor signing failed '+repr(value));return value if value['phase']==3 else None
  wait(signed,'same guest publisher signs current-parent successor',300)
  with j.client()as c:
   info=native_publisher.export(c,out/'review',out/'project-notes-1.1.0.ltrel');published=native_publisher.publish_snapshot(c,out/'review');archive=projects.archive(c,published['root'],out/'project-notes-1.1.0-graph.json')
  passed('native same-publisher successor binds exact parent, monotonic version and changed semantic behavior',release=info,parent=ready['release']['release_id'],published=published,archive=archive,source=successor_source,artifact=result['artifact'])
  j.ui.press(1);time.sleep(.2);j.ui.key(56,False)
  with j.client()as c:staged=c.stage(out/'project-notes-1.1.0.ltrel')
  j.ui.press(88);time.sleep(.5);(out/'trusted-update-review.ppm').write_bytes(j.ui.frame().ppm());j.ui.press(28)
  def active_id():
   with j.client()as c:return c.request(29,bytes.fromhex(info['project_id']))[160:192].hex()
  wait(lambda:active_id()==info['release_id'],'native approved successor activation',90)
  j.wait_text(14,152,'Title / ',0xdce9ec,timeout=45)
  j.ui.textASCII('Successor note',delay=.035);j.ui.press(28);j.wait_text(14,152,'Annotation',0xdce9ec)
  j.wait_text(16,134,'Successor note',0xa6d7b1)
  rapid='SDK input remains responsive across rapid keystrokes.';j.ui.textASCII(rapid,delay=.035);j.wait_text(18,170,rapid,0xdce9ec)
  passed('GUI approves exact update and changed app consumes annotation default resource',release_id=info['release_id'],rights=info['rights'],capability_delta=0,frame=j.ui.frame().digest)
  # Native lifecycle B performs an explicit rollback to the eligible retained
  # release. Running app instances retain their own state and code identity.
  with j.client()as c:
   catalog=[]
   for i in range(16):
    try:raw=c.request(13,struct.pack('<Q',i))
    except ValueError:continue
    if len(raw)==512:catalog.append(raw)
  index=next(i for i,raw in enumerate(catalog)if raw[160:192].hex()==info['release_id'])
  j.ui.chord(56,67)
  def selected_row(i):
   frame=j.ui.frame();at=((72+i*11)*frame.width+4)*4
   return frame.bgrx[at:at+3]==bytes.fromhex('6a5435')
  wait(lambda:selected_row(0),'native lifecycle initial selection',45)
  for i in range(index):
   j.ui.press(108,.08);wait(lambda:selected_row(i+1),'native lifecycle selected release row',45)
  (out/'native-rollback-review.ppm').write_bytes(j.ui.frame().ppm());j.ui.press(48)
  wait(lambda:active_id()==ready['release']['release_id'],'explicit GUI rollback',90);j.ui.press(1);time.sleep(.2);j.ui.key(56,False)
  passed('explicit native lifecycle rollback selects eligible original release',from_release=info['release_id'],to_release=ready['release']['release_id'])
  damaged=bytearray((out/'project-notes-1.1.0.ltrel').read_bytes());damaged[-1]^=1;tampered=out/'tampered.ltrel';tampered.write_bytes(damaged)
  with j.client()as c:
   try:c.stage(tampered)
   except ValueError as error:tamper_error=str(error)
   else:raise AssertionError('tampered application staged')
   revoked=struct.unpack_from('<Q',c.request(30,bytes.fromhex(info['release_id'])),8)[0]
   try:c.request(25,struct.pack('<Q',revoked))
   except ValueError as error:revoked_error=str(error)
   else:raise AssertionError('currently known revoked application executed')
   c.stage(out/'project-notes-1.1.0.ltrel');c.request(23,bytes.fromhex(info['release_id'])+struct.pack('<Q',info['rights']))
   try:c.request(24)
   except ValueError as error:reinstall_error=str(error)
   else:raise AssertionError('known revoked release reinstalled through a fresh catalog slot')
  passed('tampered and currently known revoked release execution/reinstallation refused',tampered=tamper_error,revoked=revoked_error,reinstall=reinstall_error,revoked_release=info['release_id'])
  with j.client()as c:
   selected_note=next(r for r in projects.roots(c)if r['name']=='project-notes');_,note_files=projects.snapshot(c,selected_note['cap']);require(len(note_files)==1,'selected retention included another note')
   note=next(iter(note_files.values()));require(len(note)==4096 and b'Release plan' in note and 'café'.encode()in note,'retained note did not preserve actual useful UTF-8 revision')
   credential=os.urandom(32);credential_path=out/'publisher-recovery.key';credential_path.write_bytes(credential);credential_path.chmod(0o600)
   retained=native_publisher.retain(c,session['source_root'],session['publisher'],credential,include_roots=(selected_note['cap'],ready['published']['root'],published['root']))
  passed('explicit typed publisher, selected project and one selected note retained through Objects domain3',retained=retained,retained_note_members=list(note_files),unselected_notes_restored=False)
  old_key=session['publisher'];old_root=session['source_root'];live_session=json.loads((prior/'live-session.json').read_bytes());j.ui.close();j.ui=None;os.killpg(live_session['pid'],signal.SIGKILL);time.sleep(.2);j.boot()
  j.trust_stage(ROOT/'build/campaign010-native-bootstrap-current/native-editor.ltrel','native-editor');j.ui.press(1)
  with j.client()as c:
   identity.start(c,ROOT/'build/campaign010-native-bootstrap-current/identity.ltrel',args.public);project_vault.unlock(c,args.vault_key.read_bytes());require(not projects.roots(c),'old project handles revived before explicit recovery');inventory=project_vault.inventory(c);recovered=project_vault.recover(c)
   authority=next(r for r in recovered['roots']if r['name'].startswith('publisher-'));fresh=native_publisher.recover(c,authority['cap'],credential)
   require(fresh['key']!=old_key and not fresh['signing_authorized'],'recovery revived old signing authority')
   try:identity.invoke(c,401,h=old_key)
   except ValueError:pass
   else:raise AssertionError('old publisher handle survived restart')
   try:c.objects(29,old_root)
   except ValueError:pass
   else:raise AssertionError('old root handle survived restart')
   require(not any(r['name']=='Review annotation'for r in recovered['roots']),'unselected private note recovered')
  passed('restart recovery issues fresh roots and publisher binding with inspection-only authority',recovered=recovered,publisher=fresh,old_handles_rejected=True,external_freshness_claim=False)
  with j.client()as c:
   c.request(10,bytes.fromhex(ready['release']['project_id'])+(prior/'project-notes.pub').read_bytes());c.stage(prior/'project-notes.ltrel')
   restored=next(r for r in recovered['roots']if r['name']==ready['published']['name'])
   fresh_release=projects.resolve(c,restored['cap'],ready['release']['release_node'])
   material=c.request(15,struct.pack('<Q',fresh_release));require(len(material)==64 and struct.unpack_from('<Q',material,8)[0]==1,'fresh recovered release material differs')
  j.ui.press(88);time.sleep(.5);j.ui.press(28);j.wait_text(14,152,'Title / ',0xdce9ec,timeout=45);j.ui.press(62)
  # F4 is the ordinary Notes import action and opens the trusted root picker.
  def picker():
   frame=j.ui.frame();rows=[rendered_text(frame,32,107+i*12,14).rstrip()for i in range(16)]
   return rows if 'project-notes'in rows else None
  rows=wait(picker,'recovered selected note root picker',45)
  for _ in range(rows.index('project-notes')):j.ui.press(108,.08)
  j.ui.press(28);j.wait_text(16,134,'Release plan',0xa6d7b1)
  require(rendered_text(j.ui.frame(),168,134,13,0xdce9ec).strip()!='Project guide','unselected note restored through app import')
  j.ui.chord(29,33);j.ui.textASCII('caf',delay=.04);j.ui.chord(29,22);j.ui.textASCII('00e9',delay=.04);j.ui.press(28);j.ui.press(28);j.ui.press(1);j.wait_text(16,134,'Release plan',0xa6d7b1)
  passed('ordinary app imports recovered selected note and searches preserved UTF-8',frame=j.ui.frame().digest,title='Release plan',query='café',unselected_private_state=False)
  evidence.update(result='pass',session=dict(socket=str(j.socket),graphics=str(j.graphics),pid=j.proc.pid,publisher=fresh,recovered=recovered,image=str(args.image),backend=args.backend));save()
 except BaseException as error:
  with contextlib.suppress(Exception):(out/'failure.ppm').write_bytes(j.ui.frame().ppm())
  evidence.update(result='failure',error=repr(error),traceback=traceback.format_exc());save();raise
 finally:
  if j.ui:j.ui.close()
 return 0
if __name__=='__main__':raise SystemExit(main())
