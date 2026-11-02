"""Actual native workbench → public SDK → guest release → useful Notes journey.

All edits and approvals use native device input. The host transports selected
source and compiler results, never creates a publisher signature or guest state.
"""
import argparse,contextlib,hashlib,json,os,signal,struct,subprocess,sys,time,traceback
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import build_jobs,identity,live,native_publisher,projects,project_vault,releases,sdk
from creator_journey import Journey,require,rendered_text
from graphical_devices import DeviceInput

class NotesJourney(Journey):
 def boot(self,vault=True):
  self.socket.unlink(missing_ok=True);self.graphics.unlink(missing_ok=True)
  self.log=(self.out/'transport.log').open('wb');backend=self.args.backend
  command=[sys.executable,ROOT/'lt','run','--image',self.image_path,'--backend',backend,'--socket',self.socket,'--graphics',self.graphics]
  if getattr(self.args,'network_mux',False):command+=['--network-mux']
  if vault:command+=['--vault',self.args.vault]
  self.proc=subprocess.Popen(list(map(str,command)),cwd=ROOT,stdout=self.log,stderr=self.log,start_new_session=True)
  deadline=time.monotonic()+90
  while not self.socket.exists():
   require(self.proc.poll()is None,'native guest exited at boot')
   if time.monotonic()>deadline:raise TimeoutError('native graphical boot')
   time.sleep(.05)
  self.ui=DeviceInput(backend,self.graphics);time.sleep(.5)

def wait(fn,label,seconds=180):
 deadline=time.monotonic()+seconds
 while time.monotonic()<deadline:
  value=fn()
  if value:return value
  time.sleep(.15)
 raise TimeoutError(label)

def run_json(command,output):
 with Path(output).open('w')as stream:
  completed=subprocess.run(list(map(str,command)),cwd=ROOT,stdout=stream,stderr=subprocess.PIPE,text=True)
 if completed.returncode:raise RuntimeError('command failed '+repr(command)+': '+completed.stderr[-4096:]+'; output '+str(output))
 return json.loads(Path(output).read_bytes())

def choose_project(j,name):
 old=j.ui.frame().digest;j.ui.press(61);j.ui.wait_frame(old);time.sleep(.4)
 def ready():
  frame=j.ui.frame();rows=[rendered_text(frame,32,107+i*12,len(name)+1).rstrip()for i in range(16)]
  return rows if name in rows else None
 rows=wait(ready,'native selected-project picker '+name,30)
 for _ in range(rows.index(name)):j.ui.press(108,.08)
 j.ui.press(28);time.sleep(.5)

def exercise_notes(j,out,first_open=False,start=0,typing_delay=.035):
 fg=0xdce9ec;accent=0xa6d7b1
 if not first_open and start==0:j.wait_text(14,152,'Title / ',fg,timeout=45)
 notes=[('Release plan','Project Notes 1.0 release draft\nShip SDK and signed source\nReview caf'),('Project guide','Document the creator workflow\nBuild frozen source and inspect evidence'),('Launch checklist','Check dependency pin and federation policy\nApprove exact permissions'),('Review annotation','Search should find SDK in the release plan\nKeep this scratch note ephemeral')]
 for index,(title,body)in enumerate(notes):
  if index<start:continue
  if index:j.ui.press(60)
  if index:j.wait_text(14,152,'Title / ',fg,timeout=45)
  if index or not first_open:j.ui.textASCII(title,delay=typing_delay);j.ui.press(28)
  j.wait_text(14,152,'Release draft',fg,timeout=30)
  j.ui.textASCII(body,delay=typing_delay)
  if index==0:
   j.ui.chord(29,22);j.ui.textASCII('00e9',delay=.04);j.ui.press(28);choose_project(j,'notes-source')
  j.ui.chord(29,31);j.wait_text(14,354,'Saved immutable revision',fg,timeout=45)
  frame=j.wait_text(16+index*152,134,title,accent,timeout=30)
  require(rendered_text(frame,320,370,4,accent)=='0001','first immutable note revision did not render1')
  (out/('note-'+str(index+1)+'.ppm')).write_bytes(frame.ppm())
 # Search title/body from a distinct selected note, with actual case folding.
 j.ui.chord(29,33);j.ui.textASCII('sDk',delay=.04);j.ui.press(28);j.ui.press(1);time.sleep(.4)
 frame=j.wait_text(16,134,'Release plan',accent)
 require(rendered_text(frame,18,170,13,fg)=='Project Notes','search did not select matching note body')
 # Revisions are actual immutable objects. F8 is read-only; escape restores2.
 j.ui.textASCII('\nReady for review',delay=typing_delay);j.ui.chord(29,31);j.wait_text(14,354,'Saved immutable revision',fg,timeout=45)
 j.wait_text(320,370,'0002',accent)
 j.ui.press(66);j.wait_text(320,370,'0001',accent)
 j.ui.press(1);j.wait_text(320,370,'0002',accent)
 # UTF-8 search insertion exercises actual preserved bytes, not only a glyph.
 j.ui.chord(29,33);j.ui.textASCII('caf',delay=.04);j.ui.chord(29,22);j.ui.textASCII('00e9',delay=.04);j.ui.press(28);j.ui.press(28);j.ui.press(1)
 time.sleep(.4);frame=j.wait_text(16,134,'Release plan',accent);(out/'notes-search-revision.ppm').write_bytes(frame.ppm())
 return dict(titles=[x[0]for x in notes],utf8='café',revision=2,search='sDk and café',frame=frame.digest)

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,required=True);p.add_argument('--editor',type=Path,required=True);p.add_argument('--identity',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--project',type=Path,default=ROOT/'examples/project-notes');p.add_argument('--backend',choices=('qemu','x86_64','aarch64'),default='qemu');p.add_argument('--keep',action='store_true');a=p.parse_args()
 out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);pub=ROOT/'tests/keys/development-rsa-public.pem';key=ROOT/'tests/keys/development-rsa.pem';vault=out/'objects.img';vault_key=out/'objects.key'
 backing=subprocess.run(list(map(str,[sys.executable,ROOT/'lt','vault-init',vault,'--sectors','24576','--key-out',vault_key])),cwd=ROOT,capture_output=True,text=True,check=True)
 (out/'vault-init.json').write_text(json.dumps(dict(schema=1,result='created',bytes=vault.stat().st_size,output=backing.stdout.strip()),indent=2)+'\n')
 j=NotesJourney(SimpleNamespace(output=out/'personal',image=a.image,backend=a.backend,public=pub,key=key,vault=vault,vault_key=vault_key));worker=None;worker_log=None;started=time.monotonic();record=dict(schema=1,result='running',image_sha256=hashlib.sha256(a.image.read_bytes()).hexdigest(),backend=a.backend,checks=[])
 def save():record['elapsed_seconds']=round(time.monotonic()-started,3);(out/'execution.json').write_text(json.dumps(record,indent=2)+'\n')
 def passed(label,**values):record['checks'].append(dict(check=label,result='pass',**values));save();print('PASS',label,flush=True)
 def stop_worker():
  nonlocal worker,worker_log
  if worker and worker.poll()is None:
   os.killpg(worker.pid,signal.SIGINT)
   try:worker.wait(timeout=10)
   except subprocess.TimeoutExpired:os.killpg(worker.pid,signal.SIGKILL);worker.wait()
  if worker_log:worker_log.close()
  worker=None;worker_log=None
 try:
  preflight=sdk.check(sdk.read_project(a.project));passed('public source/dependency preflight',sdk=preflight['sdk'],dependency_lock=preflight['dependency_lock_id'],dependencies=preflight['dependencies'])
  j.boot();j.trust_stage(a.editor,'native-editor');j.ui.press(1)
  def editor_actor():
   with j.client()as c:actors=identity.instances(c)
   return next((row[0] for row in actors if row[2]==895 and row[1]in(1,2,3,4)),None)
  editor_instance=wait(editor_actor,'installed native editor requester')
  with j.client()as c:signer=identity.start(c,a.identity,pub);project_vault.unlock(c,vault_key.read_bytes())
  imported=run_json([sys.executable,ROOT/'lt','project','--socket',j.socket,'import',a.project,'--name','notes-source'],out/'source-import.json');root=imported['root']
  # Signed library enters normal native graph admission, then an exact kind13
  # edge is added to the authorized app source head before any editor freeze.
  lock=json.loads((a.project/'lemma.lock.json').read_bytes())
  for pin in lock['dependencies']:
   carrier=a.project/'deps'/(pin['release_id']+'.json')
   attached=run_json([sys.executable,ROOT/'lt','sdk','attach-dependency',carrier,'--socket',j.socket,'--root',root],out/('dependency-'+pin['release_id']+'.json'));imported['head']=attached['head']
   passed('native signed source dependency graph admission and exact source edge',**attached)
  j.open_named_project('notes-source');time.sleep(.3)
  # A genuine UInt64/Bool type error after imports, entered through native keys.
  bad_line='def campaignTypeError : UInt64 := true\n';j.ui.press(102)
  for _ in range(7):j.ui.press(108)
  j.ui.textASCII(bad_line,delay=.035);j.ui.press(62);time.sleep(.3)
  def current_head():return next(r['head']for r in j.roots()if r['cap']==root)
  error_head=wait(lambda:(h if(h:=current_head())!=imported['head']else None),'native workbench immutable commit',45)
  worker_log=(out/'compiler-worker.log').open('wb');worker=subprocess.Popen(list(map(str,[sys.executable,ROOT/'lt','project','--socket',j.socket,'serve','--project','project-notes','--root',root,'--requester',editor_instance,'--output',out/'worker'])),cwd=ROOT,stdout=worker_log,stderr=worker_log,start_new_session=True)
  j.ui.press(63)
  def diagnostic():
   for path in sorted((out/'worker').glob('session-*/job-*/job.result.json')):
    value=json.loads(path.read_bytes())
    if value.get('delivered')and value.get('status')=='error':return path,value
  bad_path,bad=wait(diagnostic,'actual located type error from key-free serve',300);require(any(d['path']=='Main.lean'and d['line']==8 for d in bad['diagnostics']),'type error location missing');stop_worker()
  j.ui.press(64);time.sleep(.3);(out/'native-located-type-error.ppm').write_bytes(j.ui.frame().ppm());passed('native source edit and located genuine type error through key-free compiler worker',source=error_head,diagnostics=bad['diagnostics'],result_path=str(bad_path))
  # Correct source and edit the semantic resource as actual native text input.
  j.ui.press(102)
  for _ in range(7):j.ui.press(108)
  for _ in bad_line:j.ui.press(111,.015)
  for _ in range(4):j.ui.press(61)
  j.ui.press(102);j.ui.chord(29,30);j.ui.textASCII('1\n1\n',delay=.04);j.ui.press(62);time.sleep(.35)
  wait(lambda:current_head()!=error_head,'native correction/resource immutable commit',45)
  ready_head,ready_files=j.snapshot(root);require(ready_files['templates.txt']==b'1\n1\n'and b'campaignTypeError'not in ready_files['Main.lean'],'native correction/resource edit differs')
  j.ui.press(63);time.sleep(.25)
  # Public one-shot build exposes a legitimate deferred completion, allowing
  # exact-source ownership checks while the native editor advances normally.
  build_log=(out/'builder-command.json').open('w');builder=subprocess.Popen(list(map(str,[sys.executable,ROOT/'lt','project','--socket',j.socket,'build','--defer-result','--output',out/'builder'])),cwd=ROOT,stdout=build_log,stderr=subprocess.PIPE,text=True)
  j.ui.press(61);j.ui.press(102);j.ui.textASCII('-- Unbuilt local follow-up remains separate\n',delay=.035);j.ui.press(62);time.sleep(.3);newer_head=wait(lambda:(h if(h:=current_head())!=ready_head else None),'interleaved native immutable commit',45)
  _,builder_error=builder.communicate(timeout=180);build_log.close();require(builder.returncode==0,'real frozen build failed '+builder_error)
  result=json.loads((out/'builder/job.result.json').read_bytes());require(result['status']=='ok',result['diagnostic_text']);require(result['source_root']==ready_head,'build silently used newer editable source')
  with j.client()as c:
   wrong=dict(result,source_root=newer_head)
   try:projects.complete_build(c,wrong)
   except ValueError:pass
   else:raise AssertionError('mismatched frozen source result attached')
  # Complete is a plain public CLI whose output is the exact source identity.
  done=subprocess.run(list(map(str,[sys.executable,ROOT/'lt','project','--socket',j.socket,'complete',out/'builder/job.result.json'])),cwd=ROOT,capture_output=True,text=True,check=True);require(done.stdout.strip()==ready_head,'completion returned wrong source')
  require(j.snapshot(root)[0]==newer_head,'frozen completion overwrote interleaved source')
  result=json.loads((out/'builder/job.result.json').read_bytes());passed('native correction and semantic resource build exact snapshot A while B remains editable',source=ready_head,newer_source=newer_head,artifact=result['artifact'],stale_result_refused=True,result_path=str(out/'builder/job.result.json'))
  # A separately invoked verifier receives the same exported immutable files,
  # SDK, dependency carrier, recipe and toolchain. It owns no signing key.
  with j.client()as c:
   exact,files=projects.snapshot(c,result['guest_session']['source_root_capability'],ready_head)
  verifier_source=out/'verifier-source';verifier_source.mkdir()
  for name,data in files.items():path=verifier_source/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
  verified=run_json([sys.executable,ROOT/'lt','sdk','build',verifier_source,'--output',out/'verifier'],out/'verifier-command.json');require(verified['status']=='ok'and verified['artifact']['sha256']==result['artifact']['sha256'],'verifier actual artifacts differ');require(verified['snapshot_digest']==result['snapshot_digest'],'verifier frozen source members differ')
  passed('separately configured local verifier reproduces actual artifact bytes from exact lock/closure',artifact=verified['artifact'],snapshot_digest=verified['snapshot_digest'],independent_administration=False)
  with j.client()as c:
   logical=projects.project_identity(c,root);fields,public=identity.invoke(c,400,a=1,data=hashlib.sha256(b'LT-PROJECT-PUBLISHER\0').digest()+bytes.fromhex(logical));publisher=fields[1];decoded=identity.decode_public(public)
   proposal=native_publisher.prepare(c,root=root,publisher=publisher,name='project-notes',version='1.0.0',license='MIT',result_path=out/'builder/job.result.json',output=out/'review')
  j.ui.chord(56,88);time.sleep(.6);(out/'trusted-release-review.ppm').write_bytes(j.ui.frame().ppm());j.ui.press(28)
  def signed():
   with j.client()as c:state=native_publisher.inspect(c)
   if state['phase']==4:raise AssertionError('native signing failed '+repr(state))
   return state if state['phase']==3 else None
  wait(signed,'guest-owned Project Notes release signature',300)
  with j.client()as c:
   info=native_publisher.export(c,out/'review',out/'project-notes.ltrel');published=native_publisher.publish_snapshot(c,out/'review');archive=projects.archive(c,published['root'],out/'project-notes-graph.json')
  (out/'project-notes.pub').write_bytes(bytes.fromhex(decoded['public_key']));require(j.snapshot(root)[0]==newer_head,'publishing A overwrote newer local B')
  passed('trusted native publisher signs and publishes exact application release with actual helper closure',release=info,publisher=decoded,published=published,archive=archive,host_private_key=False,newer_source_preserved=True)
  (out/'ready.json').write_text(json.dumps(dict(schema=1,envelope=str(out/'project-notes.ltrel'),public_key=str(out/'project-notes.pub'),release=info,published=published,archive=archive,socket=str(j.socket),session_only=True),indent=2)+'\n')
  j.ui.press(1);time.sleep(.25)
  with j.client()as c:c.request(10,bytes.fromhex(info['project_id'])+bytes.fromhex(decoded['public_key']));staged=c.stage(out/'project-notes.ltrel')
  j.ui.press(88);time.sleep(.5);j.ui.press(28);time.sleep(1)
  with j.client()as c:
   active=c.request(29,bytes.fromhex(info['project_id']));require(active[160:192].hex()==info['release_id'],'Launcher activated wrong release');actors=identity.instances(c);running=[r[0]for r in actors if r[2]==895 and r[0]!=editor_instance and r[1]in(1,2,3,4)];require(running,'Project Notes did not run')
  exercised=exercise_notes(j,out);passed('installed ordinary Notes creates four useful notes, UTF-8 text, search and immutable revisions',instance=running[-1],**exercised)
  # Explicitly retain the selected note only through trusted native review.
  with j.client()as c:before=project_vault.inventory(c)
  j.ui.press(67);j.wait_text(16,40,'project-notes');(out/'trusted-note-retention.ppm').write_bytes(j.ui.frame().ppm());j.ui.press(28)
  def retained():
   with j.client()as c:saved=project_vault.inventory(c)
   return saved if saved['generation']>before['generation']and any(r['name']=='project-notes'for r in saved['projects'])else None
  saved=wait(retained,'selected note retention',180);passed('trusted selected note retention excludes unrelated scratch notes',inventory=saved)
  record['session']=dict(socket=str(j.socket),graphics=str(j.graphics),backend=a.backend,image=str(a.image.resolve()),source_root=root,source_head=newer_head,published=published,identity_service=signer,publisher=publisher,app_instance=running[-1],editor_instance=editor_instance,session_only=True)
  record['result']='pass';save()
 except BaseException as error:
  with contextlib.suppress(Exception):(out/'failure.ppm').write_bytes(j.ui.frame().ppm())
  with contextlib.suppress(Exception):(out/'failure-roots.json').write_text(json.dumps(j.roots(),indent=2)+'\n')
  record.update(result='failure',error=repr(error),traceback=traceback.format_exc());save();raise
 finally:
  stop_worker()
  if not a.keep:j.stop(hard=True)
  elif j.proc and j.proc.poll()is None:
   (out/'live-session.json').write_text(json.dumps(dict(socket=str(j.socket),graphics=str(j.graphics),pid=j.proc.pid,backend=a.backend,image=str(a.image.resolve()),result=record['result']),indent=2)+'\n')
 return 0
if __name__=='__main__':raise SystemExit(main())
