"""Continue the actual Forge-fetched second user with a native Notes fork.

The upstream graph must already have traversed the native distribution journey.
Native input forks it, changes real search behavior and a semantic resource,
then builds, reviews, signs, publishes, installs and uses the distinct artifact.
"""
import argparse,contextlib,hashlib,json,struct,subprocess,sys,time,traceback
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import identity,live,native_publisher,projects,sdk
from campaign010_project_notes import NotesJourney,run_json,wait
from creator_journey import require,rendered_text
from graphical_devices import DeviceInput

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--reader',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
 p.add_argument('--editor',type=Path,required=True);p.add_argument('--identity',type=Path,required=True)
 p.add_argument('--capability-boundary',action='store_true',help='sign a real successor requesting Network and refuse reuse of the old895 approval')
 a=p.parse_args();reader=json.loads(a.reader.read_bytes());out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
 args=SimpleNamespace(output=Path(reader['socket']).parent,image=Path(reader['image']),backend=reader['backend'],public=ROOT/'tests/keys/development-rsa-public.pem',key=ROOT/'tests/keys/development-rsa.pem')
 j=NotesJourney(args);j.socket=Path(reader['socket']);j.graphics=Path(reader['graphics']);j.ui=DeviceInput(reader['backend'],j.graphics)
 evidence=dict(schema=1,result='running',reader_record=str(a.reader.resolve()),image_sha256=hashlib.sha256(args.image.read_bytes()).hexdigest(),checks=[]);began=time.monotonic()
 def save():
  evidence['elapsed_seconds']=round(time.monotonic()-began,3)
  (out/'execution.json').write_text(json.dumps(evidence,indent=2)+'\n')
 def passed(label,**fields):
  evidence['checks'].append(dict(check=label,result='pass',**fields));save();print('PASS',label,flush=True)
 def roots():
  with j.client()as c:return projects.roots(c)
 try:
  upstream=reader['root']
  with j.client()as c:
   original_head,original_files=projects.snapshot(c,upstream['cap'])
   original_logical=projects.project_identity(c,upstream['cap'])
   require(original_head==upstream['head'],'fetched source head changed before fork')
   require(b'def foldSearch : UInt64 := 1' in original_files['Main.lean'],'unexpected upstream search behavior')
   service=identity.start(c,a.identity,args.public)
   fields,descriptor=identity.invoke(c,400,a=1,data=hashlib.sha256(b'LT-PROJECT-PUBLISHER\0').digest()+bytes.fromhex(original_logical))
   publisher=fields[1];public=identity.decode_public(descriptor);publisher_id=hashlib.sha256(bytes.fromhex(public['public_key'])).hexdigest()
  # The ordinary signed editor is a separate application, selected by native
  # installation/execution review, never injected into the fetched app.
  j.trust_stage(a.editor,'native-editor');j.ui.press(1)
  j.open_named_project(upstream['name'])
  j.ui.chord(29,33)
  j.wait_text(8,370,'Fork name',0xe9bc75,timeout=45)
  j.ui.textASCII('notes-fork',delay=.06);j.ui.press(28)
  j.wait_text(8,370,'New publisher public key ID',0xe9bc75,timeout=45)
  j.ui.textASCII(publisher_id,delay=.04);j.ui.press(28)
  fork=wait(lambda:next((r for r in roots()if r['name']=='notes-fork'),None),'actual native fork root',90)
  with j.client()as c:
   fork_logical=projects.project_identity(c,fork['cap']);origin=native_publisher.fork_origin(c,fork['cap'],fork['head'])
   require(fork_logical!=original_logical,'fork reused upstream logical identity')
   require(origin['logical_project_id']==original_logical and origin['release_id']==reader['release_id'] and origin['publisher_key_id']==publisher_id,'native fork lineage differs from selected upstream/new publisher')
   require(projects.snapshot(c,upstream['cap'])[0]==original_head,'fork mutated upstream')
  passed('native Ctrl+F forks actual network-fetched project under separately generated guest publisher',upstream=upstream,upstream_logical=original_logical,fork=fork,logical_project_id=fork_logical,publisher=public,publisher_key_id=publisher_id,lineage=origin)
  # Older published wrappers may expose the helper only through the primary
  # Release's signed Source edge. Resolve exact fetched carriers through the
  # ordinary SDK importer before freezing this fresh fork's source closure.
  resolved=[]
  with j.client()as c:
   current,_=projects.snapshot(c,fork['cap']);entries=projects.decode_manifest(c.read_object(projects.resolve(c,fork['cap'],current)))
   for pin in json.loads(original_files['lemma.lock.json'])['dependencies']:
    if any(n=='deps/'+pin['release_id']+'.rel'and k==13 for n,k,_ in entries):continue
    resolved.append(sdk.attach_dependency(c,fork['cap'],json.loads(original_files['deps/'+pin['release_id']+'.json'])))
   fork['head']=projects.snapshot(c,fork['cap'])[0]
  if resolved:
   j.open_named_project('notes-fork')
   passed('public SDK resolves missing fork dependency edges from the exact fetched signed source carrier',dependencies=resolved,private_fixture=False)
  # Home is the native file start. Down preserves column0, then Right reaches
  # the actual foldSearch value. All source bytes are changed by device input.
  j.ui.press(102)
  for _ in range(20):j.ui.press(108,.08)
  for _ in 'def foldSearch : UInt64 := ':j.ui.press(106,.04)
  j.ui.press(111,.08);j.ui.textASCII('0',delay=.08);j.ui.press(62)
  changed=wait(lambda:next((r['head']for r in roots()if r['cap']==fork['cap']and r['head']!=fork['head']),None),'native search behavior commit',90)
  with j.client()as c:_,files=projects.snapshot(c,fork['cap'])
  require(files['Main.lean']==original_files['Main.lean'].replace(b'def foldSearch : UInt64 := 1',b'def foldSearch : UInt64 := 0',1),'physical source edit changed unexpected bytes')
  # Canonical file order is Main, carrier, lock, project declaration, resource.
  for _ in range(4):j.ui.press(61,.08)
  j.ui.press(102);j.ui.chord(29,30);j.ui.textASCII('1\n2\n',delay=.06);j.ui.press(62)
  frozen=wait(lambda:next((r['head']for r in roots()if r['cap']==fork['cap']and r['head']!=changed),None),'native semantic resource commit',90)
  with j.client()as c:
   _,files=projects.snapshot(c,fork['cap']);require(files['templates.txt']==b'1\n2\n','semantic resource change missing')
   require(projects.snapshot(c,upstream['cap'])[0]==original_head,'editing fork changed upstream')
  j.ui.press(63);j.wait_text(8,370,'BUILD QUEUED',0xe9bc75,timeout=60)
  result=run_json([sys.executable,ROOT/'lt','project','--socket',j.socket,'build','--output',out/'builder'],out/'builder-command.json')
  require(result['status']=='ok'and result['source_root']==frozen,'fork build did not use exact selected source')
  with j.client()as c:prepared=native_publisher.prepare(c,root=fork['cap'],publisher=publisher,name='project-notes',version='1.0.1',license='MIT',result_path=out/'builder/job.result.json',output=out/'review')
  j.ui.chord(56,88);time.sleep(.5);(out/'trusted-fork-release-review.ppm').write_bytes(j.ui.frame().ppm());j.ui.press(28)
  def signed():
   with j.client()as c:value=native_publisher.inspect(c)
   require(value['phase']!=4,'native fork signing failed '+repr(value))
   return value if value['phase']==3 else None
  state=wait(signed,'fresh guest publisher signs native fork',300)
  with j.client()as c:
   release=native_publisher.export(c,out/'review',out/'project-notes-fork.ltrel');published=native_publisher.publish_snapshot(c,out/'review');archive=projects.archive(c,published['root'],out/'project-notes-fork-graph.json')
   require(release['release_id']!=reader['release_id']and release['logical_project_id']==fork_logical and release['publisher_key_id']==publisher_id,'signed fork identity did not change')
   manifest=json.loads((out/'review/manifest.json').read_bytes());require(manifest['fork_origin']==origin,'signed manifest lost exact actual fork lineage')
   require(any(n.startswith('deps/')and k==13 for n,k,_ in projects.decode_manifest(c.read_object(projects.resolve(c,published['root'],published['head'])))),'fork publication lost helper release graph')
  passed('native source and semantic changes build, sign and republish distinct working fork with preserved helper and lineage',source=frozen,artifact=result['artifact'],release=release,published=published,archive=archive,host_publisher_key=False)
  j.ui.press(1);j.ui.key(56,False)
  selected_public=out/'project-notes-fork.pub';selected_public.write_bytes(bytes.fromhex(public['public_key']))
  trusted=subprocess.run(list(map(str,[sys.executable,ROOT/'lt','ctl','--socket',j.socket,'trust','--publication-id',release['project_id'],'--public',selected_public])),cwd=ROOT,capture_output=True,text=True,check=True)
  (out/'publisher-trust-command.json').write_text(json.dumps(dict(command='lt ctl trust --publication-id exact --public selected',publication_id=release['project_id'],publisher_key_id=publisher_id,response=trusted.stdout.strip(),execution_approved=False),indent=2)+'\n')
  with j.client()as c:
   c.stage(out/'project-notes-fork.ltrel');c.request(15,struct.pack('<Q',release['release_handle']))
  j.ui.press(88);time.sleep(.5);j.ui.press(28)
  j.wait_text(14,152,'Title / ',0xdce9ec,timeout=60)
  j.ui.textASCII('Fork guide',delay=.30);j.ui.press(28);j.wait_text(14,152,'Annotation',0xdce9ec)
  j.ui.textASCII('SDK exact search',delay=.30);j.ui.chord(29,31);j.wait_text(14,354,'Saved immutable revision',0xdce9ec,timeout=60)
  j.ui.press(60);j.wait_text(14,152,'Title / ',0xdce9ec);j.ui.textASCII('Local scratch',delay=.30);j.ui.press(28);j.ui.textASCII('Another project note',delay=.30)
  j.ui.chord(29,33);j.ui.textASCII('sdk',delay=.30);j.ui.press(28);j.wait_text(14,354,'No matching note',0xdce9ec)
  require(rendered_text(j.ui.frame(),168,134,13,0xa6d7b1)=='Local scratch','failed case-sensitive search selected another note')
  (out/'fork-case-sensitive-refusal.ppm').write_bytes(j.ui.frame().ppm())
  j.ui.press(1);j.ui.chord(29,33);j.ui.textASCII('SDK',delay=.30);j.ui.press(28)
  j.wait_text(16,134,'Fork guide',0xa6d7b1);j.ui.press(1);j.wait_text(18,170,'SDK exact search',0xdce9ec)
  (out/'fork-changed-behavior.ppm').write_bytes(j.ui.frame().ppm())
  passed('distinct installed native fork runs changed case-sensitive search and Annotation semantic default',release_id=release['release_id'],negative_query='sdk',positive_query='SDK',selected_note='Fork guide',semantic_category='Annotation',typing_seconds_per_key=.30,frame=j.ui.frame().digest)
  if a.capability_boundary:
   # The live new fork publisher may create a real successor, but its prior
   # execution approval cannot authorize added Network authority.
   for _ in range(8):
    if rendered_text(j.ui.frame(),8,51,6,0xd8e6ed)=='EDITOR':break
    j.ui.chord(56,15);time.sleep(.4)
   require(rendered_text(j.ui.frame(),8,51,6,0xd8e6ed)=='EDITOR','ordinary focus cycling did not select native editor')
   j.open_named_project('notes-fork')
   for _ in range(3):j.ui.press(61,.08)
   j.ui.press(102)
   project_lines=files['lemma.project.json'].decode().splitlines()
   rights_line=next(i for i,line in enumerate(project_lines)if '"rights"'in line)
   for _ in range(rights_line):j.ui.press(108,.08)
   prefix=project_lines[rights_line].split('895',1)[0]
   for _ in prefix:j.ui.press(106,.05)
   for _ in range(3):j.ui.press(111,.08)
   j.ui.textASCII('1919',delay=.08);j.ui.press(62)
   escalated_source=wait(lambda:next((r['head']for r in roots()if r['cap']==fork['cap']and r['head']!=frozen),None),'native changed permission declaration',90)
   with j.client()as c:
    _,changed_files=projects.snapshot(c,fork['cap']);require(json.loads(changed_files['lemma.project.json'])['rights']==1919,'native permission edit differs')
   j.ui.press(63);j.wait_text(8,370,'BUILD QUEUED',0xe9bc75,timeout=60)
   changed_build=run_json([sys.executable,ROOT/'lt','project','--socket',j.socket,'build','--output',out/'capability-builder'],out/'capability-builder-command.json')
   require(changed_build['status']=='ok'and changed_build['source_root']==escalated_source,'permission successor did not use exact source')
   with j.client()as c:native_publisher.prepare(c,root=fork['cap'],publisher=publisher,name='project-notes',version='1.0.2',license='MIT',parent=release['release_id'],result_path=out/'capability-builder/job.result.json',output=out/'capability-review')
   j.ui.chord(56,88);time.sleep(.5);(out/'trusted-capability-release-review.ppm').write_bytes(j.ui.frame().ppm());j.ui.press(28)
   wait(signed,'same live guest publisher signs permission successor',300)
   with j.client()as c:changed_release=native_publisher.export(c,out/'capability-review',out/'project-notes-capability-successor.ltrel')
   j.ui.press(1);j.ui.key(56,False)
   with j.client()as c:
    c.stage(out/'project-notes-capability-successor.ltrel');c.request(15,struct.pack('<Q',changed_release['release_handle']))
    try:c.request(23,bytes.fromhex(changed_release['release_id'])+struct.pack('<Q',895))
    except ValueError as error:approval_error=str(error)
    else:raise AssertionError('old895 approval authorized1919 successor')
    try:c.request(24)
    except ValueError as error:install_error=str(error)
    else:raise AssertionError('permission successor installed without fresh exact approval')
    active=c.request(29,bytes.fromhex(release['project_id']))
    require(active[160:192].hex()==release['release_id'],'failed permission escalation changed active release')
   passed('actual signed successor requesting added Network cannot reuse prior895 execution approval',release=changed_release,parent=release['release_id'],previous_rights=895,requested_rights=1919,added_rights=1024,approval_error=approval_error,install_error=install_error,installed=False)
  evidence.update(result='pass',live_session=reader,fork=fork,publisher=publisher,published=published);save()
 except BaseException as error:
  with contextlib.suppress(Exception):(out/'failure.ppm').write_bytes(j.ui.frame().ppm())
  evidence.update(result='failure',error=repr(error),traceback=traceback.format_exc());save();raise
 finally:
  if j.ui:j.ui.close()
 return 0
if __name__=='__main__':raise SystemExit(main())
