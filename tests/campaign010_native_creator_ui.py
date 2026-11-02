"""Native Ctrl+P creates a publisher and reviews/signs/publishes actual Notes.

The key-free compiler supplies inert candidate bytes. Device input approves the
signature and creates the immutable publication root; no host publisher key or
authoritative publication graph is supplied by this driver.
"""
import argparse,hashlib,json,os,signal,struct,subprocess,sys,time,traceback
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import identity,live_build,native_publisher,projects,releases,sdk
from creator_journey import Journey,require

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('image','output'):p.add_argument('--'+name,type=Path,required=True)
 p.add_argument('--project',type=Path,default=ROOT/'examples/project-notes');p.add_argument('--identity',type=Path,required=True);p.add_argument('--keep-on-failure',action='store_true')
 a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False);pub=ROOT/'tests/keys/development-rsa-public.pem';key=ROOT/'tests/keys/development-rsa.pem'
 binary=live_build.app('Guest.Desktop','Guest.Desktop.main','native-creator-ui-editor',2)
 raw,_=releases.make(binary,'native-editor','1.0.1',895,key,profile=2);editor=a.output/'editor.ltrel';editor.write_bytes(raw)
 j=Journey(SimpleNamespace(output=a.output/'personal',image=a.image,public=pub,key=key,backend='qemu'))
 worker=None;log=None;report=dict(schema=1,result='running',scope=__doc__,image_sha256=hashlib.sha256(a.image.read_bytes()).hexdigest(),checks=[]);started=time.monotonic()
 def save():report['elapsed_seconds']=time.monotonic()-started;(a.output/'execution.json').write_text(json.dumps(report,indent=2)+'\n')
 def passed(label,**values):report['checks'].append(dict(check=label,result='pass',**values));save();print('PASS',label,flush=True)
 def wait(fn,label,timeout=240):
  end=time.monotonic()+timeout
  while time.monotonic()<end:
   result=fn()
   if result:return result
   time.sleep(.15)
  raise TimeoutError(label)
 try:
  j.boot(vault=False);j.trust_stage(editor,'native-editor');j.ui.press(1)
  with j.client()as c:
   requester=next(r[0]for r in identity.instances(c)if r[2]==895 and r[0]&255>=7)
   signer=identity.start(c,a.identity,pub)
  imported=subprocess.run(list(map(str,[sys.executable,ROOT/'lt','project','--socket',j.socket,'import',a.project,'--name','native-notes'])),capture_output=True,text=True,check=True)
  root=json.loads(imported.stdout)['root']
  with j.client()as c:
   for carrier in sorted((a.project/'deps').glob('*.json')):sdk.attach_dependency(c,root,json.loads(carrier.read_bytes()))
   original=projects.snapshot(c,root)[0]
  j.open_named_project('native-notes');time.sleep(.4)
  log=(a.output/'compiler.log').open('wb');worker=subprocess.Popen(list(map(str,[sys.executable,ROOT/'lt','project','--socket',j.socket,'serve','--project','project-notes','--root',root,'--requester',requester,'--output',a.output/'worker'])),stdout=log,stderr=log,cwd=ROOT,start_new_session=True)
  j.ui.press(63)
  def built():
   for path in (a.output/'worker').glob('session-*/job-*/job.result.json'):
    value=json.loads(path.read_bytes())
    if value.get('delivered'):
     if value.get('status')!='ok':raise AssertionError(value.get('diagnostic_text'))
     return path,value
  result_path,result=wait(built,'normal public Notes build')
  passed('native workbench builds actual public Notes through key-free compiler',result_path=str(result_path),artifact=result['artifact'],signer=signer)
  with j.client()as c:
   job=c.request(160,struct.pack('<8Q',7,1,0,0,0,0,0,1));meta,data=c.objects(29,root)
   (a.output/'before-creator.json').write_text(json.dumps(dict(job_header=struct.unpack_from('<8Q',job),job_authority=struct.unpack_from('<4Q',job,192),root_metadata=meta,logical=projects.project_identity(c,root)),indent=2)+'\n')
  time.sleep(.5)
  j.ui.chord(29,25)
  last=[]
  def prepared():
   with j.client()as c:raw=c.request(187)
   q=struct.unpack_from('<8Q',raw)
   if not last or last[-1]!=q:last.append(q);print('CREATOR',q,flush=True)
   if q[1]==4:raise AssertionError(('native creator preparation failure',q))
   return q if q[1]==3 else None
  request=wait(prepared,'native Ctrl+P publisher creation and exact proposal')
  with j.client()as c:
   state=native_publisher.inspect(c);require(state['phase']==1,'proposal was signed before trusted review')
   _,public=identity.invoke(c,401,h=request[2]);decoded=identity.decode_public(public)
   chunks=[];offset=0
   while True:
    raw=c.request(191,struct.pack('<Q',offset));q=struct.unpack_from('<8Q',raw);require(q[0]==0 and q[2]==offset and len(raw)==64+q[3],'metadata page differs')
    chunks.append(raw[64:]);offset+=q[3]
    if offset==q[1]:break
   manifest=json.loads(b''.join(chunks));require(manifest['rights']==895 and manifest['license']=='MIT','review differs from actual project declaration')
   try:c.request(227,bytes.fromhex(state['release_id']))
   except ValueError:pass
   else:raise AssertionError('host portal bypassed physical release approval')
  passed('Ctrl+P creates guest-owned publisher and prepares bounded exact manifest review',request=request,publisher=decoded,release_id=state['release_id'],manifest_bytes=offset,manifest_sha256=hashlib.sha256(b''.join(chunks)).hexdigest())
  # The trusted preparation panel transitions to publisher review when ready.
  time.sleep(.8);j.ui.press(28)
  def signed():
   with j.client()as c:value=native_publisher.inspect(c)
   if value['phase']==4:raise AssertionError(value)
   return value if value['phase']==3 else None
  state=wait(signed,'physical native release approval')
  j.ui.press(25)
  alias='published-'+state['release_id'][:16]
  def published():
   with j.client()as c:return next((r for r in projects.roots(c)if r['name']==alias),None)
  selected=wait(published,'physical immutable native publication')
  with j.client()as c:
   require(projects.snapshot(c,root)[0]==original,'publication overwrote editable source')
   head=projects.resolve(c,selected['cap'],selected['head']);q,ids=c.objects(21,head);entries=projects.decode_manifest(c.read_object(head))
   require(any(k==13 and n.startswith('deps/')for n,k,_ in entries),'native publication lost real helper dependency')
   require(any(k==13 and n=='release.ltrel'for n,k,_ in entries),'native publication omitted signed release')
   archive=projects.archive(c,selected['cap'],a.output/'native-notes-graph.json')
  passed('physical P publishes a real native immutable graph for Forge without replacing source',publication=selected,archive=archive,source_parent=ids[32:64].hex(),release=state)
  with j.client()as c:
   review=next(result_path.parent.glob('native-review-*'))
   info=native_publisher.export(c,review,a.output/'project-notes.ltrel')
   c.request(10,bytes.fromhex(info['project_id'])+bytes.fromhex(decoded['public_key']))
   c.stage(a.output/'project-notes.ltrel');c.request(23,bytes.fromhex(info['release_id'])+struct.pack('<Q',info['rights']))
   slot=struct.unpack_from('<Q',c.request(24),8)[0]
   c.request(30,bytes.fromhex(info['release_id']))
   c.stage(a.output/'project-notes.ltrel');c.request(23,bytes.fromhex(info['release_id'])+struct.pack('<Q',info['rights']))
   try:c.request(24)
   except ValueError as error:reinstall_error=str(error)
   else:raise AssertionError('known revoked release installed through a fresh catalog slot')
  passed('exact known revoked release cannot acquire a fresh installation slot',release_id=info['release_id'],error=reinstall_error)
  report['result']='pass'
 except BaseException as error:report.update(result='failure',error=repr(error),traceback=traceback.format_exc());raise
 finally:
  if worker and worker.poll()is None:
   os.killpg(worker.pid,signal.SIGINT)
   try:worker.wait(timeout=10)
   except subprocess.TimeoutExpired:os.killpg(worker.pid,signal.SIGKILL);worker.wait()
  if log:log.close()
  if a.keep_on_failure and report['result']=='failure':
   if j.ui:j.ui.close();j.ui=None
   report['live_process']=j.proc.pid;report['socket']=str(j.socket);report['graphics']=str(j.graphics)
  else:j.stop(hard=True)
  save()
 return 0
if __name__=='__main__':raise SystemExit(main())
