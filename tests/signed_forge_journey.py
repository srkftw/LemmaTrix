"""Actual scoped editor build/sign, peer Release fetch and native Forge install.

Uses the existing image and compiled tools. Host signing/compiler bootstrap is
explicit; client actions are physical input and guest SDK paths.
"""
import argparse,base64,hashlib,json,os,signal,socket,struct,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import capsule,forge,live,network,projects,releases
from forge_journey import Node,wait as bounded_wait,import_project
from creator_journey import rendered_text,rendered_score

WAIT_FLOOR=0
def wait(check,label,seconds=90):return bounded_wait(check,label,max(seconds,WAIT_FLOOR))

class ClientNode(Node):
 def client(self):return live.Client(self.sock,timeout=max(180,WAIT_FLOOR))
 def install_app(self,package,public,name):
  c=self.client()
  try:
   before=c.request(2);known={struct.unpack_from('<Q',before,i)[0] for i in range(0,len(before),32)}
   c.request(10,releases.project(name)+releases.public_modulus(public));info=c.stage(package)
  finally:c.close()
  self.ui.press(88)
  wait(lambda:rendered_text(self.ui.frame(),16,12,24)=='SIGNED PACKAGE CANDIDATE','real package inspection',120)
  time.sleep(.3);self.ui.press(28)
  def installed():
   c=self.client()
   try:
    try:active=c.request(29,releases.project(name))
    except ValueError:return None
    if active[160:192].hex()!=info['release_id']:return None
    focus=rendered_text(self.ui.frame(),520,34,16)
    if len(focus)!=16 or any(ch not in '0123456789abcdef' for ch in focus):return None
    instance=int(focus,16)
    return instance if 7<=instance&255<12 and instance not in known else None
   finally:c.close()
  return wait(installed,'physically approved app starts',120),info
 def focus(self,instance):
  target=f'{instance:016x}'
  for _ in range(10):
   if rendered_text(self.ui.frame(),520,34,16)==target:return
   self.ui.chord(56,15);time.sleep(.3)
  raise AssertionError('physical Alt-Tab failed to focus expected incarnation')
 def open_editor_root(self,name):
  self.ui.chord(42,60);time.sleep(.5)
  frame=self.ui.frame();rows=[rendered_text(frame,32,107+i*12,len(name)+1).rstrip() for i in range(16)]
  if name not in rows:raise AssertionError(('trusted picker lacks project',name,rows))
  for _ in range(rows.index(name)):self.ui.press(108);time.sleep(.12)
  self.ui.press(28);time.sleep(.7)

def package(binary,name,version,rights,key,path):
 data,manifest=releases.make(binary,name,version,rights,key,profile=2)
 path.write_bytes(data);Path(str(path)+'.manifest.json').write_text(json.dumps(manifest,sort_keys=True,separators=(',',':')));return path

def native_score(node):
 try:return rendered_score(node.ui.frame())
 except AssertionError:return None

def events(path):
 result=[]
 if path.exists():
  for line in path.read_text().splitlines():
   try:result.append(json.loads(line))
   except ValueError:pass
 return result

def archive_selected(c,root,path):
 fields,meta=c.objects(29,root);head=meta[:32].hex();records=[];cursor=0
 while cursor<64:
  f,ids=c.objects(26,root,cursor)
  if not f[1]:break
  payload=c.read_object(f[1],True)
  records.append(dict(kind=f[4],schema=f[5],id=ids[:32].hex(),parent=ids[32:64].hex(),payload=base64.b64encode(payload).decode('ascii')));cursor=f[3]
 if c.objects(29,root)[1][:32].hex()!=head:raise AssertionError('selected public export changed while archiving')
 logical=projects.project_identity(c,root)
 path.write_text(json.dumps(dict(schema=1,selected=[dict(name=meta[32:32+fields[2]].decode('ascii'),head=head)],project_id=logical,nodes=records),sort_keys=True,separators=(',',':'))+'\n')
 return head

def main():
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,default=ROOT/'build/signed-forge-journey');p.add_argument('--reuse-release-dir',type=Path);p.add_argument('--fork',action='store_true');p.add_argument('--creator-backend',choices=('qemu','x86_64','aarch64'),default='qemu');p.add_argument('--recipient-backend',choices=('qemu','x86_64','aarch64'),default='qemu');p.add_argument('--timeout',type=int,default=240);p.add_argument('--reuse-forge-package',type=Path);p.add_argument('--image',type=Path,default=ROOT/'build/platform/150a446ccca25014c1a1c05a8b8932303e72d0bf2ef56336fd1b5480418b4c1e.bin');a=p.parse_args();a.output=a.output.resolve();a.output.mkdir(parents=True,exist_ok=False)
 global WAIT_FLOOR
 if not 1<=a.timeout<=1800:p.error('timeout must be1..1800 seconds')
 WAIT_FLOOR=a.timeout
 os.environ['LT_GUEST_IMAGE']=str(a.image.resolve());image=hashlib.sha256(a.image.read_bytes()).hexdigest();key=(a.reuse_release_dir or a.output)/'publisher.pem';public=(a.reuse_release_dir or a.output)/'publisher.pub'
 if not a.reuse_release_dir:capsule.generate_key(key,public)
 forge_package=a.reuse_forge_package or package(ROOT/'build/live/apps/native-forge.bin','native-forge','0.4.1',1919,key,a.output/'forge.ltrel')
 need_editor=not a.reuse_release_dir or a.fork
 editor_package=package(ROOT/'build/live/apps/native-editor.bin','native-editor','0.4.1',895,key,a.output/'editor.ltrel') if need_editor else None
 probe=socket.socket();probe.bind(('127.0.0.1',0));port=probe.getsockname()[1];probe.close();endpoint=f'127.0.0.1:{port}'
 credentials=[a.output/'creator.credential',a.output/'recipient.credential'];network.provision(*credentials,os.getrandom(32),os.getrandom(32),hashlib.sha256(b'LT signed Forge integration1').digest())
 nodes=[];worker=None;log=None;report=[]
 def passed(label,**data):report.append(dict(check=label,result='pass',**data));print('PASS',label,flush=True);(a.output/'journey.json').write_text(json.dumps(dict(image=image,creator_backend=a.creator_backend,recipient_backend=a.recipient_backend,checks=report),indent=2)+'\n')
 try:
  recipient=ClientNode(a.output/'recipient',endpoint,True,a.recipient_backend);nodes.append(recipient);creator=ClientNode(a.output/'creator',endpoint,False,a.creator_backend);nodes.append(creator)
  for node,credential in zip((creator,recipient),credentials):
   c=node.client()
   try:network.configure(c,credential)
   finally:c.close()
  def auth():
   okay=[]
   for n in nodes:
    c=n.client()
    try:okay.append(network.status(c)['endpoint_authenticated'])
    finally:c.close()
   return all(okay)
  wait(auth,'Noise authenticated release peers',120)
  for n,credential in zip((creator,recipient),credentials):
   n.instance,_=n.install_app(forge_package,public,'native-forge')
   c=n.client()
   try:forge.configure(c,n.instance,credential)
   finally:c.close()
  if need_editor:
   editor,editor_info=creator.install_app(editor_package,public,'native-editor');creator.ui.press(1);time.sleep(.3)
  if not a.reuse_release_dir:
   root,original,files,private=import_project(creator)
   c=creator.client()
   try:
    logical=projects.project_identity(c,root);publication=releases.publication(logical,hashlib.sha256(releases.public_modulus(public)).hexdigest()).hex()
    c.request(10,bytes.fromhex(publication)+releases.public_modulus(public))
   finally:c.close()
   creator.open_editor_root('creator')
   log_path=a.output/'worker.log';log=log_path.open('wb');worker=subprocess.Popen([str(ROOT/'lt'),'project','--socket',str(creator.sock),'serve','--project','creator','--root',str(root),'--requester',str(editor),'--sign-key',str(key),'--output',str(a.output/'worker'),'--version','1.0.0'],cwd=ROOT,stdout=log,stderr=log,start_new_session=True)
   wait(lambda:any(e.get('event')=='ready' for e in events(log_path)),'explicit scoped worker ready',60)
   creator.ui.press(63)
   def staged():
    if worker.poll() is not None:raise AssertionError(('worker exited',log_path.read_text()))
    all_events=events(log_path)
    errors=[e for e in all_events if e.get('event') in ('error','diagnostic','rejected')]
    if errors:raise AssertionError(('actual build/sign failure',errors))
    return next((e for e in all_events if e.get('event')=='staged'),None)
   signed=wait(staged,'native F5 actual scoped build and signed release',240)
   os.killpg(worker.pid,signal.SIGINT);worker.wait(timeout=15);worker=None;log.close();log=None
   result_path=next((a.output/'worker').rglob('job.result.json'));result=json.loads(result_path.read_text());envelope=Path(signed['path']).read_bytes();assert result['status']=='ok' and signed['signature_verified'] and signed['material_checked'];assert result['guest_session']['project_id']==logical
   passed('native editor exact source build signs under stable identity and live root scope',source_root=result['source_root'],logical_project=logical,publication=publication,release=signed['release'],artifact=result['artifact']['sha256'],bytes=result['artifact']['bytes'],job=result['job_id'],requester=editor,private_excluded=private)
   c=creator.client()
   try:published_head=archive_selected(c,root,a.output/'published-closure.json')
   finally:c.close()
  else:
   archive=json.loads((a.reuse_release_dir/'published-closure.json').read_text())
   records=[dict(n,payload=base64.b64decode(n['payload'],validate=True)) for n in archive['nodes']]
   old_report=json.loads((a.reuse_release_dir/'journey.json').read_text())['checks'][0]
   signed=next(e for e in events(a.reuse_release_dir/'worker.log') if e.get('event')=='staged')
   result_path=next((a.reuse_release_dir/'worker').rglob('job.result.json'));result=json.loads(result_path.read_text());logical=archive['project_id'];publication=old_report['publication'];published_head=archive['selected'][0]['head']
   c=creator.client()
   try:
    root=projects.import_records(c,archive['selected'],records)[0]['cap'];assert projects.project_identity(c,root)==logical
    shell=struct.unpack_from('<Q',c.request(2),4*32)[0];c.objects(27,root,shell,127)
    denied=c.request(160,struct.pack('<8Q',7,int(result['job_id']),0,0,0,0,0,1));assert struct.unpack_from('<Q',denied)[0]!=0
   finally:c.close()
   passed('restore exact already signed public graph into creator with fresh caps and no restored BuildJob signing authority',source_release=signed['release'],publication=publication,logical_project=logical,original_build=str(result_path))
  creator.focus(creator.instance);creator.select('creator');creator.ui.press(62)
  wait(lambda:creator.inspect()['offered_nodes'],'native signed closure offer',120)
  recipient.ui.press(61);wait(lambda:recipient.inspect()['metadata_nodes'],'signed project metadata',120);assert not recipient.roots()
  recipient.ui.press(63)
  def fetched():
   info=recipient.inspect()
   if info['status']==9:raise AssertionError(('native signed graph rejection',info))
   return info if info['status']==11 else None
  received=wait(fetched,'native signed release closure retrieval',240)
  c=recipient.client()
  try:
   roots=projects.roots(c);remote=next(r for r in roots if r['head']==published_head);assert projects.project_identity(c,remote['cap'])==logical
   c.request(10,bytes.fromhex(publication)+releases.public_modulus(public))
   try:c.request(29,bytes.fromhex(publication))
   except ValueError:pass
   else:raise AssertionError('federated fetch granted execution before local approval')
  finally:c.close()
  recipient.ui.press(64)
  wait(lambda:rendered_text(recipient.ui.frame(),16,12,24)=='SIGNED PACKAGE CANDIDATE','Forge F6 actual release inspection',120)
  prompt=recipient.ui.frame();assert rendered_text(prompt,80,40,7)=='creator';assert rendered_text(prompt,136,110,4)=='0300';(a.output/'recipient/exact-release-approval.ppm').write_bytes(prompt.ppm());time.sleep(.3);recipient.ui.press(28)
  def activated():
   c=recipient.client()
   try:
    try:active=c.request(29,bytes.fromhex(publication))
    except ValueError:return None
    return active if active[160:192].hex()==signed['release'] else None
   finally:c.close()
  wait(activated,'actual graph release activated after local authority review',120);time.sleep(.5)
  recipient.ui.textASCII('cat123',delay=.08)
  wait(lambda:native_score(recipient)=='00000014','native application real supplied input',90)
  (a.output/'recipient/native-input.ppm').write_bytes(recipient.ui.frame().ppm());passed('encrypted network Release graph passes F6 actual material and exact rights approval then runs supplied input',release=signed['release'],rights=768,input='cat123',score='00000014',received=received)
  if a.fork:
   fork_key=a.output/'fork-publisher.pem';fork_public=a.output/'fork-publisher.pub';capsule.generate_key(fork_key,fork_public)
   fork_publisher=hashlib.sha256(releases.public_modulus(fork_public)).hexdigest();fork_name='creator-fork'
   recipient_editor,_=recipient.install_app(editor_package,public,'native-editor');recipient.ui.press(1);time.sleep(.3)
   recipient.open_editor_root(remote['name'])
   recipient.ui.press(62);time.sleep(.4)
   c=recipient.client()
   try:assert c.objects(29,remote['cap'])[1][:32].hex()==published_head,'unchanged native save changed selected revision'
   finally:c.close()
   recipient.ui.chord(29,33)
   wait(lambda:rendered_text(recipient.ui.frame(),8,370,24,0xe9bc75)=='Fork name (new identity;','native fork alias prompt',60)
   recipient.ui.textASCII(fork_name,delay=.06);recipient.ui.press(28)
   wait(lambda:rendered_text(recipient.ui.frame(),8,370,len('New publisher public key ID'),0xe9bc75)=='New publisher public key ID','native fork publisher prompt',60)
   recipient.ui.textASCII(fork_publisher,delay=.06);recipient.ui.press(28)
   wait(lambda:rendered_text(recipient.ui.frame(),8,370,len('Fork created; own identity.'),0xe9bc75)=='Fork created; own identity.','native fork actual completion',60)
   c=recipient.client()
   try:
    fork_root=next(r for r in projects.roots(c) if r['name']==fork_name)['cap'];fork_logical=projects.project_identity(c,fork_root)
    assert fork_logical!=logical
    upstream_files=projects.snapshot(c,remote['cap'])[1]
    assert projects.snapshot(c,fork_root)[1]==upstream_files
    fork_binding=c.objects(29,fork_root)[0][7];assert fork_binding!=c.objects(29,remote['cap'])[0][7]
    fork_entries=projects.decode_manifest(c.read_object(c.objects(24,fork_root)[0][1]));fork_lineage_id=next(identity for _,kind,identity in fork_entries if kind==15)
    fork_lineage=c.read_object(projects.resolve(c,fork_root,fork_lineage_id));assert fork_lineage[48:80].hex()==logical and fork_lineage[80:112].hex()==published_head and fork_lineage[144:176].hex()==fork_publisher,(fork_lineage[48:176].hex(),logical,published_head,fork_publisher)
    assert fork_lineage[112:144].hex()==signed['release'],'native Fork omitted actual selected signed upstream release'
   finally:c.close()
   # Real graphical edit of the consumed Util algorithm and resource value.
   recipient.ui.press(61);time.sleep(.2);recipient.ui.click(164+23*6,96+5*11+2);recipient.ui.press(111);recipient.ui.textASCII('7',delay=.06);recipient.ui.press(62);time.sleep(.5)
   recipient.ui.press(61);time.sleep(.3);recipient.ui.chord(29,18);time.sleep(.3)
   assert rendered_text(recipient.ui.frame(),110,142,2,0xaad6a4)=='05'
   recipient.ui.press(103);recipient.ui.press(28);recipient.ui.press(62);time.sleep(.5)
   c=recipient.client()
   try:
    fork_source,changed=projects.snapshot(c,fork_root);assert changed['Util.lean']==upstream_files['Util.lean'].replace(b'Weight : UInt64 := 3',b'Weight : UInt64 := 7') and changed['accent.txt']==b'6\n'
    assert projects.snapshot(c,remote['cap'])[1]==upstream_files and projects.project_identity(c,fork_root)==fork_logical
    fork_publication=releases.publication(fork_logical,fork_publisher).hex();c.request(10,bytes.fromhex(fork_publication)+releases.public_modulus(fork_public))
   finally:c.close()
   (a.output/'recipient/fork-edited.ppm').write_bytes(recipient.ui.frame().ppm())
   passed('recipient native Ctrl-F creates fresh identity and publisher choice; graphical source and resource edits preserve upstream',upstream_project=logical,upstream_head=published_head,fork_project=fork_logical,fork_lineage=fork_lineage_id,publisher=fork_publisher,source_root=fork_source,source_weight=7,resource_accent=6)
   fork_log_path=a.output/'fork-worker.log';log=fork_log_path.open('wb');worker=subprocess.Popen([str(ROOT/'lt'),'project','--socket',str(recipient.sock),'serve','--project',fork_name,'--root',str(fork_root),'--requester',str(recipient_editor),'--sign-key',str(fork_key),'--output',str(a.output/'fork-worker'),'--version','1.0.0'],cwd=ROOT,stdout=log,stderr=log,start_new_session=True)
   wait(lambda:any(e.get('event')=='ready' for e in events(fork_log_path)),'explicit fork worker ready',60);recipient.ui.press(63)
   def fork_staged():
    if worker.poll() is not None:raise AssertionError(('fork worker exited',fork_log_path.read_text()))
    all_events=events(fork_log_path);errors=[e for e in all_events if e.get('event') in ('error','diagnostic','rejected')]
    if errors:raise AssertionError(('actual fork build/sign failure',errors))
    return next((e for e in all_events if e.get('event')=='staged'),None)
   fork_signed=wait(fork_staged,'native fork real scoped build and own publisher release',240)
   os.killpg(worker.pid,signal.SIGINT);worker.wait(timeout=15);worker=None;log.close();log=None
   fork_result_path=next((a.output/'fork-worker').rglob('job.result.json'));fork_result=json.loads(fork_result_path.read_text());assert fork_result['artifact']['sha256']!=result['artifact']['sha256'] and fork_signed['signature_verified'] and fork_signed['material_checked'] and fork_result['guest_session']['project_id']==fork_logical
   c=recipient.client()
   try:fork_head=archive_selected(c,fork_root,a.output/'fork-published-closure.json')
   finally:c.close()
   subprocess.run([sys.executable,str(ROOT/'tests/signing_authority_live.py'),'--socket',str(recipient.sock),'--result',str(fork_result_path),'--archive',str(a.output/'fork-published-closure.json'),'--root-alias',fork_name,'--key',str(fork_key),'--wrong-key',str(key),'--output',str(a.output/'authority-negative')],check=True,cwd=ROOT)
   passed('fork exact changed source builds and signs under its own selected live root and publisher identity',release=fork_signed['release'],publication=fork_publication,artifact=fork_result['artifact']['sha256'],bytes=fork_result['artifact']['bytes'],source_root=fork_result['source_root'],job=fork_result['job_id'])
   # The recipient now serves its own explicit fork closure to the original user.
   recipient.focus(recipient.instance);recipient.select(fork_name);recipient.ui.press(62)
   wait(lambda:recipient.inspect()['status'] in (4,5) and recipient.inspect()['offered_nodes'],'native fork closure offer',120)
   creator.focus(creator.instance);creator.ui.press(61);wait(lambda:creator.inspect()['status']==6,'fork peer metadata',120);creator.ui.press(63)
   def fork_fetched():
    info=creator.inspect()
    if info['status']==9:raise AssertionError(('native fork graph rejection',info))
    return info if info['status']==11 else None
   fork_received=wait(fork_fetched,'native signed fork closure retrieval',240)
   c=creator.client()
   try:
    fetched_fork=next(r for r in projects.roots(c) if r['head']==fork_head);assert projects.project_identity(c,fetched_fork['cap'])==fork_logical
    c.request(10,bytes.fromhex(fork_publication)+releases.public_modulus(fork_public))
   finally:c.close()
   creator.ui.press(64);wait(lambda:rendered_text(creator.ui.frame(),16,12,24)=='SIGNED PACKAGE CANDIDATE','actual fork F6 release approval',120)
   fork_prompt=creator.ui.frame();assert rendered_text(fork_prompt,80,40,len(fork_name))==fork_name and rendered_text(fork_prompt,136,110,4)=='0300'
   (a.output/'creator/fork-release-approval.ppm').write_bytes(fork_prompt.ppm());time.sleep(.3);creator.ui.press(28)
   def fork_active():
    c=creator.client()
    try:
     try:active=c.request(29,bytes.fromhex(fork_publication))
     except ValueError:return None
     return active if active[160:192].hex()==fork_signed['release'] else None
    finally:c.close()
   wait(fork_active,'actual peer fork generation activated after authority review',120);time.sleep(.5);creator.ui.textASCII('cat123',delay=.08)
   wait(lambda:native_score(creator)=='0000001b','changed native fork supplied input behavior',90)
   (a.output/'creator/fork-native-input.ppm').write_bytes(creator.ui.frame().ppm())
   c=creator.client()
   try:
    assert projects.project_identity(c,root)==logical
   finally:c.close()
   passed('own signed fork returns through encrypted network and runs changed source plus resource on original user guest',release=fork_signed['release'],fork_project=fork_logical,upstream_project=logical,rights=768,input='cat123',score='0000001b',received=fork_received)
 except BaseException:
  for node in nodes:
   if node.ui:
    try:(node.path/'failure.ppm').write_bytes(node.ui.frame().ppm())
    except BaseException:pass
  raise
 finally:
  if worker and worker.poll() is None:os.killpg(worker.pid,signal.SIGINT);worker.wait(timeout=15)
  if log:log.close()
  for n in nodes:
   try:n.stop()
   except BaseException:pass
if __name__=='__main__':main()
