"""One real generation update after native checkpoint, peer delivery and rollback.

Reuses an explicitly exported, already signed fork from signed_forge_journey.
A fresh scoped publisher approval authorizes the new session's live local root;
reimporting the graph itself restores no previous BuildJob authority.
"""
import argparse,base64,hashlib,json,os,signal,socket,struct,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import capsule,forge,network,projects,releases
from signed_forge_journey import ClientNode,archive_selected,events,package
from forge_journey import wait
from creator_journey import rendered_text,rendered_score

def actual_score(node):
 try:return rendered_score(node.ui.frame())
 except AssertionError:return None

def main():
 p=argparse.ArgumentParser();p.add_argument('--input-dir',required=True,type=Path);p.add_argument('--output',required=True,type=Path);p.add_argument('--image',required=True,type=Path);a=p.parse_args();a.output=a.output.resolve();a.output.mkdir(parents=True,exist_ok=False);source=a.input_dir.resolve();os.environ['LT_GUEST_IMAGE']=str(a.image.resolve())
 archive=json.loads((source/'fork-published-closure.json').read_text());old=next(e for e in events(source/'fork-worker.log') if e.get('event')=='staged');logical=archive['project_id'];head=archive['selected'][0]['head'];name=archive['selected'][0]['name'];key=source/'fork-publisher.pem';public=source/'fork-publisher.pub';publisher=hashlib.sha256(releases.public_modulus(public)).hexdigest();publication=releases.publication(logical,publisher).hex()
 forge_package=package(ROOT/'build/live/apps/native-forge.bin','native-forge','0.4.2',1919,key,a.output/'forge.ltrel');editor_package=package(ROOT/'build/live/apps/native-editor.bin','native-editor','0.4.2',895,key,a.output/'editor.ltrel')
 probe=socket.socket();probe.bind(('127.0.0.1',0));port=probe.getsockname()[1];probe.close();endpoint=f'127.0.0.1:{port}';credentials=[a.output/'creator.credential',a.output/'recipient.credential'];network.provision(*credentials,os.getrandom(32),os.getrandom(32),hashlib.sha256(b'LT native generation update1').digest())
 nodes=[];worker=None;log=None;checks=[]
 def passed(label,**fields):
  checks.append(dict(check=label,result='pass',**fields));print('PASS',label,flush=True);(a.output/'journey.json').write_text(json.dumps(dict(image=hashlib.sha256(a.image.read_bytes()).hexdigest(),checks=checks),indent=2)+'\n')
 def inspect_release(node,release,score):
  node.ui.press(64);wait(lambda:rendered_text(node.ui.frame(),16,12,24)=='SIGNED PACKAGE CANDIDATE','actual native generation authority prompt',120)
  frame=node.ui.frame();assert rendered_text(frame,80,40,len(name))==name and rendered_text(frame,136,110,4)=='0300';(node.path/(release[:12]+'-approval.ppm')).write_bytes(frame.ppm());time.sleep(.3);node.ui.press(28)
  def active():
   c=node.client()
   try:
    try:raw=c.request(29,bytes.fromhex(publication))
    except ValueError:return None
    return raw if raw[160:192].hex()==release else None
   finally:c.close()
  wait(active,'physically approved generation activates',120);wait(lambda:actual_score(node)=='00000000','new native app ready',90);node.ui.textASCII('cat123',delay=.08);wait(lambda:actual_score(node)==score,'native generation supplied input result',90);return int(rendered_text(node.ui.frame(),520,34,16),16)
 def transfer(sender,receiver,selected,expected):
  sender.focus(sender.instance);sender.select(selected);sender.ui.press(62);wait(lambda:sender.inspect()['status'] in (4,5),'native exact generation closure offer',120)
  receiver.focus(receiver.instance);receiver.ui.press(61);wait(lambda:receiver.inspect()['status']==6,'actual peer generation metadata',120);receiver.ui.press(63)
  def complete():
   state=receiver.inspect()
   if state['status']==9:raise AssertionError(('generation transfer rejected',state,sender.inspect()))
   return state if state['status']==11 else None
  done=wait(complete,'native complete generation graph',240);assert any(r['head']==expected for r in receiver.roots());return done
 try:
  recipient=ClientNode(a.output/'recipient',endpoint,True);nodes.append(recipient);creator=ClientNode(a.output/'creator',endpoint);nodes.append(creator)
  for node,credential in zip((creator,recipient),credentials):
   c=node.client()
   try:network.configure(c,credential)
   finally:c.close()
  def authenticated():
   values=[]
   for node in nodes:
    c=node.client()
    try:values.append(network.status(c)['endpoint_authenticated'])
    finally:c.close()
   return all(values)
  wait(authenticated,'fresh authenticated update peers',120)
  for node,credential in zip((creator,recipient),credentials):
   node.instance,_=node.install_app(forge_package,public,'native-forge');c=node.client()
   try:forge.configure(c,node.instance,credential);c.request(10,bytes.fromhex(publication)+releases.public_modulus(public))
   finally:c.close()
  editor,_=creator.install_app(editor_package,public,'native-editor');creator.ui.press(1);time.sleep(.3)
  c=creator.client()
  try:
   records=[dict(n,payload=base64.b64decode(n['payload'],validate=True)) for n in archive['nodes']];root=projects.import_records(c,archive['selected'],records)[0]['cap'];assert projects.project_identity(c,root)==logical
   shell=struct.unpack_from('<Q',c.request(2),4*32)[0];c.objects(27,root,shell,127)
  finally:c.close()
  transfer(creator,recipient,name,head);recipient_app=inspect_release(recipient,old['release'],'0000001b')
  creator.focus(creator.instance);creator.select(name);creator_app=inspect_release(creator,old['release'],'0000001b')
  passed('both users inspect and run existing independently signed fork generation',project=logical,release=old['release'],input='cat123',score='0000001b',creator_instance=creator_app,recipient_instance=recipient_app)
  creator.focus(editor);creator.open_editor_root(name);creator.ui.chord(29,37)
  wait(lambda:rendered_text(creator.ui.frame(),8,233,len('Checkpoint current source only?'))=='Checkpoint current source only?','native source-only checkpoint scope prompt',60);(creator.path/'checkpoint-scope.ppm').write_bytes(creator.ui.frame().ppm());time.sleep(.3);creator.ui.press(28)
  wait(lambda:rendered_text(creator.ui.frame(),8,233,len('Checkpoint complete.'))=='Checkpoint complete.','native checkpoint committed',90);(creator.path/'checkpoint-complete.ppm').write_bytes(creator.ui.frame().ppm());creator.ui.press(1)
  c=creator.client()
  try:
   checkpoint=projects.snapshot(c,root)[0];assert projects.project_identity(c,root)==logical;current=c.objects(24,root)[0][1];assert c.objects(21,current)[0][5]==2
  finally:c.close()
  creator.ui.press(61);time.sleep(.2);creator.ui.click(164+23*6,96+5*11+2);creator.ui.press(111);creator.ui.textASCII('9',delay=.06);creator.ui.press(62);time.sleep(.4)
  creator.ui.press(61);time.sleep(.3);creator.ui.chord(29,18);time.sleep(.3);assert rendered_text(creator.ui.frame(),110,142,2,0xaad6a4)=='06';creator.ui.press(103);creator.ui.press(28);creator.ui.press(62);time.sleep(.5)
  c=creator.client()
  try:
   changed,files=projects.snapshot(c,root);assert b'Weight : UInt64 := 9' in files['Util.lean'] and files['accent.txt']==b'7\n' and projects.project_identity(c,root)==logical
  finally:c.close()
  passed('native source-only checkpoint preserves fork identity and subsequent real source/resource edits',project=logical,archive=head,checkpoint=checkpoint,source_root=changed,source_weight=9,resource_accent=7)
  log_path=a.output/'worker.log';log=log_path.open('wb');worker=subprocess.Popen([str(ROOT/'lt'),'project','--socket',str(creator.sock),'serve','--project',name,'--root',str(root),'--requester',str(editor),'--sign-key',str(key),'--output',str(a.output/'worker'),'--version','1.1.0'],cwd=ROOT,stdout=log,stderr=log,start_new_session=True);wait(lambda:any(e.get('event')=='ready' for e in events(log_path)),'new explicit live-root publisher scope ready',60);creator.ui.press(63)
  wait(lambda:any(e.get('event')=='building' for e in events(log_path)),'actual new generation compiler starts',90)
  recipient.ui.textASCII('Z9',delay=.08);wait(lambda:actual_score(recipient)=='00000022','unrelated old app responds during remote guest local build',90);(recipient.path/'old-generation-responsive.ppm').write_bytes(recipient.ui.frame().ppm())
  def staged():
   errors=[e for e in events(log_path) if e.get('event') in ('error','diagnostic','rejected')]
   if errors:raise AssertionError(('actual generation build/sign rejected',errors))
   return next((e for e in events(log_path) if e.get('event')=='staged'),None)
  new=wait(staged,'one real generation2 scoped build/sign',240);assert new['parent']==old['release'] and new['version']=='1.1.0'
  os.killpg(worker.pid,signal.SIGINT);worker.wait(timeout=15);worker=None;log.close();log=None
  c=creator.client()
  try:new_head=archive_selected(c,root,a.output/'published-closure.json')
  finally:c.close()
  passed('generation2 signs a real changed artifact with exact active parent while earlier app remains responsive',release=new['release'],parent=new['parent'],version=new['version'],source_root=new['source_root'],old_app_input='cat123Z9',old_app_score='00000022')
  transfer(creator,recipient,name,new_head);new_app=inspect_release(recipient,new['release'],'00000020');(recipient.path/'generation2-input.ppm').write_bytes(recipient.ui.frame().ppm())
  # The trusted lifecycle view obtains project relation tokens itself. Physical B
  # explicitly selects rollback; these tokens never cross the peer protocol.
  recipient.ui.chord(56,67);time.sleep(.5);recipient.ui.press(108);time.sleep(.5);recipient.ui.press(48);time.sleep(.5)
  c=recipient.client()
  try:active=c.request(29,bytes.fromhex(publication));assert active[160:192].hex()==old['release']
  finally:c.close()
  (recipient.path/'explicit-rollback.ppm').write_bytes(recipient.ui.frame().ppm());recipient.ui.press(1);recipient.focus(new_app);assert actual_score(recipient)=='00000020';recipient.focus(recipient_app);assert actual_score(recipient)=='00000022';recipient.ui.textASCII('A',delay=.08);wait(lambda:actual_score(recipient)=='00000029','prior running generation survives rollback and accepts input',90)
  passed('network generation2 activation and explicit native rollback preserve both running generations',project=logical,updated=new['release'],rolled_back=old['release'],generation2_input='cat123',generation2_score='00000020',original_running_input='cat123Z9A',original_running_score='00000029')
 except BaseException:
  for node in nodes:
   if node.ui:
    try:(node.path/'failure.ppm').write_bytes(node.ui.frame().ppm())
    except BaseException:pass
  raise
 finally:
  if worker and worker.poll() is None:os.killpg(worker.pid,signal.SIGINT);worker.wait(timeout=15)
  if log:log.close()
  for node in nodes:
   try:node.stop()
   except BaseException:pass
if __name__=='__main__':main()
