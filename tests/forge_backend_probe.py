"""Focused shipped Forge-v1 SDK transfer and native execution on a backend.

The small headless fixture is explicit administrative setup, not a graphical
Forge workflow claim. Project content reaches the recipient only through the
guest protocol. The actual selected app still requires trusted graphical
inspection and physical approval, then receives non-canned hardware input.
"""
import argparse,base64,hashlib,json,os,socket,struct,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import forge,live,network,projects,releases
from signed_forge_journey import ClientNode,native_score,package,wait
from creator_journey import rendered_text
import signed_forge_journey

def call(node,op,h=0,data=b''):
 c=node.client()
 try:return c.request(150,struct.pack('<Q8Q',node.instance,op,h,0,0,0,0,0,1)+data)
 finally:c.close()

def main():
 p=argparse.ArgumentParser();p.add_argument('--image',required=True,type=Path);p.add_argument('--output',required=True,type=Path);p.add_argument('--recipient-backend',choices=('qemu','x86_64','aarch64'),default='aarch64');p.add_argument('--release-dir',type=Path,default=ROOT/'build/signed-forge-journey-2');p.add_argument('--binary',type=Path,default=ROOT/'build/live/apps/forge-transfer-probe.bin');p.add_argument('--reuse-probe-package',type=Path);p.add_argument('--timeout',type=int,default=900);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
 signed_forge_journey.WAIT_FLOOR=a.timeout
 os.environ['LT_GUEST_IMAGE']=str(a.image.resolve());key=a.release_dir/'publisher.pem';public=a.release_dir/'publisher.pub'
 probe=a.reuse_probe_package or package(a.binary,'forge-transfer-probe','0.4.0',1407,key,a.output/'probe.ltrel')
 fixture=releases.inspect(probe.read_bytes());assert fixture['rights']==1407 and fixture['executable_sha256']==hashlib.sha256(a.binary.read_bytes()).hexdigest()
 archive=json.loads((a.release_dir/'published-closure.json').read_text());old=json.loads((a.release_dir/'journey.json').read_text());signed=next(x for x in old['checks'] if 'release' in x and 'publication' in x)
 publication=signed['publication'];release=signed['release'];head=archive['selected'][0]['head'];logical=archive['project_id']
 records=[dict(kind=n['kind'],schema=n.get('schema',1),id=n['id'],parent=n['parent'],payload=base64.b64decode(n['payload'])) for n in archive['nodes']]
 probe_socket=socket.socket();probe_socket.bind(('127.0.0.1',0));port=probe_socket.getsockname()[1];probe_socket.close();endpoint=f'127.0.0.1:{port}'
 credentials=[a.output/'creator.credential',a.output/'recipient.credential'];network.provision(*credentials,os.getrandom(32),os.getrandom(32),hashlib.sha256(b'Forge-v1 focused assembly SDK probe').digest())
 report=dict(image=hashlib.sha256(a.image.read_bytes()).hexdigest(),creator_backend='qemu',recipient_backend=a.recipient_backend,profile='Forge-v1 legacy record stream over Noise bulk',scope='administratively installed headless public-SDK fixture; trusted graphical selected-app approval and actual input; not a graphical Forge tool acceptance claim',fixture_sha256=hashlib.sha256(a.binary.read_bytes()).hexdigest(),fixture_bytes=a.binary.stat().st_size,project_compilations=0,checks=[]);nodes=[]
 def passed(label,**fields):
  print('PASS',label,flush=True);report['checks'].append(dict(check=label,result='pass',**fields));(a.output/'evidence.json').write_text(json.dumps(report,indent=2)+'\n')
 try:
  recipient=ClientNode(a.output/'recipient',endpoint,True,a.recipient_backend);nodes.append(recipient);creator=ClientNode(a.output/'creator',endpoint,False,'qemu');nodes.append(creator)
  for node,credential in zip((creator,recipient),credentials):
   print('SETUP network configure',node.path.name,flush=True);c=node.client()
   try:network.configure(c,credential)
   finally:c.close()
  def auth():
   states=[]
   for node in nodes:
    c=node.client()
    try:states.append(network.status(c)['endpoint_authenticated'])
    finally:c.close()
   return all(states)
  wait(auth,'authenticated ordered endpoints',a.timeout);passed('independent guests establish authenticated encrypted endpoint relationship')
  for node,credential in zip((creator,recipient),credentials):
   print('SETUP install SDK fixture',node.path.name,flush=True);c=node.client()
   try:
    c.request(10,releases.project('forge-transfer-probe')+releases.public_modulus(public));slot,info=c.install(probe);node.instance=struct.unpack_from('<Q',c.request(25,struct.pack('<Q',slot)),8)[0]
    print('SETUP configure SDK fixture',node.path.name,flush=True);forge.configure(c,node.instance,credential)
   finally:c.close()
   passed('explicit headless SDK fixture installed and scoped',role=node.path.name,instance=node.instance,bytes=info['size'])
  c=creator.client()
  try:
   root=projects.import_records(c,archive['selected'],records)[0]['cap'];granted=c.objects(27,root,creator.instance,127)[0][1]
  finally:c.close()
  assert struct.unpack_from('<Q',call(creator,3,granted))[0]==0;assert not recipient.roots()
  call(creator,4);wait(lambda:creator.inspect()['offered_nodes']==len(records),'exact approved closure offered',a.timeout)
  call(recipient,5);wait(lambda:recipient.inspect()['metadata_nodes']==len(records),'metadata discovery',a.timeout);assert not recipient.roots()
  passed('metadata describes exact approved source/artifact/evidence closure without recipient content',nodes=len(records),payload_bytes=sum(len(n['payload']) for n in records),root=head)
  call(recipient,6)
  def fetched():
   info=recipient.inspect()
   if info['status']==9:
    diagnostic=call(recipient,56);raise AssertionError(('native import failure',info,list(struct.unpack_from('<16Q',diagnostic,64))))
   return info if info['status']==11 else None
  received=wait(fetched,'actual native closure retrieval and atomic validation',a.timeout)
  c=recipient.client()
  try:
   actual=next(r for r in projects.roots(c) if r['head']==head);assert projects.project_identity(c,actual['cap'])==logical
   c.request(10,bytes.fromhex(publication)+releases.public_modulus(public))
   try:c.request(29,bytes.fromhex(publication))
   except ValueError:pass
   else:raise AssertionError('graph retrieval granted local execution')
  finally:c.close()
  passed('network-only recipient closure validates under native atomic importer with fresh authority',root=head,logical_project_id=logical,received=received,bytes=sum(len(n['payload']) for n in records))
  print('ACTION public SDK inspect-install',flush=True);queued=call(recipient,7)
  assert len(queued)==64 and struct.unpack_from('<Q',queued)[0]==0,'SDK inspection action was not acknowledged'
  def approval():
   frame=recipient.ui.frame()
   return frame if frame is not None and rendered_text(frame,16,12,24)=='SIGNED PACKAGE CANDIDATE' else None
  prompt=wait(approval,'trusted fetched release inspection',a.timeout)
  assert rendered_text(prompt,80,40,7)=='creator';assert rendered_text(prompt,136,110,4)=='0300';(recipient.path/'exact-release-approval.ppm').write_bytes(prompt.ppm());time.sleep(.3);recipient.ui.press(28)
  def active():
   c=recipient.client()
   try:
    try:record=c.request(29,bytes.fromhex(publication))
    except ValueError:return False
    return record[160:192].hex()==release
   finally:c.close()
  wait(active,'selected exact signed app activated',a.timeout);time.sleep(.5);recipient.ui.textASCII('cat123',delay=.1)
  wait(lambda:native_score(recipient)=='00000014','real native app supplied input',a.timeout);(recipient.path/'native-input.ppm').write_bytes(recipient.ui.frame().ppm())
  passed('physically approved actual signed app executes supplied input on selected backend',release=release,rights=768,input='cat123',score='00000014');report['result']='pass'
 except BaseException as error:
  report.update(result='fail',error=repr(error))
  for node in nodes:
   if node.ui:
    try:(node.path/'failure.ppm').write_bytes(node.ui.frame().ppm())
    except BaseException:pass
  raise
 finally:
  (a.output/'evidence.json').write_text(json.dumps(report,indent=2)+'\n')
  for node in nodes:
   try:node.stop()
   except BaseException:pass
if __name__=='__main__':main()
