"""Two real native Forge users: physical UI offer/fetch and atomic graph import."""
import argparse,hashlib,json,os,signal,socket,struct,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import capsule,forge,live,network,projects,releases
from graphical_devices import DeviceInput
from creator_journey import rendered_text

def wait(check,label,seconds=90):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  value=check()
  if value:return value
  time.sleep(.08)
 raise TimeoutError(label)

class Node:
 def __init__(self,path,endpoint,listen=False,backend='qemu'):
  self.path=path;path.mkdir(parents=True,exist_ok=True);self.sock=path/'portal.sock';self.qmp=path/'display.qmp';self.log=(path/'guest.log').open('wb');self.ui=None
  for p in [self.sock,self.qmp]:p.unlink(missing_ok=True)
  self.proc=subprocess.Popen([str(ROOT/'lt'),'run','--backend',backend,'--socket',str(self.sock),'--graphics',str(self.qmp),'--network-listen' if listen else '--network',endpoint],cwd=ROOT,stdout=self.log,stderr=subprocess.STDOUT,start_new_session=True)
  wait(lambda:self.sock.exists(),'node boot');self.ui=DeviceInput(backend,self.qmp)
 def client(self):return live.Client(self.sock,timeout=180)
 def stop(self):
  if self.ui:self.ui.close();self.ui=None
  if self.proc.poll() is None:
   try:
    c=self.client()
    try:c.request(70)
    except EOFError:pass
    finally:c.close()
   except (OSError,EOFError):pass
   try:self.proc.wait(timeout=12)
   except subprocess.TimeoutExpired:os.killpg(self.proc.pid,signal.SIGKILL);self.proc.wait()
  self.log.close()
 def inspect(self):
  c=self.client()
  try:return forge.inspect(c,self.instance)
  finally:c.close()
 def roots(self):
  c=self.client()
  try:return projects.roots(c)
  finally:c.close()
 def install(self,package,public):
  c=self.client()
  try:
   c.request(10,releases.project('native-forge')+releases.public_modulus(public));info=c.stage(package)
  finally:c.close()
  self.ui.press(88)
  def approval_presented():
   frame=self.ui.frame()
   return frame if rendered_text(frame,16,12,24)=='SIGNED PACKAGE CANDIDATE' and rendered_text(frame,80,40,12)=='native-forge' else None
  prompt=wait(approval_presented,'actual signed package prompt presented',120)
  (self.path/'exact-approval.ppm').write_bytes(prompt.ppm())
  # Presentation may precede the compositor's completed-frame gesture arm by a
  # service turn; retain a short physical reaction interval after actual pixels.
  time.sleep(.3);self.ui.press(28)
  def installed():
   c=self.client()
   try:
    try:active=c.request(29,releases.project('native-forge'))
    except ValueError:return None
    if active[160:192].hex()!=info['release_id']:return None
    # A fresh test node installs one app. Its incarnation is exposed in the
    # trusted compositor chrome; use those actual pixels rather than racing a
    # UART process-table query against the final GUI-approval service turn.
    focus=rendered_text(self.ui.frame(),520,34,16)
    if len(focus)!=16 or any(c not in '0123456789abcdef' for c in focus):return None
    instance=int(focus,16)
    return instance if 7<=instance&255<12 else None
   finally:c.close()
  self.instance=wait(installed,'native Forge installation');return info
 def select(self,name):
  self.ui.press(60);time.sleep(.5)
  frame=self.ui.frame();rows=[rendered_text(frame,32,107+i*12,len(name)+1).rstrip() for i in range(16)]
  assert name in rows,(name,rows)
  for _ in range(rows.index(name)):self.ui.press(108);time.sleep(.1)
  self.ui.press(28)
  wait(lambda:self.inspect()['status']==1 and rendered_text(self.ui.frame(),140,168,len(name))==name,'trusted selected project delivered to native Forge')

def import_project(node):
 c=node.client()
 try:
  records=[];entries=[];files={}
  for path in sorted((ROOT/'examples/creator').rglob('*')):
   if not path.is_file():continue
   relative=path.relative_to(ROOT/'examples/creator').as_posix();payload=path.read_bytes();files[relative]=payload
   identity=projects.canonical_node(10,payload);records.append(dict(kind=10,id=identity,payload=payload));entries.append((relative,10,identity))
  payload=projects.manifest(entries);head=projects.canonical_node(11,payload);records.insert(0,dict(kind=11,id=head,payload=payload))
  root=projects.import_records(c,[dict(name='creator',head=head)],records)[0]['cap']
  shell=struct.unpack_from('<Q',c.request(2),4*32)[0];c.objects(27,root,shell,127)
  private=c.import_object(b'PRIVATE unrelated session source '+os.getrandom(49).hex().encode(),10)
  private_id=c.objects(21,private)[1][:32].hex()
  return root,head,files,private_id
 finally:c.close()

def run(output,package,public,creator_backend='qemu',recipient_backend='qemu'):
 output.mkdir(parents=True,exist_ok=True);nodes=[];report=[]
 def passed(name,**fields):
  report.append(dict(check=name,status='passed',**fields));print('PASS',name,flush=True)
  (output/'journey.json').write_text(json.dumps(dict(image=hashlib.sha256((ROOT/'build/live/guest.bin').read_bytes()).hexdigest(),creator_backend=creator_backend,recipient_backend=recipient_backend,checks=report),indent=2)+'\n')
 probe=socket.socket();probe.bind(('127.0.0.1',0));port=probe.getsockname()[1];probe.close();endpoint=f'127.0.0.1:{port}'
 credentials=[output/'client.credential',output/'server.credential']
 network.provision(*credentials,os.getrandom(32),os.getrandom(32),hashlib.sha256(b'local Forge authorized integration').digest())
 try:
  receiver=Node(output/'recipient',endpoint,True,recipient_backend);nodes.append(receiver);sender=Node(output/'creator',endpoint,False,creator_backend);nodes.append(sender)
  for node,credential in [(receiver,credentials[1]),(sender,credentials[0])]:
   c=node.client()
   try:network.configure(c,credential)
   finally:c.close()
  def authenticated():
   result=[]
   for node in nodes:
    c=node.client()
    try:result.append(network.status(c)['endpoint_authenticated'])
    finally:c.close()
   return all(result)
  wait(authenticated,'Noise authenticated endpoints',120)
  for node,credential in [(sender,credentials[0]),(receiver,credentials[1])]:
   info=node.install(package,public)
   c=node.client()
   try:forge.configure(c,node.instance,credential)
   finally:c.close()
   assert node.inspect()['configured'];passed('GUI approved isolated native Forge',node=node.path.name,instance=node.instance,release=info['release_id'])
  root,head,files,private_id=import_project(sender);assert sum(map(len,files.values()))>65536
  sender.select('creator');sender.ui.press(62)
  offered=wait(lambda:(s if (s:=sender.inspect())['offered_nodes'] and s['status'] in (4,5) else None),'native exact closure offer')
  receiver.ui.press(61)
  metadata=wait(lambda:(s if (s:=receiver.inspect())['metadata_nodes'] else None),'peer metadata')
  assert not receiver.roots(),'metadata browsing imported content'
  (receiver.path/'metadata.ppm').write_bytes(receiver.ui.frame().ppm());passed('native metadata discovery is content-free',metadata=metadata,private_id=private_id,offered=offered)
  receiver.ui.press(63)
  def fetched():
   state=receiver.inspect()
   if state['status']==9:raise AssertionError(('native importer/transfer rejected',state,sender.inspect()))
   return state if state['status']==11 and state['selected_root'] and not state['import_transaction'] else None
  done=wait(fetched,'native graph fetch',240)
  roots=receiver.roots();assert len(roots)==1 and roots[0]['head']==head,roots
  c=receiver.client()
  try:
   actual,received=projects.snapshot(c,roots[0]['cap']);assert actual==head and received==files
   identities=[];cursor=0
   while True:
    f,ids=c.objects(26,roots[0]['cap'],cursor)
    if not f[1]:break
    identities.append(ids[:32].hex());cursor=f[3]
   assert private_id not in identities
   assert projects.project_identity(c,roots[0]['cap'])==head
  finally:c.close()
  wait(lambda:sender.inspect()['status']==10,'validated peer completion receipt')
  (receiver.path/'fetched.ppm').write_bytes(receiver.ui.frame().ppm());passed('native authenticated streamed closure validated and atomically published',head=head,files=len(files),source_bytes=sum(map(len,files.values())),nodes=len(identities),private_absent=True,state=done)
  return report
 finally:
  for node in nodes:
   try:node.stop()
   except BaseException:pass

def main():
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,default=ROOT/'build/forge-journey');p.add_argument('--package',type=Path);p.add_argument('--public',type=Path);p.add_argument('--creator-backend',choices=('qemu','x86_64','aarch64'),default='qemu');p.add_argument('--recipient-backend',choices=('qemu','x86_64','aarch64'),default='qemu');a=p.parse_args()
 if not a.package:
  a.output.mkdir(parents=True,exist_ok=True);private=a.output/'publisher.pem';a.public=a.output/'publisher.pub';a.package=a.output/'native-forge.ltrel'
  if not private.exists():capsule.generate_key(private,a.public)
  data,manifest=releases.make(ROOT/'build/live/apps/native-forge.bin','native-forge','0.4.0',1919,private,sources=[ROOT/'Guest/Forge.lean'],profile=2,source_base=ROOT)
  a.package.write_bytes(data);Path(str(a.package)+'.manifest.json').write_text(json.dumps(manifest))
 run(a.output,a.package,a.public,a.creator_backend,a.recipient_backend)
if __name__=='__main__':main()
