"""Native server-save/inspect/recover controls over the purpose2 guest store."""
import argparse,hashlib,json,os,signal,struct,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import capsule,forge,live,network,projects,releases,server_store
from forge_journey import Node,wait,import_project
from graphical_devices import DeviceInput
from creator_journey import rendered_text

class Server(Node):
 def __init__(self,path,disk):
  self.path=path;path.mkdir(parents=True,exist_ok=True);self.sock=path/'portal.sock';self.qmp=path/'display.qmp';self.log=(path/'guest.log').open('wb');self.ui=None
  for p in [self.sock,self.qmp]:p.unlink(missing_ok=True)
  self.proc=subprocess.Popen([str(ROOT/'lt'),'run','--socket',str(self.sock),'--graphics',str(self.qmp),'--server-store',str(disk)],cwd=ROOT,stdout=self.log,stderr=subprocess.STDOUT,start_new_session=True)
  wait(lambda:self.sock.exists(),'server boot');self.ui=DeviceInput('qemu',self.qmp)
 def setup(self,package,public,credentials,namespace):
  self.install(package,public);c=self.client()
  try:
   network.configure(c,credentials)
   server_store.call(c,230)
   grant=server_store.call(c,231,self.instance,2,1048576,namespace)[0][1]
   forge.configure(c,self.instance,credentials,'seed','portable',grant)
  finally:c.close()
 def archive(self):
  c=self.client()
  try:
   raw=c.request(150,struct.pack('<Q',self.instance)+struct.pack('<8Q',55,0,0,0,0,0,0,1))
   assert len(raw)==208 and struct.unpack_from('<Q',raw)[0]==0,(len(raw),raw[:64].hex())
   phase,done,total,code,root=struct.unpack_from('<5Q',raw,64)
   n=struct.unpack_from('<Q',raw,136)[0]
   return dict(phase=phase,done=done,total=total,code=code,root=root,head=raw[104:136].hex(),name=raw[144:144+n].decode('ascii'))
  finally:c.close()

def main():
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,default=ROOT/'build/forge-server-recovery');a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
 private=a.output/'operator.pem';public=a.output/'operator.pub';package=a.output/'native-forge-server.ltrel';disk=a.output/'server.img'
 if not private.exists():capsule.generate_key(private,public)
 envelope,manifest=releases.make(ROOT/'build/live/apps/native-forge.bin','native-forge','0.4.0',3967,private,sources=[ROOT/'Guest/Forge.lean',ROOT/'Guest/ForgeArchive.lean'],profile=2,source_base=ROOT)
 package.write_bytes(envelope);Path(str(package)+'.manifest.json').write_text(json.dumps(manifest))
 server_store.provision(disk)
 client_credential=a.output/'client.credential';credential=a.output/'server.credential'
 network.provision(client_credential,credential,os.getrandom(32),os.getrandom(32),os.getrandom(32));namespace=hashlib.sha256(b'explicit native Forge seed archive test').digest()
 node=None;checks=[]
 try:
  node=Server(a.output/'initial',disk);node.setup(package,public,credential,namespace)
  root,head,files,private_id=import_project(node);node.select('creator');node.ui.press(66)
  def saved():
   state=node.archive()
   if state['phase']==9:raise AssertionError(('native archive save rejected',state))
   return state if state['phase']==8 else None
  state=wait(saved,'native server durable save',180)
  (node.path/'saved.ppm').write_bytes(node.ui.frame().ppm());checks.append(dict(check='native F8 exact server closure commit',state=state,head=head,source_bytes=sum(map(len,files.values()))))
  node.stop();node=None
  node=Server(a.output/'restarted',disk);node.setup(package,public,credential,namespace)
  assert not node.roots(),'server graph was preloaded outside its own durable store'
  node.ui.press(67)
  preview=wait(lambda:(s if (s:=node.archive())['phase']==4 else None),'native server inventory',90)
  assert preview['name']=='creator' and preview['head']==head,preview
  wait(lambda:rendered_text(node.ui.frame(),10,306,7,foreground=0xe9bc75)=='creator','rendered exact server recovery scope',45)
  (node.path/'scope.ppm').write_bytes(node.ui.frame().ppm())
  node.ui.press(67)
  def recovered():
   state=node.archive()
   if state['phase']==9:raise AssertionError(('native recovery rejected',state))
   return state if state['phase']==8 else None
  state=wait(recovered,'native server graph recovery',180)
  roots=node.roots();assert len(roots)==1 and roots[0]['head']==head,roots
  c=node.client()
  try:
   actual,retrieved=projects.snapshot(c,roots[0]['cap']);assert actual==head and retrieved==files
   identities=[];cursor=0
   while True:
    f,ids=c.objects(26,roots[0]['cap'],cursor)
    if not f[1]:break
    identities.append(ids[:32].hex());cursor=f[3]
   assert private_id not in identities
  finally:c.close()
  (node.path/'recovered.ppm').write_bytes(node.ui.frame().ppm());checks.append(dict(check='native F9 inspected then recovered server graph after restart without host graph replay',state=state,preview=preview,private_absent=True))
  report=dict(image=hashlib.sha256((ROOT/'build/live/guest.bin').read_bytes()).hexdigest(),environment='QEMU guests; same host; explicit unencrypted server role retention',checks=checks)
  (a.output/'journey.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
 finally:
  if node:node.stop()

if __name__=='__main__':main()
