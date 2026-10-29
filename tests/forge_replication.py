"""Native peer replication and retrieval from independently restarted seed stores.

Administrative setup selects endpoints, pairwise credentials and purpose2 grants.
Every source offer, metadata request, fetch and durable save uses physical input.
"""
import argparse,hashlib,json,os,signal,socket,struct,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import forge,network,projects,server_store
from forge_journey import Node,wait,import_project
from forge_server_recovery import Server
from graphical_devices import DeviceInput

class Peer(Node):
 def __init__(self,path,endpoint,listen=False,disk=None):
  self.path=path;path.mkdir(parents=True,exist_ok=True);self.sock=path/'portal.sock';self.qmp=path/'display.qmp';self.log=(path/'guest.log').open('wb');self.ui=None
  for p in (self.sock,self.qmp):p.unlink(missing_ok=True)
  command=[str(ROOT/'lt'),'run','--socket',str(self.sock),'--graphics',str(self.qmp),'--network-listen' if listen else '--network',endpoint]
  if disk:command+=['--server-store',str(disk)]
  self.proc=subprocess.Popen(command,cwd=ROOT,stdout=self.log,stderr=subprocess.STDOUT,start_new_session=True)
  wait(lambda:self.sock.exists(),'peer boot');self.ui=DeviceInput('qemu',self.qmp)
 def setup(self,package,public,credential,namespace=None,recover=False):
  self.install(package,public);c=self.client()
  try:
   network.configure(c,credential);grant=0
   if namespace:
    server_store.call(c,230);grant=server_store.call(c,231,self.instance,2,1048576,namespace)[0][1]
   forge.configure(c,self.instance,credential,'seed' if namespace else 'client','portable',grant,recover)
  finally:c.close()
 archive=Server.archive

def pair_credentials(path,client_id,server_id):
 path.mkdir(parents=True,exist_ok=True)
 client,server=path/'client.credential',path/'server.credential'
 network.provision(client,server,client_id,server_id,hashlib.sha256(b'Forge replication-v1 explicit service').digest())
 probe=socket.socket();probe.bind(('127.0.0.1',0));port=probe.getsockname()[1];probe.close()
 return client,server,f'127.0.0.1:{port}'

def authenticate(a,b):
 def ready():
  for node in (a,b):
   c=node.client()
   try:
    if not network.status(c)['endpoint_authenticated']:return False
   finally:c.close()
  return True
 wait(ready,'fresh pairwise endpoint authentication',180)

def fetched(node,head,files):
 def done():
  state=node.inspect()
  if state['status']==9:raise AssertionError(('native transfer rejected',state))
  return state if state['status']==11 and state['selected_root'] and not state['import_transaction'] else None
 state=wait(done,'native exact graph fetch',300)
 c=node.client()
 try:
  roots=projects.roots(c);assert len(roots)==1 and roots[0]['head']==head,roots
  actual,received=projects.snapshot(c,roots[0]['cap']);assert actual==head and received==files
 finally:c.close()
 return state

def browse_fetch(sender,receiver,head,files):
 receiver.ui.press(61)
 metadata=wait(lambda:(s if (s:=receiver.inspect())['metadata_nodes'] else None),'seed metadata',120)
 assert not receiver.roots(),'metadata request imported source'
 receiver.ui.press(63);state=fetched(receiver,head,files)
 wait(lambda:sender.inspect()['status']==10,'seed completion receipt',120)
 (receiver.path/'fetched.ppm').write_bytes(receiver.ui.frame().ppm())
 return dict(metadata=metadata,complete=state)

def save(node):
 node.ui.press(66)
 def done():
  state=node.archive()
  if state['phase']==9:raise AssertionError(('server commit rejected',state))
  return state if state['phase']==8 else None
 return wait(done,'explicit native server retention',240)

def main():
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,default=ROOT/'build/forge-replication');p.add_argument('--package',type=Path,required=True);p.add_argument('--public',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
 image=hashlib.sha256((ROOT/'build/live/guest.bin').read_bytes()).hexdigest();identities=[os.getrandom(32) for _ in range(4)];namespaces=[hashlib.sha256(b'explicit seed one namespace').digest(),hashlib.sha256(b'explicit seed two namespace').digest()]
 disks=[a.output/'seed-one.img',a.output/'seed-two.img']
 for disk in disks:server_store.provision(disk)
 nodes=[];checks=[]
 def passed(check,**data):
  checks.append(dict(check=check,status='passed',**data));report=dict(image=image,environment='Distinct QEMU guests and backing devices on one Linux development host',identities=[i.hex() for i in identities],checks=checks)
  (a.output/'journey.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(checks[-1]),flush=True)
 def stop_all():
  while nodes:
   node=nodes.pop()
   try:node.stop()
   except (OSError,EOFError):pass
 try:
  creator_key,seed_key,endpoint=pair_credentials(a.output/'relationship-creator-seed1',identities[0],identities[1])
  seed=Peer(a.output/'seed1-receive',endpoint,True,disks[0]);nodes.append(seed);creator=Peer(a.output/'creator',endpoint);nodes.append(creator)
  seed.setup(a.package,a.public,seed_key,namespaces[0]);creator.setup(a.package,a.public,creator_key);authenticate(creator,seed)
  root,head,files,private_id=import_project(creator);creator.select('creator');creator.ui.press(62)
  wait(lambda:creator.inspect()['offered_nodes'],'exact approved offered root')
  first=browse_fetch(creator,seed,head,files);commit1=save(seed)
  passed('creator native offer replicated to first independently durable seed',head=head,source_bytes=sum(map(len,files.values())),private_id=private_id,transfer=first,commit=commit1)
  stop_all()
  # The original publisher remains offline from this point. No graph fixture is
  # replayed into either restarted seed. Only explicit backing is attached.
  seed1_key,seed2_key,endpoint=pair_credentials(a.output/'relationship-seed1-seed2',identities[1],identities[2])
  second=Peer(a.output/'seed2-receive',endpoint,True,disks[1]);nodes.append(second);first=Peer(a.output/'seed1-restarted',endpoint,False,disks[0]);nodes.append(first)
  second.setup(a.package,a.public,seed2_key,namespaces[1]);assert not first.roots()
  first.setup(a.package,a.public,seed1_key,namespaces[0],True);authenticate(first,second)
  wait(lambda:first.inspect()['offered_nodes'],'own durable store recovered and seeded',240)
  replication=browse_fetch(first,second,head,files);commit2=save(second)
  passed('first restarted seed recovered its own store and replicated over Noise to second seed while publisher offline',transfer=replication,commit=commit2)
  stop_all()
  # Remove the first provider too; the independently committed second store is
  # sufficient under a fresh recipient relationship and grant.
  recipient_key,seed2_key,endpoint=pair_credentials(a.output/'relationship-recipient-seed2',identities[3],identities[2])
  second=Peer(a.output/'seed2-restarted',endpoint,True,disks[1]);nodes.append(second);recipient=Peer(a.output/'recipient',endpoint);nodes.append(recipient)
  assert not second.roots();second.setup(a.package,a.public,seed2_key,namespaces[1],True);recipient.setup(a.package,a.public,recipient_key);authenticate(second,recipient)
  wait(lambda:second.inspect()['offered_nodes'],'second own-store restart seed',240)
  final=browse_fetch(second,recipient,head,files)
  c=recipient.client()
  try:
   root=projects.roots(c)[0]['cap'];ids=[];cursor=0
   while True:
    f,payload=c.objects(26,root,cursor)
    if not f[1]:break
    ids.append(payload[:32].hex());cursor=f[3]
   assert private_id not in ids
  finally:c.close()
  passed('new native recipient retrieves exact project after publisher and first seed are absent',head=head,transfer=final,private_absent=True)
 finally:stop_all()
if __name__=='__main__':main()
