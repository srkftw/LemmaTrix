"""Actual native cancellation and verified-record failover to a fresh seed.

The host switch only transports opaque stream bytes. Seed2 receives its source
through the same guest protocol before the recipient starts; no final graph is
preloaded into that seed or the recipient. Changing a route closes old byte
streams, then the operator explicitly provisions a fresh ordered relationship.
"""
import argparse,hashlib,json,os,select,socket,struct,sys,threading,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import capsule,forge,network,releases
from forge_journey import Node,wait,import_project
from forge_replication import authenticate,fetched
from creator_journey import rendered_text

class OpaqueSwitch:
 def __init__(self):
  self.lock=threading.Lock();self.closed=False;self.pair=();self.connections={};self.pending={};self.listeners=[]
  for _ in range(3):
   listener=socket.socket();listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);listener.bind(('127.0.0.1',0));listener.listen(2);listener.setblocking(False);self.listeners.append(listener)
  self.endpoints=[f'127.0.0.1:{s.getsockname()[1]}' for s in self.listeners]
  self.thread=threading.Thread(target=self.run,daemon=True);self.thread.start()
 def route(self,a,b):
  with self.lock:
   for c in self.connections.values():c.close()
   self.connections={};self.pending={};self.pair=(a,b)
 def run(self):
  while not self.closed:
   with self.lock:
    sources=self.listeners+[self.connections[i] for i in self.pair if i in self.connections]
    writes=[self.connections[i] for i in self.pair if i in self.connections and self.pending.get(i)]
    try:ready,writable,_=select.select(sources,writes,[],.01)
    except (ValueError,OSError):continue
    for listener in self.listeners:
     if listener not in ready:continue
     c,_=listener.accept();c.setblocking(False);index=self.listeners.index(listener)
     if index in self.connections:self.connections[index].close()
     self.connections[index]=c;self.pending[index]=bytearray()
    for index in self.pair:
     c=self.connections.get(index)
     if not c:continue
     other=self.pair[1] if index==self.pair[0] else self.pair[0]
     try:
      if c in ready:
       data=c.recv(4096)
       if not data:raise ConnectionError()
       pending=self.pending.setdefault(other,bytearray())
       if len(pending)+len(data)>65536:raise ConnectionError('bounded opaque queue full')
       pending.extend(data)
      if c in writable:
       n=c.send(self.pending[index]);del self.pending[index][:n]
     except (OSError,ConnectionError):
      c.close();self.connections.pop(index,None);self.pending.pop(index,None)
   time.sleep(.002)
 def close(self):
  self.closed=True;self.thread.join(timeout=2)
  for c in list(self.connections.values())+self.listeners:c.close()

def cache(node):
 c=node.client()
 try:return forge.cache_inspect(c,node.instance)
 finally:c.close()

def relationship(switch,nodes,path,a,b,identities):
 path.mkdir(parents=True,exist_ok=True);client,server=path/'client.credential',path/'server.credential'
 network.provision(client,server,identities[a],identities[b],hashlib.sha256(b'Forge verified resume explicit service').digest())
 
 for index in (a,b):
  wait(lambda:(s if not (s:=nodes[index].inspect())['pending_job'] and not s['import_transaction'] and not s['send_phase'] else None),'previous authorized transfer quiescent',120)
 switch.route(a,b);time.sleep(1)
 for index,credential in [(a,client),(b,server)]:
  c=nodes[index].client()
  try:
   network.configure(c,credential)
   forge.configure(c,nodes[index].instance,credential)
  finally:c.close()
 authenticate(nodes[a],nodes[b]);return client,server

def browse(node):
 node.ui.press(61);return wait(lambda:(s if (s:=node.inspect())['status']==6 and s['metadata_nodes'] else None),'native seed metadata',150)
def transfer(sender,receiver,head,files):
 browse(receiver);receiver.ui.press(63);done=fetched(receiver,head,files)
 wait(lambda:sender.inspect()['status']==10,'native validated receipt',120);return done

def main():
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--image',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False);os.environ['LT_GUEST_IMAGE']=str(a.image.resolve())
 key,public=a.output/'operator.pem',a.output/'operator.pub';capsule.generate_key(key,public)
 data,manifest=releases.make(ROOT/'build/live/apps/native-forge-resume-final.bin','native-forge','0.4.1',1919,key,profile=2)
 package=a.output/'native-forge.ltrel';package.write_bytes(data)
 (a.output/'package.json').write_text(json.dumps(manifest,indent=2))
 switch=OpaqueSwitch();nodes=[];identities=[os.getrandom(32) for _ in range(3)];checks=[]
 def passed(name,**details):
  checks.append(dict(check=name,**details));report=dict(image=hashlib.sha256(a.image.read_bytes()).hexdigest(),package=releases.inspect(data)['release_id'],environment='three isolated QEMU guests, distinct peer identities, one Linux development host, opaque bounded byte switch',checks=checks)
  (a.output/'journey.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(checks[-1]),flush=True)
 try:
  for i in range(3):
   node=Node(a.output/['publisher','seed','recipient'][i],switch.endpoints[i]);nodes.append(node);node.install(package,public)
  relationship(switch,nodes,a.output/'publisher-seed',0,1,identities)
  root,head,files,private=import_project(nodes[0]);nodes[0].select('creator');nodes[0].ui.press(62)
  wait(lambda:nodes[0].inspect()['status']==4,'native exact source offer',120)
  first=transfer(nodes[0],nodes[1],head,files)
  nodes[1].ui.press(62);wait(lambda:nodes[1].inspect()['status']==4,'independently received seed offer',120)
  passed('seed acquired actual closure from publisher through native Fetch',head=head,source_bytes=sum(map(len,files.values())),state=first)
  relationship(switch,nodes,a.output/'publisher-recipient',0,2,identities)
  browse(nodes[2]);nodes[2].ui.press(63)
  def meaningful():
   s=nodes[2].inspect();c=cache(nodes[2])
   if s['status']==9:raise AssertionError(('download rejected',s,c))
   return (s,c) if c['validated_bytes']>=1024 and s['import_transaction'] and s['received_nodes']<s['metadata_nodes'] and s['send_offset']>=0 else None
  progress,checked=wait(meaningful,'at least one independently checked complete record during unfinished graph',180)
  nodes[2].ui.press(1)
  wait(lambda:not nodes[2].inspect()['import_transaction'],'native cancellation reclaims hidden stage',90)
  wait(lambda:nodes[0].inspect()['send_phase']==0,'authenticated cancel releases provider transfer',90)
  assert not nodes[2].roots(),'cancelled graph became published';assert cache(nodes[2])['validated_bytes']>=checked['validated_bytes']
  assert cache(nodes[2])['allocated_bytes']==cache(nodes[2])['validated_bytes'],'incomplete cache candidate retained allocation'
  passed('physical Esc interrupts graph, reclaims stage, preserves only checked record bytes',partial=progress,cache=cache(nodes[2]),no_partial_root=True)
  nodes[0].stop()
  relationship(switch,nodes,a.output/'fresh-seed-recipient',1,2,identities)
  before=cache(nodes[2]);assert before['validated_bytes']>=checked['validated_bytes']
  browse(nodes[2]);nodes[2].ui.press(63);done=fetched(nodes[2],head,files)
  wait(lambda:nodes[1].inspect()['status']==10,'fresh seed actual validated receipt',120)
  reused=cache(nodes[2]);assert reused['reused_bytes']>0 and reused['skipped_records']>0,reused
  c=nodes[2].client()
  try:
   ids=[];cursor=0;root=nodes[2].roots()[0]['cap']
   while True:
    fields,identities=c.objects(26,root,cursor)
    if not fields[1]:break
    ids.append(identities[:32].hex());cursor=fields[3]
   assert private not in ids
  finally:c.close()
  frame=wait(lambda:(f if rendered_text((f:=nodes[2].ui.frame()),10,390,31,0x9fc6a5)=='CHECKED / REUSED BYTES (SESSION)' and rendered_text(f,340,390,8)==format(reused['reused_bytes'],'08x') else None),'actual rendered checked and reused session bytes',120)
  (nodes[2].path/'checked-reused.ppm').write_bytes(frame.ppm())
  passed('fresh authorized seed and fresh Noise grant reuse verified immutable records before atomic complete publication',head=head,complete=done,cache=reused,previous_publisher_offline=True,private_object_absent=True)
 finally:
  for node in reversed(nodes):
   try:node.stop()
   except BaseException:pass
  switch.close()
if __name__=='__main__':main()
