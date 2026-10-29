"""Actual isolated Lean admission policies, signatures and durable metadata.

Uses one already built/signed explicitly exported public graph. No new compiler
execution and no recipient final graph are synthesized by this test.
"""
import argparse,base64,hashlib,json,os,signal,struct,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import capsule,federation,live,projects,releases,server_store
from forge_journey import wait

class Registry:
 def __init__(self,path,backing,package,public,fedpublic,policy,namespace):
  path.mkdir(parents=True,exist_ok=True);self.path=path;self.socket=path/'portal.sock';self.log=(path/'guest.log').open('wb')
  self.process=subprocess.Popen([str(ROOT/'lt'),'run','--socket',str(self.socket),'--server-store',str(backing)],cwd=ROOT,stdout=self.log,stderr=subprocess.STDOUT,start_new_session=True)
  wait(lambda:self.socket.exists(),'registry guest ready');c=self.client()
  try:
   raw=package.read_bytes();c.request(10,raw[128:160]+releases.public_modulus(public));slot,info=c.install(package)
   self.instance=struct.unpack_from('<Q',c.request(25,struct.pack('<Q',slot)),8)[0]
   server_store.call(c,230);self.grant=server_store.call(c,231,self.instance,1,1048576,namespace)[0][1]
   self.configuration=federation.configure(c,self.instance,fedpublic,policy,self.grant,False)
  finally:c.close()
 def client(self):return live.Client(self.socket,timeout=180)
 def stop(self):
  if self.process.poll() is None:
   try:
    c=self.client()
    try:c.request(70)
    finally:c.close()
   except (OSError,EOFError,ValueError):pass
   try:self.process.wait(timeout=10)
   except subprocess.TimeoutExpired:os.killpg(self.process.pid,signal.SIGKILL);self.process.wait()
  self.log.close()

def main():
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,default=ROOT/'build/federation-policy');p.add_argument('--public-graph',type=Path,default=ROOT/'build/signed-forge-journey-2/published-closure.json');p.add_argument('--publisher',type=Path,default=ROOT/'build/signed-forge-journey-2/publisher.pub');p.add_argument('--image',type=Path,default=ROOT/'build/platform/150a446ccca25014c1a1c05a8b8932303e72d0bf2ef56336fd1b5480418b4c1e.bin');a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False);os.environ['LT_GUEST_IMAGE']=str(a.image.resolve())
 archive=json.loads(a.public_graph.read_text());records=[dict(r,payload=base64.b64decode(r['payload'],validate=True)) for r in archive['nodes']];head=archive['selected'][0]['head'];logical=archive['project_id']
 operator=a.output/'operator.pem';public=a.output/'operator.pub';capsule.generate_key(operator,public)
 package=a.output/'native-registry.ltrel';data,manifest=releases.make(ROOT/'build/live/apps/native-registry.bin','native-registry','0.4.0',2175,operator,profile=2);package.write_bytes(data);Path(str(package)+'.manifest.json').write_text(json.dumps(manifest))
 checks=[];nodes=[];descriptors=[];keys=[];disks=[];namespaces=[]
 def passed(label,**facts):
  checks.append(dict(check=label,status='passed',**facts));report=dict(image=hashlib.sha256(a.image.read_bytes()).hexdigest(),public_graph=str(a.public_graph),logical_project=logical,head=head,environment='Two isolated QEMU registries with different keys/policies/backing on one development host; disclosed narrowly scoped signer',checks=checks)
  (a.output/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(checks[-1]),flush=True)
 try:
  for index,policy in enumerate(('portable','restricted')):
   private=a.output/f'federation-{index}.pem';fedpublic=a.output/f'federation-{index}.pub';capsule.generate_key(private,fedpublic);keys.append((private,fedpublic));disk=a.output/f'registry-{index}.img';server_store.provision(disk);disks.append(disk);namespace=os.getrandom(32);namespaces.append(namespace)
   node=Registry(a.output/f'registry-{index}',disk,package,public,fedpublic,policy,namespace);nodes.append(node);c=node.client()
   try:
    root=projects.import_records(c,archive['selected'],records)[0]['cap'];assert projects.project_identity(c,root)==logical
    publisher=releases.public_modulus(a.publisher);publication=releases.publication(logical,hashlib.sha256(publisher).hexdigest())
    federation.call(c,node.instance,3,data=publication+publisher)
    borrowed=c.objects(27,root,node.instance,25)[0][1]
    q,decision=federation.call(c,node.instance,2,h=borrowed)
    assert len(decision)==512 and q[1]>0
    expected=2 if index==0 else 3
    assert struct.unpack_from('<Q',decision,16)[0]==expected,(index,decision[:64].hex())
    # Merely evaluated entries are private to pending signer inspection.
    try:federation.call(c,node.instance,6)
    except ValueError as error:assert 'status6' in str(error)
    else:raise AssertionError('unsigned admission appeared in signed catalog')
    signed=federation.sign_once(c,node.instance,private,policy);assert signed['listing']==expected
    q,descriptor=federation.call(c,node.instance,6);assert len(descriptor)==768 and descriptor[:512]==decision;descriptors.append(descriptor)
    _,verified=federation.call(c,node.instance,11,data=descriptor+bytes.fromhex(head));assert verified==descriptor
    tampered=bytearray(descriptor);tampered[192]^=1
    try:federation.call(c,node.instance,11,data=bytes(tampered)+bytes.fromhex(head))
    except ValueError as error:assert 'status5' in str(error)
    else:raise AssertionError('tampered federation descriptor verified')
    passed('actual guest material evaluation and signed policy difference',policy=policy,listing=signed['listing'],reason=signed['reason'],sequence=signed['sequence'],federation=signed['federation'],publisher=hashlib.sha256(publisher).hexdigest(),root=head,metadata_persisted=True,local_execution_approved=False)
   finally:c.close()
  # Each own durable catalog must recover without source graph replay.
  for node in nodes:node.stop()
  nodes=[]
  for index,policy in enumerate(('portable','restricted')):
   node=Registry(a.output/f'restarted-{index}',disks[index],package,public,keys[index][1],policy,namespaces[index]);nodes.append(node);c=node.client()
   try:
    assert not projects.roots(c),'registry unexpectedly restored graph content outside its metadata contract'
    q,_=federation.call(c,node.instance,10);assert q[1]==1
    q,descriptor=federation.call(c,node.instance,6);assert descriptor==descriptors[index]
    # Another selected federation's authentic signature is still the wrong pin.
    try:federation.call(c,node.instance,11,data=descriptors[1-index]+bytes.fromhex(head))
    except ValueError as error:assert 'status5' in str(error)
    else:raise AssertionError('different federation signature accepted')
    passed('own durable signed catalog recovered with no graph replay',policy=policy,records=1,content_available=False)
   finally:c.close()
  node=nodes[0];c=node.client()
  try:
   old=descriptors[0];q,_=federation.call(c,node.instance,8,h=0,a=struct.unpack_from('<Q',old,48)[0]);assert q[1]==2
   revoke=federation.sign_once(c,node.instance,keys[0][0],'portable');assert revoke['listing']==3 and revoke['reason']==6
   q,new=federation.call(c,node.instance,6);assert q[1]==2
   q,_=federation.call(c,node.instance,11,data=new+bytes.fromhex(head));assert q[1]==3
   try:federation.call(c,node.instance,11,data=old+bytes.fromhex(head))
   except ValueError as error:assert 'status3' in str(error)
   else:raise AssertionError('known superseded admission replay accepted')
   passed('signed exact-release revocation supersedes old admission and rejects known replay',sequence=2,reason=6)
  finally:c.close()
 finally:
  for node in nodes:
   try:node.stop()
   except Exception:pass
if __name__=='__main__':main()
