"""Native quote/approval, isolated actual rebuilds and returned artifact bytes."""
import argparse,hashlib,json,os,socket,struct,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import capsule,forge,live,network,projects,releases,remote_build
from forge_journey import Node,wait,import_project

def remote(node):
 c=node.client()
 try:return remote_build.inspect(c,node.instance)
 finally:c.close()

def single(output,package,public,role):
 output.mkdir(parents=True,exist_ok=True);nodes=[]
 probe=socket.socket();probe.bind(('127.0.0.1',0));port=probe.getsockname()[1];probe.close();endpoint=f'127.0.0.1:{port}'
 credentials=[output/'client.credential',output/'provider.credential']
 network.provision(*credentials,os.getrandom(32),os.getrandom(32),hashlib.sha256(b'LT remote-build contract1 '+role.encode()).digest())
 try:
  provider=Node(output/'provider',endpoint,True);nodes.append(provider);client=Node(output/'client',endpoint);nodes.append(client)
  for node,credential in [(provider,credentials[1]),(client,credentials[0])]:
   c=node.client()
   try:network.configure(c,credential)
   finally:c.close()
  def authenticated():
   good=[]
   for node in nodes:
    c=node.client()
    try:good.append(network.status(c)['endpoint_authenticated'])
    finally:c.close()
   return all(good)
  wait(authenticated,'Noise authenticated native build peers',120)
  for node,credential,node_role in [(client,credentials[0],'client'),(provider,credentials[1],role)]:
   node.install(package,public);c=node.client()
   try:
    forge.configure(c,node.instance,credential,node_role)
    remote_build.configure(c,node.instance,credential,node_role,role)
   finally:c.close()
  root,head,files,private=import_project(client);client.select('creator');client.ui.press(62)
  wait(lambda:client.inspect()['offered_nodes'],'source exact closure frozen')
  provider.ui.press(61);wait(lambda:provider.inspect()['metadata_nodes'],'provider receives source offer metadata')
  provider.ui.press(63)
  def imported():
   state=provider.inspect()
   if state['status']==9:
    c=provider.client()
    try:diagnostic=c.request(150,struct.pack('<Q',provider.instance)+struct.pack('<8Q',56,0,0,0,0,0,0,1))
    finally:c.close()
    raise AssertionError(('source native import failure',state,struct.unpack_from('<16Q',diagnostic,64)))
   return state['status']==11
  wait(imported,'provider receives authorized exact source closure',180)
  wait(lambda:client.inspect()['status']==10,'source transfer receipt',120)
  client.ui.press(65)
  def quoted():
   info=remote(client)
   if info['error'] and info['state'] not in (1,7):raise AssertionError(('quote error',info))
   return info if info['state']==1 else None
  quote=wait(quoted,'native remote zero-price quote',120)
  assert remote(provider)['state']==1,'provider executed before requester approval'
  (client.path/'quoted.ppm').write_bytes(client.ui.frame().ppm())
  print('PASS native quote awaits physical approval',role,flush=True)
  client.ui.press(68)
  authority=wait(lambda:(r if (r:=remote(provider))['state']==2 and r['local_job'] else None),'guest admitted approved remote job',120)
  c=provider.client()
  try:result=remote_build.execute_once(c,provider.instance,output/'executor')
  finally:c.close()
  assert result is not None and result['status']=='ok',result
  print('PASS actual namespace build',role,result['artifact']['sha256'],flush=True)
  completed=wait(lambda:(r if (r:=remote(client))['state']==3 else None),'authenticated remote artifact receipt',120)
  assert completed['source_root']==head and completed['artifact_hash']==result['artifact']['sha256'],completed
  wait(lambda:client.inspect()['metadata_nodes'],'actual artifact graph advertised',120)
  # Result metadata can arrive a few service turns after its computation receipt.
  def offered_result():
   c=client.client()
   try:
    raw=c.request(150,struct.pack('<Q',client.instance)+struct.pack('<8Q',2,0,0,0,0,0,0,1))
    return len(raw)==320 and struct.unpack_from('<Q',raw,64+144)[0]>=10
   finally:c.close()
  wait(offered_result,'result closure metadata replaces input advertisement',120)
  client.ui.press(63)
  def result_root():
   roots=client.roots()
   return next((r for r in roots if r['head']==completed['artifact_root']),None)
  received=wait(result_root,'native fetch validates actual remote artifact closure',180)
  c=client.client()
  try:
   actual,returned=projects.snapshot(c,received['cap']);assert actual==completed['artifact_root']
   binary=returned['app.bin'];assert hashlib.sha256(binary).hexdigest()==result['artifact']['sha256'] and binary==Path(result['artifact']['path']).read_bytes()
  finally:c.close()
  (client.path/'artifact-received.ppm').write_bytes(client.ui.frame().ppm())
  print('PASS actual binary returned through guest graph transfer',role,len(binary),flush=True)
  result_path=Path(result['artifact']['path']).parent/'job.result.json'
  images=[]
  for node in nodes:
   images.extend(line.rsplit(' image ',1)[1] for line in (node.path/'guest.log').read_text().splitlines() if line.startswith('SESSION ') and ' image ' in line)
  assert len(images)==2 and len(set(images))==1,('actual guest images differ',images)
  record={'role':role,'image':images[0],'quote':{k:v for k,v in quote.items() if k!='contract'},'authority':{k:v for k,v in authority.items() if k!='contract'},'result':str(result_path),'artifact_root':actual,'artifact_bytes':len(binary),'artifact_sha256':hashlib.sha256(binary).hexdigest(),'source_root':head,'source_bytes':sum(map(len,files.values())),'unrelated_private_object_id':private,'native_actions':['F2 select exact source','F4 offer','F3 discover','F5 fetch source','F7 quote','F10 approve','F5 fetch actual result']}
  (output/'journey.json').write_text(json.dumps(record,indent=2)+'\n');return record
 finally:
  for node in nodes:
   try:node.stop()
   except BaseException:pass

def main():
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,default=ROOT/'build/remote-build-journey');p.add_argument('--package',type=Path);p.add_argument('--public',type=Path);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
 if not a.package:
  private=a.output/'publisher.pem';a.public=a.output/'publisher.pub';a.package=a.output/'native-forge.ltrel'
  if not private.exists():capsule.generate_key(private,a.public)
  data,manifest=releases.make(ROOT/'build/live/apps/native-forge.bin','native-forge','0.4.0',1919,private,sources=[ROOT/'Guest/Forge.lean',ROOT/'Guest/RemoteBuild.lean'],profile=2,source_base=ROOT)
  a.package.write_bytes(data);Path(str(a.package)+'.manifest.json').write_text(json.dumps(manifest))
 builder=single(a.output/'builder',a.package,a.public,'builder')
 verifier=single(a.output/'verifier',a.package,a.public,'verifier')
 assert builder['image']==verifier['image'],'builder/verifier guest platform identities differ'
 comparison=remote_build.compare(builder['result'],verifier['result'])
 report={'image':builder['image'],'executions':[builder,verifier],'verification':comparison,'hardware':'QEMU guest instances and separate host namespace compiler executions on same development host; no independent-operator/hardware claim'}
 (a.output/'journey.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
