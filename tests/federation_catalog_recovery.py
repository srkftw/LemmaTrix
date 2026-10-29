"""Discover signed metadata from a registry's own recovered catalog, without seed content.

The test reuses an explicitly selected existing operator store/namespace. It
never copies that backing or replays graph fixtures into either guest.
"""
import argparse,hashlib,json,os,socket,struct,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import capsule,forge,live,network,nodes,releases,projects
from creator_journey import rendered_text
from federation_forge import install_registry,admission
from federation_node import HeadlessRegistryNode
from forge_journey import Node,wait

def start_recovered(output,source,endpoint,credential,package,public,image):
 output.mkdir(parents=True,exist_ok=False)
 server=HeadlessRegistryNode.__new__(HeadlessRegistryNode)
 server.path=output;server.sock=output/'portal.sock';server.ui=None;server.proc=None;server.log=None;server.config=output/'node.json'
 primary=releases.inspect(package.read_bytes());secondary=source['registry']
 command=[str(ROOT/'lt'),'node','init',str(server.config),'--role','registry','--package',str(package),'--public',str(public),'--release-id',primary['release_id'],'--rights','1151','--credentials',str(credential),'--store',source['server_store'],'--namespace',source['namespace'],'--bytes',str(source['bytes']),'--endpoint',endpoint,'--listen','--registry-package',secondary['package'],'--registry-public',secondary['publisher_public'],'--registry-release-id',secondary['release_id'],'--registry-rights','2175','--federation-public',secondary['federation_public'],'--federation-policy',secondary['policy']]
 result=subprocess.run(command,cwd=ROOT,capture_output=True,text=True,check=True);(output/'initialized.json').write_text(result.stdout)
 server.log=(output/'guest.log').open('wb')
 server.proc=subprocess.Popen([str(ROOT/'lt'),'node','run',str(server.config),'--socket',str(server.sock),'--image',str(image),'--recover-catalog'],cwd=ROOT,stdout=server.log,stderr=subprocess.STDOUT,start_new_session=True)
 def started():
  text=(output/'guest.log').read_text()
  if server.proc.poll() is not None:raise AssertionError(('normal node recovery failed',text))
  return '"headless": true' in text
 wait(started,'normal role startup recovered its own signed catalog',180)
 c=server.client()
 try:
  table=c.request(2);active=[struct.unpack_from('<4Q',table,i) for i in range(0,len(table),32)];active=[r for r in active if 7<=r[0]&255<12 and 0<r[1]<5]
  assert [r[2] for r in active]==[1151,2175],active
  server.instance,server.registry_instance=active[0][0],active[1][0]
  catalog=nodes.catalog(c,server.registry_instance);assert catalog['entries'] and not projects.roots(c)
 finally:c.close()
 return server,catalog

def main():
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--image',type=Path,required=True);p.add_argument('--source-node',type=Path,required=True);p.add_argument('--expected-root',required=True);p.add_argument('--gui-binary',type=Path,required=True);p.add_argument('--server-binary',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False);os.environ['LT_GUEST_IMAGE']=str(a.image.resolve());source=json.loads(a.source_node.read_text());backing=Path(source['server_store']);before=hashlib.sha256(backing.read_bytes()).hexdigest()
 _,old=network.load_credentials(Path(source['credentials']));clientcred,servercred=a.output/'reader.credential',a.output/'registry.credential';network.provision(clientcred,servercred,os.getrandom(32),old[32:64],hashlib.sha256(b'Forge explicit recovered metadata service').digest())
 key,public=a.output/'operator.pem',a.output/'operator.pub';capsule.generate_key(key,public)
 packages=[]
 for name,binary,rights in [('native-forge',a.gui_binary,1919),('forge-server',a.server_binary,1151)]:
  data,_=releases.make(binary,name,'0.4.2',rights,key,profile=2);path=a.output/(name+'.ltrel');path.write_bytes(data);packages.append(path)
 probe=socket.socket();probe.bind(('127.0.0.1',0));endpoint=f'127.0.0.1:{probe.getsockname()[1]}';probe.close();server=reader=None
 try:
  server,catalog=start_recovered(a.output/'registry',source,endpoint,servercred,packages[1],public,a.image)
  assert any(r['descriptor']['root']==a.expected_root for r in catalog['entries'])
  reader=Node(a.output/'reader',endpoint);c=reader.client()
  try:network.configure(c,clientcred)
  finally:c.close()
  def authenticated():
   for node in (server,reader):
    c=node.client()
    try:
     if not network.status(c)['endpoint_authenticated']:return False
    finally:c.close()
   return True
  wait(authenticated,'fresh reader/restarted registry authentication',180)
  reader.install(packages[0],public);c=reader.client()
  try:forge.configure(c,reader.instance,clientcred)
  finally:c.close()
  secondary=source['registry'];install_registry(reader,Path(secondary['package']),Path(secondary['publisher_public']),Path(secondary['federation_public']),secondary['policy'])
  reader.ui.press(61)
  record=wait(lambda:(r if (r:=admission(reader))['remote_phase']==2 and r['descriptor']['root']==a.expected_root else None),'native F3 verifies recovered signed listing',180)
  state=reader.inspect();assert state['metadata_nodes']==0 and state['metadata_bytes']==0 and not reader.roots() and not server.roots(),state
  reader.ui.press(63);wait(lambda:reader.inspect()['status']==15,'native metadata-only listing denies unavailable Fetch',120)
  assert not reader.inspect()['import_transaction'] and not reader.roots() and not server.roots()
  reader.ui.press(59)
  frame=wait(lambda:(f if rendered_text((f:=reader.ui.frame()),60,278,len('METADATA ONLY - CHOOSE SEED'),0xe9bc75)=='METADATA ONLY - CHOOSE SEED' else None),'native availability denial rendered',120)
  (reader.path/'metadata-only.ppm').write_bytes(frame.ppm())
  report=dict(image=hashlib.sha256(a.image.read_bytes()).hexdigest(),root=a.expected_root,federation=record['descriptor']['federation_id'],signed_listing=record,metadata_nodes=0,metadata_bytes=0,graph_roots_on_registry=0,graph_roots_on_reader=0,fetch_denied_without_import=True,normal_operator_recovery=True,backing_sha256=before,store_unchanged=hashlib.sha256(backing.read_bytes()).hexdigest()==before,source_store=str(backing),environment='separate QEMU registry/reader guests on one development host; existing operator store reopened without fixture replay')
  assert report['store_unchanged'];(a.output/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
 finally:
  for node in (reader,server):
   if node:node.stop()
if __name__=='__main__':main()
