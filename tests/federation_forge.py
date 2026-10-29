"""Physical Forge publication, chosen-federation metadata and native Fetch.

Only the creator imports the explicitly selected already signed public bundle.
The recipient's actual content must arrive over the encrypted guest protocol.
"""
import argparse,base64,hashlib,json,os,socket,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import capsule,federation,forge,network,projects,releases
from creator_journey import rendered_text
from forge_journey import Node,wait
from federation_node import HeadlessRegistryNode

def admission(node,local=False):
 c=node.client()
 try:return forge.federation_inspect(c,node.instance,local)
 finally:c.close()

def install_registry(node,package,public,fedpublic,policy):
 c=node.client()
 try:
  raw=package.read_bytes();c.request(10,raw[128:160]+releases.public_modulus(public))
  slot,_=c.install(package)
  instance=struct.unpack_from('<Q',c.request(25,struct.pack('<Q',slot)),8)[0]
  configuration=federation.configure(c,instance,fedpublic,policy)
  forge.federation_configure(c,node.instance,configuration['federation_id'],1 if policy=='portable' else 2)
  return instance
 finally:c.close()

def single(output,forge_package,server_package,registry_package,operator_public,archive,publisher_public,policy,image):
 output.mkdir(parents=True,exist_ok=True);nodes=[]
 probe=socket.socket();probe.bind(('127.0.0.1',0));port=probe.getsockname()[1];probe.close();endpoint=f'127.0.0.1:{port}'
 credentials=[output/'creator.credential',output/'registry.credential']
 service=hashlib.sha256(b'LT chosen federation native journey '+policy.encode()).digest()
 server_id=os.getrandom(32);network.provision(*credentials,os.getrandom(32),server_id,service)
 fedkey=output/'federation.pem';fedpublic=output/'federation.pub';capsule.generate_key(fedkey,fedpublic)
 try:
  server=HeadlessRegistryNode(output/'registry',endpoint,credentials[1],server_package,registry_package,operator_public,fedpublic,policy,image);nodes.append(server)
  creator=Node(output/'creator',endpoint);nodes.append(creator)
  c=creator.client()
  try:network.configure(c,credentials[0])
  finally:c.close()
  def authenticated(pair):
   checks=[]
   for node in pair:
    c=node.client()
    try:checks.append(network.status(c)['endpoint_authenticated'])
    finally:c.close()
   return all(checks)
  wait(lambda:authenticated([creator,server]),'creator/registry Noise peers',120)
  creator.install(forge_package,operator_public)
  c=creator.client()
  try:forge.configure(c,creator.instance,credentials[0])
  finally:c.close()
  install_registry(creator,registry_package,operator_public,fedpublic,policy)
  selected=archive['selected'];head=selected[0]['head'];logical=archive['project_id']
  records=[dict(r,payload=base64.b64decode(r['payload'],validate=True)) for r in archive['nodes']]
  c=creator.client()
  try:
   root=projects.import_records(c,selected,records)[0]['cap']
   assert projects.project_identity(c,root)==logical
   shell=struct.unpack_from('<Q',c.request(2),4*32)[0];c.objects(27,root,shell,127)
  finally:c.close()
  publisher=releases.public_modulus(publisher_public)
  publication=releases.publication(logical,hashlib.sha256(publisher).hexdigest())
  c=server.client()
  try:federation.call(c,server.registry_instance,3,data=publication+publisher)
  finally:c.close()
  assert not server.roots(),'registry received source before native publication'
  creator.select(selected[0]['name']);creator.ui.press(87)
  local=wait(lambda:(r if (r:=admission(server,True))['local_phase']==1 else None),'creator F11 uploads exact source; headless registry admits after native import',240)
  expected=2 if policy=='portable' else 3
  assert local['descriptor']['classification']==expected and local['descriptor']['root']==head,local
  assert not local['descriptor']['signature_present'],'unsigned decision falsely presented signed'
  assert any(r['head']==head for r in server.roots()),'admission preceded actual graph arrival'
  creator.ui.press(61);wait(lambda:creator.inspect()['metadata_nodes'],'unsigned metadata returned to publisher')
  before=len(creator.roots());creator.ui.press(63)
  wait(lambda:creator.inspect()['status']==14,'chosen federation blocks unsigned Fetch')
  assert len(creator.roots())==before and not creator.inspect()['import_transaction']
  c=server.client()
  try:signed=federation.sign_once(c,server.registry_instance,fedkey,policy)
  finally:c.close()
  assert signed['listing']==expected
  own_decision=wait(lambda:(r if (r:=admission(creator))['remote_phase'] in (2,3) and r['descriptor']['signature_present'] else None),'actual signed publication receipt travels through messages9/10',180)
  assert own_decision['classification']==expected and own_decision['descriptor']['root']==head
  (creator.path/'publication-receipt.ppm').write_bytes(creator.ui.frame().ppm())
  print('PASS physical creator F11 / headless native import / signed policy',policy,flush=True)
  # A fresh reader is a separately authorized pairwise relationship. The old
  # publisher disappears; no keys, handles or execution approvals cross over.
  creator.stop();nodes.remove(creator)
  reader_credentials=[output/'reader.credential',output/'reader-registry.credential']
  network.provision(*reader_credentials,os.getrandom(32),server_id,service)
  c=server.client()
  try:
   network.configure(c,reader_credentials[1])
   forge.configure(c,server.instance,reader_credentials[1],'registry')
  finally:c.close()
  recipient=Node(output/'recipient',endpoint);nodes.append(recipient)
  c=recipient.client()
  try:network.configure(c,reader_credentials[0])
  finally:c.close()
  wait(lambda:authenticated([recipient,server]),'fresh recipient/registry Noise relationship',120)
  recipient.install(forge_package,operator_public)
  c=recipient.client()
  try:forge.configure(c,recipient.instance,reader_credentials[0])
  finally:c.close()
  install_registry(recipient,registry_package,operator_public,fedpublic,policy)
  assert not recipient.roots(),'new recipient was preloaded with final graph'
  recipient.ui.press(61)
  decision=wait(lambda:(r if (r:=admission(recipient))['remote_phase'] in (2,3) and r['descriptor']['signature_present'] else None),'fresh recipient discovers actual signed federation result',180)
  assert decision['classification']==expected and decision['descriptor']['root']==head,decision
  assert decision['descriptor']['publisher_key_id']==hashlib.sha256(publisher).hexdigest()
  assert not recipient.roots(),'signed metadata granted graph content'
  def rendered():
   frame=recipient.ui.frame()
   # Application surfaces begin below the48-pixel trusted compositor chrome.
   if rendered_text(frame,10,56,34,0x9fc6a5).rstrip()!='FEDERATION ADMISSION / F1 RETURN':return None
   if rendered_text(frame,70,118,2,0xe9bc75)!=f'{decision["remote_phase"]:02x}':return None
   if rendered_text(frame,130,118,2,0xe9bc75)!=f'{expected:02x}':return None
   if rendered_text(frame,10,268,16,0xe9bc75)!=f'{decision["descriptor"]["rights"]:016x}':return None
   return frame
  frame=wait(rendered,'actual native signed authority rendered',120)
  (recipient.path/'admission.ppm').write_bytes(frame.ppm())
  recipient.ui.press(63)
  if expected==2:
   wait(lambda:recipient.inspect()['status']==11,'verified native Fetch commits actual signed project',240)
   roots=recipient.roots();assert len(roots)==1 and roots[0]['head']==head,roots
   c=recipient.client()
   try:
    found=[];cursor=0
    while True:
     fields,payload=c.objects(26,roots[0]['cap'],cursor)
     if not fields[1]:break
     found.append(payload[:32].hex());cursor=fields[3]
    assert set(found)==set(r['id'] for r in records),('received closure differs',found)
    try:c.request(29,publication)
    except ValueError:pass
    else:raise AssertionError('federation admission granted local execution')
   finally:c.close()
   outcome='fresh recipient fetched actual14-node signed graph after publisher exit; local execution still unapproved'
  else:
   wait(lambda:recipient.inspect()['status']==14,'restricted policy denies native Fetch')
   assert not recipient.roots() and not recipient.inspect()['import_transaction']
   assert any(r['head']==head for r in server.roots()),'rejected listing corrupted portable project'
   outcome='signed policy rejection shown; no graph imported; portable project remains usable on registry'
  record={'policy':policy,'root':head,'logical_project':logical,'federation':signed['federation'],'classification':expected,'reason':decision['reason'],'signature_checked_in_guest':True,'unsigned_fetch_denied':True,'registry_source_received_only_through_network':True,'registry_started_through_normal_node_commands':True,'publisher_offline_before_new_recipient':True,'metadata_only_until_explicit_fetch':True,'publisher':decision['descriptor']['publisher_key_id'],'rights':decision['descriptor']['rights'],'source_commitment':decision['descriptor']['source_commitment'],'evidence_commitment':decision['descriptor']['evidence_commitment'],'outcome':outcome,'local_execution_approved':False,'native_actions':['F2 select exact recovered revision','creator F11 publication','headless authorized upload/import/admission','F3 metadata','F5 unsigned denied','fresh recipient F3 discovery','F1 signed authority view','F5 chosen policy enforced']}
  (output/'journey.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record),flush=True);return record
 finally:
  for node in nodes:
   try:node.stop()
   except BaseException:pass

def main():
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--image',type=Path,required=True);p.add_argument('--public-graph',type=Path,default=ROOT/'build/signed-forge-journey-2/published-closure.json');p.add_argument('--publisher',type=Path,default=ROOT/'build/signed-forge-journey-2/publisher.pub');p.add_argument('--packages',type=Path,help='reuse exact already signed role packages and operator.pub');a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False);os.environ['LT_GUEST_IMAGE']=str(a.image.resolve())
 archive=json.loads(a.public_graph.read_text());operator=a.output/'operator.pem';public=(a.packages/'operator.pub') if a.packages else a.output/'operator.pub'
 if not a.packages:capsule.generate_key(operator,public)
 packages=[]
 for name,rights in [('native-forge',1919),('forge-server',1151),('native-registry',2175)]:
  if a.packages:
   package=a.packages/f'{name}.ltrel';assert releases.inspect(package.read_bytes())['rights']==rights;packages.append(package);continue
  data,manifest=releases.make(ROOT/f'build/live/apps/{name}.bin',name,'0.4.0',rights,operator,profile=2)
  package=a.output/f'{name}.ltrel';package.write_bytes(data);Path(str(package)+'.manifest.json').write_text(json.dumps(manifest));packages.append(package)
 records=[single(a.output/policy,*packages,public,archive,a.publisher,policy,a.image) for policy in ('portable','restricted')]
 assert records[0]['root']==records[1]['root'] and records[0]['federation']!=records[1]['federation']
 report={'image':hashlib.sha256(a.image.read_bytes()).hexdigest(),'protocol':'Forge graph1 + admission1 (messages9/10), RegistrySDK1','environment':'isolated QEMU guests; separate federation configurations on one development host; disclosed signer bootstrap','checks':records}
 (a.output/'journey.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
