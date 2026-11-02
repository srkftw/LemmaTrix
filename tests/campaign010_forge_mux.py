"""Real signed helper and 32-node Notes publication over explicit v2 bulk peers.

Guest UI performs selection, publication, retention, discovery and fetch. Only
initial source imports use the selected existing guest-signed public archives.
No remote-worker execution is claimed by this Forge transport test.
"""
import argparse,base64,hashlib,json,os,socket,struct,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import capsule,federation,forge,identity,network,projects,releases,server_store
from campaign010_forge_distribution import Node,PUBLIC,Client,digest
from campaign010_forge_continue import verify_closure,fetch
from forge_journey import wait
from forge_replication import save
from graphical_devices import DeviceInput
from creator_journey import rendered_text

class MuxNode(Node):
 def __init__(self,path,disk=None):
  self.path=path;path.mkdir(parents=True,exist_ok=True);self.sock=path/'portal.sock';self.qmp=path/'display.qmp';self.log=(path/'guest.log').open('wb');self.ui=None
  command=[str(ROOT/'lt'),'run','--socket',str(self.sock),'--graphics',str(self.qmp),'--network-mux']
  if disk:command+=['--server-store',str(disk)]
  self.proc=subprocess.Popen(command,cwd=ROOT,stdout=self.log,stderr=subprocess.STDOUT,start_new_session=True)
  wait(self.sock.exists,'fresh multiplexed personal/provider boot');self.ui=DeviceInput('qemu',self.qmp)
 def select(self,name):
  before=self.inspect()['selected_root']
  self.focus(self.instance)
  if rendered_text(self.ui.frame(),10,56,10,0x9fc6a5)=='FEDERATION':self.ui.press(59);time.sleep(.5)
  self.ui.press(60)
  def ready():
   f=self.ui.frame();rows=[rendered_text(f,32,107+i*12,len(name)+1).rstrip()for i in range(16)];return rows if name in rows else None
  rows=wait(ready,'native selected project rows',60)
  for _ in range(rows.index(name)):self.ui.press(108);time.sleep(.5)
  time.sleep(.5);self.ui.press(28)
  wait(lambda:(state if(state:=self.inspect())['status']==1 and state['selected_root']!=before else None),'new native selected project delivered to Forge',90)

def archive(path):
 doc=json.loads(path.read_text());rows=[dict(row,payload=base64.b64decode(row['payload'],validate=True))for row in doc['nodes']]
 root=doc['selected'][0];manifest=next(r['payload']for r in rows if r['id']==root['head'])
 release=next(r['payload']for r in rows if r['id']==next(i for name,kind,i in projects.decode_manifest(manifest)if kind==13 and not name.startswith('deps/')))
 offset=96+struct.unpack_from('<Q',release,16)[0]*128;envelope=release[offset:offset+608]
 assert len(envelope)==608 and struct.unpack_from('<Q',envelope,8)[0]==4
 return dict(path=str(path.resolve()),doc=doc,rows=rows,root=root,release=envelope[160:192].hex(),publication=envelope[128:160],publisher=envelope[576:608],facet=struct.unpack_from('<Q',envelope,384)[0])

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--resume-setup',action='store_true',help='resume preserved exact authenticated actors after setup-only failure')
 for field in ('image','archive','helper','identity','registry','forge','server-forge','output'):p.add_argument('--'+field,type=Path,required=True)
 a=p.parse_args();a.output=a.output.resolve();a.output.mkdir(parents=True,exist_ok=a.resume_setup);os.environ['LT_GUEST_IMAGE']=str(a.image.resolve())
 app,helper=archive(a.archive),archive(a.helper);assert len(app['rows'])>24 and app['facet']==1 and helper['facet']==2
 disk=a.output/'provider.img';(None if a.resume_setup else server_store.provision(disk));nodes=[];checks=[];phase='cold native setup';started=time.monotonic()
 report=dict(schema=1,result='running',image_sha256=hashlib.sha256(a.image.read_bytes()).hexdigest(),sdk_changed=False,checks=checks,limitations=['QEMU guests with independent state on one Linux x86-64 host.','Signed endpoint descriptors and first-party service packages use explicit legacy RSA bootstrap; project release and operator keys/signatures remain guest-owned Ed25519.','RemoteBuild v2 wrappers typecheck, but this test executes Forge transfers, not a remote compiler.'])
 def write():
  report.update(phase=phase,elapsed_seconds=round(time.monotonic()-started,3),live_actors=[dict(pid=n.proc.pid,socket=str(n.sock),graphics=str(n.qmp),forge=getattr(n,'instance',None),registry=getattr(n,'registry',None),image=str(a.image.resolve()))for n in nodes]);(a.output/'execution.json').write_text(json.dumps(report,indent=2)+'\n')
 def progress(label):
  nonlocal phase
  phase=label;write();print('PROGRESS',label,flush=True)
 def passed(label,**values):checks.append(dict(check=label,result='pass',**values));write();print('PASS',label,flush=True)
 def actor(label,disk=None):
  n=MuxNode(a.output/label,disk);nodes.append(n);write();return n
 def relation(label,client_id):
  path=a.output/label;path.mkdir();key,pub=path/'endpoint.pem',path/'endpoint.pub';capsule.generate_key(key,pub)
  probe=socket.socket();probe.bind(('127.0.0.1',0));endpoint='127.0.0.1:'+str(probe.getsockname()[1]);probe.close()
  description=path/'service.public';meta=network.create_description(key,client_id,endpoint,'forge',description,hashlib.sha256(a.image.read_bytes()).digest())
  client,server=path/'client.credential',path/'server.credential';network.provision(client,server,client_id,bytes.fromhex(meta['server_id']),bytes.fromhex(meta['service_id']))
  return client,server,description
 def link(provider,client,credentials,provider_slot=0):
  ck,sk,desc=credentials
  with provider.client()as c:network.configure(c,sk,desc,slot=provider_slot);network.call(c,13,slot=provider_slot)
  with client.client()as c:network.configure(c,ck,desc,slot=0);network.call(c,13,slot=0)
  def ready():
   states=[]
   for node,slot in ((provider,provider_slot),(client,0)):
    with node.client()as c:states.append(network.status(c,slot=slot))
   return states if all(s['endpoint_authenticated']for s in states)else None
  return wait(ready,'explicit signed v2 bulk peers authenticate',180)
 def forge_setup(n,package,credential,role='client',slot=0):
  n.install(package,PUBLIC)
  grant=0
  with n.client()as c:
   if role!='client':server_store.call(c,230);grant=server_store.call(c,231,n.instance,2,1048576,digest('Campaign010 MUX helper graph'))[0][1]
   forge.configure(c,n.instance,credential,role,'portable',grant,peer_slot=slot,stream=1)
  return grant
 def registry(n,configuration=None):
  with n.client()as c:
   if configuration is None:service=identity.start(c,a.identity,PUBLIC)
   raw=a.registry.read_bytes();c.request(10,raw[128:160]+releases.public_key(PUBLIC));slot,_=c.install(a.registry);n.registry=struct.unpack_from('<Q',c.request(25,struct.pack('<Q',slot)),8)[0]
   if configuration is None:
    server_store.call(c,230);grant=server_store.call(c,231,n.registry,1,1048576,digest('Campaign010 MUX native catalog'))[0][1]
    configuration=federation.configure_native(c,n.registry,'consumer',service['release'],releases.inspect(raw)['release_id'],store_grant=grant,allowed_rights=895)
    for item in (helper,app):federation.call(c,n.registry,3,data=item['publication']+item['publisher'])
   else:federation.configure_native_verifier(c,n.registry,configuration['public_key'],'consumer',allowed_rights=895,generation=configuration['generation'])
   forge.federation_configure(c,n.instance,configuration['federation_id'],3)
  n.configuration=configuration;write();return configuration
 def decision(n,item,local=False):
  with n.client()as c:r=forge.federation_inspect(c,n.instance,local)
  return r if r['descriptor']['release_id']==item['release']and(r['local_phase']==2 if local else r['remote_phase']in(2,3))else None
 def import_source(n,item):
  with n.client()as c:
   root=projects.import_records(c,item['doc']['selected'],item['rows'])[0]['cap'];shell=struct.unpack_from('<Q',c.request(2),4*32)[0];c.objects(27,root,shell,127)
  n.select(item['root']['name']);n.ui.press(87)
 try:
  if a.resume_setup:
   prior=json.loads((a.output/'execution.json').read_text());assert not prior['checks'],'setup-only continuation must not discard initialized native authority'
   for label,row in zip(('provider','source'),prior['live_actors']):
    n=object.__new__(MuxNode);n.path=a.output/label;n.sock=Path(row['socket']);n.qmp=Path(row['graphics']);n.log=(n.path/'guest.log').open('ab');n.ui=DeviceInput('qemu',n.qmp);n.proc=type('Existing',(),{'pid':row['pid'],'poll':lambda self:None})()
    nodes.append(n)
   provider,source=nodes;path=a.output/'source-provider';keys=(path/'client.credential',path/'server.credential',path/'service.public')
   with provider.client()as c:
    for who,state,rights,_ in identity.instances(c):
     if who&255>=7 and 0<state<5:c.request(26,struct.pack('<Q',who))
   provider.ui.press(1)
   ready=[]
   for n in nodes:
    with n.client()as c:ready.append(network.status(c,slot=0))
  else:
   provider=actor('provider',disk);source=actor('source');keys=relation('source-provider',digest('Campaign010 MUX source'));ready=link(provider,source,keys)
  forge_setup(provider,a.server_forge,keys[1],'registry');forge_setup(source,a.forge,keys[0]);configuration=registry(provider);registry(source,configuration)
  passed('fresh explicit v2 bulk relationship authenticates with independently selected signed endpoint',endpoints=ready,peer_slots=[0,0],stream=1)
  for item in (helper,app):
   progress('native network publication '+item['root']['name']);import_source(source,item)
   accepted=wait(lambda:decision(source,item),'exact native publication decision over multiplex transport',300)
   local=wait(lambda:decision(provider,item,True),'provider actual signed closure and decision',180)
   expected=1 if item['facet']==2 else 2;assert accepted['classification']==expected and local['descriptor']['classification']==expected
   exact=verify_closure(provider,item['doc']);(a.output/(item['root']['name']+'-admission.json')).write_text(json.dumps(accepted,indent=2)+'\n')
   provider.focus(provider.instance)
   if item is app:
    with provider.client()as c:
     grant=server_store.call(c,231,provider.instance,2,1048576,digest('Campaign010 MUX Notes32 graph'))[0][1]
     raw=c.request(150,struct.pack('<Q8Q',provider.instance,61,0,grant,0,0,0,0,1));assert struct.unpack_from('<Q',raw)[0]==0
   stored=save(provider)
   passed('separately published source-only helper'if item is helper else 'actual32-node successor published and retained without widening application profile',release=item['release'],transfer=exact,decision=accepted,retention=stored)
  # Retire only this completed Forge process, not the native Registry or its
  # catalog. Its fresh incarnation selects a different approved bulk peer.
  progress('fresh second personal user retrieves the actual32-node provider closure')
  if a.resume_setup:
   with source.client()as c:
    try:c.request(70)
    except EOFError:pass
   source.ui.close();source.log.close()
  else:source.stop()
  nodes.remove(source)
  with provider.client()as c:c.request(26,struct.pack('<Q',provider.instance));provider.instance=struct.unpack_from('<Q',c.request(25,struct.pack('<Q',1)),8)[0]
  reader=actor('reader');second=relation('reader-provider',digest('Campaign010 MUX second user'));ready=link(provider,reader,second,1)
  with provider.client()as c:forge.configure(c,provider.instance,second[1],'seed','portable',peer_slot=1,stream=1);forge.federation_configure(c,provider.instance,configuration['federation_id'],3)
  forge_setup(reader,a.forge,second[0]);registry(reader,configuration)
  provider.focus(provider.instance);root=next(r for r in provider.roots()if r['head']==app['root']['head']);provider.select(root['name']);provider.ui.press(62)
  wait(lambda:provider.inspect()['offered_nodes']==len(app['rows']),'native exact32-node offer',180)
  result=fetch(provider,reader,app['doc'])
  passed('fresh second user fetches and validates every actual32-node successor object through v2 bulk transport',transfer=result,endpoints=ready)
  report['result']='pass';write();print('PASS COMPLETE',flush=True)
 except BaseException as exc:
  report.update(result='fail',error=repr(exc));write()
  for n in nodes:
   try:(n.path/'failure.ppm').write_bytes(n.ui.frame().ppm())
   except Exception:pass
  raise
 finally:
  # Preserve exact native actors for real UI diagnosis and coexistence followup.
  for n in nodes:
   if n.ui:n.ui.close();n.ui=None
   n.log.close()

if __name__=='__main__':main()
