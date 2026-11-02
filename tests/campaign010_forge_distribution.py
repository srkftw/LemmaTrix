"""Native Notes release admission, Forge publication and surviving seed fetch.

Initial setup imports only the selected public guest-signed export through the
normal graph importer. Native UI selects, offers, publishes, fetches and retains;
all later seed content comes from encrypted guest-to-guest Forge transfers.
"""
import argparse, base64, hashlib, json, os, socket, struct, sys, time
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import federation, forge, identity, live, network, projects, releases, server_store
from creator_journey import rendered_text
from durable_signed_releases import Seed, transfer
from forge_journey import wait
from forge_replication import authenticate, save
from signed_forge_journey import ClientNode

PUBLIC=ROOT/'tests/keys/development-rsa-public.pem'

class Client(live.Client):
 def __enter__(self):return self
 def __exit__(self,*args):self.close()


def digest(label):return hashlib.sha256(label.encode()).digest()


class Node(Seed):
 server_package=None
 def client(self):return Client(self.sock,timeout=300)
 def select(self,name):
  self.focus(self.instance)
  if rendered_text(self.ui.frame(),10,56,10,0x9fc6a5)=='FEDERATION':
   self.ui.press(59)
   wait(lambda:rendered_text(self.ui.frame(),10,56,5,0xd8e6ed)=='FORGE','return from native admission review')
  return super().select(name)
 def setup_link(self,package,credential,namespace=None,recover=False,role='client'):
  self.install(self.server_package if namespace else package,PUBLIC)
  with self.client() as c:
   network.configure(c,credential)
   grant=0
   if namespace:
    server_store.call(c,230)
    grant=server_store.call(c,231,self.instance,2,1048576,namespace)[0][1]
   forge.configure(c,self.instance,credential,role,'portable',grant,recover)
  (self.path/'live-runtime.json').write_text(json.dumps(dict(schema=1,live_only=True,pid=self.proc.pid,socket=str(self.sock),graphics=str(self.qmp),forge=self.instance,role=role,credential_path=str(credential.resolve()),store_grant=grant,store_namespace=namespace.hex()if namespace else None),indent=2)+'\n')
  return grant


def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('image','archive','identity','registry','forge','server-forge','output'):p.add_argument('--'+name,type=Path,required=True)
 p.add_argument('--helper-archive',type=Path)
 p.add_argument('--keep-on-failure',action='store_true',help='leave exact native actors running and release UI clients for public-interface diagnosis/continuation')
 a=p.parse_args();a.output=a.output.resolve();a.output.mkdir(parents=True,exist_ok=False)
 os.environ['LT_GUEST_IMAGE']=str(a.image.resolve())
 Node.server_package=a.server_forge
 document=json.loads(a.archive.read_bytes())
 records=[dict(n,payload=base64.b64decode(n['payload'],validate=True)) for n in document['nodes']]
 selected=document['selected'][0];head=selected['head'];name=selected['name']
 release_node=next(n['payload'] for n in records if n['kind']==13 and n['id']==next(i for path,kind,i in projects.decode_manifest(next(n['payload']for n in records if n['id']==head)) if kind==13 and not path.startswith('deps/')))
 count=struct.unpack_from('<Q',release_node,16)[0];start=96+count*128;header=release_node[start:start+608]
 assert len(header)==608 and struct.unpack_from('<Q',header,8)[0]==4
 publisher=header[576:608];publication=header[128:160];release_id=header[160:192].hex()
 identity_info=releases.inspect(a.identity.read_bytes());registry_info=releases.inspect(a.registry.read_bytes())
 detail=release_node[32+count*128:];manifest_length=struct.unpack_from('<Q',detail,24)[0]
 signed_manifest=json.loads(detail[64+608:64+608+manifest_length])
 disks=[a.output/'alpha.img',a.output/'seed.img',a.output/'beta.img']
 for disk in disks:server_store.provision(disk)
 nodes=[];checks=[];started=time.monotonic();stage='setup'
 record=dict(schema=1,result='running',scope=__doc__,image_sha256=hashlib.sha256(a.image.read_bytes()).hexdigest(),archive_sha256=hashlib.sha256(a.archive.read_bytes()).hexdigest(),release_id=release_id,checks=checks,commands=[],limitations=['Local independently initialized guest state on one x86-64 Linux host; no independent security administration or public deployment claim.','Legacy first-party package bootstrap remains explicitly RSA; release/admission authority is native guest Ed25519.'])
 record.update(services={n:dict(path=str(path.resolve()),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),release_id=releases.inspect(path.read_bytes())['release_id'])for n,path in [('identity',a.identity),('registry',a.registry),('forge',a.forge),('server_forge',a.server_forge)]},sdk=signed_manifest['sdk'],dependencies=signed_manifest['dependencies'],recipe=signed_manifest['recipe'],source=signed_manifest['provenance'],artifact_sha256=header[192:224].hex())
 def write():
  record['elapsed_seconds']=round(time.monotonic()-started,3);record['stage']=stage
  (a.output/'execution.json').write_text(json.dumps(record,indent=2)+'\n')
 def passed(label,**fields):checks.append(dict(check=label,result='pass',**fields));write();print('PASS',label,flush=True)
 def progress(label):
  nonlocal stage
  stage=label;write();print('PROGRESS',label,flush=True)
 def relation(label,client_id,server_id):
  path=a.output/label;path.mkdir();s=socket.socket();s.bind(('127.0.0.1',0));port=s.getsockname()[1];s.close()
  client,server=path/'client.credential',path/'server.credential'
  network.provision(client,server,client_id,server_id,digest('Campaign010 public Forge '+label))
  return client,server,f'127.0.0.1:{port}'
 def actor(label,endpoint,listen=False,disk=None):
  n=Node(a.output/label,endpoint,listen,disk);nodes.append(n)
  record['commands'].append(dict(actor=label,backend='QEMU RV64',image=str(a.image.resolve()),endpoint=endpoint,listen=listen,store=str(disk)if disk else None));write();return n
 def stop_all():
  while nodes:
   n=nodes.pop()
   try:n.stop()
   except (OSError,EOFError,ValueError):pass
 def start_registry(n,policy,allowed=None,namespace='catalog',recover=None,credential=None):
  with n.client() as c:
   service=identity.start(c,a.identity,PUBLIC)
   raw=a.registry.read_bytes();c.request(10,raw[128:160]+releases.public_key(PUBLIC));slot,_=c.install(a.registry)
   instance=struct.unpack_from('<Q',c.request(25,struct.pack('<Q',slot)),8)[0]
   server_store.call(c,230)
   grant=server_store.call(c,231,instance,1,1048576,digest('Campaign010 '+namespace))[0][1]
   if recover:
    configured=federation.recover_native(c,instance,credential,recover,service['release'],registry_info['release_id'],store_grant=grant)
   else:
    configured=federation.configure_native(c,instance,policy,service['release'],registry_info['release_id'],store_grant=grant,allowed_rights=allowed)
    federation.call(c,instance,3,data=publication+publisher)
  n.registry=instance;n.configuration=configured;n.catalog_grant=grant
  (n.path/'live-registry.json').write_text(json.dumps(dict(schema=1,live_only=True,configuration=configured,store_namespace=namespace),indent=2)+'\n')
  return configured
 def verifier(n,configuration,policy='consumer',allowed=895,namespace=None,recover=False):
  with n.client() as c:
   raw=a.registry.read_bytes();c.request(10,raw[128:160]+releases.public_key(PUBLIC));slot,_=c.install(a.registry)
   n.registry=struct.unpack_from('<Q',c.request(25,struct.pack('<Q',slot)),8)[0]
   grant=0
   if namespace:
    server_store.call(c,230);grant=server_store.call(c,231,n.registry,1,1048576,digest('Campaign010 '+namespace))[0][1]
   federation.configure_native_verifier(c,n.registry,configuration['public_key'],policy,allowed_rights=allowed,generation=configuration['generation'],store_grant=grant)
   if recover:
    restored=federation.call(c,n.registry,10)[0][1]
    if not restored:raise AssertionError('independent seed lost retained admission evidence')
   forge.federation_configure(c,n.instance,configuration['federation_id'],{'portable':1,'restricted':2,'consumer':3}[policy])
 def publication_result(n,remote=True,expected_release=release_id):
  with n.client() as c:
   result=forge.federation_inspect(c,n.instance,not remote)
  if result['descriptor']['release_id']!=expected_release:return None
  if remote:
   return result if result['remote_phase']in(2,3) else None
  return result if result['local_phase']==2 else None
 def offer(n):
  n.focus(n.instance);n.select(name);n.ui.press(62)
  return wait(lambda:(s if(s:=n.inspect())['offered_nodes'] else None),'native exact release offer',180)
 def direct_admit(n,root):
  with n.client() as c:
   delegated=c.objects(27,root,n.registry,25)[0][1]
   q,_=federation.call(c,n.registry,2,h=delegated)
   slot=q[2]
  def done():
   with n.client() as c:q,raw=federation.call(c,n.registry,7,h=slot)
   if q[1]>2:raise AssertionError(('native admission failed',q))
   return raw if q[1]==2 else None
  return wait(done,'native independent policy decision',180)
 def install_notes(n):
  n.focus(n.instance)
  with n.client() as c:
   c.request(10,publication+publisher)
   try:c.request(29,publication)
   except ValueError:pass
   else:raise AssertionError('Forge fetch granted execution without approval')
  n.ui.press(64)
  frame=wait(lambda:(f if rendered_text(f:=n.ui.frame(),16,12,24)=='SIGNED PACKAGE CANDIDATE'else None),'actual fetched Notes release approval',180)
  assert rendered_text(frame,80,40,len('project-notes'))=='project-notes'
  (n.path/'exact-notes-approval.ppm').write_bytes(frame.ppm());time.sleep(.4);n.ui.press(28)
  def running():
   with n.client() as c:
    try:active=c.request(29,publication)
    except ValueError:return None
   return active if active[160:192].hex()==release_id else None
  wait(running,'exact fetched native release activated',180)
  frame=wait(lambda:(f if rendered_text(f:=n.ui.frame(),14,56,len('Project Notes'),0xdce9ec)=='Project Notes'else None),'ordinary native Notes application surface',120)
  (n.path/'project-notes-running.ppm').write_bytes(frame.ppm())
  n.ui.textASCII('Distribution review',delay=.08);n.ui.press(28)
  n.ui.textASCII('Verified the surviving provider supplied the signed source and helper.',delay=.08)
  n.ui.chord(29,31)
  wait(lambda:rendered_text(n.ui.frame(),14,354,len('Saved immutable revision'),0xdce9ec)=='Saved immutable revision','second user native note revision saved',90)
  n.ui.chord(29,33);n.ui.textASCII('surviving',delay=.08);n.ui.press(28);n.ui.press(1)
  frame=wait(lambda:(f if rendered_text(f:=n.ui.frame(),18,170,len('Verified the surviving provider'),0xdce9ec)=='Verified the surviving provider'else None),'second user searches actual note content',90)
  (n.path/'project-notes-used.ppm').write_bytes(frame.ppm())
  return frame.digest
 try:
  # One source relationship, one independently signing federation/provider.
  stage='native Alpha publication'
  client_key,alpha_key,endpoint=relation('source-alpha',digest('source'),digest('alpha'))
  alpha=actor('alpha',endpoint,True,disks[0]);source=actor('source',endpoint)
  alpha.setup_link(a.forge,alpha_key,digest('Campaign010 alpha graph'),role='registry')
  source.setup_link(a.forge,client_key);authenticate(source,alpha)
  progress('Alpha link authenticated; initialize independent native operator')
  alpha_config=start_registry(alpha,'consumer',895,'alpha catalog')
  verifier(source,alpha_config)
  with alpha.client() as c:forge.federation_configure(c,alpha.instance,alpha_config['federation_id'],3)
  with source.client() as c:
   root=projects.import_records(c,document['selected'],records)[0]['cap']
   shell=struct.unpack_from('<Q',c.request(2),4*32)[0];c.objects(27,root,shell,127)
  progress('Exact signed Notes graph imported; native Forge publication requested')
  source.select(name);source.ui.press(87)
  admitted=wait(lambda:publication_result(source),'Forge F11 exact native federation publication',300)
  assert admitted['classification']==2 and admitted['descriptor']['release_id']==release_id
  local=wait(lambda:publication_result(alpha,False),'operator accepted source closure and native decision',180)
  assert local['descriptor']['classification']==2
  passed('native Forge F11 transfers actual signed closure and obtains guest-owned Alpha admission',remote=admitted,operator=local)
  if a.helper_archive:
   progress('Publish separately signed source-only Notes.Schema through the same real Alpha path')
   helper=json.loads(a.helper_archive.read_bytes())
   helper_records=[dict(n,payload=base64.b64decode(n['payload'],validate=True))for n in helper['nodes']]
   helper_head=helper['selected'][0]['head']
   helper_manifest=projects.decode_manifest(next(n['payload']for n in helper_records if n['id']==helper_head))
   helper_release=next(n['payload']for n in helper_records if n['id']==next(i for path,kind,i in helper_manifest if kind==13 and not path.startswith('deps/')))
   detail=96+struct.unpack_from('<Q',helper_release,16)[0]*128
   helper_header=helper_release[detail:detail+608];helper_id=helper_header[160:192].hex()
   with alpha.client()as c:federation.call(c,alpha.registry,3,data=helper_header[128:160]+helper_header[576:608])
   with source.client()as c:
    helper_root=projects.import_records(c,helper['selected'],helper_records)[0]['cap']
    shell=struct.unpack_from('<Q',c.request(2),4*32)[0];c.objects(27,helper_root,shell,127)
   source.select(helper['selected'][0]['name']);source.ui.press(87)
   helper_decision=wait(lambda:publication_result(source,expected_release=helper_id),'separately published native helper development decision',180)
   assert helper_decision['classification']==1
   passed('separately signed helper is published through Forge as DevelopmentArtifact without installation authority',release_id=helper_id,archive_sha256=hashlib.sha256(a.helper_archive.read_bytes()).hexdigest(),decision=helper_decision)
  # Preserve exactly this accepted graph and independent sealed operator key.
  alpha.focus(alpha.instance);alpha.select(next(r['name']for r in alpha.roots()if r['head']==head));committed=save(alpha)
  unlock=os.urandom(32);authority_ns=digest('Campaign010 alpha authority').hex()
  with alpha.client() as c:
   retained=federation.retain_native(c,alpha.registry,alpha_config['key'],unlock,authority_ns,'consumer',895)
  passed('Alpha retains only its chosen accepted graph, catalog and typed independent operator seal',graph=committed,authority=retained)
  stop_all()
  # The Beta operator is independently initialized and makes a real refusal.
  progress('independent Beta policy refusal')
  observer_key,beta_key,endpoint=relation('beta-only',digest('beta observer'),digest('beta'))
  beta=actor('beta',endpoint,True,disks[2]);beta.setup_link(a.forge,beta_key,digest('Campaign010 beta graph'),role='registry')
  observer=actor('beta-observer',endpoint);observer.setup_link(a.forge,observer_key)
  beta_config=start_registry(beta,'restricted',None,'beta catalog')
  verifier(observer,beta_config,policy='restricted',allowed=None);authenticate(observer,beta)
  with beta.client() as c:
   beta_root=projects.import_records(c,document['selected'],records)[0]['cap']
  refused=direct_admit(beta,beta_root);refusal=forge.admission_record(refused)
  assert refusal['classification']==3 and refusal['release_id']==release_id
  with beta.client() as c:forge.federation_configure(c,beta.instance,beta_config['federation_id'],2)
  observer.ui.press(61)
  observed=wait(lambda:publication_result(observer),'native Forge discovery of Beta policy refusal',180)
  assert observed['remote_phase']==3 and observed['classification']==3 and not observer.roots()
  if rendered_text(observer.ui.frame(),10,56,10,0x9fc6a5)!='FEDERATION':observer.ui.press(59)
  wait(lambda:rendered_text(observer.ui.frame(),10,56,10,0x9fc6a5)=='FEDERATION','actual signed policy refusal panel')
  (observer.path/'policy-refusal.ppm').write_bytes(observer.ui.frame().ppm())
  passed('independently initialized Beta refuses the same immutable release and Forge displays that signed decision',configuration=beta_config,decision=refusal,forge=observed)
  stop_all()
  # Alpha restarts from its own approved durable store and sealed identity.
  progress('restarted Alpha replication to independent seed')
  alpha_key,seed_key,endpoint=relation('alpha-seed',digest('alpha'),digest('seed'))
  seed=actor('seed',endpoint,True,disks[1]);alpha=actor('alpha-restarted',endpoint,False,disks[0])
  seed.setup_link(a.forge,seed_key,digest('Campaign010 seed graph'),role='seed')
  alpha.setup_link(a.forge,alpha_key,digest('Campaign010 alpha graph'),role='registry')
  recovered=start_registry(alpha,'consumer',895,'alpha catalog',recover=authority_ns,credential=unlock)
  assert recovered['public_key']==alpha_config['public_key'] and recovered['generation']>alpha_config['generation']
  with alpha.client() as c:forge.federation_configure(c,alpha.instance,recovered['federation_id'],3)
  verifier(seed,recovered,namespace='seed verified catalog');authenticate(alpha,seed)
  preview=alpha.recover(digest('Campaign010 alpha graph'),head)
  wait(lambda:publication_result(alpha,False),'recovered exact Alpha catalog descriptor selected',180)
  first=transfer(alpha,seed,document);stored=save(seed)
  with seed.client() as c:retained_sequence=federation.call(c,seed.registry,23)[0][1]
  passed('restarted Alpha preserves accepted catalog/sealed identity and seeds a separate provider through Forge',recovery=recovered,preview=preview,transfer=first,seed_commit=stored)
  stop_all()
  # Neither source nor original Alpha provider is running now. No archive is
  # imported into the seed or recipient after this point.
  progress('surviving seed retrieval and native install')
  reader_key,seed_key,endpoint=relation('reader-seed',digest('new personal reader'),digest('seed'))
  seed=actor('seed-restarted',endpoint,True,disks[1]);reader=actor('reader',endpoint)
  seed.setup_link(a.forge,seed_key,digest('Campaign010 seed graph'),role='seed')
  reader.setup_link(a.forge,reader_key);verifier(seed,recovered,namespace='seed verified catalog',recover=True);verifier(reader,recovered);authenticate(reader,seed)
  seed.recover(digest('Campaign010 seed graph'),head)
  wait(lambda:publication_result(seed,False),'surviving seed reattaches original retained admission',180)
  final=transfer(seed,reader,document);frame=install_notes(reader)
  passed('surviving independently restarted seed supplies exact signed closure and original admission while source/Alpha are offline',transfer=final,retained_sequence=retained_sequence,installed_release=release_id,application_frame=frame)
  # Keep this actual network-fetched second user available for the connected
  # native fork continuation. No process handle becomes retained authority.
  roots=reader.roots();actual=next(r for r in roots if r['head']==head)
  (a.output/'reader-live.json').write_text(json.dumps(dict(schema=1,pid=reader.proc.pid,socket=str(reader.sock),graphics=str(reader.qmp),backend='qemu',image=str(a.image.resolve()),image_sha256=record['image_sha256'],forge=reader.instance,registry=reader.registry,root=actual,release_id=release_id,live_only=True),indent=2)+'\n')
  record['result']='pass';record['reader_continuation']=str(a.output/'reader-live.json')
  nodes.remove(reader);reader.ui.close();reader.ui=None
  if reader.log:reader.log.close()
 except BaseException as error:
  record.update(result='failure',error=repr(error));raise
 finally:
  for n in nodes:
   try:(n.path/'final.ppm').write_bytes(n.ui.frame().ppm())
   except Exception:pass
  if record['result']=='failure'and a.keep_on_failure:
   live_actors=[]
   for n in nodes:
    live_actors.append(dict(pid=n.proc.pid,socket=str(n.sock),graphics=str(n.qmp),forge=getattr(n,'instance',None),registry=getattr(n,'registry',None),live_only=True))
    if n.ui:n.ui.close();n.ui=None
    if n.log:n.log.close()
   (a.output/'failed-live-actors.json').write_text(json.dumps(dict(schema=1,image=str(a.image.resolve()),actors=live_actors,warning='Session handles describe only these still-live incarnations; they are not recovery authority.'),indent=2)+'\n')
   record['live_continuation']=str(a.output/'failed-live-actors.json')
  else:stop_all()
  write()
 return 0


if __name__=='__main__':raise SystemExit(main())
