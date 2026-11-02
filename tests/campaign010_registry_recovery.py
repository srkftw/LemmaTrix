"""Restart a real Registry catalog and its independently sealed guest identity."""
import argparse,base64,hashlib,importlib.util,json,os,struct,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import federation,identity,projects,releases,server_store
node_spec=importlib.util.spec_from_file_location('server_store_acceptance',ROOT/'tests/server_store.py')
node_test=importlib.util.module_from_spec(node_spec);node_spec.loader.exec_module(node_test);Node=node_test.Node

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('image','archive','identity','registry','output'):p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False);os.environ['LT_GUEST_IMAGE']=str(a.image.resolve())
 disk=a.output/'server.img';server_store.provision(disk)
 public=ROOT/'tests/keys/development-rsa-public.pem';credential=os.urandom(32)
 catalog_ns=hashlib.sha256(b'campaign010 independently initialized native Registry catalog').digest()
 authority_ns=hashlib.sha256(b'campaign010 typed native Registry authority').hexdigest()
 document=json.loads(a.archive.read_bytes());records=[dict(n,payload=base64.b64decode(n['payload'],validate=True))for n in document['nodes']]
 report=dict(schema=1,scope=__doc__,image_sha256=hashlib.sha256(a.image.read_bytes()).hexdigest(),checks=[],result='running')
 started=time.monotonic();node=None
 def passed(label,**fields):
  report['checks'].append(dict(check=label,result='pass',**fields));save();print('PASS',label,flush=True)
 def save():
  report['elapsed_seconds']=time.monotonic()-started;(a.output/'execution.json').write_text(json.dumps(report,indent=2)+'\n')
 def boot(directory):
  directory.mkdir();n=Node(disk,directory);service=identity.start(n.client,a.identity,public)
  raw=a.registry.read_bytes();n.client.request(10,raw[128:160]+releases.public_key(public));slot,info=n.client.install(a.registry)
  instance=struct.unpack_from('<Q',n.client.request(25,struct.pack('<Q',slot)),8)[0]
  server_store.call(n.client,230)
  grant=server_store.call(n.client,231,instance,1,1048576,catalog_ns)[0][1]
  return n,service,instance,info,grant
 def complete(client,instance,slot):
  until=time.monotonic()+180
  while time.monotonic()<until:
   q,data=federation.call(client,instance,7,h=slot)
   if q[1]==2:return data
   if q[1]>2:raise AssertionError(('native signing unavailable',q,federation.call(client,instance,14)[0]))
   time.sleep(.05)
  raise TimeoutError('bounded native Registry decision')
 try:
  node,service,instance,info,grant=boot(a.output/'first')
  configured=federation.configure_native(node.client,instance,'portable',service['release'],info['release_id'],store_grant=grant)
  root=projects.import_records(node.client,document['selected'],records)[0]['cap']
  release=next(n['payload']for n in records if n['kind']==13);count=struct.unpack_from('<Q',release,16)[0];h=release[96+count*128:]
  federation.call(node.client,instance,3,data=h[128:160]+h[576:608])
  delegated=node.client.objects(27,root,instance,25)[0][1]
  q,_=federation.call(node.client,instance,2,h=delegated);decision=complete(node.client,instance,q[2])
  saved=federation.retain_native(node.client,instance,configured['key'],credential,authority_ns,'portable')
  passed('native decision and typed sealed operator authority committed to separate approved server namespaces',configuration=configured,retention=saved,decision_sha256=hashlib.sha256(decision).hexdigest())
  old_instance=instance;old_grant=grant;node.stop(crash=True);node=None
  node,service,instance,info,grant=boot(a.output/'restarted')
  assert instance!=old_instance and grant!=old_grant
  try:federation.recover_native(node.client,instance,bytes(32),authority_ns,service['release'],info['release_id'],store_grant=grant)
  except ValueError:pass
  else:raise AssertionError('empty credential recovered operator identity')
  recovered=federation.recover_native(node.client,instance,credential,authority_ns,service['release'],info['release_id'],store_grant=grant)
  assert recovered['public_key']==configured['public_key'] and recovered['generation']>configured['generation']
  _,retained=federation.call(node.client,instance,6,h=0);assert retained==decision
  q,_=federation.call(node.client,instance,11,data=decision+decision[320:352]);assert q[1]==1
  passed('server restart restores exact authenticated catalog and same sealed identity with fresh live bindings',recovery=recovered,old_instance=old_instance,new_instance=instance,old_grant=old_grant,new_grant=grant)
  federation.call(node.client,instance,8,h=0)
  revoked=complete(node.client,instance,1)
  assert struct.unpack_from('<Q',revoked,16)[0]==3 and struct.unpack_from('<Q',revoked,392)[0]==recovered['generation']
  q,_=federation.call(node.client,instance,11,data=revoked+revoked[320:352]);assert q[1]==3
  federation.retain_native(node.client,instance,recovered['key'],credential,authority_ns,'portable')
  passed('recovered current native operator signs and durably commits a new exact revocation',sequence=struct.unpack_from('<Q',revoked,48)[0],generation=recovered['generation'])
  report['result']='pass'
 except BaseException as error:report.update(result='failure',error=repr(error));raise
 finally:
  if node:node.stop(crash=True)
  save()
 return 0
if __name__=='__main__':raise SystemExit(main())
