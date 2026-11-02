"""Explicit signing/bootstrap adapter for the isolated Lean registry policy.

The guest evaluates actual canonical material. The signer signs only the chosen
federation's domain-separated immutable decisions; no host catalog is created.
"""
import argparse,hashlib,json,struct,tempfile,time
from pathlib import Path
import capsule,live,releases,identity,server_store
MAGIC=0x314d4441544c

def call(client,instance,op,h=0,a=0,b=0,data=b'',c=0):
 raw=client.request(150,struct.pack('<Q',instance)+struct.pack('<8Q',op,h,a,b,c,0,0,1)+data)
 if len(raw)<64:raise ValueError('short registry response')
 q=struct.unpack_from('<8Q',raw)
 if q[0]:raise ValueError(f'native registry status{q[0]}')
 return q,raw[64:]

def configure(client,instance,public,policy,store_grant=0,bind=True,allowed_rights=None):
 modulus=releases.public_modulus(public)
 if policy not in ('portable','restricted','consumer'):raise ValueError('unknown explicit federation policy')
 if policy=='consumer' and (type(allowed_rights) is not int or not 0<=allowed_rights<=8191):raise ValueError('consumer federation requires an explicit known allowed-rights mask')
 q,_=call(client,instance,1,a={'portable':1,'restricted':2,'consumer':3}[policy],b=store_grant,c=allowed_rights or 0,data=modulus)
 if bind:client.request(181,struct.pack('<Q',instance))
 return dict(instance=instance,policy=policy,federation_id=hashlib.sha256(modulus).hexdigest(),store_grant=store_grant,bound=bind,execution_authority=False)

def sign_once(client,instance,key,policy,allowed_rights=None):
 try:q,pending=call(client,instance,4)
 except ValueError as error:
  if str(error)=='native registry status6':return None
  raise
 modulus=capsule.modulus(key);federation=hashlib.sha256(modulus).digest();rule={'portable':1,'restricted':2,'consumer':3}[policy]
 if rule==3 and (type(allowed_rights) is not int or not 0<=allowed_rights<=8191):raise ValueError('consumer signing requires an explicit known allowed-rights mask')
 rule_bytes=struct.pack('<4Q',0x31594c4f50544c,rule,allowed_rights if rule==3 else 768 if rule==1 else 256,0 if rule==1 else 1)
 if len(pending)!=512 or struct.unpack_from('<Q',pending)[0]!=MAGIC or struct.unpack_from('<Q',pending,8)[0]!=1 or pending[288:320]!=federation or pending[256:288]!=hashlib.sha256(rule_bytes).digest() or struct.unpack_from('<Q',pending,32)[0]!=rule:
  raise ValueError('guest decision differs from explicitly authorized federation/key/policy; no signature produced')
 with tempfile.TemporaryDirectory(prefix='lt-admission-sign-') as directory:
  header=Path(directory)/'admission';header.write_bytes(pending)
  signature=releases.pkg.crypto(['dgst','-sha256','-sign',key,header]).stdout
 if len(signature)!=256:raise ValueError('federation signer did not return RSA2048 signature')
 # Pending query returns the immutable slot in header word2; no slot is trusted
 # from peer material. The guest rechecks signature and persistence before list.
 slot=q[2]
 call(client,instance,5,h=q[1],a=slot,data=signature)
 return dict(sequence=q[1],listing=struct.unpack_from('<Q',pending,16)[0],reason=struct.unpack_from('<Q',pending,24)[0],logical_project_id=pending[64:96].hex(),publication_id=pending[96:128].hex(),release_id=pending[128:160].hex(),root=pending[320:352].hex(),federation=federation.hex(),signature='RSA2048/SHA256 over immutable guest-evaluated admission-v1',local_execution_approved=False)

def policy_commitment(policy,allowed_rights=None):
 rule={'portable':1,'restricted':2,'consumer':3}[policy]
 if rule==3 and (type(allowed_rights) is not int or not 0<=allowed_rights<=8191):raise ValueError('consumer policy requires its exact allowed-rights mask')
 return hashlib.sha256(struct.pack('<4Q',0x31594c4f50544c,rule,allowed_rights if rule==3 else 768 if rule==1 else 256,0 if rule==1 else 1)).digest()

def configure_native(client,instance,policy,identity_release,registry_release,*,store_grant=0,allowed_rights=None,limit=16):
 """Initialize independent guest-owned operator authority. No host key input."""
 client.request(181,struct.pack('<Q',instance))
 signer=identity.endpoint(client,411)
 identity.bind(client,signer,instance,bytes.fromhex(identity_release),bytes.fromhex(registry_release),411)
 q,descriptor=identity.invoke(client,411,a=instance,b=limit,data=policy_commitment(policy,allowed_rights)+bytes.fromhex(registry_release))
 public=identity.decode_public(descriptor)
 key=q[1];raw=bytes.fromhex(public['public_key']);rule={'portable':1,'restricted':2,'consumer':3}[policy]
 # Native Registry independently derives the same exact policy commitment.
 payload=struct.pack('<Q8Q',instance,13,key,rule,store_grant,allowed_rights or 0,public['generation'],0,1)+raw
 response=client.request(150,payload)
 if len(response)!=64 or struct.unpack_from('<Q',response)[0]:raise ValueError('native Registry configuration refused')
 return dict(instance=instance,policy=policy,federation_id=hashlib.sha256(raw).hexdigest(),public_key=raw.hex(),key=key,generation=public['generation'],policy_id=policy_commitment(policy,allowed_rights).hex(),store_grant=store_grant,decision_budget=limit,signing='native scoped Ed25519 admission-v2',session_only=True,execution_authority=False)

def configure_native_verifier(client,instance,public,policy,*,store_grant=0,allowed_rights=None,generation=1):
 raw=bytes.fromhex(public)
 if len(raw)!=32 or not any(raw):raise ValueError('exact selected federation Ed25519 public key required')
 rule={'portable':1,'restricted':2,'consumer':3}[policy];policy_commitment(policy,allowed_rights)
 payload=struct.pack('<Q8Q',instance,13,0,rule,store_grant,allowed_rights or 0,generation,0,1)+raw
 response=client.request(150,payload)
 if len(response)!=64 or struct.unpack_from('<Q',response)[0]:raise ValueError('native Registry verifier configuration refused')
 client.request(181,struct.pack('<Q',instance))
 return dict(instance=instance,policy=policy,federation_id=hashlib.sha256(raw).hexdigest(),signing_authority=False,execution_authority=False)

AUTHORITY_MAGIC=0x3159454b52464c

def authority_grant(client,namespace):
 raw=identity.digest(namespace)
 launcher=next(row[0]for row in identity.instances(client)if row[0]&255==1)
 server_store.call(client,230)
 return server_store.call(client,231,launcher,1,512,raw)[0][1]

def retain_native(client,instance,key,credential,namespace,policy,allowed_rights=None):
 """Store only Identity's typed encrypted role7 seal, never a private key.

 The independently supplied credential remains outside intentional unencrypted
 server storage. Catalog retention uses its separate Registry-owned namespace.
 """
 if len(credential)!=32 or not any(credential):raise ValueError('operator sealing credential must be32nonzero bytes')
 client.request(181,struct.pack('<Q',instance))
 _,descriptor=identity.invoke(client,401,h=key)
 public=identity.decode_public(descriptor);commitment=policy_commitment(policy,allowed_rights)
 if public['role']!=7 or public['federation']!=commitment.hex():raise ValueError('select a native operator key for this exact policy')
 _,sealed=identity.invoke(client,411,h=2,a=key,data=credential)
 if len(sealed)!=192:raise ValueError('incomplete native Registry seal')
 header=struct.pack('<8Q',AUTHORITY_MAGIC,1,{'portable':1,'restricted':2,'consumer':3}[policy],allowed_rights or 0,public['generation'],0,0,0)
 material=(header+bytes.fromhex(public['public_key'])+commitment+sealed).ljust(512,b'\0')
 grant=authority_grant(client,namespace)
 server_store.call(client,232,grant,len(material),data=hashlib.sha256(material).digest())
 try:
  server_store.call(client,233,grant,0,data=material)
  server_store.call(client,234,grant)
 except BaseException:
  try:server_store.call(client,235,grant)
  except (ValueError,OSError,EOFError):pass
  raise
 return dict(namespace=namespace,public_key=public['public_key'],generation=public['generation'],policy=policy,
             retained='native Identity sealed role7 authority; approved purpose2 store',private_key_exported=False,
             freshness='latest committed local server store; no whole-store rollback detection',
             continuation='recover catalog and authority together before admitting further releases')

def recover_native(client,instance,credential,namespace,identity_release,registry_release,*,store_grant=0):
 if len(credential)!=32 or not any(credential):raise ValueError('operator sealing credential must be32nonzero bytes')
 grant=authority_grant(client,namespace)
 _,stored=server_store.call(client,236,grant)
 if len(stored)!=512 or struct.unpack_from('<Q',stored,32)[0]!=512:raise ValueError('no exact retained native operator record')
 _,material=server_store.call(client,237,grant,0,512)
 if len(material)!=512 or hashlib.sha256(material).digest()!=stored[80:112]:raise ValueError('retained operator integrity failure')
 words=struct.unpack_from('<8Q',material)
 if words[:2]!=(AUTHORITY_MAGIC,1)or words[2]not in(1,2,3)or words[3]>8191 or not words[4]or any(words[5:])or any(material[320:]):raise ValueError('unsupported retained native operator record')
 policy={1:'portable',2:'restricted',3:'consumer'}[words[2]];allowed=words[3]
 if material[96:128]!=policy_commitment(policy,allowed):raise ValueError('retained policy commitment differs')
 client.request(181,struct.pack('<Q',instance))
 signer=identity.endpoint(client,411)
 identity.bind(client,signer,instance,bytes.fromhex(identity_release),bytes.fromhex(registry_release),411)
 q,descriptor=identity.invoke(client,411,h=3,a=instance,data=credential+material[64:96]+material[128:320])
 public=identity.decode_public(descriptor)
 if public['role']!=7 or public['federation']!=material[96:128].hex()or public['public_key']!=material[64:96].hex()or public['generation']<=words[4]:raise ValueError('native recovered authority differs from selected record')
 payload=struct.pack('<Q8Q',instance,13,q[1],words[2],store_grant,allowed,public['generation'],0,1)+material[64:96]
 response=client.request(150,payload)
 if len(response)!=64 or struct.unpack_from('<Q',response)[0]:raise ValueError('native recovered Registry configuration refused')
 records=call(client,instance,10)[0][1] if store_grant else 0
 return dict(instance=instance,key=q[1],policy=policy,public_key=public['public_key'],generation=public['generation'],
             federation_id=hashlib.sha256(material[64:96]).hexdigest(),recovered_catalog_records=records,
             old_live_bindings_restored=False,namespace=namespace,
             freshness='local committed store only; an older whole-store backup needs explicit operator reconciliation')

def main(argv=None):
 p=argparse.ArgumentParser(description='Isolated guest federation policy and narrowly scoped signer bootstrap')
 p.add_argument('--socket',type=Path,required=True);p.add_argument('--instance',type=int,required=True)
 sub=p.add_subparsers(dest='command',required=True)
 q=sub.add_parser('configure');q.add_argument('--public',type=Path,required=True);q.add_argument('--policy',choices=('portable','restricted','consumer'),required=True);q.add_argument('--store-grant',type=int,default=0);q.add_argument('--allowed-rights',type=lambda x:int(x,0));q.add_argument('--no-bind',action='store_true')
 q=sub.add_parser('trust-publisher');q.add_argument('--public',type=Path,required=True);g=q.add_mutually_exclusive_group(required=True);g.add_argument('--project-id');g.add_argument('--legacy-project')
 q=sub.add_parser('worker');q.add_argument('--key',type=Path,required=True);q.add_argument('--policy',choices=('portable','restricted','consumer'),required=True);q.add_argument('--once',action='store_true');q.add_argument('--allowed-rights',type=lambda x:int(x,0))
 q=sub.add_parser('native-init');q.add_argument('--policy',choices=('portable','restricted','consumer'),required=True);q.add_argument('--identity-release',required=True);q.add_argument('--registry-release',required=True);q.add_argument('--store-grant',type=int,default=0);q.add_argument('--allowed-rights',type=lambda x:int(x,0));q.add_argument('--limit',type=int,default=16)
 q=sub.add_parser('native-verifier');q.add_argument('--public',required=True);q.add_argument('--policy',choices=('portable','restricted','consumer'),required=True);q.add_argument('--store-grant',type=int,default=0);q.add_argument('--allowed-rights',type=lambda x:int(x,0));q.add_argument('--generation',type=int,default=1)
 q=sub.add_parser('native-retain');q.add_argument('--key',required=True,type=int);q.add_argument('--credential',required=True,type=Path);q.add_argument('--namespace',required=True);q.add_argument('--policy',choices=('portable','restricted','consumer'),required=True);q.add_argument('--allowed-rights',type=lambda x:int(x,0))
 q=sub.add_parser('native-recover');q.add_argument('--credential',required=True,type=Path);q.add_argument('--namespace',required=True);q.add_argument('--identity-release',required=True);q.add_argument('--registry-release',required=True);q.add_argument('--store-grant',required=True,type=int)
 for command in ('query','recover'):
  q=sub.add_parser(command)
  if command=='query':q.add_argument('--cursor',type=int,default=0)
 q=sub.add_parser('search');q.add_argument('query');q.add_argument('--cursor',type=int,default=0);q.add_argument('--facet',type=int,choices=(0,1,2),default=0)
 q=sub.add_parser('store');q.add_argument('--grant',type=int,required=True)
 a=p.parse_args(argv);c=live.Client(a.socket)
 try:
  if a.command=='configure':result=configure(c,a.instance,a.public,a.policy,a.store_grant,not a.no_bind,a.allowed_rights)
  elif a.command=='native-init':result=configure_native(c,a.instance,a.policy,a.identity_release,a.registry_release,store_grant=a.store_grant,allowed_rights=a.allowed_rights,limit=a.limit)
  elif a.command=='native-verifier':result=configure_native_verifier(c,a.instance,a.public,a.policy,store_grant=a.store_grant,allowed_rights=a.allowed_rights,generation=a.generation)
  elif a.command=='native-retain':result=retain_native(c,a.instance,a.key,a.credential.read_bytes(),a.namespace,a.policy,a.allowed_rights)
  elif a.command=='native-recover':result=recover_native(c,a.instance,a.credential.read_bytes(),a.namespace,a.identity_release,a.registry_release,store_grant=a.store_grant)
  elif a.command=='trust-publisher':
   modulus=releases.public_key(a.public);publication=releases.publication(a.project_id,hashlib.sha256(modulus).hexdigest()) if a.project_id else releases.project(a.legacy_project)
   result={'slot':call(c,a.instance,3,data=publication+modulus)[0][1],'publication_id':publication.hex()}
  elif a.command=='worker':
   while True:
    result=sign_once(c,a.instance,a.key,a.policy,a.allowed_rights)
    if result is not None:print(json.dumps(result,indent=2),flush=True)
    if a.once:return 0
    time.sleep(.5)
  elif a.command=='search':
   query=a.query.encode('ascii')
   q,payload=call(c,a.instance,21,h=a.cursor,a=a.facet,b=len(query),data=query);result={'sequence':q[1],'next_cursor':q[3],'slot':q[2],'descriptor':payload.hex()}
  elif a.command=='store':result={'grant':call(c,a.instance,9,h=a.grant)[0][1]}
  elif a.command=='recover':result={'records':call(c,a.instance,10)[0][1]}
  else:
   q,payload=call(c,a.instance,6,h=a.cursor);result={'sequence':q[1],'next_cursor':q[3],'descriptor':payload.hex(),'listing':struct.unpack_from('<Q',payload,16)[0],'root':payload[320:352].hex()}
 finally:c.close()
 print(json.dumps(result,indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
