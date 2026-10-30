"""Explicit signing/bootstrap adapter for the isolated Lean registry policy.

The guest evaluates actual canonical material. The signer signs only the chosen
federation's domain-separated immutable decisions; no host catalog is created.
"""
import argparse,hashlib,json,struct,tempfile,time
from pathlib import Path
import capsule,live,releases
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

def main(argv=None):
 p=argparse.ArgumentParser(description='Isolated guest federation policy and narrowly scoped signer bootstrap')
 p.add_argument('--socket',type=Path,required=True);p.add_argument('--instance',type=int,required=True)
 sub=p.add_subparsers(dest='command',required=True)
 q=sub.add_parser('configure');q.add_argument('--public',type=Path,required=True);q.add_argument('--policy',choices=('portable','restricted','consumer'),required=True);q.add_argument('--store-grant',type=int,default=0);q.add_argument('--allowed-rights',type=lambda x:int(x,0));q.add_argument('--no-bind',action='store_true')
 q=sub.add_parser('trust-publisher');q.add_argument('--public',type=Path,required=True);g=q.add_mutually_exclusive_group(required=True);g.add_argument('--project-id');g.add_argument('--legacy-project')
 q=sub.add_parser('worker');q.add_argument('--key',type=Path,required=True);q.add_argument('--policy',choices=('portable','restricted','consumer'),required=True);q.add_argument('--once',action='store_true');q.add_argument('--allowed-rights',type=lambda x:int(x,0))
 for command in ('query','recover'):
  q=sub.add_parser(command)
  if command=='query':q.add_argument('--cursor',type=int,default=0)
 q=sub.add_parser('search');q.add_argument('query');q.add_argument('--cursor',type=int,default=0);q.add_argument('--facet',type=int,choices=(0,1,2),default=0)
 q=sub.add_parser('store');q.add_argument('--grant',type=int,required=True)
 a=p.parse_args(argv);c=live.Client(a.socket)
 try:
  if a.command=='configure':result=configure(c,a.instance,a.public,a.policy,a.store_grant,not a.no_bind,a.allowed_rights)
  elif a.command=='trust-publisher':
   modulus=releases.public_modulus(a.public);publication=releases.publication(a.project_id,hashlib.sha256(modulus).hexdigest()) if a.project_id else releases.project(a.legacy_project)
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
