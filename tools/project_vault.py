"""Explicit byte orchestration for guest-authenticated Project Vault transactions.

All graph/schema/content checks, encryption, storage commits and root publication
run in guest services. This adapter transports bounded records and never stores
vault plaintext on the host. Publisher keys and install authority are excluded.
"""
import argparse,hashlib,json,struct
from pathlib import Path
import live,projects


def call(client,op,h=0,offset=0,count=0,data=b''):
 raw=client.request(op,struct.pack('<8Q',op,h,3,offset,count,0,0,1)+data)
 if len(raw)<64:raise ValueError('short Project Vault reply')
 fields=struct.unpack_from('<8Q',raw)
 if fields[0]:raise ValueError(f'Project Vault status{fields[0]}')
 return fields,raw[64:]


def unlock(client,key):
 if len(key)!=32:raise ValueError('vault key must contain32bytes')
 raw=client.request(200,struct.pack('<8Q',200,0,3,0,0,0,0,1)+key)
 if len(raw)<64 or struct.unpack_from('<Q',raw)[0]:raise ValueError('vault unlock failed')


def retain(client,roots):
 if not 1<=len(roots)<=6:raise ValueError('select1..6root capabilities')
 processes=client.request(2)
 if len(processes)<128:raise ValueError('Vault process unavailable')
 vault=struct.unpack_from('<Q',processes,96)[0]
 if not vault:raise ValueError('Vault process unavailable')
 delegated=[];frozen=[]
 try:
  for root in roots:
   _,metadata=client.objects(29,root)
   snapshot=client.objects(32,root,data=metadata[:32])[0][1];frozen.append(snapshot)
  for root in frozen:delegated.append((root,client.objects(27,root,vault,1)[0][1]))
  fields,_=call(client,210,offset=len(delegated),data=struct.pack('<'+'Q'*len(delegated),*(grant for _,grant in delegated)))
  return dict(generation=fields[1],nodes=fields[2],projects=fields[3],bytes=fields[4],format=fields[6])
 finally:
  for root,grant in delegated:
   try:client.objects(31,root,grant)
   except Exception:pass
  for root in frozen:
   try:client.objects(28,root)
   except Exception:pass


def inventory(client):
 fields,_=call(client,211)
 roots=[];nodes=[]
 for i in range(fields[3]):
  _,data=call(client,213,i)
  n=struct.unpack_from('<Q',data)[0]
  roots.append(dict(name=data[40:40+n].decode('ascii'),head=data[8:40].hex()))
 for i in range(fields[2]):
  _,data=call(client,214,i)
  kind,length=struct.unpack_from('<2Q',data)
  nodes.append(dict(index=i,kind=kind,length=length,id=data[16:48].hex(),parent=data[48:80].hex(),sha256=data[80:112].hex()))
 return dict(generation=fields[1],bytes=fields[4],projects=roots,nodes=nodes)


def recover(client):
 saved=inventory(client)
 if not saved['projects']:return dict(generation=saved['generation'],roots=[],nodes=0,bytes=0)
 # Index order is an encoding detail. Dependency order is derived from canonical
 # parent and typed edge commitments and checked again by Objects on each commit.
 pending={node['id']:node for node in saved['nodes']};restored={};created=[]
 try:
  while pending:
   progress=False
   for identity,node in list(pending.items()):
    parent=node['parent']
    if parent!='00'*32 and parent not in restored:continue
    payload=bytearray()
    for offset in range(0,node['length'],512):
     _,data=call(client,215,node['index'],offset,min(512,node['length']-offset));payload.extend(data)
    if len(payload)!=node['length'] or hashlib.sha256(payload).hexdigest()!=node['sha256']:raise ValueError('transported member digest mismatch')
    if node['kind']!=10:
     entries=projects.decode_manifest(bytes(payload))
     if any(child not in restored for _,_,child in entries):continue
    handle,actual=projects.node(client,bytes(payload),node['kind'],restored.get(parent,0))
    created.append(handle)
    if actual!=identity:raise ValueError('guest reconstructed a different canonical node identity')
    restored[identity]=handle;del pending[identity];progress=True
   if not progress:raise ValueError('missing/cyclic graph references; no project roots published')
  entries=b''
  for root in saved['projects']:
   name=projects.safe_name(root['name']).encode('ascii')
   if root['head'] not in restored:raise ValueError('missing selected project head')
   entries+=struct.pack('<2Q',restored[root['head']],len(name))+bytes.fromhex(root['head'])+name.ljust(80,b'\0')
  fields,data=client.objects(30,a=len(saved['projects']),data=entries)
  caps=struct.unpack('<'+'Q'*fields[1],data)
  return dict(generation=saved['generation'],bytes=saved['bytes'],nodes=len(restored),roots=[dict(**root,cap=cap) for root,cap in zip(saved['projects'],caps)])
 except BaseException:
  # Until op30 succeeds all imports are private, unrooted stages. Abort/drop them
  # in reverse order. Prior visible roots and durable commit roots remain intact.
  for handle in reversed(created):
   try:client.objects(8,handle)
   except Exception:pass
  raise


def main(argv=None):
 parser=argparse.ArgumentParser(description='Explicit guest Project Vault snapshot retention and recovery')
 parser.add_argument('--socket',required=True,type=Path)
 parser.add_argument('--key',type=Path)
 sub=parser.add_subparsers(dest='command',required=True)
 save=sub.add_parser('save');save.add_argument('roots',nargs='+',type=int)
 sub.add_parser('inspect');sub.add_parser('recover');sub.add_parser('delete')
 args=parser.parse_args(argv);client=live.Client(args.socket)
 try:
  if args.key:unlock(client,args.key.read_bytes())
  if args.command=='save':result=retain(client,args.roots)
  elif args.command=='inspect':result=inventory(client)
  elif args.command=='recover':result=recover(client)
  else:result=call(client,216)[0]
  print(json.dumps(result,indent=2))
 finally:client.close()
 return 0
