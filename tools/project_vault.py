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
 if fields[0]:raise ValueError(f'Project Vault status{fields[0]} stage{fields[1]}')
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
  nodes.append(dict(index=i,kind=kind,length=length,id=data[16:48].hex(),parent=data[48:80].hex(),sha256=data[80:112].hex(),schema=2 if len(data)>=136 and struct.unpack_from('<Q',data,128)[0]==2 else 1))
 return dict(generation=fields[1],bytes=fields[4],projects=roots,nodes=nodes)


def recover(client,selection=None):
 saved=inventory(client)
 if not saved['projects']:return dict(generation=saved['generation'],roots=[],nodes=0,bytes=0)
 chosen=list(range(len(saved['projects']))) if selection is None else list(selection)
 if not chosen or len(set(chosen))!=len(chosen) or any(i<0 or i>=len(saved['projects']) for i in chosen):raise ValueError('explicit recovery selection is outside authenticated inventory')
 mask=sum(1<<i for i in chosen)
 fields,data=call(client,217,offset=mask)
 if fields[1]!=len(chosen) or len(data)!=8*len(chosen):raise ValueError('incomplete native recovery result')
 caps=struct.unpack('<'+'Q'*len(chosen),data)
 return dict(generation=saved['generation'],bytes=saved['bytes'],nodes=len(saved['nodes']),native_import=True,roots=[dict(**saved['projects'][i],cap=cap) for i,cap in zip(sorted(chosen),caps)])


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
