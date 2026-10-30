"""Explicit provisioning for the Lean LibraryPeer registry/seed package.

No catalog, payload index or serving policy is implemented by this adapter.
"""
import argparse,json,struct
from pathlib import Path
import live,network,nodes,releases

def call(client,instance,op,slot=0,a=0,b=0,c=0,d=0,e=0,data=b''):
 raw=client.request(150,struct.pack('<Q8Q',instance,op,slot,a,b,c,d,e,1)+data)
 if len(raw)<64:raise ValueError('short LibraryPeer result')
 fields=struct.unpack_from('<8Q',raw)
 if fields[0]:raise ValueError(f'native LibraryPeer status{fields[0]}')
 return fields,raw[64:]

def main(argv=None):
 parser=argparse.ArgumentParser(description='Headless native Library registry/seed relationship setup')
 parser.add_argument('--socket',type=Path,required=True);sub=parser.add_subparsers(dest='command',required=True)
 start=sub.add_parser('start');start.add_argument('--package',type=Path,required=True);start.add_argument('--public',type=Path,required=True);start.add_argument('--release-id',required=True);start.add_argument('--rights',type=lambda x:int(x,0),default=1025)
 setup=sub.add_parser('configure');setup.add_argument('--instance',type=int,required=True);setup.add_argument('--slot',type=int,choices=range(4),required=True);setup.add_argument('--role',choices=('registry','seed'),required=True);setup.add_argument('--credentials',type=Path,required=True);setup.add_argument('--root',required=True);setup.add_argument('--stream',type=int,help='default: registry1; seed little-endian first8 bytes of manifestSHA OR1');setup.add_argument('--content-handle',type=int,default=0);setup.add_argument('--budget',type=int,default=16777216);setup.add_argument('--lifetime',type=int,default=100000)
 for name in ('inspect','remove'):
  command=sub.add_parser(name);command.add_argument('--instance',type=int,required=True);command.add_argument('--slot',type=int,choices=range(16 if name=='inspect' else 4),required=True)
 args=parser.parse_args(argv);client=live.Client(args.socket,timeout=180)
 try:
  if args.command=='start':
   config=nodes.approved_package(args.package,args.public,args.release_id,args.rights)
   instance=nodes.start_package(client,config,nodes.validate_package(config));result={'instance':instance,'release_id':args.release_id,'rights':args.rights,'role':'unconfigured; explicit scoped relationship required'}
  elif args.command=='configure':
   role,material=network.load_credentials(args.credentials);peer=material[32:64] if role==1 else material[:32]
   root=network.digest(args.root);stream=args.stream if args.stream is not None else (1 if args.role=='registry' else int.from_bytes(root[:8],'little') | 1)
   if args.role=='seed' and args.content_handle==0:raise ValueError('seed requires an explicitly shared local Content handle; never a host path')
   fields,_=call(client,args.instance,400,args.slot,1 if args.role=='registry' else 2,stream,args.content_handle,args.budget,args.lifetime,peer+material[64:96]+root)
   result={'instance':args.instance,'slot':args.slot,'role':args.role,'stream':stream,'scope_index':fields[1],'root':args.root,'configured':True,'retention':'separate explicit storage policy; no persistence created by this command'}
  elif args.command=='inspect':
   fields,_=call(client,args.instance,401,args.slot);result=dict(instance=args.instance,slot=args.slot,state=fields[2],active=fields[2]==1,waiting_for_authentication=fields[2]==2,role=fields[3],send_pending=bool(fields[4]),response_bytes=fields[5],snapshot_id=fields[6],last_error=fields[7])
  else:call(client,args.instance,402,args.slot);result={'instance':args.instance,'slot':args.slot,'removed':True}
 finally:client.close()
 print(json.dumps(result,indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
