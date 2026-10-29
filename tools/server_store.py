"""Explicit server backing provisioning; all online transactions execute in Lean."""
import argparse,hashlib,json,os,struct
from pathlib import Path
import live
FORMAT=0x31524f5453544c
SECTORS=33088

def provision(path):
 flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW
 fd=os.open(path,flags,0o600)
 try:
  os.ftruncate(fd,SECTORS*512)
  os.write(fd,struct.pack('<3Q',FORMAT,1,SECTORS).ljust(512,b'\0'))
  os.fsync(fd)
 finally:os.close(fd)
 return dict(path=str(path),sectors=SECTORS,bytes=SECTORS*512,format=1,purpose='lt-server-v1',encryption='none; intentional operator storage')

def call(client,op,h=0,a=0,b=0,data=b''):
 raw=client.request(op,struct.pack('<8Q',op,h,a,b,0,0,0,1)+data)
 if len(raw)<64:raise ValueError('short server store response')
 fields=struct.unpack_from('<8Q',raw)
 if fields[0]:raise ValueError(f'server store status {fields[0]}')
 return fields,raw[64:]

def main(argv=None):
 p=argparse.ArgumentParser(description='Purpose-bound durable guest server store')
 sub=p.add_subparsers(dest='command',required=True)
 q=sub.add_parser('init');q.add_argument('image',type=Path)
 q=sub.add_parser('mount');q.add_argument('--socket',required=True,type=Path)
 q=sub.add_parser('permit');q.add_argument('--socket',required=True,type=Path);q.add_argument('--instance',required=True,type=int);q.add_argument('--namespace',required=True);q.add_argument('--role',required=True,choices=('registry','seed','builder','verifier'));q.add_argument('--bytes',type=int,default=1048576)
 q=sub.add_parser('revoke');q.add_argument('--socket',required=True,type=Path);q.add_argument('--grant',required=True,type=int)
 a=p.parse_args(argv)
 if a.command=='init':result=provision(a.image)
 else:
  c=live.Client(a.socket)
  try:
   if a.command=='mount':result=dict(slots=call(c,230)[0][1],format=1)
   elif a.command=='permit':
    ns=bytes.fromhex(a.namespace)
    if len(ns)!=32:raise ValueError('namespace must contain 32 bytes')
    result=dict(grant=call(c,231,a.instance,('registry','seed','builder','verifier').index(a.role)+1,a.bytes,ns)[0][1],namespace=ns.hex(),owner=a.instance,role=a.role)
   else:result=dict(revoked=call(c,239,a.grant)[0][1])
  finally:c.close()
 print(json.dumps(result,indent=2));return 0

if __name__=='__main__':raise SystemExit(main())
