"""Opaque setup and inspection of the native Library; policies execute in Lean."""
import argparse, json, struct
from pathlib import Path
import live

def call(client,instance,op,h=0,a=0,b=0,data=b''):
 raw=client.request(150,struct.pack('<Q8Q',instance,op,h,a,b,0,0,0,1)+data)
 if len(raw)<64:raise ValueError('short native Library response')
 fields=struct.unpack_from('<8Q',raw)
 if fields[0]:raise ValueError(f'native Library status{fields[0]}')
 return fields,raw[64:]

def main(argv=None):
 p=argparse.ArgumentParser(description='Native Library explicit role setup and read-only inspection')
 p.add_argument('--socket',required=True,type=Path);p.add_argument('--instance',required=True,type=int)
 sub=p.add_subparsers(dest='command',required=True)
 q=sub.add_parser('configure');q.add_argument('--federation',required=True)
 q=sub.add_parser('replicate');q.add_argument('--federation',required=True);q.add_argument('--collection',required=True);q.add_argument('--bytes',type=int,required=True)
 sub.add_parser('state')
 for name in ('row','job'):
  q=sub.add_parser(name);q.add_argument('index',type=int)
 for name in ('pause','retry','cancel'):
  q=sub.add_parser(name);q.add_argument('index',type=int)
  if name=='retry':q.add_argument('--provider',type=int,choices=(1,2),required=True)
 a=p.parse_args(argv);c=live.Client(a.socket)
 try:
  if a.command in ('configure','replicate'):
   federation=bytes.fromhex(a.federation)
   if len(federation)!=32 or not any(federation):raise ValueError('nonzero federation identity32 required')
   c.request(184,struct.pack('<Q',a.instance))
   if a.command=='configure':f,_=call(c,a.instance,700,data=federation)
   else:
    collection=bytes.fromhex(a.collection)
    if len(collection)!=32 or not any(collection):raise ValueError('nonzero selected collection identity32 required')
    f,_=call(c,a.instance,706,a=a.bytes,data=federation+collection)
   result={'instance':a.instance,'configured':True,'role':'personal native selection' if a.command=='configure' else 'explicit headless acquisition','retention':'separate approval required','seed_sources':[1] if a.command=='replicate' else [1,2]}
  elif a.command=='state':
   f,_=call(c,a.instance,701);result=dict(records=f[1],selected=f[2],monitoring=bool(f[3]),automatic_acquisition=bool(f[4]),approved_bytes_used=f[5],notice=f[6])
  elif a.command in ('pause','retry','cancel'):
   f,_=call(c,a.instance,707,a.index,{'pause':1,'retry':2,'cancel':3}[a.command],getattr(a,'provider',0));result=dict(job=f[1],state=f[2],control=a.command,authority='existing frozen native operation and policy only')
  elif a.command=='row':
   f,data=call(c,a.instance,703,a.index,0,128)
   words=struct.unpack('<16Q',data);result=dict(index=a.index,present=bool(words[0]),metadata_added=bool(words[1]),local_content_reference=bool(words[2]),availability=words[3],pin=bool(words[4]),reason=words[5],job=words[8])
  else:
   f,data=call(c,a.instance,704,a.index,0,128)
   words=struct.unpack('<16Q',data);result=dict(index=a.index,state=words[0],record=words[1],provider=words[2],content_reference=bool(words[3]),chunk=words[4],chunk_offset=words[5],validation_job=bool(words[6]),bytes_received=words[7],policy_generation=words[8],byte_ceiling=words[9],operation_id=words[10],error=words[12],mode=words[13],source_mask=words[14])
  print(json.dumps(result,indent=2));return 0
 finally:c.close()

if __name__=='__main__':raise SystemExit(main())
