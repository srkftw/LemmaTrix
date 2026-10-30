"""Opaque setup and inspection of the native Library; policies execute in Lean."""
import argparse, json, struct
from pathlib import Path
import live

def call(client,instance,op,h=0,a=0,b=0,data=b'',c=0,d=0,e=0):
 raw=client.request(150,struct.pack('<Q8Q',instance,op,h,a,b,c,d,e,1)+data)
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
 q=sub.add_parser('policy');q.add_argument('--collection',required=True);q.add_argument('--federation',required=True);q.add_argument('--bytes',type=int,required=True);q.add_argument('--providers',type=int,choices=(2,4,6),default=6);q.add_argument('--mode',type=int,choices=(1,2,3,4),default=3);q.add_argument('--retention',type=int,choices=(0,1),default=0);q.add_argument('--generation',type=int,default=0)
 for name in ('monitor','revoke-policy'):
  q=sub.add_parser(name);q.add_argument('--collection',required=True);q.add_argument('--federation',required=True)
 q=sub.add_parser('open-item');q.add_argument('--permit',type=int,required=True);q.add_argument('--operation',type=int,required=True);q.add_argument('--registry',type=int);q.add_argument('--cursor',type=int,default=0)
 q=sub.add_parser('export');q.add_argument('--output',type=Path,required=True)
 for name in ('collection','save-policy','recover-policy','bind-store'):
  q=sub.add_parser(name);q.add_argument('index',type=int,choices=range(8))
  if name in ('save-policy','recover-policy'):q.add_argument('--vault-slot',type=int,choices=range(8),required=True)
  if name=='bind-store':q.add_argument('--permit',type=int,required=True)

 for name in ('row','job'):
  q=sub.add_parser(name);q.add_argument('index',type=int)
 for name in ('pause','retry','cancel'):
  q=sub.add_parser(name);q.add_argument('index',type=int)
  if name=='retry':q.add_argument('--provider',type=int,choices=(1,2),required=True)
 a=p.parse_args(argv);c=live.Client(a.socket)
 try:
  if a.command=='export':
   import hashlib,os,inventory,content
   f,_=call(c,a.instance,725)
   if f[4]!=1:raise ValueError('press X in the native Library to select one complete item for export')
   nonce=f[1];destination=hashlib.sha256(b'LT-selected-export-destination-v1\0'+os.urandom(32)).digest()
   f,_=call(c,a.instance,725,nonce,data=destination)
   handle=f[3]
   try:
    result=inventory.export(c,handle,a.output)
    call(c,a.instance,726,nonce)
    result.update(native_selection=nonce,destination_acknowledged=True,scope='one native selected immutable content root')
   finally:content.api(c).objects(309,handle)
  elif a.command=='open-item':
   import inventory
   if a.registry is not None:
    import federation
    q,admission=federation.call(c,a.registry,6,h=a.cursor)
    _,consumer=federation.call(c,a.registry,20,h=q[2])
    selected=admission+consumer
    if len(selected)!=1536:raise ValueError('selected native catalog record is incomplete')
   else:selected=b''.join(inventory.call(c,265,a.permit,offset,512)[1] for offset in (0,512,1024))
   fields,_=inventory.open_item(c,a.permit,a.instance,a.operation)
   original=c.import_object(selected,kind=2)
   delegated=c.objects(6,original,a.instance,25)[0][1]
   try:
    f,_=call(c,a.instance,724,delegated,fields[1],fields[6])
    result=dict(row=f[1],opened=True,network_required=False,payload_rehydrated=False,metadata_bytes=len(selected))
   finally:c.objects(47,original)
  elif a.command in ('policy','monitor','revoke-policy'):

   import inventory
   collection=inventory.identity(a.collection);federation=inventory.identity(a.federation)
   action={'policy':1,'monitor':2,'revoke-policy':3}[a.command]
   f,_=call(c,a.instance,720,action,getattr(a,'bytes',1),getattr(a,'providers',0),data=collection+federation,c=getattr(a,'mode',3),d=getattr(a,'retention',0),e=getattr(a,'generation',0))
   result=dict(collection_slot=f[1],generation=f[2],monitoring=bool(f[3]),acquisition_authorized=bool(f[4]),bytes_reserved=f[5])
  elif a.command in ('collection','save-policy','recover-policy','bind-store'):
   import inventory
   if a.command=='bind-store':
    f,_=call(c,a.instance,722,a.index,a.permit);result=dict(collection_slot=f[1],live_storage_permit_bound=True)
   elif a.command=='recover-policy':
    _,record=inventory.call(c,275,a.vault_slot)
    f,_=call(c,a.instance,723,a.index,data=record)
    result=dict(collection_slot=f[1],recovered=True,acquisition='awaiting explicit renewal',old_live_grants_restored=False)
   else:
    _,record=call(c,a.instance,721,a.index)
    if a.command=='save-policy':
     f,_=inventory.call(c,274,a.vault_slot,data=record)
     result=dict(vault_slot=f[1],generation=f[2],encrypted=True,live_grants_persisted=False)
    else:
     q=lambda offset:struct.unpack_from('<Q',record,offset)[0]
     result=dict(slot=a.index,present=bool(q(0)),generation=q(8),monitoring=bool(q(16)),acquisition_authorized=bool(q(24)),byte_ceiling=q(48),bytes_reserved=q(56),providers=q(64),mode=q(72),retention=q(88),awaiting_approval=bool(q(96)),collection=record[160:192].hex(),federation=record[192:224].hex(),last_matched_edition=record[224:256].hex(),matches=q(256))
  elif a.command in ('configure','replicate'):

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
   f,_=call(c,a.instance,701)
   records=[call(c,a.instance,721,i)[1] for i in range(8)]
   q=lambda record,offset:struct.unpack_from('<Q',record,offset)[0]
   active=[r for r in records if q(r,0)]
   result=dict(records=f[1],selected=f[2],collections=len(active),monitoring=sum(q(r,16) for r in active),automatic_acquisition=sum(q(r,24) for r in active),approved_bytes_reserved=sum(q(r,56) for r in active),notice=f[6])
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
