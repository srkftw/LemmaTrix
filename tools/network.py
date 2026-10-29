"""Explicit pairwise Noise provisioning and bounded guest broker IPC.

The host supplies selected credentials and moves opaque management bytes. All
handshake, record protection, pin/grant checks and peer messages execute in Lean.
"""
import argparse,json,os,stat,struct
from pathlib import Path
import live
MAGIC=b'LTNPSK1\0'

def digest(value):
 raw=bytes.fromhex(value)
 if len(raw)!=32 or not any(raw):raise ValueError('identity/service/root must be a nonzero32-byte hexadecimal digest')
 return raw

def provision(client_path,server_path,client_id,server_id,service_id):
 if client_path.resolve()==server_path.resolve():raise ValueError('ordered roles require separate credential files')
 if client_id==server_id:raise ValueError('client and server identities must be distinct')
 material=client_id+server_id+service_id+os.getrandom(32)
 if len(material)!=128:raise ValueError('entropy or provisioning extent failure')
 created=[]
 try:
  for path,role in [(client_path,1),(server_path,2)]:
   fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);created.append(path)
   try:
    raw=struct.pack('<8s3Q',MAGIC,1,role,128)+material
    written=os.write(fd,raw)
    if written!=len(raw):raise OSError('short credential write')
    os.fsync(fd)
   finally:os.close(fd)
 except BaseException:
  for path in created:path.unlink(missing_ok=True)
  raise
 return {'client_credentials':str(client_path),'server_credentials':str(server_path),'client_id':client_id.hex(),'server_id':server_id.hex(),'service_id':service_id.hex(),'profile':'Noise_NNpsk0_25519_ChaChaPoly_SHA256','secret':'fresh ordered pairwise PSK; secret bytes omitted'}

def load_credentials(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  info=os.fstat(fd)
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)&0o077:raise ValueError('credentials require an owned regular file without group/other permissions')
  raw=os.read(fd,161)
 finally:os.close(fd)
 if len(raw)!=160:raise ValueError('credentials must be exactly160 bytes')
 magic,version,role,size=struct.unpack_from('<8s3Q',raw)
 if magic!=MAGIC or version!=1 or role not in (1,2) or size!=128:raise ValueError('unsupported credential profile')
 if not all(any(raw[i:i+32]) for i in range(32,160,32)) or raw[32:64]==raw[64:96]:raise ValueError('invalid ordered pins or key')
 return role,raw[32:]

def call(client,op,h=0,a=0,b=0,c=0,d=0,e=0,data=b'',allow_error=False):
 if len(data)>720:raise ValueError('broker application payload exceeds720 bytes')
 raw=client.request(170,struct.pack('<8Q',op,h,a,b,c,d,e,1)+data)
 if len(raw)<64 or len(raw)>784:raise ValueError('invalid broker response length')
 fields=struct.unpack_from('<8Q',raw)
 if fields[0] and not allow_error:raise ValueError(f'guest network broker status{fields[0]}')
 return fields,raw[64:]

def configure(client,path):
 role,material=load_credentials(path)
 call(client,1,a=role,data=material)
 return {'role':'client' if role==1 else 'server','client_id':material[:32].hex(),'server_id':material[32:64].hex(),'service_id':material[64:96].hex(),'configured':True,'authenticated':False}

def status(client):
 f,_=call(client,7)
 return {'protocol_version':1,'profile':'Noise_NNpsk0_25519_ChaChaPoly_SHA256','session_phase':f[1],'endpoint_authenticated':f[1]==3,'configured_role':{0:'unconfigured',1:'client',2:'server'}.get(f[2],'invalid'),'device_status':f[3],'broker_ticks':f[4],'last_error':f[5],'traffic_privacy':'direct endpoints visible; no anonymity','modes_available':['encrypted_bulk']}

def main(argv=None):
 p=argparse.ArgumentParser(description='Explicit ordered Noise relationship provisioning; private files contain a PSK')
 sub=p.add_subparsers(dest='command',required=True)
 q=sub.add_parser('init');q.add_argument('--client-out',type=Path,required=True);q.add_argument('--server-out',type=Path,required=True);q.add_argument('--client-id',required=True);q.add_argument('--server-id',required=True);q.add_argument('--service-id',required=True)
 q=sub.add_parser('configure');q.add_argument('--socket',type=Path,required=True);q.add_argument('--credentials',type=Path,required=True)
 for command in ('status','reset'):
  q=sub.add_parser(command);q.add_argument('--socket',type=Path,required=True)
 a=p.parse_args(argv)
 if a.command=='init':result=provision(a.client_out,a.server_out,digest(a.client_id),digest(a.server_id),digest(a.service_id))
 else:
  client=live.Client(a.socket)
  try:
   if a.command=='configure':result=configure(client,a.credentials)
   elif a.command=='status':result=status(client)
   else:call(client,9);result={'reset':True,'pending_jobs':'failed; reauthorize application resumption'}
  finally:client.close()
 print(json.dumps(result,indent=2));return 0

if __name__=='__main__':raise SystemExit(main())
