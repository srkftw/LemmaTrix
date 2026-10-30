"""Explicit pairwise Noise provisioning and bounded guest broker IPC.

The host supplies selected credentials and moves opaque management bytes. All
handshake, record protection, pin/grant checks and peer messages execute in Lean.
"""
import argparse,hashlib,json,os,stat,struct,tempfile
from pathlib import Path
import live
import capsule,releases
MAGIC=b'LTNPSK1\0'
DESCRIPTION_MAGIC=0x315653444e544c

def load_description(path):
 with Path(path).open('rb') as source:raw=source.read(1025)
 if len(raw)!=1024:raise ValueError('public service description must contain1024bytes')
 public,descriptor,signature=raw[:256],raw[256:768],raw[768:]
 q=struct.unpack('<8Q',descriptor[:64]);n=struct.unpack_from('<Q',descriptor,160)[0]
 profile=(q[1]==(1 if q[2]<=4 else 2) and q[6]==16777216) or (q[2] in (5,6) and q[1]==3 and q[6]==134217728)
 if q[0]!=DESCRIPTION_MAGIC or not profile or not 1<=q[2]<=6 or q[3:6]!=(3,2 if q[2]<=2 else 6 if q[2]<=4 else 4,720) or q[7]!=65536 or not 0<n<=96 or any(c<33 or c>126 for c in descriptor[168:168+n]) or descriptor[168+n:]!=bytes(512-168-n):raise ValueError('invalid signed service descriptor profile/padding')
 if not public[0]&128 or not public[-1]&1 or hashlib.sha256(public).digest()!=descriptor[96:128] or not any(descriptor[64:96]) or descriptor[64:96]==descriptor[96:128]:raise ValueError('service public identity/pair binding mismatch')
 modulus=int.from_bytes(public,'big');s=int.from_bytes(signature,'big')
 expected=b'\x00\x01'+b'\xff'*202+b'\x00'+bytes.fromhex('3031300d060960864801650304020105000420')+hashlib.sha256(descriptor).digest()
 if s>=modulus or pow(s,65537,modulus).to_bytes(256,'big')!=expected:raise ValueError('public service descriptor signature failed')
 return public,descriptor,signature

def create_description(key,client_id,endpoint,kind,output,image_id=None,max_grant=None):
 public=capsule.modulus(key);server_id=hashlib.sha256(public).digest();text=endpoint.encode('ascii')
 if client_id==server_id or not 0<len(text)<=96 or any(c<33 or c>126 for c in text):raise ValueError('distinct ordered client ID and1..96 ASCII endpoint required')
 role=('forge','registry','builder','verifier','library-registry','library-seed').index(kind)+1
 max_grant=max_grant if max_grant is not None else (134217728 if role>=5 else 16777216)
 if max_grant not in (16777216,134217728) or (role<=4 and max_grant!=16777216):raise ValueError('large grant profile requires an explicit Library service role')
 version=3 if max_grant==134217728 else (1 if role<=4 else 2)
 descriptor=bytearray(512);struct.pack_into('<8Q',descriptor,0,DESCRIPTION_MAGIC,version,role,3,2 if role<=2 else 6 if role<=4 else 4,720,max_grant,65536)
 descriptor[64:96]=client_id;descriptor[96:128]=server_id
 descriptor[128:160]=image_id or bytes(32);struct.pack_into('<Q',descriptor,160,len(text));descriptor[168:168+len(text)]=text
 with tempfile.TemporaryDirectory(prefix='lt-service-sign-') as directory:
  source=Path(directory)/'description';source.write_bytes(descriptor)
  signature=releases.pkg.crypto(['dgst','-sha256','-sign',key,source]).stdout
 if len(signature)!=256:raise ValueError('RSA2048 service signature required')
 releases.pkg.write_new(output,public+descriptor+signature)
 load_description(output)
 return {'path':str(output),'client_id':client_id.hex(),'server_id':server_id.hex(),'service_id':hashlib.sha256(descriptor).hexdigest(),'kind':kind,'version':version,'max_grant_bytes':max_grant,'endpoint_declaration':endpoint,'image_declaration':bytes(descriptor[128:160]).hex(),'signature':'RSA2048/SHA256; independent of pairwise Noise MAC and publisher/federation keys'}

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

def call(client,op,h=0,a=0,b=0,c=0,d=0,e=0,data=b'',allow_error=False,slot=None):
 if len(data)>(768 if op==11 else 720):raise ValueError('broker payload exceeds selected operation extent')
 raw=client.request(170,struct.pack('<8Q',op,h,a,b,c,d,e,1 if slot is None else 2 | (slot<<8))+data)
 if len(raw)<64 or len(raw)>784:raise ValueError('invalid broker response length')
 fields=struct.unpack_from('<8Q',raw)
 if fields[0] and not allow_error:raise ValueError(f'guest network broker status{fields[0]}')
 return fields,raw[64:]

def configure(client,path,description=None,slot=None):
 role,material=load_credentials(path)
 if description:
  public,descriptor,signature=load_description(description)
  if material[:96]!=descriptor[64:128]+hashlib.sha256(descriptor).digest():raise ValueError('credentials differ from selected signed public relationship/service')
  call(client,11,data=public+descriptor,slot=slot);call(client,12,data=signature,slot=slot)
 call(client,1,a=role,data=material,slot=slot)
 return {'role':'client' if role==1 else 'server','client_id':material[:32].hex(),'server_id':material[32:64].hex(),'service_id':material[64:96].hex(),'configured':True,'authenticated':False,'signed_description_supplied':bool(description),'peer_authentication':'ordered pairwise Noise secret; public service signature is separately checked'}

def status(client,slot=None):
 f,_=call(client,7,slot=slot)
 return {'protocol_version':1 if slot is None else 2,'connection_slot':slot or 0,'profile':'Noise_NNpsk0_25519_ChaChaPoly_SHA256','session_phase':f[1],'endpoint_authenticated':f[1]==3,'configured_role':{0:'unconfigured',1:'client',2:'server'}.get(f[2],'invalid'),'device_status':f[3],'broker_ticks':f[4],'last_error':f[5],'inbox_records':f[6],'public_service_description_verified':f[7]==1,'traffic_privacy':'direct endpoints visible; no anonymity','modes_available':['encrypted_bulk']}

def main(argv=None):
 p=argparse.ArgumentParser(description='Explicit ordered Noise relationship provisioning; private files contain a PSK')
 sub=p.add_subparsers(dest='command',required=True)
 q=sub.add_parser('description');q.add_argument('--sign-key',type=Path,required=True);q.add_argument('--client-id',required=True);q.add_argument('--endpoint',required=True);q.add_argument('--kind',choices=('forge','registry','builder','verifier','library-registry','library-seed'),required=True);q.add_argument('--image-id');q.add_argument('--max-grant',type=int,choices=(16777216,134217728),help='finite signed wire budget ceiling; large profile only for Library roles');q.add_argument('--output',type=Path,required=True)
 q=sub.add_parser('inspect-description');q.add_argument('description',type=Path)
 q=sub.add_parser('init');q.add_argument('--client-out',type=Path,required=True);q.add_argument('--server-out',type=Path,required=True);q.add_argument('--client-id');q.add_argument('--server-id');q.add_argument('--service-id');q.add_argument('--description',type=Path)
 q=sub.add_parser('configure');q.add_argument('--socket',type=Path,required=True);q.add_argument('--credentials',type=Path,required=True);q.add_argument('--description',type=Path)
 q.add_argument('--slot',type=int,choices=range(4))
 for command in ('status','reset','open','remove','performance'):
  q=sub.add_parser(command);q.add_argument('--socket',type=Path,required=True);q.add_argument('--slot',type=int,choices=range(4))
 a=p.parse_args(argv)
 if a.command=='description':result=create_description(a.sign_key,digest(a.client_id),a.endpoint,a.kind,a.output,digest(a.image_id) if a.image_id else None,a.max_grant)
 elif a.command=='inspect-description':
  public,descriptor,signature=load_description(a.description);n=struct.unpack_from('<Q',descriptor,160)[0]
  result={'version':struct.unpack_from('<Q',descriptor,8)[0],'server_id':descriptor[96:128].hex(),'client_id':descriptor[64:96].hex(),'service_id':hashlib.sha256(descriptor).hexdigest(),'endpoint_declaration':descriptor[168:168+n].decode('ascii'),'max_grant_bytes':struct.unpack_from('<Q',descriptor,48)[0],'signature_verified':True,'verification_authority':'explicitly selected public description; guest checks it independently at configure'}
 elif a.command=='init':
  if a.description:
   _,descriptor,_=load_description(a.description);pins=descriptor[64:128]+hashlib.sha256(descriptor).digest()
   supplied=(a.client_id,a.server_id,a.service_id)
   if any(value is not None and digest(value)!=pins[i*32:(i+1)*32] for i,value in enumerate(supplied)):raise ValueError('explicit pins differ from selected public descriptor')
   result=provision(a.client_out,a.server_out,pins[:32],pins[32:64],pins[64:96])
  else:
   if not all((a.client_id,a.server_id,a.service_id)):raise ValueError('select a signed description or all three explicit legacy pins')
   result=provision(a.client_out,a.server_out,digest(a.client_id),digest(a.server_id),digest(a.service_id))
 else:
  client=live.Client(a.socket)
  try:
   if a.command=='configure':result=configure(client,a.credentials,a.description,a.slot)
   elif a.command=='status':result=status(client,a.slot)
   elif a.command=='performance':
    fields,raw=call(client,16,slot=a.slot)
    if len(raw)!=96:raise ValueError('wrong bounded diagnostic length')
    names=('context_switch_ticks','seal_ticks','open_ticks','pump_ticks','context_switches','seal_attempts','open_attempts','pump_turns','rpc_calls','bounded_waits','no_progress_waits','burst_limit_yields')
    result=dict(zip(names,struct.unpack('<12Q',raw)))
    result.update(scope='aggregate node diagnostics; management authority only',time_basis='local monotonic ticks including preemption; not CPU cycles or billing',traffic_privacy='no per-content or per-peer association history')
   else:
    if a.command in ('open','remove') and a.slot is None:raise ValueError('multiplex transport open/remove requires --slot')
    call(client,{'reset':9,'open':13,'remove':14}[a.command],slot=a.slot);result={a.command:True,'connection_slot':a.slot or 0,'pending_jobs':'old authority never resumes; issue fresh grants after authentication'}
  finally:client.close()
 print(json.dumps(result,indent=2));return 0

if __name__=='__main__':raise SystemExit(main())
