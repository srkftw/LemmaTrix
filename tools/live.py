"""Byte transport and CLI for a long-lived guest; all platform state is guest-owned."""
import argparse,hashlib,json,os,select,socket,struct,subprocess,sys,time
from pathlib import Path
import driver,releases,capsule
MAGIC=b'LT2\0';REPLY=b'LR2\0'
def args_for(backend,image,vault=None,readonly=False):
 if backend=='qemu':
  args=[driver.tool('qemu-system-riscv64'),'-M','virt','-cpu','rv64','-m','128M','-smp','1','-bios','none','-nographic','-monitor','none','-global','virtio-mmio.force-legacy=true','-kernel',str(image),'-object','rng-random,filename=/dev/urandom,id=lt-rng','-device','virtio-rng-device,rng=lt-rng']
  if vault:args+=['-drive',f'file={vault},format=raw,if=none,id=lt-vault'+(',readonly=on' if readonly else ''),'-device','virtio-blk-device,drive=lt-vault']
  return args
 args=[str(driver.BUILD/('lt-'+backend)),str(image),'--interactive']
 if backend=='aarch64':args.insert(0,driver.tool('qemu-aarch64'))
 if vault:args+=['--vault',str(vault)]
 if readonly:args+=['--vault-readonly']
 return args

def session(backend,path,vault=None,readonly=False):
 image=driver.BUILD/'live/guest.bin'
 if not image.exists():raise ValueError('run ./lt live-build first')
 if vault:
  vault=vault.resolve()
  if not vault.is_file():raise ValueError('vault backing must be an explicitly supplied existing image')
 if path.exists():raise ValueError('socket path exists; refusing to replace it')
 server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
 process=subprocess.Popen(args_for(backend,image,vault,readonly),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=None,bufsize=0)
 client=None;pending=bytearray()
 try:
  # Transport readiness only: no requests are interpreted or approved here.
  # Do not advertise a portal until the Lean launcher has completed boot and
  # emitted its empty rid0 ready frame; boot UART reset must not discard input.
  ready=struct.pack('<4sIQQQ',REPLY,0,0,0,0);deadline=time.monotonic()+60
  while ready not in pending:
   if process.poll() is not None:raise RuntimeError('guest exited before launcher readiness: '+repr(bytes(pending[-512:])))
   if time.monotonic()>deadline:raise TimeoutError('guest launcher readiness timeout')
   active,_,_=select.select([process.stdout],[],[],0.5)
   if active:
    data=os.read(process.stdout.fileno(),4096)
    if not data:raise EOFError('guest closed output before readiness')
    pending.extend(data)
    if len(pending)>131072:raise ValueError('unbounded guest startup output')
  server.bind(str(path));os.chmod(path,0o600);server.listen(8)
  print('SESSION',backend,'socket',path,'image',hashlib.sha256(image.read_bytes()).hexdigest(),flush=True)
  os.set_blocking(process.stdin.fileno(),False)
  os.set_blocking(process.stdout.fileno(),False)
  server.setblocking(False)
  outbound=bytearray()
  while process.poll() is None:
   readers=[server,process.stdout]
   if client and len(outbound)<16384:readers.append(client)
   writers=([process.stdin] if outbound else [])+([client] if client and pending else [])
   active,writable,_=select.select(readers,writers,[],1)
   for src in active:
    if src is server:
     try:new,_=server.accept()
     except BlockingIOError:continue
     new.setblocking(False)
     if client:client.close()
     client=new
    elif src is process.stdout:
     try:data=os.read(process.stdout.fileno(),65536)
     except BlockingIOError:continue
     if not data:continue
     pending.extend(data)
     if len(pending)>131072:
      # A nonreading frontend cannot block management or another connection.
      # Disconnect it and retain only bounded transport output for resync.
      if client:client.close();client=None
      del pending[:-131072]
    elif src is client:
     try:data=client.recv(min(16384-len(outbound),65536))
     except BlockingIOError:continue
     except ConnectionResetError:data=b''
     if not data:client.close();client=None
     else:outbound.extend(data)
   for dst in writable:
    if dst is process.stdin:
     try:sent=os.write(process.stdin.fileno(),outbound)
     except BlockingIOError:continue
     except BrokenPipeError:break
     del outbound[:sent]
    elif dst is client and pending:
     try:sent=client.send(pending)
     except BlockingIOError:continue
     except (BrokenPipeError,ConnectionResetError):client.close();client=None;continue
     del pending[:sent]
  return process.wait()
 finally:
  if client:client.close()
  server.close();path.unlink(missing_ok=True)
  if process.poll() is None:process.terminate();process.wait(timeout=5)
class Client:
 def __init__(self,path,timeout=180):
  self.stream=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.stream.settimeout(timeout);self.stream.connect(str(path));self.buffer=bytearray();self.counter=time.time_ns()
 def close(self):self.stream.close()
 def request(self,op,payload=b'',rid=None):
  if len(payload)>1024:raise ValueError('frame payload exceeds1024')
  if rid is None:self.counter=max(self.counter+1,time.time_ns());rid=self.counter
  self.stream.sendall(struct.pack('<4sIQQQ',MAGIC,len(payload),rid,op,0)+payload)
  while True:
   where=self.buffer.find(REPLY)
   if where>=0:
    if where:del self.buffer[:where]
    if len(self.buffer)>=32:
     magic,status,answer,length,reserved=struct.unpack_from('<4sIQQQ',self.buffer)
     if length>1024 or reserved:raise ValueError('invalid guest reply frame')
     if len(self.buffer)>=32+length:
      out=bytes(self.buffer[32:32+length]);del self.buffer[:32+length]
      if answer!=rid:continue
      if status:raise ValueError(f'guest rejected command{op}, status{status}')
      return out
   elif len(self.buffer)>4096:
    # App output is kernel-framed ASCII hex, never a permission/control frame.
    del self.buffer[:-3]
   data=self.stream.recv(65536)
   if not data:raise EOFError('management session closed')
   self.buffer.extend(data)
 def objects(self,op,h=0,a=0,b=0,c=0,d=0,e=0,data=b''):
  raw=self.request(100,struct.pack('<8Q',op,h,a,b,c,d,e,1)+data)
  if len(raw)<64:raise ValueError('short Objects response')
  fields=struct.unpack_from('<8Q',raw)
  if fields[0]:raise ValueError(f'Objects status{fields[0]}')
  return fields,raw[64:]
 def import_object(self,data,kind=1,parent=0):
  if len(data)>65536:raise ValueError('object exceeds64KiB')
  fields,_=self.objects(1,parent,len(data),kind,1,data=hashlib.sha256(data).digest());handle=fields[1]
  try:
   for offset in range(0,len(data),512):self.objects(2,handle,offset,data=data[offset:offset+512])
   return self.objects(3,handle,data=hashlib.sha256(data).digest())[0][1]
  except BaseException:
   try:self.objects(13,handle)
   except Exception:pass
   raise
 def read_object(self,h,export=False):
  fields,_=self.objects(5,h);length=fields[2];out=bytearray()
  for offset in range(0,length,512):out.extend(self.objects(14 if export else 4,h,offset,min(512,length-offset))[1])
  return bytes(out)
 def stage(self,path):
  raw=Path(path).read_bytes();self.request(20,struct.pack('<Q',len(raw)))
  for offset in range(0,len(raw),512):self.request(21,struct.pack('<Q',offset)+raw[offset:offset+512])
  header=self.request(22)
  if header!=raw[:512]:raise ValueError('guest inspected a different candidate header')
  return releases.inspect(raw)
 def install(self,path):
  info=self.stage(path)
  self.request(23,bytes.fromhex(info['release_id'])+struct.pack('<Q',info['rights']))
  slot=struct.unpack_from('<Q',self.request(24),8)[0]
  return slot,info

def main(argv=None):
 p=argparse.ArgumentParser(description='Live byte portal; guest owns all state and policy')
 sub=p.add_subparsers(dest='mode',required=True)
 s=sub.add_parser('session');s.add_argument('--backend',choices=['qemu','x86_64','aarch64'],default='qemu');s.add_argument('--socket',required=True,type=Path);s.add_argument('--vault',type=Path);s.add_argument('--vault-readonly',action='store_true')
 v=sub.add_parser('vault-init');v.add_argument('path',type=Path);v.add_argument('--sectors',type=int,default=512);v.add_argument('--key-out',type=Path)
 c=sub.add_parser('ctl');c.add_argument('--socket',required=True,type=Path);cs=c.add_subparsers(dest='command',required=True)
 for name in ['ping','processes','cancel','gc','objects-gc','list','stats','shutdown']:cs.add_parser(name)
 trust=cs.add_parser('trust');trust.add_argument('--project',required=True);trust.add_argument('--public',required=True,type=Path)
 untrust=cs.add_parser('untrust');untrust.add_argument('key_id')
 for name in ['inspect','install']:
  a=cs.add_parser(name);a.add_argument('release',type=Path)
  if name=='install':a.add_argument('--approve-release');a.add_argument('--rights',type=lambda x:int(x,0))
 approve=cs.add_parser('approve');approve.add_argument('release_id');approve.add_argument('--rights',required=True,type=lambda x:int(x,0))
 cs.add_parser('activate')
 for name in ['start','stop','service-stop','service-restart']:
  a=cs.add_parser(name);a.add_argument('identity',type=lambda x:int(x,0))
 a=cs.add_parser('restart');a.add_argument('identity',type=lambda x:int(x,0));a.add_argument('--release-slot',required=True,type=int)
 for name in ['rollback','active']:
  a=cs.add_parser(name);a.add_argument('project')
 a=cs.add_parser('revoke-release');a.add_argument('release_id')
 a=cs.add_parser('import');a.add_argument('path',type=Path);a.add_argument('--kind',type=int,default=1);a.add_argument('--parent',type=lambda x:int(x,0),default=0)
 for name in ['metadata','read','drop']:
  a=cs.add_parser(name);a.add_argument('handle',type=lambda x:int(x,0))
 a=cs.add_parser('export');a.add_argument('handle',type=lambda x:int(x,0));a.add_argument('--output',type=Path,required=True)
 a=cs.add_parser('share');a.add_argument('handle',type=lambda x:int(x,0));a.add_argument('--to',type=lambda x:int(x,0),required=True);a.add_argument('--rights',type=lambda x:int(x,0),required=True)
 a=cs.add_parser('revoke');a.add_argument('handle',type=lambda x:int(x,0));a.add_argument('--grant',type=lambda x:int(x,0),required=True)
 a=cs.add_parser('edit');a.add_argument('instance',type=lambda x:int(x,0));a.add_argument('handle',type=lambda x:int(x,0));a.add_argument('--offset',type=int,required=True);a.add_argument('--delete',type=int,default=0);a.add_argument('--replacement',type=Path,required=True)
 a=cs.add_parser('app');a.add_argument('instance',type=lambda x:int(x,0));a.add_argument('--operation',type=int,required=True);a.add_argument('--handle',type=lambda x:int(x,0),default=0);a.add_argument('--a',type=lambda x:int(x,0),default=0);a.add_argument('--b',type=lambda x:int(x,0),default=0);a.add_argument('--data',type=Path)
 va=cs.add_parser('vault');vs=va.add_subparsers(dest='vault_command',required=True)
 for name in ['status','lock','recover','delete']:vs.add_parser(name)
 a=vs.add_parser('unlock');a.add_argument('--key',type=Path,required=True)
 a=vs.add_parser('retain');a.add_argument('handle',type=lambda x:int(x,0))
 args=p.parse_args(argv)
 if args.mode=='session':return session(args.backend,args.socket,args.vault,args.vault_readonly)
 if args.mode=='vault-init':
  if args.sectors<304:raise ValueError('development Objects vault needs >=304 sectors')
  if args.path.exists() or (args.key_out and args.key_out.exists()):raise ValueError('vault/key output exists; refusing overwrite')
  with args.path.open('xb') as f:f.truncate(args.sectors*512)
  if args.key_out:
   with args.key_out.open('xb') as key:
    os.fchmod(key.fileno(),0o600);key.write(os.urandom(32))
  print('Created explicit development backing image',args.path);return 0
 client=Client(args.socket)
 try:
  cmd=args.command
  if cmd=='list':
   entries=[];cursor=0
   while cursor<256:
    record,_=client.objects(9,a=cursor)
    if not record[1]:break
    entries.append(record);cursor=(record[1]&255)+1
   print(json.dumps(entries,indent=2))
  elif cmd in ['objects-gc','stats']:
   print(client.objects({'objects-gc':11,'stats':10}[cmd])[0])
  elif cmd in ['ping','processes','cancel','gc','shutdown']:
   try:raw=client.request({'ping':1,'processes':2,'cancel':3,'gc':31,'shutdown':70}[cmd])
   except EOFError:
    if cmd!='shutdown':raise
    raw=b''
   if cmd=='processes':print(json.dumps([dict(zip(['instance','state','rights','exit_cause'],struct.unpack_from('<4Q',raw,i))) for i in range(0,len(raw),32)],indent=2))
   else:print(raw.hex())
  elif cmd=='trust':
   # Public key path is used only to export modulus; private material never enters transport.
   modulus=releases.public_modulus(args.public)
   print(client.request(10,releases.project(args.project)+modulus).hex())
  elif cmd=='untrust':print(client.request(11,bytes.fromhex(args.key_id)).hex())
  elif cmd=='inspect':print(json.dumps(client.stage(args.release),indent=2))
  elif cmd=='approve':print(client.request(23,bytes.fromhex(args.release_id)+struct.pack('<Q',args.rights)).hex())
  elif cmd=='activate':print(struct.unpack_from('<Q',client.request(24),8)[0])
  elif cmd=='install':
   info=client.stage(args.release);print(json.dumps(info,indent=2))
   if args.approve_release is not None:
    if args.approve_release!=info['release_id'] or args.rights!=info['rights']:raise ValueError('explicit approval must match the exact inspected release and rights')
    client.request(23,bytes.fromhex(args.approve_release)+struct.pack('<Q',args.rights))
    print('Installed release slot',struct.unpack_from('<Q',client.request(24),8)[0])
   else:print('Candidate staged; use approve RELEASE_ID --rights MASK then activate, or install with --approve-release and --rights')
  elif cmd in ['start','stop','service-stop','service-restart']:print(struct.unpack_from('<Q',client.request({'start':25,'stop':26,'service-stop':32,'service-restart':33}[cmd],struct.pack('<Q',args.identity)),8)[0])
  elif cmd=='restart':print(struct.unpack_from('<Q',client.request(27,struct.pack('<2Q',args.identity,args.release_slot)),8)[0])
  elif cmd in ['rollback','active']:
   raw=client.request(28 if cmd=='rollback' else 29,releases.project(args.project));print(raw.hex())
  elif cmd=='revoke-release':print(client.request(30,bytes.fromhex(args.release_id)).hex())
  elif cmd=='import':print(client.import_object(args.path.read_bytes(),args.kind,args.parent))
  elif cmd=='metadata':
   fields,digest=client.objects(5,args.handle);print(json.dumps({'fields':fields,'sha256':digest.hex()},indent=2))
  elif cmd=='read':print(repr(client.read_object(args.handle)))
  elif cmd=='export':
   with args.output.open('xb') as f:f.write(client.read_object(args.handle,True))
  elif cmd=='drop':print(client.objects(8,args.handle)[0])
  elif cmd=='share':print(client.objects(6,args.handle,args.to,args.rights)[0][1])
  elif cmd=='revoke':print(client.objects(7,args.handle,args.grant)[0])
  elif cmd=='edit':
   data=args.replacement.read_bytes()
   if len(data)>512:raise ValueError('patch replacement is bounded to512bytes per edit')
   raw=client.request(150,struct.pack('<Q8Q',args.instance,23,args.handle,args.offset,args.delete,0,0,0,1)+data)
   print(json.dumps({'fields':struct.unpack_from('<8Q',raw),'data_hex':raw[64:].hex()},indent=2))
  elif cmd=='app':
   data=args.data.read_bytes() if args.data else b''
   raw=client.request(150,struct.pack('<Q8Q',args.instance,args.operation,args.handle,args.a,args.b,0,0,0,1)+data)
   print(json.dumps({'fields':struct.unpack_from('<8Q',raw),'data_hex':raw[64:].hex()},indent=2))
  elif cmd=='vault':
   v=args.vault_command
   if v=='retain':raw=client.request(203,struct.pack('<Q',args.handle))
   elif v=='recover':raw=client.request(207)
   else:
    op={'unlock':200,'lock':201,'status':202,'delete':205}[v];payload=struct.pack('<8Q',op,0,3,0,0,0,0,1)
    if v=='unlock':
     key=args.key.read_bytes()
     if len(key)!=32:raise ValueError('vault key must be exactly32 raw bytes; no hash-as-KDF passphrases')
     payload+=key
    raw=client.request(op,payload)
   print(json.dumps({'fields':struct.unpack_from('<8Q',raw),'data_hex':raw[64:].hex()},indent=2))
 finally:client.close()
 return 0
if __name__=='__main__':sys.exit(main())
