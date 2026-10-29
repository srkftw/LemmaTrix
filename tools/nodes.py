"""Explicit operator startup for an identified headless guest role package.

The config selects opaque devices, endpoint, credential paths, exact signed code
and operator budgets. Catalogs, object contents and protocol state stay in Lean.
"""
import argparse,hashlib,json,os,signal,struct,subprocess,time
from pathlib import Path
import forge,live,network,projects,releases,server_store
ROOT=Path(__file__).resolve().parents[1]
ROLES=('seed','builder','verifier')

def initialize(args):
 package=args.package.resolve();public=args.public.resolve();credential=args.credentials.resolve()
 info=releases.inspect(package.read_bytes())
 if info['release_id']!=args.release_id or info['rights']!=args.rights:raise ValueError('operator approval must match exact release and rights')
 network.load_credentials(credential)
 namespace=bytes.fromhex(args.namespace)
 if len(namespace)!=32 or not any(namespace):raise ValueError('namespace must be a nonzero32-byte identity')
 if not 0<args.bytes<=1048576:raise ValueError('namespace quota must be1..1048576')
 config=dict(schema=1,role=args.role,package=str(package),publisher_public=str(public),credentials=str(credential),release_id=args.release_id,rights=args.rights,server_store=str(args.store.resolve()),namespace=args.namespace,bytes=args.bytes,endpoint=args.endpoint,listen=args.listen,recover_and_seed=args.recover_and_seed,policy='explicit-purpose2-operator-retention',server_store_encryption='none',signature='package checked by guest on each startup',operator_independence=False)
 if args.recover_and_seed and args.role!='seed':raise ValueError('recover-and-seed requires seed role')
 fd=os.open(args.config,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w') as output:json.dump(config,output,indent=2);output.write('\n');output.flush();os.fsync(output.fileno())
 return config

def connect(socket,process):
 until=time.monotonic()+60
 while time.monotonic()<until:
  if process.poll() is not None:raise RuntimeError('guest exited before operator setup')
  try:return live.Client(socket,timeout=180)
  except (OSError,EOFError):time.sleep(.1)
 raise TimeoutError('guest operator portal did not become available')

def run(args):
 if args.socket.exists():raise ValueError('node socket path already exists; refusing to attach to or stop another guest')
 config=json.loads(args.config.read_text())
 if config.get('schema')!=1 or config.get('role') not in ROLES:raise ValueError('unsupported node config')
 package=Path(config['package']);raw=package.read_bytes();info=releases.inspect(raw)
 if info['release_id']!=config['release_id'] or info['rights']!=config['rights']:raise ValueError('configured signed code or approved rights changed')
 # Resolve the selected common image once. An operator may pin an immutable
 # image with --image or LT_GUEST_IMAGE while other work rebuilds build/live.
 image=Path(args.image or os.environ.get('LT_GUEST_IMAGE') or ROOT/'build/live/guest.bin').resolve()
 image_digest=hashlib.sha256(image.read_bytes()).hexdigest()
 # The common image is untouched. Role code is a separately approved package.
 command=[str(ROOT/'lt'),'run','--backend',args.backend,'--socket',str(args.socket),'--image',str(image),'--server-store',config['server_store'],'--network-listen' if config['listen'] else '--network',config['endpoint']]
 process=subprocess.Popen(command,cwd=ROOT,start_new_session=True)
 client=None
 try:
  client=connect(args.socket,process)
  client.request(10,raw[128:160]+releases.public_modulus(Path(config['publisher_public'])))
  inspected=client.stage(package)
  if inspected['release_id']!=config['release_id']:raise ValueError('guest inspected a different role package')
  # init records an explicit operator approval of this exact signed release and
  # rights. This administrative startup is separate from personal GUI approval.
  client.request(23,bytes.fromhex(config['release_id'])+struct.pack('<Q',config['rights']))
  slot=struct.unpack_from('<Q',client.request(24),8)[0]
  instance=struct.unpack_from('<Q',client.request(25,struct.pack('<Q',slot)),8)[0]
  network.configure(client,Path(config['credentials']));server_store.call(client,230)
  role=('registry','seed','builder','verifier').index(config['role'])+1
  grant=server_store.call(client,231,instance,role,config['bytes'],bytes.fromhex(config['namespace']))[0][1]
  forge.configure(client,instance,Path(config['credentials']),config['role'],'portable',grant,config['recover_and_seed'])
  if config['role'] in ('builder','verifier'):
   import remote_build
   remote_build.configure(client,instance,Path(config['credentials']),config['role'])
  result=dict(role=config['role'],instance=instance,release_id=config['release_id'],server_store_grant=grant,retention=config['policy'],socket=str(args.socket),image=image_digest,image_path=str(image),headless=True)
  print(json.dumps(result,indent=2),flush=True);client.close();client=None
  return process.wait()
 except KeyboardInterrupt:
  return 130
 finally:
  if client:client.close()
  if process.poll() is None:
   try:
    control=live.Client(args.socket,timeout=5)
    try:control.request(70)
    finally:control.close()
   except (OSError,EOFError,ValueError,TimeoutError):pass
   try:process.wait(timeout=10)
   except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait()

def main(argv=None):
 p=argparse.ArgumentParser(description='Explicit common-image headless node startup; guest owns application state')
 sub=p.add_subparsers(dest='command',required=True)
 q=sub.add_parser('init');q.add_argument('config',type=Path);q.add_argument('--role',choices=ROLES,required=True);q.add_argument('--package',type=Path,required=True);q.add_argument('--public',type=Path,required=True);q.add_argument('--credentials',type=Path,required=True);q.add_argument('--release-id',required=True);q.add_argument('--rights',type=lambda x:int(x,0),required=True);q.add_argument('--store',type=Path,required=True);q.add_argument('--namespace',required=True);q.add_argument('--bytes',type=int,default=1048576);q.add_argument('--endpoint',required=True);q.add_argument('--listen',action='store_true');q.add_argument('--recover-and-seed',action='store_true')
 q=sub.add_parser('run');q.add_argument('config',type=Path);q.add_argument('--socket',type=Path,required=True);q.add_argument('--backend',choices=('qemu','x86_64','aarch64'),default='qemu');q.add_argument('--image',type=Path)
 for command in ('inspect','stop'):
  q=sub.add_parser(command);q.add_argument('--socket',type=Path,required=True)
  if command=='inspect':q.add_argument('--instance',type=int,required=True)
 args=p.parse_args(argv)
 if args.command=='init':print(json.dumps(initialize(args),indent=2));return 0
 if args.command=='run':return run(args)
 client=live.Client(args.socket)
 try:
  if args.command=='stop':
   try:client.request(70)
   except EOFError:pass
   return 0
  print(json.dumps(dict(network=network.status(client),forge=forge.inspect(client,args.instance),roots=projects.roots(client,include_identity=True)),indent=2));return 0
 finally:client.close()
if __name__=='__main__':raise SystemExit(main())
