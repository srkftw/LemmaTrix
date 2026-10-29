"""Explicit operator startup for an identified headless guest role package.

The config selects opaque devices, endpoint, credential paths, exact signed code
and operator budgets. Catalogs, object contents and protocol state stay in Lean.
"""
import argparse,hashlib,json,os,signal,struct,subprocess,time
from pathlib import Path
import federation,forge,live,network,projects,releases,server_store
ROOT=Path(__file__).resolve().parents[1]
ROLES=('registry','seed','builder','verifier')

def approved_package(package,public,release_id,rights):
 package=package.resolve();public=public.resolve()
 info=releases.inspect(package.read_bytes());releases.public_modulus(public)
 if info['release_id']!=release_id or info['rights']!=rights:raise ValueError('operator approval must match exact release and rights')
 return dict(package=str(package),publisher_public=str(public),release_id=release_id,rights=rights)

def validate_package(config):
 raw=Path(config['package']).read_bytes();info=releases.inspect(raw)
 if info['release_id']!=config['release_id'] or info['rights']!=config['rights']:raise ValueError('configured signed code or approved rights changed')
 releases.public_modulus(Path(config['publisher_public']))
 return raw

def start_package(client,config,raw):
 client.request(10,raw[128:160]+releases.public_modulus(Path(config['publisher_public'])))
 inspected=client.stage(Path(config['package']))
 if inspected['release_id']!=config['release_id']:raise ValueError('guest inspected a different role package')
 # init records explicit operator approval of this exact signed release and
 # rights. This administrative startup is separate from personal GUI approval.
 client.request(23,bytes.fromhex(config['release_id'])+struct.pack('<Q',config['rights']))
 slot=struct.unpack_from('<Q',client.request(24),8)[0]
 return struct.unpack_from('<Q',client.request(25,struct.pack('<Q',slot)),8)[0]

def catalog(client,instance):
 entries=[];cursor=0
 while cursor<16:
  try:fields,descriptor=federation.call(client,instance,6,h=cursor)
  except ValueError as error:
   if str(error)=='native registry status6':break
   raise
  if len(descriptor)!=768 or not cursor<fields[3]<=16:raise ValueError('invalid bounded registry pagination')
  entries.append(dict(slot=fields[2],sequence=fields[1],descriptor=forge.admission_record(descriptor),signed_descriptor=descriptor.hex(),content_available=False,content_availability='not asserted by metadata-only catalog',local_execution_approved=False))
  cursor=fields[3]
 return dict(instance=instance,entries=entries,content_available=False,content_availability='catalog does not promise seed retention')

def initialize(args):
 approved=approved_package(args.package,args.public,args.release_id,args.rights);credential=args.credentials.resolve()
 _,material=network.load_credentials(credential)
 namespace=bytes.fromhex(args.namespace)
 if len(namespace)!=32 or not any(namespace):raise ValueError('namespace must be a nonzero32-byte identity')
 if not 0<args.bytes<=1048576:raise ValueError('namespace quota must be1..1048576')
 if not args.store.is_file():raise ValueError('server backing must be an explicitly selected existing image')
 config=dict(schema=1,role=args.role,**approved,credentials=str(credential),server_store=str(args.store.resolve()),namespace=namespace.hex(),bytes=args.bytes,endpoint=args.endpoint,listen=args.listen,recover_and_seed=args.recover_and_seed,policy='explicit-purpose2-operator-retention',server_store_encryption='none',signature='package checked by guest on each startup',operator_independence=False)
 if args.description:
  description=args.description.resolve();_,descriptor,_=network.load_description(description)
  if material[:96]!=descriptor[64:128]+hashlib.sha256(descriptor).digest():raise ValueError('credentials differ from explicitly selected signed service description')
  config.update(network_description=str(description),network_description_sha256=hashlib.sha256(description.read_bytes()).hexdigest())
 if args.recover_and_seed and args.role!='seed':raise ValueError('recover-and-seed requires seed role')
 secondary=(args.registry_package,args.registry_public,args.registry_release_id,args.registry_rights,args.federation_public,args.federation_policy)
 if args.role=='registry':
  if any(value is None for value in secondary):raise ValueError('registry role requires explicit registry package/public/release-id/rights and federation public/policy')
  if args.rights!=1151 or args.registry_rights!=2175:raise ValueError('registry role requires headless Forge rights1151 and isolated Registry rights2175')
  registry=approved_package(args.registry_package,args.registry_public,args.registry_release_id,args.registry_rights)
  modulus=releases.public_modulus(args.federation_public)
  registry.update(federation_public=str(args.federation_public.resolve()),federation_id=hashlib.sha256(modulus).hexdigest(),policy=args.federation_policy)
  config.update(registry=registry,recover_catalog=args.recover_catalog)
 elif any(value is not None for value in secondary) or args.recover_catalog:raise ValueError('registry package, federation policy and catalog recovery require registry role')
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
 if args.recover_catalog and config['role']!='registry':raise ValueError('catalog recovery requires registry role')
 raw=validate_package(config)
 registry=config.get('registry') if config['role']=='registry' else None
 if config['role']=='registry':
  if not registry or config['rights']!=1151 or registry['rights']!=2175 or registry.get('policy') not in ('portable','restricted'):raise ValueError('unsupported isolated registry role configuration')
  registry_raw=validate_package(registry)
  if hashlib.sha256(releases.public_modulus(Path(registry['federation_public']))).hexdigest()!=registry['federation_id']:raise ValueError('configured federation public identity changed')
 description=Path(config['network_description']) if config.get('network_description') else None
 if description and hashlib.sha256(description.read_bytes()).hexdigest()!=config['network_description_sha256']:raise ValueError('configured signed public service description changed')
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
  instance=start_package(client,config,raw)
  network.configure(client,Path(config['credentials']),description);server_store.call(client,230)
  registry_instance=start_package(client,registry,registry_raw) if registry else None
  role=('registry','seed','builder','verifier').index(config['role'])+1
  store_owner=registry_instance if registry else instance
  grant=server_store.call(client,231,store_owner,role,config['bytes'],bytes.fromhex(config['namespace']))[0][1]
  registry_info=None
  if registry:
   registry_info=federation.configure(client,registry_instance,Path(registry['federation_public']),registry['policy'],grant)
   store=federation.call(client,registry_instance,12)[0]
   committed,generation=store[1:3]
   registry_info['committed_catalog_bytes']=committed;registry_info['store_generation']=generation
   recover=config.get('recover_catalog') or args.recover_catalog
   if committed and not recover:raise ValueError('selected namespace already has committed catalog data; use node run --recover-catalog; no catalog was overwritten')
   if recover and not committed:raise ValueError('no committed catalog to recover in the empty selected namespace; no catalog was written')
   registry_info['catalog_recovery']=dict(state='empty selected namespace',records=0)
   if recover:
    count=federation.call(client,registry_instance,10)[0][1]
    registry_info['catalog_recovery']=dict(state='recovered',records=count)
  forge.configure(client,instance,Path(config['credentials']),config['role'],'portable',0 if registry else grant,config['recover_and_seed'])
  if registry:forge.federation_configure(client,instance,registry['federation_id'],1 if registry['policy']=='portable' else 2)
  if config['role'] in ('builder','verifier'):
   import remote_build
   client.request(182,struct.pack('<Q',instance))
   remote_build.configure(client,instance,Path(config['credentials']),config['role'])
  result=dict(role=config['role'],instance=instance,release_id=config['release_id'],server_store_grant=grant,server_store_owner=store_owner,retention=config['policy'],socket=str(args.socket),image=image_digest,image_path=str(image),headless=True)
  if registry:result.update(registry_instance=registry_instance,registry=registry_info,publisher_enrollment='separate explicit lt federation trust-publisher',admission_signer='separate explicit lt federation worker; no private signing key in node config')
  if config['role'] in ('builder','verifier'):result.update(additional_operator_authority='BuildJobs enqueue only; no signing authority',build_requester_instance=instance)
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
 q.add_argument('--registry-package',type=Path);q.add_argument('--registry-public',type=Path);q.add_argument('--registry-release-id');q.add_argument('--registry-rights',type=lambda x:int(x,0));q.add_argument('--federation-public',type=Path);q.add_argument('--federation-policy',choices=('portable','restricted'));q.add_argument('--recover-catalog',action='store_true')
 q.add_argument('--description',type=Path)
 q=sub.add_parser('run');q.add_argument('config',type=Path);q.add_argument('--socket',type=Path,required=True);q.add_argument('--backend',choices=('qemu','x86_64','aarch64'),default='qemu');q.add_argument('--image',type=Path);q.add_argument('--recover-catalog',action='store_true')
 for command in ('inspect','stop'):
  q=sub.add_parser(command);q.add_argument('--socket',type=Path,required=True)
  if command=='inspect':q.add_argument('--instance',type=int,required=True);q.add_argument('--registry-instance',type=int)
 args=p.parse_args(argv)
 if args.command=='init':print(json.dumps(initialize(args),indent=2));return 0
 if args.command=='run':return run(args)
 client=live.Client(args.socket)
 try:
  if args.command=='stop':
   try:client.request(70)
   except EOFError:pass
   return 0
  result=dict(network=network.status(client),forge=forge.inspect(client,args.instance),roots=projects.roots(client,include_identity=True))
  try:result['bound_build_requester']=struct.unpack('<Q',client.request(183))[0]
  except ValueError as error:
   if str(error)!='guest rejected command183, status1':raise
   result['build_requester_inspection']='unavailable on selected guest image'
  if args.registry_instance:result['registry']=catalog(client,args.registry_instance)
  print(json.dumps(result,indent=2));return 0
 finally:client.close()
if __name__=='__main__':raise SystemExit(main())
