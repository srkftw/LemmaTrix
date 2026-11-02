"""Public developer commands. Compilation has no publisher private-key input."""
import argparse,hashlib,json,os,re,sys
from pathlib import Path
import public_sdk as sdk

def read_project(directory):
 directory=Path(directory).resolve();files={}
 sdk.require(directory.is_dir(),'project directory does not exist')
 for path in sorted(directory.rglob('*')):
  if any(x.startswith('.') or x=='build' for x in path.relative_to(directory).parts):continue
  sdk.require(not path.is_symlink(),'project symlinks are not a source closure')
  if path.is_file():files[sdk.relative(path.relative_to(directory).as_posix())]=path.read_bytes()
 sdk.records(files)
 return files

def check(files):
 lock,manifest,_,dependencies,_,modules=sdk.resolve(files)
 sdk.require('lemma.project.json' in files,'missing lemma.project.json; run ./lt sdk init DIRECTORY')
 project=json.loads(files['lemma.project.json'])
 sdk.require(project.get('schema')==1 and project.get('facet') in ('NativeApplication','DevelopmentArtifact'),'unsupported project manifest/facet')
 sdk.require(isinstance(project.get('name'),str) and re.fullmatch('[a-z0-9][a-z0-9._-]{0,47}',project['name']),'project name must use 1..48 lowercase ASCII name characters')
 source_only=project['facet']=='DevelopmentArtifact'
 if source_only:
  sdk.require(project.get('exports') and all(n in lock.get('exports',project['exports']) for n in project['exports']),'source-only dependency must declare exports')
 else:sdk.require(type(project.get('rights')) is int and 0<=project['rights']<=8191,'unknown capability rights mask')
 sdk.require(isinstance(project.get('license'),str) and bool(project['license']),'declare a license or NOASSERTION; this does not establish legal authorization')
 sdk.require(isinstance(project.get('distribution_authority'),str) and bool(project['distribution_authority']),'explicit distribution authority declaration required')
 if not source_only:sdk.require(project.get('machine')=='LT-Dev-v2' and project.get('profile')==lock['profile'],'manifest and lock target profile differ')
 sdk.require(project.get('module')==lock['module'] and project.get('entry')==lock['entry'],'manifest and lock entry differ')
 if not source_only:sdk.require(project.get('persistence') in ('ephemeral','explicit-selected-objects'),'declare ephemeral or explicit-selected-objects persistence')
 if not source_only:sdk.require(project.get('network') in ('unavailable','reviewed-intents','approved-mode1-terminal'),'network must declare its actual supported authority')
 if project.get('network')=='approved-mode1-terminal':sdk.require(project['rights']&1024,'direct approved terminal use requires network.broker capability')
 diagnostics=[]
 for name,data in {**dependencies,**files}.items():
  if not name.endswith('.lean'):continue
  text=sdk.Source(data).read_text()
  import live_build
  clean=live_build.without_comments(text)
  for pattern,label in [(r'\b(?:IO\.Process|IO\.FS\.(?:write|remove|rename|create)|Socket|System\.FilePath\.isAbsolute)\b','forbidden host effect; use platform SDK objects/intents'),(r'\b(?:extern|implemented_by)\b','custom host/runtime extern is unsupported'),(r'\bGuest\s*\.','private Guest reference; use public Lemma API')]:
   match=re.search(pattern,clean)
   if match:diagnostics.append({'path':name,'line':clean[:match.start()].count('\n')+1,'message':label})
 sdk.require(not diagnostics,'app-check failed: '+json.dumps(diagnostics))
 return {'schema':1,'status':'ok','project':project['name'],'facet':project['facet'],'sdk':lock['sdk'],'dependency_lock_id':lock['content_id'],'dependencies':[p['release_id'] for p in lock['dependencies']],'source_files':sdk.records(files),'dependency_sources':sdk.records(dependencies) if dependencies else [],'modules':modules,'rights':project.get('rights',0),'license':project['license'],'distribution_authority':project['distribution_authority'],'checks':['canonical source/module paths','reserved namespaces','finite cycle-free pinned module closure','exact SDK/dependency cache bytes','manifest/recipe/profile agreement','license/distribution declarations','forbidden host/private calls'],'release_prerequisites':['actual frozen Build/Evidence','trusted exact native signing review','current publisher and federation policy','separate install/execution approval'],'assurance':'structural preflight; not compiler correctness, legal authorization or full verification'}

def write_lock(directory,module=None,entry=None,profile=None,dependencies=None):
 directory=Path(directory);project=json.loads((directory/'lemma.project.json').read_bytes())
 old=json.loads((directory/'lemma.lock.json').read_bytes()) if (directory/'lemma.lock.json').exists() else None
 deps=dependencies if dependencies is not None else old.get('dependencies',[]) if old else []
 lock=sdk.make_lock(module=module or project.get('module'),entry=entry or project.get('entry'),profile=profile or project.get('profile',0),dependencies=deps,facet=project['facet'])
 if old and old.get('dependencies')!=lock['dependencies']:
  # CLI requires the caller's explicit update command. Report capability effects
  # before replacing the reviewable lock; this never grants guest authority.
  print(json.dumps({'dependency_change':{'before':old.get('dependencies',[]),'after':lock['dependencies']},'guest_authority_changed':False}),file=sys.stderr)
 (directory/'lemma.lock.json').write_bytes(sdk.canonical(lock)+b'\n');return lock

TEMPLATE=b'''import Lemma.UI\nimport Lemma.Objects\nnamespace Main\n-- Private app memory and ordinary caller surface; no trusted approval surface.\npartial def loop (surface t : UInt64) : UInt64 :=\n  let e := Lemma.UI.event t\n  if e == 1 then Lemma.UI.exit 0 e\n  else loop surface (Lemma.UI.wait (Lemma.UI.now e+1) e)\ndef main (initial : UInt64) : UInt64 :=\n  let surface := Lemma.UI.createSurface initial\n  if surface == Lemma.UI.error then surface else\n  let t := Lemma.UI.fill 0 0 640 352 0x152632 surface\n  let t := Lemma.UI.hex 0x1e77a 5 40 40 0xe5eef7 0x152632 t\n  let t := Lemma.UI.upload surface 0 901120 t\n  loop surface (Lemma.UI.present surface t)\nend Main\n'''

def dependency_archive(document):
 """Prepare inert graph records from a real signed source dependency.
 Every record still enters the normal native ImportJobs admission path.
 """
 import projects,releases,struct
 info,files,_=sdk.verify_dependency(document)
 records=[];entries=[]
 for name,data in sorted(files.items()):
  ident=projects.canonical_node(10,data);records.append(dict(kind=10,id=ident,payload=data));entries.append((name,10,ident))
 source=projects.manifest(entries);source_id=projects.canonical_node(11,source)
 manifest=document['manifest']
 sdk.require(manifest.get('provenance',{}).get('source_root')==source_id,'dependency needs its original publisher-provided graph archive for source ancestry')
 records.append(dict(kind=11,id=source_id,payload=source))
 parts=[releases.pkg.canonical(manifest),releases.pkg.canonical(manifest['sources']),releases.pkg.canonical(manifest['evidence']),releases.pkg.canonical(dict(license=manifest['license'],distribution_authority='explicit local author declaration'))]
 envelope=__import__('base64').b64decode(document['release'],validate=True)
 detail=struct.pack('<8Q',0x31544e43524c544c,1,608,*map(len,parts),0)+envelope+b''.join(parts)
 payload=projects.manifest([('source',11,source_id)],detail);release_node=projects.canonical_node(13,payload)
 records.append(dict(kind=13,id=release_node,payload=payload))
 top=projects.manifest([*entries,('release.ltrel',13,release_node)])
 head=projects.canonical_node(11,top,parent=source_id);records.append(dict(kind=11,id=head,payload=top,parent=source_id))
 return info,release_node,head,records

def attach_dependency(client,root,document):
 import projects
 info,release_node,head,records=dependency_archive(document)
 selected=next((r for r in projects.roots(client)if r['cap']==root),None)
 sdk.require(selected is not None,'selected application root is not authorized')
 _,files=projects.snapshot(client,root,selected['head']);lock=sdk.validate_lock(json.loads(files['lemma.lock.json']))
 pin=next((p for p in lock['dependencies']if p['release_id']==info['release_id']),None)
 sdk.require(pin is not None and pin['publisher_key_id']==info['publisher_key_id']and pin['content_id']==sdk.sha(sdk.canonical(document)),'selected lock does not authorize this exact dependency carrier')
 alias='dep-'+info['release_id'][:24];existing=next((r for r in projects.roots(client)if r['name']==alias),None)
 if existing:
  sdk.require(existing['head']==head,'dependency graph name already refers to another immutable root');dependency=existing['cap']
 else:dependency=projects.import_records(client,[dict(name=alias,head=head)],records)[0]['cap']
 # Resolve only after native ImportJobs has validated the actual signed graph.
 handle=projects.resolve(client,dependency,release_node);fields,ids=client.objects(21,handle)
 sdk.require(fields[4]==13 and ids[:32].hex()==release_node,'native dependency release node differs from verified import')
 source_handle=projects.resolve(client,root,selected['head']);original=client.read_object(source_handle);entries=projects.decode_manifest(original);detail=original[32+len(entries)*128:]
 name='deps/'+info['release_id']+'.rel';prior=next((e for e in entries if e[0]==name),None)
 if prior:sdk.require(prior==(name,13,release_node),'dependency attachment name conflicts with another graph node')
 else:entries.append((name,13,release_node))
 new_handle,new_head=projects.node(client,projects.manifest(entries,detail),11,source_handle)
 encoded=selected['name'].encode('ascii');fields,_=client.objects(22,new_handle,root,len(encoded),data=bytes.fromhex(selected['head'])+encoded.ljust(64,b'\0'))
 return dict(schema=1,root=fields[1],head=new_head,previous_head=selected['head'],release_id=info['release_id'],release_node=release_node,dependency_root=dependency,source_attachment=name,native_import_validated=True,installed=False,execution_authority=False,session_only=True)

def main(argv=None):
 p=argparse.ArgumentParser(description='Versioned public Lemma SDK, offline exact dependencies and key-free isolated native builds')
 sub=p.add_subparsers(dest='cmd',required=True)
 sub.add_parser('identity')
 init=sub.add_parser('init');init.add_argument('directory',type=Path);init.add_argument('--name',default='native-tool');init.add_argument('--template',choices=('utility','objects','social'),default='utility')
 lock=sub.add_parser('lock');lock.add_argument('directory',type=Path)
 for name in ('check','build'):
  item=sub.add_parser(name);item.add_argument('directory',type=Path)
  if name=='build':item.add_argument('--output',type=Path,required=True)
 imp=sub.add_parser('import-dependency');imp.add_argument('carrier',type=Path);imp.add_argument('--release',required=True);imp.add_argument('--publisher',required=True);imp.add_argument('--project',type=Path)
 pack=sub.add_parser('pack-dependency');pack.add_argument('--release',type=Path,required=True);pack.add_argument('--manifest',type=Path,required=True);pack.add_argument('--public',type=Path,required=True);pack.add_argument('--source',type=Path,required=True);pack.add_argument('--output',type=Path,required=True)
 attach=sub.add_parser('attach-dependency');attach.add_argument('carrier',type=Path);attach.add_argument('--socket',type=Path,required=True);attach.add_argument('--root',type=int,required=True)
 exp=sub.add_parser('export-sdk');exp.add_argument('directory',type=Path)
 ins=sub.add_parser('import-sdk');ins.add_argument('directory',type=Path)
 args=p.parse_args(argv)
 if args.cmd=='attach-dependency':
  import live
  client=live.Client(args.socket,timeout=300)
  try:report=attach_dependency(client,args.root,json.loads(args.carrier.read_bytes()))
  finally:client.close()
  print(json.dumps(report,indent=2));return 0
 if args.cmd=='identity':print(json.dumps(sdk.cache_sdk(),indent=2));return 0
 if args.cmd=='init':
  sdk.require(not args.directory.exists(),'project directory already exists; refusing to overwrite')
  sdk.require(re.fullmatch('[a-z0-9][a-z0-9._-]{0,47}',args.name),'invalid project name')
  args.directory.mkdir(parents=True)
  project={'schema':1,'name':args.name,'facet':'NativeApplication','module':'Main','entry':'Main.main','machine':'LT-Dev-v2','profile':2,'rights':768 if args.template=='utility' else 831,'license':'NOASSERTION','distribution_authority':'local author declaration; review before distribution','persistence':'ephemeral' if args.template=='utility' else 'explicit-selected-objects','network':'reviewed-intents' if args.template=='social' else 'unavailable','assurance':['host-bootstrap Lean/LLVM; source-to-binary unverified'],'template':args.template}
  (args.directory/'lemma.project.json').write_bytes(sdk.canonical(project)+b'\n');(args.directory/'Main.lean').write_bytes(TEMPLATE)
  if args.template!='utility':
   # Reuse the same public object-backed client, with an actual staged immutable
   # selected object revision rather than a separate toy SDK implementation.
   s=(args.directory/'Main.lean').read_text().replace('  let surface := Lemma.UI.createSurface initial','  let r := Lemma.Objects.stage 0 1 0 initial\n  let t := if r == Lemma.Objects.error then r else Lemma.Objects.abortStage (Lemma.Objects.result r) r\n  let surface := Lemma.UI.createSurface t')
   (args.directory/'Main.lean').write_text(s)
  if args.template=='social':
   s=(args.directory/'Main.lean').read_text().replace('import Lemma.Objects','import Lemma.Objects\nimport Lemma.Social\nimport Lemma.Messenger')
   (args.directory/'Main.lean').write_text(s)
  print(json.dumps(write_lock(args.directory),indent=2));return 0
 if args.cmd=='lock':print(json.dumps(write_lock(args.directory),indent=2));return 0
 if args.cmd in ('check','build'):
  files=read_project(args.directory);report=check(files)
  if args.cmd=='check':print(json.dumps(report,indent=2));return 0
  import build_jobs
  lock=sdk.validate_lock(json.loads(files['lemma.lock.json']));snapshot,_=build_jobs.source_commitment(files)
  result=build_jobs.build_source_snapshot(files,module=lock['module'],entry=lock['entry'],profile=lock['profile'],jobid='sdk-'+snapshot[:24],rootid=snapshot,outputdir=args.output)
  print(json.dumps(result,indent=2));return 0 if result['status']=='ok' else 1
 if args.cmd=='pack-dependency':
  manifest=json.loads(args.manifest.read_bytes());sources=read_project(args.source)
  selected={r['path']:sources[r['path']] for r in manifest['sources']}
  document=sdk.dependency_document(args.release.read_bytes(),manifest,args.public.read_bytes(),selected);info,_,_=sdk.verify_dependency(document)
  sdk.require(not args.output.exists(),'dependency carrier output already exists');args.output.write_bytes(sdk.canonical(document));print(json.dumps(info,indent=2));return 0
 if args.cmd=='import-dependency':
  pin=sdk.cache_dependency(json.loads(args.carrier.read_bytes()),publisher=args.publisher,release_id=args.release)
  if args.project:
   destination=args.project/'deps'/(args.release+'.json');destination.parent.mkdir(parents=True,exist_ok=True);destination.write_bytes(sdk.canonical(json.loads(args.carrier.read_bytes())))
   previous=json.loads((args.project/'lemma.lock.json').read_bytes());deps=[x for x in previous['dependencies'] if not set(x['exports'])&set(pin['exports'])]+[pin]
   write_lock(args.project,dependencies=sorted(deps,key=lambda x:x['release_id']))
  print(json.dumps(pin,indent=2));return 0
 if args.cmd=='export-sdk':
  manifest=sdk.cache_sdk();source=sdk.CACHE/manifest['content_id'];sdk.require(not args.directory.exists(),'SDK export destination already exists');import shutil;shutil.copytree(source,args.directory);print(manifest['content_id']);return 0
 if args.cmd=='import-sdk':
  manifest=sdk.validate_manifest(json.loads((args.directory/'manifest.json').read_bytes()));sdk._read_sdk(args.directory,manifest);dest=sdk.CACHE/manifest['content_id']
  if dest.exists():sdk._read_sdk(dest,manifest)
  else:import shutil;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copytree(args.directory,dest)
  print(manifest['content_id']);return 0
if __name__=='__main__':
 try:sys.exit(main())
 except (ValueError,KeyError,OSError,RuntimeError) as error:print('lt sdk:',error,file=sys.stderr);sys.exit(1)
