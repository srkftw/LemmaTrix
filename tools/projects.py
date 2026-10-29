"""Explicit guest graph import/export and host bootstrap job boundary."""
import argparse,hashlib,json,struct,sys
from pathlib import Path,PurePosixPath
import live
MAGIC=0x31464e4d544c

def safe_name(name):
 p=PurePosixPath(name)
 if not name or len(name.encode())>80 or p.is_absolute() or any(x in ('','.','..') for x in name.split('/')) or any(ord(c)<33 or ord(c)>126 or c in '\\:' for c in name):raise ValueError('canonical relative ASCII project name required')
 return name

def node(client,data,kind,parent=0):
 h=client.import_object(data,kind,parent)
 fields,ids=client.objects(21,h)
 if len(ids)!=64:raise ValueError('node identity response missing')
 return h,ids[:32].hex()

def manifest(entries,detail=b''):
 body=struct.pack('<4Q',MAGIC,1,len(entries),len(detail))
 for name,kind,identity in sorted(entries):
  encoded=safe_name(name).encode();body+=struct.pack('<2Q',kind,len(encoded))+bytes.fromhex(identity)+encoded.ljust(80,b'\0')
 return body+detail

def decode_manifest(data):
 if len(data)<32:raise ValueError('short manifest')
 magic,version,count,detail=struct.unpack_from('<4Q',data)
 if (magic,version)!=(MAGIC,1) or count>32 or len(data)!=32+count*128+detail:raise ValueError('invalid manifest')
 entries=[]
 for i in range(count):
  entry=data[32+i*128:160+i*128];kind,n=struct.unpack_from('<2Q',entry)
  if not 0<n<=80:raise ValueError('name bound')
  name=safe_name(entry[48:48+n].decode('ascii'))
  if entry[48+n:]!=bytes(80-n):raise ValueError('noncanonical padding')
  entries.append((name,kind,entry[16:48].hex()))
 if entries!=sorted(entries) or len({x[0] for x in entries})!=len(entries):raise ValueError('manifest ordering')
 return entries

def roots(client):
 answer=[];cursor=0
 while cursor<64:
  f,data=client.objects(23,a=cursor)
  if not f[1]:break
  answer.append(dict(cap=f[1],name=data[32:32+f[2]].decode(),head=data[:32].hex()))
  if f[3]<=cursor:raise ValueError('root cursor did not advance')
  cursor=f[3]
 return answer

def resolve(client,root,identity):return client.objects(25,root,data=bytes.fromhex(identity))[0][1]
def snapshot(client,root,head=None):
 h=client.objects(24,root)[0][1] if head is None else resolve(client,root,head)
 f,ids=client.objects(21,h);identity=ids[:32].hex()
 files={}
 for name,kind,member in decode_manifest(client.read_object(h)):
  if kind!=10:continue
  handle=resolve(client,root,member)
  files[name]=client.read_object(handle,True)
 return identity,files

def build_bridge(client,outputdir,module='Main',entry='Main.main'):
 import build_jobs
 raw=client.request(160,struct.pack('<8Q',2,0,0,0,0,0,0,1))
 if len(raw)<160 or struct.unpack_from('<Q',raw)[0]:raise ValueError('no queued build job')
 f=struct.unpack_from('<8Q',raw);jobid,service,root,profile=f[1],f[3],f[4],f[5]
 head=raw[64:96].hex();expected_compiler=raw[128:160].hex()
 actual,files=snapshot(client,root,head)
 if actual!=head:raise ValueError('frozen source root mismatch')
 
 if module!='Main' or entry!='Main.main':raise ValueError('graphical jobs freeze the fixed Main.main recipe')
 result=build_jobs.build_source_snapshot(files,module=module,entry=entry,profile=profile,jobid=jobid,rootid=head,outputdir=outputdir)
 if result.get('toolchain_id')!=expected_compiler:raise ValueError('guest frozen compiler/toolchain commitment differs; build result not returned')
 located=result.get('diagnostics',[])
 diagnostic=(f"{located[0]['path']}:{located[0]['line']}:{located[0]['column']}: {located[0]['message']}" if located else result.get('diagnostic_text',''))
 diag=diagnostic.encode('utf-8')[:512]
 # Preserve only complete UTF-8 in the guest display diagnostic bound.
 diag=diag.decode('utf-8','ignore').encode('utf-8')
 artifact=result.get('artifact',{}).get('sha256','00'*32)
 payload=struct.pack('<8Q',3,jobid,service,2 if result['status']=='ok' else 3,0,profile,len(diag),1)+bytes.fromhex(head)+bytes.fromhex(artifact)+bytes.fromhex(result['request_digest'])+bytes.fromhex(result['toolchain_id'])+diag
 accepted=client.request(160,payload)
 if len(accepted)<128 or struct.unpack_from('<Q',accepted)[0]:raise ValueError('guest rejected stale/wrong source build response')
 outputdir=Path(outputdir);outputdir.mkdir(parents=True,exist_ok=True)
 result['guest_session']={'job_service':service,'job_id':jobid,'source_root_capability':root}
 path=outputdir/'job.result.json';path.write_text(json.dumps(result,indent=2)+'\n')
 return result

def publish_result(result_path,key,name,version,output,parent=None,*,client=None,rights=768,attach_root=None):
 import releases,packaging as pkg
 if client is None:raise ValueError('publishing requires the current guest connection for referenced Build/Evidence content')
 r=json.loads(Path(result_path).read_text())
 if r['status']!='ok':raise ValueError('cannot publish failed build')
 artifact=Path(r['artifact']['path']);binary=artifact.read_bytes()
 if hashlib.sha256(binary).hexdigest()!=r['artifact']['sha256']:raise ValueError('build artifact changed after result')
 session=r.get('guest_session',{})
 if not {'job_service','job_id','source_root_capability'}<=session.keys():raise ValueError('current guest job authority is absent; imported build assertions cannot manufacture it')
 job_request=struct.pack('<8Q',6,session['job_id'],0,0,0,0,0,1)
 raw=client.request(160,job_request)
 if len(raw)<128:raise ValueError('guest Build/Evidence response is missing')
 jf=struct.unpack_from('<8Q',raw)
 if jf[0] or jf[3]!=session['job_service'] or raw[64:96].hex()!=r['source_root'] or raw[96:128].hex()!=r['artifact']['sha256']:raise ValueError('guest job/source/output commitments differ from selected build')
 build_handle,evidence_handle=jf[6],jf[7]
 if not build_handle or not evidence_handle:raise ValueError('guest Build/Evidence records unavailable')
 _,build_ids=client.objects(21,build_handle);_,evidence_ids=client.objects(21,evidence_handle)
 source_handle=client.objects(24,session['source_root_capability'])[0][1]
 _,source_ids=client.objects(21,source_handle)
 if source_ids[:32].hex()!=r['source_root']:raise ValueError('frozen source changed')
 source_payload=client.read_object(source_handle)
 source_entries=decode_manifest(source_payload)
 # Every source member is explicitly resolved under the frozen job scope before
 # it can enter a published snapshot. Session handles stay in local job state.
 for _,kind,identity in source_entries:
  if kind==10:resolve(client,session['source_root_capability'],identity)
 records=[dict(path=m['path'],sha256=m['sha256'],size=m['bytes']) for m in r['source_files']]
 evidence=[dict(kind='host-sandbox-build',job_id=r['job_id'],source_root=r['source_root'],request_digest=r['request_digest'],toolchain_id=r['toolchain_id'],binary_sha256=r['artifact']['sha256'],source_to_binary='unverified')]
 envelope,signed_manifest=releases.make(artifact,name,version,rights,key,parent=parent,license='NOASSERTION',evidence=evidence,profile=r['runtime_profile'],source_records_override=records)
 # Signing and writing the explicit package are distinct from graph admission,
 # publisher trust, install approval and local execution.
 pkg.write_new(Path(output),envelope);pkg.write_new(Path(str(output)+'.manifest.json'),pkg.canonical(signed_manifest))
 chunks=[]
 for i,offset in enumerate(range(0,len(binary),65536)):
  _,identity=node(client,binary[offset:offset+65536],10)
  chunks.append((f'code/chunk-{i:04d}.bin',10,identity))
 binary_manifest,binary_id=node(client,manifest(chunks,pkg.canonical({'schema':1,'bytes':len(binary),'sha256':r['artifact']['sha256']})),11)
 canonical_manifest=pkg.canonical(signed_manifest)
 canonical_sources=pkg.canonical(signed_manifest['sources'])
 canonical_evidence=pkg.canonical(signed_manifest['evidence'])
 canonical_license=pkg.canonical({'license':signed_manifest['license'],'distribution_authority':'explicit local author declaration'})
 detail=struct.pack('<8Q',0x31544e43524c544c,1,768,len(canonical_manifest),len(canonical_sources),len(canonical_evidence),len(canonical_license),0)+envelope[:768]+canonical_manifest+canonical_sources+canonical_evidence+canonical_license
 release_entries=[('build',12,build_ids[:32].hex()),('code',11,binary_id),('evidence',14,evidence_ids[:32].hex()),('source',11,r['source_root'])]
 release_handle,release_node_id=node(client,manifest(release_entries,detail),13)
 published_entries=[entry for entry in source_entries if entry[1]==10]
 if any(path=='release.ltrel' for path,_,_ in published_entries):raise ValueError('source name release.ltrel conflicts with explicit release attachment')
 published_entries.append(('release.ltrel',13,release_node_id))
 snapshot_detail=pkg.canonical({'schema':1,'kind':'published-project-snapshot','source_root':r['source_root'],'release_node':release_node_id,'signed_release':envelope[160:192].hex()})
 # The caller can request an exact CAS attachment. A build of A never overwrites
 # intervening edits B: a separately named published snapshot is created instead.
 attached=False;root=0;expected=bytes(32);ancestry=0
 if attach_root is not None:
  _,meta=client.objects(29,attach_root)
  if meta[:32].hex()==r['source_root']:
   root=attach_root;expected=meta[:32];ancestry=client.objects(24,root)[0][1];attached=True
 snapshot,snapshot_id=node(client,manifest(published_entries,snapshot_detail),11,ancestry)
 snapshot_name=(next(x['name'] for x in roots(client) if x['cap']==root) if attached else f'{name}-release-{version}')
 encoded=safe_name(snapshot_name).encode('ascii')
 if len(encoded)>63:raise ValueError('published snapshot name exceeds63bytes')
 try:rf,_=client.objects(22,snapshot,root,len(encoded),data=expected+encoded.ljust(64,b'\0'))
 except ValueError:
  if not attached:raise
  # Preserve a concurrent edit rather than retrying a changed expected head.
  snapshot,snapshot_id=node(client,manifest(published_entries,snapshot_detail),11)
  encoded=f'{name}-release-{version}'.encode('ascii')
  if len(encoded)>63:raise ValueError('published snapshot name exceeds63bytes')
  rf,_=client.objects(22,snapshot,0,len(encoded),data=bytes(32)+encoded.ljust(64,b'\0'));attached=False
 published_root=rf[1]
 processes=client.request(2)
 shell=struct.unpack_from('<Q',processes,128)[0] if len(processes)>=160 else 0
 shell_root=client.objects(27,published_root,shell,127)[0][1] if shell else 0
 result=releases.inspect(envelope,manifest=signed_manifest)
 result['content']={'release_node':release_node_id,'release_handle':release_handle,'binary_manifest':binary_id,'build_node':build_ids[:32].hex(),'evidence_node':evidence_ids[:32].hex(),'source_root':r['source_root'],'snapshot_root':published_root,'snapshot_head':snapshot_id,'snapshot_name':encoded.decode('ascii'),'shell_root_capability':shell_root,'attached_to_selected_root':attached,'guest_present_commitments_checked':True,'publisher_signature':'requires Launcher verification under current local trust','installed':False}
 return result

def main(argv=None):
 p=argparse.ArgumentParser(description='Canonical guest Project roots; explicit byte import/export')
 p.add_argument('--socket',type=Path,required=True);s=p.add_subparsers(dest='cmd',required=True)
 s.add_parser('list')
 a=s.add_parser('build');a.add_argument('--output',type=Path,required=True);a.add_argument('--module',default='Main');a.add_argument('--entry',default='Main.main')
 a=s.add_parser('publish');a.add_argument('result',type=Path);a.add_argument('--sign-key',type=Path,required=True);a.add_argument('--name',required=True);a.add_argument('--version',required=True);a.add_argument('--parent');a.add_argument('--rights',type=lambda x:int(x,0),default=768);a.add_argument('--attach-root',type=int);a.add_argument('--output',type=Path,required=True)
 a=s.add_parser('import');a.add_argument('directory',type=Path);a.add_argument('--name',required=True);a.add_argument('--root',type=int,default=0);a.add_argument('--expected')
 a=s.add_parser('export');a.add_argument('--root',type=int,required=True);a.add_argument('--head');a.add_argument('--output',type=Path,required=True)
 a=s.add_parser('share');a.add_argument('--root',type=int,required=True);a.add_argument('--to',type=int,required=True);a.add_argument('--rights',type=int,default=127)
 args=p.parse_args(argv);client=live.Client(args.socket)
 try:
  if args.cmd=='build':print(json.dumps(build_bridge(client,args.output,args.module,args.entry),indent=2))
  elif args.cmd=='publish':print(json.dumps(publish_result(args.result,args.sign_key,args.name,args.version,args.output,args.parent,client=client,rights=args.rights,attach_root=args.attach_root),indent=2))
  elif args.cmd=='list':print(json.dumps(roots(client),indent=2))
  elif args.cmd=='share':print(client.objects(27,args.root,args.to,args.rights)[0][1])
  elif args.cmd=='import':
   directory=args.directory.resolve();entries=[];total=0
   paths=sorted(x for x in directory.rglob('*') if x.is_file())
   if not 1<=len(paths)<=24:raise ValueError('project requires1..24members')
   for path in paths:
    if path.is_symlink() or not path.resolve().is_relative_to(directory):raise ValueError('symlink source denied')
    relative=safe_name(path.relative_to(directory).as_posix());data=path.read_bytes();total+=len(data)
    if total>1048576:raise ValueError('project import exceeds1MiB')
    h,identity=node(client,data,10);entries.append((relative,10,identity))
   parent=client.objects(24,args.root)[0][1] if args.root else 0
   h,identity=node(client,manifest(entries),11,parent)
   name=safe_name(args.name).encode()
   if len(name)>63:raise ValueError('root name exceeds63bytes')
   expected=bytes.fromhex(args.expected) if args.expected else bytes(32)
   f,data=client.objects(22,h,args.root,len(name),data=expected+name.ljust(64,b'\0'))
   process=client.request(2);shell=struct.unpack_from('<Q',process,4*32)[0]
   client.objects(27,f[1],shell,127)
   print(json.dumps(dict(root=f[1],head=data[:32].hex(),name=args.name,members=len(entries),bytes=total),indent=2))
  elif args.cmd=='export':
   identity,files=snapshot(client,args.root,args.head)
   args.output.mkdir(parents=True,exist_ok=False)
   for name,data in files.items():
    path=args.output/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
   (args.output/'project.snapshot.json').write_text(json.dumps(dict(schema=1,head=identity,members=[dict(path=n,sha256=hashlib.sha256(b).hexdigest(),size=len(b)) for n,b in sorted(files.items())]),indent=2)+'\n')
   print(identity)
 finally:client.close()
 return 0
if __name__=='__main__':sys.exit(main())
