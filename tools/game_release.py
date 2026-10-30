"""Explicit isolated Crate Workshop build and canonical signed game publication.

The host bootstrap compiles a selected original snapshot in the existing key-free
sandbox. Guest Objects validates every real source/build/evidence/Release node;
Registry independently decides native+consumer eligibility. No installation,
retention, provider grant or local execution is approved by this command.
"""
import argparse,hashlib,json,struct,time
from pathlib import Path
import build_jobs,consumers,live,projects,releases
ROOT=Path(__file__).resolve().parents[1]

def source_files(generation):
 code=(ROOT/'Guest/CrateGame.lean').read_text().replace('import Guest.CrateModel','import CrateModel')
 return {'CrateGame.lean':code.encode(),'CrateModel.lean':(ROOT/'Guest/CrateModel.lean').read_bytes(),
  'Main.lean':('import CrateGame\nnamespace Main\ndef main (initial : UInt64) : UInt64 := Guest.CrateGame.'+('main' if generation==1 else 'secondMain')+' initial\nend Main\n').encode(),
  'assets/original.ltlevels':(ROOT/'resources/crate-workshop/original.ltlevels').read_bytes(),
  'assets/near-goal.ltlevels':(ROOT/'resources/crate-workshop/near-goal.ltlevels').read_bytes()}

def publish(client,*,generation,key,output,previous=None,version=None):
 if generation not in (1,2):raise ValueError('supported original generation is1 or2')
 output=Path(output);output.mkdir(parents=True,exist_ok=True)
 files=source_files(generation);source_entries=[]
 for name,data in sorted(files.items()):
  _,node_id=projects.node(client,data,10);source_entries.append((name,10,node_id))
 # Native source origin remains stable across the update by retaining its exact
 # preceding source Manifest. The executable has the same legacy publication ID.
 previous_source=previous['source_root'] if previous else None
 predecessor=projects.resolve(client,previous['root'],previous_source) if previous_source else 0
 source_handle,source_id=projects.node(client,projects.manifest(source_entries),11,predecessor)
 job_id=int(time.time_ns()%0xffffffff)+1
 snapshot=output/'snapshot'
 for relative,content in files.items():
  path=snapshot/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(content)
 result_path=output/'build-result.json'
 cached=json.loads(result_path.read_text()) if result_path.exists() else None
 expected_snapshot,_=build_jobs.source_commitment(files)
 reused=bool(cached and cached.get('status')=='ok' and cached.get('snapshot_digest')==expected_snapshot and cached.get('source_root')==source_id and cached.get('toolchain_id')==build_jobs.compiler_identity() and Path(cached['artifact']['path']).is_file() and hashlib.sha256(Path(cached['artifact']['path']).read_bytes()).hexdigest()==cached['artifact']['sha256'])
 if reused:
  result=cached;job_id=int(result['job_id'])
 else:result=build_jobs.build_source_snapshot(files,module='Main',entry='Main.main',profile=2,jobid=job_id,rootid=source_id,outputdir=output/'sandbox')
 (output/'build-result.json').write_text(json.dumps(result,indent=2)+'\n')
 if result.get('status')!='ok':raise RuntimeError('actual isolated game build failed: '+result.get('diagnostic_text',''))
 binary=Path(result['artifact']['path']).read_bytes();binary_sha=hashlib.sha256(binary).digest()
 detail=struct.pack('<6Q',0x31444c4942544c,1,2,job_id,0x3153424a544c,2)+bytes.fromhex(source_id)+binary_sha+bytes.fromhex(result['request_digest'])+bytes.fromhex(result['toolchain_id'])+b'Main.main'.ljust(16,b'\0')+struct.pack('<Q',0)
 if len(detail)!=200:raise ValueError('invalid real build detail')
 _,evidence_id=projects.node(client,projects.manifest([('source',11,source_id)],detail),14)
 _,build_id=projects.node(client,projects.manifest([('evidence',14,evidence_id),('source',11,source_id)],detail),12)
 evidence=[dict(kind='host-sandbox-build',job_id=str(job_id),source_root=source_id,request_digest=result['request_digest'],toolchain_id=result['toolchain_id'],binary_sha256=binary_sha.hex(),source_to_binary='unverified')]
 records=[dict(path=item['path'],sha256=item['sha256'],size=item['bytes']) for item in result['source_files']]
 package,manifest=releases.make(result['artifact']['path'],'crate-workshop',version or ('1.0.0' if generation==1 else '1.1.0'),795,key,parent=previous['release_id'] if previous else None,license='NOASSERTION',evidence=evidence,profile=2,source_records_override=records,logical_project_id=previous['source_logical_project_id'] if previous else source_id)
 package_path=output/'crate-workshop.ltrel';package_path.write_bytes(package);Path(str(package_path)+'.manifest.json').write_bytes(releases.pkg.canonical(manifest))
 chunks=[]
 for i,offset in enumerate(range(0,len(binary),65536)):
  _,node_id=projects.node(client,binary[offset:offset+65536],10);chunks.append((f'code/chunk-{i:04d}.bin',10,node_id))
 _,code_id=projects.node(client,projects.manifest(chunks,releases.pkg.canonical(dict(schema=1,bytes=len(binary),sha256=binary_sha.hex()))),11)
 canonical_manifest=releases.pkg.canonical(manifest);canonical_sources=releases.pkg.canonical(manifest['sources']);canonical_evidence=releases.pkg.canonical(evidence);canonical_license=releases.pkg.canonical(dict(license=manifest['license'],distribution_authority='explicit local author declaration'))
 release_detail=struct.pack('<8Q',0x31544e43524c544c,1,768,len(canonical_manifest),len(canonical_sources),len(canonical_evidence),len(canonical_license),0)+package[:768]+canonical_manifest+canonical_sources+canonical_evidence+canonical_license
 _,release_id=projects.node(client,projects.manifest([('build',12,build_id),('code',11,code_id),('evidence',14,evidence_id),('source',11,source_id)],release_detail),13)
 selected=[*source_entries,('release.ltrel',13,release_id)]
 head_handle,head=projects.node(client,projects.manifest(selected),11,source_handle)
 name=f'crate-workshop-{generation}';fields,_=client.objects(22,head_handle,0,len(name),data=bytes(32)+name.encode().ljust(64,b'\0'));root=fields[1]
 edition_version=(previous.get('edition_version',previous['generation'])+1) if previous else generation
 raw=consumers.create(key=key,project='crate-workshop',facet='game',collection=hashlib.sha256(b'Crate Workshop original collection').digest(),item=hashlib.sha256(b'Crate Workshop game').digest(),edition=hashlib.sha256(b'Crate Workshop native edition'+package[160:192]).digest(),title='Crate Workshop / original puzzles / generation '+str(generation),resource=files['assets/original.ltlevels'],executable=package,sequence=1,edition_version=edition_version,supersedes=previous['edition'] if previous else None,license_id=1)
 (output/'consumer.release').write_bytes(raw)
 attached=consumers.attach(client,raw,files['assets/original.ltlevels'],name=name,root=root)
 info=releases.inspect(package,releases.public_modulus(Path(str(key).replace('.pem','.pub'))),manifest) if Path(str(key).replace('.pem','.pub')).exists() else releases.inspect(package,manifest=manifest)
 result=dict(generation=generation,edition_version=edition_version,build_reused=reused,root=root,head=attached['head'],source_root=source_id,source_logical_project_id=previous['source_logical_project_id'] if previous else source_id,logical_project_id=projects.project_identity(client,root),publication_id=info['project_id'],release_id=info['release_id'],edition=consumers.inspect(raw)['edition'],package=str(package_path),binary_sha256=binary_sha.hex(),consumer_sha256=hashlib.sha256(raw).hexdigest(),source_files=records,build_result=str(output/'build-result.json'),installed=False,retained=False)
 (output/'publication.json').write_text(json.dumps(result,indent=2)+'\n');return result

def main(argv=None):
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--socket',required=True,type=Path);p.add_argument('--key',required=True,type=Path);p.add_argument('--generation',required=True,type=int,choices=(1,2));p.add_argument('--previous',type=Path);p.add_argument('--version');p.add_argument('--output',required=True,type=Path);a=p.parse_args(argv)
 previous=json.loads(a.previous.read_text()) if a.previous else None
 if a.generation==2 and previous is None:raise ValueError('generation2 requires exact prior publication state from this live guest')
 c=live.Client(a.socket)
 try:result=publish(c,generation=a.generation,key=a.key,output=a.output,previous=previous,version=a.version)
 finally:c.close()
 print(json.dumps(result,indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
