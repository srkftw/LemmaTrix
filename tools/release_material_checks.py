"""Focused guest rejection of freshly signed semantic material substitutions.

Reuses the actual existing source/build/code graph and native binary. The two
negative headers are signed only under the explicitly supplied campaign publisher
key; this performs no host compilation and makes no source-to-binary proof claim.
"""
import argparse,copy,hashlib,json,struct
from pathlib import Path
import live,projects,releases,capsule,packaging as pkg


def release_payload(entries,envelope,manifest):
 parts=[pkg.canonical(manifest),pkg.canonical(manifest['sources']),pkg.canonical(manifest['evidence']),pkg.canonical({'license':manifest['license'],'distribution_authority':'explicit local author declaration'})]
 detail=struct.pack('<8Q',0x31544e43524c544c,1,768,*(len(p) for p in parts),0)+envelope[:768]+b''.join(parts)
 return projects.manifest(entries,detail)


def check(client,root,key,result_path,output):
 result=json.loads(Path(result_path).read_text());artifact=Path(result['artifact']['path'])
 assert result['status']=='ok' and hashlib.sha256(artifact.read_bytes()).hexdigest()==result['artifact']['sha256']
 current=client.objects(24,root)[0][1]
 project=projects.decode_manifest(client.read_object(current))
 release_id=next(identity for name,kind,identity in project if name=='release.ltrel' and kind==13)
 handle=projects.resolve(client,root,release_id);original=client.read_object(handle)
 entries=projects.decode_manifest(original);detail=original[32+len(entries)*128:]
 magic,version,prefix,mn,sn,en,ln,reserved=struct.unpack_from('<8Q',detail)
 assert (magic,version,prefix,reserved)==(0x31544e43524c544c,1,768,0)
 signed=detail[64:832];manifest=json.loads(detail[832:832+mn])
 assert signed[192:224].hex()==result['artifact']['sha256']
 source=next(identity for name,kind,identity in entries if name=='source' and kind==11)
 assert source==result['source_root']
 # Fresh admission of the exact valid old graph exercises new guest validation;
 # old saved records cannot inherit a merely historical checked flag.
 duplicate,identity=projects.node(client,original,13)
 assert identity==release_id
 client.objects(8,duplicate)
 checks=['existing valid signed Release content is readmitted with exact actual source/evidence material']
 # Explicit campaign key authority also provisions this disposable guest's
 # publisher scope; no install or execution approval is granted.
 client.request(10,releases.project(manifest['project'])+capsule.modulus(key))
 for label in ('source','evidence'):
  changed=copy.deepcopy(manifest)
  if label=='source':
   changed['sources'][0]['size']+=1
  else:
   old=changed['evidence'][0]['request_digest']
   changed['evidence'][0]['request_digest']=('99' if old[:2]!='99' else '88')+old[2:]
  envelope,new_manifest=releases.make(artifact,manifest['project'],manifest['version'],manifest['rights'],key,parent=manifest['parent'],license=manifest['license'],evidence=changed['evidence'],profile=result['runtime_profile'],source_records_override=changed['sources'])
  # make() verifies the new RSA header, executable and all signed JSON hashes.
  path=output/(label+'-substitution.ltrel');path.write_bytes(envelope)
  assert client.stage(path)['guest_signature_verified']
  payload=release_payload(entries,envelope,new_manifest)
  try:client.import_object(payload,13)
  except ValueError as error:
   if 'status2' not in str(error):raise
  else:raise AssertionError('guest accepted signed '+label+' JSON unrelated to actual material')
  checks.append('fresh valid publisher signature and JSON commitments cannot substitute unrelated '+label+' claims for actual typed graph material')
 return dict(checks=checks,source_root=source,binary_sha256=result['artifact']['sha256'],existing_release_node=release_id,scope='present source/evidence semantic consistency only; host builder assertions and source-to-binary correctness remain unverified',compiler_executions=0,new_signed_negative_headers=2,guest_verified_negative_signatures=2,installed=False)


def main(argv=None):
 p=argparse.ArgumentParser(description='Exact present-material Release admission negatives')
 p.add_argument('--socket',type=Path,required=True);p.add_argument('--root',type=int,required=True);p.add_argument('--sign-key',type=Path,required=True);p.add_argument('--artifact-result',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
 args=p.parse_args(argv);args.output.mkdir(parents=True,exist_ok=False);client=live.Client(args.socket)
 try:
  result=check(client,args.root,args.sign_key,args.artifact_result,args.output)
  (args.output/'material.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
 finally:client.close()
 return 0
if __name__=='__main__':raise SystemExit(main())
