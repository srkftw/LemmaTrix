"""Actual caller-scoped Objects47 release, live readers and pinned closure checks.

The signed ordinary probes have read1 only, without share8 or revoke16. Their
IPC calls retain actual kernel caller identity; Launcher does not proxy rights.
"""
import argparse,contextlib,hashlib,json,os,signal,struct,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import live,nodes,projects,releases
from library_journey import wait


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,required=True);p.add_argument('--binary',type=Path,required=True)
 p.add_argument('--key',type=Path,default=ROOT/'build/campaign005/publisher.pem');p.add_argument('--public',type=Path,default=ROOT/'build/campaign005/publisher.pub');p.add_argument('--output',type=Path,required=True)
 a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);sock=out/'portal.sock';log=(out/'guest.log').open('wb');client=None;proc=None;checks=[];packages={}
 def passed(label,**facts):
  checks.append(dict(check=label,result='passed',**facts));print('PASS',label,flush=True)
  (out/'progress.json').write_text(json.dumps(dict(image_sha256=hashlib.sha256(a.image.read_bytes()).hexdigest(),checks=checks),indent=2)+'\n')
 def rejected(action,label):
  try:action()
  except ValueError as error:return str(error)
  raise AssertionError(label+' unexpectedly succeeded')
 try:
  command=list(map(str,[ROOT/'lt','run','--backend','qemu','--image',a.image,'--socket',sock]));proc=subprocess.Popen(command,cwd=ROOT,stdout=log,stderr=log,start_new_session=True)
  wait(sock.exists,90,'guest boot');client=live.Client(sock,timeout=180)
  for name in ('object-ref-a','object-ref-b'):
   raw,_=releases.make(a.binary,name,'1.0.0',1,a.key,profile=2,license='NOASSERTION');path=out/(name+'.ltrel');path.write_bytes(raw);info=releases.inspect(raw,releases.public_modulus(a.public))
   instance=nodes.start_package(client,nodes.approved_package(path,a.public,info['release_id'],1),raw)
   packages[name]=dict(instance=instance,rights=1,release_id=info['release_id'],package_sha256=hashlib.sha256(raw).hexdigest())
  table=client.request(2)
  for selected in packages.values():
   actual=[struct.unpack_from('<4Q',table,i) for i in range(0,len(table),32) if struct.unpack_from('<Q',table,i)[0]==selected['instance']]
   assert len(actual)==1 and 0<actual[0][1]<5 and actual[0][2]==1,'probe did not run with actual read1 rights only'
  def call(name,op,h,offset=0,count=0):
   raw=client.request(150,struct.pack('<Q8Q',packages[name]['instance'],910,op,h,offset,count,0,0,1));assert len(raw)>=64
   return struct.unpack_from('<8Q',raw),raw[64:]
  def stats():return list(client.objects(10)[0][1:4])
  baseline=stats();payload=bytes((i*53+9)&255 for i in range(384));creator=client.import_object(payload,2);old_id=client.objects(5,creator)[0][7]
  readers=[client.objects(6,creator,packages[name]['instance'],1)[0][1] for name in packages]
  live_stats=stats();assert live_stats[:2]==[baseline[0]+1,baseline[1]+len(payload)]
  for name,h in zip(packages,readers):assert call(name,4,h,0,len(payload))[1]==payload
  assert call('object-ref-b',47,readers[0])[0][0]==3,'wrong caller released another caller scope'
  assert call('object-ref-a',8,readers[0])[0][0]==1,'read-only caller obtained destructive revoke/drop authority'
  assert rejected(lambda:client.objects(47,creator,a=1),'reserved release argument')=='Objects status2'
  raw=client.request(100,struct.pack('<8Q',47,creator,0,0,0,0,0,2));assert struct.unpack_from('<Q',raw)[0]==2
  assert client.read_object(creator)==payload,'denied release changed creator bytes'
  passed('read-only scoped readers work; wrong caller, destructive drop, reserved argument and schema2 are denied',actual_rights=1,creator_handle=creator,reader_handles=readers,creator_object_id=old_id,live_creator_stats=live_stats,payload_sha256=hashlib.sha256(payload).hexdigest())
  client.objects(47,creator);assert stats()[:2]==live_stats[:2]
  creator_stale=rejected(lambda:client.read_object(creator),'released creator read')
  for name,h in zip(packages,readers):assert call(name,4,h,0,len(payload))[1]==payload
  assert call('object-ref-a',47,readers[0])[0][0]==0
  assert call('object-ref-a',47,readers[0])[0][0]==3 and call('object-ref-a',4,readers[0],0,len(payload))[0][0]==3
  assert call('object-ref-b',4,readers[1],0,len(payload))[1]==payload and stats()[:2]==live_stats[:2]
  assert call('object-ref-b',47,readers[1])[0][0]==0
  freed=stats();assert freed==baseline,('last reference did not reclaim actual creator capacity',baseline,freed)
  assert call('object-ref-b',4,readers[1],0,len(payload))[0][0]==3
  replacement=client.import_object(b'fresh record after final scoped release',2);new_id=client.objects(5,replacement)[0][7]
  assert old_id&63==new_id&63 and old_id!=new_id and replacement not in [creator,*readers]
  assert client.read_object(replacement)==b'fresh record after final scoped release'
  for name,h in zip(packages,readers):assert call(name,47,h)[0][0]==3
  client.objects(47,replacement);assert stats()==baseline
  passed('creator and individual reader releases preserve surviving exact bytes; last reader reclaims record and bytes with generation-safe slot reuse',creator_stale_read=creator_stale,after_last_release=freed,reused_record_slot=old_id&63,old_object_id=old_id,fresh_object_id=new_id,fresh_handle=replacement)
  source=b'namespace ReferencePinned\ndef value : UInt64 := 73\nend ReferencePinned\n';blob,blob_id=projects.node(client,source,10);manifest_bytes=projects.manifest([('value.lean',10,blob_id)]);manifest,head=projects.node(client,manifest_bytes,11)
  name=b'reference-release-pinned';root=client.objects(22,manifest,0,len(name),data=bytes(32)+name.ljust(64,b'\0'))[0][1];pinned_stats=stats()
  client.objects(47,blob);client.objects(47,manifest)
  assert stats()[:2]==pinned_stats[:2] and projects.roots(client)[0]['head']==head
  rejected(lambda:client.read_object(blob),'released pinned blob capability');rejected(lambda:client.read_object(manifest),'released pinned manifest capability')
  selected_manifest=projects.resolve(client,root,head);selected_blob=projects.resolve(client,root,blob_id)
  assert client.read_object(selected_manifest)==manifest_bytes and client.read_object(selected_blob)==source
  client.objects(47,selected_manifest);client.objects(47,selected_blob)
  assert stats()[:2]==pinned_stats[:2]
  selected_blob=projects.resolve(client,root,blob_id);assert client.read_object(selected_blob)==source;client.objects(47,selected_blob)
  passed('releasing all Object capabilities to pinned nodes preserves complete named Project closure and fresh authorized scoped resolves',head=head,blob_id=blob_id,root_handle=root,pinned_creator_stats=pinned_stats,after_cap_releases=stats(),source_sha256=hashlib.sha256(source).hexdigest())
  before_stage=stats();data=b'uncommitted private stage';stage=client.objects(1,0,len(data),2,1,data=hashlib.sha256(data).digest())[0][1];client.objects(2,stage,0,data=data)
  stage_denial=rejected(lambda:client.objects(47,stage),'release of uncommitted stage');client.objects(13,stage)
  assert stats()==before_stage
  passed('uncommitted stage cannot use committed-reference release; explicit abort reclaims it',stage_denial=stage_denial,after_abort_stats=stats())
  before_dead=stats();dead_payload=b'last authorized reader process death'
  dead_creator=client.import_object(dead_payload,2);dead_read=client.objects(6,dead_creator,packages['object-ref-a']['instance'],1)[0][1]
  client.request(26,struct.pack('<Q',packages['object-ref-a']['instance']));client.objects(47,dead_creator)
  assert stats()==before_dead,'dead reader capability prevented creator reference reclamation'
  later_creator=client.import_object(dead_payload,2);later_read=client.objects(6,later_creator,packages['object-ref-b']['instance'],1)[0][1]
  client.objects(47,later_creator);assert stats()[:2]==[before_dead[0]+1,before_dead[1]+len(dead_payload)]
  assert call('object-ref-b',4,later_read,0,len(dead_payload))[1]==dead_payload
  client.request(26,struct.pack('<Q',packages['object-ref-b']['instance']));client.objects(11)
  assert stats()==before_dead,'last reader death orphaned a released record while its original creator stayed alive'
  final_blob=projects.resolve(client,root,blob_id);assert client.read_object(final_blob)==source,'dead-reader collection damaged pinned Project data';client.objects(47,final_blob)
  passed('dead reader scope is cleaned before creator release; later last-reader death is collected while original creator remains live',dead_before_release_read_handle=dead_read,dead_after_release_read_handle=later_read,after_dead_collection=stats(),original_creator='live Launcher',pinned_project_bytes_preserved=True)
  result=dict(schema=1,result='passed',backend='qemu',image_sha256=hashlib.sha256(a.image.read_bytes()).hexdigest(),probe_sha256=hashlib.sha256(a.binary.read_bytes()).hexdigest(),packages=packages,command=command,checks=checks,limitations=['focused Objects47/schema1 public SDK authority and reclamation checks; no repeated native save UI or vault-retention proof claimed','two ordinary signed test callers are explicitly installed through normal operator bootstrap; their kernel-supplied rights remain1'])
  (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
 finally:
  if client:
   with contextlib.suppress(EOFError,OSError,ValueError):client.request(70)
   client.close()
  if proc and proc.poll() is None:
   try:proc.wait(20)
   except subprocess.TimeoutExpired:os.killpg(proc.pid,signal.SIGTERM);proc.wait(10)
  log.close()


if __name__=='__main__':main()
