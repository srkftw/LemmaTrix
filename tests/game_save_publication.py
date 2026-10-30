"""Build one real save-reference successor of the preserved secure Game1.2.

Only this explicit publisher receives the old public archive. The new1.4 body
is actually compiled in the key-free sandbox and signed separately. Prior
package/source/build records remain unchanged; no consumer execution is granted.
"""
import argparse,base64,hashlib,json,shutil,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import game_release,live,projects,releases
from creator_journey import require
from signed_forge_journey import archive_selected


def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--image',type=Path,required=True)
 p.add_argument('--key',type=Path,default=ROOT/'build/campaign005/publisher.pem')
 p.add_argument('--previous',type=Path,default=ROOT/'build/campaign005/game-secure-editions/game1/publication.json')
 p.add_argument('--archive',type=Path,default=ROOT/'build/campaign005/game-secure-editions/game1-closure.json')
 p.add_argument('--version',default='1.4.0')
 p.add_argument('--edition-version',type=int,default=5)
 p.add_argument('--output',type=Path,required=True)
 a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);socket=out/'portal.sock';log=(out/'publisher.log').open('wb')
 proc=subprocess.Popen([str(ROOT/'lt'),'run','--image',str(a.image.resolve()),'--socket',str(socket)],cwd=ROOT,stdout=log,stderr=log,start_new_session=True)
 try:
  deadline=time.monotonic()+90
  while not socket.exists():
   require(proc.poll()is None,'publisher exited before readiness')
   if time.monotonic()>deadline:raise TimeoutError('publisher boot readiness')
   time.sleep(.1)
  c=live.Client(socket,timeout=240)
  try:
   previous=json.loads(a.previous.read_text());archive=json.loads(a.archive.read_text())
   require(previous['release_id']=='3a56b13d0e211adf25e66d05c09dedc48506c84cb4fe328af8295b3460be7779','unexpected preserved first Game')
   old_path=Path(previous['package']);old_raw=old_path.read_bytes();old_info=releases.inspect(old_raw)
   require(old_info['release_id']==previous['release_id'],'old signed artifact differs from recorded publication')
   imported=projects.import_records(c,[dict(x,name='crate-previous-public')for x in archive['selected']],[dict(r,payload=base64.b64decode(r['payload']))for r in archive['nodes']])
   previous['root']=imported[0]['cap'];require(projects.project_identity(c,previous['root'])==previous['logical_project_id'],'old source origin changed on import')
   old_dir=out/'game1';old_dir.mkdir();(old_dir/'crate-workshop.ltrel').write_bytes(old_raw)
   for suffix in ('.manifest.json',):
    source=Path(str(old_path)+suffix)
    if source.exists():shutil.copyfile(source,old_dir/('crate-workshop.ltrel'+suffix))
   (old_dir/'publication.json').write_text(json.dumps(previous,indent=2)+'\n');shutil.copyfile(a.archive,out/'game1-closure.json')
   print('PASS exact preserved Game1.2 public source and signed artifact',flush=True)
   successor=game_release.publish(c,generation=2,key=a.key,output=out/'game2',previous=previous,version=a.version,edition_version=a.edition_version)
   require(not successor['build_reused'],'first save-reference successor unexpectedly reused a build')
   info=releases.inspect(Path(successor['package']).read_bytes())
   require(info['parent']==previous['release_id'] and successor['logical_project_id']==previous['logical_project_id']==successor['source_logical_project_id'],'new native/source lineage differs')
   require(successor['edition_version']==a.edition_version and successor['binary_sha256']!=previous['binary_sha256'],'new source did not produce a distinct declared successor')
   print('PASS actual isolated1.4 source build and signed successor',successor['release_id'],flush=True)
   path=out/'game2-closure.json';head=archive_selected(c,successor['root'],path);closure=json.loads(path.read_text());size=sum(len(base64.b64decode(r['payload']))for r in closure['nodes'])
   require(head==successor['head'] and len(closure['nodes'])<=24 and size<=1048576,'successor closure exceeds supported graph profile')
   result=dict(schema=1,result='passed',publisher_image_sha256=hashlib.sha256(a.image.read_bytes()).hexdigest(),previous_publication_sha256=hashlib.sha256(a.previous.read_bytes()).hexdigest(),previous_archive_sha256=hashlib.sha256(a.archive.read_bytes()).hexdigest(),previous_release=previous['release_id'],new_publication=successor,new_native_parent=info['parent'],native_version=info['version'],previous_artifact_preserved=True,new_actual_builds=1,new_closure=dict(nodes=len(closure['nodes']),payload_bytes=size,head=head,archive_sha256=hashlib.sha256(path.read_bytes()).hexdigest()),source_to_binary='unverified',executed=False,retained=False)
   (out/'evidence.json').write_text(json.dumps(result,indent=2)+'\n');print('PASS exact bounded new canonical closure',len(closure['nodes']),size,flush=True)
   try:c.request(70)
   except EOFError:pass
  finally:c.close()
  proc.wait(timeout=20)
 finally:
  if proc.poll()is None:proc.terminate();proc.wait(timeout=20)
  log.close()
if __name__=='__main__':main()
