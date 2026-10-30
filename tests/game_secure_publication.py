"""Actual isolated builds for caller-bound game scopes, preserving lineage.

Prior public generation2 is imported under an explicit temporary local name.
Patched releases1.2/1.3 continue its exact Source origin and native parent chain.
No prior artifact is overwritten; the compiler/signing bootstrap is disclosed.
"""
import argparse,base64,hashlib,json,os,signal,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import game_release,live,projects
from signed_forge_journey import archive_selected

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',required=True,type=Path);p.add_argument('--key',required=True,type=Path);p.add_argument('--previous',required=True,type=Path);p.add_argument('--archive',required=True,type=Path);p.add_argument('--output',required=True,type=Path);p.add_argument('--reuse-builds',type=Path);a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);sock=out/'portal.sock';log=(out/'publisher.log').open('wb');proc=subprocess.Popen([str(ROOT/'lt'),'run','--image',str(a.image.resolve()),'--socket',str(sock)],cwd=ROOT,stdout=log,stderr=log,start_new_session=True)
 try:
  deadline=time.monotonic()+90
  while not sock.exists():
   if proc.poll() is not None:raise RuntimeError('publisher boot failed')
   if time.monotonic()>deadline:raise TimeoutError('publisher boot')
   time.sleep(.1)
  c=live.Client(sock,timeout=240)
  try:
   previous=json.loads(a.previous.read_text());archive=json.loads(a.archive.read_text());selected=[dict(r,name='crate-previous-public') for r in archive['selected']];roots=projects.import_records(c,selected,[dict(r,payload=base64.b64decode(r['payload'])) for r in archive['nodes']]);previous['root']=roots[0]['cap'];assert projects.project_identity(c,previous['root'])==previous['logical_project_id'];print('PASS exact previous public source origin imported',flush=True)
   if a.reuse_builds:
    import shutil
    for name in ['game1','game2']:
     (out/name).mkdir();shutil.copyfile(a.reuse_builds/name/'build-result.json',out/name/'build-result.json')
   first=game_release.publish(c,generation=1,key=a.key,output=out/'game1',previous=previous,version='1.2.0');print('PASS actual isolated secure1.2 source build and signed graph',first['release_id'],flush=True)
   second=game_release.publish(c,generation=2,key=a.key,output=out/'game2',previous=first,version='1.3.0');print('PASS actual isolated secure1.3 source build and signed graph',second['release_id'],flush=True)
   assert first['logical_project_id']==second['logical_project_id']==previous['logical_project_id'];closures=[]
   for generation,pub in [(1,first),(2,second)]:
    cursor=count=total=0
    while True:
     fields,_=c.objects(26,pub['root'],cursor)
     if fields[1]==0:break
     count+=1;total+=fields[2];assert fields[3]>cursor;cursor=fields[3]
    assert count<=24 and total<=1048576,(count,total)
    path=out/('game'+str(generation)+'-closure.json');head=archive_selected(c,pub['root'],path);assert head==pub['head'];closures.append(dict(generation=generation,records=count,bytes=total,head=head,archive=str(path)))
   report=dict(image=hashlib.sha256(a.image.read_bytes()).hexdigest(),publications=[first,second],previous_release=previous['release_id'],stable_logical_project=first['logical_project_id'],closures=closures,new_actual_builds=sum(not pub['build_reused'] for pub in [first,second]),scope_boundary='Game501/503 calls Objects.checkDelegation against exact IPC caller before any metadata/read',source_to_binary='unverified');(out/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS fresh game graph closures and original stable identity',flush=True)
   try:c.request(70)
   except EOFError:pass
  finally:c.close()
  proc.wait(timeout=20)
 finally:
  if proc.poll() is None:os.killpg(proc.pid,signal.SIGTERM);proc.wait(timeout=10)
  log.close()
if __name__=='__main__':main()
