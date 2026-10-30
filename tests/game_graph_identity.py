"""Re-import cached real game builds, checking stable live graph identity/closure."""
import argparse,hashlib,json,os,signal,struct,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import game_release,live
from signed_forge_journey import archive_selected

def main():
 p=argparse.ArgumentParser();p.add_argument('--builds',required=True,type=Path);p.add_argument('--key',required=True,type=Path);p.add_argument('--output',required=True,type=Path);a=p.parse_args();a.output=a.output.resolve();a.output.mkdir(parents=True,exist_ok=False);sock=a.output/'portal.sock';log=(a.output/'guest.log').open('wb');proc=subprocess.Popen([str(ROOT/'lt'),'run','--socket',str(sock)],cwd=ROOT,stdout=log,stderr=log,start_new_session=True)
 try:
  deadline=time.monotonic()+90
  while not sock.exists():
   if proc.poll() is not None:raise RuntimeError('guest exited')
   if time.monotonic()>deadline:raise TimeoutError('boot')
   time.sleep(.05)
  c=live.Client(sock,timeout=240)
  try:
   first=game_release.publish(c,generation=1,key=a.key,output=a.builds/'game1');second=game_release.publish(c,generation=2,key=a.key,output=a.builds/'game2',previous=first)
   assert first['logical_project_id']==second['logical_project_id']==first['source_logical_project_id']==second['source_logical_project_id']
   counts=[]
   for generation,pub in ((1,first),(2,second)):
    count=total=cursor=0
    while True:
     fields,_=c.objects(26,pub['root'],cursor)
     if fields[1]==0:break
     count+=1;total+=fields[2];assert fields[3]>cursor;cursor=fields[3]
    assert count<=24 and total<=1048576,(generation,count,total)
    path=a.output/('game'+str(generation)+'-closure.json');head=archive_selected(c,pub['root'],path);assert head==pub['head'];counts.append(dict(generation=generation,records=count,payload_bytes=total,head=head,archive=str(path)))
   report=dict(image=hashlib.sha256((ROOT/'build/live/guest.bin').read_bytes()).hexdigest(),stable_logical_project_id=first['logical_project_id'],publications=[first,second],closures=counts,builds_reused=True,new_compilations=0)
   (a.output/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
   try:c.request(70)
   except EOFError:pass
  finally:c.close()
  proc.wait(timeout=20)
 finally:
  if proc.poll() is None:os.killpg(proc.pid,signal.SIGKILL);proc.wait()
  log.close()
if __name__=='__main__':main()
