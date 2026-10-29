"""Actual no-vault restart after a completed native signed project session."""
import argparse,hashlib,json,os,signal,struct,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import live,projects
from signed_forge_journey import events

def main():
 p=argparse.ArgumentParser();p.add_argument('--previous',required=True,type=Path);p.add_argument('--output',required=True,type=Path);p.add_argument('--image',required=True,type=Path);a=p.parse_args();previous=a.previous.resolve();a.output=a.output.resolve();a.output.mkdir(parents=True,exist_ok=False)
 old_report=json.loads((previous/'journey.json').read_text());last=old_report['checks'][-1];assert last['check']=='network generation2 activation and explicit native rollback preserve both running generations' and last['result']=='pass'
 ready=next(e for e in events(previous/'worker.log') if e['event']=='ready');result=json.loads(next((previous/'worker').rglob('job.result.json')).read_text());old_root=ready['authority']['root'];old_snapshot=result['guest_session']['source_root_capability'];publication=bytes.fromhex(ready['publication_id']);log=(a.output/'guest.log').open('wb');sock=a.output/'portal.sock'
 process=subprocess.Popen([str(ROOT/'lt'),'run','--backend','qemu','--image',str(a.image.resolve()),'--socket',str(sock)],cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
 c=None
 def denied(call,status):
  try:call()
  except ValueError as e:assert str(e)==status,str(e)
  else:raise AssertionError('previous session authority unexpectedly survived without vault retention')
 try:
  end=time.monotonic()+45
  while not sock.exists():
   if process.poll() is not None:raise AssertionError('fresh no-vault guest exited')
   if time.monotonic()>end:raise TimeoutError('no-vault boot')
   time.sleep(.05)
  c=live.Client(sock,timeout=30);assert projects.roots(c)==[]
  denied(lambda:c.objects(29,old_root),'Objects status3');denied(lambda:c.objects(24,old_snapshot),'Objects status3')
  denied(lambda:c.request(29,publication),'guest rejected command29, status1');denied(lambda:c.request(13,struct.pack('<Q',0)),'guest rejected command13, status1')
  authority=c.request(160,struct.pack('<8Q',7,int(result['job_id']),0,0,0,0,0,1));assert struct.unpack_from('<Q',authority)[0]!=0
  table=c.request(2);fresh_instances=[struct.unpack_from('<Q',table,i)[0] for i in range(32,len(table),32)];assert ready['authority']['requester'] not in fresh_instances and result['guest_session']['job_service'] not in fresh_instances;assert all(struct.unpack_from('<Q',table,i+8)[0]==0 for i in range(7*32,len(table),32))
  report=dict(image=hashlib.sha256(a.image.read_bytes()).hexdigest(),previous_evidence=str(previous/'journey.json'),previous_project=ready['authority']['project_id'],previous_active_release=last['rolled_back'],previous_live_root=old_root,previous_frozen_root=old_snapshot,previous_requester=ready['authority']['requester'],previous_job_service=result['guest_session']['job_service'],previous_job_id=result['job_id'],fresh_service_instances=fresh_instances[:6],checks=['no attached personal vault or server backing','fresh guest has no project roots','old local root and frozen BuildJob capability handles denied','prior execution approval and installed generation catalog absent','prior installed application incarnations gone','old requester/service incarnations and BuildJob signing authority absent'],durability='this assertion concerns only the personal session; separately authorized server backing follows its own store policy')
  (a.output/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
 finally:
  if c:
   try:c.request(70)
   except (EOFError,OSError,ValueError):pass
   c.close()
  try:process.wait(timeout=10)
  except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait()
  log.close()
if __name__=='__main__':main()
