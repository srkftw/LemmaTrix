"""Real no-vault UI/build/run plus narrow new desktop authority negatives.

Uses the persistent, explicitly scoped host publisher worker. The native probe is
an ordinary signed compartment; it invokes kernel/IPC boundaries without touching
guest memory from the host. No OS compilation or crypto-vector repetition.
"""
import argparse,hashlib,json,os,signal,struct,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import live,projects,project_vault,releases
from creator_journey import Journey,require,rendered_score,rendered_text


def main():
 p=argparse.ArgumentParser();p.add_argument('--editor',type=Path,required=True);p.add_argument('--probe',type=Path,required=True);p.add_argument('--public',type=Path,required=True);p.add_argument('--key',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output=a.output.resolve()
 require(not a.output.exists(),'output must be a new owned directory')
 j=Journey(a);worker=None;worker_log=None
 try:
  j.boot(False);editor,editor_instance=j.trust_stage(a.editor,'native-editor');j.ui.press(1);time.sleep(.3)
  command=[ROOT/'lt','project','--socket',j.socket,'import',ROOT/'examples/creator','--name','creator']
  subprocess.run(list(map(str,command)),cwd=ROOT,check=True,capture_output=True)
  j.open_named_project('creator')
  # Real edits create an immutable new source/project revision before F5.
  j.ui.press(107);j.ui.textASCII('\n-- explicit ephemeral session edit\n',delay=.04);j.ui.press(62);time.sleep(.5)
  with j.client() as c:
   root=next(r for r in projects.roots(c) if r['name']=='creator');head,files=projects.snapshot(c,root['cap']);require(files['Main.lean'].endswith(b'-- explicit ephemeral session edit\n'),'native ephemeral edit was not committed')
   c.request(10,releases.project('creator')+releases.public_modulus(a.public))
   try:project_vault.unlock(c,bytes([89])*32)
   except ValueError:pass
   else:raise AssertionError('no-vault guest acknowledged an unavailable durable store')
  worker_path=j.out/'publisher-worker.log';worker_log=worker_path.open('wb')
  command=[ROOT/'lt','project','--socket',j.socket,'serve','--project','creator','--sign-key',a.key.resolve(),'--output',j.out/'worker','--version','2.0.0']
  worker=subprocess.Popen(list(map(str,command)),cwd=ROOT,stdout=worker_log,stderr=worker_log,start_new_session=True)
  j.ui.press(63);deadline=time.monotonic()+180;staged=None
  while time.monotonic()<deadline:
   require(worker.poll() is None,'publisher worker exited unexpectedly')
   for line in worker_path.read_text().splitlines():
    try:event=json.loads(line)
    except ValueError:continue
    if event['event']=='staged':staged=event
   if staged:break
   time.sleep(.1)
  require(staged is not None,'F5 persistent bootstrap did not stage a real signed result')
  require(staged['signature_verified'] and staged['material_checked'] and not staged['installed'],'worker skipped signature/material/local-authority separation')
  old=j.ui.frame().digest;j.ui.press(88);j.ui.wait_frame(old);time.sleep(.6);j.ui.press(28);time.sleep(2)
  j.ui.textASCII('cat123',delay=.09);time.sleep(.6);frame=j.ui.frame();require(rendered_score(frame)=='00000014','no-vault exact build did not run on arbitrary input')
  require(hashlib.sha256((ROOT/'build/live/guest.bin').read_bytes()).hexdigest()==j.image,'ordinary project build changed OS image')
  with j.client() as c:active=c.request(29,releases.project('creator'));require(active[160:192].hex()==staged['release'],'F12 did not activate exact worker result')
  (j.out/'ephemeral-native-app.ppm').write_bytes(frame.ppm());j.passed('no-vault real editing/F5 sandbox worker/F12 exact approval/native input',source=head,release=staged['release'],score=rendered_score(frame),durability='ephemeral',worker=staged)
  os.killpg(worker.pid,signal.SIGINT);worker.wait(timeout=10);worker=None;worker_log.close();worker_log=None
  probe,old_instance=j.trust_stage(a.probe,'workspace-authority')
  def probe_call(c,instance,stale):
   response=c.request(150,struct.pack('<Q8Q',instance,1,stale,0,0,0,0,0,1));status,mask,own=struct.unpack_from('<3Q',response)
   require(status==0 and mask==4095 and own==instance,'native surface/focus/approval authority negative failed: '+repr((status,mask,own)))
  with j.client() as c:
   probe_call(c,old_instance,0);c.request(26,struct.pack('<Q',old_instance))
   slot=None
   for index in range(16):
    try:header=c.request(13,struct.pack('<Q',index))
    except ValueError:continue
    if header[160:192].hex()==probe['release_id']:slot=index+1;break
   require(slot is not None,'installed authority probe catalog missing')
   new_instance=struct.unpack_from('<Q',c.request(25,struct.pack('<Q',slot)))[0]
  time.sleep(.3)
  with j.client() as c:probe_call(c,new_instance,old_instance);c.request(26,struct.pack('<Q',new_instance))
  require(new_instance!=old_instance and new_instance&255==old_instance&255,'probe did not exercise reused process slot')
  time.sleep(.5);j.ui.chord(56,15);time.sleep(.4);j.ui.chord(29,38);j.ui.textASCII('dog',delay=.09);time.sleep(.5)
  frame=j.ui.frame();require(rendered_score(frame)=='00000005','unrelated native app was unusable after probe death/slot reuse')
  j.passed('ordinary native app cannot forge focus/display/input/approval; stale surface denied',checks=12,old_instance=old_instance,new_instance=new_instance,unrelated_app_score=rendered_score(frame))
  j.stop()
  # A fresh no-vault boot has no named root or inherited local execution trust.
  j.boot(False)
  with j.client() as c:
   require(projects.roots(c)==[],'ephemeral named project survived a no-vault restart')
   try:c.request(25,struct.pack('<Q',1))
   except ValueError:pass
   else:raise AssertionError('old ephemeral install authority survived')
  j.passed('no-vault restart discards project and execution authority');j.stop()
 finally:
  if worker and worker.poll() is None:os.killpg(worker.pid,signal.SIGTERM);worker.wait(timeout=10)
  if worker_log:worker_log.close()
  if j.proc and j.proc.poll() is None:j.stop(hard=True)
if __name__=='__main__':main()
