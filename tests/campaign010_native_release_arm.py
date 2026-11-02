"""A separately initialized AArch64 assembly guest installs guest-signed v4 bytes.

The AArch64 instruction interpreter runs under qemu-aarch64 on this x86 host.
This focused public-CLI admission/run check does not claim native ARM hardware.
"""
import argparse,hashlib,json,os,signal,struct,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import live,releases
from graphical_devices import DeviceInput,prepare_input
from creator_journey import rendered_text

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,required=True);p.add_argument('--release',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--request-timeout',type=int,default=300);p.add_argument('--application',choices=('sdk','notes'),default='sdk');p.add_argument('--backend',choices=('aarch64','x86_64'),default='aarch64');a=p.parse_args()
 out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);sock=out/'portal.sock';graphics=out/'display';fd=prepare_input(a.backend,graphics);log=(out/'transport.log').open('wb')
 args=[sys.executable,ROOT/'lt','run','--backend',a.backend,'--image',a.image.resolve(),'--socket',sock,'--graphics',graphics]
 proc=subprocess.Popen(list(map(str,args)),cwd=ROOT,stdout=log,stderr=log,start_new_session=True);c=None;ui=None;start=time.monotonic()
 record=dict(schema=1,result='running',backend='AArch64 assembly emulator under qemu-aarch64 on x86-64 Linux'if a.backend=='aarch64'else'native x86-64 assembly emulator on x86-64 Linux',image_sha256=hashlib.sha256(a.image.read_bytes()).hexdigest(),release_sha256=hashlib.sha256(a.release.read_bytes()).hexdigest(),commands=[list(map(str,args))],checks=[],timings=[])
 def mark(action,since):
  item=dict(action=action,seconds=round(time.monotonic()-since,3));record['timings'].append(item);print(json.dumps(item),flush=True)
 try:
  deadline=time.monotonic()+300
  while not sock.exists():
   if proc.poll()is not None:raise RuntimeError('emulator stopped before its public portal')
   if time.monotonic()>deadline:raise TimeoutError('emulator boot')
   time.sleep(.05)
  c=live.Client(sock,timeout=a.request_timeout);raw=a.release.read_bytes();info=releases.inspect(raw,raw[576:608]);now=time.monotonic();c.request(10,bytes.fromhex(info['project_id'])+raw[576:608]);mark('approve exact publisher',now)
  now=time.monotonic();c.request(20,struct.pack('<Q',len(raw)))
  for offset in range(0,len(raw),512):c.request(21,struct.pack('<Q',offset)+raw[offset:offset+512])
  mark('upload exact guest-signed artifact',now);now=time.monotonic();header=c.request(22)
  if header!=raw[:512]:raise AssertionError('native verification returned a substituted header')
  mark('native Launcher Ed25519 verification',now);now=time.monotonic();c.request(23,bytes.fromhex(info['release_id'])+struct.pack('<Q',info['rights']));slot=struct.unpack_from('<Q',c.request(24),8)[0];admitted=info
  mark('explicit native installation approval',now)
  instance=struct.unpack_from('<Q',c.request(25,struct.pack('<Q',slot)),8)[0]
  if not instance:raise AssertionError('native application did not start')
  ui=DeviceInput(a.backend,graphics);deadline=time.monotonic()+120
  while True:
   frame=ui.frame()
   ready=(rendered_text(frame,14,152,8,0xdce9ec)=='Title / ')if a.application=='notes'else(rendered_text(frame,40,88,5,0xe5eef7)=='1e77a')
   if ready:break
   if time.monotonic()>deadline:raise TimeoutError('native public SDK application surface')
   time.sleep(.3)
  (out/'application.ppm').write_bytes(frame.ppm())
  processes=c.request(2);rows=[struct.unpack_from('<4Q',processes,i)for i in range(0,len(processes),32)]
  if not any(r[0]==instance and 0<r[1]<5 and r[2]==info['rights']for r in rows):raise AssertionError('actual native process is absent')
  record['checks'].append(dict(check='exact guest-signed v4 release independently verifies and runs under separate assembly guest authority',result='pass',release=admitted,instance=instance,frame_sha256=frame.digest))
  if a.application=='notes':
   ui.textASCII('ARM note',delay=.12);ui.press(28);deadline=time.monotonic()+120
   while rendered_text(ui.frame(),16,134,8,0xa6d7b1)!='ARM note':
    if time.monotonic()>deadline:raise TimeoutError('Project Notes title input')
    time.sleep(.2)
   body='AArch64 public SDK';ui.textASCII(body,delay=.12);deadline=time.monotonic()+120
   while rendered_text(ui.frame(),18,170,len(body),0xdce9ec)!=body:
    if time.monotonic()>deadline:raise TimeoutError('Project Notes body input')
    time.sleep(.2)
   frame=ui.frame();(out/'notes-edited.ppm').write_bytes(frame.ppm());record['checks'].append(dict(check='actual ordinary Project Notes consumes native title and body input',result='pass',title='ARM note',body=body,frame_sha256=frame.digest))
  tampered=out/'tampered.ltrel';changed=bytearray(raw);changed[-1]^=1;tampered.write_bytes(changed)
  try:c.stage(tampered)
  except ValueError:pass
  else:raise AssertionError('tampered artifact was admitted')
  record['checks'].append(dict(check='tampered new-profile executable is refused',result='pass'));record['result']='pass'
 except BaseException as error:record.update(result='failure',error=repr(error));raise
 finally:
  record['elapsed_seconds']=time.monotonic()-start;(out/'execution.json').write_text(json.dumps(record,indent=2)+'\n')
  if c:c.close()
  if ui:ui.close()
  if proc.poll()is None:os.killpg(proc.pid,signal.SIGKILL);proc.wait(timeout=10)
  os.close(fd);log.close()
 return 0

if __name__=='__main__':raise SystemExit(main())
