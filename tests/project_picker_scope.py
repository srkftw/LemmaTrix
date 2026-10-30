"""Actual public picker masks, caller binding, trusted labels and physical cancellation.

The tiny ordinary signed probe preserves its own kernel-supplied rights while
forwarding the bounded Compositor interface. No guest memory or UI state writes.
"""
import argparse,contextlib,hashlib,json,os,signal,struct,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import live,nodes,releases
from creator_journey import rendered_text
from graphical_devices import DeviceInput
TITLE='TRUSTED PROJECT OPEN / SELECT A NAMED PROJECT'
LABELS={1:'ACCESS: READ ONLY / NO EDIT OR PUBLISH AUTHORITY',25:'ALLOW READ SHARE REVOKE - DATA ONLY',127:'ACCESS: READ CREATE REVISE SHARE REVOKE ENUMERATE EXPORT'}

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,required=True)
 p.add_argument('--binary',type=Path,required=True);p.add_argument('--key',type=Path,required=True)
 p.add_argument('--public',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
 a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
 sock=out/'portal.sock';graphics=out/'display.qmp';log=(out/'guest.log').open('wb');proc=None;c=None;ui=None;checks=[]
 def wait(check,label,seconds=30):
  deadline=time.monotonic()+seconds
  while time.monotonic()<deadline:
   value=check()
   if value:return value
   time.sleep(.05)
  raise TimeoutError(label)
 try:
  proc=subprocess.Popen(list(map(str,[ROOT/'lt','run','--image',a.image,'--socket',sock,'--graphics',graphics])),cwd=ROOT,stdout=log,stderr=log,start_new_session=True)
  wait(sock.exists,'boot',90);c=live.Client(sock,timeout=180);ui=DeviceInput('qemu',graphics)
  processes=c.request(2);compositor=struct.unpack_from('<Q',processes,4*32)[0]
  assert compositor&255==4 and 0<struct.unpack_from('<Q',processes,4*32+8)[0]<5
  # Launcher has object127 but no display256; it cannot bypass the ordinary
  # graphical endpoint check even when targeting the full service identity.
  try:c.request(150,struct.pack('<Q8Q',compositor,14,25,1,0,0,0,0,1))
  except ValueError as error:checks.append(dict(check='Launcher cannot bypass graphical endpoint admission',result='passed',denial=str(error)))
  else:raise AssertionError('Launcher bypassed graphical endpoint display requirement')
  packages={}
  for name,rights in [('picker-full',383),('picker-read',257)]:
   raw,info=releases.make(a.binary,name,'1.0.0',rights,a.key,profile=2,license='NOASSERTION');path=out/(name+'.ltrel');path.write_bytes(raw)
   decoded=releases.inspect(raw,releases.public_modulus(a.public));assert decoded['rights']==rights
   instance=nodes.start_package(c,nodes.approved_package(path,a.public,decoded['release_id'],rights),raw)
   packages[name]=dict(instance=instance,rights=rights,release=decoded['release_id'])
  def call(name,op,requested=0,nonce=0,version=1):
   reply=c.request(150,struct.pack('<Q8Q',packages[name]['instance'],900,compositor,op,requested,nonce,version,0,1))
   assert len(reply)==64,('wrong public response length',len(reply))
   fields=struct.unpack('<8Q',reply);assert fields[0] in (0,1),('probe/kernel failure rather than Compositor response',fields)
   return fields
  def title_present():return rendered_text(ui.frame(),12,10,len(TITLE))==TITLE
  for i,(mask,nonce,version) in enumerate([(0,100,1),(3,101,1),(73,102,1),(127,103,1),(4096,104,1),(25,0,1),(25,105,2)]):
   fields=call('picker-full',14,mask,nonce,version);assert fields[0]==1
   assert not title_present(),'denied request opened a trusted panel'
   assert call('picker-full',4,nonce=nonce)[0]==1,'denied request created a queryable result'
   checks.append(dict(check='unsupported mask, zero nonce or version denied without a panel',requested=mask,nonce=nonce,version=version,result='passed'))
  assert call('picker-read',14,25,200)[0]==1 and not title_present()
  checks.append(dict(check='ordinary read1+display caller denied requested read/share/revoke25',actual_rights=257,requested=25,result='passed'))
  for name,op,mask,nonce in [('picker-full',14,1,301),('picker-full',14,25,302),('picker-read',14,1,303),('picker-full',3,0,304)]:
   fields=call(name,op,mask,nonce);assert fields[0]==0 and fields[1]==nonce
   expected=LABELS[127 if op==3 else mask]
   def displayed():
    frame=ui.frame()
    return frame if rendered_text(frame,12,10,len(TITLE))==TITLE and rendered_text(frame,12,50,len(expected))==expected else None
   frame=wait(displayed,'exact trusted picker label');(out/(name+'-'+str(nonce)+'.ppm')).write_bytes(frame.ppm())
   pending=call(name,4,nonce=nonce);assert pending[:3]==(0,0,1)
   other='picker-read' if name=='picker-full' else 'picker-full'
   assert call(other,4,nonce=nonce)[0]==1 and call(name,4,nonce=nonce+10000)[0]==1
   ui.press(1)
   result=wait(lambda:(r if (r:=call(name,4,nonce=nonce))[2]==3 else None),'physical Escape cancellation')
   assert result[:3]==(0,0,3) and call(name,4,nonce=nonce)[:3]==result[:3]
   wait(lambda:not title_present(),'cancelled panel dismissed')
   checks.append(dict(check='exact trusted label, caller/nonce isolation and repeatable physical Escape cancellation',caller=name,actual_rights=packages[name]['rights'],operation=op,requested=mask,nonce=nonce,label=expected,frame_sha256=frame.digest,returned_handle=result[1],state=result[2],result='passed'))
  report=dict(schema=1,result='passed',image_sha256=hashlib.sha256(a.image.read_bytes()).hexdigest(),backend='qemu',compositor_instance=compositor,packages=packages,probe_sha256=hashlib.sha256(a.binary.read_bytes()).hexdigest(),checks=checks,scope='public operation14 request masks and cancellation; no root approval/delegation or remote mod acquisition claimed')
  (out/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
 finally:
  if ui:ui.close()
  if c:
   with contextlib.suppress(EOFError,OSError,ValueError):c.request(70)
   c.close()
  if proc and proc.poll() is None:
   try:proc.wait(15)
   except subprocess.TimeoutExpired:os.killpg(proc.pid,signal.SIGTERM);proc.wait(15)
  log.close()

if __name__=='__main__':main()
