"""Actual Library.retainGameSave failure paths retire temporary Compositor scopes.

A Lean fixture imports the real Library function and initializes its own private
selected save row. Invalid objects and a busy trusted picker are deliberate
negative inputs, not native Game/save/admission or vault-retention positives.
"""
import argparse,contextlib,hashlib,json,os,signal,struct,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import live,nodes,releases
from creator_journey import rendered_text
from graphical_devices import DeviceInput
from library_journey import wait


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,required=True);p.add_argument('--binary',type=Path,required=True)
 p.add_argument('--key',type=Path,default=ROOT/'build/campaign005/publisher.pem');p.add_argument('--public',type=Path,default=ROOT/'build/campaign005/publisher.pub');p.add_argument('--output',type=Path,required=True)
 a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);sock=out/'portal.sock';graphics=out/'display.qmp';log=(out/'guest.log').open('wb');client=None;proc=None;ui=None;checks=[]
 try:
  raw,_=releases.make(a.binary,'library-save-failure-probe','1.0.0',1919,a.key,profile=2,license='NOASSERTION');path=out/'library-save-failure-probe.ltrel';path.write_bytes(raw);info=releases.inspect(raw,releases.public_modulus(a.public))
  command=list(map(str,[ROOT/'lt','run','--backend','qemu','--image',a.image,'--socket',sock,'--graphics',graphics]));proc=subprocess.Popen(command,cwd=ROOT,stdout=log,stderr=log,start_new_session=True)
  wait(sock.exists,90,'guest boot');client=live.Client(sock,timeout=180);ui=DeviceInput('qemu',graphics)
  instance=nodes.start_package(client,nodes.approved_package(path,a.public,info['release_id'],1919),raw);client.request(184,struct.pack('<Q',instance))
  rows=client.request(2);actual=[struct.unpack_from('<4Q',rows,i) for i in range(0,len(rows),32) if struct.unpack_from('<Q',rows,i)[0]==instance]
  assert len(actual)==1 and 0<actual[0][1]<5 and actual[0][2]==1919
  def call(op,value=0):
   raw=client.request(150,struct.pack('<Q8Q',instance,op,value,0,0,0,0,0,1));assert len(raw)==64
   return struct.unpack('<8Q',raw)
  def capacity():
   r=call(921);assert r[0]==0 and r[2]==4 and 0<r[1]<=32,r
   return r[1]
  invalid=call(920,191);assert invalid[0]==0 and invalid[1]==191
  before_invalid=capacity();invalid_result=call(922,40);assert invalid_result[:4]==(0,40,42,0),invalid_result
  after_invalid=capacity();assert before_invalid==after_invalid==32,'malformed-length retain attempts leaked Compositor Object scopes'
  checks.append(dict(check='actual Library retainGameSave rejects191-byte selected Object before sharing;40 calls leave all32 Compositor capability slots available',result='passed',bytes=191,calls=40,expected_notice=42,pending_approval=invalid_result[3],available_before=before_invalid,available_after=after_invalid))
  proper_length=call(920,192);assert proper_length[0]==0 and proper_length[1]==192
  before_busy=capacity();nonce=7300001;opened=call(923,nonce);assert opened[:2]==(0,nonce)
  title='TRUSTED PROJECT OPEN / SELECT A NAMED PROJECT';label='ACCESS: READ ONLY / NO EDIT OR PUBLISH AUTHORITY'
  def picker():
   frame=ui.frame()
   return frame if rendered_text(frame,12,10,len(title))==title and rendered_text(frame,12,50,len(label))==label else None
  frame=wait(picker,30,'actual read-only trusted picker');(out/'busy-trusted-picker.ppm').write_bytes(frame.ppm());assert call(924,nonce)[:3]==(0,0,1)
  busy_result=call(922,40);assert busy_result[:4]==(0,40,21,0),busy_result
  after_busy=capacity();assert before_busy==after_busy==32,'busy-portal retain attempts leaked Compositor Object scopes'
  assert call(924,nonce)[:3]==(0,0,1),'rejected save retention replaced the original trusted picker'
  ui.press(1);cancelled=wait(lambda:(r if (r:=call(924,nonce))[2]==3 else None),30,'physical Escape picker cancellation');assert cancelled[:3]==(0,0,3)
  checks.append(dict(check='actual Library retainGameSave revokes each newly shared Compositor scope after portal11 busy rejection;40 calls preserve original picker and all32 target slots',result='passed',bytes=192,calls=40,expected_notice=21,pending_approval=busy_result[3],available_before=before_busy,available_after=after_busy,picker_nonce=nonce,picker_state_during_rejection=1,physical_escape_state=cancelled[2],trusted_label=label,frame_sha256=frame.digest))
  report=dict(schema=1,result='passed',backend='qemu',image_sha256=hashlib.sha256(a.image.read_bytes()).hexdigest(),library_source_sha256=hashlib.sha256((ROOT/'Guest/Library.lean').read_bytes()).hexdigest(),probe_sha256=hashlib.sha256(a.binary.read_bytes()).hexdigest(),probe_release=info['release_id'],probe_instance=instance,actual_rights=1919,command=command,checks=checks,method='ordinary signed Lean fixture imports and invokes Guest.Library.retainGameSave; own private selected row and Objects; public Objects.share/revoke quota calibration exposes no Compositor private state',limitations=['negative function regression, not a native Library save UI, Game execution, consumer admission or encrypted retention positive','192-byte object is deliberately dummy zero bytes; open trusted picker rejects portal11 before typed-save parsing','temporary target grants are stored privately in the Lean fixture and all calibration grants are revoked; no host guest-memory writes','single QEMU image execution only; no new audio, network or physical-vault evidence'])
  (out/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
 finally:
  if ui:ui.close()
  if client:
   with contextlib.suppress(EOFError,OSError,ValueError):client.request(70)
   client.close()
  if proc and proc.poll() is None:
   try:proc.wait(20)
   except subprocess.TimeoutExpired:os.killpg(proc.pid,signal.SIGTERM);proc.wait(10)
  log.close()


if __name__=='__main__':main()
