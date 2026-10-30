"""Representative final-image content and decoded-PCM paths on each backend.

Reuses one pre-signed AudioProbe package. It transports no media file to an
audio decoder and never reads or patches guest memory.
"""
import argparse, contextlib, hashlib, json, os, signal, struct, subprocess, sys, time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import live, nodes, releases
import content_store

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--backend',choices=('qemu','x86_64','aarch64'),required=True)
 p.add_argument('--image',type=Path,required=True)
 p.add_argument('--package',type=Path,required=True)
 p.add_argument('--public',type=Path,required=True)
 p.add_argument('--output',type=Path,required=True)
 p.add_argument('--service-restart',action='store_true')
 p.add_argument('--reference-release',action='store_true')
 a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
 sock=out/'portal.sock';capture=out/'samples.pcm';log=(out/'transport.log').open('wb');proc=None
 try:
  proc=subprocess.Popen(list(map(str,[ROOT/'lt','run','--backend',a.backend,'--image',a.image,'--socket',sock,'--pcm-sink',capture])),stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True)
  until=time.monotonic()+320
  while not sock.exists():
   if proc.poll() is not None:raise RuntimeError('guest exited before readiness')
   if time.monotonic()>until:raise TimeoutError('launcher readiness')
   time.sleep(.05)
  with contextlib.closing(live.Client(sock,timeout=300)) as c:
   checked=content_store.run(c,large=False,tiny=True)
   restarted=None
   if a.service_restart:
    before=c.request(2);old=struct.unpack_from('<Q',before,2*32)[0];vault=struct.unpack_from('<Q',before,3*32)[0]
    payload=b'Objects profile3 data and reply mapping before restart'
    old_handle=c.import_object(payload,2);assert c.read_object(old_handle)==payload
    c.request(32,struct.pack('<Q',old));replacement=struct.unpack_from('<Q',c.request(33,struct.pack('<Q',old)),8)[0]
    assert replacement!=old and replacement&255==2
    fresh=c.import_object(b'fresh service2 mapping and generation',2)
    assert fresh!=old_handle and c.read_object(fresh)==b'fresh service2 mapping and generation'
    try:c.read_object(old_handle)
    except ValueError:pass
    else:raise AssertionError('stale Objects handle resolved after fresh allocation')
    after=c.request(2);assert struct.unpack_from('<Q',after,3*32)[0]==vault and 0<struct.unpack_from('<Q',after,3*32+8)[0]<5
    restarted=dict(previous=old,replacement=replacement,vault_neighbor_live=True,stale_after_fresh_allocation='denied')
   reference_release=None
   if a.reference_release:
    payload=b'committed caller reference through Objects47'
    h=c.import_object(payload,2);assert c.read_object(h)==payload
    released=c.objects(47,h)[0];assert released[0]==0
    replacement_handle=c.import_object(b'fresh generation after last reference',2)
    assert replacement_handle!=h and c.read_object(replacement_handle)==b'fresh generation after last reference'
    try:c.read_object(h)
    except ValueError:pass
    else:raise AssertionError('released reference named a fresh allocation')
    reference_release=dict(status=released[0],stale_after_fresh_allocation='denied',replacement_sha256=hashlib.sha256(c.read_object(replacement_handle)).hexdigest())
   # A Launcher management caller cannot impersonate the trusted compositor
   # even when its request names the Objects domain and guesses an operation.
   denied=c.request(247,struct.pack('<8Q',247,1,3,0,0,0,0,1))
   assert len(denied)==80 and struct.unpack_from('<Q',denied)[0]==1
   raw=a.package.read_bytes();info=releases.inspect(raw,releases.public_modulus(a.public))
   instance=nodes.start_package(c,nodes.approved_package(a.package,a.public,info['release_id'],4096),raw)
   def call(op,h=0,n=0):
    reply=c.request(150,struct.pack('<Q8Q',instance,op,h,n,0,0,0,0,1))
    return struct.unpack_from('<8Q',reply)[1]
   epoch=call(810);assert epoch!=(1<<64)-1
   assert call(811,epoch,1024)==1024
   until=time.monotonic()+60
   while capture.stat().st_size!=1024:
    if time.monotonic()>until:raise TimeoutError('actual PCM descriptor')
    time.sleep(.05)
   assert capture.read_bytes()==struct.pack('<I',0x33441122)*256
   call(812,epoch);assert call(811,epoch,1024)==(1<<64)-1
  report=dict(result='passed',image=hashlib.sha256(a.image.read_bytes()).hexdigest(),backend=a.backend,content=checked,objects_service_restart=restarted,own_reference_release=reference_release,progress247_foreign_caller='denied',audio_release=info['release_id'],pcm_bytes=1024,pcm_sha256=hashlib.sha256(capture.read_bytes()).hexdigest(),speaker_output=False)
  (out/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
 finally:
  if proc and proc.poll() is None:
   os.killpg(proc.pid,signal.SIGTERM)
   try:proc.wait(15)
   except subprocess.TimeoutExpired:os.killpg(proc.pid,signal.SIGKILL);proc.wait()
  log.close()

if __name__=='__main__':main()
