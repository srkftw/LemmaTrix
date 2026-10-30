"""Actual guest PCM descriptor backpressure against a deliberately blocked raw sink."""
import argparse,hashlib,json,os,signal,struct,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools')]
import live,nodes,releases
ERROR=(1<<64)-1

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--backend',choices=('qemu','x86_64','aarch64'),default='qemu')
 p.add_argument('--image',type=Path,required=True);p.add_argument('--package',type=Path,required=True)
 p.add_argument('--public',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
 a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
 adapter=out/'adapter';adapter.mkdir();release=out/'release-sink';consumed=out/'consumed.pcm'
 # This is an explicitly identified test raw sink, not an audio decoder or a
 # claim of physical speaker output. It stops reading until the test releases
 # it, forcing the existing bounded pipe/socket/device queues to fill.
 stub=adapter/'aplay';stub.write_text('#!'+sys.executable+'\n'+
  'import os,pathlib,sys,time\n'+
  'release=pathlib.Path('+repr(str(release))+')\n'+
  'deadline=time.monotonic()+600\n'+
  'while not release.exists():\n'+
  ' if time.monotonic()>deadline:sys.exit(23)\n'+
  ' time.sleep(.01)\n'+
  'with open('+repr(str(consumed))+',"xb",buffering=0) as f:\n'+
  ' while True:\n'+
  '  b=os.read(sys.stdin.fileno(),4096)\n'+
  '  if not b:break\n'+
  '  f.write(b)\n');stub.chmod(0o700)
 sock=out/'portal.sock';capture=out/'samples.pcm';log=(out/'guest.log').open('wb');proc=None;c=None
 def wait(test,label,seconds=30):
  deadline=time.monotonic()+seconds
  while time.monotonic()<deadline:
   value=test()
   if value:return value
   time.sleep(.02)
  raise TimeoutError(label)
 try:
  env=dict(os.environ,PATH=str(adapter)+os.pathsep+os.environ.get('PATH',''))
  proc=subprocess.Popen(list(map(str,[ROOT/'lt','run','--backend',a.backend,'--image',a.image,'--socket',sock,'--pcm-sink',capture,'--pcm-play'])),cwd=ROOT,env=env,stdout=log,stderr=log,start_new_session=True)
  wait(sock.exists,'boot',320);c=live.Client(sock,timeout=240)
  raw=a.package.read_bytes();info=releases.inspect(raw,releases.public_modulus(a.public))
  assert info['rights']==4096
  instance=nodes.start_package(c,nodes.approved_package(a.package,a.public,info['release_id'],4096),raw)
  def call(op,h=0,n=0):
   reply=c.request(150,struct.pack('<Q8Q',instance,op,h,n,0,0,0,0,1));return struct.unpack_from('<8Q',reply)[1]
  epoch=call(810);assert epoch!=ERROR
  accepted=0;deadline=time.monotonic()+90;blocked=False;start=time.monotonic()
  while time.monotonic()<deadline and accepted<256*1024:
   count=call(811,epoch,1024)
   if count==0:
    blocked=True;break
   assert count==1024,count;accepted+=count
  assert blocked,'bounded sink did not apply descriptor backpressure'
  before=call(813,epoch);assert before!=ERROR and before&1==0
  assert call(811,epoch,1024)==0 and call(813,epoch)==before
  def ready():
   value=call(813,epoch);assert value!=ERROR
   return value&1==1
  release.touch();wait(ready,'descriptor resumed after sink became writable')
  wait(lambda:capture.stat().st_size==accepted,'all accepted samples delivered')
  wait(lambda:consumed.exists() and consumed.stat().st_size==accepted,'raw child consumed all samples')
  assert call(812,epoch)!=ERROR and call(811,epoch,1024)==ERROR
  expected=struct.pack('<I',0x33441122)*(accepted//4)
  assert capture.read_bytes()==expected
  c.close();c=None;os.killpg(proc.pid,signal.SIGTERM);proc.wait(15)
  assert consumed.read_bytes()==expected
  result=dict(result='passed',backend=a.backend,image_sha256=hashlib.sha256(a.image.read_bytes()).hexdigest(),release=info['release_id'],accepted_bytes=accepted,sample_sha256=hashlib.sha256(expected).hexdigest(),seconds=time.monotonic()-start,checks=['bounded raw sink filled','guest write returned zero without consuming a second descriptor','native inspection remained responsive under backpressure','descriptor resumed after sink release','every accepted byte captured and consumed exactly once','stop invalidated epoch'],speaker_output=False)
  (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
 finally:
  release.touch()
  if c:c.close()
  if proc and proc.poll() is None:os.killpg(proc.pid,signal.SIGTERM);proc.wait(15)
  log.close()

if __name__=='__main__':main()
