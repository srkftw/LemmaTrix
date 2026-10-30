"""Actual PCM capability, process ownership, epoch, alignment and death checks."""
import argparse,contextlib,hashlib,json,os,signal,struct,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools')]
import live,nodes,releases
ERROR=(1<<64)-1

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--backend',choices=('qemu','x86_64','aarch64'),default='qemu');p.add_argument('--image',type=Path,default=ROOT/'build/live/guest.bin');p.add_argument('--binary',type=Path,default=ROOT/'build/live/apps/audio-probe.bin');p.add_argument('--key',type=Path,default=ROOT/'build/campaign005/publisher.pem');p.add_argument('--public',type=Path,default=ROOT/'build/campaign005/publisher.pub');p.add_argument('--packages',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);sock=out/'portal.sock';capture=out/'samples.pcm';log=(out/'guest.log').open('wb');proc=None
 def wait(test,label):
  end=time.monotonic()+320
  while time.monotonic()<end:
   value=test()
   if value:return value
   time.sleep(.05)
  raise TimeoutError(label)
 try:
  proc=subprocess.Popen(list(map(str,[ROOT/'lt','run','--backend',a.backend,'--image',a.image,'--socket',sock,'--pcm-sink',capture])),cwd=ROOT,stdout=log,stderr=log,start_new_session=True);wait(sock.exists,'boot')
  c=live.Client(sock,timeout=240);ids={}
  packages=a.packages or out
  packages.mkdir(parents=True,exist_ok=True)
  for name,rights in [('audio-owner',4096),('audio-none',0),('audio-other',4096)]:
   path=packages/(name+'.ltrel')
   if not path.exists():
    raw,_=releases.make(a.binary,name,'1.0.0',rights,a.key,profile=2,license='NOASSERTION');path.write_bytes(raw)
   raw=path.read_bytes();info=releases.inspect(raw,releases.public_modulus(a.public));assert info['rights']==rights and raw[768:]==a.binary.read_bytes()
   ids[name]=dict(instance=nodes.start_package(c,nodes.approved_package(path,a.public,info['release_id'],rights),raw),release=info['release_id'])
  # A correctly re-signed publisher envelope with unknown bit8192 must fail
  # in the actual guest decoder, independently of the host writer's checks.
  unknown=packages/'unknown-audio-right.ltrel'
  if not unknown.exists():
   raw=(packages/'audio-owner.ltrel').read_bytes();header=bytearray(raw[:512]);struct.pack_into('<Q',header,64,8192);header[160:192]=bytes(32);header[160:192]=hashlib.sha256(header).digest();source=out/'unknown-header';source.write_bytes(header)
   signature=releases.pkg.crypto(['dgst','-sha256','-sign',a.key,source]).stdout;unknown.write_bytes(header+signature+raw[768:])
  bad=unknown.read_bytes();c.request(20,struct.pack('<Q',len(bad)))
  for offset in range(0,len(bad),512):c.request(21,struct.pack('<Q',offset)+bad[offset:offset+512])
  try:c.request(22)
  except ValueError as error:assert 'guest rejected command22' in str(error)
  else:raise AssertionError('guest admitted unknown audio right8192')
  def call(name,op,h=0,n=0):
   raw=c.request(150,struct.pack('<Q8Q',ids[name]['instance'],op,h,n,0,0,0,0,1));return struct.unpack_from('<8Q',raw)[1]
  assert call('audio-none',810)==ERROR
  epoch=call('audio-owner',810);assert epoch!=ERROR
  assert call('audio-other',810)==ERROR and call('audio-other',811,epoch,1024)==ERROR
  assert call('audio-none',811,epoch,1024)==ERROR
  for n in (0,2,1028):assert call('audio-owner',811,epoch,n)==ERROR
  assert call('audio-owner',814,epoch,4)==ERROR
  assert call('audio-owner',811,epoch,1024)==1024
  wait(lambda:capture.stat().st_size==1024,'actual first descriptor')
  assert call('audio-owner',812,epoch)!=ERROR
  assert call('audio-owner',811,epoch,1024)==ERROR and call('audio-owner',813,epoch)==ERROR
  fresh=call('audio-other',810);assert fresh!=ERROR and fresh!=epoch
  assert call('audio-owner',811,fresh,1024)==ERROR
  assert call('audio-other',811,fresh,1024)==1024
  wait(lambda:capture.stat().st_size==2048,'actual second descriptor')
  call('audio-other',815)
  end=time.monotonic()+120
  while True:
   final=call('audio-owner',810)
   if final!=ERROR:break
   if time.monotonic()>end:raise TimeoutError('process death did not release output')
   time.sleep(.05)
  assert final!=fresh and call('audio-owner',813,final)==1
  expected=struct.pack('<I',0x33441122)*512;assert capture.read_bytes()==expected
  call('audio-owner',812,final);c.close()
  report=dict(result='passed',backend=a.backend,image=hashlib.sha256(a.image.read_bytes()).hexdigest(),packages=ids,bytes=2048,sample_sha256=hashlib.sha256(expected).hexdigest(),checks=['correctly signed unknown right8192 denied by guest decoder','missing audio right denied','cross-process ownership denied','unaligned zero oversized and unmapped writes denied','actual PCM device descriptors captured','stop invalidates epoch','process death releases ownership and clears accepted counter','no queued samples inherited'],speaker_output=False)
  (out/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
 finally:
  if proc and proc.poll() is None:os.killpg(proc.pid,signal.SIGTERM);proc.wait(15)
  log.close()
if __name__=='__main__':main()
