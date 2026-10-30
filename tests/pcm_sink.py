"""Bounded host raw-PCM adapter checks; no guest, media decoder or audio device.

Real stub subprocesses consume exact bytes, exit unexpectedly, or refuse input.
This verifies PipeWire argv selection and error/cleanup rather than audibility.
"""
import hashlib,json,socket,struct,sys,tempfile,time
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import pcm

def wait(check,seconds=3):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  if check():return
  time.sleep(.01)
 raise TimeoutError('bounded raw adapter check')
def script(path,body):
 path.write_text('#!'+sys.executable+'\n'+body);path.chmod(0o700)
 return str(path)
def fallback(executable):
 return patch.object(pcm.shutil,'which',side_effect=lambda name:executable if name=='pw-cat' else None)
def run():
 checks=[]
 with tempfile.TemporaryDirectory(prefix='lt-pcm-adapter-') as tmp:
  base=Path(tmp);executable=base/'pw-cat';received=base/'received';args=base/'args.json'
  with patch.object(pcm.shutil,'which',side_effect=lambda name:'/selected/'+name):assert pcm.playback_command()[0]=='/selected/aplay'
  with patch.object(pcm.shutil,'which',return_value=None):
   try:pcm.PCMSink(play=True)
   except ValueError:pass
   else:raise AssertionError('missing executables accepted')
  script(executable,'import json,sys\nfrom pathlib import Path\nPath('+repr(str(args))+').write_text(json.dumps(sys.argv[1:]))\nwith open('+repr(str(received))+',"wb",buffering=0) as out:\n while True:\n  raw=sys.stdin.buffer.read(4096)\n  if not raw:break\n  out.write(raw)\n')
  with fallback(str(executable)),patch.object(pcm.sys,'byteorder','big'):
   try:pcm.playback_command()
   except ValueError:pass
   else:raise AssertionError('native-endian s16 accepted on big-endian host')
  raw=struct.pack('<hh',-12345,23456)*4096
  with fallback(str(executable)):sink=pcm.PCMSink(play=True)
  try:
   sink.start();sink.guest.settimeout(2);sink.guest.sendall(raw)
   wait(lambda:received.exists() and received.stat().st_size==len(raw))
   assert received.read_bytes()==raw
   assert json.loads(args.read_text())==['--playback','--raw','--format','s16','--rate','48000','--channels','2','--channel-map','stereo','-']
  finally:sink.close()
  assert sink.returncode==0 and sink.error is None and not sink.thread.is_alive() and not sink.watcher.is_alive()
  checks.append(dict(check='aplay preferred;pw-cat fallback receives exact raw S16LE bytes;missing backend and big-endian fallback reject',bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),result='passed'))
  for code in (23,0):
   script(executable,'import sys\nsys.exit('+str(code)+')\n')
   with fallback(str(executable)):sink=pcm.PCMSink(play=True)
   try:
    sink.start();wait(lambda:sink.error is not None);sink.guest.settimeout(1)
    try:sink.guest.sendall(raw[:4])
    except OSError:pass
    else:raise AssertionError('dead sink kept accepting samples')
   finally:sink.close()
   assert sink.returncode==code and not sink.thread.is_alive() and not sink.watcher.is_alive()
   checks.append(dict(check='unexpected child exit closes transport and remains inspectable',exit_status=code,error=str(sink.error),result='passed'))
  ready=base/'ready'
  script(executable,'import signal,time\nfrom pathlib import Path\nsignal.signal(signal.SIGTERM,signal.SIG_IGN)\nPath('+repr(str(ready))+').touch()\nwhile True:time.sleep(1)\n')
  with fallback(str(executable)):sink=pcm.PCMSink(play=True)
  try:
   sink.start();wait(ready.exists);sink.guest.settimeout(.25);sent=0;backpressure=False
   for _ in range(128):
    try:sent+=sink.guest.send(raw[:4096])
    except socket.timeout:backpressure=True;break
   assert backpressure,'unreading sink admitted unbounded sample queue'
   started=time.monotonic()
  finally:sink.close()
  seconds=time.monotonic()-started
  assert seconds<8 and sink.returncode==-9 and not sink.thread.is_alive() and not sink.watcher.is_alive()
  checks.append(dict(check='unreading TERM-resistant child backpressures and bounded cleanup kills/reaps it',bytes_accepted_before_backpressure=sent,cleanup_seconds=seconds,result='passed'))
 return dict(schema=1,result='passed',scope='host adapter with real stub subprocesses only',checks=checks,speaker_output_exercised=False,guest_execution=False,pcm_or_wav_decoding=False)
if __name__=='__main__':print(json.dumps(run(),indent=2))
