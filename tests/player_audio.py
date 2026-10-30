"""Actual Lean WAV range decoder to PCM1 through native input and sample capture."""
import argparse,hashlib,json,os,struct,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import content,live,releases
from creator_journey import Journey,require
from graphical_devices import DeviceInput

class AudioJourney(Journey):
 def boot(self,vault=False):
  self.capture=self.out/'guest.pcm';self.log=(self.out/'transport.log').open('wb')
  cmd=[ROOT/'lt','run','--backend',self.args.backend,'--image',self.image_path,'--socket',self.socket,'--graphics',self.graphics,'--pcm-sink',self.capture]
  self.proc=subprocess.Popen(list(map(str,cmd)),cwd=ROOT,stdout=self.log,stderr=self.log,start_new_session=True)
  end=time.monotonic()+320
  while not self.socket.exists():
   require(self.proc.poll() is None,'guest exited at boot')
   if time.monotonic()>end:raise TimeoutError('boot readiness')
   time.sleep(.05)
  self.ui=DeviceInput(self.args.backend,self.graphics);time.sleep(.3)

def request(c,instance,op,h=0,a=0,b=0):
 raw=c.request(150,struct.pack('<Q8Q',instance,op,h,a,b,0,0,0,1));return struct.unpack_from('<8Q',raw)

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--player',type=Path,required=True);p.add_argument('--public',type=Path,required=True);p.add_argument('--image',type=Path);p.add_argument('--controls',action='store_true');p.add_argument('--backend',choices=('qemu','x86_64','aarch64'),default='qemu');p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output=a.output.resolve();j=AudioJourney(a)
 try:
  j.boot();info,instance=j.trust_stage(a.player,'native-player');j.wait_text(16,60,'LEMMA PLAYER')
  raw=content.original_wave(1,2)
  # Exercise padded unknown chunks, deliberately misaligning the data position
  # relative to4096 while preserving correct frame alignment within the WAV.
  raw=raw[:12]+b'JUNK'+struct.pack('<I',1)+b'x\0'+raw[12:]
  raw=raw[:4]+struct.pack('<I',len(raw)-8)+raw[8:]
  with j.client() as c:
   root,manifest=content.import_content(c,raw,1001,b'p'*32,b'f'*32)
   cc=content.api(c);grant=cc.objects(308,root,instance)[0][1]
   s=request(c,instance,600,grant,2,48000);require(s[0]==0 and s[2]==1,'native WAV parser rejected valid unknown padded chunk')
  j.ui.press(57);started=time.monotonic()
  while True:
   with j.client() as c:s=request(c,instance,601)
   if s[2]==5:break
   if time.monotonic()-started>600:raise TimeoutError(('native playback',s))
   time.sleep(.1)
  # PCM bytes travelled through the actual guest device descriptor and host
  # sink, not the original WAV file or a host WAV decoder.
  expected=raw[54:];captured=j.capture.read_bytes()
  require(captured==expected,'captured native stereo samples differ from downloaded data')
  j.passed('native stereo WAV decoding, unknown-chunk padding, split range reads and actual PCM output',release=info['release_id'],payload_bytes=len(raw),frames=48000,sample_bytes=len(captured),sample_sha256=hashlib.sha256(captured).hexdigest(),elapsed_seconds=time.monotonic()-started,speaker_output=False,network_attached=False)
  if a.controls:
   from library_journey import wait
   def snapshot():
    with j.client() as c:return request(c,instance,601)
   j.ui.press(105);wait(lambda:snapshot()[2:4]==(3,0),60,'native seek left clamps to beginning')
   j.ui.press(106);wait(lambda:snapshot()[2:4]==(3,48000),60,'native seek right clamps to duration')
   require(j.capture.read_bytes()==captured,'seeking emitted unexpected PCM')
   j.ui.press(105);wait(lambda:snapshot()[3]==0,60,'native seek returns to beginning')
   j.ui.press(57);wait(lambda:(s:=snapshot())[2]==2 and 0<s[3]<48000,60,'actual playback advances before pause')
   j.ui.press(57);paused=wait(lambda:(s if (s:=snapshot())[2]==3 else None),60,'native pause')
   time.sleep(.15);require(snapshot()[3]==paused[3],'paused frame position advanced')
   j.ui.press(57);wait(lambda:snapshot()[2]==5,120,'native resume reaches end')
   require(j.capture.read_bytes()==captured+expected,'pause/resume duplicated or omitted actual samples')
   captured+=expected
   j.ui.press(31);stopped=wait(lambda:(s if (s:=snapshot())[2]==1 and s[3]==0 else None),60,'native stop resets position')
   require(stopped[6]==0,'stopped player retained an output epoch')
   j.passed('native seek bounds, pause/resume byte continuity and stop',paused_frame=paused[3],frames_after_resume=48000,additional_pcm_bytes=len(expected),stopped_output_epoch=stopped[6])
  # Reuse the same process and explicit read scope for mono conversion.
  mono=content.original_wave(1,1)
  with j.client() as c:
   root2,_=content.import_content(c,mono,1002,b'p'*32,b'f'*32)
   grant2=content.api(c).objects(308,root2,instance)[0][1]
   require(request(c,instance,600,grant2,1,48000)[2]==1,'mono WAV rejected')
  j.ui.press(57);until=time.monotonic()+600
  while True:
   with j.client() as c:s=request(c,instance,601)
   if s[2]==5:break
   if time.monotonic()>until:raise TimeoutError(('mono playback',s))
   time.sleep(.1)
  pcm=mono[44:];duplicated=b''.join(pcm[i:i+2]*2 for i in range(0,len(pcm),2))
  require(j.capture.read_bytes()==captured+duplicated,'native mono channel conversion differs')
  j.passed('native mono to stereo sample conversion',source_sample_bytes=len(pcm),output_sample_bytes=len(duplicated),sample_sha256=hashlib.sha256(duplicated).hexdigest())
  with j.client() as c:
   malformed=bytearray(mono);struct.pack_into('<I',malformed,24,44100)
   bad,_=content.import_content(c,bytes(malformed),1003,b'p'*32,b'f'*32)
   h=content.api(c).objects(308,bad,instance)[0][1]
   require(request(c,instance,600,h,1,48000)[2]==6,'unsupported44100Hz accepted')
  j.passed('unsupported sample rate rejected by isolated native parser')
  frame=j.ui.frame();(j.out/'player.ppm').write_bytes(frame.ppm())
  print(json.dumps({'image':j.image,'backend':a.backend,'checks':j.report,'limits':'headless capture measures accepted frames, not real-time speakers'},indent=2))
 finally:j.stop()
if __name__=='__main__':main()
