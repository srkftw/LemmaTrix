"""Finish native offline playback on an already approved/recovered live guest."""
import argparse,hashlib,json,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import content
from library_native_resume import Existing,instances
from library_journey import appcall,wait
from creator_journey import require,rendered_text

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--base',type=Path,required=True);p.add_argument('--seconds',type=int,required=True);a=p.parse_args();out=a.base.resolve();personal=Existing(out/'off',True);lib=instances(personal,1919)[0];player=instances(personal,4865)[0];report=json.loads((out/'journey.json').read_text());wave=content.original_wave(a.seconds,2)
 def focus(target,title,x,y):
  for _ in range(5):
   old=rendered_text(personal.ui.frame(),520,34,16)
   if old==f'{target:016x}':wait(lambda:rendered_text(personal.ui.frame(),x,y,len(title))==title,60,'actual focused surface repaint');return
   personal.ui.chord(56,15);wait(lambda:rendered_text(personal.ui.frame(),520,34,16)!=old,60,'native focus changed')
  raise AssertionError('focused native target missing')
 def player_state():
  with personal.client() as c:return appcall(c,player,601)[0]
 try:
  with personal.client() as c:
   f,row=appcall(c,lib,703,0,0,64);require(struct.unpack_from('<Q',row,24)[0]==3 and struct.unpack_from('<Q',row,48)[0]==1,'selected row is not native recovered retained content');inv=c.request(241,struct.pack('<8Q',241,0,3,0,0,0,0,1));require(struct.unpack_from('<Q',inv,16)[0]==4,'selected recovery incomplete')
  focus(lib,'LEMMA LIBRARY',12,58);personal.ui.press(57);wait(lambda:player_state()[2]==1,300,'actual selected content attached to native Player');
  for _ in range(5):
   old=rendered_text(personal.ui.frame(),520,34,16)
   if old==f'{player:016x}':break
   personal.ui.chord(56,15);wait(lambda:rendered_text(personal.ui.frame(),520,34,16)!=old,60,'native player focus changed')
  require(rendered_text(personal.ui.frame(),520,34,16)==f'{player:016x}','actual native Player not focused');personal.ui.press(57);wait(lambda:player_state()[2]==5,1800,'actual offline guest PCM ended');actual=personal.capture.read_bytes();require(actual==wave[44:],'retained offline decoded PCM differs');(out/'offline-playback.ppm').write_bytes(personal.ui.frame().ppm());report['checks'].append(dict(check='fresh U/Enter recovers selected collection/content; offline native player emits exact retained PCM',result='passed',network_providers_running=False,recipient_network_configured=False,pcm_bytes=len(actual),pcm_sha256=hashlib.sha256(actual).hexdigest(),speaker_output=False,playback_actions_waited_for_native_attach=True));(out/'journey.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS offline exactPCM',len(actual),hashlib.sha256(actual).hexdigest(),flush=True);personal.stop()
 finally:
  if personal.ui:personal.ui.close()
if __name__=='__main__':main()
