"""Continue an owned native media job without resetting or preloading its state."""
import argparse,hashlib,json,struct,sys,time,traceback
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import content,project_vault,releases
from creator_journey import Journey,require,rendered_text
from library_game_save import Guest
from library_native_resume import Existing,instances
from library_journey import appcall,wait
from native_responsive import NativeResponsive

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--base',type=Path,required=True);p.add_argument('--packages',type=Path,required=True);p.add_argument('--seconds',type=int,default=6);a=p.parse_args();out=a.base.resolve();packages=a.packages.resolve();image=out/'platform.bin';image_id=hashlib.sha256(image.read_bytes()).hexdigest();public=ROOT/'build/campaign005/publisher.pub';wave=content.original_wave(a.seconds,2);manifest,_,_=content.commitments(wave);rootsha=hashlib.sha256(manifest).hexdigest();personal=Existing(out/'personal',True);registry=Existing(out/'registry');seed=Existing(out/'seed');lib=instances(personal,1919)[0];game=instances(personal,795)[0];player=instances(personal,4865)[0];responsive=NativeResponsive(personal,game,lib);fid=hashlib.sha256(releases.public_modulus(out/'federation.pub')).digest();report={'image':image_id,'packages_directory':str(packages.relative_to(ROOT)),'checks':[],'limitations':['explicit development backing; no physical-vault durability claim','captured decoded PCM; speaker output not exercised','continuation reuses a live authorized acquisition after a test focus timeout']}
 def passed(label,**facts):
  report['checks'].append(dict(check=label,result='passed',**facts));(out/'journey.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS',label,flush=True)
 def word(offset):
  with personal.client() as c:return struct.unpack_from('<Q',appcall(c,lib,701)[1],offset)[0]
 def job_state():
  with personal.client() as c:return struct.unpack_from('<Q',appcall(c,lib,704,0,0,8)[1])[0]
 def panel():return rendered_text(personal.ui.frame(),16,16,7)=='TRUSTED'
 def library_surface():return rendered_text(personal.ui.frame(),520,34,16)==f'{lib:016x}' and rendered_text(personal.ui.frame(),12,58,13)=='LEMMA LIBRARY'
 try:
  hashing=responsive.hashing(1800);responsive.focus_library();passed('native game input and unrelated Objects complete while the same integrity job remains active',**hashing)
  wait(lambda:job_state()==10,1800,'actual acquired media validation');personal.ui.press(19);wait(panel,300,'native selected content retention approval');(out/'content-approval.ppm').write_bytes(personal.ui.frame().ppm());personal.ui.press(28);wait(library_surface,300,'selected retention panel dismissed')
  persistence=responsive.persisting(600);responsive.focus_library();passed('native game input and unrelated Objects complete while selected encrypted persistence remains active',**persistence);wait(lambda:word(176)==17,1800,'native co-committed media retention')
  with personal.client() as c:
   status=c.request(246,struct.pack('<8Q',246,0,3,0,0,0,0,1));generation=struct.unpack_from('<Q',status,8)[0]
  passed('native R/Enter co-retains exact media and signed selection',bytes=len(wave),chunks=(len(wave)+4095)//4096,manifest_sha256=rootsha,generation=generation)
  personal.stop();registry.stop();seed.stop();personal=Guest('off',out,image,out/'personal.vault')
  j=Journey(argparse.Namespace(output=personal.base/'native-actions',public=public,image=image));j.socket=personal.socket;j.graphics=personal.graphics;j.ui=personal.ui;j.image=image_id
  pi,player=j.trust_stage(packages/'native-player.ltrel','native-player');li,lib=j.trust_stage(packages/'library-native.ltrel','library-native');report['offline_packages']=[pi,li]
  with personal.client() as c:project_vault.unlock(c,(out/'personal.key').read_bytes());c.request(184,struct.pack('<Q',lib));appcall(c,lib,700,data=fid)
  require(word(16)==0,'collection silently recovered before native approval');personal.ui.press(22);wait(panel,300,'native selected content recovery approval');(out/'recovery-approval.ppm').write_bytes(personal.ui.frame().ppm());personal.ui.press(28);wait(library_surface,300,'selected recovery panel dismissed');wait(lambda:word(16)==1 and word(176)==17,1800,'native U/Enter co-recovery');personal.ui.press(35);personal.ui.press(57)
  def loaded():
   with personal.client() as c:return appcall(c,player,601)[0][2]==1
  wait(loaded,300,'actual selected content attached to native Player')
  for _ in range(5):
   current=rendered_text(personal.ui.frame(),520,34,16)
   if current==f'{player:016x}':break
   personal.ui.chord(56,15);wait(lambda:rendered_text(personal.ui.frame(),520,34,16)!=current,60,'native player focus change')
  require(rendered_text(personal.ui.frame(),520,34,16)==f'{player:016x}','actual trusted player focus not selected');personal.ui.press(57)
  def ended():
   with personal.client() as c:return appcall(c,player,601)[0][2]==5
  wait(ended,1800,'actual offline guest decoded PCM');actual=personal.capture.read_bytes();require(actual==wave[44:],'retained decoded PCM differs from original selected bytes');(out/'offline-playback.ppm').write_bytes(personal.ui.frame().ppm());passed('fresh U/Enter recovers selected collection/content; offline native player emits exact retained PCM',network_providers_running=False,recipient_network_configured=False,pcm_bytes=len(actual),pcm_sha256=hashlib.sha256(actual).hexdigest(),speaker_output=False);personal.stop()
 except BaseException as e:
  print(traceback.format_exc(),flush=True);(out/'continuation-error.txt').write_text(traceback.format_exc());raise
 finally:
  if personal.ui:personal.ui.close()
if __name__=='__main__':main()
