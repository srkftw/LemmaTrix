"""Fresh native recovery/playback from an existing explicitly retained vault.

No registry, provider, host media input or recipient network relationship is
started. Only signed app packages and the user's selected encrypted backing/key
are supplied. This never creates or copies a retained payload.
"""
import argparse, hashlib, json, struct, sys, time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import content, project_vault, releases
from creator_journey import Journey, require, rendered_text
from library_game_save import Guest, preserve_failure
from library_journey import appcall, wait

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('image','vault','vault-key','federation-public','library','player','public','output'):
  p.add_argument('--'+name,type=Path,required=True)
 p.add_argument('--seconds',type=int,required=True)
 a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
 guest=Guest('personal',out,a.image.resolve(),a.vault.resolve())
 image_id=hashlib.sha256(a.image.read_bytes()).hexdigest()
 records=[]
 try:
  j=Journey(argparse.Namespace(output=out/'native-actions',public=a.public,image=a.image))
  j.socket=guest.socket;j.graphics=guest.graphics;j.ui=guest.ui;j.image=image_id
  for package,name in ((a.player,'native-player'),(a.library,'library-native')):
   info,instance=j.trust_stage(package,name)
   records.append(dict(release_id=info['release_id'],rights=info['rights'],instance=instance))
   if name=='native-player':player=instance
   else:lib=instance
  with guest.client() as c:
   c.request(184,struct.pack('<Q',lib))
   project_vault.unlock(c,a.vault_key.read_bytes())
   fid=hashlib.sha256(releases.public_modulus(a.federation_public)).digest()
   appcall(c,lib,700,data=fid)
   require(struct.unpack_from('<Q',appcall(c,lib,701)[1],16)[0]==0,'collection recovered without selection approval')
  def word(offset):
   with guest.client() as c:return struct.unpack_from('<Q',appcall(c,lib,701)[1],offset)[0]
  guest.ui.press(22)
  wait(lambda:rendered_text(guest.ui.frame(),16,16,7)=='TRUSTED',300,'native recovery approval')
  (out/'approval.ppm').write_bytes(guest.ui.frame().ppm());guest.ui.press(28)
  wait(lambda:rendered_text(guest.ui.frame(),12,58,13)=='LEMMA LIBRARY',300,'recovery approval dismissed')
  wait(lambda:word(16)==1 and word(176)==17,1200,'native selected encrypted recovery')
  with guest.client() as c:
   _,row=appcall(c,lib,703,0,0,128)
   require(struct.unpack_from('<Q',row,24)[0]==3 and struct.unpack_from('<Q',row,48)[0]==1,'retained row unavailable')
   require(struct.unpack_from('<Q',appcall(c,lib,701)[1],96)[0]==0,'recovery resurrected acquisition policy')
  guest.ui.press(35)
  wait(lambda:rendered_text(guest.ui.frame(),12,58,13)=='LEMMA LIBRARY',120,'Library focus after attach selection')
  guest.ui.press(57)
  def state():
   with guest.client() as c:return appcall(c,player,601)[0]
  wait(lambda:state()[2]==1,300,'actual retained range capability attached to Player')
  for _ in range(5):
   old=rendered_text(guest.ui.frame(),520,34,16)
   if old==f'{player:016x}':break
   guest.ui.chord(56,15)
   wait(lambda:rendered_text(guest.ui.frame(),520,34,16)!=old,60,'native focus changed')
  require(rendered_text(guest.ui.frame(),520,34,16)==f'{player:016x}','actual Player not focused')
  began=time.monotonic();guest.ui.press(57)
  wait(lambda:state()[2]==5,600,'offline native decoded PCM complete')
  elapsed=time.monotonic()-began;actual=guest.capture.read_bytes()
  # Expected original composition is constructed only after playback; it is
  # not an input supplied to the guest or the sample adapter.
  require(actual==content.original_wave(a.seconds,2)[44:],'actual offline PCM differs from original retained composition')
  (out/'playback.ppm').write_bytes(guest.ui.frame().ppm())
  report=dict(result='passed',image=image_id,packages=records,retained_backing=str(a.vault.resolve()),native_actions='U / physical Enter / H / Space / Alt-Tab / Space',network_configured=False,providers_started=False,media_input_supplied=False,acquisition_authority_recovered=False,pcm_bytes=len(actual),pcm_sha256=hashlib.sha256(actual).hexdigest(),seconds_to_submit_samples=elapsed,speaker_output=False)
  (out/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2),flush=True)
 except BaseException as error:
  preserve_failure([guest],out,error);raise
 finally:guest.stop()

if __name__=='__main__':main()
