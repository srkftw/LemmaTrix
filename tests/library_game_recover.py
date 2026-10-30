"""Continue a retained-save native journey in its already fresh personal guest.

This recovery controller is used after an interrupted test, with its existing
signed catalog and explicitly approved encrypted backing. It supplies fresh
execution/network/read authority and never writes a game state or approval.
"""
import argparse,base64,hashlib,json,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import federation,library_peer,projects,project_vault,releases
from creator_journey import Journey,require,rendered_text
from crate_game import state
from library_journey import appcall,wait
from library_native_resume import Existing,instances,relationship,focus,frame_text


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--base',type=Path,required=True);p.add_argument('--image',type=Path,required=True);p.add_argument('--packages',type=Path,required=True);p.add_argument('--personal-dir',default='restarted');p.add_argument('--archive',type=Path,required=True);p.add_argument('--game',type=Path,required=True);p.add_argument('--public',type=Path,default=ROOT/'build/campaign005/publisher.pub');p.add_argument('--mod',action='store_true');a=p.parse_args();out=a.base.resolve();personal=Existing(out/a.personal_dir,True);registry=Existing(out/'registry');verifier=instances(personal,2175)[0];peer=instances(registry,1025)[0];fid=hashlib.sha256(releases.public_modulus(out/'federation.pub')).digest();report=json.loads((out/'journey.json').read_text());report['recipient_image']=hashlib.sha256(a.image.read_bytes()).hexdigest();info=releases.inspect(a.game.read_bytes());archived=json.loads(a.archive.read_text())
 def passed(label,**facts):
  report['checks'].append(dict(check=label,result='passed',**facts));(out/'journey.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS',label,flush=True)
 with personal.client() as c:
  federation.configure(c,verifier,out/'federation.pub','consumer',allowed_rights=8191);project_vault.unlock(c,(out/'personal.key').read_bytes());inventory=c.request(202,struct.pack('<8Q',202,0,3,0,0,0,0,1));require(struct.unpack_from('<Q',inventory,16)[0]==192,'no explicitly retained game save');saved_sha=inventory[64:96].hex()
  roots=projects.roots(c)
  if roots:
   exact=[r for r in roots if r['head']==archived['selected'][0]['head']];require(len(exact)==1,'unexpected preexisting public graph');root=exact[0]['cap']
  else:root=projects.import_records(c,archived['selected'],[dict(r,payload=base64.b64decode(r['payload'])) for r in archived['nodes']])[0]['cap']
  shell=struct.unpack_from('<Q',c.request(2),4*32)[0];c.objects(27,root,shell,127);c.request(10,bytes.fromhex(info['project_id'])+releases.public_modulus(a.public))
 j=Journey(argparse.Namespace(output=personal.base/'native-actions',public=a.public,image=a.image));j.socket=personal.socket;j.graphics=personal.graphics;j.ui=personal.ui
 libraries=instances(personal,1919)
 if libraries:lib=libraries[0]
 else:
  libinfo,lib=j.trust_stage(a.packages/'library-native.ltrel','library-native');report.setdefault('recipient_packages',[]).append(libinfo)
 with personal.client() as c:c.request(184,struct.pack('<Q',lib));appcall(c,lib,700,data=fid)
 def word(off):
  with personal.client() as c:return struct.unpack_from('<Q',appcall(c,lib,701)[1],off)[0]
 identity,service,_=relationship(registry,personal,out/'registry.service',out/'registry.credential',out/'personal.credential',0)
 with registry.client() as c:library_peer.call(c,peer,402,0);library_peer.call(c,peer,400,0,1,1,0,16777216,100000,identity+service+fid)
 personal.ui.press(59);personal.ui.press(16);wait(lambda:word(16)==1,300,'fresh signed Game catalog');personal.ui.press(62);personal.ui.press(23);wait(lambda:frame_text(personal,32,107,'crate-workshop-1'),120,'native selected game Project');personal.ui.press(28);wait(lambda:frame_text(personal,16,12,'SIGNED P'),300,'fresh signed Game execution approval');personal.ui.press(28);game=wait(lambda:(instances(personal,795) or [None])[0],180,'fresh actual native game');focus(personal,'Library');personal.ui.press(36);wait(lambda:word(168)==game,60,'exact executable game binding')
 def played():
  with personal.client() as c:return state(c,game)
 require(played()['won']==0 and played()['moves']==0,'fresh game silently inherited progress');personal.ui.press(49);wait(lambda:frame_text(personal,16,16,'TRUSTED'),300,'native selected-save recovery approval');(out/'save-recovery-approval.ppm').write_bytes(personal.ui.frame().ppm());personal.ui.press(28);wait(lambda:frame_text(personal,12,58,'LEMMA LIBRARY'),300,'recovery mutation completed and panel dismissed');wait(lambda:word(176)==61,300,'fresh scoped selected save recovery');personal.ui.press(38);wait(lambda:played()['won']==1 and played()['moves']==2,120,'native L compatible save load');focus(personal,'Game');(out/'recovered-native-game.ppm').write_bytes(personal.ui.frame().ppm());passed('fresh Library N/Enter/L and fresh execution approval recover exact compatible progress',state=played(),save_sha256=saved_sha,stale_capabilities_reused=False,network_session_reauthenticated=True,resumed_after_controller_lock_error=True)
 if a.mod:
  focus(personal,'Library');personal.ui.press(50);wait(lambda:frame_text(personal,32,107,'crate-workshop-1'),120,'M selected Project');personal.ui.press(28);wait(lambda:frame_text(personal,16,176,'assets/near-goal.ltlevels'),120,'actual Source data choice');personal.ui.press(28);expected=hashlib.sha256((ROOT/'resources/crate-workshop/near-goal.ltlevels').read_bytes()).hexdigest();wait(lambda:played()['pack']==expected,120,'M scoped Source handoff');focus(personal,'Game');personal.ui.press(32);wait(lambda:played()['won']==1,60,'actual one-push mod win');require(played()['moves']==1,'mod did not change actual target');focus(personal,'Library');personal.ui.press(38);wait(lambda:word(176)==42,60,'incompatible retained pack explicitly refused');require(played()['pack']==expected and played()['moves']==1,'incompatible save destroyed mod state');focus(personal,'Game');personal.ui.press(50);focus(personal,'Library');personal.ui.press(38);wait(lambda:played()['won']==1 and played()['moves']==2,60,'original pack restores prior compatible save');passed('native Library M selected Source mod changes gameplay and incompatible saved pack remains recoverable',mod_sha256=expected,modified_win_moves=1,prior_save_recovered_moves=2,arbitrary_execution_authority=False)
 personal.stop();registry.stop()

if __name__=='__main__':main()
