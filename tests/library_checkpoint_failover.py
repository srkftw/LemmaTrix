"""Native partial retention, restart, alternate seed and offline PCM recovery.

Publisher bytes enter two explicit seed guests only. Personal acquisition uses
actual Noise/range protocols and every consent uses native keyboard input.
Verified partial progress is encrypted through the trusted Objects approval,
then a fresh Library policy adopts it from the second independent provider.
"""
import argparse,hashlib,json,os,socket,struct,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import capsule,consumers,content,federation,library_peer,network,nodes,project_vault,releases
from creator_journey import Journey,require,rendered_text
from library_game_save import Guest,preserve_failure
from library_journey import appcall,wait

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,default=ROOT/'build/live/guest.bin');p.add_argument('--library',type=Path,default=ROOT/'build/live/apps/library.bin');p.add_argument('--registry',type=Path,default=ROOT/'build/live/apps/registry.bin');p.add_argument('--peer',type=Path,default=ROOT/'build/live/apps/library-peer.bin');p.add_argument('--player',type=Path,default=ROOT/'build/campaign005/player.ltrel');p.add_argument('--key',type=Path,default=ROOT/'build/campaign005/publisher.pem');p.add_argument('--public',type=Path,default=ROOT/'build/campaign005/publisher.pub');p.add_argument('--keep-running',action='store_true');p.add_argument('--seconds',type=int,default=1);p.add_argument('--output',type=Path,required=True);p.add_argument('--packages',type=Path);p.add_argument('--game',type=Path);a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);image=out/'platform.bin';image.write_bytes(a.image.read_bytes());image_id=hashlib.sha256(image.read_bytes()).hexdigest();guests=[];report=[]
 def passed(label,**facts):
  report.append(dict(check=label,result='passed',**facts));print('PASS',label,flush=True);(out/'journey.json').write_text(json.dumps(dict(image=image_id,checks=report,limitations=['explicit development backing file; no physical-vault durability claim','captured decoded samples; speaker output not exercised']),indent=2)+'\n')
 def package(binary,name,rights):
  raw,_=releases.make(binary,name,'1.0.0',rights,a.key,profile=2,license='NOASSERTION');path=out/(name+'.ltrel');path.write_bytes(raw);return path
 # Freeze the exact bodies once; later rebuilds cannot retarget this run.
 regpkg=a.packages/'library-registry.ltrel' if a.packages else package(a.registry,'retain-registry',2175)
 peerpkg=a.packages/'library-peer.ltrel' if a.packages else package(a.peer,'retain-peer',1025)
 libpkg=a.packages/'library-native.ltrel' if a.packages else package(a.library,'retain-library',1919)
 libname='library-native' if a.packages else 'retain-library'
 def install(node,path):
  raw=path.read_bytes();info=releases.inspect(raw)
  with node.client() as c:return nodes.start_package(c,nodes.approved_package(path,a.public,info['release_id'],info['rights']),raw)
 vault=out/'personal.vault';key=out/'personal.key';subprocess.run([str(ROOT/'lt'),'vault-init',str(vault),'--sectors','60000','--key-out',str(key)],cwd=ROOT,check=True)
 fedkey=out/'federation.pem';fedpub=out/'federation.pub';capsule.generate_key(fedkey,fedpub);fid=hashlib.sha256(releases.public_modulus(fedpub)).digest();identity=hashlib.sha256(os.urandom(32)).digest()
 wave=content.original_wave(a.seconds,2);manifest,_,_=content.commitments(wave);rootsha=hashlib.sha256(manifest).digest();record=consumers.create(key=a.key,project='native-retained-courtyard',collection=content.COLLECTION,item=hashlib.sha256(b'Native retention original Courtyard').digest(),edition=hashlib.sha256(b'approved stereo').digest(),title='Open Courtyard / selected retained stereo',resource=manifest,frames=a.seconds*48000,channels=2,license_id=1)
 try:
  registry=Guest('registry',out,image);seeds=[Guest('seed1',out,image),Guest('seed2',out,image)];personal=Guest('personal',out,image,vault);guests.extend([registry,*seeds,personal]);reg=install(registry,regpkg);regpeer=install(registry,peerpkg);seedpeers=[install(seed,peerpkg) for seed in seeds];verifier=install(personal,regpkg)
  for node,instance in [(registry,reg),(personal,verifier)]:
   with node.client() as c:federation.configure(c,instance,fedpub,'consumer',allowed_rights=8191)
  with registry.client() as c:
   root=consumers.attach(c,record,manifest,name='retained-media-metadata')['root'];federation.call(c,reg,3,data=record[32:64]+releases.public_modulus(a.public));federation.call(c,reg,2,h=c.objects(27,root,reg,25)[0][1]);decision=federation.sign_once(c,reg,fedkey,'consumer',8191);require(decision['listing']==4,'actual signed media admission failed')
  relationships=[]
  for slot,node in enumerate([registry,*seeds]):
   private=out/('provider'+str(slot)+'.pem');public=out/('provider'+str(slot)+'.pub');capsule.generate_key(private,public);probe=socket.socket();probe.bind(('127.0.0.1',0));port=probe.getsockname()[1];probe.close();description=out/('provider'+str(slot)+'.service');details=network.create_description(private,identity,'127.0.0.1:'+str(port),'library-registry' if slot==0 else 'library-seed',description);creds=[out/('client'+str(slot)+'.credential'),out/('server'+str(slot)+'.credential')];network.provision(*creds,identity,bytes.fromhex(details['server_id']),bytes.fromhex(details['service_id']))
   with node.client() as c:
    network.configure(c,creds[1],description,slot=0);wait(lambda:network.call(c,13,slot=0,allow_error=True)[0][0]==0,60,'server listen')
   with personal.client() as c:network.configure(c,creds[0],description,slot=slot)
   relationships.append(dict(details=details,description=description,creds=creds))
  seedhandles=[]
  for index,seed in enumerate(seeds):
   with seed.client() as c:
    h,_=content.import_content(c,wave,7001,bytes.fromhex(relationships[index+1]['details']['server_id']),fid);seedhandles.append(content.api(c).objects(308,h,seedpeers[index])[0][1])
  def approve_apps(node):
   j=Journey(argparse.Namespace(output=node.base/'native-actions',public=a.public,image=a.image));j.socket=node.socket;j.graphics=node.graphics;j.ui=node.ui;j.image=image_id;player_info,player=j.trust_stage(a.player,'native-player');libinfo,lib=j.trust_stage(libpkg,libname)
   with node.client() as c:c.request(184,struct.pack('<Q',lib));project_vault.unlock(c,key.read_bytes());appcall(c,lib,700,data=fid)
   def word(offset):
    with node.client() as c:return struct.unpack_from('<Q',appcall(c,lib,701)[1],offset)[0]
   return j,player,lib,word
  j,player,lib,word=approve_apps(personal);personal.ui.press(60)
  for slot in range(3):
   personal.ui.press(slot+2);personal.ui.press(28)
   def authenticated():
    with personal.client() as c:return network.status(c,slot)['endpoint_authenticated']
   wait(authenticated,300,'native selected provider '+str(slot))
  with registry.client() as c:library_peer.call(c,regpeer,400,0,1,1,0,16777216,100000,identity+bytes.fromhex(relationships[0]['details']['service_id'])+fid)
  for index,seed in enumerate(seeds):
   with seed.client() as c:library_peer.call(c,seedpeers[index],400,0,2,int.from_bytes(rootsha[:8],'little')|1,seedhandles[index],16777216,100000,identity+bytes.fromhex(relationships[index+1]['details']['service_id'])+rootsha)
  personal.ui.press(59);personal.ui.press(16);wait(lambda:word(16)==1,300,'native metadata catalog');personal.ui.press(30)
  def metadata_added():
   with personal.client() as c:
    fields,data=appcall(c,lib,703,0,8,8)
    return len(data)==8 and struct.unpack('<Q',data)[0]!=0
  wait(metadata_added,60,'metadata-only Add retained reference');personal.ui.press(34);wait(lambda:word(208)==1,30,'native bounded acquisition approval');personal.ui.press(28)
  def job_state():
   with personal.client() as c:return struct.unpack_from('<Q',appcall(c,lib,704,0,0,8)[1])[0]
  def job_words():
   with personal.client() as c:return struct.unpack('<16Q',appcall(c,lib,704,0,0,128)[1])
  def some_checked():
   q=job_words()
   if q[0] in (12,13,14):raise RuntimeError(('acquisition failed',q))
   return q[4]>=3 and q[0]<10
  wait(some_checked,600,'three validated chunks');personal.ui.press(25);wait(lambda:job_state()==11,60,'native transfer pause')
  with personal.client() as c:
   q,_=appcall(c,lib,705,0);checkpoint_read=q[1];state=content.api(c).objects(306,checkpoint_read)[0];checked=state[3];require(8192<=checked<len(wave),'transfer did not leave a meaningful partial checkpoint')
  personal.ui.press(19);wait(lambda:word(376)==1,60,'native checkpoint approval request');wait(lambda:rendered_text(personal.ui.frame(),16,16,7)=='TRUSTED',300,'trusted partial checkpoint approval');personal.ui.press(28);wait(lambda:word(376)==0 and word(176)==17,1200,'native encrypted partial checkpoint commit')
  with personal.client() as c:
   inventory=c.request(246,struct.pack('<8Q',246,0,3,0,0,0,0,1));fields=struct.unpack_from('<8Q',inventory);require(fields[2]==1 and fields[3]==checked,'retained partial index changed verified-byte count');generation=fields[1]
  passed('native pause and trusted R retain only checked partial chunks plus selected metadata',verified_bytes=checked,total_bytes=len(wave),generation=generation,complete=False)
  personal.stop();seeds[0].stop();personal=Guest('p2',out,image,vault);guests.append(personal);verifier=install(personal,regpkg)
  with personal.client() as c:
   federation.configure(c,verifier,fedpub,'consumer',allowed_rights=8191)
   for slot in (0,2):network.configure(c,relationships[slot]['creds'][0],relationships[slot]['description'],slot=slot)
  j,player,lib,word=approve_apps(personal);require(word(16)==0,'collection silently recovered');personal.ui.press(22);wait(lambda:word(376)==2,60,'native U recovery request');wait(lambda:rendered_text(personal.ui.frame(),16,16,7)=='TRUSTED',300,'trusted partial recovery approval');personal.ui.press(28);wait(lambda:word(16)==1 and word(376)==0,1200,'native partial U recovery');wait(lambda:rendered_text(personal.ui.frame(),12,58,13)=='LEMMA LIBRARY',120,'partial recovery panel dismissed')
  with personal.client() as c:
   q,_=appcall(c,lib,705,0);restored=q[1];state=content.api(c).objects(306,restored)[0];require(state[2]==1 and state[3]==checked,'recovery published incomplete root or lost checked chunks');q,_=appcall(c,lib,703,0,0,128);require(struct.unpack_from('<Q',_ ,24)[0]==1,'Library mislabeled partial ready')
  require(word(96)==0,'old acquisition authority restored')
  personal.ui.press(60)
  for slot in (0,2):
   personal.ui.press(slot+2);personal.ui.press(28)
   def authenticated():
    with personal.client() as c:return network.status(c,slot)['endpoint_authenticated']
   wait(authenticated,300,'fresh alternate provider authentication '+str(slot))
  with registry.client() as c:
   library_peer.call(c,regpeer,402,0);library_peer.call(c,regpeer,400,0,1,1,0,16777216,100000,identity+bytes.fromhex(relationships[0]['details']['service_id'])+fid)
  with seeds[1].client() as c:
   library_peer.call(c,seedpeers[1],402,0);library_peer.call(c,seedpeers[1],400,0,2,int.from_bytes(rootsha[:8],'little')|1,seedhandles[1],16777216,100000,identity+bytes.fromhex(relationships[2]['details']['service_id'])+rootsha)
  personal.ui.press(59);personal.ui.press(16);wait(lambda:word(40)!=0,60,'catalog refresh started');wait(lambda:word(40)==0,300,'current signed metadata refresh');personal.ui.press(3);personal.ui.press(34);wait(lambda:word(208)==1,60,'fresh acquisition consent');personal.ui.press(28)
  def completed():
   q=job_words()
   if q[0] in (12,13,14):raise RuntimeError(('failover failed',q))
   return q[0]==10
  responsive=None
  if a.game:
   from native_responsive import NativeResponsive
   responsive=NativeResponsive.install(personal,a.game,a.public,lib)
   hashing=responsive.hashing(1200);responsive.focus_library()
   passed('game input and unrelated Objects complete during actual alternate-provider integrity validation',**hashing)
  wait(completed,1200,'alternate seed remaining checked acquisition')
  with personal.client() as c:
   q,_=appcall(c,lib,705,0);complete=q[1];actual=b''.join(content.api(c).objects(307,complete,off,min(512,len(wave)-off))[1] for off in range(0,len(wave),512));require(actual==wave,'alternate provider content bytes differ')
  require(job_words()[2]==2,'selected alternate provider was not used')
  passed('fresh native consent resumes retained verified chunks from seed2 after seed1 shutdown',verified_reused=checked,remaining_bytes=len(wave)-checked,provider=2,payload_sha256=hashlib.sha256(actual).hexdigest(),old_authority_restored=False)
  personal.ui.press(19);wait(lambda:word(376)==1,60,'complete content retention approval');wait(lambda:rendered_text(personal.ui.frame(),16,16,7)=='TRUSTED',300,'trusted complete content approval');personal.ui.press(28);wait(lambda:rendered_text(personal.ui.frame(),12,58,13)=='LEMMA LIBRARY',300,'complete retention panel dismissed')
  if responsive:
   persistence=responsive.persisting(300);responsive.focus_library()
   passed('game input and unrelated Objects complete during actual selected encrypted persistence',**persistence)
  wait(lambda:word(376)==0 and word(176)==17,1200,'complete content retention')
  personal.stop();registry.stop();seeds[1].stop();personal=Guest('p3',out,image,vault);guests.append(personal);j,player,lib,word=approve_apps(personal)
  require(word(16)==0,'unapproved collection rows silently recovered');personal.ui.press(22)
  wait(lambda:rendered_text(personal.ui.frame(),16,16,7)=='TRUSTED',300,'native selected content recovery approval')
  (out/'recovery-approval.ppm').write_bytes(personal.ui.frame().ppm());personal.ui.press(28);wait(lambda:word(16)==1 and word(176)==17,1200,'native U/Enter co-recovery')
  wait(lambda:rendered_text(personal.ui.frame(),12,58,13)=='LEMMA LIBRARY',120,'offline Library repaint')
  personal.ui.press(35);wait(lambda:word(160)==player,120,'native Player binding');personal.ui.press(57)
  def attached():
   with personal.client() as c:return appcall(c,player,601)[0][2]==1
  wait(attached,180,'offline verified content attachment')
  current=rendered_text(personal.ui.frame(),520,34,16);personal.ui.chord(56,15)
  wait(lambda:rendered_text(personal.ui.frame(),520,34,16)==f'{player:016x}',60,'trusted Player focus')
  personal.ui.press(57)
  def ended():
   with personal.client() as c:return appcall(c,player,601)[0][2]==5
  wait(ended,300,'actual offline decoded PCM playback');captured=personal.capture.read_bytes();require(captured==wave[44:],'retained offline guest PCM differs from selected media')
  (out/'offline-playback.ppm').write_bytes(personal.ui.frame().ppm());passed('fresh U/Enter recovers co-committed selected collection and content; offline native player emits exact PCM',network_providers_running=False,recipient_network_configured=False,pcm_bytes=len(captured),pcm_sha256=hashlib.sha256(captured).hexdigest(),speaker_output=False)
 except BaseException as error:
  preserve_failure(guests,out,error)
  if a.keep_running:
   print('PRESERVED failed guests; see failure.json',flush=True);guests=[]
  raise
 finally:
  for node in reversed(guests):
   if node.proc.poll() is None:node.stop()
if __name__=='__main__':main()
