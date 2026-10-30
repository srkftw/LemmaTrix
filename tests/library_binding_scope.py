"""Actual Library rejects signed edition substitution and active Fetch rebinding.

The ordinary Lean probe imports the actual Library functions. A real native
Registry admits both canonical Game releases and deliberately conflicting signed
consumer records; only the probe's own row/save are fixture state.
"""
import argparse,base64,contextlib,hashlib,json,os,signal,struct,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import capsule,consumers,content,federation,live,nodes,projects,releases
from library_journey import wait


def require(value,message):
 if not value:raise AssertionError(message)


def archive_record(archive,name):
 records={r['id']:base64.b64decode(r['payload'])for r in archive['nodes']}
 manifest=records[archive['selected'][0]['head']]
 identity=next(identity for path,kind,identity in projects.decode_manifest(manifest)if path==name)
 return records[identity]


def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--image',type=Path,required=True);p.add_argument('--binary',type=Path,required=True);p.add_argument('--packages',type=Path,required=True)
 p.add_argument('--editions',type=Path,default=ROOT/'build/campaign005/game-save-editions')
 p.add_argument('--key',type=Path,default=ROOT/'build/campaign005/publisher.pem');p.add_argument('--public',type=Path,default=ROOT/'build/campaign005/publisher.pub');p.add_argument('--output',type=Path,required=True)
 a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);sock=out/'portal.sock';log=(out/'guest.log').open('wb');proc=client=None;checks=[];packages=[]
 try:
  command=list(map(str,[ROOT/'lt','run','--backend','qemu','--image',a.image,'--socket',sock]));proc=subprocess.Popen(command,cwd=ROOT,stdout=log,stderr=log,start_new_session=True);wait(sock.exists,90,'guest boot');client=live.Client(sock,timeout=240)
  def start(path):
   raw=path.read_bytes();info=releases.inspect(raw,releases.public_modulus(a.public));who=nodes.start_package(client,nodes.approved_package(path,a.public,info['release_id'],info['rights']),raw);packages.append(dict(release=info['release_id'],project=info['project_id'],instance=who,rights=info['rights']));return who,info
  registry,_=start(a.packages/'library-registry.ltrel')
  fedkey,fedpub=out/'federation.pem',out/'federation.pub';capsule.generate_key(fedkey,fedpub);federation.configure(client,registry,fedpub,'consumer',allowed_rights=8191)
  def admit(root,record,classification):
   federation.call(client,registry,3,data=record[32:64]+releases.public_modulus(a.public));federation.call(client,registry,2,h=client.objects(27,root,registry,25)[0][1]);decision=federation.sign_once(client,registry,fedkey,'consumer',8191);require(decision['listing']==classification,'properly signed fixture record failed actual Registry admission')
   cursor=0
   while True:
    fields,descriptor=federation.call(client,registry,6,h=cursor)
    if struct.unpack_from('<Q',descriptor,48)[0]==decision['sequence']:break
    cursor=fields[3]
   _,original=federation.call(client,registry,20,h=fields[2]);require(original==record,'native Registry substituted consumer bytes')
   return descriptor,decision
  archives=[json.loads((a.editions/f'game{i}-closure.json').read_text())for i in (1,2)]
  game_paths=[a.editions/f'game{i}/crate-workshop.ltrel'for i in (1,2)]
  roots=[projects.import_records(client,archive['selected'],[dict(r,payload=base64.b64decode(r['payload']))for r in archive['nodes']])[0]['cap']for archive in archives]
  original=archive_record(archives[0],'consumer.release');pack=archive_record(archives[0],'game.levels');descriptor_a,decision_a=admit(roots[0],original,5)
  collision=consumers.create(key=a.key,project='ignored-exact-native-publication',facet='game',collection=hashlib.sha256(b'different signed Game collection').digest(),item=hashlib.sha256(b'different signed Game item').digest(),edition=original[160:192],title='Different signed Game reusing edition identifier',resource=pack,executable=game_paths[1].read_bytes(),sequence=2,edition_version=6,license_id=1)
  # Imported graph roots grant scoped resolution, not ambient visibility of
  # every child. Select each existing head edge through that public authority
  # before authoring a new manifest which retains those exact dependencies.
  game2_head=base64.b64decode(next(r['payload']for r in archives[1]['nodes']if r['id']==archives[1]['selected'][0]['head']))
  for _,_,identity in projects.decode_manifest(game2_head):
   projects.resolve(client,roots[1],identity)
  conflict_root=consumers.attach(client,collision,pack,name='edition-collision-game',root=roots[1])['root'];descriptor_b,decision_b=admit(conflict_root,collision,5)
  require(collision[160:192]==original[160:192]and collision[256:288]!=original[256:288]and collision[96:160]!=original[96:160],'Game collision fixture does not change its executable and collection/item')
  # A cross-facet/publisher-namespace collision is also a genuinely signed,
  # independently admitted record, rather than a malformed signature input.
  wave=content.original_wave(.001,2);manifest,_,_=content.commitments(wave)
  media=consumers.create(key=a.key,project='different-publication-edition-collision',collection=hashlib.sha256(b'different media collection').digest(),item=hashlib.sha256(b'different media item').digest(),edition=original[160:192],title='Admitted media reusing Game edition identifier',resource=manifest,frames=48,channels=2,license_id=1)
  media_root=consumers.attach(client,media,manifest,name='edition-collision-media')['root'];descriptor_m,decision_m=admit(media_root,media,4)
  raw,_=releases.make(a.binary,'library-binding-probe','1.0.0',1919,a.key,profile=2,license='NOASSERTION');probe_path=out/'library-binding-probe.ltrel';probe_path.write_bytes(raw);probe,probe_info=start(probe_path);client.request(184,struct.pack('<Q',probe))
  def call(op,h=0,a=0,b=0,data=b''):
   raw=client.request(150,struct.pack('<Q8Q',probe,op,h,a,b,0,0,0,1)+data);require(len(raw)>=64,'short probe response');return struct.unpack_from('<8Q',raw),raw[64:]
  def accept(descriptor,record):
   metadata=descriptor+record
   for offset in range(0,1536,512):require(call(950,a=offset,b=512,data=metadata[offset:offset+512])[0][0]==0,'probe metadata upload failed')
   return call(951)
  def row():return b''.join(call(954,a=offset,b=512)[1]for offset in range(0,2048,512))
  accepted=accept(descriptor_a,original);require(accepted[0][:3]==(0,14,1)and accepted[1]==hashlib.sha256(original).digest(),'initial actual Library admission failed')
  saved=bytearray(192);struct.pack_into('<2Q',saved,0,0x3156415343544c,1);saved[16:48]=pack[16:48];saved[48:80]=hashlib.sha256(pack).digest();struct.pack_into('<6Q',saved,80,1,0,2,536870912,28,1)
  require(hashlib.sha256(saved).hexdigest()=='199fe54e37946001f2a728dd841a2476d1e58506a39231c976cc57b5052043fe','bounded save fixture differs from actual original two-push save bytes')
  private=call(952,data=saved);require(private[0][0]==0 and private[0][3]and private[0][4],'private metadata/save initialization failed');before=row();require(call(953)[1]==saved,'committed selected save differs')
  rejections=[]
  for label,descriptor,record,decision in [('different Game executable',descriptor_b,collision,decision_b),('different publication and media facet',descriptor_m,media,decision_m)]:
   result=accept(descriptor,record);require(result[0][1]==29 and result[0][2]==1,'conflicting properly signed edition was not rejected');require(row()==before and call(953)[1]==saved,'collision retargeted metadata/private references or changed save bytes');rejections.append(dict(variant=label,classification=decision['listing'],sequence=decision['sequence'],consumer_sha256=hashlib.sha256(record).hexdigest(),notice=result[0][1],row_unchanged=True,selected_save_sha256=hashlib.sha256(saved).hexdigest()))
  checks.append(dict(check='actual Library rejects two properly signed/admitted same-edition substitutions before mutating selected metadata and private save references',result='passed',original_consumer_sha256=hashlib.sha256(original).hexdigest(),edition_id=original[160:192].hex(),original_admission_sequence=decision_a['sequence'],private_metadata_handle=private[0][3],private_save_handle=private[0][4],save_bytes=192,rejections=rejections))
  fresh_descriptor,fresh_decision=admit(roots[0],original,5);refreshed=accept(fresh_descriptor,original);after=row();require(refreshed[0][1]==14 and refreshed[0][5]==fresh_decision['sequence']and after[:256]==before[:256]and after[1024:1792]==original and call(953)[1]==saved,'byte-identical consumer admission refresh lost private references')
  checks.append(dict(check='a fresher valid federation descriptor for byte-identical signed consumer refreshes without changing private references',result='passed',sequence_before=decision_a['sequence'],sequence_after=fresh_decision['sequence'],consumer_sha256=hashlib.sha256(original).hexdigest(),private_prefix_unchanged=True,save_sha256=hashlib.sha256(saved).hexdigest()))
  fetch1,fetch_info=start(a.packages/'library-fetch.ltrel')
  # Starting the approved current catalog slot again creates a second ordinary
  # incarnation of the same helper; no special role is inferred from its slot.
  slot=0
  for index in range(16):
   try:catalog=client.request(13,struct.pack('<Q',index))
   except ValueError:continue
   if catalog[160:192].hex()==fetch_info['release_id']:slot=index+1;break
  require(slot!=0,'current Fetch catalog slot missing');fetch2=struct.unpack_from('<Q',client.request(25,struct.pack('<Q',slot)),8)[0];require(fetch1!=fetch2,'two actual helper incarnations were not created')
  operation=770001;require(call(955,fetch2,operation)[0][6:]==(fetch2,operation),'fixture active helper binding failed')
  guarded=call(956);require(guarded[0][1]==18 and guarded[0][6:]==(fetch2,operation),'O retargeted an active helper operation')
  call(955,fetch2,0);rebound=call(956);require(rebound[0][1]==16 and rebound[0][6:]==(fetch1,0),'idle explicit O did not select the first actual live helper')
  checks.append(dict(check='actual bindProcess refuses O while an operation is active and permits explicit idle rebinding between two real helper incarnations',result='passed',first_helper=fetch1,original_helper=fetch2,operation=operation,busy_notice=guarded[0][1],binding_while_active=guarded[0][6],binding_when_idle=rebound[0][6],no_operation_id_change=True))
  with contextlib.suppress(EOFError):client.request(70)
  client.close();client=None;proc.wait(30);require(proc.returncode==0,'guest did not stop normally')
  result=dict(schema=1,result='passed',backend='qemu',image_sha256=hashlib.sha256(a.image.read_bytes()).hexdigest(),library_source_sha256=hashlib.sha256((ROOT/'Guest/Library.lean').read_bytes()).hexdigest(),probe_sha256=hashlib.sha256(a.binary.read_bytes()).hexdigest(),probe_release=probe_info['release_id'],packages=packages,checks=checks,command=command,normal_shutdown=True,scope='ordinary native Lean fixture invokes actual Library.acceptMetadata/add/bindProcess; real native Registry checks canonical Game and signed consumer facets; all fixture state is its own private row/Objects',limitations=['focused actual-function regression, not graphical catalog/install/save retention or live remote Fetch acquisition evidence','two actual approved helper incarnations are live, but the fixture initializes its own bounded active-operation identity to isolate rebinding; it does not claim a simultaneous network transfer','selected192-byte save fixture exactly matches the separately executed original two-push save; this check does not execute Game input or recover a vault','same QEMU reference image only; no changed kernel/device/physical storage claim'])
  (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
 finally:
  if client:
   with contextlib.suppress(EOFError,OSError,ValueError):client.request(70)
   client.close()
  if proc and proc.poll()is None:
   try:proc.wait(30)
   except subprocess.TimeoutExpired:os.killpg(proc.pid,signal.SIGTERM);proc.wait(10)
  log.close()


if __name__=='__main__':main()
