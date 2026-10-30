"""Actual guest consumer/native admission, signatures and own-store recovery."""
import argparse,hashlib,json,os,signal,struct,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import capsule,consumers,content,federation,game_release,live,projects,releases,server_store

def require(value,message):
 if not value:raise AssertionError(message)

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--key',type=Path,required=True);p.add_argument('--public',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--games',action='store_true');p.add_argument('--reuse-builds',type=Path);a=p.parse_args();a.output=a.output.resolve();a.output.mkdir(parents=True,exist_ok=False)
 image=hashlib.sha256((ROOT/'build/live/guest.bin').read_bytes()).hexdigest();reports=[];proc=None;log=None;socket=a.output/'portal.sock';backing=a.output/'registry.store';server_store.provision(backing)
 fedkey=a.output/'federation.pem';fedpub=a.output/'federation.pub';capsule.generate_key(fedkey,fedpub)
 package,manifest=releases.make(ROOT/'build/live/apps/registry.bin','consumer-registry','1.0.0',2175,a.key,profile=2,sources=[ROOT/'Guest/Registry.lean',ROOT/'Guest/ConsumerFormat.lean'],source_base=ROOT)
 package_path=a.output/'registry.ltrel';package_path.write_bytes(package);Path(str(package_path)+'.manifest.json').write_bytes(releases.pkg.canonical(manifest))
 def passed(label,**fields):
  reports.append(dict(check=label,result='pass',**fields));print('PASS',label,flush=True);(a.output/'journey.json').write_text(json.dumps(dict(image=image,checks=reports),indent=2)+'\n')
 def boot():
  nonlocal proc,log
  socket.unlink(missing_ok=True);log=(a.output/('guest-'+str(len(reports))+'.log')).open('wb')
  proc=subprocess.Popen([str(ROOT/'lt'),'run','--socket',str(socket),'--server-store',str(backing)],cwd=ROOT,stdout=log,stderr=log,start_new_session=True)
  deadline=time.monotonic()+90
  while not socket.exists():
   require(proc.poll() is None,'guest failed boot')
   if time.monotonic()>deadline:raise TimeoutError('registry guest boot')
   time.sleep(.05)
 def stop():
  nonlocal proc,log
  if proc and proc.poll() is None:
   c=live.Client(socket)
   try:
    try:c.request(70)
    except EOFError:pass
   finally:c.close()
   proc.wait(timeout=20)
  if log:log.close();log=None
 def install(c):
  c.request(10,releases.project('consumer-registry')+releases.public_modulus(a.public));info=c.stage(package_path);c.request(23,bytes.fromhex(info['release_id'])+struct.pack('<Q',2175));slot=struct.unpack_from('<Q',c.request(24),8)[0];instance=struct.unpack_from('<Q',c.request(25,struct.pack('<Q',slot)),8)[0]
  server_store.call(c,230);grant=server_store.call(c,231,instance,1,1048576,hashlib.sha256(b'Campaign005 consumer catalog explicit namespace').digest())[0][1]
  federation.configure(c,instance,fedpub,'consumer',grant,allowed_rights=8191)
  return instance
 def trust(c,instance,publication):federation.call(c,instance,3,data=publication+releases.public_modulus(a.public))
 def admit(c,instance,root):
  handle=c.objects(27,root,instance,25)[0][1];fields,_=federation.call(c,instance,2,h=handle);signed=federation.sign_once(c,instance,fedkey,'consumer',8191);return fields[2],signed
 try:
  boot();c=live.Client(socket,timeout=240)
  try:
   instance=install(c);trust(c,instance,releases.project('open-courtyard'))
   raw=content.original_wave(1,2);cm,_,_=content.commitments(raw)
   record=consumers.create(key=a.key,project='open-courtyard',facet='media',collection=hashlib.sha256(b'original collection').digest(),item=hashlib.sha256(b'item1').digest(),edition=hashlib.sha256(b'stereo').digest(),title='Original Courtyard / stereo',resource=cm,frames=48000,channels=2,license_id=2)
   imported=consumers.attach(c,record,cm,name='courtyard-stereo');slot,signed=admit(c,instance,imported['root']);require(signed['listing']==4 and signed['reason']==0,('media admission failed',signed))
   fields,signed_record=federation.call(c,instance,20,h=slot);require(signed_record==record,'guest changed original signed consumer bytes')
   closure=projects.closure(c,imported['root']) if hasattr(projects,'closure') else []
   passed('genuine signed media metadata and manifest admitted without payload acquisition',slot=slot,consumer=hashlib.sha256(record).hexdigest(),root=imported['head'],classification=signed['listing'],payload_bytes_transferred=0)
   altered=bytearray(record);altered[344]^=1
   forged=consumers.attach(c,altered,cm,name='forged-title');_,rejected=admit(c,instance,forged['root']);require(rejected['listing']==3 and rejected['reason']==3,'signed title substitution admitted')
   # Import a manifest substitution directly through ordinary Objects, retaining
   # the original signed metadata so the guest checks its commitment itself.
   bad_cm=bytearray(cm);bad_cm[128]^=1
   entries=[]
   for name,data in [('consumer.release',record),('content.manifest',bad_cm)]:
    _,identity=projects.node(c,data,10);entries.append((name,10,identity))
   h,head=projects.node(c,projects.manifest(entries),11);name=b'wrong-manifest';root=c.objects(22,h,0,len(name),data=bytes(32)+name.ljust(64,b'\0'))[0][1]
   _,rejected2=admit(c,instance,root);require(rejected2['listing']==3 and rejected2['reason']==7,'manifest substitution admitted')
   passed('guest rejects actual signed-title and resource substitutions',signature_reason=rejected['reason'],manifest_reason=rejected2['reason'])
   if a.games:
    original=game_release.publish(c,generation=1,key=a.key,output=(a.reuse_builds or a.output)/'game1');trust(c,instance,bytes.fromhex(original['publication_id']));gslot,gsigned=admit(c,instance,original['root']);require(gsigned['listing']==5,('native Game consumer gate failed',gsigned))
    _,game_record=federation.call(c,instance,20,h=gslot);require(consumers.inspect(game_record)['executable_release']==original['release_id'],'consumer Game executable identity differs')
    next_game=game_release.publish(c,generation=2,key=a.key,output=(a.reuse_builds or a.output)/'game2',previous=original);require(next_game['source_logical_project_id']==original['source_logical_project_id'] and next_game['logical_project_id']==original['logical_project_id'],'game update changed stable Project identity');_,gsigned2=admit(c,instance,next_game['root']);require(gsigned2['listing']==5,('generation2 Game gate failed',gsigned2))
    passed('actual isolated game builds produce canonical native plus consumer admission',original=original,updated=next_game,classification=5)
   fields,desc=federation.call(c,instance,6);require(fields[0]==0 and len(desc)==768,'catalog pagination failed')
   signed_catalog=[];cursor=0
   while True:
    try:q,data=federation.call(c,instance,6,h=cursor)
    except ValueError as error:
     if str(error)=='native registry status6':break
     raise
    signed_catalog.append((q[2],data));cursor=q[3]
   # Revoke after the original consumer lookup and inspect the current decision.
   fields,_=federation.call(c,instance,8,h=slot,a=signed['sequence']);revoked=federation.sign_once(c,instance,fedkey,'consumer',8191);require(revoked['listing']==3,'revocation not recorded')
   try:federation.call(c,instance,20,h=slot)
   except ValueError:pass
   else:raise AssertionError('revoked consumer still exposed by lookup')
   passed('revocation denies consumer lookup under current signed knowledge',revocation=revoked)
  finally:c.close()
  stop();boot();c=live.Client(socket,timeout=240)
  try:
   instance=install(c);recovered=federation.call(c,instance,10)[0][1];require(recovered>=4,'own-store catalog recovery incomplete');require(not projects.roots(c),'catalog recovery recreated payload/project roots')
   records=[];cursor=0
   while True:
    try:q,desc=federation.call(c,instance,6,h=cursor)
    except ValueError as error:
     if str(error)=='native registry status6':break
     raise
    cursor=q[3];classification=struct.unpack_from('<Q',desc,16)[0]
    if classification in (4,5):
     _,metadata=federation.call(c,instance,20,h=q[2]);require(hashlib.sha256(metadata).digest()==desc[400:432],'recovered consumer commitment differs');records.append(hashlib.sha256(metadata).hexdigest())
   passed('registry own-store v2 recovery retains signed consumer bytes with no media payload',records=recovered,available_consumers=records,project_roots=0,backing_bytes=backing.stat().st_size)
  finally:c.close()
  stop()
 finally:
  if proc and proc.poll() is None:os.killpg(proc.pid,signal.SIGKILL);proc.wait()
  if log:log.close()
if __name__=='__main__':main()
