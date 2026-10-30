"""Actual Registry-v1 kernel checks with installed rights-zero native probes.

The probe returns only entropy digests. Host code provisions exact local grants;
the guest kernel owns caller identity, package authority, entropy, and revocation.
"""
import argparse, contextlib, hashlib, json, os, signal, struct, subprocess, sys, time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools')]
import live,nodes,releases
ERROR=(1<<64)-1

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--backend',choices=('qemu','x86_64','aarch64'),default='qemu')
 p.add_argument('--image',type=Path,required=True)
 p.add_argument('--service',type=Path,default=ROOT/'build/live/apps/binding-service.bin')
 p.add_argument('--client',type=Path,default=ROOT/'build/live/apps/binding-client.bin')
 p.add_argument('--key',type=Path,default=ROOT/'tests/keys/development-rsa.pem')
 p.add_argument('--public',type=Path,default=ROOT/'tests/keys/development-rsa-public.pem')
 p.add_argument('--output',type=Path,required=True)
 a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
 image=out/'guest.bin';image.write_bytes(a.image.read_bytes())
 sock=out/'portal.sock';log=(out/'guest.log').open('wb');proc=client=None;checks=[];packages={}
 def passed(label):checks.append(label);print('PASS',label,flush=True)
 try:
  command=list(map(str,[ROOT/'lt','run','--backend',a.backend,'--image',image,'--socket',sock]))
  proc=subprocess.Popen(command,cwd=ROOT,stdout=log,stderr=log,start_new_session=True)
  end=time.monotonic()+330
  while not sock.exists():
   if proc.poll()is not None:raise RuntimeError('guest failed before portal')
   if time.monotonic()>end:raise TimeoutError('guest boot')
   time.sleep(.05)
  client=live.Client(sock,timeout=240)
  launcher=next(struct.unpack_from('<Q',raw,32)[0] for raw in [client.request(2)])
  def install(name,binary,rights):
   raw,_=releases.make(binary,name,'1.0.0',rights,a.key,profile=2,license='NOASSERTION')
   path=out/(name+'.ltrel');path.write_bytes(raw);info=releases.inspect(raw)
   who=nodes.start_package(client,nodes.approved_package(path,a.public,info['release_id'],rights),raw)
   packages[name]=dict(instance=who,release=info['release_id'],rights=rights)
   return who,bytes.fromhex(info['release_id'])
  service,sid=install('binding-service',a.service,0)
  bad,badid=install('binding-network-service',a.service,1024)
  caller,cid=install('binding-client',a.client,0)
  attacker,aid=install('binding-other-client',a.client,0)
  def bind(target,who,operation,service_hash,caller_hash=bytes(32),prior=0):
   body=struct.pack('<6Q',1,1,target,who,operation,prior)+service_hash+caller_hash+bytes(16)
   return struct.unpack('<Q',client.request(171,body))[0]
  def deny(label,call):
   try:call()
   except ValueError as error:assert 'guest rejected command' in str(error),(label,str(error))
   else:raise AssertionError(label+' was allowed')
  def app(who,op):
   return client.request(150,struct.pack('<Q8Q',who,op,0,0,0,0,0,0,1))
  deny('network-authorized signer',lambda:bind(bad,launcher,400,badid))
  deny('substituted service release',lambda:bind(service,launcher,400,bytes(32)))
  deny('substituted caller release',lambda:bind(service,caller,400,sid,bytes(32)))
  deny('signer operation outside typed range',lambda:bind(service,launcher,399,sid))
  passed('role1 requires installed rights-zero service, exact admitted service/caller releases and typed operation400..409')
  generation=bind(service,launcher,400,sid)
  assert generation>0
  assert struct.unpack('<Q',client.request(172,struct.pack('<2Q',1,400)))[0]==service
  reply=app(service,400);fields=struct.unpack_from('<8Q',reply)
  assert len(reply)==96 and fields[:7]==(0,ERROR,0,ERROR,ERROR,ERROR,ERROR),fields
  digest=reply[64:96];assert any(digest)
  assert app(service,400)[64:96]!=digest
  passed('actual registered signer gets fresh32-byte private-arena entropy; wrong token, size, region, network and Vault raw device calls deny')
  deny('unbound operation',lambda:app(service,401))
  deny('PID alias bypass',lambda:app(service&255,400))
  deny('wrong prior generation',lambda:bind(service,launcher,400,sid,prior=generation+1))
  new_generation=bind(service,launcher,400,sid,prior=generation)
  assert new_generation>generation
  deny('stale revoke generation',lambda:client.request(173,struct.pack('<4Q',1,launcher,400,generation)))
  passed('exact full endpoint and operation enforced; replacement and revocation compare current generation')
  caller_generation=bind(service,caller,400,sid,cid)
  client_reply=app(caller,900)
  assert len(client_reply)==96 and struct.unpack_from('<Q',client_reply)[0]==0
  denied=struct.unpack_from('<2Q',app(attacker,900));assert denied==(ERROR,ERROR),denied
  passed('bound rights-zero application uses broker; separately installed unbound caller cannot discover it or access entropy')
  client.request(173,struct.pack('<4Q',1,caller,400,caller_generation))
  assert struct.unpack_from('<2Q',app(caller,900))==(ERROR,ERROR)
  assert struct.unpack_from('<Q',app(service,400))[0]==0
  passed('per-caller operation revocation leaves separately approved Launcher operation usable')
  client.request(173,struct.pack('<4Q',1,0,0,0))
  deny('revoked role falls through generic Launcher privilege',lambda:app(service,400))
  assert struct.unpack('<Q',client.request(172,struct.pack('<2Q',1,400)))[0]==ERROR
  generation=bind(service,launcher,400,sid)
  assert struct.unpack_from('<Q',app(service,400))[0]==0
  bind(service,launcher,401,sid)
  assert struct.unpack_from('<5Q',app(service,401))==(0,)+(0x1122334455667788,)*4
  client.request(26,struct.pack('<Q',service))
  assert struct.unpack('<Q',client.request(172,struct.pack('<2Q',1,400)))[0]==ERROR
  # Restarting the same admitted bytes creates a new incarnation in the
  # reclaimed slot. Former authority must not transfer through slot reuse.
  selected=0
  for index in range(16):
   try:record=client.request(13,struct.pack('<Q',index))
   except ValueError:continue
   if record[160:192]==sid:selected=index+1;break
  assert selected
  fresh=struct.unpack_from('<Q',client.request(25,struct.pack('<Q',selected)),8)[0]
  assert fresh!=service and fresh&255==service&255
  assert struct.unpack('<Q',client.request(172,struct.pack('<2Q',1,400)))[0]==ERROR
  deny('stale incarnation registration',lambda:bind(service,launcher,400,sid))
  generation=bind(fresh,launcher,400,sid)
  bind(fresh,launcher,401,sid)
  assert struct.unpack_from('<5Q',app(fresh,401))==(0,0,0,0,0)
  passed('same-slot restart clears native data, bottom of guarded stack and both near/far private arena markers')
  assert struct.unpack_from('<Q',app(fresh,400))[0]==0
  passed('role-wide revocation fails closed; process teardown and same-package slot reuse require fresh explicit binding')
  with contextlib.suppress(EOFError):client.request(70)
  client.close();client=None;proc.wait(30);assert proc.returncode==0
  report=dict(schema=1,result='passed',backend=a.backend,image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),packages=packages,checks=checks,command=command,
   limits=dict(process_slots=12,installed_slots=5,roles=4,operation_grants=32,entropy_bytes=32,private_arena_bytes=2097152),
   limitations=['controlled installed native probe; not Messenger, retained keys or native protocol evidence','assembly backends share RV64 guest but interpret it; AArch64 is emulated on this host','policy proofs cover Boolean predicates; source-to-binary compiler and complete kernel are not verified'])
  (out/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
 finally:
  if client:client.close()
  if proc and proc.poll()is None:os.killpg(proc.pid,signal.SIGTERM);proc.wait(15)
  log.close()
if __name__=='__main__':main()
