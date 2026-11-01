"""Installed native Feed signer boundary, using actual kernel caller bindings."""
from __future__ import annotations
import argparse,hashlib,json,struct,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import live_build,releases,nodes,identity,messenger,live_acceptance as accept
from native_identity import verify


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--backend',choices=['qemu','x86_64','aarch64'],default='qemu');p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 a.output.mkdir(parents=True,exist_ok=False)
 packages={}
 for module,entry,name,rights in [('Guest.Identity','Guest.Identity.main','feed-identity',0),('tests.fixtures.FeedSignerClient','Guest.FeedSignerClient.main','feed-signer-client',1024)]:
  binary=live_build.app(module,entry,name,2);raw,_=releases.make(binary,name,'0.9.0',rights,ROOT/'tests/keys/development-rsa.pem',profile=2)
  path=a.output/(name+'.ltrel');path.write_bytes(raw);packages[name]=path
 checks=[]
 def passed(name,**detail):checks.append(dict(check=name,result='passed',**detail));print('PASS',name,flush=True)
 with accept.Session(a.backend,a.output/'guest') as c:
  c.timeout=300
  signer=identity.start(c,packages['feed-identity'],ROOT/'tests/keys/development-rsa-public.pem')
  path=packages['feed-signer-client'];raw=path.read_bytes();info=releases.inspect(raw)
  owner=nodes.start_package(c,nodes.approved_package(path,ROOT/'tests/keys/development-rsa-public.pem',info['release_id'],1024),raw)
  launcher=messenger.launcher(c);sid=bytes.fromhex(signer['release']);oid=bytes.fromhex(info['release_id'])
  messenger.bind(c,5,owner,launcher,480,oid)
  for op in (402,410):identity.bind(c,signer['service'],owner,sid,oid,op)
  def request(inner):
   raw=c.request(150,struct.pack('<Q',owner)+accept.command(480,data=inner));f=accept.fields(raw);assert f[0]==0,f
   job=f[1];end=time.monotonic()+300
   while time.monotonic()<end:
    try:raw=c.request(150,struct.pack('<Q',owner)+accept.command(480,h=1,a=job))
    except ValueError:time.sleep(.03);continue
    f=accept.fields(raw)
    if f[0]==6:time.sleep(.03);continue
    return f,raw[64:]
   raise TimeoutError('native Feed signer completion')
  federation=hashlib.sha256(b'Feed signer selected federation').digest();scope=hashlib.sha256(b'Feed author account scope').digest()
  f,descriptor=request(accept.command(410,data=federation+scope));assert f[0]==0 and len(descriptor)==288,f
  key=f[1];public=descriptor[96:128]
  verify(public,descriptor[:192],descriptor[192:256],a.output/'descriptor-verify')
  passed('current native Feed account creates scoped Ed25519 key; descriptor independently verifies',public=public.hex(),generation=1)
  body=bytearray(256);struct.pack_into('<4Q',body,0,0x3144564546544c,1,1,1)
  text=b'Use original signed events for a finite federated community.'
  body[64:96]=hashlib.sha256(text).digest();struct.pack_into('<Q',body,96,len(text));body[112:144]=federation
  def approve(b):return request(accept.command(410,h=1,a=key,data=hashlib.sha256(b).digest()))[0]
  grant=approve(body);assert grant[0]==0,grant
  changed=bytearray(body);changed[144:176]=hashlib.sha256(b'broader audience').digest()
  f,_=request(accept.command(402,h=grant[1],data=changed));assert f[0]==1,f
  f,event=request(accept.command(402,h=grant[1],data=body));assert f[0]==0 and len(event)==480,f
  assert event[160:416]==body and event[48:80]==federation
  verify(public,event[:416],event[416:],a.output/'event-verify')
  passed('one-use approval binds exact audience, body commitment and event kind; original480-byte envelope independently verifies',event_id=hashlib.sha256(event).hexdigest())
  f,_=request(accept.command(402,h=grant[1],data=body));assert f[0]==3,f
  passed('consumed publication approval cannot sign twice')
  forged=bytearray(body);struct.pack_into('<Q',forged,16,8);forged[208:240]=hashlib.sha256(b'target').digest();struct.pack_into('<Q',forged,240,1)
  grant=approve(forged);assert grant[0]==0
  f,_=request(accept.command(402,h=grant[1],data=forged));assert f[0]==1,f
  passed('Feed author cannot sign federation moderation decisions')
  wrong=bytearray(body);wrong[112:144]=hashlib.sha256(b'other federation').digest();grant=approve(wrong)
  f,_=request(accept.command(402,h=grant[1],data=wrong));assert f[0]==1,f
  passed('typed signer rejects body federation outside key scope')
  credential=hashlib.sha256(b'qualification high entropy credential only').digest()
  f,sealed=request(accept.command(410,h=3,a=key,data=credential));assert f[0]==0 and len(sealed)==192,f
  assert public not in sealed and descriptor[32:96] not in sealed
  f,_=request(accept.command(410,h=5));assert f[0]==0,f
  f,_=request(accept.command(410,h=1,a=key,data=hashlib.sha256(body).digest()));assert f[0]==1,f
  passed('typed seal returns ciphertext only; lock invalidates owned keys and approvals')
  f,_=request(accept.command(410,h=4,data=bytes(32)+public+sealed));assert f[0]==2,f
  f,recovered=request(accept.command(410,h=4,data=credential+public+sealed));assert f[0]==0 and len(recovered)==288,f
  assert recovered[96:128]==public and struct.unpack_from('<Q',recovered,24)[0]==2
  verify(public,recovered[:192],recovered[192:256],a.output/'recovered-descriptor-verify')
  passed('explicit native sealed recovery creates fresh handle and key generation without old grants',generation=2)
  assert f[1]!=key
 record=dict(schema=1,backend=a.backend,aarch64_emulated=a.backend=='aarch64',image_sha256=hashlib.sha256((ROOT/'build/live/guest.bin').read_bytes()).hexdigest(),checks=checks,limits=['Boundary probe is not the graphical federated journey.','Whole backing replacement lacks an external freshness anchor.'])
 (a.output/'evidence.json').write_text(json.dumps(record,indent=2)+'\n')
if __name__=='__main__':main()
