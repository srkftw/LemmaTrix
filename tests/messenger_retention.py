"""Installed native owner tests: real kernel async IPC, separate guests and domain2 backing.
Opaque ciphertext is carried by this test; routed product acceptance is separate.
"""
from __future__ import annotations
import argparse,hashlib,json,os,resource,shutil,struct,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import driver,live_build,messenger,releases,live_acceptance as accept
PUB=ROOT/'tests/keys/development-rsa-public.pem'
def invoke(c,op,h=0,a=0,b=0,data=b'',expected=0):
 endpoint=messenger.endpoint(c,2,op);token=struct.unpack('<Q',c.request(175,struct.pack('<Q8Q',endpoint,op,h,a,b,0,0,0,1)+data))[0]
 deadline=time.monotonic()+600
 while time.monotonic()<deadline:
  raw=c.request(176,struct.pack('<Q',token))
  if len(raw)==8:time.sleep(.025);continue
  f=struct.unpack_from('<8Q',raw)
  if f[0]!=expected:raise AssertionError(f'operation{op}: status{f[0]} expected{expected}, fields{f}')
  return f,raw[64:]
 raise TimeoutError(f'native operation{op} failed to complete')
def start(c,package):
 owner,sid=messenger.install(c,package,PUB,0);who=messenger.launcher(c)
 for op in range(420,436):messenger.bind(c,2,owner,who,op,sid)
 return owner
def approve(c,public):
 f,fp=invoke(c,423,data=public);invoke(c,424,h=f[1],data=fp);return f[1]
def authorize(c,owner):c.request(174,struct.pack('<2Q',owner,1))
def main():
 p=argparse.ArgumentParser();p.add_argument('--backend',default='qemu',choices=['qemu','x86_64']);p.add_argument('--output',type=Path,default=ROOT/'build/messenger-retention/evidence.json');a=p.parse_args();d=a.output.parent;d.mkdir(parents=True,exist_ok=True)
 image=d/'guest.bin';shutil.copyfile(ROOT/'build/live/guest.bin',image);os.environ['LT_GUEST_IMAGE']=str(image)
 binary=live_build.app('Guest.MessengerSession','Guest.MessengerSession.main','sessions-retention',2)
 raw,_=releases.make(binary,'sessions-retention','1.0.0',0,ROOT/'tests/keys/development-rsa.pem',profile=2)
 package=d/'owner.ltrel';package.write_bytes(raw)
 vault=d/'personal.img'
 if vault.exists():raise ValueError('test output backing exists; choose a fresh output directory')
 resource.setrlimit(resource.RLIMIT_FSIZE,(resource.RLIM_INFINITY,resource.RLIM_INFINITY))
 with vault.open('xb') as f:f.truncate(5396000*512)
 credential=hashlib.sha256(b'public fixture Messenger domain2 unlock credential').digest();federation=hashlib.sha256(b'local owner test federation').digest();checks=[]
 def passed(name,**extra):checks.append(dict(check=name,result='pass',**extra));print('PASS',name,flush=True)
 sb=accept.Session(a.backend,d/'bob');b=sb.client;b.timeout=600
 try:
  bob=start(b,package);_,bpub=invoke(b,421,data=federation)
  invoke(b,434,a=13,data=hashlib.sha256(b'approved mailbox fixture descriptor').digest())
  _,binvitation=invoke(b,434,a=12)
  _,enrollment=invoke(b,434,a=10)
  assert len(binvitation)==320 and enrollment[32:64]==hashlib.sha256(binvitation[256:288]).digest()
  invoke(b,434,a=11,expected=1)
  sa=accept.Session(a.backend,d/'alice1',vault);c=sa.client;c.timeout=600
  try:
   alice=start(c,package);_,apub=invoke(c,421,data=federation);assert apub[32:64]!=bpub[32:64]
   invoke(c,434,a=13,data=hashlib.sha256(b'approved mailbox fixture descriptor').digest())
   _,ainvitation=invoke(c,434,a=12)
   authorize(c,alice);invoke(c,432,h=0,a=1,data=credential);approve(c,binvitation);approve(b,ainvitation)
   substituted=binvitation[:256]+bytes([binvitation[256]^1])+binvitation[257:]
   invoke(c,423,data=substituted,expected=8)
   passed('independent guest-generated X25519 credentials; explicit domain2 authorization and contact approval')
   f,_=invoke(c,426,h=1,a=len(b'crash-safe native text'),data=b'crash-safe native text');handle=f[1]
   _,packet=invoke(c,427,h=handle);_,retried=invoke(c,435,h=handle);assert packet==retried
   sa.close();passed('retained ciphertext and next chain commit before publication; exact retry')
  except BaseException:sa.abort();raise
  sa=accept.Session(a.backend,d/'alice2',vault);c=sa.client;c.timeout=600
  try:
   alice=start(c,package);authorize(c,alice);invoke(c,432,h=1,a=1,data=credential)
   _,recovered=invoke(c,435,h=handle);assert packet==recovered
   f,_=invoke(b,428,a=len(packet),data=packet);_,text=invoke(b,429,h=f[1]);assert text==b'crash-safe native text'
   invoke(b,428,a=len(packet),data=packet,expected=10)
   f,_=invoke(b,426,h=1,a=len(b'native ratchet reply'),data=b'native ratchet reply');_,reply=invoke(b,427,h=f[1]);f,_=invoke(c,428,a=len(reply),data=reply);inbox=f[1]
   _,text=invoke(c,429,h=inbox);assert text==b'native ratchet reply'
   passed('actual personal guest restart, authorized recovery, decrypt once, duplicate outcome and Double Ratchet reply')
   backup=d/'older-backup.img'
   subprocess.run(['cp','--reflink=auto','--sparse=always',str(vault),str(backup)],check=True)
   invoke(c,430,h=handle)
   useful=(ROOT/'Guest/Library.lean').read_bytes();assert len(useful)>65536
   title=b'Authorized LemmaTrix Library Lean source'
   f,_=invoke(c,434,h=1,a=1,b=len(useful),data=title);message=f[1];sender_attachment=f[2]
   _,manifest=invoke(c,427,h=message);f,_=invoke(b,428,a=len(manifest),data=manifest);f,shown=invoke(b,429,h=f[1]);receiver_attachment=f[5];assert shown==title and receiver_attachment
   out=bytearray();began=time.monotonic();cipher_hash=hashlib.sha256()
   count=(len(useful)+511)//512
   for first in range(0,count,14):
    for i in range(first,min(first+14,count)):
     block=useful[i*512:(i+1)*512];f,hidden=invoke(c,434,h=sender_attachment,a=16,b=i,data=block)
     assert not hidden and f[2]==0,'staging released uncommitted ciphertext'
    invoke(c,434,h=sender_attachment,a=18,b=first,expected=12)
    invoke(c,434,h=sender_attachment,a=17)
    cached=[]
    for i in range(first,min(first+14,count)):
     f,public=invoke(c,434,h=sender_attachment,a=18,b=i);encrypted=public[32:];assert len(encrypted)==f[2];cached.append(encrypted)
    if first==0:
     sa.close();sa=accept.Session(a.backend,d/'alice-attachment-restart',vault);c=sa.client;c.timeout=600
     alice=start(c,package);authorize(c,alice);invoke(c,432,h=1,a=1,data=credential)
     for i,prior in enumerate(cached):
      _,public=invoke(c,434,h=sender_attachment,a=18,b=i);assert public[32:]==prior
     block=useful[:512];broken=bytes([block[0]^1])+block[1:];invoke(c,434,h=sender_attachment,a=16,b=0,data=broken,expected=9)
     passed('actual restart preserves sixteen-entry committed attachment ciphertext cache; changed cached plaintext denied')
    for i,encrypted in zip(range(first,min(first+14,count)),cached):
     cipher_hash.update(encrypted)
     _,decrypted=invoke(b,434,h=receiver_attachment,a=3,b=i,data=encrypted);out.extend(decrypted)
   assert bytes(out)==useful
   passed('bounded512-byte encrypted attachment path with useful >64KiB project source',bytes=len(useful),chunks=(len(useful)+511)//512,sha256=hashlib.sha256(useful).hexdigest(),ciphertext_stream_sha256=cipher_hash.hexdigest(),seconds=time.monotonic()-began)
   invoke(c,431);invoke(c,426,h=1,a=3,data=b'bad',expected=5)
   authorize(c,alice);invoke(c,432,h=1,a=1,data=credential);_,text=invoke(c,429,h=inbox);assert text==b'native ratchet reply'
   passed('lock clears access and revokes storage; separate management consent and recovery restores history')
   sa.close()
  except BaseException:sa.abort();raise
  sa=accept.Session(a.backend,d/'alice3',backup);c=sa.client;c.timeout=600
  try:
   alice=start(c,package);authorize(c,alice);invoke(c,432,h=2,a=1,data=credential)
   invoke(c,435,h=handle,expected=5);_,text=invoke(c,429,h=inbox);assert text==b'native ratchet reply'
   _,fresh=invoke(c,421,data=federation);assert fresh[32:64]!=apub[32:64]
   invoke(c,426,h=1,a=3,data=b'bad',expected=8)
   passed('supported history-only backup import denies old outbox and sending authority; fresh device identity')
   sa.close()
  except BaseException:sa.abort();raise
 finally:sb.close()
 report=dict(schema=1,image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),package_sha256=hashlib.sha256(raw).hexdigest(),package_code_bytes=binary.stat().st_size,backend=a.backend,checks=checks,limits='Local owner/storage/chunk integration. Ciphertext carried by test adapter; no routed graphical/mailbox acceptance claim, no whole-store rollback detection or independent cryptographic review.')
 a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
