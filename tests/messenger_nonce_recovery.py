"""Installed domain2 latest-root loss must never resume an older sending chain."""
import argparse,hashlib,json,os,resource,shutil,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import live_build,releases,live_acceptance as accept
from messenger_retention import invoke,start,authorize

def main():
 p=argparse.ArgumentParser();p.add_argument('--backend',default='qemu',choices=['qemu','x86_64']);p.add_argument('--output',type=Path,default=ROOT/'build/messenger-nonce-recovery/evidence.json');a=p.parse_args();d=a.output.parent;d.mkdir(parents=True,exist_ok=True)
 image=d/'guest.bin';shutil.copyfile(ROOT/'build/live/guest.bin',image);os.environ['LT_GUEST_IMAGE']=str(image)
 binary=live_build.app('Guest.MessengerSession','Guest.MessengerSession.main','sessions-final',2);raw,_=releases.make(binary,'sessions-final','1.0.0',0,ROOT/'tests/keys/development-rsa.pem',profile=2);package=d/'owner.ltrel';package.write_bytes(raw)
 vault=d/'personal.img';resource.setrlimit(resource.RLIMIT_FSIZE,(resource.RLIM_INFINITY,resource.RLIM_INFINITY))
 with vault.open('xb') as f:f.truncate(5396000*512)
 key=hashlib.sha256(b'disclosed nonce recovery fixture credential').digest();fed=hashlib.sha256(b'nonce-recovery-federation').digest()
 with accept.Session(a.backend,d/'session',vault) as c:
  c.timeout=600;owner=start(c,package);_,before=invoke(c,421,data=fed);authorize(c,owner);invoke(c,432,h=0,a=1,data=key)
  invoke(c,434,a=13,data=hashlib.sha256(b'explicit selected service descriptor fixture').digest())
  invoke(c,431);authorize(c,owner);invoke(c,432,h=1,a=1,data=key);invoke(c,431)
  with vault.open('r+b',buffering=0) as f:
   f.seek((5394976+2)*512);root=f.read(512);assert struct.unpack_from('<Q',root,24)[0]==2
   # Deliberate opaque media-fault adapter: remove the most recent root sector.
   # No identity/session key or ciphertext is decoded or edited by this test.
   f.seek((5394976+2)*512);f.write(bytes(512));os.fsync(f.fileno())
  authorize(c,owner);invoke(c,432,h=1,a=1,data=key,expected=13)
  authorize(c,owner);invoke(c,432,h=2,a=1,data=key);invoke(c,435,h=1,expected=5)
  _,after=invoke(c,421,data=fed);assert before[32:64]!=after[32:64]
 report=dict(schema=1,backend=a.backend,image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),package_sha256=hashlib.sha256(raw).hexdigest(),package_code_bytes=binary.stat().st_size,checks=['ordinary recovery with matching nonce allocator succeeds','lost latest root with newer authenticated allocator denies sending recovery','explicit history-only reconciliation discards old sending authority','new device key after reconciliation'],fault='One512-byte public root publication replaced by zero bytes while owner locked; allocator and encrypted banks retained.',limits='No external freshness anchor: undetectable substitution of an entire older backing remains outside this check.')
 a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
