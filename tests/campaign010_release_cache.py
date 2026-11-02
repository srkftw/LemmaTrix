"""Execute exact-stage cache guards on an actual guest-signed release.

The fixture provisions public bytes into its own test process. It creates no
publisher key, signing grant, graph admission, installation or live UI state.
"""
import argparse, hashlib, json, sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import live_build, onion_crypto as native, releases
from network_crypto import store_bytes


def source(raw):
 s='''import Guest.Launcher
set_option maxRecDepth 10000
set_option maxHeartbeats 4000000
namespace build.Campaign010ReleaseCache
open Guest Guest.LiveMemory
'''
 for offset in range(0,len(raw),512):
  s+=f'@[noinline] def chunk{offset//512} (t : UInt64) : UInt64 :=\n'
  s+=store_bytes(0x700000+offset,raw[offset:offset+512])+'\n  t\n'
 s+='''
def check (t : UInt64) : UInt64 :=
  let t := zero Guest.Launcher.control 1024 (zero Guest.Launcher.verificationCache 256 t)
  let t := zero (Guest.Launcher.trust 0) 6144 t
'''
 for offset in range(0,len(raw),512):s+=f'  let t := chunk{offset//512} t\n'
 s+=f'''  let t := store64 (Guest.Launcher.control+256) {len(raw)} t
  let t := store64 (Guest.Launcher.trust 0) 1 t
  let t := copy (Guest.Launcher.stage+128) (Guest.Launcher.trust 0+8) 32 t
  let t := copy (Guest.Launcher.stage+576) (Guest.Launcher.trust 0+40) 32 t
  let t := copy (Guest.Launcher.stage+96) (Guest.Launcher.trust 0+296) 32 t
  let t := Guest.Launcher.resetStageVerification t
  if !Guest.Launcher.validate t then 1 else
  if load64 Guest.Launcher.verificationCache t != 1 then 2 else
  -- The successful cache path must avoid invoking the crypto owner again.
  -- Ed25519 clears this private scratch sentinel when it executes.
  let t := store64 0x6b0000 0x1122334455667788 t
  if !Guest.Launcher.validate t || load64 0x6b0000 t != 0x1122334455667788 then 3 else
  let original := load8 (Guest.Launcher.stage+608) t
  let t := store8 (Guest.Launcher.stage+608) (original ^^^ 1) t
  if Guest.Launcher.validate t then 4 else
  let t := store8 (Guest.Launcher.stage+608) original t
  -- Same public publisher ID with substituted trust-key bytes cannot inherit
  -- a prior signature result: the exact selected trust key is in the cache.
  let originalKey := load8 (Guest.Launcher.trust 0+40) t
  let t := store8 (Guest.Launcher.trust 0+40) (originalKey ^^^ 1) t
  if Guest.Launcher.validate t then 5 else
  let t := store8 (Guest.Launcher.trust 0+40) originalKey t
  let t := store64 (Guest.Launcher.trust 0) 0 t
  if Guest.Launcher.validate t then 6 else
  let t := store64 (Guest.Launcher.trust 0) 1 t
  -- Replacing the signature leaves the header/release ID intact. Its complete
  -- envelope commitment must miss the cache and reject the invalid scalar.
  let saved := load8 (Guest.Launcher.stage+575) t
  let t := store8 (Guest.Launcher.stage+575) 255 t
  if Guest.Launcher.validate t then 7 else
  let t := store8 (Guest.Launcher.stage+575) saved t
  if !Guest.Launcher.validate t then 8 else
  let epoch := load64 (Guest.Launcher.control+568) t
  let t := Guest.Launcher.resetStageVerification t
  if load64 Guest.Launcher.verificationCache t != 0 ||
    load64 (Guest.Launcher.control+568) t != epoch+1 then 9 else 0
end build.Campaign010ReleaseCache
'''
 return s


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--release',type=Path,required=True);p.add_argument('--backend',action='append',choices=('qemu','x86_64','aarch64'));a=p.parse_args()
 raw=a.release.read_bytes();info=releases.inspect(raw,raw[576:608])
 if releases.release_prefix(raw)!=608:raise ValueError('requires actual native Ed25519 release')
 live_build.compile_module('Guest.Launcher');native.B=ROOT/'build/campaign010-release-cache'
 binary=native.build(source(raw),'Campaign010ReleaseCache')
 record=dict(schema=1,release_id=info['release_id'],release_sha256=hashlib.sha256(raw).hexdigest(),image_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),checks=[native.execute(binary,b) for b in a.backend or ['qemu']],behavior=['initial actual guest Ed25519 signature verified','unchanged exact stage uses verified cache','changed artifact, signature and selected trust key refused','current trust revocation checked despite cached signature','new staging epoch invalidates cache'],limits='Focused compiled Launcher predicate execution on actual public guest-signed bytes; fixture creates no live application authority or install approval.')
 (native.B/'execution.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))


if __name__=='__main__':main()
