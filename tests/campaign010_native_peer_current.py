"""Emitted nativePeerCurrent checks over public prevalidated enrollment state.

This fixture supplies only active/revoked public enrollment records and frozen
certificate digests. It performs no certificate signature verification, grant
renewal, live transport, actor operation or expiry-clock simulation. The actual
peerValid predicate checks enrollment state and its signed revocation flag;
civil-time expiry is not a field in that predicate.
"""
import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import live_build,onion_crypto

B=ROOT/'build/campaign010-native-peer-current'
SOURCE='''import Guest.Network
namespace build.Campaign010NativePeerCurrent
open Guest Guest.LiveSDK
def stamp : UInt64 := Guest.PeerDescription.st
def own : UInt64 := Guest.NodeEnrollment.localNode
def selectedPeer : UInt64 := Guest.NodeEnrollment.peer 7
def seed (t : UInt64) : UInt64 :=
  let t := zero Guest.NodeEnrollment.base 1024 (zero own 128 (zero stamp 16 t))
  let t := store64 own 1 (store64 selectedPeer 1 (store64 (stamp+8) 8 t))
  let t := store64 (own+512) 0x1122334455667788 (store64 (own+520) 0x1020304050607080
    (store64 (own+528) 0x9080706050403020 (store64 (own+536) 0x9988776655443322 t)))
  let t := store64 (selectedPeer+512) 0x8877665544332211 (store64 (selectedPeer+520) 0x8070605040302010
    (store64 (selectedPeer+528) 0x2030405060708090 (store64 (selectedPeer+536) 0x2233445566778899 t)))
  copy (own+512) (stamp+32) 32 (copy (selectedPeer+512) (stamp+64) 32 t)
@[noinline] def check (t : UInt64) : UInt64 :=
  let t := seed t
  -- Encoded selection8 names approved peer7, not the local export sentinel.
  if !Guest.Network.nativePeerCurrent t then 1 else
  -- Even a plausible public candidate beyond the eight peers cannot pass.
  let outside := Guest.NodeEnrollment.peer 8
  let t := copy selectedPeer outside 544 (store64 (stamp+8) 9 t)
  if Guest.Network.nativePeerCurrent t then 2 else
  let t := store8 (own+543) 0xaa (seed t)
  if Guest.Network.nativePeerCurrent t then 3 else
  let t := store8 (selectedPeer+543) 0xbb (seed t)
  if Guest.Network.nativePeerCurrent t then 4 else
  let t := store8 (stamp+63) 0xaa (seed t)
  if Guest.Network.nativePeerCurrent t then 5 else
  let t := store8 (stamp+95) 0xbb (seed t)
  if Guest.Network.nativePeerCurrent t then 6 else
  let t := store64 own 0 (seed t)
  if Guest.Network.nativePeerCurrent t then 7 else
  let t := store64 selectedPeer 0 (seed t)
  if Guest.Network.nativePeerCurrent t then 8 else
  let t := store64 selectedPeer 2 (seed t)
  if Guest.Network.nativePeerCurrent t then 9 else
  let t := store64 (selectedPeer+360) 1 (seed t)
  if Guest.Network.nativePeerCurrent t then 10 else
  -- An unrelated revoked slot cannot invalidate the exact selected peer7.
  let t := store64 (Guest.NodeEnrollment.peer 0) 2 (seed t)
  if !Guest.Network.nativePeerCurrent t then 11 else
  -- Keep the original first-slot encoding and no-native-selection behavior.
  let t := copy selectedPeer (Guest.NodeEnrollment.peer 0) 544 (store64 (stamp+8) 1 t)
  if !Guest.Network.nativePeerCurrent t then 12 else
  let t := store64 own 0 (store64 selectedPeer 2 (store64 (stamp+8) 0 t))
  if !Guest.Network.nativePeerCurrent t then 13 else 0
end build.Campaign010NativePeerCurrent
'''

def main():
 sources=('Guest/Network.lean','Guest/NodeEnrollment.lean','Guest/TorRouter.lean')
 before={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest()for name in sources}
 live_build.compile_module('Guest.Network')
 onion_crypto.B=B;binary=onion_crypto.build(SOURCE,'Campaign010NativePeerCurrent')
 after={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest()for name in sources}
 if before!=after:raise RuntimeError('production source changed during focused compilation; no qualified result recorded')
 record=dict(schema=1,result='pass',image_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),image_bytes=binary.stat().st_size,production_source_sha256=after,fixture_source_sha256=hashlib.sha256(SOURCE.encode()).hexdigest(),checks=[onion_crypto.execute(binary,backend)for backend in('qemu','aarch64')],cases=13,boundaries=['encoded selection8 accepts exactly approved active peer7 and current local/peer certificate digests','selection9 refuses a plausible out-of-range public candidate','changed own or selected-peer digest refuses, including the final digest byte','changed frozen own/peer stamp refuses','inactive own or selected peer refuses','explicit revoked state2 and signed revocation flag1 each refuse','revocation of unrelated peer0 does not invalidate selected peer7','legacy first-slot and no-native-selection behavior preserved'],limitations=__doc__,environment='x86-64 Linux; RV64 QEMU and AArch64 assembly emulator under qemu-aarch64. No physical ARM hardware or full transport qualification.')
 (B/'evidence.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))
if __name__=='__main__':main()
