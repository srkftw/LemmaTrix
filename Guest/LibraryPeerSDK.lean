import Guest.NetworkSDK
namespace Guest.LibraryPeerSDK
open Guest.LiveSDK
-- LibraryPeer-v1 is carried only by authenticated Network-v2 operation2.
-- A remote protocol ID is never a local capability. A grant binds the selected
-- federation/content manifest commitment and the caller incarnation separately.
def magic : UInt64 := 0x31524545504c544c
def maxData : UInt64 := 640
def data : UInt64 := wire+128
def grant (slot pins stream budget lifetime t : UInt64) : UInt64 :=
  let t := zero chunk 8 t
  let t := store64 chunk 3 t
  let t := store64 (chunk+8) Guest.NetworkSDK.encryptedBulk t
  let t := store64 (chunk+16) budget t
  let t := store64 (chunk+24) 65536 t
  let t := store64 (chunk+32) lifetime t
  let t := store64 (chunk+40) 2 t
  let t := store64 (chunk+48) stream t
  Guest.NetworkSDK.grantPeer slot pins chunk t
def request (slot grantHandle requestId operation h a b t : UInt64) : UInt64 :=
  if requestId == 0 || operation == 0 || operation > 6 then error else
  let t := zero chunk 8 t
  let t := store64 chunk magic t
  let t := store64 (chunk+8) 1 t
  let t := store64 (chunk+16) operation t
  let t := store64 (chunk+24) h t
  let t := store64 (chunk+32) a t
  let t := store64 (chunk+40) b t
  Guest.NetworkSDK.sendPeer slot grantHandle 2 requestId chunk 64 t
def receive (slot grantHandle t : UInt64) : UInt64 := Guest.NetworkSDK.receivePeer slot grantHandle t
def valid (operation requestId received : UInt64) : Bool :=
  received >= 128 && received <= 768 && status received == 0 &&
  load64 (wire+16) received == received-64 && load64 (wire+24) received == requestId &&
  load64 (wire+64) received == magic && load64 (wire+72) received == 1 &&
  load64 (wire+80) received == operation && load64 (wire+96) received == requestId
def remoteStatus (t : UInt64) : UInt64 := load64 (wire+88) t
def total (t : UInt64) : UInt64 := load64 (wire+104) t
def resultId (t : UInt64) : UInt64 := load64 (wire+112) t
def next (t : UInt64) : UInt64 := load64 (wire+120) t
end Guest.LibraryPeerSDK
