import Guest.LiveSDK
namespace Guest.NetworkSDK
open Guest.LiveSDK
-- Explicit mode contract. Only encryptedBulk is implemented in profile1.
def interactiveOnion : UInt64 := 1
def delayedMix : UInt64 := 2
def encryptedBulk : UInt64 := 3
def privateCluster : UInt64 := 4
def modeAvailable (mode : UInt64) : Bool := mode == encryptedBulk
theorem privacy_modes_fail_closed : modeAvailable interactiveOnion = false ∧ modeAvailable delayedMix = false ∧ modeAvailable privateCluster = false := by decide
def maxPayload : UInt64 := 720
def callNetwork (length t : UInt64) : UInt64 := syscall 30 6 wire length 1024 t
-- Provisioning buffer holds ordered clientID/serverID/serviceID/PSK,32 bytes each.
-- Management-only; the PSK is never returned in status or normal IPC output.
def configure (role provisioning t : UInt64) : UInt64 :=
  let t := header 1 0 role 0 0 0 0 t
  callNetwork 192 (copy provisioning (wire+64) 128 t)
-- pins=peerID32/serviceID32/rootID32; operation1..16 has separate grants.
def grant (pins direction mode budget rate lifetime operation t : UInt64) : UInt64 :=
  let t := header 2 0 direction mode budget rate lifetime t
  let t := copy pins (wire+64) 96 t
  callNetwork 168 (store64 (wire+160) operation t)
def send (grantHandle operation source length t : UInt64) : UInt64 :=
  if length > maxPayload then error else
    let t := header 3 grantHandle operation 0 0 0 0 t
    callNetwork (64+length) (copy source (wire+64) length t)
def poll (job t : UInt64) : UInt64 := callNetwork 64 (header 4 job 0 0 0 0 0 t)
def cancel (job t : UInt64) : UInt64 := callNetwork 64 (header 5 job 0 0 0 0 0 t)
def receive (grantHandle t : UInt64) : UInt64 := callNetwork 64 (header 6 grantHandle 0 0 0 0 0 t)
def inspect (t : UInt64) : UInt64 := callNetwork 64 (header 7 0 0 0 0 0 0 t)
def revoke (grantHandle t : UInt64) : UInt64 := callNetwork 64 (header 8 grantHandle 0 0 0 0 0 t)
def nonce (t : UInt64) : UInt64 := callNetwork 64 (header 10 0 0 0 0 0 0 t)
def reset (t : UInt64) : UInt64 := callNetwork 64 (header 9 0 0 0 0 0 0 t)
-- V2 context selection is explicit on every request, never ambient process
-- state. slot0..3 are independent enrollments. V1 retains legacy stream0.
def version2 (slot t : UInt64) : UInt64 := store64 (wire+56) ((2 : UInt64) ||| (slot <<< 8)) t
def callPeer (slot length t : UInt64) : UInt64 :=
  if slot >= 4 then error else callNetwork length (version2 slot t)
def configurePeer (slot role provisioning t : UInt64) : UInt64 :=
  let t := header 1 0 role 0 0 0 0 t
  callPeer slot 192 (copy provisioning (wire+64) 128 t)
def openPeer (slot t : UInt64) : UInt64 := callPeer slot 64 (header 13 0 0 0 0 0 0 t)
def removePeer (slot t : UInt64) : UInt64 := callPeer slot 64 (header 14 0 0 0 0 0 0 t)
def describePeer (slot t : UInt64) : UInt64 := callPeer slot 64 (header 15 0 0 0 0 0 0 t)
def inspectPeer (slot t : UInt64) : UInt64 := callPeer slot 64 (header 7 0 0 0 0 0 0 t)
-- policy is seven words: direction,positive-mode,budget,rate,lifetime,
-- operation,stream. A pointer keeps the freestanding eight-register ABI.
def grantPeer (slot pins policy t : UInt64) : UInt64 :=
  let t := header 2 0 (load64 policy t) (load64 (policy+8) t) (load64 (policy+16) t) (load64 (policy+24) t) (load64 (policy+32) t) t
  let t := copy pins (wire+64) 96 t
  let t := store64 (wire+160) (load64 (policy+40) t) t
  callPeer slot 176 (store64 (wire+168) (load64 (policy+48) t) t)
def sendPeer (slot grantHandle operation request source length t : UInt64) : UInt64 :=
  if length > 704 || request == 0 then error else
    let t := header 3 grantHandle operation request 0 0 0 t
    callPeer slot (64+length) (copy source (wire+64) length t)
def receivePeer (slot grantHandle t : UInt64) : UInt64 := callPeer slot 64 (header 6 grantHandle 0 0 0 0 0 t)
def revokePeer (slot grantHandle t : UInt64) : UInt64 := callPeer slot 64 (header 8 grantHandle 0 0 0 0 0 t)
def pollPeer (slot job t : UInt64) : UInt64 := callPeer slot 64 (header 4 job 0 0 0 0 0 t)
def cancelPeer (slot job t : UInt64) : UInt64 := callPeer slot 64 (header 5 job 0 0 0 0 0 t)
end Guest.NetworkSDK
