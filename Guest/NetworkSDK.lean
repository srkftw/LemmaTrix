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
end Guest.NetworkSDK
