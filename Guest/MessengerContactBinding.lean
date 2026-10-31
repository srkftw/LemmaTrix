import Guest.LiveSDK
import Guest.Ed25519
import Guest.ServiceHash
namespace Guest.MessengerContactBinding
open Guest.LiveSDK
-- Public contact certification is independent of the XEdDSA identity and SPK
-- signature. It binds the stable messaging IK, device and selected federation.
-- SHA256(IK32 || federation32 || device32) is the displayed device fingerprint.
def work : UInt64 := 0x65a000
def eq (a b n t : UInt64) : Bool := Guest.Ed25519.difference a b n 0 t == 0
def nonzero (p n t : UInt64) : Bool := Guest.Ed25519.nonzero p n 0 t != 0
def refreshAllowed (existingBound incomingBound exactCertificate : Bool) : Bool :=
  !existingBound || (incomingBound && exactCertificate)
theorem bound_downgrade_denied (exact : Bool) : refreshAllowed true false exact = false := by
  simp [refreshAllowed]
theorem bound_substitution_denied : refreshAllowed true true false = false := by
  decide
def fingerprint (bundle out t : UInt64) : UInt64 :=
  let t := copy (bundle+32) work 32 t
  let t := copy (bundle+192) (work+32) 64 t
  Guest.ServiceHash.sha256At (work+256) work 96 out t
def valid (certificate bundle t : UInt64) : Bool :=
  let t := fingerprint bundle (work+128) t
  load64 certificate t == 0x31474953544c && load64 (certificate+8) t == 1 &&
  load64 (certificate+16) t == 2 && load64 (certificate+24) t == 1 &&
  load64 (certificate+32) t > 0 && load64 (certificate+40) t == 128 &&
  eq (certificate+48) (bundle+192) 32 t && nonzero (certificate+80) 32 t &&
  nonzero (certificate+112) 32 t && !nonzero (certificate+144) 16 t &&
  load64 (certificate+160) t == 0x315443544c && load64 (certificate+168) t == 1 &&
  load64 (certificate+176) t == load64 (bundle+16) t && load64 (bundle+16) t > 0 &&
  load64 (certificate+184) t == 1 && eq (certificate+192) (bundle+32) 32 t &&
  eq (certificate+224) (bundle+224) 32 t && eq (certificate+256) (work+128) 32 t &&
  Guest.Ed25519.verify (certificate+112) certificate 288 (certificate+288) t
def clear (t : UInt64) : UInt64 := zero work 128 t
end Guest.MessengerContactBinding
