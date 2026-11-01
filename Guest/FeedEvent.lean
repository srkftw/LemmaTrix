import Guest.LiveSDK
import Guest.Ed25519
import Guest.ServiceHash
namespace Guest.FeedEvent
open Guest.LiveSDK
-- Original Identity certificate framing, never a federation re-signature.
def magic : UInt64 := 0x3144564546544c
def signingMagic : UInt64 := 0x31474953544c
def envelopeBytes : UInt64 := 480
def bodyBytes : UInt64 := 256
def maxContent : UInt64 := 16384
def hashScratch : UInt64 := 0x6d0000
def digest : UInt64 := 0x6d1000
def eq (a b n t : UInt64) : Bool := Guest.Ed25519.difference a b n 0 t == 0
def nonzero (p n t : UInt64) : Bool := Guest.Ed25519.nonzero p n 0 t != 0
def zeroed (p n t : UInt64) : Bool := !nonzero p n t
def bodyValid (p t : UInt64) : Bool :=
  let kind := load64 (p+16) t
  load64 p t == magic && load64 (p+8) t == 1 && kind > 0 && kind <= 9 &&
  load64 (p+24) t > 0 && nonzero (p+64) 32 t &&
  load64 (p+96) t <= maxContent && nonzero (p+112) 32 t && load64 (p+248) t == 0 &&
  (kind != 2 || nonzero (p+32) 32 t) &&
  (kind != 3 || nonzero (p+176) 32 t) &&
  ((kind != 4 && kind != 5 && kind != 6 && kind != 7 && kind != 8) || nonzero (p+208) 32 t) &&
  ((kind != 6 && kind != 7 && kind != 8) || zeroed (p+144) 32 t) &&
  (kind != 8 || (load64 (p+240) t >= 1 && load64 (p+240) t <= 3))
def framingValid (p t : UInt64) : Bool :=
  let role := load64 (p+16) t
  let purpose := load64 (p+24) t
  load64 p t == signingMagic && load64 (p+8) t == 1 &&
  ((role == 5 && purpose == 4 && load64 (p+176) t != 8) ||
   (role == 6 && purpose == 5 && load64 (p+176) t == 8)) &&
  load64 (p+32) t > 0 && load64 (p+40) t == bodyBytes && nonzero (p+112) 32 t &&
  zeroed (p+144) 16 t && eq (p+48) (p+272) 32 t && bodyValid (p+160) t
-- The verifier preserves the exact original signed480 bytes. Author-provided
-- time is display metadata, never used as an admission or ordering clock.
def valid (p t : UInt64) : Bool :=
  framingValid p t && Guest.Ed25519.verify (p+112) p 416 (p+416) t
partial def utf8 (p n i remaining lower upper t : UInt64) : Bool :=
  if i == n then remaining == 0 else
  let c := load8 (p+i) t
  if remaining != 0 then
    c >= lower && c <= upper && utf8 p n (i+1) (remaining-1) 128 191 t
  else if c == 10 || c == 9 || (c >= 32 && c <= 126) then utf8 p n (i+1) 0 0 0 t
  else if c >= 194 && c <= 223 then utf8 p n (i+1) 1 128 191 t
  else if c == 224 then utf8 p n (i+1) 2 160 191 t
  else if c >= 225 && c <= 236 then utf8 p n (i+1) 2 128 191 t
  else if c == 237 then utf8 p n (i+1) 2 128 159 t
  else if c >= 238 && c <= 239 then utf8 p n (i+1) 2 128 191 t
  else if c == 240 then utf8 p n (i+1) 3 144 191 t
  else if c >= 241 && c <= 243 then utf8 p n (i+1) 3 128 191 t
  else if c == 244 then utf8 p n (i+1) 3 128 143 t
  else false
def contentValid (event content n t : UInt64) : Bool :=
  if n != load64 (event+256) t || n > maxContent || !utf8 content n 0 0 0 0 t then false else
  let t := Guest.ServiceHash.sha256At hashScratch content n digest t
  eq digest (event+224) 32 t
def identity (event out t : UInt64) : UInt64 := Guest.ServiceHash.sha256At hashScratch event envelopeBytes out t
def scopePermits (home peer audienceHome audiencePeer : Bool) : Bool :=
  (home && audienceHome) || (peer && audiencePeer)
theorem no_scope_no_replication : scopePermits false false true true = false := by decide
theorem different_scope_denied : scopePermits true false false true = false := by decide
end Guest.FeedEvent
