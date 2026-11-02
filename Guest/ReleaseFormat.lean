import Guest.LiveMemory
import Guest.ServiceSignature
import Guest.Ed25519
namespace Guest.ReleaseFormat
open Guest.LiveMemory
-- Release-v2 is byte-for-byte the RSA2048 format. Release-v4 is a different,
-- non-fallback pure-Ed25519 profile: header512, signature64, public key32.
-- No certificate envelope, Ed25519ph or self-referential release commitment.
def header (p t : UInt64) : UInt64 :=
  if load64 p t == 0x3253454c544c && (load64 (p+8) t == 2 || load64 (p+8) t == 4) &&
    load64 (p+16) t == 512 then 512 else 0
def «prefix» (p t : UInt64) : UInt64 :=
  if header p t == 0 then 0 else if load64 (p+8) t == 2 then 768 else 608
partial def zeros (p n t : UInt64) : Bool :=
  if n == 0 then true else load8 p t == 0 && zeros (p+1) (n-1) t
partial def nameValid (p i n t : UInt64) : Bool :=
  if i == n then true else
  let c := load8 (p+i) t
  ((c >= 97 && c <= 122) || (c >= 48 && c <= 57) ||
    (i > 0 && (c == 45 || c == 46 || c == 95))) && nameValid p (i+1) n t
def executable (p t : UInt64) : Bool :=
  header p t != 0 && (load64 (p+8) t == 2 || load64 (p+384) t == 1)
def validHeader (p t : UInt64) : Bool :=
  let n := load64 (p+424) t
  let legacy := load64 (p+8) t == 2
  let native := executable p t
  let profile := load64 (p+400) t
  header p t == 512 && load64 (p+64) t <= 8191 &&
  load64 (p+72) t <= 0xffffffff && load64 (p+80) t <= 0xffffffff && load64 (p+88) t <= 0xffffffff &&
  n > 0 && n <= 48 && nameValid (p+432) 0 n t && zeros (p+432+n) (48-n) t && zeros (p+496) 16 t &&
  (if legacy then load64 (p+384) t == 0 && load64 (p+392) t == 0 && load64 (p+480) t == 65537 &&
      (load64 (p+488) t == 0 || load64 (p+488) t == 3)
    else (load64 (p+384) t == 1 || load64 (p+384) t == 2) && load64 (p+392) t > 0 &&
      load64 (p+392) t <= 0xffffffff && load64 (p+480) t == 1 && load64 (p+488) t == 4 &&
      !zeros (p+96) 32 t && !zeros (p+128) 32 t && !zeros (p+224) 32 t &&
      !zeros (p+256) 32 t && !zeros (p+320) 32 t && !zeros (p+352) 32 t) &&
  load64 (p+40) t == 2 && load64 (p+48) t == 2 && load64 (p+56) t == 2 &&
  (if native then
    load64 (p+24) t > 0 && load64 (p+24) t <= (if profile == 2 then 262144 else 65536) &&
    load64 (p+24) t%4 == 0 && (profile == 1 || profile == 2) &&
    load64 (p+32) t == (if profile == 2 then 0x200000 else 0x400000) &&
    load64 (p+408) t == 65536+(if profile == 2 then 2097152 else 0) && load64 (p+416) t == 16384
   else load64 (p+24) t == 0 && load64 (p+32) t == 0 && load64 (p+64) t == 0 &&
    profile == 0 && load64 (p+408) t == 0 && load64 (p+416) t == 0 && zeros (p+192) 32 t)
-- The terminating NUL is part of the domain. Exactly22+512 bytes are signed.
def messageLength : UInt64 := 534
def signedMessage (p out t : UInt64) : UInt64 :=
  let t := store64 out 0x454a4f52502d544c t
  let t := store64 (out+8) 0x41454c45522d5443 t
  let t := store64 (out+16) 0x31562d4553 t
  copy p (out+22) 512 t
-- Scratch is private to the serialized service. Preserve Noise multiplication
-- scratch because the Launcher uses the same physical range for replay bytes.
def verify (p trustedKey t : UInt64) : Bool :=
  if !validHeader p t then false else
  if load64 (p+8) t == 2 then Guest.ServiceSignature.verify p 512 (p+512) trustedKey t else
  if !equal trustedKey (p+576) 32 t then false else
  let t := Guest.ServiceHash.sha256At 0x600200 trustedKey 32 0x603300 t
  if !equal 0x603300 (p+96) 32 t then false else
  let t := copy 0x632000 0x603400 256 t
  let t := signedMessage p 0x603000 t
  let valid := Guest.Ed25519.verify trustedKey 0x603000 messageLength (p+512) t
  let t := copy 0x603400 0x632000 256 t
  Guest.Effects.effectValue (if valid then 1 else 0) t == 1
end Guest.ReleaseFormat
