import Guest.Primitives
import Guest.SHA256
import Guest.Policy
import Guest.Signature
namespace Guest.Package
-- LTPKG1 development capsule: all fields little-endian UInt64; digest is SHA256 bytes.
-- RSA boot-policy signature and payload hash are checked independently; Ed25519 export metadata stays host-verified.
partial def equalDigest (a b n t : UInt64) : Bool :=
  if n == 0 then true else
    if Guest.load8 a t == Guest.load8 b t then equalDigest (a+1) (b+1) (n-1) t else false

def valid (capsule approved t : UInt64) : Bool :=
  Guest.load64 capsule t == 0x31474b50544c &&
  Guest.load64 (capsule+8) t == 1 &&
  Guest.load64 (capsule+16) t == 1 &&
  Guest.load64 (capsule+24) t == 1 &&
  Guest.load64 (capsule+32) t == 0x400000 &&
  Guest.load64 (capsule+40) t > 0 && Guest.load64 (capsule+40) t <= 65536 &&
  (Guest.load64 (capsule+48) t &&& approved) == Guest.load64 (capsule+48) t &&
  Guest.load64 (capsule+96) t == 2 &&
  Guest.load64 (capsule+104) t == 0 && Guest.load64 (capsule+112) t == 0 && Guest.load64 (capsule+120) t == 0 &&
  Guest.load64 (capsule+56) t > 0 && (Guest.load64 (capsule+40) t &&& 3) == 0 &&
  Signature.verify capsule 128 (capsule+0x10100) 0x80810000 t &&
  (let token := Hash.sha256 (capsule+128) (Guest.load64 (capsule+40) t) 0x80970000 t
   equalDigest 0x80970000 (capsule+64) 32 token)
end Guest.Package
