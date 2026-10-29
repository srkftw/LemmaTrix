import Guest.Noise25519
namespace Guest.NetworkCryptoChecks
partial def equal (a b n t : UInt64) : Bool :=
  if n == 0 then true else if Guest.load8 a t != Guest.load8 b t then false else equal (a+1) (b+1) (n-1) t
-- RFC7748 section6.1 Alice's private key and Bob's public key.
def x25519 (initial : UInt64) : UInt64 :=
  let p : UInt64 := 0x640000
  let t := Guest.store64 p 0x7da518730a6d0777 initial
  let t := Guest.store64 (p+8) 0x4566b25172c1163c t
  let t := Guest.store64 (p+16) 0x2a99c0eb872f4cdf t
  let t := Guest.store64 (p+24) 0x2a2cb91da5fb77b1 t
  let t := Guest.store64 (p+32) 0xb4c17d7b7ddb9ede t
  let t := Guest.store64 (p+40) 0x3735e4ecc2615bd3 t
  let t := Guest.store64 (p+48) 0x4d67785bc843833f t
  let t := Guest.store64 (p+56) 0x4f2b886f147efcad t
  let t := Guest.store64 (p+96) 0xe12dcea45b9d5d4a t
  let t := Guest.store64 (p+104) 0x250f3580f43b8e72 t
  let t := Guest.store64 (p+112) 0x339ed147c9217ee0 t
  let t := Guest.store64 (p+120) 0x4217161e3c9bf076 t
  let t := Guest.Noise25519.x25519 p (p+32) (p+64) t
  -- Expected output populated by harness; no host implementation computes guest result.
  if equal (p+64) (p+96) 32 t then 0 else 1
end Guest.NetworkCryptoChecks
