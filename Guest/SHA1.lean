import Guest.Primitives
namespace Guest.SHA1
-- FIPS180-4 SHA-1 exclusively for the ordinary Tor relay rolling digest.
-- Caller-owned incremental context128 bytes; scratch704, disjoint input/output.
def mask : UInt64 := 0xffffffff
def rotl (x n : UInt64) : UInt64 := ((x <<< n) ||| (x >>> (32-n))) &&& mask
partial def zero (p n t : UInt64) : UInt64 :=
  if n == 0 then t else zero (p+1) (n-1) (store8 p 0 t)
def init (c t : UInt64) : UInt64 :=
  let t := zero c 128 t
  let t := store64 c 0x67452301 t
  let t := store64 (c+8) 0xefcdab89 t
  let t := store64 (c+16) 0x98badcfe t
  let t := store64 (c+24) 0x10325476 t
  store64 (c+32) 0xc3d2e1f0 t
partial def words (c s i t : UInt64) : UInt64 :=
  if i == 16 then t else
    let p := c+56+i*4
    let v := (load8 p t <<< 24) ||| (load8 (p+1) t <<< 16) ||| (load8 (p+2) t <<< 8) ||| load8 (p+3) t
    words c s (i+1) (store64 (s+i*8) v t)
partial def expand (s i t : UInt64) : UInt64 :=
  if i == 80 then t else
    let v := load64 (s+(i-3)*8) t ^^^ load64 (s+(i-8)*8) t ^^^ load64 (s+(i-14)*8) t ^^^ load64 (s+(i-16)*8) t
    expand s (i+1) (store64 (s+i*8) (rotl v 1) t)
partial def stateCopy (c s i t : UInt64) : UInt64 :=
  if i == 5 then t else stateCopy c s (i+1) (store64 (s+640+i*8) (load64 (c+i*8) t) t)
partial def rounds (s i t : UInt64) : UInt64 :=
  if i == 80 then t else
    let a := load64 (s+640) t
    let b := load64 (s+648) t
    let c := load64 (s+656) t
    let d := load64 (s+664) t
    let e := load64 (s+672) t
    let f := if i < 20 then (b &&& c) ||| ((b ^^^ mask) &&& d) else if i < 40 then b ^^^ c ^^^ d else if i < 60 then (b &&& c) ||| (b &&& d) ||| (c &&& d) else b ^^^ c ^^^ d
    let k := if i < 20 then 0x5a827999 else if i < 40 then 0x6ed9eba1 else if i < 60 then 0x8f1bbcdc else 0xca62c1d6
    let v := (rotl a 5+f+e+k+load64 (s+i*8) t) &&& mask
    let t := store64 (s+640) v t
    let t := store64 (s+648) a t
    let t := store64 (s+656) (rotl b 30) t
    let t := store64 (s+664) c t
    rounds s (i+1) (store64 (s+672) d t)
partial def combine (c s i t : UInt64) : UInt64 :=
  if i == 5 then t else combine c s (i+1) (store64 (c+i*8) ((load64 (c+i*8) t+load64 (s+640+i*8) t) &&& mask) t)
def compress (c s t : UInt64) : UInt64 := combine c s 0 (rounds s 0 (stateCopy c s 0 (expand s 16 (words c s 0 t))))
def byte (c s value t : UInt64) : UInt64 :=
  let used := load64 (c+48) t
  let t := store8 (c+56+used) value t
  let t := store64 (c+40) (load64 (c+40) t+1) t
  if used == 63 then store64 (c+48) 0 (compress c s t) else store64 (c+48) (used+1) t
partial def updateLoop (c s data n i t : UInt64) : UInt64 :=
  if i == n then t else updateLoop c s data n (i+1) (byte c s (load8 (data+i) t) t)
def update (c s data n t : UInt64) : UInt64 := updateLoop c s data n 0 t
partial def pad (c s t : UInt64) : UInt64 :=
  if load64 (c+48) t == 56 then t else pad c s (byte c s 0 t)
partial def lengthBytes (c s bits i t : UInt64) : UInt64 :=
  if i == 8 then t else lengthBytes c s bits (i+1) (byte c s ((bits >>> ((7-i)*8)) &&& 255) t)
partial def output (c out i t : UInt64) : UInt64 :=
  if i == 20 then t else output c out (i+1) (store8 (out+i) ((load64 (c+(i/4)*8) t >>> ((3-i%4)*8)) &&& 255) t)
def finish (c s out t : UInt64) : UInt64 :=
  let bits := load64 (c+40) t*8
  let t := pad c s (byte c s 128 t)
  output c out 0 (lengthBytes c s bits 0 t)
-- Scratch is actually704 bytes:80 UInt64 schedule words + five round words.
def hash (c s data n out t : UInt64) : UInt64 := finish c s out (update c s data n (init c t))
end Guest.SHA1
