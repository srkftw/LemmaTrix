import Guest.Primitives
namespace Guest.SHA512
-- SHA-512, FIPS 180-4 / RFC6234 sections 5.3 and 6.4.
-- Caller-selected private serialized scratch: 768 bytes; input <=262144 bytes.
def work (scratch : UInt64) : UInt64 := scratch
def hashState (scratch : UInt64) : UInt64 := scratch+640
def roundState (scratch : UInt64) : UInt64 := scratch+704
def mask : UInt64 := 0xffffffffffffffff
def rotr (x n : UInt64) : UInt64 := (x >>> n) ||| (x <<< (64-n))
def k (i : UInt64) : UInt64 :=
  if i == 0 then 0x428a2f98d728ae22 else
  if i == 1 then 0x7137449123ef65cd else
  if i == 2 then 0xb5c0fbcfec4d3b2f else
  if i == 3 then 0xe9b5dba58189dbbc else
  if i == 4 then 0x3956c25bf348b538 else
  if i == 5 then 0x59f111f1b605d019 else
  if i == 6 then 0x923f82a4af194f9b else
  if i == 7 then 0xab1c5ed5da6d8118 else
  if i == 8 then 0xd807aa98a3030242 else
  if i == 9 then 0x12835b0145706fbe else
  if i == 10 then 0x243185be4ee4b28c else
  if i == 11 then 0x550c7dc3d5ffb4e2 else
  if i == 12 then 0x72be5d74f27b896f else
  if i == 13 then 0x80deb1fe3b1696b1 else
  if i == 14 then 0x9bdc06a725c71235 else
  if i == 15 then 0xc19bf174cf692694 else
  if i == 16 then 0xe49b69c19ef14ad2 else
  if i == 17 then 0xefbe4786384f25e3 else
  if i == 18 then 0x0fc19dc68b8cd5b5 else
  if i == 19 then 0x240ca1cc77ac9c65 else
  if i == 20 then 0x2de92c6f592b0275 else
  if i == 21 then 0x4a7484aa6ea6e483 else
  if i == 22 then 0x5cb0a9dcbd41fbd4 else
  if i == 23 then 0x76f988da831153b5 else
  if i == 24 then 0x983e5152ee66dfab else
  if i == 25 then 0xa831c66d2db43210 else
  if i == 26 then 0xb00327c898fb213f else
  if i == 27 then 0xbf597fc7beef0ee4 else
  if i == 28 then 0xc6e00bf33da88fc2 else
  if i == 29 then 0xd5a79147930aa725 else
  if i == 30 then 0x06ca6351e003826f else
  if i == 31 then 0x142929670a0e6e70 else
  if i == 32 then 0x27b70a8546d22ffc else
  if i == 33 then 0x2e1b21385c26c926 else
  if i == 34 then 0x4d2c6dfc5ac42aed else
  if i == 35 then 0x53380d139d95b3df else
  if i == 36 then 0x650a73548baf63de else
  if i == 37 then 0x766a0abb3c77b2a8 else
  if i == 38 then 0x81c2c92e47edaee6 else
  if i == 39 then 0x92722c851482353b else
  if i == 40 then 0xa2bfe8a14cf10364 else
  if i == 41 then 0xa81a664bbc423001 else
  if i == 42 then 0xc24b8b70d0f89791 else
  if i == 43 then 0xc76c51a30654be30 else
  if i == 44 then 0xd192e819d6ef5218 else
  if i == 45 then 0xd69906245565a910 else
  if i == 46 then 0xf40e35855771202a else
  if i == 47 then 0x106aa07032bbd1b8 else
  if i == 48 then 0x19a4c116b8d2d0c8 else
  if i == 49 then 0x1e376c085141ab53 else
  if i == 50 then 0x2748774cdf8eeb99 else
  if i == 51 then 0x34b0bcb5e19b48a8 else
  if i == 52 then 0x391c0cb3c5c95a63 else
  if i == 53 then 0x4ed8aa4ae3418acb else
  if i == 54 then 0x5b9cca4f7763e373 else
  if i == 55 then 0x682e6ff3d6b2b8a3 else
  if i == 56 then 0x748f82ee5defb2fc else
  if i == 57 then 0x78a5636f43172f60 else
  if i == 58 then 0x84c87814a1f0ab72 else
  if i == 59 then 0x8cc702081a6439ec else
  if i == 60 then 0x90befffa23631e28 else
  if i == 61 then 0xa4506cebde82bde9 else
  if i == 62 then 0xbef9a3f7b2c67915 else
  if i == 63 then 0xc67178f2e372532b else
  if i == 64 then 0xca273eceea26619c else
  if i == 65 then 0xd186b8c721c0c207 else
  if i == 66 then 0xeada7dd6cde0eb1e else
  if i == 67 then 0xf57d4f7fee6ed178 else
  if i == 68 then 0x06f067aa72176fba else
  if i == 69 then 0x0a637dc5a2c898a6 else
  if i == 70 then 0x113f9804bef90dae else
  if i == 71 then 0x1b710b35131c471b else
  if i == 72 then 0x28db77f523047d84 else
  if i == 73 then 0x32caab7b40c72493 else
  if i == 74 then 0x3c9ebe0a15c9bebc else
  if i == 75 then 0x431d67c49c100d4c else
  if i == 76 then 0x4cc5d4becb3e42b6 else
  if i == 77 then 0x597f299cfc657e2a else
  if i == 78 then 0x5fcb6fab3ad6faec else
  if i == 79 then 0x6c44198c4a475817 else
  0
def initialState (scratch : UInt64) (t : UInt64) : UInt64 :=
  let t := store64 (hashState scratch) 0x6a09e667f3bcc908 t
  let t := store64 ((hashState scratch)+8) 0xbb67ae8584caa73b t
  let t := store64 ((hashState scratch)+16) 0x3c6ef372fe94f82b t
  let t := store64 ((hashState scratch)+24) 0xa54ff53a5f1d36f1 t
  let t := store64 ((hashState scratch)+32) 0x510e527fade682d1 t
  let t := store64 ((hashState scratch)+40) 0x9b05688c2b3e6c1f t
  let t := store64 ((hashState scratch)+48) 0x1f83d9abfb41bd6b t
  store64 ((hashState scratch)+56) 0x5be0cd19137e2179 t
def messageByte (_scratch : UInt64) (data len total offset t : UInt64) : UInt64 :=
  if offset < len then load8 (data+offset) t
  else if offset == len then 128
  else if offset >= total-8 then ((len*8) >>> ((total-1-offset)*8)) &&& 255
  else 0
partial def wordBytes (data len total p i value t : UInt64) : UInt64 :=
  if i == 8 then value else wordBytes data len total p (i+1) ((value <<< 8) ||| messageByte 0 data len total (p+i) t) t
partial def firstWords (scratch data len total block i t : UInt64) : UInt64 :=
  if i == 16 then t else
    let w := wordBytes data len total (block*128+i*8) 0 0 t
    firstWords scratch data len total block (i+1) (store64 ((work scratch)+i*8) w t)
partial def expandWords (scratch : UInt64) (i t : UInt64) : UInt64 :=
  if i == 80 then t else
    let a := load64 ((work scratch)+(i-15)*8) t
    let b := load64 ((work scratch)+(i-2)*8) t
    let s0 := rotr a 1 ^^^ rotr a 8 ^^^ (a >>> 7)
    let s1 := rotr b 19 ^^^ rotr b 61 ^^^ (b >>> 6)
    let w := (load64 ((work scratch)+(i-16)*8) t + s0 + load64 ((work scratch)+(i-7)*8) t + s1) &&& mask
    expandWords scratch (i+1) (store64 ((work scratch)+i*8) w t)
partial def initRound (scratch : UInt64) (i t : UInt64) : UInt64 :=
  if i == 8 then t else
    initRound scratch (i+1) (store64 ((roundState scratch)+i*8) (load64 ((hashState scratch)+i*8) t) t)
partial def rounds (scratch : UInt64) (i t : UInt64) : UInt64 :=
  if i == 80 then t else
    let a := load64 (roundState scratch) t
    let b := load64 ((roundState scratch)+8) t
    let c := load64 ((roundState scratch)+16) t
    let d := load64 ((roundState scratch)+24) t
    let e := load64 ((roundState scratch)+32) t
    let f := load64 ((roundState scratch)+40) t
    let g := load64 ((roundState scratch)+48) t
    let h := load64 ((roundState scratch)+56) t
    let big1 := rotr e 14 ^^^ rotr e 18 ^^^ rotr e 41
    let ch := (e &&& f) ^^^ ((e ^^^ mask) &&& g)
    let temp1 := (h+big1+ch+k i+load64 ((work scratch)+i*8) t) &&& mask
    let big0 := rotr a 28 ^^^ rotr a 34 ^^^ rotr a 39
    let maj := (a &&& b) ^^^ (a &&& c) ^^^ (b &&& c)
    let temp2 := (big0+maj) &&& mask
    let t := store64 (roundState scratch) ((temp1+temp2) &&& mask) t
    let t := store64 ((roundState scratch)+8) a t
    let t := store64 ((roundState scratch)+16) b t
    let t := store64 ((roundState scratch)+24) c t
    let t := store64 ((roundState scratch)+32) ((d+temp1) &&& mask) t
    let t := store64 ((roundState scratch)+40) e t
    let t := store64 ((roundState scratch)+48) f t
    let t := store64 ((roundState scratch)+56) g t
    rounds scratch (i+1) t
partial def combine (scratch : UInt64) (i t : UInt64) : UInt64 :=
  if i == 8 then t else
    let v := (load64 ((hashState scratch)+i*8) t+load64 ((roundState scratch)+i*8) t) &&& mask
    combine scratch (i+1) (store64 ((hashState scratch)+i*8) v t)
partial def blocks (scratch : UInt64) (data len total i n t : UInt64) : UInt64 :=
  if i == n then t else
    let t := firstWords scratch data len total i 0 t
    let t := expandWords scratch 16 t
    let t := initRound scratch 0 t
    let t := rounds scratch 0 t
    let t := combine scratch 0 t
    blocks scratch data len total (i+1) n t
partial def outputBytes (scratch : UInt64) (out i t : UInt64) : UInt64 :=
  if i == 64 then t else
    let w := load64 ((hashState scratch)+(i/8)*8) t
    let b := (w >>> ((7-i%8)*8)) &&& 255
    outputBytes scratch out (i+1) (store8 (out+i) b t)
/-- Returns an effect token on success, all ones if len > 262144 (without writing memory).
    Callers validate physical input/output extents and serialize access to fixed scratch. -/
def sha512At (scratch : UInt64) (data len out t : UInt64) : UInt64 :=
  if len > 262144 then 0xffffffffffffffff else
    let n := (len+144)/128
    let t := initialState scratch t
    let t := blocks scratch data len (n*128) 0 n t
    outputBytes scratch out 0 t
def sha512 (data len out t : UInt64) : UInt64 := sha512At 0x644000 data len out t
end Guest.SHA512
