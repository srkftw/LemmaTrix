import Guest.Primitives
namespace Guest.ServiceHash
-- SHA-256, FIPS 180-4 algorithm and RFC 6234 section 6.2 constants.
-- Scratch is caller-selected, private, serialized ephemeral memory (640 bytes).
-- No heap, no secret keys, no signing claim. Inputs are limited to 262144 bytes.
def work (scratch : UInt64) : UInt64 := scratch
def hashState (scratch : UInt64) : UInt64 := scratch+512
def roundState (scratch : UInt64) : UInt64 := scratch+576
def mask : UInt64 := 0xffffffff
def rotr (x n : UInt64) : UInt64 := ((x >>> n) ||| (x <<< (32-n))) &&& mask

def roundConstantReference (i : UInt64) : UInt64 :=
  if i == 0 then 0x428a2f98 else
  if i == 1 then 0x71374491 else
  if i == 2 then 0xb5c0fbcf else
  if i == 3 then 0xe9b5dba5 else
  if i == 4 then 0x3956c25b else
  if i == 5 then 0x59f111f1 else
  if i == 6 then 0x923f82a4 else
  if i == 7 then 0xab1c5ed5 else
  if i == 8 then 0xd807aa98 else
  if i == 9 then 0x12835b01 else
  if i == 10 then 0x243185be else
  if i == 11 then 0x550c7dc3 else
  if i == 12 then 0x72be5d74 else
  if i == 13 then 0x80deb1fe else
  if i == 14 then 0x9bdc06a7 else
  if i == 15 then 0xc19bf174 else
  if i == 16 then 0xe49b69c1 else
  if i == 17 then 0xefbe4786 else
  if i == 18 then 0x0fc19dc6 else
  if i == 19 then 0x240ca1cc else
  if i == 20 then 0x2de92c6f else
  if i == 21 then 0x4a7484aa else
  if i == 22 then 0x5cb0a9dc else
  if i == 23 then 0x76f988da else
  if i == 24 then 0x983e5152 else
  if i == 25 then 0xa831c66d else
  if i == 26 then 0xb00327c8 else
  if i == 27 then 0xbf597fc7 else
  if i == 28 then 0xc6e00bf3 else
  if i == 29 then 0xd5a79147 else
  if i == 30 then 0x06ca6351 else
  if i == 31 then 0x14292967 else
  if i == 32 then 0x27b70a85 else
  if i == 33 then 0x2e1b2138 else
  if i == 34 then 0x4d2c6dfc else
  if i == 35 then 0x53380d13 else
  if i == 36 then 0x650a7354 else
  if i == 37 then 0x766a0abb else
  if i == 38 then 0x81c2c92e else
  if i == 39 then 0x92722c85 else
  if i == 40 then 0xa2bfe8a1 else
  if i == 41 then 0xa81a664b else
  if i == 42 then 0xc24b8b70 else
  if i == 43 then 0xc76c51a3 else
  if i == 44 then 0xd192e819 else
  if i == 45 then 0xd6990624 else
  if i == 46 then 0xf40e3585 else
  if i == 47 then 0x106aa070 else
  if i == 48 then 0x19a4c116 else
  if i == 49 then 0x1e376c08 else
  if i == 50 then 0x2748774c else
  if i == 51 then 0x34b0bcb5 else
  if i == 52 then 0x391c0cb3 else
  if i == 53 then 0x4ed8aa4a else
  if i == 54 then 0x5b9cca4f else
  if i == 55 then 0x682e6ff3 else
  if i == 56 then 0x748f82ee else
  if i == 57 then 0x78a5636f else
  if i == 58 then 0x84c87814 else
  if i == 59 then 0x8cc70208 else
  if i == 60 then 0x90befffa else
  if i == 61 then 0xa4506ceb else
  if i == 62 then 0xbef9a3f7 else
  if i == 63 then 0xc67178f2 else
  0

-- The bounded round index uses six decisions rather than up to64. No new
-- scratch, payload cache or cryptographic primitive is introduced.
def k (i : UInt64) : UInt64 :=
  if i >= 64 then 0 else
  if i < 32 then
    if i < 16 then
      if i < 8 then
        if i < 4 then
          if i < 2 then
            if i < 1 then
              0x428a2f98
            else
              0x71374491
          else
            if i < 3 then
              0xb5c0fbcf
            else
              0xe9b5dba5
        else
          if i < 6 then
            if i < 5 then
              0x3956c25b
            else
              0x59f111f1
          else
            if i < 7 then
              0x923f82a4
            else
              0xab1c5ed5
      else
        if i < 12 then
          if i < 10 then
            if i < 9 then
              0xd807aa98
            else
              0x12835b01
          else
            if i < 11 then
              0x243185be
            else
              0x550c7dc3
        else
          if i < 14 then
            if i < 13 then
              0x72be5d74
            else
              0x80deb1fe
          else
            if i < 15 then
              0x9bdc06a7
            else
              0xc19bf174
    else
      if i < 24 then
        if i < 20 then
          if i < 18 then
            if i < 17 then
              0xe49b69c1
            else
              0xefbe4786
          else
            if i < 19 then
              0x0fc19dc6
            else
              0x240ca1cc
        else
          if i < 22 then
            if i < 21 then
              0x2de92c6f
            else
              0x4a7484aa
          else
            if i < 23 then
              0x5cb0a9dc
            else
              0x76f988da
      else
        if i < 28 then
          if i < 26 then
            if i < 25 then
              0x983e5152
            else
              0xa831c66d
          else
            if i < 27 then
              0xb00327c8
            else
              0xbf597fc7
        else
          if i < 30 then
            if i < 29 then
              0xc6e00bf3
            else
              0xd5a79147
          else
            if i < 31 then
              0x06ca6351
            else
              0x14292967
  else
    if i < 48 then
      if i < 40 then
        if i < 36 then
          if i < 34 then
            if i < 33 then
              0x27b70a85
            else
              0x2e1b2138
          else
            if i < 35 then
              0x4d2c6dfc
            else
              0x53380d13
        else
          if i < 38 then
            if i < 37 then
              0x650a7354
            else
              0x766a0abb
          else
            if i < 39 then
              0x81c2c92e
            else
              0x92722c85
      else
        if i < 44 then
          if i < 42 then
            if i < 41 then
              0xa2bfe8a1
            else
              0xa81a664b
          else
            if i < 43 then
              0xc24b8b70
            else
              0xc76c51a3
        else
          if i < 46 then
            if i < 45 then
              0xd192e819
            else
              0xd6990624
          else
            if i < 47 then
              0xf40e3585
            else
              0x106aa070
    else
      if i < 56 then
        if i < 52 then
          if i < 50 then
            if i < 49 then
              0x19a4c116
            else
              0x1e376c08
          else
            if i < 51 then
              0x2748774c
            else
              0x34b0bcb5
        else
          if i < 54 then
            if i < 53 then
              0x391c0cb3
            else
              0x4ed8aa4a
          else
            if i < 55 then
              0x5b9cca4f
            else
              0x682e6ff3
      else
        if i < 60 then
          if i < 58 then
            if i < 57 then
              0x748f82ee
            else
              0x78a5636f
          else
            if i < 59 then
              0x84c87814
            else
              0x8cc70208
        else
          if i < 62 then
            if i < 61 then
              0x90befffa
            else
              0xa4506ceb
          else
            if i < 63 then
              0xbef9a3f7
            else
              0xc67178f2

theorem round_constants_preserved :
    (List.range 64).all (fun n => k n.toUInt64 == roundConstantReference n.toUInt64) = true := by
  decide

def initialState (scratch : UInt64) (t : UInt64) : UInt64 :=
  let t := store64 (hashState scratch) 0x6a09e667 t
  let t := store64 ((hashState scratch)+8) 0xbb67ae85 t
  let t := store64 ((hashState scratch)+16) 0x3c6ef372 t
  let t := store64 ((hashState scratch)+24) 0xa54ff53a t
  let t := store64 ((hashState scratch)+32) 0x510e527f t
  let t := store64 ((hashState scratch)+40) 0x9b05688c t
  let t := store64 ((hashState scratch)+48) 0x1f83d9ab t
  store64 ((hashState scratch)+56) 0x5be0cd19 t
def messageByte (_scratch : UInt64) (data len total offset t : UInt64) : UInt64 :=
  if offset < len then load8 (data+offset) t
  else if offset == len then 128
  else if offset >= total-8 then ((len*8) >>> ((total-1-offset)*8)) &&& 255
  else 0
partial def firstWords (scratch : UInt64) (data len total block i t : UInt64) : UInt64 :=
  if i == 16 then t else
    let p := block*64+i*4
    let w := (messageByte scratch data len total p t <<< 24) ||| (messageByte scratch data len total (p+1) t <<< 16) |||
      (messageByte scratch data len total (p+2) t <<< 8) ||| messageByte scratch data len total (p+3) t
    firstWords scratch data len total block (i+1) (store64 ((work scratch)+i*8) w t)
partial def expandWords (scratch : UInt64) (i t : UInt64) : UInt64 :=
  if i == 64 then t else
    let a := load64 ((work scratch)+(i-15)*8) t
    let b := load64 ((work scratch)+(i-2)*8) t
    let s0 := rotr a 7 ^^^ rotr a 18 ^^^ (a >>> 3)
    let s1 := rotr b 17 ^^^ rotr b 19 ^^^ (b >>> 10)
    let w := (load64 ((work scratch)+(i-16)*8) t + s0 + load64 ((work scratch)+(i-7)*8) t + s1) &&& mask
    expandWords scratch (i+1) (store64 ((work scratch)+i*8) w t)
partial def initRound (scratch : UInt64) (i t : UInt64) : UInt64 :=
  if i == 8 then t else
    initRound scratch (i+1) (store64 ((roundState scratch)+i*8) (load64 ((hashState scratch)+i*8) t) t)
partial def rounds (scratch : UInt64) (i t : UInt64) : UInt64 :=
  if i == 64 then t else
    let a := load64 (roundState scratch) t
    let b := load64 ((roundState scratch)+8) t
    let c := load64 ((roundState scratch)+16) t
    let d := load64 ((roundState scratch)+24) t
    let e := load64 ((roundState scratch)+32) t
    let f := load64 ((roundState scratch)+40) t
    let g := load64 ((roundState scratch)+48) t
    let h := load64 ((roundState scratch)+56) t
    let big1 := rotr e 6 ^^^ rotr e 11 ^^^ rotr e 25
    let ch := (e &&& f) ^^^ ((e ^^^ mask) &&& g)
    let temp1 := (h+big1+ch+k i+load64 ((work scratch)+i*8) t) &&& mask
    let big0 := rotr a 2 ^^^ rotr a 13 ^^^ rotr a 22
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
  if i == 32 then t else
    let w := load64 ((hashState scratch)+(i/4)*8) t
    let b := (w >>> ((3-i%4)*8)) &&& 255
    outputBytes scratch out (i+1) (store8 (out+i) b t)
/-- Returns an effect token on success, all ones if len > 262144 (without writing memory).
    Callers validate physical input/output extents and serialize access to fixed scratch. -/
def sha256At (scratch : UInt64) (data len out t : UInt64) : UInt64 :=
  if len > 262144 then 0xffffffffffffffff else
    let n := (len+72)/64
    let t := initialState scratch t
    let t := blocks scratch data len (n*64) 0 n t
    outputBytes scratch out 0 t
def sha256 (data len out t : UInt64) : UInt64 := sha256At 0x600200 data len out t
end Guest.ServiceHash
