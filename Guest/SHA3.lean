import Guest.Primitives
namespace Guest.SHA3
-- FIPS202 Keccak-f1600, SHA3-256 and SHAKE256. Caller context224/scratch256.
-- rate136 bytes; context position200, delimiter208, squeezing216.
def err : UInt64 := 0xffffffffffffffff
def rotl (v n : UInt64) : UInt64 := if n == 0 then v else (v <<< n) ||| (v >>> (64-n))
def rc (i : UInt64) : UInt64 :=
  if i == 0 then 0x0000000000000001 else
  if i == 1 then 0x0000000000008082 else
  if i == 2 then 0x800000000000808a else
  if i == 3 then 0x8000000080008000 else
  if i == 4 then 0x000000000000808b else
  if i == 5 then 0x0000000080000001 else
  if i == 6 then 0x8000000080008081 else
  if i == 7 then 0x8000000000008009 else
  if i == 8 then 0x000000000000008a else
  if i == 9 then 0x0000000000000088 else
  if i == 10 then 0x0000000080008009 else
  if i == 11 then 0x000000008000000a else
  if i == 12 then 0x000000008000808b else
  if i == 13 then 0x800000000000008b else
  if i == 14 then 0x8000000000008089 else
  if i == 15 then 0x8000000000008003 else
  if i == 16 then 0x8000000000008002 else
  if i == 17 then 0x8000000000000080 else
  if i == 18 then 0x000000000000800a else
  if i == 19 then 0x800000008000000a else
  if i == 20 then 0x8000000080008081 else
  if i == 21 then 0x8000000000008080 else
  if i == 22 then 0x0000000080000001 else
  if i == 23 then 0x8000000080008008 else
  0
def rho (i : UInt64) : UInt64 :=
  if i == 0 then 0 else
  if i == 1 then 1 else
  if i == 2 then 62 else
  if i == 3 then 28 else
  if i == 4 then 27 else
  if i == 5 then 36 else
  if i == 6 then 44 else
  if i == 7 then 6 else
  if i == 8 then 55 else
  if i == 9 then 20 else
  if i == 10 then 3 else
  if i == 11 then 10 else
  if i == 12 then 43 else
  if i == 13 then 25 else
  if i == 14 then 39 else
  if i == 15 then 41 else
  if i == 16 then 45 else
  if i == 17 then 15 else
  if i == 18 then 21 else
  if i == 19 then 8 else
  if i == 20 then 18 else
  if i == 21 then 2 else
  if i == 22 then 61 else
  if i == 23 then 56 else
  if i == 24 then 14 else
  0
partial def zero (p n t : UInt64) : UInt64 :=
  if n == 0 then t else zero (p+1) (n-1) (store8 p 0 t)
partial def thetaColumns (c s x t : UInt64) : UInt64 :=
  if x == 5 then t else
    let v := load64 (c+x*8) t ^^^ load64 (c+(x+5)*8) t ^^^ load64 (c+(x+10)*8) t ^^^ load64 (c+(x+15)*8) t ^^^ load64 (c+(x+20)*8) t
    thetaColumns c s (x+1) (store64 (s+200+x*8) v t)
partial def thetaApply (c s i t : UInt64) : UInt64 :=
  if i == 25 then t else
    let x := i%5
    let d := load64 (s+200+((x+4)%5)*8) t ^^^ rotl (load64 (s+200+((x+1)%5)*8) t) 1
    thetaApply c s (i+1) (store64 (c+i*8) (load64 (c+i*8) t ^^^ d) t)
partial def rhoPi (c s i t : UInt64) : UInt64 :=
  if i == 25 then t else
    let x := i%5
    let y := i/5
    let j := y+5*((2*x+3*y)%5)
    rhoPi c s (i+1) (store64 (s+j*8) (rotl (load64 (c+i*8) t) (rho i)) t)
partial def chi (c s i t : UInt64) : UInt64 :=
  if i == 25 then t else
    let x := i%5
    let y := i/5
    let a := load64 (s+i*8) t
    let b := load64 (s+(5*y+(x+1)%5)*8) t
    let d := load64 (s+(5*y+(x+2)%5)*8) t
    chi c s (i+1) (store64 (c+i*8) (a ^^^ ((b ^^^ 0xffffffffffffffff) &&& d)) t)
partial def permuteRounds (c s r t : UInt64) : UInt64 :=
  if r == 24 then t else
    let t := thetaColumns c s 0 t
    let t := thetaApply c s 0 t
    let t := rhoPi c s 0 t
    let t := chi c s 0 t
    permuteRounds c s (r+1) (store64 c (load64 c t ^^^ rc r) t)
def permute (c s t : UInt64) : UInt64 := permuteRounds c s 0 t
def init (c shake t : UInt64) : UInt64 := store64 (c+208) (if shake == 0 then 6 else 31) (zero c 224 t)
partial def absorbLoop (c s data n i t : UInt64) : UInt64 :=
  if i == n then t else
    let pos := load64 (c+200) t
    let t := store8 (c+pos) (load8 (c+pos) t ^^^ load8 (data+i) t) t
    let t := if pos == 135 then store64 (c+200) 0 (permute c s t) else store64 (c+200) (pos+1) t
    absorbLoop c s data n (i+1) t
def absorb (c s data n t : UInt64) : UInt64 :=
  if load64 (c+216) t != 0 || n > 4096 then err else absorbLoop c s data n 0 t
def finalize (c s t : UInt64) : UInt64 :=
  let pos := load64 (c+200) t
  let t := store8 (c+pos) (load8 (c+pos) t ^^^ load64 (c+208) t) t
  let t := store8 (c+135) (load8 (c+135) t ^^^ 128) t
  let t := permute c s t
  store64 (c+216) 1 (store64 (c+200) 0 t)
partial def squeezeLoop (c s out n i t : UInt64) : UInt64 :=
  if i == n then t else
    let pos := load64 (c+200) t
    let t := if pos == 136 then store64 (c+200) 0 (permute c s t) else t
    let pos := if pos == 136 then 0 else pos
    let t := store8 (out+i) (load8 (c+pos) t) t
    squeezeLoop c s out n (i+1) (store64 (c+200) (pos+1) t)
def squeeze (c s out n t : UInt64) : UInt64 :=
  if n > 4096 then err else
    let t := if load64 (c+216) t == 0 then finalize c s t else t
    squeezeLoop c s out n 0 t
def sha3 (c s data n out t : UInt64) : UInt64 :=
  if n > 4096 then err else squeeze c s out 32 (absorb c s data n (init c 0 t))
def shake (c s data n out outLen t : UInt64) : UInt64 :=
  if n > 4096 || outLen > 4096 then err else squeeze c s out outLen (absorb c s data n (init c 1 t))
end Guest.SHA3
