import Guest.Noise25519
import Guest.SHA512
import Guest.Effects
namespace Guest.Ed25519
-- RFC8032 pure Ed25519; canonical purpose framing is the caller's responsibility.
-- Secret arithmetic has fixed iteration counts, mask selection, and no secret
-- indexed tables. This source discipline is not a compiler/constant-time proof.
-- Serialized private scratch 0x640000..0x646fff, plus Noise25519 multiplication
-- scratch 0x632000..0x6320ff. Caller checks all pointer extents and non-overlap.
def err : UInt64 := 0xffffffffffffffff
def pointP : UInt64 := 0x640000
def pointQ : UInt64 := 0x640200
def pointR : UInt64 := 0x640400
def pointA : UInt64 := 0x640600
def pointB : UInt64 := 0x640800
def ft (i : UInt64) : UInt64 := 0x641000+i*128
def fc (i : UInt64) : UInt64 := 0x642000+i*128
def expanded : UInt64 := 0x643000
def digestR : UInt64 := 0x643040
def digestK : UInt64 := 0x643080
def reducedR : UInt64 := 0x6430c0
def reducedK : UInt64 := 0x6430e0
def remainder : UInt64 := 0x643100
def subtraction : UInt64 := 0x643200
def wide : UInt64 := 0x643400
def rawWide : UInt64 := 0x643800
def encoded : UInt64 := 0x643900
def encoded2 : UInt64 := 0x643920
def hashScratch : UInt64 := 0x644000
def concat : UInt64 := 0x645000
open Guest.Noise25519 (add sub mul sq normalize pack unpack swap)
partial def zeroWords (p n t : UInt64) : UInt64 :=
  if n == 0 then t else zeroWords (p+8) (n-1) (store64 p 0 t)
partial def copyBytes (a b n t : UInt64) : UInt64 :=
  if n == 0 then t else copyBytes (a+1) (b+1) (n-1) (store8 b (load8 a t) t)
partial def copyWords (a b n t : UInt64) : UInt64 :=
  if n == 0 then t else copyWords (a+8) (b+8) (n-1) (store64 b (load64 a t) t)
partial def difference (a b n v t : UInt64) : UInt64 :=
  if n == 0 then v else difference (a+1) (b+1) (n-1) (v ||| (load8 a t ^^^ load8 b t)) t
partial def nonzero (a n v t : UInt64) : UInt64 :=
  if n == 0 then v else nonzero (a+1) (n-1) (v ||| load8 a t) t
-- Every success and failure exit clears expanded scalars, nonce material,
-- scalar accumulators, point coordinates, SHA state, and concatenation buffers.
def clear (t : UInt64) : UInt64 :=
  zeroWords 0x640000 3584 (zeroWords 0x632000 32 t)
def identity (out t : UInt64) : UInt64 :=
  let t := zeroWords out 64 t
  let t := store64 (out+128) 1 t
  store64 (out+256) 1 t
def constants (t : UInt64) : UInt64 :=
  let t := store64 (fc 0+0) 30883 t
  let t := store64 (fc 0+8) 4953 t
  let t := store64 (fc 0+16) 19914 t
  let t := store64 (fc 0+24) 30187 t
  let t := store64 (fc 0+32) 55467 t
  let t := store64 (fc 0+40) 16705 t
  let t := store64 (fc 0+48) 2637 t
  let t := store64 (fc 0+56) 112 t
  let t := store64 (fc 0+64) 59544 t
  let t := store64 (fc 0+72) 30585 t
  let t := store64 (fc 0+80) 16505 t
  let t := store64 (fc 0+88) 36039 t
  let t := store64 (fc 0+96) 65139 t
  let t := store64 (fc 0+104) 11119 t
  let t := store64 (fc 0+112) 27886 t
  let t := store64 (fc 0+120) 20995 t
  let t := store64 (fc 1+0) 61785 t
  let t := store64 (fc 1+8) 9906 t
  let t := store64 (fc 1+16) 39828 t
  let t := store64 (fc 1+24) 60374 t
  let t := store64 (fc 1+32) 45398 t
  let t := store64 (fc 1+40) 33411 t
  let t := store64 (fc 1+48) 5274 t
  let t := store64 (fc 1+56) 224 t
  let t := store64 (fc 1+64) 53552 t
  let t := store64 (fc 1+72) 61171 t
  let t := store64 (fc 1+80) 33010 t
  let t := store64 (fc 1+88) 6542 t
  let t := store64 (fc 1+96) 64743 t
  let t := store64 (fc 1+104) 22239 t
  let t := store64 (fc 1+112) 55772 t
  let t := store64 (fc 1+120) 9222 t
  let t := store64 (fc 2+0) 54554 t
  let t := store64 (fc 2+8) 36645 t
  let t := store64 (fc 2+16) 11616 t
  let t := store64 (fc 2+24) 51542 t
  let t := store64 (fc 2+32) 42930 t
  let t := store64 (fc 2+40) 38181 t
  let t := store64 (fc 2+48) 51040 t
  let t := store64 (fc 2+56) 26924 t
  let t := store64 (fc 2+64) 56412 t
  let t := store64 (fc 2+72) 64982 t
  let t := store64 (fc 2+80) 57905 t
  let t := store64 (fc 2+88) 49316 t
  let t := store64 (fc 2+96) 21502 t
  let t := store64 (fc 2+104) 52590 t
  let t := store64 (fc 2+112) 14035 t
  let t := store64 (fc 2+120) 8553 t
  let t := store64 (fc 3+0) 26200 t
  let t := store64 (fc 3+8) 26214 t
  let t := store64 (fc 3+16) 26214 t
  let t := store64 (fc 3+24) 26214 t
  let t := store64 (fc 3+32) 26214 t
  let t := store64 (fc 3+40) 26214 t
  let t := store64 (fc 3+48) 26214 t
  let t := store64 (fc 3+56) 26214 t
  let t := store64 (fc 3+64) 26214 t
  let t := store64 (fc 3+72) 26214 t
  let t := store64 (fc 3+80) 26214 t
  let t := store64 (fc 3+88) 26214 t
  let t := store64 (fc 3+96) 26214 t
  let t := store64 (fc 3+104) 26214 t
  let t := store64 (fc 3+112) 26214 t
  let t := store64 (fc 3+120) 26214 t
  let t := store64 (fc 4+0) 41136 t
  let t := store64 (fc 4+8) 18958 t
  let t := store64 (fc 4+16) 6951 t
  let t := store64 (fc 4+24) 50414 t
  let t := store64 (fc 4+32) 58488 t
  let t := store64 (fc 4+40) 44335 t
  let t := store64 (fc 4+48) 6150 t
  let t := store64 (fc 4+56) 12099 t
  let t := store64 (fc 4+64) 55207 t
  let t := store64 (fc 4+72) 15867 t
  let t := store64 (fc 4+80) 153 t
  let t := store64 (fc 4+88) 11085 t
  let t := store64 (fc 4+96) 57099 t
  let t := store64 (fc 4+104) 20417 t
  let t := store64 (fc 4+112) 9344 t
  let t := store64 (fc 4+120) 11139 t
  let t := store64 (fc 5+0) 1 t
  let t := store64 (fc 5+8) 0 t
  let t := store64 (fc 5+16) 0 t
  let t := store64 (fc 5+24) 0 t
  let t := store64 (fc 5+32) 0 t
  let t := store64 (fc 5+40) 0 t
  let t := store64 (fc 5+48) 0 t
  let t := store64 (fc 5+56) 0 t
  let t := store64 (fc 5+64) 0 t
  let t := store64 (fc 5+72) 0 t
  let t := store64 (fc 5+80) 0 t
  let t := store64 (fc 5+88) 0 t
  let t := store64 (fc 5+96) 0 t
  let t := store64 (fc 5+104) 0 t
  let t := store64 (fc 5+112) 0 t
  let t := store64 (fc 5+120) 0 t
  let t := store64 (fc 6+0) 0 t
  let t := store64 (fc 6+8) 0 t
  let t := store64 (fc 6+16) 0 t
  let t := store64 (fc 6+24) 0 t
  let t := store64 (fc 6+32) 0 t
  let t := store64 (fc 6+40) 0 t
  let t := store64 (fc 6+48) 0 t
  let t := store64 (fc 6+56) 0 t
  let t := store64 (fc 6+64) 0 t
  let t := store64 (fc 6+72) 0 t
  let t := store64 (fc 6+80) 0 t
  let t := store64 (fc 6+88) 0 t
  let t := store64 (fc 6+96) 0 t
  let t := store64 (fc 6+104) 0 t
  let t := store64 (fc 6+112) 0 t
  let t := store64 (fc 6+120) 0 t
  t
def base (out t : UInt64) : UInt64 :=
  let t := copyWords (fc 2) out 16 t
  let t := copyWords (fc 3) (out+128) 16 t
  let t := copyWords (fc 5) (out+256) 16 t
  mul out (out+128) (out+384) t
-- Complete extended-coordinate point addition, RFC8032 section5.1.4.
def pointAdd (p q out t : UInt64) : UInt64 :=
  let t := sub (p+128) p (ft 0) t
  let t := sub (q+128) q (ft 8) t
  let t := mul (ft 0) (ft 8) (ft 0) t
  let t := add (p+128) p (ft 1) t
  let t := add (q+128) q (ft 8) t
  let t := mul (ft 1) (ft 8) (ft 1) t
  let t := mul (p+384) (q+384) (ft 2) t
  let t := mul (ft 2) (fc 1) (ft 2) t
  let t := mul (p+256) (q+256) (ft 3) t
  let t := add (ft 3) (ft 3) (ft 3) t
  let t := sub (ft 1) (ft 0) (ft 4) t
  let t := sub (ft 3) (ft 2) (ft 5) t
  let t := add (ft 3) (ft 2) (ft 6) t
  let t := add (ft 1) (ft 0) (ft 7) t
  let t := mul (ft 4) (ft 5) out t
  let t := mul (ft 6) (ft 7) (out+128) t
  let t := mul (ft 5) (ft 6) (out+256) t
  mul (ft 4) (ft 7) (out+384) t
partial def pointSwap (p q bit i t : UInt64) : UInt64 :=
  if i == 64 then t else
    let av := load64 (p+i*8) t
    let bv := load64 (q+i*8) t
    let x := (av ^^^ bv) &&& (0-bit)
    let t := store64 (p+i*8) (av ^^^ x) t
    pointSwap p q bit (i+1) (store64 (q+i*8) (bv ^^^ x) t)
partial def scalarLoop (scalar position t : UInt64) : UInt64 :=
  if position == 0 then t else
    let i := position-1
    let bit := (load8 (scalar+i/8) t >>> (i%8)) &&& 1
    let t := pointSwap pointP pointQ bit 0 t
    let t := pointAdd pointP pointQ pointQ t
    let t := pointAdd pointP pointP pointP t
    let t := pointSwap pointP pointQ bit 0 t
    scalarLoop scalar i t
/-- Input point and output must not overlap ladder scratch pointP/pointQ. -/
def scalarMultiply (scalar point out t : UInt64) : UInt64 :=
  let t := copyWords point pointQ 64 t
  let t := identity pointP t
  let t := scalarLoop scalar 256 t
  copyWords pointP out 64 t
partial def inverseLoop (input out position t : UInt64) : UInt64 :=
  if position == 0 then t else
    let i := position-1
    let t := sq out out t
    let t := if i == 2 || i == 4 then t else mul out input out t
    inverseLoop input out i t
def inverse (input out t : UInt64) : UInt64 :=
  inverseLoop input out 255 (copyWords (fc 5) out 16 t)
def pointEncode (point out t : UInt64) : UInt64 :=
  let t := inverse (point+256) (ft 0) t
  let t := mul point (ft 0) (ft 1) t
  let t := mul (point+128) (ft 0) (ft 2) t
  let t := pack (ft 1) encoded t
  let sign := load8 encoded t &&& 1
  let t := pack (ft 2) out t
  store8 (out+31) (load8 (out+31) t ||| (sign <<< 7)) t
-- Order L, little-endian bytes; indexed only by public loop counters.
def orderByte (i : UInt64) : UInt64 :=
  if i == 0 then 237 else if i == 1 then 211 else if i == 2 then 245 else
  if i == 3 then 92 else if i == 4 then 26 else if i == 5 then 99 else
  if i == 6 then 18 else if i == 7 then 88 else if i == 8 then 214 else
  if i == 9 then 156 else if i == 10 then 247 else if i == 11 then 162 else
  if i == 12 then 222 else if i == 13 then 249 else if i == 14 then 222 else
  if i == 15 then 20 else if i == 31 then 16 else 0
partial def reduceSubtract (i borrow t : UInt64) : UInt64 :=
  if i == 32 then borrow else
    let d := load64 (remainder+i*8) t-orderByte i-borrow
    reduceSubtract (i+1) (d >>> 63) (store64 (subtraction+i*8) (d &&& 255) t)
partial def reduceSelect (mask i t : UInt64) : UInt64 :=
  if i == 32 then t else
    let v := (load64 (remainder+i*8) t &&& mask) ||| (load64 (subtraction+i*8) t &&& (mask ^^^ 0xffffffffffffffff))
    reduceSelect mask (i+1) (store64 (remainder+i*8) v t)
partial def reduceShift (bit i t : UInt64) : UInt64 :=
  if i == 32 then t else
    let v := load64 (remainder+i*8) t*2+bit
    reduceShift (v >>> 8) (i+1) (store64 (remainder+i*8) (v &&& 255) t)
partial def reduceBits (input position t : UInt64) : UInt64 :=
  if position == 0 then t else
    let i := position-1
    let bit := (load8 (input+i/8) t >>> (i%8)) &&& 1
    let t := reduceShift bit 0 t
    let borrow := reduceSubtract 0 0 t
    let t := reduceSelect (0-borrow) 0 borrow
    reduceBits input i t
partial def reduceOutput (out i t : UInt64) : UInt64 :=
  if i == 32 then t else reduceOutput out (i+1) (store8 (out+i) (load64 (remainder+i*8) t) t)
def scalarReduce (input out t : UInt64) : UInt64 :=
  let t := zeroWords remainder 32 t
  reduceOutput out 0 (reduceBits input 512 t)
partial def multiplyInner (a b i j t : UInt64) : UInt64 :=
  if j == 32 then t else
    let p := wide+(i+j)*8
    let t := store64 p (load64 p t+load8 (a+i) t*load8 (b+j) t) t
    multiplyInner a b i (j+1) t
partial def multiplyOuter (a b i t : UInt64) : UInt64 :=
  if i == 32 then t else multiplyOuter a b (i+1) (multiplyInner a b i 0 t)
partial def addWide (r i t : UInt64) : UInt64 :=
  if i == 32 then t else addWide r (i+1) (store64 (wide+i*8) (load64 (wide+i*8) t+load8 (r+i) t) t)
partial def carryWide (i carry t : UInt64) : UInt64 :=
  if i == 64 then t else
    let v := load64 (wide+i*8) t+carry
    carryWide (i+1) (v >>> 8) (store8 (rawWide+i) (v &&& 255) t)
def multiplyAdd (r k s out t : UInt64) : UInt64 :=
  let t := zeroWords wide 64 t
  let t := multiplyOuter k s 0 t
  let t := addWide r 0 t
  scalarReduce rawWide out (carryWide 0 0 t)
def expand (seed t : UInt64) : UInt64 :=
  let t := Guest.SHA512.sha512At hashScratch seed 32 expanded t
  let t := store8 expanded (load8 expanded t &&& 248) t
  store8 (expanded+31) ((load8 (expanded+31) t &&& 63) ||| 64) t
/-- Public derivation, 32-byte seed and output; seed never leaves its caller. -/
def publicKey (seed out t : UInt64) : UInt64 :=
  let t := constants t
  let t := expand seed t
  let t := base pointR t
  let t := scalarMultiply expanded pointR pointR t
  clear (pointEncode pointR out t)
/-- Pure Ed25519; bounded canonical body <=4096 bytes. Public key must correspond
    to seed; broker owns and supplies both. Output is 64 bytes. -/
def sign (seed publicKey input len out t : UInt64) : UInt64 :=
  if len > 4096 then
    Guest.Effects.effectValue err (clear t)
  else
    let t := constants t
    let t := expand seed t
    let t := copyBytes (expanded+32) concat 32 t
    let t := copyBytes input (concat+32) len t
    let t := Guest.SHA512.sha512At hashScratch concat (32+len) digestR t
    let t := scalarReduce digestR reducedR t
    let t := base pointR t
    let t := scalarMultiply reducedR pointR pointR t
    let t := pointEncode pointR out t
    let t := copyBytes out concat 32 t
    let t := copyBytes publicKey (concat+32) 32 t
    let t := copyBytes input (concat+64) len t
    let t := Guest.SHA512.sha512At hashScratch concat (64+len) digestK t
    let t := scalarReduce digestK reducedK t
    clear (multiplyAdd reducedR reducedK expanded (out+32) t)
partial def sqrtLoop (input out position t : UInt64) : UInt64 :=
  if position == 0 then t else
    let i := position-1
    let t := sq out out t
    let t := if i == 0 then t else mul out input out t
    sqrtLoop input out i t
-- Public verification helpers may branch on untrusted public input.
def fieldEqual (a b t : UInt64) : Bool :=
  let t := pack a encoded t
  let t := pack b encoded2 t
  difference encoded encoded2 32 0 t == 0
def fieldZero (a t : UInt64) : Bool :=
  let t := pack a encoded t
  nonzero encoded 32 0 t == 0
/-- RFC8032 strict canonical y, curve square-root and negative-zero checks. -/
def pointDecode (input out t : UInt64) : UInt64 :=
  let t := unpack input (out+128) 0 t
  let t := pack (out+128) encoded t
  let sign := load8 (input+31) t >>> 7
  if difference input encoded 31 0 t != 0 || (load8 (input+31) t &&& 127) != load8 (encoded+31) t then err else
    let t := copyWords (fc 5) (out+256) 16 t
    let t := sq (out+128) (ft 0) t
    let t := mul (fc 0) (ft 0) (ft 1) t
    let t := add (ft 1) (fc 5) (ft 1) t
    let t := sub (ft 0) (fc 5) (ft 0) t
    let t := inverse (ft 1) (ft 2) t
    let t := mul (ft 0) (ft 2) (ft 3) t
    let t := sqrtLoop (ft 3) out 252 (copyWords (fc 5) out 16 t)
    let t := sq out (ft 4) t
    let t := if fieldEqual (ft 4) (ft 3) t then t else mul out (fc 4) out t
    let t := sq out (ft 4) t
    if !fieldEqual (ft 4) (ft 3) t then err else
      let t := pack out encoded t
      if nonzero encoded 32 0 t == 0 && sign == 1 then err else
        let parity := load8 encoded t &&& 1
        let t := if parity == sign then t else sub (fc 6) out out t
        mul out (out+128) (out+384) t
partial def scalarCanonical (input i borrow t : UInt64) : Bool :=
  if i == 32 then borrow == 1 else
    let d := load8 (input+i) t-orderByte i-borrow
    scalarCanonical input (i+1) (d >>> 63) t
def smallOrder (point t : UInt64) : Bool :=
  let t := copyWords point pointR 64 t
  let t := pointAdd pointR pointR pointR t
  let t := pointAdd pointR pointR pointR t
  let t := pointAdd pointR pointR pointR t
  fieldZero pointR t && fieldEqual (pointR+128) (pointR+256) t
/-- Strict Ed25519 verification: canonical A/R/S; reject small-order A/R;
    exact (uncofactored) equation allowed by RFC8032 section5.1.7. -/
def verify (publicKey input len signature t : UInt64) : Bool :=
  if len > 4096 then
    Guest.Effects.effectValue 1 (clear t) == 0
  else
    let t := constants t
    if !scalarCanonical (signature+32) 0 0 t then
      Guest.Effects.effectValue 1 (clear t) == 0
    else
      let t := pointDecode publicKey pointA t
      if t == err then
        Guest.Effects.effectValue 1 (clear t) == 0
      else
        let t := pointDecode signature pointB t
        if t == err || smallOrder pointA t || smallOrder pointB t then
          Guest.Effects.effectValue 1 (clear t) == 0
        else
          let t := copyBytes signature concat 32 t
          let t := copyBytes publicKey (concat+32) 32 t
          let t := copyBytes input (concat+64) len t
          let t := Guest.SHA512.sha512At hashScratch concat (64+len) digestK t
          let t := scalarReduce digestK reducedK t
          let t := scalarMultiply reducedK pointA pointA t
          let t := pointAdd pointA pointB pointA t
          let t := base pointR t
          let t := scalarMultiply (signature+32) pointR pointB t
          let t := pointEncode pointA digestR t
          let t := pointEncode pointB digestK t
          let d := difference digestR digestK 32 0 t
          Guest.Effects.effectValue d (clear t) == 0
end Guest.Ed25519
