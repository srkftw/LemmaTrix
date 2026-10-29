import Guest.Primitives
namespace Guest.Noise25519
-- RFC7748 X25519 Montgomery ladder. Fixed 16-limb radix-2^16 field;
-- dedicated private scratch; fixed loop counts and mask-based conditional swap.
def field : UInt64 := 0x630000
def temp : UInt64 := 0x632000
def scalar : UInt64 := 0x632400
def f (i : UInt64) : UInt64 := field+i*128
partial def zero (p n t : UInt64) : UInt64 :=
  if n == 0 then t else zero (p+8) (n-1) (store64 p 0 t)
partial def copy (a b i t : UInt64) : UInt64 :=
  if i == 16 then t else copy a b (i+1) (store64 (b+i*8) (load64 (a+i*8) t) t)
def prime (i : UInt64) : UInt64 := if i == 0 then 65517 else if i == 15 then 32767 else 65535
partial def carry (p i t : UInt64) : UInt64 :=
  if i == 15 then
    let a := load64 (p+120) t
    let t := store64 (p+120) (a &&& 32767) t
    store64 p (load64 p t+(a >>> 15)*19) t
  else
    let a := load64 (p+i*8) t
    let t := store64 (p+i*8) (a &&& 65535) t
    let t := store64 (p+(i+1)*8) (load64 (p+(i+1)*8) t+(a >>> 16)) t
    carry p (i+1) t
def normalize (p t : UInt64) : UInt64 := carry p 0 (carry p 0 (carry p 0 t))
partial def addLoop (a b out subtract i t : UInt64) : UInt64 :=
  if i == 16 then normalize out t else
    let av := load64 (a+i*8) t
    let bv := load64 (b+i*8) t
    let v := if subtract == 0 then av+bv else av+4*prime i-bv
    addLoop a b out subtract (i+1) (store64 (out+i*8) v t)
def add (a b out t : UInt64) : UInt64 := addLoop a b out 0 0 t
def sub (a b out t : UInt64) : UInt64 := addLoop a b out 1 0 t
partial def multiplyInner (a b i j t : UInt64) : UInt64 :=
  if j == 16 then t else
    let p := temp+(i+j)*8
    let t := store64 p (load64 p t+load64 (a+i*8) t*load64 (b+j*8) t) t
    multiplyInner a b i (j+1) t
partial def multiplyOuter (a b i t : UInt64) : UInt64 :=
  if i == 16 then t else multiplyOuter a b (i+1) (multiplyInner a b i 0 t)
partial def fold (out i t : UInt64) : UInt64 :=
  if i == 16 then normalize out t else
    let v := load64 (temp+i*8) t+38*load64 (temp+(i+16)*8) t
    fold out (i+1) (store64 (out+i*8) v t)
def mul (a b out t : UInt64) : UInt64 :=
  fold out 0 (multiplyOuter a b 0 (zero temp 32 t))
def sq (a out t : UInt64) : UInt64 := mul a a out t
partial def swap (a b bit i t : UInt64) : UInt64 :=
  if i == 16 then t else
    let av := load64 (a+i*8) t
    let bv := load64 (b+i*8) t
    let x := (av ^^^ bv) &&& (0-bit)
    let t := store64 (a+i*8) (av ^^^ x) t
    let t := store64 (b+i*8) (bv ^^^ x) t
    swap a b bit (i+1) t
partial def unpack (input out i t : UInt64) : UInt64 :=
  if i == 16 then store64 (out+120) (load64 (out+120) t &&& 32767) t else
    unpack input out (i+1) (store64 (out+i*8) (load8 (input+i*2) t ||| (load8 (input+i*2+1) t <<< 8)) t)
partial def reduce (p i borrow t : UInt64) : UInt64 :=
  if i == 16 then borrow else
    let d := load64 (p+i*8) t-prime i-borrow
    reduce p (i+1) (d >>> 63) (store64 (temp+i*8) (d &&& 65535) t)
partial def packLoop (p out mask i t : UInt64) : UInt64 :=
  if i == 16 then t else
    let v := (load64 (p+i*8) t &&& mask) ||| (load64 (temp+i*8) t &&& (mask ^^^ 0xffffffffffffffff))
    let t := store8 (out+i*2) (v &&& 255) t
    packLoop p out mask (i+1) (store8 (out+i*2+1) (v >>> 8) t)
def pack (p out t : UInt64) : UInt64 :=
  let t := normalize p t
  let borrow := reduce p 0 0 t
  packLoop p out (0-borrow) 0 borrow
partial def clampCopy (input i t : UInt64) : UInt64 :=
  if i == 32 then
    let t := store8 scalar (load8 scalar t &&& 248) t
    store8 (scalar+31) ((load8 (scalar+31) t &&& 127) ||| 64) t
  else clampCopy input (i+1) (store8 (scalar+i) (load8 (input+i) t) t)
partial def ladder (position previous t : UInt64) : UInt64 :=
  if position == 0 then
    let t := swap (f 1) (f 3) previous 0 t
    swap (f 2) (f 4) previous 0 t
  else
    let bit := (load8 (scalar+(position-1)/8) t >>> ((position-1)%8)) &&& 1
    let t := swap (f 1) (f 3) (previous ^^^ bit) 0 t
    let t := swap (f 2) (f 4) (previous ^^^ bit) 0 t
    let t := add (f 1) (f 2) (f 5) t
    let t := sq (f 5) (f 6) t
    let t := sub (f 1) (f 2) (f 7) t
    let t := sq (f 7) (f 8) t
    let t := sub (f 6) (f 8) (f 9) t
    let t := add (f 3) (f 4) (f 10) t
    let t := sub (f 3) (f 4) (f 11) t
    let t := mul (f 11) (f 5) (f 12) t
    let t := mul (f 10) (f 7) (f 13) t
    let t := add (f 12) (f 13) (f 14) t
    let t := sq (f 14) (f 3) t
    let t := sub (f 12) (f 13) (f 14) t
    let t := sq (f 14) (f 14) t
    let t := mul (f 0) (f 14) (f 4) t
    let t := mul (f 6) (f 8) (f 1) t
    let t := mul (f 15) (f 9) (f 14) t
    let t := add (f 6) (f 14) (f 14) t
    let t := mul (f 9) (f 14) (f 2) t
    ladder (position-1) bit t
partial def invert (position t : UInt64) : UInt64 :=
  if position == 0 then t else
    let t := sq (f 16) (f 16) t
    let i := position-1
    let t := if i == 2 || i == 4 then t else mul (f 16) (f 2) (f 16) t
    invert i t
/-- Caller checks 32-byte input/output extents. All-zero result must be rejected. -/
def x25519 (privateKey publicKey out t : UInt64) : UInt64 :=
  let t := zero field 288 t
  let t := clampCopy privateKey 0 t
  let t := unpack publicKey (f 0) 0 t
  let t := store64 (f 1) 1 t
  let t := copy (f 0) (f 3) 0 t
  let t := store64 (f 4) 1 t
  let t := store64 (f 15) 121665 t
  let t := ladder 255 0 t
  let t := store64 (f 16) 1 t
  let t := invert 255 t
  let t := mul (f 1) (f 16) (f 1) t
  let t := pack (f 1) out t
  zero field 288 (zero temp 132 t)
end Guest.Noise25519
