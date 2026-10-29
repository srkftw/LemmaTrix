import Guest.ServiceSHA256
namespace Guest.ServiceSignature
-- Public-key verification only: RSA-2048, exponent 65537, EMSA-PKCS1-v1_5/SHA-256 (RFC 8017).
-- CIOS Montgomery arithmetic uses 64 little-endian radix-2^32 limbs in UInt64 slots.
-- Scratch 0x602000..0x602c1f is service-private and serialized with package dispatch.
-- Public verification is variable-time; no private-key operations or audit claim.
def modulusWords : UInt64 := 0x602000
def baseWords : UInt64 := 0x602200
def resultWords : UInt64 := 0x602400
def temporary : UInt64 := 0x602600
def oneWords : UInt64 := 0x602840
def carryWord : UInt64 := 0x602a40
def digestBytes : UInt64 := 0x602c00
def limbMask : UInt64 := 0xffffffff

def inputWord (p i t : UInt64) : UInt64 :=
  let p := p+252-i*4
  (load8 p t <<< 24) ||| (load8 (p+1) t <<< 16) ||| (load8 (p+2) t <<< 8) ||| load8 (p+3) t
partial def decode (p out i t : UInt64) : UInt64 :=
  if i == 64 then t else decode p out (i+1) (store64 (out+i*8) (inputWord p i t) t)
partial def clear (p i n t : UInt64) : UInt64 :=
  if i == n then t else clear p (i+1) n (store64 (p+i*8) 0 t)
partial def copyWords (src dst i t : UInt64) : UInt64 :=
  if i == 64 then t else copyWords src dst (i+1) (store64 (dst+i*8) (load64 (src+i*8) t) t)
partial def atLeast (a b count t : UInt64) : Bool :=
  if count == 0 then true else
    let i := count-1
    let av := load64 (a+i*8) t
    let bv := load64 (b+i*8) t
    if av > bv then true else if av < bv then false else atLeast a b i t
partial def subtractModulus (a i borrow t : UInt64) : UInt64 :=
  if i == 64 then t else
    let av := load64 (a+i*8) t
    let bv := load64 (modulusWords+i*8) t+borrow
    let nextBorrow := if av < bv then 1 else 0
    subtractModulus a (i+1) nextBorrow (store64 (a+i*8) ((av-bv) &&& limbMask) t)
partial def doubleWords (i carry t : UInt64) : UInt64 :=
  if i == 64 then store64 carryWord carry t else
    let v := load64 (baseWords+i*8) t*2+carry
    doubleWords (i+1) (v >>> 32) (store64 (baseWords+i*8) (v &&& limbMask) t)
def doubleModulus (t : UInt64) : UInt64 :=
  let t := doubleWords 0 0 t
  if load64 carryWord t != 0 || atLeast baseWords modulusWords 64 t then subtractModulus baseWords 0 0 t else t
partial def toMontgomery (remaining t : UInt64) : UInt64 :=
  if remaining == 0 then t else toMontgomery (remaining-1) (doubleModulus t)
partial def inverse32 (n x steps : UInt64) : UInt64 :=
  if steps == 0 then x else inverse32 n ((x*(2-n*x)) &&& limbMask) (steps-1)

partial def multiplyAdd (a b row col carry t : UInt64) : UInt64 :=
  if col == 64 then
    let v := load64 (temporary+512) t+carry
    let t := store64 (temporary+512) (v &&& limbMask) t
    store64 (temporary+520) (v >>> 32) t
  else
    let v := load64 (temporary+col*8) t + load64 (a+col*8) t * load64 (b+row*8) t + carry
    multiplyAdd a b row (col+1) (v >>> 32) (store64 (temporary+col*8) (v &&& limbMask) t)
partial def reduceAdd (m col carry t : UInt64) : UInt64 :=
  if col == 64 then
    let v := load64 (temporary+512) t+carry
    let t := store64 (temporary+504) (v &&& limbMask) t
    store64 (temporary+512) (load64 (temporary+520) t+(v >>> 32)) t
  else
    let v := load64 (temporary+col*8) t + m*load64 (modulusWords+col*8) t + carry
    let t := if col == 0 then t else store64 (temporary+(col-1)*8) (v &&& limbMask) t
    reduceAdd m (col+1) (v >>> 32) t
partial def productRows (a b row n0 t : UInt64) : UInt64 :=
  if row == 64 then t else
    let t := multiplyAdd a b row 0 0 t
    let m := (load64 temporary t*n0) &&& limbMask
    let t := reduceAdd m 0 0 t
    productRows a b (row+1) n0 t

def montgomery (a b out n0 t : UInt64) : UInt64 :=
  let t := clear temporary 0 66 t
  let t := productRows a b 0 n0 t
  let t := if load64 (temporary+512) t != 0 || atLeast temporary modulusWords 64 t then subtractModulus temporary 0 0 t else t
  copyWords temporary out 0 t
partial def squares (remaining n0 t : UInt64) : UInt64 :=
  if remaining == 0 then t else squares (remaining-1) n0 (montgomery resultWords resultWords resultWords n0 t)

def derByte (i : UInt64) : UInt64 :=
  if i == 0 then 0x30 else if i == 1 then 0x31 else if i == 2 then 0x30 else
  if i == 3 then 0x0d else if i == 4 then 0x06 else if i == 5 then 0x09 else
  if i == 6 then 0x60 else if i == 7 then 0x86 else if i == 8 then 0x48 else
  if i == 9 then 0x01 else if i == 10 then 0x65 else if i == 11 then 0x03 else
  if i == 12 then 0x04 else if i == 13 then 0x02 else if i == 14 then 0x01 else
  if i == 15 then 0x05 else if i == 16 then 0x00 else if i == 17 then 0x04 else 0x20

def resultByte (i t : UInt64) : UInt64 :=
  (load64 (resultWords+((255-i)/4)*8) t >>> ((3-i%4)*8)) &&& 255
partial def validEncoding (i t : UInt64) : Bool :=
  if i == 256 then true else
    let expected := if i == 0 then 0 else if i == 1 then 1 else if i < 204 then 255 else
      if i == 204 then 0 else if i < 224 then derByte (i-205) else load8 (digestBytes+i-224) t
    if resultByte i t != expected then false else validEncoding (i+1) t

/-- Strict RSA-2048 exponent-65537 verification over exactly 256-byte BE signature/modulus.
    Modulus comes from trusted launch configuration, never from the package being checked.
    Caller checks physical extents and serializes scratch. Messages are bounded to 65536 bytes. -/
def verify (message len signature modulus t : UInt64) : Bool :=
  if len > 65536 || (load8 modulus t &&& 128) == 0 || (load8 (modulus+255) t &&& 1) == 0 then false else
    let t := decode modulus modulusWords 0 t
    let t := decode signature baseWords 0 t
    if atLeast baseWords modulusWords 64 t then false else
      let n0 := (0-inverse32 (load64 modulusWords t) 1 5) &&& limbMask
      let t := toMontgomery 2048 t
      let t := copyWords baseWords resultWords 0 t
      let t := clear oneWords 0 64 t
      let t := store64 oneWords 1 t
      let t := squares 16 n0 t
      let t := montgomery resultWords baseWords resultWords n0 t
      let t := montgomery resultWords oneWords resultWords n0 t
      let t := ServiceHash.sha256 message len digestBytes t
      validEncoding 0 t
end Guest.ServiceSignature
