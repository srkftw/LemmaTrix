import Guest.Ed25519
import Guest.VaultCrypto
import Guest.ServiceHash
namespace Guest.MessengerCrypto
-- Classical profile1: X25519, XEd25519(SHA512), HKDF/HMAC-SHA256,
-- ChaCha20Poly1305. Scratch is private to the non-networked session owner.
def scratch : UInt64 := 0x670000
def scalar : UInt64 := scratch
def publicEd : UInt64 := scratch+64
def negative : UInt64 := scratch+96
def randomInput : UInt64 := scratch+128
def hashInput : UInt64 := scratch+256
def digest : UInt64 := scratch+4608
def nonceScalar : UInt64 := scratch+4672
def challenge : UInt64 := scratch+4704
def hmacInput : UInt64 := scratch+4800
def hmacInner : UInt64 := scratch+5440
def prk : UInt64 := scratch+5504
def expandInput : UInt64 := scratch+5568
def shaScratch : UInt64 := scratch+6144
def zeroKey : UInt64 := scratch+8192
def dhMaterial : UInt64 := scratch+8256
def derived : UInt64 := scratch+8448
def nonce : UInt64 := scratch+8576
def err : UInt64 := 0xffffffffffffffff
open Guest.Ed25519 (copyBytes zeroWords difference nonzero)
def clear (t : UInt64) : UInt64 := zeroWords scratch 2048 (Guest.Ed25519.clear t)
def clamp (input out t : UInt64) : UInt64 :=
  let t := copyBytes input out 32 t
  let t := store8 out (load8 out t &&& 248) t
  store8 (out+31) ((load8 (out+31) t &&& 127) ||| 64) t
partial def negateScalar (input out i borrow t : UInt64) : UInt64 :=
  if i == 32 then t else
  let d := Guest.Ed25519.orderByte i-load8 (input+i) t-borrow
  negateScalar input out (i+1) (d >>> 63) (store8 (out+i) (d &&& 255) t)
partial def choose (a b out mask i t : UInt64) : UInt64 :=
  if i == 32 then t else
  let v := (load8 (a+i) t &&& mask) ||| (load8 (b+i) t &&& (mask ^^^ 255))
  choose a b out mask (i+1) (store8 (out+i) v t)
-- XEdDSA revision1 calculate_key_pair: use the X25519 scalar, never an Ed25519 seed.
def keyPair (privateKey t : UInt64) : UInt64 :=
  let t := Guest.Ed25519.constants t
  let t := zeroWords randomInput 8 t
  let t := clamp privateKey randomInput t
  let t := Guest.Ed25519.scalarReduce randomInput scalar t
  let t := Guest.Ed25519.base Guest.Ed25519.pointR t
  let t := Guest.Ed25519.scalarMultiply scalar Guest.Ed25519.pointR Guest.Ed25519.pointR t
  let t := Guest.Ed25519.pointEncode Guest.Ed25519.pointR publicEd t
  let sign := load8 (publicEd+31) t >>> 7
  let t := negateScalar scalar negative 0 0 t
  let t := choose negative scalar scalar (0-sign &&& 255) 0 t
  store8 (publicEd+31) (load8 (publicEd+31) t &&& 127) t
partial def domainPrefix (i t : UInt64) : UInt64 :=
  if i == 32 then t else domainPrefix (i+1) (store8 (hashInput+i) (if i == 0 then 254 else 255) t)
/-- XEd25519, exact hash_1(a||M||Z), Z is64 fresh random bytes. -/
def sign (privateKey input len random64 out t : UInt64) : UInt64 :=
  if len > 1024 then Guest.Effects.effectValue err (clear t) else
  let t := keyPair privateKey t
  let t := domainPrefix 0 t
  let t := copyBytes scalar (hashInput+32) 32 t
  let t := copyBytes input (hashInput+64) len t
  let t := copyBytes random64 (hashInput+64+len) 64 t
  let t := Guest.SHA512.sha512At shaScratch hashInput (128+len) digest t
  let t := Guest.Ed25519.scalarReduce digest nonceScalar t
  let t := Guest.Ed25519.base Guest.Ed25519.pointR t
  let t := Guest.Ed25519.scalarMultiply nonceScalar Guest.Ed25519.pointR Guest.Ed25519.pointR t
  let t := Guest.Ed25519.pointEncode Guest.Ed25519.pointR out t
  let t := copyBytes out hashInput 32 t
  let t := copyBytes publicEd (hashInput+32) 32 t
  let t := copyBytes input (hashInput+64) len t
  let t := Guest.SHA512.sha512At shaScratch hashInput (64+len) digest t
  let t := Guest.Ed25519.scalarReduce digest challenge t
  clear (Guest.Ed25519.multiplyAdd nonceScalar challenge scalar (out+32) t)
/-- Strict canonical Montgomery input; sign-zero birational conversion. -/
def montgomeryToEdwards (input out t : UInt64) : UInt64 :=
  let t := Guest.Ed25519.constants t
  let t := Guest.Noise25519.unpack input (Guest.Ed25519.ft 0) 0 t
  let t := Guest.Noise25519.pack (Guest.Ed25519.ft 0) publicEd t
  if difference input publicEd 32 0 t != 0 then err else
  let t := Guest.Noise25519.sub (Guest.Ed25519.ft 0) (Guest.Ed25519.fc 5) (Guest.Ed25519.ft 1) t
  let t := Guest.Noise25519.add (Guest.Ed25519.ft 0) (Guest.Ed25519.fc 5) (Guest.Ed25519.ft 2) t
  let t := Guest.Ed25519.inverse (Guest.Ed25519.ft 2) (Guest.Ed25519.ft 3) t
  let t := Guest.Noise25519.mul (Guest.Ed25519.ft 1) (Guest.Ed25519.ft 3) (Guest.Ed25519.ft 1) t
  Guest.Noise25519.pack (Guest.Ed25519.ft 1) out t
/-- XEdDSA verification follows its uncofactored equation and 253-bit S limit. -/
def verify (publicKey input len signature t : UInt64) : Bool :=
  if len > 1024 || load8 (signature+63) t >= 32 then Guest.Effects.effectValue 1 (clear t) == 0 else
  let t := montgomeryToEdwards publicKey publicEd t
  if t == err then Guest.Effects.effectValue 1 (clear t) == 0 else
  let t := Guest.Ed25519.pointDecode publicEd Guest.Ed25519.pointA t
  if t == err then Guest.Effects.effectValue 1 (clear t) == 0 else
  let t := Guest.Ed25519.pointDecode signature Guest.Ed25519.pointB t
  if t == err then Guest.Effects.effectValue 1 (clear t) == 0 else
  let t := copyBytes signature hashInput 32 t
  let t := copyBytes publicEd (hashInput+32) 32 t
  let t := copyBytes input (hashInput+64) len t
  let t := Guest.SHA512.sha512At shaScratch hashInput (64+len) digest t
  let t := Guest.Ed25519.scalarReduce digest challenge t
  let t := Guest.Ed25519.scalarMultiply challenge Guest.Ed25519.pointA Guest.Ed25519.pointA t
  let t := Guest.Ed25519.pointAdd Guest.Ed25519.pointA Guest.Ed25519.pointB Guest.Ed25519.pointA t
  let t := Guest.Ed25519.base Guest.Ed25519.pointR t
  let t := Guest.Ed25519.scalarMultiply (signature+32) Guest.Ed25519.pointR Guest.Ed25519.pointB t
  let t := Guest.Ed25519.pointEncode Guest.Ed25519.pointA digest t
  let t := Guest.Ed25519.pointEncode Guest.Ed25519.pointB (digest+32) t
  let d := difference digest (digest+32) 32 0 t
  Guest.Effects.effectValue d (clear t) == 0

def hash (input n out t : UInt64) : UInt64 := Guest.ServiceHash.sha256At shaScratch input n out t
partial def pad (key byte i t : UInt64) : UInt64 :=
  if i == 64 then t else
  pad key byte (i+1) (store8 (hmacInput+i) ((if i < 32 then load8 (key+i) t else 0) ^^^ byte) t)
def hmac (key input len out t : UInt64) : UInt64 :=
  if len > 256 then err else
  let t := pad key 54 0 t
  let t := copyBytes input (hmacInput+64) len t
  let t := hash hmacInput (64+len) hmacInner t
  let t := pad key 92 0 t
  let t := copyBytes hmacInner (hmacInput+64) 32 t
  hash hmacInput 96 out t
-- HKDF-SHA256, info ASCII LemmaTrix-Messenger-v1 or LemmaTrix-DR-v1.
def info (kind t : UInt64) : UInt64 :=
  let t := store64 expandInput 0x697254616d6d654c t
  let t := store64 (expandInput+8) (if kind == 1 then 0x6e657373654d2d78 else 0x0031762d52442d78) t
  if kind != 1 then store8 (expandInput+15) 1 t else
  let t := store64 (expandInput+16) 0x31762d726567 t
  store8 (expandInput+22) 1 t
-- Returns root32 and chain32; salt is exactly32 bytes, IKM<=160 bytes.
def hkdf (salt input len kind out t : UInt64) : UInt64 :=
  let t := hmac salt input len prk t
  let t := info kind t
  let ilen := if kind == 1 then 23 else 16
  let t := hmac prk expandInput ilen out t
  let t := copyBytes expandInput (expandInput+32) (ilen-1) t
  let t := copyBytes out expandInput 32 t
  let t := store8 (expandInput+31+ilen) 2 t
  hmac prk expandInput (32+ilen) (out+32) t

def publicKey (privateKey out t : UInt64) : UInt64 :=
  let t := zeroWords nonce 4 t
  let t := store8 nonce 9 t
  Guest.Noise25519.x25519 privateKey nonce out t
/-- Reject forbidden all-zero DH output before any KDF. -/
def dh (privateKey publicKey out t : UInt64) : UInt64 :=
  let t := Guest.Noise25519.x25519 privateKey publicKey out t
  if nonzero out 32 0 t == 0 then err else t
partial def ff (p n t : UInt64) : UInt64 :=
  if n == 0 then t else ff (p+1) (n-1) (store8 p 255 t)
/-- X3DH X25519 HKDF-SHA256 F||DH1||DH2||DH3[||DH4]. -/
def x3dh (identity ephemeral remoteIdentity remoteSigned remoteOneTime options out t : UInt64) : UInt64 :=
  let hasOneTime := options &&& 1
  let sender := options >>> 1
  let t := ff dhMaterial 32 t
  let r := if sender == 1 then dh identity remoteSigned (dhMaterial+32) t else dh ephemeral remoteIdentity (dhMaterial+32) t
  if r == err then err else
  let r := if sender == 1 then dh ephemeral remoteIdentity (dhMaterial+64) r else dh identity remoteSigned (dhMaterial+64) r
  if r == err then err else
  let r := dh ephemeral remoteSigned (dhMaterial+96) r
  if r == err then err else
  let r := if hasOneTime == 1 then
    if sender == 1 then dh ephemeral remoteOneTime (dhMaterial+128) r else dh remoteOneTime remoteSigned (dhMaterial+128) r
    else r
  if r == err then err else
  let t := zeroWords zeroKey 4 r
  hkdf zeroKey dhMaterial (if hasOneTime == 1 then 160 else 128) 1 out t
/-- DR KDF_CK: HMAC(CK,0x01)=MK, HMAC(CK,0x02)=nextCK. -/
def chain (input next message t : UInt64) : UInt64 :=
  let t := store8 expandInput 1 t
  let t := hmac input expandInput 1 message t
  let t := store8 expandInput 2 t
  hmac input expandInput 1 next t
def root (old privateKey remote out t : UInt64) : UInt64 :=
  let r := dh privateKey remote dhMaterial t
  if r == err then err else hkdf old dhMaterial 32 2 out r
end Guest.MessengerCrypto
