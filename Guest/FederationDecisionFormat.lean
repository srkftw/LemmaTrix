import Guest.ReleaseFormat
namespace Guest.FederationDecisionFormat
open Guest.LiveMemory
def messageLength : UInt64 := 538
def signedMessage (p out t : UInt64) : UInt64 :=
  let t := store64 out 0x52454445462d544c t
  let t := store64 (out+8) 0x45442d4e4f495441 t
  let t := store64 (out+16) 0x562d4e4f49534943 t
  let t := store64 (out+24) 0x32 t
  copy p (out+26) 512 t
def validHeader (p t : UInt64) : Bool :=
  load64 p t == 0x314d4441544c && load64 (p+8) t == 2 &&
  load64 (p+48) t > 0 && load64 (p+384) t == 1 &&
  load64 (p+392) t > 0 && load64 (p+392) t <= 0xffffffff &&
  (!Guest.ReleaseFormat.zeros (p+128) 32 t || load64 (p+16) t == 1 ||
    (load64 (p+16) t == 3 && load64 (p+24) t == 1)) && !Guest.ReleaseFormat.zeros (p+256) 32 t &&
  !Guest.ReleaseFormat.zeros (p+288) 32 t && !Guest.ReleaseFormat.zeros (p+320) 32 t
def verify (p publicKey t : UInt64) : Bool :=
  if !validHeader p t || !equal publicKey (p+576) 32 t then false else
  let t := Guest.ServiceHash.sha256At 0x600200 publicKey 32 0x603300 t
  if !equal 0x603300 (p+288) 32 t then false else
  let t := copy 0x632000 0x603400 256 t
  let t := signedMessage p 0x603000 t
  let valid := Guest.Ed25519.verify publicKey 0x603000 messageLength (p+512) t
  let t := copy 0x603400 0x632000 256 t
  Guest.Effects.effectValue (if valid then 1 else 0) t == 1
end Guest.FederationDecisionFormat
