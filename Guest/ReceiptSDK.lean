import Guest.LiveSDK
import Guest.Ed25519
namespace Guest.ReceiptSDK
open Guest.LiveSDK
def magic : UInt64 := 0x315250544c
def declarationMagic : UInt64 := 0x314b52544c
def sealMagic : UInt64 := 0x335349544c
def signingMagic : UInt64 := 0x31474953544c
def eq (a b n t : UInt64) : Bool := Guest.Ed25519.difference a b n 0 t == 0
def nonzero (p n t : UInt64) : Bool := Guest.Ed25519.nonzero p n 0 t != 0
def zeros (p n t : UInt64) : Bool := !nonzero p n t
def declarationBody (p t : UInt64) : Bool :=
  load64 p t == declarationMagic && load64 (p+8) t == 1 &&
  nonzero (p+16) 32 t && nonzero (p+48) 32 t && load64 (p+80) t > 0 &&
  load64 (p+88) t == 1 && zeros (p+96) 32 t
def bodyValid (p caller t : UInt64) : Bool :=
  load64 p t == magic && load64 (p+8) t == 1 && load64 (p+16) t == 1 &&
  load64 (p+24) t == caller && caller != 0 && nonzero (p+32) 32 t && nonzero (p+64) 32 t &&
  nonzero (p+96) 32 t && nonzero (p+128) 32 t &&
  load64 (p+160) t > 0 && load64 (p+160) t <= 8192 &&
  load64 (p+168) t > 0 && load64 (p+176) t == 1 && load64 (p+184) t == 0
-- node is the complete accepted480-byte node certificate returned only to the
-- current terminal owner. Caller independently matches itsSHA256 to the pin.
def declarationValid (node certificate nodeHash t : UInt64) : Bool :=
  load64 certificate t == signingMagic && load64 (certificate+8) t == 1 &&
  load64 (certificate+16) t == 3 && load64 (certificate+24) t == 3 &&
  load64 (certificate+32) t == load64 (node+32) t && load64 (certificate+40) t == 128 &&
  eq (certificate+48) (node+48) 96 t && zeros (certificate+144) 16 t &&
  declarationBody (certificate+160) t && eq (certificate+208) nodeHash 32 t &&
  Guest.Ed25519.verify (node+112) certificate 288 (certificate+288) t
-- args: exact request32 ptr,cipher32 ptr,terms32 ptr,nodeHash32 ptr,byteLength,
-- original service incarnation(0 admits a cached historical receipt). The
-- signed original incarnation remains present; a restart does not rewrite it.
def verify (args body signature certificate t : UInt64) : Bool :=
  let caller := load64 (body+24) t
  bodyValid body caller t &&
  (load64 (args+40) t == 0 || load64 (args+40) t == caller) &&
  eq (load64 args t) (body+32) 32 t && eq (load64 (args+8) t) (body+64) 32 t &&
  eq (load64 (args+16) t) (body+96) 32 t && eq (load64 (args+24) t) (body+128) 32 t &&
  load64 (args+32) t == load64 (body+160) t &&
  Guest.Ed25519.verify (certificate+176) body 192 signature t
end Guest.ReceiptSDK
