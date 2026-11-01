import Guest.Effects
import Guest.AES
import Guest.SHA3
import Guest.Noise25519
namespace Guest.TorNtor
-- ntor3-curve25519-sha3_256-1, official Tor spec retrieved2026-10-31.
-- HTYPE3. Canonical selected extension message is exactly byte0 (no extensions).
-- Caller scratch8192, client state256. No raw keys returned except Tor hop keys.
-- args: pointers ID0,B8,fresh private16,VER24,VER length32,CM/SM40,length48.
-- client HDATA129, server HDATA65. Result is effect token, err on failure.
-- Fresh private scalar comes from narrow admitted entropy, never host fixtures.
-- All caller pointers/extents must be checked before entering these routines.
def err : UInt64 := 0xffffffffffffffff
partial def zero (p n t : UInt64) : UInt64 :=
  if n == 0 then t else zero (p+1) (n-1) (store8 p 0 t)
partial def copy (a b n t : UInt64) : UInt64 :=
  if n == 0 then t else copy (a+1) (b+1) (n-1) (store8 b (load8 a t) t)
partial def difference (a b n v t : UInt64) : UInt64 :=
  if n == 0 then v else difference (a+1) (b+1) (n-1) (v ||| (load8 a t ^^^ load8 b t)) t
partial def nonzero (a n v t : UInt64) : UInt64 :=
  if n == 0 then v else nonzero (a+1) (n-1) (v ||| load8 a t) t
partial def beBytes (p value n i t : UInt64) : UInt64 :=
  if i == n then t else beBytes p value n (i+1) (store8 (p+i) ((value >>> ((n-1-i)*8)) &&& 255) t)
def clear (s t : UInt64) : UInt64 := zero s 8192 t
def append (s input n t : UInt64) : UInt64 :=
  let p := load64 (s+384) t
  store64 (s+384) (p+n) (copy input (s+512+p) n t)
def number (s value t : UInt64) : UInt64 :=
  let p := load64 (s+384) t
  store64 (s+384) (p+8) (beBytes (s+512+p) value 8 0 t)
def proto (s t : UInt64) : UInt64 :=
  let t := store64 (s+512) 0x75632d33726f746e t
  let t := store64 (s+520) 0x3931353532657672 t
  let t := store64 (s+528) 0x35325f336168732d t
  let t := store8 (s+536) 54 t
  let t := store8 (s+537) 45 t
  let t := store8 (s+538) 49 t
  t
def begin (s tag t : UInt64) : UInt64 :=
  if tag == 1 then
    let t := beBytes (s+512) 38 8 0 t
    let t := store64 (s+520) 0x75632d33726f746e t
    let t := store64 (s+528) 0x3931353532657672 t
    let t := store64 (s+536) 0x35325f336168732d t
    let t := store64 (s+544) 0x5f66646b3a312d36 t
    let t := store8 (s+552) 112 t
    let t := store8 (s+553) 104 t
    let t := store8 (s+554) 97 t
    let t := store8 (s+555) 115 t
    let t := store8 (s+556) 101 t
    let t := store8 (s+557) 49 t
    store64 (s+384) 46 t
  else
  if tag == 2 then
    let t := beBytes (s+512) 35 8 0 t
    let t := store64 (s+520) 0x75632d33726f746e t
    let t := store64 (s+528) 0x3931353532657672 t
    let t := store64 (s+536) 0x35325f336168732d t
    let t := store64 (s+544) 0x5f67736d3a312d36 t
    let t := store8 (s+552) 109 t
    let t := store8 (s+553) 97 t
    let t := store8 (s+554) 99 t
    store64 (s+384) 43 t
  else
  if tag == 3 then
    let t := beBytes (s+512) 36 8 0 t
    let t := store64 (s+520) 0x75632d33726f746e t
    let t := store64 (s+528) 0x3931353532657672 t
    let t := store64 (s+536) 0x35325f336168732d t
    let t := store64 (s+544) 0x5f79656b3a312d36 t
    let t := store8 (s+552) 115 t
    let t := store8 (s+553) 101 t
    let t := store8 (s+554) 101 t
    let t := store8 (s+555) 100 t
    store64 (s+384) 44 t
  else
  if tag == 4 then
    let t := beBytes (s+512) 34 8 0 t
    let t := store64 (s+520) 0x75632d33726f746e t
    let t := store64 (s+528) 0x3931353532657672 t
    let t := store64 (s+536) 0x35325f336168732d t
    let t := store64 (s+544) 0x697265763a312d36 t
    let t := store8 (s+552) 102 t
    let t := store8 (s+553) 121 t
    store64 (s+384) 42 t
  else
  if tag == 5 then
    let t := beBytes (s+512) 37 8 0 t
    let t := store64 (s+520) 0x75632d33726f746e t
    let t := store64 (s+528) 0x3931353532657672 t
    let t := store64 (s+536) 0x35325f336168732d t
    let t := store64 (s+544) 0x5f66646b3a312d36 t
    let t := store8 (s+552) 102 t
    let t := store8 (s+553) 105 t
    let t := store8 (s+554) 110 t
    let t := store8 (s+555) 97 t
    let t := store8 (s+556) 108 t
    store64 (s+384) 45 t
  else
  if tag == 6 then
    let t := beBytes (s+512) 38 8 0 t
    let t := store64 (s+520) 0x75632d33726f746e t
    let t := store64 (s+528) 0x3931353532657672 t
    let t := store64 (s+536) 0x35325f336168732d t
    let t := store64 (s+544) 0x687475613a312d36 t
    let t := store8 (s+552) 95 t
    let t := store8 (s+553) 102 t
    let t := store8 (s+554) 105 t
    let t := store8 (s+555) 110 t
    let t := store8 (s+556) 97 t
    let t := store8 (s+557) 108 t
    store64 (s+384) 46 t
  else
  err
def appendProto (s t : UInt64) : UInt64 :=
  let t := proto (s+1024) t
  append s (s+1536) 27 t
def complete (s out shake n t : UInt64) : UInt64 :=
  let len := load64 (s+384) t
  if shake == 0 then Guest.SHA3.sha3 s (s+256) (s+512) len out t
  else Guest.SHA3.shake s (s+256) (s+512) len out n t
def verification (s args t : UInt64) : UInt64 :=
  let n := load64 (args+32) t
  append s (load64 (args+24) t) n (number s n t)
def phase1 (s st args t : UInt64) : UInt64 :=
  let t := begin s 1 t
  let t := append s (st+128) 32 t
  let t := append s (st+96) 32 t
  let t := append s (st+32) 32 t
  let t := append s (st+64) 32 t
  let t := appendProto s t
  let t := verification s args t
  complete s (s+2048) 1 64 t
def messageMac (s st msg n out t : UInt64) : UInt64 :=
  let t := begin s 2 t
  let t := number s 32 t
  let t := append s (s+2080) 32 t
  let t := append s (st+96) 32 t
  let t := append s (st+64) 32 t
  let t := append s (st+32) 32 t
  complete s out 0 32 (append s msg n t)
def secret (s st remote args tag t : UInt64) : UInt64 :=
  let t := begin s tag t
  let t := append s (s+2304) 32 t
  let t := append s (st+128) 32 t
  let t := append s (st+96) 32 t
  let t := append s (st+64) 32 t
  let t := append s (st+32) 32 t
  let t := append s remote 32 t
  let t := appendProto s t
  verification s args t
def finalKeys (s st remote args t : UInt64) : UInt64 :=
  let t := complete s (s+2240) 0 32 (secret s st remote args 3 t)
  let t := complete s (s+2208) 0 32 (secret s st remote args 4 t)
  let t := append s (s+2240) 32 (begin s 5 t)
  complete s (s+2048) 1 124 t
def authenticator (s st remote msg n out t : UInt64) : UInt64 :=
  let t := begin s 6 t
  let t := append s (s+2208) 32 t
  let t := append s (st+96) 32 t
  let t := append s (st+64) 32 t
  let t := append s remote 32 t
  let t := append s (st+32) 32 t
  let t := append s (st+160) 32 t
  let t := append s msg n (number s n t)
  let t := appendProto s t
  let t := store64 (s+2400) 0x0000726576726553 t
  complete s out 0 32 (append s (s+2400) 6 t)
def validArgs (args t : UInt64) : Bool :=
  load64 (args+32) t <= 128 && load64 (args+48) t == 1 && load8 (load64 (args+40) t) t == 0
def publicKey (privateKey out t : UInt64) : UInt64 :=
  let t := zero out 32 t
  Guest.Noise25519.x25519 privateKey out out (store8 out 9 t)
def clientStart (s st args out t : UInt64) : UInt64 :=
  let t := zero st 256 (clear s t)
  if !validArgs args t then err else
    let t := copy (load64 (args+16) t) st 32 t
    let t := copy (load64 args t) (st+96) 32 t
    let t := copy (load64 (args+8) t) (st+64) 32 t
    let t := publicKey st (st+32) t
    let t := Guest.Noise25519.x25519 st (st+64) (st+128) t
    if nonzero (st+128) 32 0 t == 0 then
      let t := zero st 256 (clear s t)
      Guest.Effects.effectValue err t
    else
      let t := phase1 s st args t
      let t := Guest.AES.init (s+4096) (s+2048) 32 t
      let t := Guest.AES.crypt (s+4096) (load64 (args+40) t) (out+96) 1 t
      let t := messageMac s st (out+96) 1 (st+160) t
      let t := copy (st+96) out 32 t
      let t := copy (st+64) (out+32) 32 t
      let t := copy (st+32) (out+64) 32 t
      let t := copy (st+160) (out+97) 32 t
      clear s (store64 (st+192) 1 t)
-- server args additionally holds onionPrivate pointer56. Input must be129 bytes.
def serverRespond (s args input inputLen out keys t : UInt64) : UInt64 :=
  let t := clear s t
  let st := s+3072
  if !validArgs args t || inputLen != 129 then err else
    if difference input (load64 args t) 32 0 t != 0 || difference (input+32) (load64 (args+8) t) 32 0 t != 0 then err else
      let t := copy input (st+96) 32 t
      let t := copy (input+32) (st+64) 32 t
      let t := copy (input+64) (st+32) 32 t
      let t := copy (input+97) (st+160) 32 t
      let t := Guest.Noise25519.x25519 (load64 (args+56) t) (st+32) (st+128) t
      if nonzero (st+128) 32 0 t == 0 then
        let t := clear s t
        Guest.Effects.effectValue err t
      else
        let t := phase1 s st args t
        let t := messageMac s st (input+96) 1 (s+2272) t
        if difference (s+2272) (st+160) 32 0 t != 0 then
          let t := clear s t
          Guest.Effects.effectValue err t
        else
          let t := Guest.AES.init (s+4096) (s+2048) 32 t
          let t := Guest.AES.crypt (s+4096) (input+96) (s+2400) 1 t
          if load8 (s+2400) t != 0 then
            let t := clear s t
            Guest.Effects.effectValue err t
          else
            let t := publicKey (load64 (args+16) t) out t
            let t := Guest.Noise25519.x25519 (load64 (args+16) t) (st+32) (s+2304) t
            if nonzero (s+2304) 32 0 t == 0 then
              let t := clear s t
              Guest.Effects.effectValue err t
            else
              let t := finalKeys s st out args t
              let t := Guest.AES.init (s+4096) (s+2048) 32 t
              let t := Guest.AES.crypt (s+4096) (load64 (args+40) t) (out+64) 1 t
              let t := authenticator s st out (out+64) 1 (out+32) t
              clear s (copy (s+2080) keys 92 t)
def clientFinish (s st args input inputLen keys t : UInt64) : UInt64 :=
  let t := clear s t
  if !validArgs args t || inputLen != 65 || load64 (st+192) t != 1 then err else
    let t := Guest.Noise25519.x25519 st input (s+2304) t
    if nonzero (s+2304) 32 0 t == 0 then
      let t := zero st 256 (clear s t)
      Guest.Effects.effectValue err t
    else
      let t := finalKeys s st input args t
      let t := authenticator s st input (input+64) 1 (s+2272) t
      if difference (s+2272) (input+32) 32 0 t != 0 then
        let t := zero st 256 (clear s t)
        Guest.Effects.effectValue err t
      else
        let t := Guest.AES.init (s+4096) (s+2048) 32 t
        let t := Guest.AES.crypt (s+4096) (input+64) (s+2400) 1 t
        if load8 (s+2400) t != 0 then
          let t := zero st 256 (clear s t)
          Guest.Effects.effectValue err t
        else zero st 256 (clear s (copy (s+2080) keys 92 t))
end Guest.TorNtor
