import Guest.Primitives
namespace Guest.VaultCrypto
-- RFC 8439 AEAD_CHACHA20_POLY1305, service-private serialized scratch.
-- Pointer extents/non-overlap are checked by the trusted service caller.
-- Exact key/nonce sizes: 32/12 bytes; data<=65536, AAD<=256; tag16 follows ciphertext.
def initState : UInt64 := 0x610000
def working : UInt64 := 0x610080
def stream : UInt64 := 0x610200
def polyKey : UInt64 := 0x610240
def poly : UInt64 := 0x610280
def macBlock : UInt64 := 0x610300
def computedTag : UInt64 := 0x610320
def mask32 : UInt64 := 0xffffffff
def mask26 : UInt64 := 0x3ffffff
def err : UInt64 := 0xffffffffffffffff

def le32 (p t : UInt64) : UInt64 :=
  load8 p t ||| (load8 (p+1) t <<< 8) ||| (load8 (p+2) t <<< 16) ||| (load8 (p+3) t <<< 24)
partial def putLE (p v n t : UInt64) : UInt64 :=
  if n == 0 then t else putLE (p+1) (v >>> 8) (n-1) (store8 p (v &&& 255) t)
partial def copy (src dst n t : UInt64) : UInt64 :=
  if n == 0 then t else copy (src+1) (dst+1) (n-1) (store8 dst (load8 src t) t)
partial def clear (p n t : UInt64) : UInt64 :=
  if n == 0 then t else clear (p+8) (n-1) (store64 p 0 t)
def rotl (x n : UInt64) : UInt64 := ((x <<< n) ||| (x >>> (32-n))) &&& mask32

def qr (ai bi ci di t : UInt64) : UInt64 :=
  let a := load64 (working+ai*8) t
  let b := load64 (working+bi*8) t
  let c := load64 (working+ci*8) t
  let d := load64 (working+di*8) t
  let a := (a+b) &&& mask32
  let d := rotl (d ^^^ a) 16
  let c := (c+d) &&& mask32
  let b := rotl (b ^^^ c) 12
  let a := (a+b) &&& mask32
  let d := rotl (d ^^^ a) 8
  let c := (c+d) &&& mask32
  let b := rotl (b ^^^ c) 7
  let t := store64 (working+ai*8) a t
  let t := store64 (working+bi*8) b t
  let t := store64 (working+ci*8) c t
  store64 (working+di*8) d t
partial def rounds (n t : UInt64) : UInt64 :=
  if n == 0 then t else
    let t := qr 0 4 8 12 t
    let t := qr 1 5 9 13 t
    let t := qr 2 6 10 14 t
    let t := qr 3 7 11 15 t
    let t := qr 0 5 10 15 t
    let t := qr 1 6 11 12 t
    let t := qr 2 7 8 13 t
    let t := qr 3 4 9 14 t
    rounds (n-1) t
partial def keyWords (key i t : UInt64) : UInt64 :=
  if i == 8 then t else keyWords key (i+1) (store64 (initState+32+i*8) (le32 (key+i*4) t) t)
partial def copyState (i t : UInt64) : UInt64 :=
  if i == 16 then t else copyState (i+1) (store64 (working+i*8) (load64 (initState+i*8) t) t)
partial def serialize (i t : UInt64) : UInt64 :=
  if i == 16 then t else
    let w := (load64 (working+i*8) t+load64 (initState+i*8) t) &&& mask32
    serialize (i+1) (putLE (stream+i*4) w 4 t)
def block (key nonce counter t : UInt64) : UInt64 :=
  let t := store64 initState 0x61707865 t
  let t := store64 (initState+8) 0x3320646e t
  let t := store64 (initState+16) 0x79622d32 t
  let t := store64 (initState+24) 0x6b206574 t
  let t := keyWords key 0 t
  let t := store64 (initState+96) counter t
  let t := store64 (initState+104) (le32 nonce t) t
  let t := store64 (initState+112) (le32 (nonce+4) t) t
  let t := store64 (initState+120) (le32 (nonce+8) t) t
  let t := copyState 0 t
  let t := rounds 10 t
  serialize 0 t
partial def xorBytes (input out count i t : UInt64) : UInt64 :=
  if i == count then t else
    let b := load8 (input+i) t ^^^ load8 (stream+i) t
    xorBytes input out count (i+1) (store8 (out+i) b t)
partial def crypt (key nonce input out remaining counter t : UInt64) : UInt64 :=
  if remaining == 0 then t else
    let n := if remaining < 64 then remaining else 64
    let t := block key nonce counter t
    let t := xorBytes input out n 0 t
    crypt key nonce (input+n) (out+n) (remaining-n) (counter+1) t

def initPoly (t : UInt64) : UInt64 :=
  let t := clear poly 5 t
  let t := store64 (poly+40) (le32 polyKey t &&& 0x3ffffff) t
  let t := store64 (poly+48) ((le32 (polyKey+3) t >>> 2) &&& 0x3ffff03) t
  let t := store64 (poly+56) ((le32 (polyKey+6) t >>> 4) &&& 0x3ffc0ff) t
  let t := store64 (poly+64) ((le32 (polyKey+9) t >>> 6) &&& 0x3f03fff) t
  store64 (poly+72) ((le32 (polyKey+12) t >>> 8) &&& 0xfffff) t

def multiplyPoly (t : UInt64) : UInt64 :=
  let h0 : UInt64 := load64 poly t+(le32 macBlock t &&& mask26)
  let h1 : UInt64 := load64 (poly+8) t+((le32 (macBlock+3) t >>> 2) &&& mask26)
  let h2 : UInt64 := load64 (poly+16) t+((le32 (macBlock+6) t >>> 4) &&& mask26)
  let h3 : UInt64 := load64 (poly+24) t+((le32 (macBlock+9) t >>> 6) &&& mask26)
  let h4 : UInt64 := load64 (poly+32) t+(le32 (macBlock+12) t >>> 8)+0x1000000
  let r0 : UInt64 := load64 (poly+40) t
  let r1 : UInt64 := load64 (poly+48) t
  let r2 : UInt64 := load64 (poly+56) t
  let r3 : UInt64 := load64 (poly+64) t
  let r4 : UInt64 := load64 (poly+72) t
  let d0 : UInt64 := h0*r0+h1*r4*(5 : UInt64)+h2*r3*(5 : UInt64)+h3*r2*(5 : UInt64)+h4*r1*(5 : UInt64)
  let d1 : UInt64 := h0*r1+h1*r0+h2*r4*(5 : UInt64)+h3*r3*(5 : UInt64)+h4*r2*(5 : UInt64)+(d0 >>> 26)
  let d2 : UInt64 := h0*r2+h1*r1+h2*r0+h3*r4*(5 : UInt64)+h4*r3*(5 : UInt64)+(d1 >>> 26)
  let d3 : UInt64 := h0*r3+h1*r2+h2*r1+h3*r0+h4*r4*(5 : UInt64)+(d2 >>> 26)
  let d4 : UInt64 := h0*r4+h1*r3+h2*r2+h3*r1+h4*r0+(d3 >>> 26)
  let h0 : UInt64 := (d0 &&& mask26)+(d4 >>> 26)*(5 : UInt64)
  let t := store64 poly (h0 &&& mask26) t
  let t := store64 (poly+8) ((d1 &&& mask26)+(h0 >>> 26)) t
  let t := store64 (poly+16) (d2 &&& mask26) t
  let t := store64 (poly+24) (d3 &&& mask26) t
  store64 (poly+32) (d4 &&& mask26) t

def macByte (aad alen ciphertext len index t : UInt64) : UInt64 :=
  let aPadded := ((alen+15)/16)*16
  let cPadded := ((len+15)/16)*16
  if index < alen then load8 (aad+index) t
  else if index < aPadded then 0
  else if index < aPadded+len then load8 (ciphertext+index-aPadded) t
  else if index < aPadded+cPadded then 0
  else if index < aPadded+cPadded+8 then (alen >>> ((index-aPadded-cPadded)*8)) &&& 255
  else (len >>> ((index-aPadded-cPadded-8)*8)) &&& 255
partial def loadMacBlock (aad alen ciphertext len offset i t : UInt64) : UInt64 :=
  if i == 16 then t else
    loadMacBlock aad alen ciphertext len offset (i+1) (store8 (macBlock+i) (macByte aad alen ciphertext len (offset+i) t) t)
partial def macBlocks (aad alen ciphertext len offset total t : UInt64) : UInt64 :=
  if offset == total then t else
    let t := loadMacBlock aad alen ciphertext len offset 0 t
    let t := multiplyPoly t
    macBlocks aad alen ciphertext len (offset+16) total t

def finishPoly (t : UInt64) : UInt64 :=
  let h0 : UInt64 := load64 poly t
  let h1 : UInt64 := load64 (poly+8) t
  let h2 : UInt64 := load64 (poly+16) t+(h1 >>> 26)
  let h3 : UInt64 := load64 (poly+24) t+(h2 >>> 26)
  let h4 : UInt64 := load64 (poly+32) t+(h3 >>> 26)
  let h0 : UInt64 := h0+(h4 >>> 26)*(5 : UInt64)
  let h1 : UInt64 := (h1 &&& mask26)+(h0 >>> 26)
  let h0 : UInt64 := h0 &&& mask26
  let h2 : UInt64 := h2 &&& mask26
  let h3 : UInt64 := h3 &&& mask26
  let h4 : UInt64 := h4 &&& mask26
  let g0 : UInt64 := h0+5
  let g1 : UInt64 := h1+(g0 >>> 26)
  let g2 : UInt64 := h2+(g1 >>> 26)
  let g3 : UInt64 := h3+(g2 >>> 26)
  let g4 : UInt64 := h4+(g3 >>> 26)-0x4000000
  let m : UInt64 := (g4 >>> 63)-1
  let nm : UInt64 := m ^^^ 0xffffffffffffffff
  let h0 : UInt64 := (h0 &&& nm) ||| (g0 &&& mask26 &&& m)
  let h1 : UInt64 := (h1 &&& nm) ||| (g1 &&& mask26 &&& m)
  let h2 : UInt64 := (h2 &&& nm) ||| (g2 &&& mask26 &&& m)
  let h3 : UInt64 := (h3 &&& nm) ||| (g3 &&& mask26 &&& m)
  let h4 : UInt64 := (h4 &&& nm) ||| (g4 &&& mask26 &&& m)
  let f0 : UInt64 := ((h0 ||| (h1 <<< 26)) &&& mask32)+le32 (polyKey+16) t
  let f1 : UInt64 := (((h1 >>> 6) ||| (h2 <<< 20)) &&& mask32)+le32 (polyKey+20) t+(f0 >>> 32)
  let f2 : UInt64 := (((h2 >>> 12) ||| (h3 <<< 14)) &&& mask32)+le32 (polyKey+24) t+(f1 >>> 32)
  let f3 : UInt64 := (((h3 >>> 18) ||| (h4 <<< 8)) &&& mask32)+le32 (polyKey+28) t+(f2 >>> 32)
  let t := putLE computedTag f0 4 t
  let t := putLE (computedTag+4) f1 4 t
  let t := putLE (computedTag+8) f2 4 t
  putLE (computedTag+12) f3 4 t

def authenticate (key nonce aad alen ciphertext len t : UInt64) : UInt64 :=
  let t := block key nonce 0 t
  let t := copy stream polyKey 32 t
  let t := initPoly t
  let total := ((alen+15)/16)*16+((len+15)/16)*16+16
  let t := macBlocks aad alen ciphertext len 0 total t
  finishPoly t
partial def tagDifference (expected actual i diff t : UInt64) : UInt64 :=
  if i == 16 then diff else
    tagDifference expected actual (i+1) (diff ||| (load8 (expected+i) t ^^^ load8 (actual+i) t)) t

def encrypt (key nonce aad alen input len out t : UInt64) : UInt64 :=
  if len > 65536 || alen > 256 then err else
    let t := crypt key nonce input out len 1 t
    let t := authenticate key nonce aad alen out len t
    let t := copy computedTag (out+len) 16 t
    clear initState 104 t

def decrypt (key nonce aad alen input len out t : UInt64) : UInt64 :=
  if len > 65536 || alen > 256 then err else
    let t := authenticate key nonce aad alen input len t
    if tagDifference computedTag (input+len) 0 0 t != 0 then err+clear initState 104 t
    else
      let t := crypt key nonce input out len 1 t
      clear initState 104 t
end Guest.VaultCrypto
