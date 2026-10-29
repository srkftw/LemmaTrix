import Guest.Noise25519
import Guest.VaultCrypto
import Guest.ServiceSHA256
namespace Guest.Noise
-- Noise Framework revision34: Noise_NNpsk0_25519_ChaChaPoly_SHA256.
-- One ordered externally provisioned PSK relationship; prologue binds ordered
-- client/server public identity digests and pinned service descriptor digest.
-- NNpsk0 authenticates possession of this relationship secret, not signatures.
def state : UInt64 := 0x600000
def ck : UInt64 := state+96
def h : UInt64 := state+128
def key : UInt64 := state+160
def privateKey : UInt64 := state+192
def publicKey : UInt64 := state+224
def remoteKey : UInt64 := state+256
def psk : UInt64 := state+288
def binding : UInt64 := state+320
def hashScratch : UInt64 := 0x625000
def concat : UInt64 := 0x626000
def hmacInput : UInt64 := 0x620000
def hmacInner : UInt64 := 0x620400
def hmacOuter : UInt64 := 0x620440
def hkdfTemp : UInt64 := 0x620500
def hkdfOut : UInt64 := 0x620540
def hkdfThree : UInt64 := 0x620580
def nonce : UInt64 := 0x620900
def err : UInt64 := 0xffffffffffffffff
open Guest.VaultCrypto (copy clear)
partial def fillPad (k pad i t : UInt64) : UInt64 :=
  if i == 64 then t else
    let v := if i < 32 then load8 (k+i) t else 0
    fillPad k pad (i+1) (store8 (hmacInput+i) (v ^^^ pad) t)
def hash (input n out t : UInt64) : UInt64 := Guest.ServiceHash.sha256At hashScratch input n out t
-- Restricted HMAC: key32 and message<=256, all actual Noise calls fit.
def hmac (k input n out t : UInt64) : UInt64 :=
  if n > 256 then err else
    let t := fillPad k 54 0 t
    let t := copy input (hmacInput+64) n t
    let t := hash hmacInput (64+n) hmacInner t
    let t := fillPad k 92 0 t
    let t := copy hmacInner (hmacInput+64) 32 t
    hash hmacInput 96 out t
-- Noise HKDF, outputs2 or3. `input` can be empty; exact RFC5869 expansion.
def hkdf (input n outputs t : UInt64) : UInt64 :=
  let t := hmac ck input n hkdfTemp t
  let t := store8 hmacOuter 1 t
  let t := hmac hkdfTemp hmacOuter 1 hkdfOut t
  let t := copy hkdfOut hmacOuter 32 t
  let t := store8 (hmacOuter+32) 2 t
  let t := hmac hkdfTemp hmacOuter 33 key t
  if outputs == 2 then copy hkdfOut ck 32 t else
    let t := copy key hmacOuter 32 t
    let t := store8 (hmacOuter+32) 3 t
    let t := hmac hkdfTemp hmacOuter 33 hkdfThree t
    let t := copy hkdfOut ck 32 t
    let t := copy key hkdfOut 32 t
    copy hkdfThree key 32 t
def mixHash (input n t : UInt64) : UInt64 :=
  if n > 256 then err else
    let t := copy h concat 32 t
    let t := copy input (concat+32) n t
    hash concat (32+n) h t
def mixKey (input n t : UInt64) : UInt64 := hkdf input n 2 t
def mixKeyAndHash (input n t : UInt64) : UInt64 :=
  let t := hkdf input n 3 t
  mixHash hkdfOut 32 t
partial def difference (a b n diff t : UInt64) : UInt64 :=
  if n == 0 then diff else difference (a+1) (b+1) (n-1) (diff ||| (load8 a t ^^^ load8 b t)) t
partial def nonzero (a n v t : UInt64) : UInt64 :=
  if n == 0 then v else nonzero (a+1) (n-1) (v ||| load8 a t) t
/-- Fresh initialization is mandatory per stream attempt. No session keys persist. -/
def initHandshake (role t : UInt64) : UInt64 :=
  -- Protocol name is longer than HASHLEN, so h=SHA256(protocol_name).
  let t := store64 concat 0x4e4e5f6573696f4e t
  let t := store64 (concat+8) 0x3535325f306b7370 t
  let t := store64 (concat+16) 0x68436168435f3931 t
  let t := store64 (concat+24) 0x48535f796c6f5061 t
  let t := store64 (concat+32) 0x0000000036353241 t
  let t := hash concat 36 h t
  let t := copy h ck 32 t
  let t := mixHash binding 96 t
  let t := mixKeyAndHash psk 32 t
  let t := clear publicKey 8 t
  let t := store8 publicKey 9 t
  let t := Guest.Noise25519.x25519 privateKey publicKey publicKey t
  let t := clear (state+16) 2 t
  let t := store64 state role t
  store64 (state+8) 1 t

def emptySeal (out t : UInt64) : UInt64 :=
  let t := clear nonce 2 t
  let t := Guest.VaultCrypto.encrypt key nonce h 32 out 0 out t
  mixHash out 16 t
def emptyOpen (input t : UInt64) : UInt64 :=
  let t := clear nonce 2 t
  let r := Guest.VaultCrypto.decrypt key nonce h 32 input 0 concat t
  if r == err then err else mixHash input 16 r

def split (t : UInt64) : UInt64 :=
  let t := hkdf concat 0 2 t
  let role := load64 state t
  let t := copy ck (state+(if role == 1 then 32 else 64)) 32 t
  let t := copy key (state+(if role == 1 then 64 else 32)) 32 t
  let t := clear ck 24 t
  store64 (state+8) 3 t

def writeFirst (out t : UInt64) : UInt64 :=
  if load64 state t != 1 || load64 (state+8) t != 1 then err else
    let t := copy publicKey out 32 t
    let t := mixHash publicKey 32 t
    let t := mixKey publicKey 32 t
    let t := emptySeal (out+32) t
    store64 (state+8) 2 t

def readFirst (input t : UInt64) : UInt64 :=
  if load64 state t != 2 || load64 (state+8) t != 1 then err else
    let t := copy input remoteKey 32 t
    let t := mixHash remoteKey 32 t
    let t := mixKey remoteKey 32 t
    let r := emptyOpen (input+32) t
    if r == err then err else store64 (state+8) 2 r

def dh (t : UInt64) : UInt64 :=
  let t := Guest.Noise25519.x25519 privateKey remoteKey concat t
  if nonzero concat 32 0 t == 0 then err else mixKey concat 32 t

def writeSecond (out t : UInt64) : UInt64 :=
  if load64 state t != 2 || load64 (state+8) t != 2 then err else
    let t := copy publicKey out 32 t
    let t := mixHash publicKey 32 t
    let t := mixKey publicKey 32 t
    let r := dh t
    if r == err then err else split (emptySeal (out+32) r)

def readSecond (input t : UInt64) : UInt64 :=
  if load64 state t != 1 || load64 (state+8) t != 2 then err else
    let t := copy input remoteKey 32 t
    let t := mixHash remoteKey 32 t
    let t := mixKey remoteKey 32 t
    let r := dh t
    if r == err then err else
      let r := emptyOpen (input+32) r
      if r == err then err else split r

-- Noise transport carries authenticated ordered records. Profile expires at
-- 2^20 records/direction; only a fresh entropy-backed handshake renews it.
def sealRecord (input n out t : UInt64) : UInt64 :=
  let counter := load64 (state+16) t
  if load64 (state+8) t != 3 || n > 768 || counter >= 1048576 then err else
    let t := clear nonce 2 t
    let t := Guest.VaultCrypto.putLE (nonce+4) counter 8 t
    let t := Guest.VaultCrypto.encrypt (state+32) nonce nonce 0 input n out t
    store64 (state+16) (counter+1) t

def openRecord (input n out t : UInt64) : UInt64 :=
  let counter := load64 (state+24) t
  if load64 (state+8) t != 3 || n < 16 || n > 784 || counter >= 1048576 then err else
    let t := clear nonce 2 t
    let t := Guest.VaultCrypto.putLE (nonce+4) counter 8 t
    let r := Guest.VaultCrypto.decrypt (state+64) nonce nonce 0 input (n-16) out t
    if r == err then err else store64 (state+24) (counter+1) r

def disconnect (t : UInt64) : UInt64 :=
  let t := clear state 40 t
  clear 0x620000 320 t
end Guest.Noise
