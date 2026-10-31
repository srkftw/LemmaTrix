import Guest.MessengerCrypto
import Guest.LiveSDK
namespace Guest.MessengerAttachment
open Guest.LiveSDK
-- Two transfers, each with sixteen512-byte exact ciphertext retry entries.
-- Keys remain in the session
-- owner's private arena. Chunk identifiers reveal only random transfer IDs.
def slotAt (i : UInt64) : UInt64 := 0x6d0000+i*10240
def cacheAt (a index : UInt64) : UInt64 := a+256+(index%16)*576
def aad : UInt64 := 0x65b000
def nonce : UInt64 := 0x65b080
def hashed : UInt64 := 0x65b100
def err : UInt64 := 0xffffffffffffffff
partial def free (i t : UInt64) : UInt64 :=
  if i == 2 then err else if load64 (slotAt i) t == 0 then slotAt i else free (i+1) t
partial def find (handle i t : UInt64) : UInt64 :=
  if i == 2 then err else if load64 (slotAt i) t != 0 && load64 (slotAt i+8) t == handle then slotAt i else find handle (i+1) t
partial def findId (id i t : UInt64) : UInt64 :=
  if i == 2 then err else
  if load64 (slotAt i) t != 0 && Guest.Ed25519.difference (slotAt i+64) id 32 0 t == 0 then slotAt i else findId id (i+1) t

def draw (p t : UInt64) : UInt64 :=
  let r := syscall 130 0 p 32 0 t
  if r == 0 then r else err
-- Manifest is128 bytes: magic,version,total,chunk512,key32,id32,reserved32.
-- It may only be copied into an end-to-end encrypted Messenger message.
def create (handle total manifest t : UInt64) : UInt64 :=
  let a := free 0 t
  if a == err || handle == 0 || total == 0 || total > 8388608 then err else
  let t := zero a 1280 t
  let r := draw (a+32) t
  if r == err then err else
  let r := draw (a+64) r
  if r == err then err else
  let t := store64 a 1 r
  let t := store64 (a+8) handle t
  let t := store64 (a+96) total t
  let t := zero manifest 16 t
  let t := store64 manifest 0x31414d544c t
  let t := store64 (manifest+8) 1 t
  let t := store64 (manifest+16) total t
  let t := store64 (manifest+24) 512 t
  copy (a+32) (manifest+32) 64 t

def accept (handle manifest t : UInt64) : UInt64 :=
  let total := load64 (manifest+16) t
  let a := free 0 t
  if load64 manifest t != 0x31414d544c || load64 (manifest+8) t != 1 ||
      load64 (manifest+24) t != 512 || total == 0 || total > 8388608 || a == err then err else
  if Guest.Ed25519.nonzero (manifest+32) 64 0 t == 0 || findId (manifest+64) 0 t != err then err else
  let t := zero a 1280 t
  let t := store64 a 2 t
  let t := store64 (a+8) handle t
  let t := store64 (a+96) total t
  let t := copy (manifest+32) (a+32) 64 t
  copy (manifest+96) (a+128) 32 t

def chunkLength (a index t : UInt64) : UInt64 :=
  let total := load64 (a+96) t
  if index >= (total+511)/512 then 0 else if total-index*512 < 512 then total-index*512 else 512

partial def validCache (a i t : UInt64) : Bool :=
  if i == 16 then true else
  let p := a+256+i*576
  let number := load64 p t
  (number == 0 || (number <= (load64 (a+96) t+511)/512 &&
    (number-1)%16 == i && load64 (p+8) t == chunkLength a (number-1) t)) && validCache a (i+1) t
def validSlot (a t : UInt64) : Bool :=
  load64 a t == 0 || ((load64 a t == 1 || load64 a t == 2) &&
    load64 (a+8) t != 0 && load64 (a+96) t > 0 && load64 (a+96) t <= 8388608 &&
    load64 (a+120) t <= 1 &&
    load64 (a+104) t <= (load64 (a+96) t+511)/512 &&
    load64 (a+112) t <= load64 (a+104) t && load64 (a+104) t-load64 (a+112) t <= 16 && validCache a 0 t)

def context (a index n t : UInt64) : UInt64 :=
  let t := zero aad 16 t
  let t := store64 aad 0x314b434d544c t
  let t := store64 (aad+8) 1 t
  let t := copy (a+64) (aad+16) 32 t
  let t := store64 (aad+48) (load64 (a+96) t) t
  let t := store64 (aad+56) index t
  let t := store64 (aad+64) n t
  let t := zero nonce 2 t
  Guest.VaultCrypto.putLE (nonce+4) index 8 t
-- Seal in order. A cached retry requires the exact plaintext commitment.
-- The caller commits the batch before any ciphertext may leave this owner.
def sealChunk (a index input n out t : UInt64) : UInt64 :=
  if load64 a t != 1 || n == 0 || n != chunkLength a index t then err else
  let t := Guest.MessengerCrypto.hash input n hashed t
  let next := load64 (a+104) t
  let cached := cacheAt a index
  if index < next then
    if load64 cached t != index+1 || load64 (cached+8) t != n ||
      Guest.Ed25519.difference hashed (cached+16) 32 0 t != 0 then err else
    copy (cached+48) out (n+16) t
  else if index != next || next-load64 (a+112) t >= 16 then err else
  let t := context a index n t
  let t := zero cached 72 t
  let t := Guest.VaultCrypto.encrypt (a+32) nonce aad 72 input n (cached+48) t
  let t := copy hashed (cached+16) 32 t
  let t := store64 cached (index+1) t
  let t := store64 (cached+8) n t
  let t := store64 (a+104) (next+1) t
  copy (cached+48) out (n+16) t
def committedChunk (a index out t : UInt64) : UInt64 :=
  let cached := cacheAt a index
  let n := chunkLength a index t
  if load64 a t != 1 || n == 0 || index >= load64 (a+112) t ||
    load64 cached t != index+1 || load64 (cached+8) t != n then err else
  copy (cached+48) out (n+16) t
-- Authenticated chunk decrypt can be retried without advancing any authority.
def openChunk (a index input n out t : UInt64) : UInt64 :=
  let plen := chunkLength a index t
  if load64 a t != 2 || plen == 0 || n != plen+16 then err else
  let t := context a index plen t
  Guest.VaultCrypto.decrypt (a+32) nonce aad 72 input plen out t

def clearScratch (t : UInt64) : UInt64 := zero aad 36 t
def clear (t : UInt64) : UInt64 := zero (slotAt 0) 2560 (clearScratch t)
end Guest.MessengerAttachment
