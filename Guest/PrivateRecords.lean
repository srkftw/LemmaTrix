import Guest.ContentFormat
import Guest.VaultCrypto
namespace Guest.PrivateRecords
open Guest.LiveSDK
-- Selected encrypted collection policies. This additive region never touches
-- v1/v2 saves, the selected-content vault, operator data or indexed items.
def base : UInt64 := 0x7d0000
def first : UInt64 := 150950
def head : UInt64 := base
def other : UInt64 := base+512
def ciphertext : UInt64 := base+1024
def plaintext : UInt64 := base+4096
def scratch : UInt64 := base+8192
def derived : UInt64 := base+9216
def counterKey : UInt64 := base+9280
def allocation : UInt64 := base+9728
def allocationOther : UInt64 := base+10240
def magic : UInt64 := 0x3656505250544c
def nonceMagic : UInt64 := 0x36434e5250544c
def key : UInt64 := 0x620080
def equal (a b n t : UInt64) : Bool := ContentFormat.equal a b n t
def empty (a n t : UInt64) : Bool := ContentFormat.allZero a n t
def disk (op sector ptr bytes t : UInt64) : UInt64 :=
  let t := if op == 61 then copy ptr chunk bytes t else t
  let r := syscall op sector chunk bytes 0 t
  if r != 0 then error else if op == 60 then copy chunk ptr bytes r else r
def ready (t : UInt64) : UInt64 :=
  if load64 0x620000 t != 1 then error else
  let cap := syscall 64 1 0 0 0 t
  if cap == error || cap < 151000 then error else
  let t := copy key scratch 32 cap
  let t := store64 (scratch+32) magic t
  let t := ServiceHash.sha256At (scratch+256) scratch 40 derived t
  let t := store64 (scratch+32) nonceMagic t
  ServiceHash.sha256At (scratch+256) scratch 40 counterKey t
def validPolicy (p t : UInt64) : Bool :=
  load64 p t == 1 && load64 (p+8) t > 0 && load64 (p+8) t != error &&
  load64 (p+16) t <= 1 && load64 (p+24) t <= 1 && load64 (p+32) t == 1 &&
  load64 (p+40) t == 6 && load64 (p+48) t > 0 && load64 (p+48) t <= ContentFormat.maxBytes &&
  load64 (p+56) t <= load64 (p+48) t && load64 (p+64) t > 0 && (load64 (p+64) t &&& 6) == load64 (p+64) t &&
  load64 (p+72) t == 3 && load64 (p+80) t == 2 && load64 (p+88) t <= 1 && load64 (p+96) t <= 1 &&
  load64 (p+104) t <= 16 && empty (p+112) 48 t &&
  !empty (p+160) 32 t && !empty (p+192) 32 t && empty (p+264) 248 t
-- Counter reservations are authenticated under a separate derived key and are
-- flushed before encryption. Nonzero invalid allocator sectors fail closed;
-- falling back after corruption could reuse a previously consumed nonce.
def validCounter (p t : UInt64) : Bool :=
  load64 p t == nonceMagic && load64 (p+8) t == 1 && load64 (p+16) t > 0 &&
  load64 (p+16) t < 0xffffffff && empty (p+36) 28 t && empty (p+80) 432 t &&
  VaultCrypto.decrypt counterKey (p+24) p 64 (p+64) 0 scratch t == 0
@[noinline] def reserveNonce (t : UInt64) : UInt64 :=
  let a := disk 60 150998 allocation 512 t
  if a == error then error else
  let b := disk 60 150999 allocationOther 512 a
  if b == error then error else
  let av := validCounter allocation b
  let bv := validCounter allocationOther b
  if (!av && !empty allocation 512 b) || (!bv && !empty allocationOther 512 b) then error else
  let old := if av && (!bv || load64 (allocation+16) b >= load64 (allocationOther+16) b) then allocation else allocationOther
  let number := if !av && !bv then 1 else load64 (old+16) b+1
  if number >= 0xffffffff then error else
  let t := if !av && !bv then
      let r := syscall 63 0 chunk 4 0 b
      if r == 0 then copy chunk (allocation+24) 4 r else error
    else copy (old+24) (allocation+24) 4 b
  if t == error then error else
  let t := zero (allocation+36) 59 t
  let t := store64 allocation nonceMagic t
  let t := store64 (allocation+8) 1 t
  let t := store64 (allocation+16) number t
  let t := VaultCrypto.putLE (allocation+28) number 8 t
  let t := VaultCrypto.encrypt counterKey (allocation+24) allocation 64 scratch 0 (allocation+64) t
  let r := disk 61 (150998+number%2) allocation 512 t
  if r == error then error else
  let r := syscall 62 0 0 0 0 r
  if r != 0 then error else copy (allocation+24) (head+40) 12 r

def rootSector (slot generation : UInt64) : UInt64 := first+slot*6+(generation%2)*3
def openRoot (p slot t : UInt64) : UInt64 :=
  if load64 p t != magic || load64 (p+8) t != 1 || load64 (p+16) t != slot ||
    load64 (p+24) t == 0 || load64 (p+32) t != 512 || !empty (p+52) 12 t || !empty (p+96) 416 t then error else
  let r := disk 60 (rootSector slot (load64 (p+24) t)+1) ciphertext 1024 t
  if r == error then error else
  let t := ServiceHash.sha256At (scratch+256) ciphertext 528 scratch r
  if !equal scratch (p+64) 32 t then error else
  let r := VaultCrypto.decrypt derived (p+40) p 64 ciphertext 512 plaintext t
  if r != 0 || !validPolicy plaintext r then error else r
@[noinline] def scan (slot t : UInt64) : UInt64 :=
  let a := disk 60 (rootSector slot 0) head 512 t
  if a == error then error else
  let b := disk 60 (rootSector slot 1) other 512 a
  if b == error then error else
  let high := if load64 (head+24) b >= load64 (other+24) b then head else other
  let low := if high == head then other else head
  let r := openRoot high slot b
  if r != error then copy high head 512 r else
  let r := openRoot low slot b
  if r == error then error else copy low head 512 r

def response (code slot generation t : UInt64) : UInt64 := 64+header code slot generation 0 0 0 0 t
@[noinline] def dispatch (caller rights length t : UInt64) : UInt64 :=
  let slot := load64 (command+8) t
  let op := load64 command t
  if (rights &&& 0x100000000) == 0 || (caller &&& 255) != 1 then response 1 slot 0 t else
  if slot >= 8 || (if op == 274 then length != 576 else length != 64) then response 2 slot 0 t else
  let r := ready t
  if r == error then response 8 slot 0 r else
  if op == 275 then
    let r := scan slot r
    if r == error then response 6 slot 0 r else
    let t := response 0 slot (load64 (head+24) r) r
    512+t+copy plaintext (wire+64) 512 t
  else if op == 276 then
    let t := zero head 64 r
    let a := disk 61 (rootSector slot 0) head 512 t
    let b := if a == error then error else disk 61 (rootSector slot 1) head 512 a
    let f := if b == error then error else syscall 62 0 0 0 0 b
    response (if f == 0 then 0 else 8) slot 0 f
  else if op != 274 || !validPolicy (command+64) r then response 2 slot 0 r else
    let old := scan slot r
    let generation := if old == error then 1 else load64 (head+24) old+1
    if generation == 0 then response 4 slot 0 old else
    let t := zero head 64 old
    let t := store64 head magic t
    let t := store64 (head+8) 1 t
    let t := store64 (head+16) slot t
    let t := store64 (head+24) generation t
    let t := store64 (head+32) 512 t
    let r := reserveNonce t
    if r == error then response 5 slot 0 r else
    let t := copy (command+64) plaintext 512 r
    let t := VaultCrypto.encrypt derived (head+40) head 64 plaintext 512 ciphertext t
    let t := zero (ciphertext+528) 62 t
    let t := ServiceHash.sha256At (scratch+256) ciphertext 528 (head+64) t
    let a := disk 61 (rootSector slot generation+1) ciphertext 1024 t
    let a := if a == error then error else syscall 62 0 0 0 0 a
    if a != 0 then response 8 slot 0 a else
    let b := disk 61 (rootSector slot generation) head 512 a
    let b := if b == error then error else syscall 62 0 0 0 0 b
    response (if b == 0 then 0 else 8) slot generation b
@[noinline] def clear (t : UInt64) : UInt64 := zero base 2048 t
end Guest.PrivateRecords
