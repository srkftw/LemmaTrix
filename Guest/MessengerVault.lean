import Guest.MessengerCrypto
import Guest.MessengerAttachment
import Guest.LiveSDK
namespace Guest.MessengerVault
open Guest.LiveSDK
-- Domain2 is a separate exact-owner kernel namespace. No Objects key or mount.
-- Fixed state snapshots, not attachment allocation. Kernel mediates sectors0..1023.
def state : UInt64 := 0x690000
def key : UInt64 := state+32
def counterKey : UInt64 := state+64
def root : UInt64 := state+512
def other : UInt64 := state+1024
def allocator : UInt64 := state+1536
def allocatorOther : UInt64 := state+2048
def scratch : UInt64 := state+2560
def plain : UInt64 := 0x680000
def cipher : UInt64 := 0x692000
def bytes : UInt64 := 53248
def storedBytes : UInt64 := 53760
def bankStride : UInt64 := 108
def magic : UInt64 := 0x31564d544c
def counterMagic : UInt64 := 0x31434d544c
def err : UInt64 := 0xffffffffffffffff
def eq (a b n t : UInt64) : Bool := Guest.Ed25519.difference a b n 0 t == 0
def empty (p n t : UInt64) : Bool := Guest.Ed25519.nonzero p n 0 t == 0
def disk (op sector ptr len t : UInt64) : UInt64 := syscall op sector ptr len 2 t
partial def transfer (op sector ptr remaining t : UInt64) : UInt64 :=
  if remaining == 0 then t else
  let n := if remaining < 4096 then remaining else 4096
  let r := disk op sector ptr n t
  if r != 0 then err else transfer op (sector+n/512) (ptr+n) (remaining-n) r
def flush (t : UInt64) : UInt64 := syscall 138 0 0 0 2 t

def derive (input t : UInt64) : UInt64 :=
  let t := copy input scratch 32 t
  let t := store64 (scratch+32) 0x65676e657373654d t
  let t := store64 (scratch+40) 0x326e69616d6f4472 t
  let t := Guest.MessengerCrypto.hash scratch 48 key t
  let t := store64 (scratch+40) counterMagic t
  Guest.MessengerCrypto.hash scratch 48 counterKey t

def validCounter (p t : UInt64) : Bool :=
  load64 p t == counterMagic && load64 (p+8) t == 1 && load64 (p+16) t > 0 &&
  load64 (p+16) t < 0xffffffff && empty (p+36) 28 t && empty (p+80) 432 t &&
  Guest.VaultCrypto.decrypt counterKey (p+24) p 64 (p+64) 0 scratch t == 0

def reserveNonce (t : UInt64) : UInt64 :=
  let r := disk 136 0 allocator 512 t
  if r != 0 then err else
  let r := disk 136 1 allocatorOther 512 r
  if r != 0 then err else
  let av := validCounter allocator r
  let bv := validCounter allocatorOther r
  if (!av && !empty allocator 512 r) || (!bv && !empty allocatorOther 512 r) then err else
  let old := if av && (!bv || load64 (allocator+16) r >= load64 (allocatorOther+16) r) then allocator else allocatorOther
  let number := if !av && !bv then 1 else load64 (old+16) r+1
  if number >= 0xffffffff then err else
  let t := if !av && !bv then
    let r := syscall 130 0 scratch 32 0 r
    if r == 0 then copy scratch (allocator+24) 4 r else err
    else copy (old+24) (allocator+24) 4 r
  if t == err then err else
  let t := zero (allocator+36) 59 t
  let t := store64 allocator counterMagic t
  let t := store64 (allocator+8) 1 t
  let t := store64 (allocator+16) number t
  let t := Guest.VaultCrypto.putLE (allocator+28) number 8 t
  let t := Guest.VaultCrypto.encrypt counterKey (allocator+24) allocator 64 scratch 0 (allocator+64) t
  let r := disk 137 (number%2) allocator 512 t
  if r != 0 then err else
  let r := flush r
  if r != 0 then err else copy (allocator+24) (root+40) 12 r

def rootSector (generation : UInt64) : UInt64 := 2+(generation%2)*bankStride

def validRoot (p t : UInt64) : Bool :=
  load64 p t == magic && load64 (p+8) t == 2 && load64 (p+16) t == 2 &&
  load64 (p+24) t > 0 && load64 (p+32) t == bytes && empty (p+52) 12 t && empty (p+96) 416 t

partial def validContacts (i t : UInt64) : Bool :=
  if i == 4 then true else
  let c := plain+0x2000+i*4096
  load64 c t <= 3 && load64 (c+16) t <= 2 && load64 (c+24) t <= 1048576 &&
    load64 (c+32) t <= 1048576 && load64 (c+40) t <= 1048576 &&
    load64 (c+1600) t <= 2 && (load64 (c+1600) t != 2 ||
      (load64 (c+1616) t >= 209 && load64 (c+1616) t <= 720)) && validContacts (i+1) t
partial def validInbox (i t : UInt64) : Bool :=
  if i == 8 then true else
  let p := plain+0x6000+i*1024
  load64 p t <= 2 && load64 (p+16) t <= 4 && load64 (p+24) t <= 512 && validInbox (i+1) t

def openRoot (p t : UInt64) : UInt64 :=
  if !validRoot p t then err else
  let r := transfer 136 (rootSector (load64 (p+24) t)+1) cipher storedBytes t
  if r != 0 then err else
  let t := Guest.MessengerCrypto.hash cipher (bytes+16) scratch r
  if !eq scratch (p+64) 32 t then err else
  let r := Guest.VaultCrypto.decrypt key (p+40) p 64 cipher bytes plain t
  if r != 0 || load64 plain r != 1 || load64 (plain+8) r == 0 || !validContacts 0 r || !validInbox 0 r ||
    !Guest.MessengerAttachment.validSlot (plain+32768) r ||
    !Guest.MessengerAttachment.validSlot (plain+43008) r then err else
  let t := copy p root 512 r
  store64 (state+8) (load64 (p+24) t) t

def nonceCurrent (t : UInt64) : Bool :=
  let a := disk 136 0 allocator 512 t
  let b := if a == 0 then disk 136 1 allocatorOther 512 a else err
  if b != 0 then false else
  let av := validCounter allocator b
  let bv := validCounter allocatorOther b
  if (!av && !empty allocator 512 b) || (!bv && !empty allocatorOther 512 b) || (!av && !bv) then false else
  let p := if av && (!bv || load64 (allocator+16) b >= load64 (allocatorOther+16) b) then allocator else allocatorOther
  load64 (p+16) b == Guest.VaultCrypto.le32 (root+44) b && eq (p+24) (root+40) 4 b

def scan (allowHistoryFallback t : UInt64) : UInt64 :=
  let r := disk 136 2 root 512 t
  if r != 0 then err else
  let r := disk 136 (2+bankStride) other 512 r
  if r != 0 then err else
  let high := if load64 (root+24) r >= load64 (other+24) r then root else other
  let low := if high == root then other else root
  let opened := openRoot high r
  if opened != err then
    if allowHistoryFallback == 1 || nonceCurrent opened then opened else err
  else if allowHistoryFallback == 1 then openRoot low r else err

partial def hideHistory (i t : UInt64) : UInt64 :=
  if i == 8 then t else
  let p := plain+0x6000+i*1024
  let t := zero (p+64) 64 t
  let t := if load64 p t == 1 then store64 p 2 t else t
  hideHistory (i+1) t

def capture (history t : UInt64) : UInt64 :=
  let t := copy 0x650000 plain 32768 t
  let t := copy (Guest.MessengerAttachment.slotAt 0) (plain+32768) 20480 t
  -- Exact ciphertext cache and published high-water are one atomic snapshot.
  -- Staging never exports ciphertext; only a committed batch becomes readable.
  -- Ephemeral plaintext drafts are not recoverable until encrypted publication.
  let t := zero (plain+0x1000+256) 480 t
  let t := if history == 1 then t else hideHistory 0 t
  t

partial def scrubDrafts (i t : UInt64) : UInt64 :=
  if i == 4 then t else
  let p := plain+0x2000+i*4096+1600
  let t := if load64 p t == 1 then zero p 128 t else t
  scrubDrafts (i+1) t

def commit (t : UInt64) : UInt64 :=
  if load64 state t != 1 then t else
  let generation := load64 (state+8) t+1
  if generation == 0 then err else
  let t := capture (load64 (state+16) t) t
  let t := scrubDrafts 0 t
  let t := zero root 64 t
  let t := store64 root magic t
  let t := store64 (root+8) 2 t
  let t := store64 (root+16) 2 t
  let t := store64 (root+24) generation t
  let t := store64 (root+32) bytes t
  let r := reserveNonce t
  if r == err then err else
  let t := Guest.VaultCrypto.encrypt key (root+40) root 64 plain bytes cipher r
  let t := Guest.MessengerCrypto.hash cipher (bytes+16) (root+64) t
  let r := transfer 137 (rootSector generation+1) cipher storedBytes t
  if r != 0 then err else
  let r := flush r
  if r != 0 then err else
  let r := disk 137 (rootSector generation) root 512 r
  if r != 0 then err else
  let r := flush r
  if r != 0 then err else store64 (state+8) generation r

def unlock (input mode history t : UInt64) : UInt64 :=
  let t := zero state 512 t
  let t := derive input t
  if mode == 0 then
    let a := disk 136 2 root 512 t
    let b := if a == 0 then disk 136 (2+bankStride) other 512 a else err
    if b != 0 || !empty root 512 b || !empty other 512 b then err else
    let t := store64 state 1 b
    let t := store64 (state+16) history t
    commit t
  else
    let r := scan (if mode == 2 then 1 else 0) t
    if r == err then err else
    let t := store64 state 1 r
    store64 (state+16) history t

def restore (t : UInt64) : UInt64 :=
  let t := copy plain 0x650000 32768 t
  copy (plain+32768) (Guest.MessengerAttachment.slotAt 0) 20480 t

def clear (t : UInt64) : UInt64 :=
  let t := zero state 512 t
  let t := zero plain 6656 t
  let t := zero cipher 6720 t
  let r := syscall 140 0 0 0 2 t
  if r == err then t else r

def forget (t : UInt64) : UInt64 :=
  if load64 state t != 1 then err else
  let t := zero root 64 t
  let r := disk 137 2 root 512 t
  if r != 0 then err else
  let r := disk 137 (2+bankStride) root 512 r
  if r != 0 then err else
  let r := flush r
  if r != 0 then err else clear r
end Guest.MessengerVault
