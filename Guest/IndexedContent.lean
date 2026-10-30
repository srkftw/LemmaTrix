import Guest.ContentSDK
import Guest.ContentFormat
import Guest.ConsumerFormat
import Guest.VaultCrypto
namespace Guest.IndexedContent
open Guest.LiveSDK
-- Additive bounded directory, never a host database. Sixteen independent slots
-- per purpose; old Objects, saves, ProjectVault and server archives stay intact.
-- Banks have fixed validated geometry, not payload-sized resident allocations.
def base : UInt64 := 0x7b0000
def indexData : UInt64 := base+0x2000
def cipher : UInt64 := base+0x4000
def plain : UInt64 := base+0x6000
def stage : UInt64 := base+0x8000
def head : UInt64 := base+0xa000
def saved : UInt64 := base+0xa400
def cache : UInt64 := base+0xb000
def scratch : UInt64 := base+0xd000
def digest : UInt64 := base+0xd400
def aad : UInt64 := base+0xe000
def nonce : UInt64 := base+0xe200
def key : UInt64 := 0x620080
def firstSector : UInt64 := 151000
def bankSpan : UInt64 := 163872
def minimumSectors : UInt64 := firstSector+72+32*bankSpan
def magic : UInt64 := 0x3158444943544c
def permit (i : UInt64) : UInt64 := base+0x400+i*128
def session (i : UInt64) : UInt64 := base+0xc00+i*128
def eq (a b n t : UInt64) : Bool := ContentFormat.equal a b n t
def zeros (a n t : UInt64) : Bool := ContentFormat.allZero a n t
@[noinline] def replyCode (code value a b c d e t : UInt64) : UInt64 := 64+header code value a b c d e t
def io (kind op sector ptr bytes t : UInt64) : UInt64 :=
  if kind == 2 then
    if op == 60 then syscall 65 sector ptr bytes 2 t else
    if op == 61 then syscall 66 sector ptr bytes 2 t else syscall 67 2 0 0 0 t
  else syscall op sector ptr bytes 0 t
partial def transfer (kind op sector ptr bytes t : UInt64) : UInt64 :=
  if bytes == 0 then t else
    let n := if bytes < 4096 then bytes else 4096
    let t := if op == 61 then copy ptr chunk n t else t
    let r := io kind op sector chunk n t
    if r != 0 then error else
    transfer kind op (sector+n/512) (ptr+n) (bytes-n) (if op == 60 then copy chunk ptr n r else r)
def bankSector (slot bank : UInt64) : UInt64 := firstSector+72+(slot*2+bank)*bankSpan
def rootSector (slot bank checkpoint : UInt64) : UInt64 := firstSector+slot*4+bank*2+checkpoint%2
def nonceAt (sequence t : UInt64) : UInt64 :=
  let t := store64 nonce sequence t
  store64 (nonce+8) 0x584449 t
def crypt (kind decrypt header source length out sequence t : UInt64) : UInt64 :=
  if kind == 2 then
    if decrypt == 1 then
      let t := ServiceHash.sha256At scratch source length digest t
      if !eq digest (source+length) 32 t then error else copy source out length t
    else
      let t := copy source out length t
      ServiceHash.sha256At scratch out length (out+length) t
  else
    let t := copy key (aad+512) 32 t
    let t := store64 (aad+544) magic t
    let t := ServiceHash.sha256At scratch (aad+512) 40 (aad+768) t
    let t := nonceAt sequence t
    if decrypt == 1 then VaultCrypto.decrypt (aad+768) nonce header 96 source length out t
    else VaultCrypto.encrypt (aad+768) nonce header 96 source length out t
-- Reserve the complete transaction nonce interval and flush it before encryption.
-- Old complete high-water records survive interruption. Whole-store rollback is
-- outside freshness guarantees; random nonces are not used as an allocator.
def allocateNonces (kind t : UInt64) : UInt64 :=
  let a := transfer kind 60 (firstSector+64) plain 512 t
  let b := if a == error then error else transfer kind 60 (firstSector+65) (plain+512) 512 a
  if b == error then error else
  let high := if load64 (plain+8) b >= load64 (plain+520) b then plain else plain+512
  let low := if high == plain then plain+512 else plain
  let goodHigh := load64 high b == magic && load64 (high+8) b > 0 && load64 (high+8) b < 0x100000000000
  let goodLow := load64 low b == magic && load64 (low+8) b > 0 && load64 (low+8) b < 0x100000000000
  let checkedHigh := if goodHigh then crypt kind 1 high (high+96) 16 cipher (load64 (high+8) b) b else error
  let checkedLow := if goodLow then crypt kind 1 low (low+96) 16 cipher (load64 (low+8) b) b else error
  if (!zeros high 512 b && checkedHigh == error) || (!zeros low 512 b && checkedLow == error) then error else
  let sequence := if checkedHigh != error then load64 (high+8) b else if checkedLow != error then load64 (low+8) b else 0
  if sequence == 0 && !(zeros plain 1024 b) then error else
  let next := sequence+49156
  let t := zero plain 64 b
  let t := store64 plain magic t
  let t := store64 (plain+8) next t
  let t := zero (plain+256) 2 t
  let r := crypt kind 0 plain (plain+256) 16 (plain+96) next t
  if r != 0 then error else
  let r := transfer kind 61 (firstSector+64+(next/49156)%2) plain 512 r
  let r := if r == error then error else io kind 62 0 chunk 0 r
  if r != 0 then error else store64 (base+16) (sequence+1) r

def validHeader (kind slot t : UInt64) : Bool :=
  load64 head t == magic && load64 (head+8) t == 1 && load64 (head+16) t == kind &&
  load64 (head+24) t > 0 && load64 (head+32) t < 2 &&
  load64 (head+40) t > 0 && load64 (head+40) t <= ContentFormat.maxBytes &&
  load64 (head+48) t == (load64 (head+40) t+4095)/4096 &&
  (load64 (head+56) t == 1 || load64 (head+56) t == 2 || load64 (head+56) t == 3) &&
  load64 (head+64) t <= load64 (head+48) t && load64 (head+72) t > 0 &&
  load64 (head+80) t == load64 (head+72) t+16384+load64 (head+64) t*2+load64 (head+56) t &&
  load64 (head+88) t <= load64 (head+40) t &&
  (load64 (head+56) t == 1 || (load64 (head+64) t == load64 (head+48) t && load64 (head+88) t == load64 (head+40) t)) && load64 (head+128) t == slot && zeros (head+136) 376 t

@[noinline] def loadHeader (kind slot t : UInt64) : UInt64 :=
  if !validHeader kind slot t then error else
  let r := transfer kind 60 (bankSector slot (load64 (head+32) t)+((load64 (head+64) t+load64 (head+56) t)%2)*9) cipher 4608 t
  if r == error then error else
  let t := if kind == 2 then copy (cipher+4096) digest 32 r else
    if eq (cipher+4096) (head+96) 16 r && zeros (head+112) 16 r then copy (head+96) digest 32 r
    else ServiceHash.sha256At scratch cipher 4096 digest r
  if !eq digest (head+96) 32 t then error else
  let r := crypt kind 1 head cipher 4096 indexData (load64 (head+80) t) t
  if r != 0 || !ContentFormat.valid indexData r || load64 (indexData+24) r != load64 (head+40) r ||
    load64 (indexData+32) r != load64 (head+48) r then error else
  let t := ServiceHash.sha256At scratch indexData 256 digest r
  if !eq digest (indexData+256) 32 t then error else t
partial def scanRoots (kind slot wanted expected i bestGeneration bestCount t : UInt64) : UInt64 :=
  if i == 4 then
    if bestGeneration == 0 then if load64 (base+80) t != 0 then error else zero head 64 t else
    let t := copy saved head 512 t
    loadHeader kind slot t
  else
    let t := if i == 0 then store64 (base+80) 0 t else t
    let r := transfer kind 60 (firstSector+slot*4+i) head 512 t
    if r == error then error else
    let r := if zeros head 512 r then r else store64 (base+80) 1 r
    let r := loadHeader kind slot r
    let newer := r != error && (wanted == 0 || load64 (head+24) r == wanted) &&
      (expected == 0 || eq expected (indexData+256) 32 r) && (load64 (head+24) r > bestGeneration ||
      (load64 (head+24) r == bestGeneration && load64 (head+64) r*2+load64 (head+56) r > bestCount))
    let generation := if newer then load64 (head+24) r else bestGeneration
    let count := if newer then load64 (head+64) r*2+load64 (head+56) r else bestCount
    let t := if newer then copy head saved 512 r else t
    scanRoots kind slot wanted expected (i+1) generation count t
@[noinline] def scan (kind slot t : UInt64) : UInt64 := scanRoots kind slot 0 0 0 0 0 (store64 (base+64) 0 t)

@[noinline] def writeIndex (kind slot t : UInt64) : UInt64 :=
  let t := store64 (head+80) (load64 (head+72) t+16384+load64 (head+64) t*2+load64 (head+56) t) t
  let t := zero cipher 576 t
  let r := crypt kind 0 head indexData 4096 cipher (load64 (head+80) t) t
  if r != 0 then error else
  let t := if kind == 2 then copy (cipher+4096) (head+96) 32 r else
    let t := zero (head+96) 4 r
    copy (cipher+4096) (head+96) 16 t
  let r := transfer kind 61 (bankSector slot (load64 (head+32) t)+((load64 (head+64) t+load64 (head+56) t)%2)*9) cipher 4608 t
  let r := if r == error then error else io kind 62 0 chunk 0 r
  if r != 0 then error else
  let r := transfer kind 61 (rootSector slot (load64 (head+32) r) (load64 (head+64) r+load64 (head+56) r)) head 512 r
  if r == error then error else io kind 62 0 chunk 0 r
def liveSession (s t : UInt64) : Bool :=
  load64 s t != 0 && (load64 (s+104) t == 3 || load64 (s+104) t == 5) &&
    load64 (s+96) t == syscall 97 (load64 (s+104) t) 0 0 0 t
partial def freeEntry (i t : UInt64) : UInt64 :=
  if i == 16 then error else if !liveSession (session i) t then i else freeEntry (i+1) t
partial def freePermit (i t : UInt64) : UInt64 :=
  if i == 16 then error else if load64 (permit i) t == 0 || syscall 34 (load64 (permit i+8) t) 0 0 0 t == error then i else freePermit (i+1) t
partial def bankBusy (kind slot bank i t : UInt64) : Bool :=
  if i == 16 then false else
    (liveSession (session i) t && load64 (session i+16) t == kind && load64 (session i+24) t == slot &&
      load64 (session i+32) t == bank) || bankBusy kind slot bank (i+1) t

def newToken (slot t : UInt64) : UInt64 :=
  let service := self t
  let n := load64 base service+1
  if n > 0xffffff then error else
  let t := store64 base n service
  let epoch := ((service >>> 32)+((service >>> 8) &&& 0xffffff)) &&& 0xffffffff
  (epoch <<< 32) ||| (n <<< 8) ||| (slot+1)+t
-- The token result above is a value, not a threaded memory token. Stores are
-- emitted before its use; no serialized handle is read from a backing sector.
def issue (caller kind slot quota scope commitment t : UInt64) : UInt64 :=
  let i := freePermit 0 t
  if i == error then replyCode 4 0 0 0 0 0 0 t else
  let handle := newToken i t
  if handle == error then replyCode 4 0 0 0 0 0 0 t else
  let p := permit i
  let t := if load64 (p+112) t == 0 then t else LiveSDK.releaseReference (load64 (p+112) t) t
  let t := zero p 16 t
  let t := store64 p handle t
  let t := store64 (p+8) caller t
  let t := store64 (p+16) kind t
  let t := store64 (p+24) slot t
  let t := store64 (p+32) quota t
  let t := copy scope (p+48) 32 t
  let t := copy commitment (p+80) 32 t
  replyCode 0 handle slot quota kind 0 0 t

@[noinline] def ownedPermit (owner handle t : UInt64) : UInt64 :=
  let i := (handle &&& 255)-1
  if i >= 16 || load64 (permit i) t != handle || load64 (permit i+8) t != owner then error else permit i

def permitRequest (caller rights length t : UInt64) : UInt64 :=
  let kind := load64 (command+8) t
  let slot := load64 (command+16) t
  let quota := load64 (command+24) t
  let recipient := load64 (command+32) t
  let actual := syscall 34 recipient 0 0 0 t
  let capacity := if kind == 2 then syscall 64 2 0 0 0 actual else syscall 64 1 0 0 0 actual
  if length != 128 || slot >= 16 || quota == 0 || quota > ContentFormat.maxBytes || load64 (command+40) t != 3 ||
    actual == error || (actual &&& 1) == 0 || capacity == error || capacity < minimumSectors ||
    zeros (command+64) 32 t || zeros (command+96) 32 t then replyCode 2 0 0 0 0 0 0 t else
  if (kind == 1 && (load64 0x620000 t != 1 || (rights &&& 0x100000000) == 0)) ||
    (kind == 2 && (rights &&& 0x100000000) == 0) || (kind != 1 && kind != 2) then replyCode 1 0 0 0 0 0 0 t else
  issue recipient kind slot quota (command+64) (command+96) t

@[noinline] def newSession (owner p t : UInt64) : UInt64 :=
  let i := freeEntry 0 t
  if i == error then error else
  let handle := newToken i t
  if handle == error then error else
  let s := session i
  let t := zero s 16 t
  let t := store64 s handle t
  let t := store64 (s+8) owner t
  let t := copy (p+16) (s+16) 16 t
  let t := store64 (s+32) (load64 (head+32) t) t
  let t := store64 (s+40) (load64 (head+24) t) t
  let t := copy (indexData+256) (s+48) 32 t
  let t := store64 (s+80) (load64 p t) t
  let t := store64 (s+96) (syscall 97 5 0 0 0 t) t
  let t := store64 (s+104) 5 t
  store64 (base+24) handle t

def sessionFor (handle t : UInt64) : UInt64 :=
  let i := (handle &&& 255)-1
  if i >= 16 || load64 (session i) t != handle || !liveSession (session i) t then error else session i

@[noinline] def select (s t : UInt64) : UInt64 :=
  let kind := load64 (s+16) t
  if kind == 1 && load64 0x620000 t != 1 then error else
  if load64 (base+64) t == load64 s t then t else
  let r := scanRoots kind (load64 (s+24) t) (load64 (s+40) t) 0 0 0 0 (store64 (base+64) 0 t)
  if r == error || load64 (head+24) r != load64 (s+40) r || load64 (head+32) r != load64 (s+32) r ||
    !eq (indexData+256) (s+48) 32 r then error else store64 (base+64) (load64 s r) r

partial def fetchSelection (object offset t : UInt64) : UInt64 :=
  if offset == 1536 then t else
  let r := LiveSDK.read object offset 512 t
  if r == error || load64 wire r != 0 || load64 (wire+8) r != 512 then error else
  fetchSelection object (offset+512) (copy (wire+64) (indexData+2560+offset) 512 r)
@[noinline] def validSelection (t : UInt64) : Bool :=
  ConsumerFormat.valid (indexData+3328) t && eq (indexData+3520) (indexData+256) 32 t &&
  eq (indexData+3552) (indexData+64) 32 t && load64 (indexData+3736) t == load64 (indexData+24) t
@[noinline] def prepareReservation (p kind slot generation bank r : UInt64) : UInt64 :=
  let t := zero indexData 512 (store64 (base+64) 0 r)
  let t := copy (command+64) indexData 352 t
  let t := copy (p+48) (indexData+352) 32 t
  let t := store64 (indexData+384) (load64 (command+24) t) t
  let t := store64 (indexData+392) (load64 (command+32) t) t
  let t := store64 (indexData+400) (if load64 (base+96) t == 0 then 0 else 2) t
  let t := store64 (indexData+408) (load64 (base+96) t) t
  let t := store64 (indexData+416) (load64 (base+104) t) t
  let r := if load64 (p+112) t == 0 then t else fetchSelection (load64 (p+112) t) 0 t
  if r == error then replyCode 1 0 0 0 0 0 0 r else
  let r := if load64 (p+112) r == 0 then r else
    let t := ServiceHash.sha256At scratch (indexData+3328) 768 digest r
    if !validSelection t || !eq digest (indexData+2960) 32 t then error else t
  if r == error then replyCode 5 0 0 0 0 0 0 r else
  let t := zero head 64 r
  let t := store64 head magic t
  let t := store64 (head+8) 1 t
  let t := store64 (head+16) kind t
  let t := store64 (head+24) generation t
  let t := store64 (head+32) bank t
  let t := store64 (head+40) (load64 (indexData+24) t) t
  let t := store64 (head+48) (load64 (indexData+32) t) t
  let t := store64 (head+56) 1 t
  let t := store64 (head+72) (load64 (base+16) t) t
  let t := store64 (head+128) slot t
  let r := writeIndex kind slot t
  if r != 0 then replyCode 4 0 0 0 0 0 0 r else
  let r := newSession (load64 (command+16) r) p r
  if r == error then replyCode 4 0 0 0 0 0 0 r else
  let r := store64 (session ((load64 (base+24) r &&& 255)-1)+88) 1 r
  replyCode 0 (load64 (base+24) r) 1 0 (load64 (head+40) r) 0 0 r

@[noinline] def reserve (length t : UInt64) : UInt64 :=
  let p := ownedPermit (load64 (command+16) t) (load64 (command+48) t) t
  if p == error || length != 416 || !ContentFormat.valid (command+64) t ||
    load64 (command+24) t == 0 || load64 (command+40) t != 3 || load64 (command+88) t > load64 (p+32) t ||
    load64 (command+88) t > load64 (command+32) t || (zeros (command+352) 32 t || zeros (command+384) 32 t) ||
    load64 (command+32) t > load64 (p+32) t then replyCode 1 0 0 0 0 0 0 t else
  let t := ServiceHash.sha256At scratch (command+64) 256 digest t
  if !eq digest (command+320) 32 t || !eq digest (p+80) 32 t then replyCode 5 0 0 0 0 0 0 t else
  let kind := load64 (p+16) t
  let slot := load64 (p+24) t
  if kind == 1 && load64 0x620000 t != 1 then replyCode 3 0 0 0 0 0 0 t else
  let r := scan kind slot t
  if r == error then replyCode 5 0 0 0 0 0 0 t else
  if load64 head r != 0 && load64 (indexData+384) r == load64 (command+24) r then
    if !eq (command+320) (indexData+256) 32 r || !eq (p+48) (indexData+352) 32 r || load64 (indexData+392) r != load64 (command+32) r ||
      load64 (indexData+408) r != load64 (base+96) r || load64 (indexData+416) r != load64 (base+104) r then replyCode 2 0 0 0 0 0 0 r else
    let r := newSession (load64 (command+16) r) p r
    if r == error then replyCode 4 0 0 0 0 0 0 r else
    let r := store64 (session ((load64 (base+24) r &&& 255)-1)+88) 1 r
    replyCode 0 (load64 (base+24) r) (load64 (head+56) r) (load64 (head+88) r) (load64 (head+40) r) (load64 (head+64) r) 0 r
  else
  let generation := load64 (head+24) r+1
  let bank := generation%2
  if generation == 0 || bankBusy kind slot bank 0 r then replyCode 7 0 0 0 0 0 0 r else
  let r := allocateNonces kind r
  if r == error then replyCode 5 0 0 0 0 0 0 r else
  prepareReservation p kind slot generation bank r

def marked (index t : UInt64) : Bool := ((load8 (indexData+512+index/8) t >>> (index%8)) &&& 1) == 1

@[noinline] def chunkAAD (index length t : UInt64) : UInt64 :=
  let t := zero aad 12 t
  let t := store64 aad magic t
  let t := store64 (aad+8) (load64 (head+16) t) t
  let t := store64 (aad+16) (load64 (head+24) t) t
  let t := store64 (aad+24) index t
  let t := store64 (aad+24) (index*4096+length) t
  let t := copy (indexData+256) (aad+32) 32 t
  let t := copy (indexData+352) (aad+64) 32 t
  t
-- Full raw chunk SHA and its exact positional Merkle path are checked before
-- any range is returned; authenticated metadata alone never implies data exists.
partial def verifyPath (record index depth cursor t : UInt64) : UInt64 :=
  if cursor == depth then if eq (aad+256) (indexData+96) 32 t then t else error else
    let sibling := record+64+cursor*32
    let t := if ((index >>> cursor) &&& 1) == 0 then ContentFormat.branch aad scratch digest (aad+256) sibling t
      else ContentFormat.branch aad scratch digest sibling (aad+256) t
    verifyPath record index depth (cursor+1) (copy digest (aad+256) 32 t)
def verifyChunk (record index t : UInt64) : UInt64 :=
  let length := ContentFormat.chunkLength (load64 (indexData+24) t) index
  let depth := load64 (indexData+48) t
  if load64 record t != index || load64 (record+8) t != length || load64 (record+16) t != depth ||
    !zeros (record+24) 8 t || !zeros (record+64+depth*32) (448-depth*32) t ||
    !zeros (record+512+length) (4096-length) t then error else
  let t := ServiceHash.sha256At scratch (record+512) length digest t
  if !eq digest (record+32) 32 t then error else
  let t := ContentFormat.leaf aad scratch digest index length (record+32) t
  let t := copy digest (aad+256) 32 t
  verifyPath record index depth 0 t

def loadChunk (s index t : UInt64) : UInt64 :=
  let r := select s t
  if r == error || index >= load64 (indexData+32) r || !marked index r then error else
  if load64 (base+32) r == load64 s r && load64 (base+40) r == index then r else
  let kind := load64 (s+16) r
  let sector := bankSector (load64 (s+24) r) (load64 (s+32) r)+32+index*10
  let r := transfer kind 60 sector cipher 5120 r
  if r == error then error else
  let t := chunkAAD index (ContentFormat.chunkLength (load64 (indexData+24) r) index) r
  let r := if kind == 2 then copy cipher cache 4608 t else crypt kind 1 aad cipher 4608 cache (load64 (head+72) t+index) t
  if r != 0 then error else
  let r := verifyChunk cache index r
  if r == error then error else
  let t := store64 (base+32) (load64 s r) r
  store64 (base+40) index t

def readRange (s offset count t : UInt64) : UInt64 :=
  if count == 0 || count > 640 || offset%4096+count > 4096 then replyCode 2 0 0 0 0 0 0 t else
  let selected := select s t
  if selected == error then replyCode 5 0 0 0 0 0 0 selected else
  if offset >= load64 (indexData+24) selected || count > load64 (indexData+24) selected-offset then replyCode 2 0 0 0 0 0 0 selected else
  if !marked (offset/4096) selected then replyCode 6 0 (load64 (head+56) selected) 0 (load64 (indexData+24) selected) (offset/4096) 0 selected else
  let r := loadChunk s (offset/4096) selected
  if r == error then replyCode 5 0 0 0 0 0 0 r else
  if offset >= load64 (indexData+24) r || count > load64 (indexData+24) r-offset then replyCode 2 0 0 0 0 0 0 r else
  let t := header 0 count (load64 (head+56) r) offset (load64 (indexData+24) r) (offset/4096) 0 r
  64+count+copy (cache+512+offset%4096) (wire+64) count t

def proof (s index t : UInt64) : UInt64 :=
  let r := loadChunk s index t
  if r == error then replyCode 6 0 0 0 0 0 0 r else
  let bytes := 32+load64 (indexData+48) r*32
  let t := header 0 bytes (load64 (head+56) r) index (load64 (indexData+24) r) (load64 (indexData+48) r) 0 r
  64+bytes+copy (cache+32) (wire+64) bytes t

def stageHeader (s index length t : UInt64) : UInt64 :=
  let now := syscall 116 0 0 0 0 t
  let t := if load64 (base+48) now != 0 && now >= load64 (base+120) now then store64 (base+48) 0 now else now
  if load64 (base+48) t != 0 && load64 (base+48) t != load64 s t then replyCode 7 0 0 0 0 0 0 t else
  let r := select s t
  if r == error || load64 (head+56) r != 1 || index >= load64 (indexData+32) r || length != 96+load64 (indexData+48) r*32 then replyCode 2 0 0 0 0 0 0 r else
  let t := zero stage 640 r
  let t := store64 stage index t
  let t := store64 (stage+8) (ContentFormat.chunkLength (load64 (indexData+24) t) index) t
  let t := store64 (stage+16) (load64 (indexData+48) t) t
  let t := copy (command+64) (stage+32) (length-64) t
  let t := store64 (base+48) (load64 s t) t
  let t := store64 (base+56) 0 t
  let t := store64 (base+120) (syscall 116 0 0 0 0 t+100) t
  replyCode 0 0 0 0 0 0 0 t

def stageAppend (s offset length t : UInt64) : UInt64 :=
  let n := length-64
  if load64 (base+48) t != load64 s t || length <= 64 || length > 992 || offset != load64 (base+56) t ||
    offset > load64 (stage+8) t || n > load64 (stage+8) t-offset then replyCode 2 0 0 0 0 0 0 t else
  let t := copy (command+64) (stage+512+offset) n t
  replyCode 0 0 0 0 0 0 0 (store64 (base+120) (syscall 116 0 0 0 0 t+100) (store64 (base+56) (offset+n) t))

@[noinline] def writeAuthorized (s t : UInt64) : Bool :=
  load64 (s+88) t == 1 && ownedPermit (load64 (s+8) t) (load64 (s+80) t) t != error &&
    syscall 34 (load64 (s+8) t) 0 0 0 t != error &&
    (load64 (s+16) t == 2 || load64 0x620000 t == 1)
def commitChunkInner (s alreadyVerified t : UInt64) : UInt64 :=
  if !writeAuthorized s t then replyCode 1 0 0 0 0 0 0 t else
  if load64 (base+48) t != load64 s t || load64 (base+56) t != load64 (stage+8) t then replyCode 2 0 0 0 0 0 0 t else
  let r := select s t
  let index := load64 stage r
  if r == error || load64 (head+56) r != 1 then replyCode 3 0 0 0 0 0 0 r else
  if marked index r then replyCode 0 0 0 0 0 0 0 r else
  let r := if alreadyVerified == 1 then r else verifyChunk stage index r
  if r == error then replyCode 5 0 0 0 0 0 0 r else
  let kind := load64 (s+16) r
  let t := chunkAAD index (load64 (stage+8) r) r
  let t := zero cipher 640 t
  let r := if kind == 2 then copy stage cipher 4608 t else crypt kind 0 aad stage 4608 cipher (load64 (head+72) t+index) t
  if r != 0 then replyCode 5 0 0 0 0 0 0 r else
  let r := transfer kind 61 (bankSector (load64 (s+24) r) (load64 (s+32) r)+32+index*10) cipher 5120 r
  if r == error then replyCode 4 0 0 0 0 0 0 r else
  let byte := indexData+512+index/8
  let t := store8 byte (load8 byte r ||| ((1 : UInt64) <<< (index%8))) r
  let t := store64 (head+64) (load64 (head+64) t+1) t
  let t := store64 (head+88) (load64 (head+88) t+load64 (stage+8) t) t
  let r := writeIndex kind (load64 (s+24) t) t
  if r != 0 then replyCode 4 0 0 0 0 0 0 r else replyCode 0 0 (load64 (head+64) r) (load64 (head+88) r) 0 0 0 r

def commitChunk (s t : UInt64) : UInt64 :=
  let r := commitChunkInner s 0 t
  if load64 (base+48) r != load64 s r then r else
  let t := store64 (base+48) 0 r
  r+t

def commitVerifiedChunk (s t : UInt64) : UInt64 :=
  let r := commitChunkInner s 1 t
  if load64 (base+48) r != load64 s r then r else
  let t := store64 (base+48) 0 r
  r+t

def publish (s t : UInt64) : UInt64 :=
  if !writeAuthorized s t then replyCode 1 0 0 0 0 0 0 t else
  let r := select s t
  if r == error || load64 (head+64) r != load64 (indexData+32) r || load64 (head+88) r != load64 (indexData+24) r then replyCode 6 0 0 0 0 0 0 r else
  if load64 (head+56) r == 2 then replyCode 0 0 2 0 0 0 0 r else
  -- Complete publication uses the next state-specific nonce in the already
  -- flushed transaction reservation; it never reuses an index AEAD nonce.
  let kind := load64 (s+16) r
  let t := store64 (head+56) 2 r
  let r := writeIndex kind (load64 (s+24) t) t
  if r != 0 then replyCode 4 0 0 0 0 0 0 r else replyCode 0 0 2 0 0 0 0 r

def backend (caller length t : UInt64) : UInt64 :=
  if caller != syscall 97 5 0 0 0 t then replyCode 1 0 0 0 0 0 0 t else
  let action := load64 (command+8) t
  if action == 2 then reserve length (store64 (base+104) 0 (store64 (base+96) 0 t)) else
  let s := sessionFor (load64 (command+16) t) t
  if s == error then replyCode 3 0 0 0 0 0 0 t else
  if action == 0 && length == 64 then readRange s (load64 (command+24) t) (load64 (command+32) t) t else
  if action == 1 && length == 64 then proof s (load64 (command+24) t) t else
  if action == 8 && length == 64 then
    let r := select s t
    let index := load64 (command+24) r
    if r == error || index >= load64 (indexData+32) r then replyCode 5 0 0 0 0 0 0 r else
    replyCode 0 (if marked index r then 1 else 0) (load64 (head+56) r) index (load64 (head+40) r) 0 0 r
  else
  if action >= 3 && action <= 6 && load64 (s+88) t != 1 then replyCode 1 0 0 0 0 0 0 t else
  if action == 3 then stageHeader s (load64 (command+24) t) length t else
  if action == 4 then stageAppend s (load64 (command+24) t) length t else
  if action == 5 && length == 64 then commitVerifiedChunk s t else
  if action == 6 && length == 64 then publish s t else
  if action == 7 && length == 64 then replyCode 0 0 0 0 0 0 0 (zero s 16 t) else replyCode 2 0 0 0 0 0 0 t

def inventory (caller rights length t : UInt64) : UInt64 :=
  let kind := load64 (command+8) t
  let slot := load64 (command+16) t
  if length != 96 || slot >= 16 || (kind != 1 && kind != 2) ||
    (rights &&& 0x100000000) == 0 || (kind == 1 && load64 0x620000 t != 1) then replyCode 1 0 0 0 0 0 0 t else
  let r := scan kind slot t
  if r == error then replyCode 5 0 0 0 0 0 0 r else
  if load64 head r == 0 || load64 (head+56) r == 3 then replyCode 6 slot 0 0 0 0 0 r else
  if !eq (command+64) (indexData+352) 32 r then replyCode 1 0 0 0 0 0 0 r else
  let t := header 0 slot (load64 (head+56) r) (load64 (head+88) r) (load64 (head+40) r) (load64 (head+24) r) (load64 (indexData+384) r) r
  416+copy indexData (wire+64) 352 t

def openItem (caller length t : UInt64) : UInt64 :=
  let p := ownedPermit caller (load64 (command+8) t) t
  let recipient := load64 (command+16) t
  if length != 64 || p == error || syscall 34 recipient 0 0 0 t == error then replyCode 1 0 0 0 0 0 0 t else
  let r := scanRoots (load64 (p+16) t) (load64 (p+24) t) 0 (p+80) 0 0 0 (store64 (base+64) 0 t)
  if r == error || load64 head r == 0 || load64 (head+56) r == 3 || !eq (p+80) (indexData+256) 32 r || !eq (p+48) (indexData+352) 32 r ||
    load64 (head+40) r > load64 (p+32) r then replyCode 5 0 0 0 0 0 0 r else
  let r := newSession caller p r
  if r == error then replyCode 4 0 0 0 0 0 0 r else
  let t := header 317 (load64 (base+24) r) recipient (load64 (head+56) r) (load64 (head+88) r) (load64 (head+64) r) (load64 (indexData+384) r) r
  let t := copy indexData (wire+64) 352 t
  syscall 30 5 wire 416 1024 t

def deleteItem (caller length t : UInt64) : UInt64 :=
  let p := ownedPermit caller (load64 (command+8) t) t
  if p == error || length != 64 then replyCode 1 0 0 0 0 0 0 t else
  let kind := load64 (p+16) t
  let slot := load64 (p+24) t
  let busy := bankBusy kind slot 0 0 t || bankBusy kind slot 1 0 t
  let r := scan kind slot t
  if r == error || !eq (p+80) (indexData+256) 32 r || !eq (p+48) (indexData+352) 32 r then replyCode 1 0 0 0 0 0 0 r else
  if busy then
    if load64 (head+56) r != 2 then replyCode 7 0 0 0 0 0 0 r else
    let r := writeIndex kind slot (store64 (head+56) 3 r)
    if r != 0 then replyCode 4 0 0 0 0 0 0 r else replyCode 0 slot 1 0 0 0 0 r
  else
  let t := zero head 256 r
  let r := transfer kind 61 (firstSector+slot*4) head 2048 t
  let r := if r == error then error else io kind 62 0 chunk 0 r
  if r != 0 then replyCode 4 0 0 0 0 0 0 r else replyCode 0 slot 0 0 0 0 0 r

def bindSelection (caller length t : UInt64) : UInt64 :=
  let p := ownedPermit caller (load64 (command+8) t) t
  let object := load64 (command+16) t
  if p == error || length != 64 || object == 0 then replyCode 1 0 0 0 0 0 0 t else
  let r := LiveSDK.checkDelegation object caller t
  if r == error || load64 wire r != 0 then replyCode 1 0 0 0 0 0 0 r else
  let r := LiveSDK.metadata object r
  if r == error || load64 wire r != 0 || load64 (wire+16) r != 1536 || load64 (wire+32) r != 2 then replyCode 1 0 0 0 0 0 0 r else
  let r := if load64 (p+112) r == 0 || load64 (p+112) r == object then r else LiveSDK.releaseReference (load64 (p+112) r) r
  replyCode 0 0 0 0 0 0 0 (store64 (p+112) object r)
def selectionRead (caller length t : UInt64) : UInt64 :=
  let p := ownedPermit caller (load64 (command+8) t) t
  let offset := load64 (command+16) t
  let count := load64 (command+24) t
  if p == error || length != 64 || count == 0 || count > 512 || offset >= 1536 || count > 1536-offset then replyCode 1 0 0 0 0 0 0 t else
  let r := scanRoots (load64 (p+16) t) (load64 (p+24) t) 0 (p+80) 0 0 0 (store64 (base+64) 0 t)
  if r == error || load64 head r == 0 || !eq (p+80) (indexData+256) 32 r || !eq (p+48) (indexData+352) 32 r then replyCode 5 0 0 0 0 0 0 r else
  if !validSelection r then replyCode 6 0 0 0 0 0 0 r else
  let t := header 0 count 0 offset 1536 0 0 r
  64+count+copy (indexData+2560+offset) (wire+64) count t

def revokePermit (caller rights length t : UInt64) : UInt64 :=
  let handle := load64 (command+8) t
  let i := (handle &&& 255)-1
  if length != 64 || i >= 16 || load64 (permit i) t != handle ||
    (load64 (permit i+8) t != caller && (rights &&& 0x100000000) == 0) then replyCode 1 0 0 0 0 0 0 t else
  let p := permit i
  let r := if load64 (p+112) t == 0 then t else LiveSDK.releaseReference (load64 (p+112) t) t
  replyCode 0 0 0 0 0 0 0 (zero p 16 r)

def dispatch (caller rights length t : UInt64) : UInt64 :=
  let op := load64 command t
  if op == 268 then backend caller length t else
  if op == 260 then permitRequest caller rights length t else
  if op == 261 then inventory caller rights length t else
  if op == 262 then openItem caller length t else
  if op == 263 then deleteItem caller length t else
  if op == 264 then bindSelection caller length t else
  if op == 265 then selectionRead caller length t else
  if op == 266 then revokePermit caller rights length t else replyCode 2 0 0 0 0 0 0 t

partial def lockEntries (i t : UInt64) : UInt64 :=
  if i == 16 then t else
  let t := if load64 (permit i+16) t == 1 then
    let t := if load64 (permit i+112) t == 0 then t else LiveSDK.releaseReference (load64 (permit i+112) t) t
    zero (permit i) 16 t
    else t
  let t := if load64 (session i+16) t == 1 then zero (session i) 16 t else t
  lockEntries (i+1) t
def lockPersonal (t : UInt64) : UInt64 :=
  let holder := sessionFor (load64 (base+48) t) t
  let operatorStage := holder != error && load64 (holder+16) t == 2
  let t := lockEntries 0 t
  let t := store64 (base+32) 0 t
  let t := store64 (base+40) 0 t
  let t := store64 (base+64) 0 t
  let t := if operatorStage then t else
    let t := store64 (base+48) 0 t
    let t := store64 (base+56) 0 t
    zero stage 640 t
  let t := zero indexData 512 t
  let t := zero aad 128 t
  let t := zero plain 640 t
  zero cache 640 t
def clear (t : UInt64) : UInt64 := zero base 8192 t
end Guest.IndexedContent
