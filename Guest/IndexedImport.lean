import Guest.IndexedContent
namespace Guest.IndexedImport
open Guest.LiveSDK
-- Explicit public/operator input staging is an opaque selected block export,
-- never an authoritative host index. Every record follows the ordinary guest
-- raw-hash/Merkle validation and encrypted/operator transaction commit path.
def st : UInt64 := 0x7e0000
def response (code t : UInt64) : UInt64 :=
  let t := header code (load64 (st+8) t) (load64 (st+80) t) (load64 (st+72) t)
    (load64 (st+64) t) (load64 (st+56) t) (load64 (st+88) t) t
  64+t
def active (t : UInt64) : Bool := load64 st t == 1 && load64 (st+80) t == 1
def finish (result reason t : UInt64) : UInt64 :=
  let t := store64 (st+80) result t
  let t := store64 (st+88) reason t
  let s := IndexedContent.sessionFor (load64 (st+32) t) t
  let t := if s == error then t else zero s 16 t
  let t := store64 (IndexedContent.base+64) 0 t
  let held := load64 (IndexedContent.base+48) t
  let t := if held != 0 && held != load64 (st+32) t then t else
    let t := store64 (IndexedContent.base+48) 0 t
    zero IndexedContent.stage 640 t
  let notified := syscall 126 (load64 (st+16) t) 0 0 0 t
  if notified == error then t else notified

def start (caller rights length t : UInt64) : UInt64 :=
  if active t then
    if length == 416 && load64 (st+16) t == caller && load64 (st+8) t == load64 (command+16) t &&
      load64 (st+112) t == load64 (command+8) t && load64 (st+40) t == load64 (command+24) t &&
      load64 (st+48) t == load64 (command+32) t && load64 (st+104) t == load64 (command+40) t &&
      IndexedContent.eq (st+128) (command+320) 32 t then response 0 t else response 7 t
  else
  let permission := load64 (command+8) t
  let operation := load64 (command+16) t
  let source := load64 (command+24) t
  let records := load64 (command+32) t
  let budget := load64 (command+40) t
  let capacity := syscall 64 2 0 0 0 t
  let p := IndexedContent.ownedPermit caller permission t
  if (rights &&& 0x100000000) == 0 || length != 416 || p == error || operation == 0 || load64 (command+48) t != 3 ||
    records == 0 || records > ContentFormat.maxChunks || records != load64 (command+96) t ||
    source < IndexedContent.minimumSectors || capacity == error || source > capacity || records*10 > capacity-source ||
    budget < load64 (command+88) t || budget > load64 (p+32) t then response 1 t else
  let t := zero st 512 t
  let t := store64 (st+8) operation t
  let t := store64 (st+16) caller t
  let t := store64 (st+40) source t
  let t := store64 (st+48) records t
  let t := store64 (st+64) (load64 (command+88) t) t
  let t := store64 (st+104) budget t
  let t := store64 (st+112) permission t
  let t := store64 (st+96) (load64 (p+16) t) t
  let t := copy (command+320) (st+128) 32 t
  -- Input scope is committed with the initial index, before encryption. A retry
  -- cannot silently change source extent or renew an old capability.
  let t := store64 (IndexedContent.base+96) source t
  let t := store64 (IndexedContent.base+104) records t
  let t := store64 (command+8) 2 t
  let t := store64 (command+16) caller t
  let t := store64 (command+24) operation t
  let t := store64 (command+32) budget t
  let t := store64 (command+40) 3 t
  let t := store64 (command+48) permission t
  let r := IndexedContent.reserve 416 t
  let t := store64 (IndexedContent.base+96) 0 r
  let t := store64 (IndexedContent.base+104) 0 t
  if r == error || load64 wire t != 0 then response 1 (finish 6 (load64 wire t) t) else
  let t := store64 st 1 t
  let t := store64 (st+32) (load64 (wire+8) t) t
  let s := IndexedContent.sessionFor (load64 (st+32) t) t
  let t := if s == error then t else
    let t := store64 (s+96) (self t) t
    store64 (s+104) 3 t
  let t := store64 (st+80) 1 t
  let t := store64 (st+72) (load64 (wire+24) t) t
  if load64 (wire+16) t == 2 then response 0 (finish 4 0 t) else response 0 t

def pump (t : UInt64) : UInt64 :=
  if !active t then t else
  let alive := syscall 34 (load64 (st+16) t) 0 0 0 t
  if alive == error then finish 5 1 alive else
  let s := IndexedContent.sessionFor (load64 (st+32) alive) alive
  if s == error then finish 6 3 alive else
  let now := syscall 116 0 0 0 0 alive
  let owner := load64 (IndexedContent.base+48) now
  if owner != 0 && owner != load64 s now && now < load64 (IndexedContent.base+120) now then now else
  let t := if owner != 0 && now >= load64 (IndexedContent.base+120) now then store64 (IndexedContent.base+48) 0 now else now
  let selected := IndexedContent.select s t
  if selected == error then finish 6 5 selected else
  let index := load64 (st+56) selected
  if index == load64 (st+48) selected then
    let r := IndexedContent.publish s selected
    if r == error || load64 wire r != 0 then finish 6 5 r else finish 4 0 r
  else if IndexedContent.marked index selected then store64 (st+56) (index+1) selected
  else
    let r := IndexedContent.transfer 2 60 (load64 (st+40) selected+index*10) IndexedContent.stage 5120 selected
    if r == error || load64 IndexedContent.stage r != index then finish 6 4 r else
    let t := store64 (IndexedContent.base+48) (load64 s r) r
    let t := store64 (IndexedContent.base+56) (ContentFormat.chunkLength (load64 (st+64) t) index) t
    let r := IndexedContent.commitChunk s t
    if r == error || load64 wire r != 0 then finish 6 (100+load64 wire r) r else
    let t := store64 (st+56) (index+1) r
    let t := store64 (st+72) (load64 (wire+24) t) t
    let notified := syscall 126 (load64 (st+16) t) 0 0 0 t
    if notified == error then t else notified

def dispatch (caller rights length t : UInt64) : UInt64 :=
  let op := load64 command t
  if op == 267 then start caller rights length t else
  if length != 64 || load64 (st+16) t != caller || load64 (command+8) t != load64 (st+8) t then response 1 t else
  if op == 269 then response 0 t else
  if op == 270 && active t then response 0 (finish 5 0 t) else response 2 t

def lockPersonal (t : UInt64) : UInt64 :=
  if load64 (st+96) t != 1 then t else
    let t := if active t then finish 5 0 t else t
    zero st 512 t
def clear (t : UInt64) : UInt64 := zero st 512 t
end Guest.IndexedImport
