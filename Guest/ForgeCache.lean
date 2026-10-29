import Guest.ProjectSDK
import Guest.ProjectGraph
import Guest.Raster
namespace Guest.ForgeCache
open Guest.LiveSDK
open Guest.ProjectSDK
-- Ephemeral verified payload cache. It contains bytes and commitments, never
-- graph capabilities, peer credentials, approvals, or durable checkpoints.
def st : UInt64 := 0x750000
def head : UInt64 := 0x750080
def row (ordinal : UInt64) : UInt64 := 0x750100+ordinal*160
def payload : UInt64 := 0x760000
def capacity : UInt64 := 262144
def same (a b n t : UInt64) : Bool := Guest.ProjectGraph.equal a b n t
def init (t : UInt64) : UInt64 := zero st 800 t
def begin (root t : UInt64) : UInt64 :=
  if same root head 32 t then store64 (st+32) 0 t else
    copy root head 32 (zero st 800 t)
def matching (ordinal kind schema bytes identities t : UInt64) : Bool :=
  let r := row ordinal
  ordinal < 24 && load64 (r+128) t == 1 && load64 (r+96) t == kind &&
    load64 (r+104) t == schema && load64 (r+112) t == bytes && same identities r 96 t
def offer (ordinal kind schema bytes identities t : UInt64) : UInt64 :=
  if ordinal >= 24 then t else
  let t := store64 (st+8) (ordinal+1) t
  if matching ordinal kind schema bytes identities t then
    store64 (st+16) ordinal (store64 (st+24) 0 (store64 (st+32) 2 t))
  else
    let r := row ordinal
    let used := load64 st t
    let t := zero r 20 t
    let t := copy identities r 96 t
    let t := store64 (r+96) kind t
    let t := store64 (r+104) schema t
    let t := store64 (r+112) bytes t
    if bytes > capacity-used then t else
      let t := store64 (r+120) used t
      let t := store64 (r+136) 1 t
      store64 st (used+bytes) t
def complete (ordinal t : UInt64) : UInt64 :=
  if ordinal >= 24 || load64 (row ordinal+136) t != 1 then t else
    let t := store64 (st+16) ordinal t
    store64 (st+24) 0 (store64 (st+32) 1 t)
def active (t : UInt64) : Bool := load64 (st+32) t != 0
def abort (t : UInt64) : UInt64 :=
  let index := load64 (st+8) t
  let t := if index == 0 || index > 24 then t else
    let r := row (index-1)
    if load64 (r+128) t != 0 || load64 (r+136) t != 1 || load64 (r+120) t+load64 (r+112) t != load64 st t then t else
      zero r 20 (store64 st (load64 (r+120) t) t)
  store64 (st+32) 0 (store64 (st+8) 0 t)
-- 1 means validated cache fill completed; 2 means cached payload was appended
-- to the fresh hidden importer stage; 0 means ongoing; error means fail closed.
def pump (transaction t : UInt64) : UInt64 :=
  let phase := load64 (st+32) t
  if phase == 0 then 0+t else
  let ordinal := load64 (st+16) t
  let r := row ordinal
  let offset := load64 (st+24) t
  let total := load64 (r+112) t
  let n := if total-offset > 512 then 512 else total-offset
  let location := payload+load64 (r+120) t+offset
  if phase == 1 then
    let result := importVerifiedRead transaction ordinal offset n t
    if result != 64+n || status result != 0 || load64 (wire+16) result != total || load64 (wire+24) result != offset ||
      load64 (wire+32) result != load64 (r+96) result || load64 (wire+40) result != load64 (r+104) result then error else
      let t := copy (wire+64) location n result
      if offset+n != total then store64 (st+24) (offset+n) t else
        let t := store64 (r+128) 1 t
        let t := store64 (st+48) (load64 (st+48) t+total) t
        1+store64 (st+32) 0 t
  else if phase == 2 then
    let result := if n == 0 then 64+zero wire 8 t else importAppend transaction ordinal offset location n t
    if result != 64 || status result != 0 then error else
    if offset+n != total then store64 (st+24) (offset+n) result else
      let t := store64 (st+56) (load64 (st+56) result+total) result
      let t := store64 (st+72) (load64 (st+72) t+1) t
      2+store64 (st+32) 0 t
  else error
def view (t : UInt64) : UInt64 :=
  let t := store64 (0x414000+0) 2325059497183496259 t
  let t := store64 (0x414000+8) 4919429793672470575 t
  let t := store64 (0x414000+16) 2891402518004843040 t
  let t := store64 (0x414000+24) 2976403580087649619 t
  let t := Guest.Raster.text 0x414000 32 10 342 0x9fc6a5 0x101b25 t
  let t := Guest.Raster.hex (load64 (st+48) t) 8 250 342 0xd8e6ed 0x101b25 t
  Guest.Raster.hex (load64 (st+56) t) 8 340 342 0xd8e6ed 0x101b25 t
end Guest.ForgeCache
