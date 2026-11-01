import Guest.ForgeArchive
namespace Guest.MessengerProject
open Guest.LiveSDK Guest.ProjectSDK
-- The same bundle2 consumed by Forge: a bounded canonical index and512-byte
-- slices of an explicitly selected frozen Objects project. No payload archive
-- is accumulated in this graphical process.
def st : UInt64 := 0x730000
def index : UInt64 := 0x731000
def page : UInt64 := 0x733000
def selection : UInt64 := 0x734000
def name : UInt64 := 0x734100
def head : UInt64 := 0x734180
def phase (t : UInt64) : UInt64 := load64 st t
def total (t : UInt64) : UInt64 := load64 (st+8) t
def progress (t : UInt64) : UInt64 := load64 (st+16) t
def fail (code t : UInt64) : UInt64 :=
  let tx := load64 (st+64) t
  let t := if tx == 0 then t else importAbort tx t
  store64 st 9 (store64 (st+96) code (store64 (st+64) 0 t))
def clear (t : UInt64) : UInt64 :=
  let tx := load64 (st+64) t
  let t := if tx == 0 then t else importAbort tx t
  -- Only the synthetic immutable root owned by this process is removed. The
  -- user's picker-selected live root remains independently owned in Objects.
  let frozen := load64 (Guest.ForgeArchive.st+8) t
  let t := if frozen == 0 then t else remove frozen t
  let t := zero index 512 (zero page 64 (zero selection 16 (zero name 16 (zero head 4 t))))
  let t := zero Guest.ForgeArchive.rows 384 (zero Guest.ForgeArchive.bundleIndex 512 (zero Guest.ForgeArchive.buffer 64 t))
  Guest.ForgeArchive.init (zero st 32 t)
def prepare (root t : UInt64) : UInt64 :=
  let t := clear t
  let r := describeRoot root t
  if r != 160 || status r != 0 then fail 1 r else
  let t := copy (wire+64) head 32 r
  let t := copy (wire+96) name 64 t
  let t := store64 (st+24) (load64 (wire+16) t) t
  let r := freeze root head t
  if r != 160 || status r != 0 then fail 1 r else
  let frozen := result r
  let t := Guest.ForgeArchive.init r
  let t := store64 (Guest.ForgeArchive.st+8) frozen t
  let r := Guest.ForgeArchive.enumerate frozen 0 0 0 t
  if r == error || load64 (Guest.ForgeArchive.st+24) r == 0 then fail 2 r else
  let n := 192+load64 (Guest.ForgeArchive.st+24) r*128
  let bytes := n+load64 (Guest.ForgeArchive.st+32) r
  -- Fourteen mailbox blobs plus manifest/text fit the sixteen-row offline
  -- queue. Larger archives need a separately negotiated streaming contract.
  if bytes > 100352 then fail 2 r else
  let p := Guest.ForgeArchive.bundleIndex
  let t := zero p 512 r
  let t := store64 p Guest.ForgeArchive.magic t
  let t := store64 (p+8) 2 t
  let t := store64 (p+16) (load64 (Guest.ForgeArchive.st+24) t) t
  let t := store64 (p+24) (load64 (Guest.ForgeArchive.st+32) t) t
  let t := copy head (p+32) 32 t
  let t := store64 (p+64) (load64 (st+24) t) t
  let t := copy name (p+72) (load64 (st+24) t) t
  let t := store64 (Guest.ForgeArchive.st+40) n t
  let t := store64 (Guest.ForgeArchive.st+48) bytes t
  let t := Guest.ForgeArchive.encodeIndex 0 n t
  store64 st 1 (store64 (st+8) bytes t)
def slice (chunk t : UInt64) : UInt64 :=
  let off := chunk*512
  if phase t != 1 || off >= total t then error else
  let n := if total t-off > 512 then 512 else total t-off
  let r := Guest.ForgeArchive.bundleSlice off n page t
  if r == error then fail 3 r else store64 (st+32) n r
def receiveBegin (bytes t : UInt64) : UInt64 :=
  if bytes < 320 || bytes > 1048576 then fail 2 t else
  store64 st 10 (store64 (st+8) bytes (clear t))
-- One decrypted chunk is consumed before requesting another. The canonical
-- node importer verifies every offered identity/hash and publishes atomically.
def feed (source n t : UInt64) : UInt64 :=
  if phase t < 10 || phase t > 12 || load64 (st+40) t != load64 (st+48) t || n == 0 || n > 512 || progress t+n > total t then fail 4 t else
  store64 (st+40) 0 (store64 (st+48) n (copy source page n t))
partial def validate (i offset t : UInt64) : Bool :=
  if i == load64 (st+24) t then offset == total t else
  let p := index+192+i*128
  let n := load64 (p+8) t
  load64 p t >= 10 && load64 p t <= 15 && n <= 65536 &&
    (load64 (p+16) t == 1 || load64 (p+16) t == 2) &&
    load64 (p+24) t == offset && n <= total t-offset && validate (i+1) (offset+n) t
def beginImport (t : UInt64) : UInt64 :=
  let count := load64 (index+16) t
  let wanted := 192+count*128
  if load64 index t != Guest.ForgeArchive.magic || load64 (index+8) t != 2 || count == 0 || count > 24 ||
    load64 (index+24) t+wanted != total t || !Guest.ProjectGraph.validName (index+72) (load64 (index+64) t) 63 t ||
    !Guest.ProjectGraph.allZero (index+136) 56 t then fail 5 t else
  let t := store64 (st+24) count t
  if !validate 0 wanted t then fail 5 t else
  let t := zero selection 16 t
  let n := load64 (index+64) t
  let t := store64 (selection+8) n t
  let t := copy (index+32) (selection+16) 32 t
  let t := copy (index+72) (selection+48) n t
  let r := importBegin selection 1 count (load64 (index+24) t) t
  if r != 64 || status r != 0 then fail 6 r else
  store64 st 11 (store64 (st+64) (result r) (store64 (st+72) 0 r))
def pumpIndex (t : UInt64) : UInt64 :=
  let present :=  progress t
  let used := load64 (st+40) t
  let available := load64 (st+48) t-used
  if available == 0 then t else
  let wanted := if present == 0 then 192 else 192+load64 (index+16) t*128
  if wanted > 3264 || wanted < present then fail 5 t else
  let n := if available < wanted-present then available else wanted-present
  let t := copy (page+used) (index+present) n t
  let t := store64 (st+16) (present+n) (store64 (st+40) (used+n) t)
  if present+n >= 192 && present+n == 192+load64 (index+16) t*128 then beginImport t else t
def pumpOffer (t : UInt64) : UInt64 :=
  let i := load64 (st+72) t
  if i == load64 (st+24) t then store64 st 12 (store64 (st+72) 0 (store64 (st+80) 0 t)) else
  let p := index+192+i*128
  let r := importOfferVersion (load64 (st+64) t) i (load64 p t) (load64 (p+8) t) (p+32) (load64 (p+16) t) t
  if r != 64 || status r != 0 then fail 6 r else store64 (st+72) (i+1) r
def pumpPayload (t : UInt64) : UInt64 :=
  let i := load64 (st+72) t
  if i == load64 (st+24) t then
    let r := importSubmit (load64 (st+64) t) (load64 (st+64) t) t
    if r != 64 || status r != 0 then fail 6 r else store64 st 13 r
  else
  let p := index+192+i*128
  let off := load64 (st+80) t
  if off == load64 (p+8) t then store64 (st+72) (i+1) (store64 (st+80) 0 t) else
  let used := load64 (st+40) t
  let available := load64 (st+48) t-used
  if available == 0 then t else
  let remain := load64 (p+8) t-off
  let n := if remain < available then remain else available
  let r := importAppend (load64 (st+64) t) i off (page+used) n t
  if r != 64 || status r != 0 then fail 6 r else
  store64 (st+80) (off+n) (store64 (st+16) (progress r+n) (store64 (st+40) (used+n) r))
def pumpCommit (t : UInt64) : UInt64 :=
  let tx := load64 (st+64) t
  let r := importInspect tx t
  if r < 64 || status r != 0 then fail 6 r else
  let state := load64 (wire+16) r
  if state >= 5 then fail 6 r else if state != 4 then r else
  if r != 72 then fail 6 r else
  let root := load64 (wire+64) r
  let t := importControl tx 4 r
  let t := store64 (st+64) 0 (store64 (st+88) root t)
  let shell := syscall 97 4 0 0 0 t
  let t := delegate root shell 31 shell
  store64 st 14 t
def pump (t : UInt64) : UInt64 :=
  if phase t == 10 then pumpIndex t else if phase t == 11 then pumpOffer t else
  if phase t == 12 then pumpPayload t else if phase t == 13 then pumpCommit t else t
def needsChunk (t : UInt64) : Bool :=
  (phase t == 10 || phase t == 12) && load64 (st+40) t == load64 (st+48) t && progress t < total t
end Guest.MessengerProject
