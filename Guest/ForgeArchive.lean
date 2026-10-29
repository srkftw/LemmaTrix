import Guest.ProjectSDK
import Guest.ProjectGraph
import Guest.ServerSDK
import Guest.ServiceHash
namespace Guest.ForgeArchive
open Guest.LiveSDK
open Guest.ProjectSDK
-- Server bundle2:192-byte selected-root header,128-byte canonical node index
-- entries, then exact concatenated payloads. Handles never enter the bundle.
-- Small index + one512-byte page are resident; payloads remain in Objects/disk.
def st : UInt64 := 0x720000
def rows : UInt64 := 0x721000
def bundleIndex : UInt64 := 0x722000
def buffer : UInt64 := 0x724000
def running : UInt64 := 0x725000
def scratch : UInt64 := 0x726000
def digest : UInt64 := 0x727000
def selected : UInt64 := 0x728000
def magic : UInt64 := 0x324c444e42544c
def row (i : UInt64) : UInt64 := rows+i*128
def phase (t : UInt64) : UInt64 := load64 st t
def progress (t : UInt64) : UInt64 := load64 (st+56) t
def total (t : UInt64) : UInt64 := load64 (st+48) t
def resultRoot (t : UInt64) : UInt64 := load64 (st+104) t
def code (t : UInt64) : UInt64 := load64 (st+88) t
def init (t : UInt64) : UInt64 := zero st 512 t
def fail (code t : UInt64) : UInt64 :=
  let t := if phase t == 2 then ServerSDK.cancel (load64 (st+16) t) t else t
  let transaction := load64 (st+80) t
  let t := if transaction == 0 then t else importAbort transaction t
  let t := store64 (st+80) 0 t
  store64 st 9 (store64 (st+88) code t)
def active (t : UInt64) : Bool := phase t > 0 && phase t != 4 && phase t < 8
partial def enumerate (root cursor i bytes t : UInt64) : UInt64 :=
  if i > 24 || bytes > 1048576 then error else
    let r := closure root cursor t
    if r < 64 || status r != 0 then error else
    if result r == 0 then
      let t := store64 (st+24) i r
      store64 (st+32) bytes t
    else if i == 24 || r != 128 || load64 (wire+24) r <= cursor || load64 (wire+16) r > 1048576-bytes then error else
      let p := row i
      let handle := result r
      let next := load64 (wire+24) r
      let n := load64 (wire+16) r
      let t := store64 p handle r
      let t := store64 (p+8) (load64 (wire+32) t) t
      let t := store64 (p+16) n t
      let t := store64 (p+24) (load64 (wire+40) t) t
      let t := copy (wire+64) (p+32) 64 t
      let r := metadata handle t
      if r != 96 || status r != 0 then error else
        enumerate root next (i+1) (bytes+n) (copy (wire+64) (p+96) 32 r)
partial def encodeIndex (i offset t : UInt64) : UInt64 :=
  if i == load64 (st+24) t then t else
    let p := bundleIndex+192+i*128
    let r := row i
    let t := store64 p (load64 (r+8) t) t
    let t := store64 (p+8) (load64 (r+16) t) t
    let t := store64 (p+16) (load64 (r+24) t) t
    let t := store64 (p+24) offset t
    let t := copy (r+32) (p+32) 96 t
    encodeIndex (i+1) (offset+load64 (r+16) t) t
def save (root grant name nameLength head t : UInt64) : UInt64 :=
  if active t || grant == 0 || nameLength == 0 || nameLength > 63 then fail 1 t else
    let t := init t
    let t := store64 (st+8) root t
    let t := store64 (st+16) grant t
    let r := enumerate root 0 0 0 t
    if r == error || load64 (st+24) r == 0 then fail 2 r else
    let n := 192+load64 (st+24) r*128
    let bytes := n+load64 (st+32) r
    if bytes > 1048576 then fail 2 r else
      let t := zero bundleIndex 512 r
      let t := store64 bundleIndex magic t
      let t := store64 (bundleIndex+8) 2 t
      let t := store64 (bundleIndex+16) (load64 (st+24) t) t
      let t := store64 (bundleIndex+24) (load64 (st+32) t) t
      let t := copy head (bundleIndex+32) 32 t
      let t := store64 (bundleIndex+64) nameLength t
      let t := copy name (bundleIndex+72) nameLength t
      let t := store64 (st+40) n t
      let t := store64 (st+48) bytes t
      let t := encodeIndex 0 n t
      let t := ServiceHash.initialState running t
      store64 st 1 t
partial def sourceIndex (offset i t : UInt64) : UInt64 :=
  if i == load64 (st+24) t then error else
    let p := bundleIndex+192+i*128
    if offset >= load64 (p+24) t && offset-load64 (p+24) t < load64 (p+8) t then i else sourceIndex offset (i+1) t
partial def bundleSlice (offset count destination t : UInt64) : UInt64 :=
  if count == 0 then t else
    let indexBytes := load64 (st+40) t
    if offset < indexBytes then
      let n := if count < indexBytes-offset then count else indexBytes-offset
      bundleSlice (offset+n) (count-n) (destination+n) (copy (bundleIndex+offset) destination n t)
    else
      let i := sourceIndex offset 0 t
      if i == error then error else
      let p := bundleIndex+192+i*128
      let within := offset-load64 (p+24) t
      let n := if count < load64 (p+8) t-within then count else load64 (p+8) t-within
      let r := read (load64 (row i) t) within n t
      if r != n+64 || status r != 0 then error else
        bundleSlice (offset+n) (count-n) (destination+n) (copy (wire+64) destination n r)
partial def lengthBE (p n left t : UInt64) : UInt64 :=
  if left == 0 then t else lengthBE (p+1) n (left-1) (store8 p ((n >>> ((left-1)*8)) &&& 255) t)
def finishHash (n t : UInt64) : UInt64 :=
  let tail := n%64
  let t := copy (buffer+n-tail) (buffer+1024) tail t
  let t := zero buffer 16 t
  let t := copy (buffer+1024) buffer tail t
  let t := store8 (buffer+tail) 128 t
  let bytes := if tail < 56 then 64 else 128
  let t := lengthBE (buffer+bytes-8) (total t*8) 8 t
  let t := ServiceHash.blocks running buffer bytes bytes 0 (bytes/64) t
  ServiceHash.outputBytes running digest 0 t
def saveStep (t : UInt64) : UInt64 :=
  let offset := progress t
  let remaining := total t-offset
  let n := if remaining > 512 then 512 else remaining
  let r := bundleSlice offset n buffer t
  if r == error then fail 3 r else
  if phase r == 1 then
    let t := ServiceHash.blocks running buffer n n 0 (n/64) r
    let t := store64 (st+56) (offset+n) t
    if offset+n != total t then t else
      let t := finishHash n t
      let r := ServerSDK.begin (load64 (st+16) t) (total t) digest t
      if r != 64 || status r != 0 then fail 4 r else store64 st 2 (store64 (st+56) 0 r)
  else
    let r := ServerSDK.append (load64 (st+16) r) offset buffer n r
    if r != 64 || status r != 0 then fail 5 r else
      let t := store64 (st+56) (offset+n) r
      if offset+n != total t then t else
        let r := ServerSDK.commit (load64 (st+16) t) t
        if r != 64 || status r != 0 then fail 6 r else store64 st 8 r

def inspect (grant t : UInt64) : UInt64 :=
  if active t || grant == 0 then fail 1 t else
    let t := init t
    let t := store64 (st+16) grant t
    let r := ServerSDK.describe grant t
    if r != 576 || status r != 0 then fail 7 r else
      let bytes := load64 (wire+96) r
      if bytes < 320 || bytes > 1048576 then fail 7 r else
        let t := store64 (st+48) bytes r
        let r := ServerSDK.read grant 0 (if bytes < 512 then bytes else 512) t
        if r < 64 || status r != 0 then fail 7 r else
          let n := result r
          let t := copy (wire+64) bundleIndex n r
          let count := load64 (bundleIndex+16) t
          let payload := load64 (bundleIndex+24) t
          let indexBytes := 192+count*128
          if load64 bundleIndex t != magic || load64 (bundleIndex+8) t != 2 || count == 0 || count > 24 ||
              payload > 1048576 || indexBytes+payload != bytes || !Guest.ProjectGraph.validName (bundleIndex+72) (load64 (bundleIndex+64) t) 63 t ||
              !Guest.ProjectGraph.allZero (bundleIndex+136) 56 t then fail 8 t else
            let t := store64 (st+24) count t
            let t := store64 (st+32) payload t
            let t := store64 (st+40) indexBytes t
            let t := store64 (st+56) n t
            store64 st 3 t
partial def validateIndex (i offset t : UInt64) : Bool :=
  if i == load64 (st+24) t then offset == total t else
    let p := bundleIndex+192+i*128
    let kind := load64 p t
    let n := load64 (p+8) t
    (kind >= 10 && kind <= 15) && n <= 65536 && load64 (p+24) t == offset &&
      (load64 (p+16) t == 1 || load64 (p+16) t == 2) && n <= total t-offset && validateIndex (i+1) (offset+n) t
def inspectStep (t : UInt64) : UInt64 :=
  let offset := progress t
  let wanted := load64 (st+40) t
  if offset >= wanted then
    if validateIndex 0 wanted t then store64 st 4 t else fail 8 t
  else
    let n := if wanted-offset > 512 then 512 else wanted-offset
    let r := ServerSDK.read (load64 (st+16) t) offset n t
    if r != n+64 || status r != 0 then fail 7 r else
      let t := copy (wire+64) (bundleIndex+offset) n r
      store64 (st+56) (offset+n) t
partial def nameHex (i t : UInt64) : UInt64 :=
  if i == 16 then t else
    let b := load8 (bundleIndex+32+i/2) t
    let d := if i%2 == 0 then b >>> 4 else b &&& 15
    nameHex (i+1) (store8 (selected+53+i) (if d < 10 then d+48 else d+87) t)
def recover (t : UInt64) : UInt64 :=
  if phase t != 4 then fail 1 t else
    let t := zero selected 16 t
    let t := store64 (selected+8) 21 t
    let t := copy (bundleIndex+32) (selected+16) 32 t
    let t := store64 (selected+48) 0x2d64656573 t
    let t := nameHex 0 t
    let r := importBegin selected 1 (load64 (st+24) t) (load64 (st+32) t) t
    if r != 64 || status r != 0 then fail 9 r else
      let t := store64 (st+80) (result r) r
      let t := store64 (st+56) 0 t
      store64 st 5 t
def recoverOffer (t : UInt64) : UInt64 :=
  let i := load64 (st+64) t
  if i == load64 (st+24) t then store64 st 7 t else
    let p := bundleIndex+192+i*128
    let r := importOfferVersion (load64 (st+80) t) i (load64 p t) (load64 (p+8) t) (p+32) (load64 (p+16) t) t
    if r != 64 || status r != 0 then fail 9 r else
      let t := store64 (st+72) 0 r
      if load64 (p+8) t == 0 then store64 (st+64) (i+1) t else store64 st 6 t
def recoverRead (t : UInt64) : UInt64 :=
  let i := load64 (st+64) t
  let p := bundleIndex+192+i*128
  let offset := load64 (st+72) t
  let absolute := load64 (p+24) t+offset
  let remaining := load64 (p+8) t-offset
  let n := if remaining > 512 then 512 else remaining
  let n := if n > 4096-absolute%4096 then 4096-absolute%4096 else n
  let r := ServerSDK.read (load64 (st+16) t) absolute n t
  if r != n+64 || status r != 0 then fail 7 r else
  let t := copy (wire+64) buffer n r
  let r := importAppend (load64 (st+80) t) i offset buffer n t
  if r != 64 || status r != 0 then fail 9 r else
    let t := store64 (st+72) (offset+n) r
    let t := store64 (st+56) (progress t+n) t
    if offset+n == load64 (p+8) t then store64 st 5 (store64 (st+64) (i+1) t) else t
def recoverCommit (t : UInt64) : UInt64 :=
  let r := importCommit (load64 (st+80) t) t
  if r != 72 || status r != 0 || result r != 1 then fail 9 r else
    let root := load64 (wire+64) r
    let t := store64 (st+80) 0 r
    let t := store64 (st+104) root t
    let shell := syscall 97 4 0 0 0 t
    let t := delegate root shell 127 shell
    let launcher := syscall 97 1 0 0 0 t
    let t := delegate root launcher 127 launcher
    store64 st 8 t
def cancel (t : UInt64) : UInt64 :=
  let t := if phase t == 2 then ServerSDK.cancel (load64 (st+16) t) t else t
  fail 10 t
def pump (t : UInt64) : UInt64 :=
  if phase t == 1 || phase t == 2 then saveStep t else
  if phase t == 3 then inspectStep t else
  if phase t == 5 then recoverOffer t else
  if phase t == 6 then recoverRead t else
  if phase t == 7 then recoverCommit t else t
end Guest.ForgeArchive
