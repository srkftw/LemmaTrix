import Guest.LibraryFetchSDK
import Guest.LibraryPeerSDK
import Guest.ProjectSDK
import Guest.RegistrySDK
import Guest.ContentFormat
import Guest.ServiceHash
import Guest.WaitSDK
namespace Guest.LibraryFetch
open Guest.LiveSDK
-- One bounded acquisition operation and one queryable terminal result. The
-- Library explicitly starts a new operation to replace the previous result.
-- Payload stays in private Objects import stages, never an application arena.
def st : UInt64 := 0x600000
def counter : UInt64 := 0x600200
def admission : UInt64 := 0x601000
def selected : UInt64 := 0x602000
def offered : UInt64 := 0x603000
def pins : UInt64 := 0x604000
def policy : UInt64 := 0x604100
def scratch : UInt64 := 0x605000
def hash : UInt64 := 0x606000
def payload : UInt64 := 0x607000
def state (t : UInt64) : UInt64 := load64 st t
def phase (t : UInt64) : UInt64 := load64 (st+48) t
def response (code t : UInt64) : UInt64 :=
  let t := header code (load64 (st+160) t) (state t) (load64 (st+128) t) (load64 (st+96) t) (load64 (st+136) t) (load64 (st+104) t) t
  64+t
def denied (t : UInt64) : UInt64 := 64+header 1 0 0 0 0 0 0 t
-- Cleanup is reconciled in later turns if a reply is lost. A replacement
-- operation cannot overwrite the transaction until its terminal result is read.
def discardImport (t : UInt64) : UInt64 :=
  let transaction := load64 (st+80) t
  let r := Guest.ProjectSDK.importControl transaction 3 t
  if r == error || r < 64 then r else
  if status r == 3 then
    let r := Guest.ProjectSDK.importAbort transaction r
    if r == error then r else store64 (st+48) 31 (store64 (st+80) 0 r)
  else if status r != 0 || load64 (wire+16) r < 4 then r else
  let r := if load64 (wire+16) r == 4 then
    if r != 72 then error else Guest.ProjectSDK.remove (load64 (wire+64) r) r
    else r
  if r == error then r else
  let r := Guest.ProjectSDK.importControl transaction 4 r
  if r == error || r < 64 || (status r != 0 && status r != 3) then r else
    store64 (st+48) 31 (store64 (st+80) 0 r)
def fail (code final t : UInt64) : UInt64 :=
  let transaction := load64 (st+80) t
  let grant := load64 (st+56) t
  let slot := load64 (st+24) t
  let t := if load64 (st+64) t == 0 then t else Guest.NetworkSDK.cancelPeer slot (load64 (st+64) t) t
  let t := if grant == 0 then t else Guest.NetworkSDK.revokePeer slot grant t
  let t := store64 (st+56) 0 (store64 (st+64) 0 t)
  let t := zero payload 80 t
  let t := store64 (st+136) code (store64 st final t)
  if transaction == 0 then t else store64 (st+48) 30 t
partial def alias (index value t : UInt64) : UInt64 :=
  if index == 16 then t else
  let digit := (value >>> ((15-index)*4)) &&& 15
  let code := if digit < 10 then 48+digit else 87+digit
  alias (index+1) value (store8 (selected+56+index) code t)
def start (caller length t : UInt64) : UInt64 :=
  let slot := load64 (command+8) t
  let operation := load64 (command+16) t
  let budget := load64 (command+24) t
  if length != 832 || operation == 0 || slot < 1 || slot > 2 || budget == 0 || budget > 1048576 ||
    load64 (command+32) t != 0 || load64 (command+40) t != 0 || load64 (command+48) t != 0 then response 2 t else
  if operation == load64 (st+16) t && caller == load64 (st+8) t then
    if slot != load64 (st+24) t || budget != load64 (st+32) t || !Guest.ContentFormat.equal (command+64) admission 768 t then response 2 t else response 0 t
  else if state t == 1 || phase t == 30 then response 7 t else
  let t := zero st 32 t
  let t := store64 st 1 t
  let t := store64 (st+8) caller t
  let t := store64 (st+16) operation t
  let t := store64 (st+24) slot t
  let t := store64 (st+32) budget t
  let t := store64 (st+40) (Guest.WaitSDK.now t+90000) t
  let t := store64 (st+48) 1 t
  let t := copy (command+64) admission 768 t
  -- Freeze the selected signed provider relationship at submission. A later
  -- enrollment/UI change cannot retarget this operation while admission runs.
  let r := Guest.NetworkSDK.describePeer slot t
  if r != 576 || status r != 0 || load64 (wire+80) r != 6 || load64 (wire+88) r != 3 then response 0 (fail 13 4 r) else
  let t := copy (wire+160) pins 32 r
  let t := Guest.ServiceHash.sha256At scratch (wire+64) 512 (pins+32) t
  response 0 (copy (admission+320) (pins+64) 32 t)
def inspect (caller operation t : UInt64) : UInt64 :=
  if caller != load64 (st+8) t || operation != load64 (st+16) t then denied t else
  if state t != 2 || load64 (st+160) t != 0 then response 0 t else
  let checked := Guest.RegistrySDK.current admission (admission+320) t
  if checked != 832 || status checked != 0 || result checked != 5 then
    let r := Guest.ProjectSDK.remove (load64 (st+168) checked) checked
    response 12 (fail 12 4 r) else
  let r := Guest.ProjectSDK.delegate (load64 (st+168) checked) caller 89 checked
  if r != 160 || status r != 0 then response 6 r else
  response 0 (store64 (st+160) (result r) r)
def dispatch (caller length t : UInt64) : UInt64 :=
  let broker := syscall 119 0 0 0 0 t
  if caller != broker || broker == error || length < 64 || load64 (command+56) t != 1 then denied t else
  let op := load64 command t
  if op == 710 then start caller length t else
  if length != 64 then response 2 t else
  let operation := load64 (command+8) t
  if caller != load64 (st+8) t || operation != load64 (st+16) t then denied t else
  if op == 711 then inspect caller operation t else
  if op == 712 then
    if state t == 1 && (phase t == 12 || phase t == 11 || phase t == 10) then
      let r := if phase t != 12 then Guest.ProjectSDK.importControl (load64 (st+80) t) 3 t else t
      response 0 (store64 (st+48) (if phase r == 10 then 11 else phase r) (store64 (st+232) 1 r)) else
    if state t == 1 then response 0 (fail 0 3 t) else response 0 t
  else response 2 t
-- Each request carries a new monotonically increasing protocol identity. The
-- sequence survives operation replacement and is independent of local handles.
def request (operation ordinal offset count next t : UInt64) : UInt64 :=
  let id := load64 counter t+1
  if id == 0 then fail 10 4 t else
  let t := store64 counter id t
  let t := store64 (st+72) id t
  let t := store64 (st+144) operation t
  let t := store64 (st+152) count t
  let t := store64 (st+216) next t
  let r := Guest.LibraryPeerSDK.request (load64 (st+24) t) (load64 (st+56) t) id operation ordinal offset count t
  if r != 64 || status r != 0 then fail 11 4 r else
  store64 (st+48) 20 (store64 (st+64) (result r) r)
def verified (fresh t : UInt64) : UInt64 :=
  let r := if fresh == 1 then Guest.RegistrySDK.verify admission (admission+320) t else Guest.RegistrySDK.current admission (admission+320) t
  if r != 832 || status r != 0 || result r != 5 then fail 12 4 r else r
def connect (t : UInt64) : UInt64 :=
  let slot := load64 (st+24) t
  let r := Guest.NetworkSDK.inspectPeer slot t
  if r != 64 || status r != 0 || result r != 3 || load64 (wire+16) r != 1 || load64 (wire+56) r != 1 then fail 13 4 r else
  let r := Guest.NetworkSDK.describePeer slot r
  if r != 576 || status r != 0 || load64 (wire+80) r != 6 || load64 (wire+88) r != 3 then fail 13 4 r else
  if !Guest.ContentFormat.equal (wire+160) pins 32 r then fail 13 4 r else
  let t := Guest.ServiceHash.sha256At scratch (wire+64) 512 hash r
  if !Guest.ContentFormat.equal hash (pins+32) 32 t then fail 13 4 t else
  let t := zero policy 8 t
  let t := store64 policy 3 t
  let t := store64 (policy+8) 3 t
  let t := store64 (policy+16) (load64 (st+32) t*2+32768) t
  let t := store64 (policy+24) 65536 t
  let t := store64 (policy+32) 90000 t
  let t := store64 (policy+40) 2 t
  let stream := load64 (admission+320) t ||| 1
  let t := store64 (policy+48) stream t
  let r := Guest.NetworkSDK.grantPeer slot pins policy t
  if r != 64 || status r != 0 then fail 14 4 r else
  store64 (st+48) 3 (store64 (st+56) (result r) r)
def summary (t : UInt64) : UInt64 :=
  let nodes := load64 (st+184) t
  let bytes := load64 (st+192) t
  let nameLength := load64 (payload+8) t
  if load64 (st+224) t != 128 || nodes == 0 || nodes > 24 || bytes == 0 || bytes > load64 (st+32) t ||
    load64 payload t != 0 || nameLength == 0 || nameLength > 63 ||
    !Guest.ContentFormat.equal (payload+16) (admission+320) 32 t ||
    !Guest.ContentFormat.allZero (payload+48+nameLength) (80-nameLength) t then fail 15 4 t else
  let t := zero selected 16 t
  let t := store64 (selected+8) 24 t
  let t := copy (admission+320) (selected+16) 32 t
  -- Local reference alias is operation-bound; provider text does not select a
  -- local path or overwrite an already imported game generation.
  let t := store64 (selected+48) 0x2d7972617262696c t
  let t := alias 0 (load64 (st+16) t) t
  let t := store64 (st+88) nodes t
  let t := store64 (st+96) bytes t
  let r := Guest.ProjectSDK.importBegin selected 1 nodes bytes t
  if r != 64 || status r != 0 then fail 16 4 r else
  store64 (st+48) 5 (store64 (st+80) (result r) r)
def metadata (t : UInt64) : UInt64 :=
  let kind := load64 payload t
  let schema := load64 (payload+8) t
  let bytes := load64 (payload+16) t
  if load64 (st+224) t != 128 || kind < 10 || kind > 15 || (schema != 1 && schema != 2) || bytes == 0 || bytes > 65536 ||
    load64 (payload+24) t != 0 || bytes > load64 (st+96) t-load64 (st+128) t ||
    load64 (st+184) t != bytes || load64 (st+192) t != load64 (st+104) t then fail 17 4 t else
  let t := copy payload offered 128 t
  let t := store64 (st+112) bytes t
  let t := store64 (st+120) 0 t
  let r := Guest.ProjectSDK.importOfferVersion (load64 (st+80) t) (load64 (st+104) t) kind bytes (offered+32) schema t
  if r != 64 || status r != 0 then fail 18 4 r else store64 (st+48) 7 r
def append (t : UInt64) : UInt64 :=
  let count := load64 (st+152) t
  let offset := load64 (st+120) t
  let index := load64 (st+104) t
  if load64 (st+224) t != count || load64 (st+184) t != load64 (st+112) t || load64 (st+192) t != index then fail 19 4 t else
  let r := Guest.ProjectSDK.importAppend (load64 (st+80) t) index offset payload count t
  if r != 64 || status r != 0 then fail 20 4 r else
  let t := store64 (st+128) (load64 (st+128) r+count) r
  let t := store64 (st+120) (offset+count) t
  if offset+count != load64 (st+112) t then store64 (st+48) 7 t else
  let t := store64 (st+104) (index+1) t
  if index+1 != load64 (st+88) t then store64 (st+48) 5 t else
  if load64 (st+128) t != load64 (st+96) t then fail 21 4 t else store64 (st+48) 9 t
def ready (root t : UInt64) : UInt64 :=
  let t := store64 (st+168) root t
  let t := store64 (st+80) 0 t
  let r := verified 0 t
  if state r != 1 then Guest.ProjectSDK.remove root r else
  let r := Guest.NetworkSDK.revokePeer (load64 (st+24) r) (load64 (st+56) r) r
  let t := store64 (st+56) 0 r
  store64 st 2 t
-- A timed-out commit reply is reconciled through the same service's ordered
-- root enumeration. The complete alias/head can be found without retrying the
-- mutating commit or treating timeout as proof of rollback.
def reconcile (t : UInt64) : UInt64 :=
  let cursor := load64 (st+240) t
  let r := Guest.ProjectSDK.roots cursor t
  if r != 160 && r != 64 then r else
  if status r != 0 then r else
  if result r == 0 then fail 22 (if load64 (st+232) r == 0 then 4 else 3) r else
  if load64 (wire+16) r == 24 && Guest.ContentFormat.equal (wire+64) (admission+320) 32 r &&
    Guest.ContentFormat.equal (wire+96) (selected+48) 24 r then
    let root := result r
    if load64 (st+232) r == 0 then ready root r else
    let t := Guest.ProjectSDK.remove root r
    fail 0 3 t
  else store64 (st+240) (load64 (wire+24) r) r
def pump (t : UInt64) : UInt64 :=
  if phase t == 30 then discardImport t else
  if state t != 1 then t else
  let now := Guest.WaitSDK.now t
  if syscall 119 0 0 0 0 now != load64 (st+8) now then fail 1 4 now else
  if now >= load64 (st+40) now && phase now != 12 && phase now != 11 && phase now != 10 then fail 23 4 now else
  let t := if now >= load64 (st+40) now && (phase now == 11 || phase now == 10) then
      let r := Guest.ProjectSDK.importControl (load64 (st+80) now) 3 now
      store64 (st+48) 11 (store64 (st+232) 1 r)
    else now
  let p := phase t
  if p == 1 then
    let r := verified 1 t
    if state r != 1 then r else store64 (st+48) 2 r
  else if p == 2 then connect t else
  if p == 3 then request 7 0 0 0 4 t else
  if p == 4 then summary t else
  if p == 5 then request 8 (load64 (st+104) t) 0 0 6 t else
  if p == 6 then metadata t else
  if p == 7 then
    let remaining := load64 (st+112) t-load64 (st+120) t
    request 9 (load64 (st+104) t) (load64 (st+120) t) (if remaining < 512 then remaining else 512) 8 t
  else if p == 8 then append t else
  if p == 9 then
    let r := verified 0 t
    if state r != 1 then r else store64 (st+48) 10 r
  else if p == 10 then
    let r := Guest.ProjectSDK.importSubmit (load64 (st+80) t) (load64 (st+16) t) t
    if r == error then r else
    if r < 64 || status r != 0 then fail 24 4 r else store64 (st+48) 11 r
  else if p == 11 then
    let r := Guest.ProjectSDK.importInspect (load64 (st+80) t) t
    if r == error then r else
    if r < 64 || status r != 0 then
      if r >= 64 && status r == 3 && load64 (st+232) r != 0 then fail 0 3 r else fail 24 4 r
    else
    let state := load64 (wire+16) r
    if state == 4 then
      if r != 72 then fail 24 4 r else
      let root := load64 (wire+64) r
      let t := Guest.ProjectSDK.importControl (load64 (st+80) r) 4 r
      if load64 (st+232) t == 0 then ready root t else
        fail 0 3 (Guest.ProjectSDK.remove root (store64 (st+80) 0 t))
    else if state >= 5 then
      let reason := load64 (wire+40) r
      let t := Guest.ProjectSDK.importControl (load64 (st+80) r) 4 r
      fail reason (if load64 (st+232) t == 0 then 4 else 3) (store64 (st+80) 0 t)
    else r
  else if p == 12 then reconcile t else
  if p == 20 then
    let r := Guest.NetworkSDK.pollPeer (load64 (st+24) t) (load64 (st+64) t) t
    if r != 64 || status r != 0 || load64 (wire+16) r >= 4 then fail 25 4 r else
    if load64 (wire+16) r == 3 then store64 (st+48) 21 (store64 (st+64) 0 r) else r
  else if p == 21 then
    let r := Guest.LibraryPeerSDK.receive (load64 (st+24) t) (load64 (st+56) t) t
    if r != error && status r == 6 then r else
    if !Guest.LibraryPeerSDK.valid (load64 (st+144) r) (load64 (st+72) r) r then fail 26 4 r else
    if Guest.LibraryPeerSDK.remoteStatus r != 0 then fail (100+Guest.LibraryPeerSDK.remoteStatus r) 4 r else
    let n := r-128
    if n > 512 then fail 26 4 r else
    let t := store64 (st+184) (Guest.LibraryPeerSDK.total r) r
    let t := store64 (st+192) (Guest.LibraryPeerSDK.resultId r) t
    let t := store64 (st+224) n t
    let t := copy Guest.LibraryPeerSDK.data payload n t
    store64 (st+48) (load64 (st+216) t) t
  else fail 27 4 t
partial def serve (endpoint t : UInt64) : UInt64 :=
  let t := pump t
  let n := syscall 36 endpoint incoming 1024 0 t
  let t := if n >= 96 && n != error && load64 (incoming+24) n == 2 then
    let token := load64 (incoming+8) n
    let r := dispatch (load64 incoming n) (n-32) n
    reply token r r else n
  let now := Guest.WaitSDK.now t
  let t := Guest.WaitSDK.deadline (now+(if phase now == 30 || (state now == 1 && phase now != 21) then 1 else 10)) now
  serve endpoint t
def main (t : UInt64) : UInt64 := serve (self t) (zero st 128 t)
end Guest.LibraryFetch
