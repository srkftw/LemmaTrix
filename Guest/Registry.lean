import Guest.ProjectSDK
import Guest.ProjectGraph
import Guest.ServiceSignature
import Guest.ServerSDK
namespace Guest.Registry
open Guest.LiveSDK
open Guest.ProjectSDK
-- An isolated registry compartment. Publisher verification, technical checks,
-- federation listing and local Launcher approval are separate judgments.
def st : UInt64 := 0x620000
def manifest : UInt64 := 0x630000
def material : UInt64 := 0x640000
def decision : UInt64 := 0x650000
def sha : UInt64 := 0x651000
def key (i : UInt64) : UInt64 := 0x660000+i*384
def entry (i : UInt64) : UInt64 := 0x670000+i*1024
def catalog : UInt64 := 0x670000
def stored : UInt64 := 0x680000
def magic : UInt64 := 0x314d4441544c
def equal (a b n t : UInt64) : Bool := Guest.ProjectGraph.equal a b n t
def response (code value t : UInt64) : UInt64 :=
  let t := zero wire 8 t
  let t := store64 wire code t
  64+store64 (wire+8) value t
def hash (p n out t : UInt64) : UInt64 := Guest.ServiceHash.sha256At 0x600200 p n out t
partial def readAll (h p n off t : UInt64) : UInt64 :=
  if off == n then t else
    let count := if n-off > 512 then 512 else n-off
    let r := read h off count t
    if r != count+64 || status r != 0 then error else readAll h p n (off+count) (copy (wire+64) (p+off) count r)
def getNode (root id destination limit t : UInt64) : UInt64 :=
  let r := resolve root id t
  if r != 128 || status r != 0 || load64 (wire+16) r > limit then error else
    let n := load64 (wire+16) r
    let h := result r
    let r := readAll h destination n 0 r
    if r == error then error else Guest.Effects.effectValue n r
partial def findKey (publication publisher i t : UInt64) : UInt64 :=
  if i == 4 then error else
    if load64 (key i) t == 1 && equal (key i+8) publication 32 t && equal (key i+296) publisher 32 t then i else findKey publication publisher (i+1) t
partial def freeKey (i t : UInt64) : UInt64 :=
  if i == 4 then error else if load64 (key i) t == 0 then i else freeKey (i+1) t
partial def freeEntry (i t : UInt64) : UInt64 :=
  if i == 16 then error else if load64 (entry i+768) t == 0 then i else freeEntry (i+1) t
partial def selectedRelease (i count found t : UInt64) : UInt64 :=
  if i == count then found else
    if load64 (manifest+32+i*128) t == 13 then
      if found != error then error else selectedRelease (i+1) count i t
    else selectedRelease (i+1) count found t
def configure (length t : UInt64) : UInt64 :=
  let policy := load64 (command+16) t
  if load64 st t != 0 || length != 320 || (policy != 1 && policy != 2) || (load8 (command+64) t &&& 128) == 0 || (load8 (command+319) t &&& 1) == 0 then response 2 0 t else
    let t := zero st 128 t
    let t := store64 st 1 t
    let t := store64 (st+8) policy t
    let t := store64 (st+320) (load64 (command+24) t) t
    let t := copy (command+64) (st+64) 256 t
    let t := hash (st+64) 256 (st+32) t
    -- The policy commitment includes version and actual configured rule set.
    let t := store64 decision 0x31594c4f50544c t
    let t := store64 (decision+8) policy t
    let t := store64 (decision+16) (if policy == 1 then 768 else 256) t
    let t := store64 (decision+24) (if policy == 1 then 0 else 1) t
    let t := hash decision 32 (st+352) t
    response 0 policy t
def trustPublisher (length t : UInt64) : UInt64 :=
  if length != 352 || (load8 (command+96) t &&& 128) == 0 || (load8 (command+351) t &&& 1) == 0 then response 2 0 t else
    let t := hash (command+96) 256 sha t
    let known := findKey (command+64) sha 0 t
    let slot := if known == error then freeKey 0 t else known
    if slot == error then response 4 0 t else
      let p := key slot
      let t := zero p 48 t
      let t := store64 p 1 t
      let t := copy (command+64) (p+8) 32 t
      let t := copy (command+96) (p+40) 256 t
      response 0 slot (copy sha (p+296) 32 t)
def baseDecision (root _slot t : UInt64) : UInt64 :=
  let t := zero decision 64 t
  let t := store64 decision magic t
  let t := store64 (decision+8) 1 t
  let t := store64 (decision+32) (load64 (st+8) t) t
  let t := store64 (decision+48) (load64 (st+16) t+1) t
  let t := copy (st+352) (decision+256) 32 t
  let t := copy (st+32) (decision+288) 32 t
  let t := store64 (decision+384) 1 t
  let t := store64 (decision+392) 0 t
  let r := describeRoot root t
  if r != 160 || status r != 0 then error else
    let t := copy (wire+64) (decision+320) 32 r
    let r := projectIdentity root t
    if r != 192 || status r != 0 then error else copy (wire+160) (decision+64) 32 r
def outcome (listing reason t : UInt64) : UInt64 :=
  store64 (decision+24) reason (store64 (decision+16) listing t)
partial def unknownLicense (p n i t : UInt64) : Bool :=
  if i+11 > n then false else
    (load64 (p+i) t == 0x5452455353414f4e && load8 (p+i+8) t == 73 && load8 (p+i+9) t == 79 && load8 (p+i+10) t == 78) || unknownLicense p n (i+1) t
partial def releaseName (p n i t : UInt64) : Bool :=
  if i == n then true else
    let c := load8 (p+i) t
    ((c >= 97 && c <= 122) || (c >= 48 && c <= 57) || (i > 0 && (c == 46 || c == 95 || c == 45))) && releaseName p n (i+1) t
def nativeProfile (h t : UInt64) : Bool :=
  let p := load64 (h+400) t
  let size := load64 (h+24) t
  let name := load64 (h+424) t
  load64 h t == 0x3253454c544c && load64 (h+8) t == 2 && load64 (h+16) t == 512 &&
  (p == 1 || p == 2) && size > 0 && size <= (if p == 2 then 262144 else 65536) && size%4 == 0 &&
  load64 (h+32) t == (if p == 2 then 0x200000 else 0x400000) &&
  load64 (h+40) t == 2 && load64 (h+48) t == 2 && load64 (h+56) t == 2 && load64 (h+64) t <= 4095 &&
  load64 (h+72) t <= 0xffffffff && load64 (h+80) t <= 0xffffffff && load64 (h+88) t <= 0xffffffff &&
  load64 (h+384) t == 0 && load64 (h+392) t == 0 &&
  load64 (h+408) t == 65536+(if p == 2 then 2097152 else 0) && load64 (h+416) t == 16384 &&
  name > 0 && name <= 48 && releaseName (h+432) name 0 t && Guest.ProjectGraph.allZero (h+432+name) (48-name) t &&
  load64 (h+480) t == 65537 && (load64 (h+488) t == 0 || load64 (h+488) t == 3) && Guest.ProjectGraph.allZero (h+496) 16 t
-- Listing1 portable development graph;2 technically admitted native release;
-- 3 rejected. Reasons1missingrelease,2publisher,3signature,4profile/rights,
-- 5licenseunknown. These are disclosed federation rules, never execution grants.
def evaluateRelease (root selected t : UInt64) : UInt64 :=
  let n := getNode root (manifest+48+selected*128) material 65536 t
  if n == error || n < 1376 || load64 (material+16) n != 4 then outcome 3 4 n else
    let h := material+608
    let t := copy (h+128) (decision+96) 32 n
    let t := copy (h+160) (decision+128) 32 t
    let t := copy (material+432) (decision+160) 32 t
    let t := copy (h+192) (decision+192) 32 t
    let t := copy (h+352) (decision+224) 32 t
    let t := store64 (decision+40) (load64 (h+64) t) t
    let t := store64 (decision+56) (load64 (h+400) t) t
    let t := copy (h+96) (decision+352) 32 t
    let i := findKey (h+128) (h+96) 0 t
    if i == error then outcome 3 2 t else
    if !Guest.ServiceSignature.verify h 512 (h+512) (key i+40) t then outcome 3 3 t else
    let rights := load64 (h+64) t
    let allowed := if load64 (st+8) t == 1 then 768 else 256
    if !nativeProfile h t || (rights &&& allowed) != rights then outcome 3 4 t else
    let mn := load64 (material+568) t
    let sn := load64 (material+576) t
    let en := load64 (material+584) t
    let ln := load64 (material+592) t
    let license := h+768+mn+sn+en
    let unknown := ln == 0 || ln > 512 || unknownLicense license ln 0 t
    if load64 (st+8) t == 2 && unknown then outcome 3 5 t else outcome 2 0 t
def evaluate (caller root t : UInt64) : UInt64 :=
  let r := describeRoot root t
  if r != 160 || status r != 0 || load64 (wire+48) r != caller then response 1 0 r else
  let slot := freeEntry 0 r
  if slot == error then response 4 0 slot else
  let t := baseDecision root slot slot
  if t == error then response 1 0 t else
  let r := openHead root t
  if r != 128 || status r != 0 || load64 (wire+16) r > 65536 then response 1 0 r else
  let t := readAll (result r) manifest (load64 (wire+16) r) 0 r
  if t == error || load64 (manifest+16) t > 32 then response 2 0 t else
  let selected := selectedRelease 0 (load64 (manifest+16) t) error t
  let t := if selected == error then outcome (if load64 (st+8) t == 1 then 1 else 3) (if load64 (st+8) t == 1 then 0 else 1) t else evaluateRelease root selected t
  let t := copy decision (entry slot) 512 t
  let t := store64 (entry slot+768) 1 t
  let t := store64 (entry slot+776) root t
  let t := store64 (st+16) (load64 (decision+48) t) t
  let t := response 0 (load64 (decision+48) t) t
  let t := store64 (wire+16) slot t
  576+copy decision (wire+64) 512 t
def admit (caller root t : UInt64) : UInt64 :=
  let r := describeRoot root t
  if r != 160 || status r != 0 || load64 (wire+48) r != caller then response 1 0 r else
    let t := copy (wire+64) sha 32 r
    let r := freeze root sha t
    if r != 160 || status r != 0 then response 4 0 r else
      let frozen := result r
      let t := evaluate (self r) frozen r
      let n := t
      -- No graph capability, ownership or availability survives as catalog
      -- authority. Only the immutable evaluated commitments enter the record.
      let t := copy wire stored n t
      let t := remove frozen t
      n+copy stored wire n t
partial def newer (i j t : UInt64) : Bool :=
  if j == 16 then false else
    (load64 (entry j+768) t == 2 && equal (entry i+64) (entry j+64) 96 t &&
      equal (entry i+320) (entry j+320) 32 t && load64 (entry j+48) t > load64 (entry i+48) t) || newer i (j+1) t
partial def next (i pending t : UInt64) : UInt64 :=
  if i == 16 then error else
    let state := load64 (entry i+768) t
    if (pending == 1 && state == 1) || (pending == 0 && state == 2 && !newer i 0 t) then i else next (i+1) pending t
def query (cursor pending t : UInt64) : UInt64 :=
  let i := next cursor pending t
  if i == error then response 6 0 i else
    let t := response 0 (load64 (entry i+48) i) i
    let t := store64 (wire+16) i t
    let t := store64 (wire+24) (i+1) t
    let n := if pending == 1 then 512 else 768
    64+n+copy (entry i) (wire+64) n t
partial def snapshotEntries (i count t : UInt64) : UInt64 :=
  if i == 16 then store64 (stored+24) count t else
    let live := load64 (entry i+768) t == 2
    let t := if live then copy (entry i) (stored+512+i*768) 768 t else zero (stored+512+i*768) 96 t
    snapshotEntries (i+1) (count+(if live then 1 else 0)) t
partial def appendSnapshot (grant offset t : UInt64) : UInt64 :=
  if offset == 12800 then t else
    let r := Guest.ServerSDK.append grant offset (stored+offset) 512 t
    if r != 64 || status r != 0 then error else appendSnapshot grant (offset+512) r
def persist (t : UInt64) : UInt64 :=
  let grant := load64 (st+320) t
  if grant == 0 then t else
    let t := zero stored 1600 t
    let t := store64 stored 0x3154474352544c t
    let t := store64 (stored+8) 1 t
    let t := store64 (stored+16) (load64 (st+8) t) t
    let t := store64 (stored+32) (load64 (st+16) t) t
    let t := copy (st+32) (stored+48) 32 t
    let t := copy (st+352) (stored+80) 32 t
    let t := snapshotEntries 0 0 t
    let t := hash stored 12800 sha t
    let r := Guest.ServerSDK.begin grant 12800 sha t
    if r != 64 || status r != 0 then error else
      let r := appendSnapshot grant 0 r
      if r == error then
        let t := Guest.ServerSDK.cancel grant r
        Guest.Effects.effectValue error t
      else
        let r := Guest.ServerSDK.commit grant r
        if r != 64 || status r != 0 then error else r
partial def readSnapshot (grant offset t : UInt64) : UInt64 :=
  if offset == 12800 then t else
    let r := Guest.ServerSDK.read grant offset 512 t
    if r != 576 || status r != 0 then error else
      readSnapshot grant (offset+512) (copy (wire+64) (stored+offset) 512 r)
def validDescriptor (p t : UInt64) : Bool :=
  load64 p t == magic && load64 (p+8) t == 1 && load64 (p+16) t > 0 && load64 (p+16) t <= 3 &&
  load64 (p+32) t == load64 (st+8) t && load64 (p+48) t > 0 &&
  equal (p+256) (st+352) 32 t && equal (p+288) (st+32) 32 t &&
  load64 (p+384) t == 1 && Guest.ProjectGraph.allZero (p+392) 120 t &&
  Guest.ServiceSignature.verify p 512 (p+512) (st+64) t
partial def restoreEntries (i count t : UInt64) : UInt64 :=
  if i == 16 then if count == load64 (stored+24) t then t else error else
    let p := stored+512+i*768
    if Guest.ProjectGraph.allZero p 768 t then restoreEntries (i+1) count t else
    if !validDescriptor p t || load64 (p+48) t > load64 (stored+32) t then error else
      let t := copy p (entry i) 768 t
      restoreEntries (i+1) (count+1) (store64 (entry i+768) 2 t)
def recover (t : UInt64) : UInt64 :=
  let grant := load64 (st+320) t
  if grant == 0 || load64 (st+16) t != 0 then response 1 0 t else
  let r := Guest.ServerSDK.describe grant t
  if r != 576 || status r != 0 || load64 (wire+96) r != 12800 then response 6 0 r else
    let r := readSnapshot grant 0 r
    if r == error || load64 stored r != 0x3154474352544c || load64 (stored+8) r != 1 ||
        load64 (stored+16) r != load64 (st+8) r || load64 (stored+24) r > 16 ||
        !equal (stored+48) (st+32) 32 r || !equal (stored+80) (st+352) 32 r ||
        !Guest.ProjectGraph.allZero (stored+112) 400 r then response 5 0 r else
      let t := restoreEntries 0 0 r
      if t == error then response 5 0 (zero catalog 2048 t) else
        response 0 (load64 (stored+24) t) (store64 (st+16) (load64 (stored+32) t) t)
def signResult (job length t : UInt64) : UInt64 :=
  let slot := load64 (command+16) t
  if slot >= 16 || length != 320 || load64 (entry slot+768) t != 1 || load64 (entry slot+48) t != job then response 3 0 t else
    if !Guest.ServiceSignature.verify (entry slot) 512 (command+64) (st+64) t then response 5 0 t else
      let t := copy (command+64) (entry slot+512) 256 t
      let t := store64 (entry slot+768) 2 t
      let r := persist t
      if r == error then response 6 0 (store64 (entry slot+768) 1 r) else response 0 job r
partial def cached (descriptor i best t : UInt64) : UInt64 :=
  if i == 16 then best else
    let same := load64 (entry i+768) t == 2 && equal (descriptor+64) (entry i+64) 96 t && equal (descriptor+320) (entry i+320) 32 t
    cached descriptor (i+1) (if same && (best == error || load64 (entry i+48) t > load64 (entry best+48) t) then i else best) t
def verifyIncoming (length t : UInt64) : UInt64 :=
  if length != 864 || !validDescriptor (command+64) t || !equal (command+384) (command+832) 32 t then response 5 0 t else
    let p := command+64
    let previous := cached p 0 error t
    if previous != error && (load64 (p+48) t < load64 (entry previous+48) t ||
        (load64 (p+48) t == load64 (entry previous+48) t && !equal p (entry previous) 768 t)) then response 3 0 t else
      let slot := if previous == error then freeEntry 0 t else previous
      if slot == error then response 4 0 t else
        let t := copy p (entry slot) 768 t
        let t := store64 (entry slot+768) 2 t
        let t := response 0 (load64 (p+16) t) t
        let t := store64 (wire+16) (load64 (p+24) t) t
        832+copy (entry slot) (wire+64) 768 t
def revokeListing (slot expected t : UInt64) : UInt64 :=
  if slot >= 16 || load64 (entry slot+768) t != 2 || load64 (entry slot+48) t != expected then response 3 0 t else
    let vacant := freeEntry 0 t
    if vacant == error then response 4 0 vacant else
      let sequence := load64 (st+16) vacant+1
      if sequence == 0 then response 4 0 vacant else
        let t := copy (entry slot) (entry vacant) 512 vacant
        let t := store64 (entry vacant+16) 3 t
        let t := store64 (entry vacant+24) 6 t
        let t := store64 (entry vacant+48) sequence t
        let t := store64 (entry vacant+768) 1 t
        response 0 sequence (store64 (st+16) sequence t)
def dispatch (caller rights length t : UInt64) : UInt64 :=
  let op := load64 command t
  let h := load64 (command+8) t
  let admin := (caller &&& 255) == 1 && (rights &&& 0x100000000) != 0
  if length < 64 || load64 (command+56) t != 1 then response 2 0 t else
  if op == 1 && admin then configure length t else
  if load64 st t != 1 then response 7 0 t else
  if op == 3 && admin then trustPublisher length t else
  if op == 2 && length == 64 then admit caller h t else
  if op == 4 && admin && length == 64 then query 0 1 t else
  if op == 5 && admin then signResult h length t else
  if op == 6 && length == 64 && h <= 16 then query h 0 t else
  if op == 7 && length == 64 && h < 16 then
    let t := response 0 (load64 (entry h+768) t) t
    let n := if load64 (entry h+768) t == 2 then 768 else 512
    64+n+copy (entry h) (wire+64) n t
  else if op == 8 && admin && length == 64 then revokeListing h (load64 (command+16) t) t
  else if op == 9 && admin && length == 64 then response 0 h (store64 (st+320) h t)
  else if op == 10 && admin && length == 64 then recover t
  else if op == 11 then verifyIncoming length t
  else if op == 12 && admin && length == 64 then
    let r := Guest.ServerSDK.describe (load64 (st+320) t) t
    if r != 576 || status r != 0 then response 6 0 r else
      let bytes := load64 (wire+96) r
      let generation := load64 (wire+88) r
      let t := response 0 bytes r
      64+store64 (wire+16) generation t
  else response 2 0 t
partial def serve (t : UInt64) : UInt64 :=
  let n := receive (self t) t
  if n < 96 || n > 1024 then serve n else
    let token := load64 (incoming+8) n
    let r := dispatch (load64 incoming n) (load64 (incoming+16) n) (n-32) n
    serve (reply token r r)
def main (initial : UInt64) : UInt64 := serve (zero st 49152 initial)
end Guest.Registry
