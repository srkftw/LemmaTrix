import Guest.ProjectSDK
import Guest.ProjectGraph
import Guest.ContentStore
import Guest.ServiceSDK
import Guest.BuildArtifact
import Guest.ServiceSignature
import Guest.ForgeArchive
namespace Guest.BuildJobs
open Guest.LiveSDK
open Guest.ProjectSDK
def st : UInt64 := 0x600000
def job (i : UInt64) : UInt64 := 0x601000+i*2048
def fail (code t : UInt64) : UInt64 := 64+store64 wire code (zero wire 8 t)
partial def freeJob (i t : UInt64) : UInt64 :=
  if i == 4 then error else if load64 (job i) t == 0 then i else freeJob (i+1) t
partial def findJob (id i t : UInt64) : UInt64 :=
  if i == 4 then error else if load64 (job i+8) t == id && load64 (job i) t != 0 then i else findJob id (i+1) t
partial def nextJob (i t : UInt64) : UInt64 :=
  if i == 4 then error else if load64 (job i) t == 1 then i else nextJob (i+1) t
partial def queuedFor (requester i t : UInt64) : UInt64 :=
  if i == 4 then error else
  if load64 (job i) t == 1 && load64 (job i+16) t == requester then i else queuedFor requester (i+1) t
partial def digits (n count p t : UInt64) : UInt64 :=
  if count == 0 then t else
    let d := (n >>> ((count-1)*4)) &&& 15
    digits n (count-1) (p+1) (store8 p (if d < 10 then d+48 else d+87) t)
def authorityResponse (j t : UInt64) : UInt64 :=
  let t := zero wire 8 t
  let t := store64 (wire+8) (load64 (j+8) t) t
  let t := store64 (wire+16) (load64 j t) t
  let t := store64 (wire+24) (self t) t
  let t := store64 (wire+32) (load64 (j+32) t) t
  let t := store64 (wire+40) 2 t
  let t := store64 (wire+48) (load64 (j+240) t) t
  let t := store64 (wire+56) (load64 (j+248) t) t
  let t := copy (j+64) (wire+64) 32 t
  let t := copy (j+96) (wire+96) 32 t
  let t := copy (st+32) (wire+128) 32 t
  let t := copy (j+800) (wire+160) 32 t
  let t := store64 (wire+192) (load64 (j+832) t) t
  let t := store64 (wire+200) (load64 (j+16) t) t
  let t := store64 (wire+208) (load64 (j+840) t) t
  let t := store64 (wire+216) 1 t
  256+zero (wire+224) 4 t

def response (j t : UInt64) : UInt64 :=
  if load64 j t == 1 then authorityResponse j t else
    let t := authorityResponse j t
    let t := copy (j+256) (wire+128) (load64 (j+40) t) t
    128+load64 (j+40) t+t


def payload : UInt64 := 0x620000
def detail : UInt64 := 0x621000
def sourceArchive : UInt64 := 0x62f000

partial def appendNodeBytes (h length offset t : UInt64) : UInt64 :=
  if offset == length then t else
    let count := if length-offset > 512 then 512 else length-offset
    let r := append h offset (payload+offset) count t
    if r != 64 || status r != 0 then error else appendNodeBytes h length (offset+count) r

def createNode (kind length t : UInt64) : UInt64 :=
  let r := stage length kind 0 t
  if r != 64 || status r != 0 then error else
    let h := result r
    let appended := appendNodeBytes h length 0 r
    if appended == error then Guest.Effects.effectValue error (abortStage h appended) else
      let hashed := stageDigest h appended
      if hashed != 96 || status hashed != 0 then Guest.Effects.effectValue error (abortStage h hashed) else
        let r := commit h (wire+64) hashed
        if r != 96 || status r != 0 then Guest.Effects.effectValue error (abortStage h r) else result r

def entry (p kind identity name n t : UInt64) : UInt64 :=
  let t := zero p 16 t
  let t := store64 p kind t
  let t := store64 (p+8) n t
  let t := copy identity (p+16) 32 t
  copy name (p+48) n t

def buildDetail (j t : UInt64) : UInt64 :=
  let t := zero detail 128 t
  let t := store64 detail 0x31444c4942544c t
  let t := store64 (detail+8) 1 t
  let t := store64 (detail+16) (load64 j t) t
  let t := store64 (detail+24) (load64 (j+8) t) t
  let t := store64 (detail+32) 0x3153424a544c t
  let t := store64 (detail+40) 2 t
  let t := copy (j+64) (detail+48) 32 t
  let t := copy (j+96) (detail+80) 32 t
  let t := copy (j+192) (detail+112) 32 t
  let t := copy (st+32) (detail+144) 32 t
  let t := store64 (detail+176) 0x69616d2e6e69614d t
  let t := store8 (detail+184) 110 t
  let t := store64 (detail+192) (load64 (j+40) t) t
  copy (j+256) (detail+200) (load64 (j+40) t) t

def publishEvidence (j t : UInt64) : UInt64 :=
  let t := buildDetail j t
  let n := 200+load64 (j+40) t
  let t := zero payload 128 t
  let t := store64 payload 0x31464e4d544c t
  let t := store64 (payload+8) 1 t
  let t := store64 (payload+16) 1 t
  let t := store64 (payload+24) n t
  let t := store64 0x610080 0x656372756f73 t
  let t := entry (payload+32) 11 (j+64) 0x610080 6 t
  let t := copy detail (payload+160) n t
  let evidence := createNode 14 (160+n) t
  if evidence == error then error else
    let t := store64 (j+232) evidence evidence
    let r := nodeMetadata evidence t
    if r != 128 || status r != 0 then error else
      copy (wire+64) (j+160) 32 r

def publishBuild (j t : UInt64) : UInt64 :=
  let n := 200+load64 (j+40) t
  let t := zero payload 128 t
  let t := store64 payload 0x31464e4d544c t
  let t := store64 (payload+8) 1 t
  let t := store64 (payload+16) 2 t
  let t := store64 (payload+24) n t
  let t := store64 0x610080 0x65636e6564697665 t
  let t := entry (payload+32) 14 (j+160) 0x610080 8 t
  let t := store64 0x610080 0x656372756f73 t
  let t := entry (payload+160) 11 (j+64) 0x610080 6 t
  let t := copy detail (payload+288) n t
  let build := createNode 12 (288+n) t
  if build == error then error else
    let t := store64 (j+224) build build
    let r := nodeMetadata build t
    if r != 128 || status r != 0 then error else
      copy (wire+64) (j+128) 32 r

def shareRecord (j record destination t : UInt64) : UInt64 :=
  let target := load64 (j+16) t
  let actual := syscall 34 target 0 0 0 t
  if actual == error || (actual &&& 1) == 0 then store64 destination 0 actual else
    let r := share record target 1 actual
    if r != 64 || status r != 0 then store64 destination 0 r else store64 destination (result r) r

def attachRecords (j t : UInt64) : UInt64 :=
  let published := publishEvidence j t
  if published == error then error else
    let t := shareRecord j (load64 (j+232) published) (j+248) published
    if load64 j t != 2 then t else
      let published := publishBuild j t
      if published == error then error else
        shareRecord j (load64 (j+224) published) (j+240) published

def cancel (j t : UInt64) : UInt64 :=
  let root := load64 (j+24) t
  let r := ProjectSDK.remove root t
  if r != 64 || status r != 0 then fail 1 r else
    let build := load64 (j+224) r
    let evidence := load64 (j+232) r
    let t := if build == 0 then r else drop build r
    let t := if evidence == 0 then t else drop evidence t
    let staged := load64 (j+896) t
    let artifact := load64 (j+920) t
    let t := if staged == 0 then t else abortStage staged t
    let t := if artifact == 0 then t else drop artifact t
    let t := zero j 256 t
    fail 0 t

partial def latestSuccess (caller i newest t : UInt64) : UInt64 :=
  if i == 4 then newest else
    let j := job i
    let id := load64 (j+8) t
    latestSuccess caller (i+1) (if load64 j t == 2 && load64 (j+16) t == caller && id > newest then id else newest) t

-- At most four slots are searched. Pending jobs and a live caller's most recent
-- successful result remain intact when later queued builds fail.
def recyclable (state sameCaller latest dead : Bool) : Bool := state && ((sameCaller && !latest) || dead)
theorem newest_live_success_preserved : recyclable true true true false = false := by decide

partial def oldestCompleted (caller newest i selected t : UInt64) : UInt64 :=
  if i == 4 then Guest.Effects.effectValue selected t else
    let j := job i
    let completed := load64 j t >= 2
    let owner := load64 (j+16) t
    let actual := if completed && owner != caller then syscall 34 owner 0 0 0 t else t
    let allowed := recyclable completed (owner == caller) (load64 (j+8) actual == newest) (completed && owner != caller && actual == error)
    let selected := if allowed && (selected == error || load64 (j+8) actual < load64 (job selected+8) actual) then i else selected
    oldestCompleted caller newest (i+1) selected actual

def reserveJob (caller t : UInt64) : UInt64 :=
  let vacant := freeJob 0 t
  if vacant != error then vacant else
    let selected := oldestCompleted caller (latestSuccess caller 0 0 t) 0 error t
    if selected == error then error else
      let cleared := cancel (job selected) selected
      if cleared != 64 || status cleared != 0 then error else Guest.Effects.effectValue selected cleared

def enqueue (caller root t : UInt64) : UInt64 :=
  if load64 st t >= 65535 then fail 4 t else
  if load64 (st+64) t != 1 then fail 7 t else
    let r := describeRoot root t
    if r != 160 || status r != 0 || load64 (wire+48) r != caller then fail 1 r else
      let t := copy (wire+64) 0x610000 32 r
      let t := store64 0x610100 (load64 (wire+56) t) t
      let t := store64 0x610108 (load64 (wire+48) t) t
      let identity := projectIdentity root t
      if identity != 192 || status identity != 0 then fail 1 identity else
      let t := copy (wire+160) 0x610120 32 identity
      let slot := reserveJob caller t
      if slot == error then fail 4 slot else
      let r := freezeExport root 0x610000 slot
      if r != 160 || status r != 0 then fail 1 r else
        let frozen := result r
        let t := store64 0x610040 frozen r
        let r := openHead frozen t
        if r != 128 || status r != 0 then fail 1 (ProjectSDK.remove frozen r) else
          let h := result r
          let t := store64 0x610048 h r
          let launcher := syscall 97 1 0 0 0 t
          let r := delegate frozen launcher 65 t
          if r != 160 || status r != 0 then fail 1 (ProjectSDK.remove frozen r) else
            let j := job slot
            let id := load64 st r+1
            let t := store64 st id r
            let t := zero j 256 t
            let t := store64 j 1 t
            let t := store64 (j+8) id t
            let t := store64 (j+16) caller t
            let t := store64 (j+24) frozen t
            let t := store64 (j+32) (result r) t
            let t := store64 (j+48) h t
            let t := copy 0x610000 (j+64) 32 t
            let t := copy 0x610120 (j+800) 32 t
            let t := store64 (j+832) (load64 0x610100 t) t
            let t := store64 (j+840) (load64 0x610108 t) t
            let t := store64 (j+848) root t
            response j t


def artifactGrants (j caller t : UInt64) : UInt64 :=
  if load64 j t != 2 || load64 (j+224) t == 0 || load64 (j+232) t == 0 then fail 6 t else
    let r := share (load64 (j+224) t) caller 1 t
    if r != 64 || status r != 0 then fail 1 r else
      let build := result r
      let t := store64 0x610090 build r
      let r := share (load64 (j+232) t) caller 1 t
      if r != 64 || status r != 0 then fail 1 r else
        let evidence := result r
        let r := response j r
        let t := store64 (wire+48) build r
        let t := store64 (wire+56) evidence t
        Guest.Effects.effectValue r t

def validateJobAuthority (j t : UInt64) : UInt64 :=
  let alive := syscall 34 (load64 (j+16) t) 0 0 0 t
  if alive == error then error else
    let r := describeRoot (load64 (j+848) alive) alive
    if r != 160 || status r != 0 || load64 (wire+48) r != load64 (j+16) r ||
      load64 (wire+56) r != load64 (j+832) r then error else r

-- Remote artifact return-v1: a completed job's binary is an actual object,
-- distinct from the asserted digest. Initial supported output cap is64KiB.
def artifactBegin (j length t : UInt64) : UInt64 :=
  let n := load64 (command+24) t
  if length != 160 || load64 j t != 2 || load64 (command+16) t != self t || n == 0 || n > 65536 ||
    !Guest.ProjectGraph.equal (command+64) (j+64) 32 t || !Guest.ProjectGraph.equal (command+96) (j+96) 32 t ||
    !Guest.ProjectGraph.equal (command+128) (st+32) 32 t then fail 1 t else
  if load64 (j+920) t != 0 then fail (if n == load64 (j+904) t then 6 else 2) t else
    let previous := load64 (j+896) t
    let t := if previous == 0 then t else abortStage previous t
    let r := stage n 10 0 t
    if r != 64 || status r != 0 then fail 4 r else
      let t := store64 (j+896) (result r) r
      let t := store64 (j+904) n t
      fail 0 (store64 (j+912) 0 t)
def artifactAppend (j length t : UInt64) : UInt64 :=
  let n := length-64
  let offset := load64 (command+24) t
  if length < 65 || length > 576 || load64 j t != 2 || load64 (command+16) t != self t ||
    load64 (j+896) t == 0 || offset != load64 (j+912) t || offset > load64 (j+904) t || n > load64 (j+904) t-offset then fail 1 t else
    let r := append (load64 (j+896) t) offset (command+64) n t
    if r != 64 || status r != 0 then fail 4 r else fail 0 (store64 (j+912) (offset+n) r)
def artifactCommit (j length t : UInt64) : UInt64 :=
  if length != 64 || load64 j t != 2 || load64 (command+16) t != self t then fail 1 t else
  if load64 (j+920) t != 0 then fail 0 t else
  if load64 (j+896) t == 0 || load64 (j+904) t != load64 (j+912) t then fail 1 t else
    let r := commit (load64 (j+896) t) (j+96) t
    if r != 96 || status r != 0 then
      let h := load64 (j+896) r
      let t := store64 (j+896) 0 r
      fail 2 (abortStage h t)
    else
      let t := store64 (j+920) (result r) r
      let t := store64 (j+896) 0 t
      -- commit returns the payload SHA, not the canonical typed Source ID.
      -- Graph references must always use nodeMetadata's canonical identity.
      let r := nodeMetadata (load64 (j+920) t) t
      if r != 128 || status r != 0 then fail 2 r else
        fail 0 (copy (wire+64) (j+928) 32 r)
def artifactRead (j caller t : UInt64) : UInt64 :=
  if load64 j t != 2 then fail 6 t else
  if load64 (j+1016) t == 2 then
    if load64 (j+992) t != 2 then fail 6 t else
    let r := Guest.ContentStore.share (load64 (j+976) t) 8 (load64 (j+984) t) caller t
    if r != 64 || status r != 0 then fail 1 r else
      let h := result r
      let t := header 0 h (load64 (j+904) r) 2 (load64 (j+1008) r) 0 0 r
      96+copy (j+928) (wire+64) 32 t
  else if load64 (j+920) t == 0 then fail 6 t else
    let r := share (load64 (j+920) t) caller 3 t
    if r != 64 || status r != 0 then fail 1 r else
      let h := result r
      let t := zero wire 8 r
      let t := store64 (wire+8) h t
      let t := store64 (wire+16) (load64 (j+904) t) t
      96+copy (j+928) (wire+64) 32 t

-- Generic artifacts stay in ContentStore, never in Project's64KiB records.
-- Hash one512-byte quantum before publishing a read scope, in addition to the
-- normal chunk/Merkle validation already performed by ContentStore.
def artifactContent (j caller length t : UInt64) : UInt64 :=
  let h := load64 (command+16) t
  let ri := Guest.ContentStore.authorized caller h 1 t
  if length != 64 || load64 j t != 2 || ri == error then fail 1 t else
  let p := Guest.ContentStore.root ri
  if load64 p t != 2 || load64 (p+32) t == 0 || load64 (p+32) t > 262144 ||
    load64 (p+264) t != 2 || load64 (p+296) t != Guest.ContentFormat.genericArtifact ||
    !Guest.ProjectGraph.equal (p+320) (j+96) 32 t ||
    !Guest.ProjectGraph.equal (p+384) (j+64) 32 t then fail 2 t else
  if load64 (j+1016) t == 2 then
    fail (if Guest.ProjectGraph.equal (p+128) (j+928) 32 t then 0 else 2) t
  else
    let t := store64 (j+960) ri t
    let t := store64 (j+968) (load64 (p+8) t) t
    let t := store64 (j+976) caller t
    let t := store64 (j+984) h t
    let t := store64 (j+992) 1 t
    let t := store64 (j+1000) 0 t
    let t := store64 (j+1016) 2 t
    let t := store64 (j+904) (load64 (p+32) t) t
    let t := copy (p+128) (j+928) 32 t
    fail 0 (Guest.ServiceHash.initialState (j+1024) t)

partial def bigEndianLength (p n count t : UInt64) : UInt64 :=
  if count == 0 then t else bigEndianLength (p+1) n (count-1) (store8 p ((n >>> ((count-1)*8)) &&& 255) t)
def artifactQuantum (j t : UInt64) : UInt64 :=
  if load64 (j+992) t != 1 then t else
  let total := load64 (j+904) t
  let offset := load64 (j+1000) t
  let count := if total-offset > 512 then 512 else total-offset
  let r := Guest.ContentStore.read (load64 (j+976) t) (load64 (j+984) t) offset count t
  if r != 64+count || status r != 0 then store64 (j+992) 3 r else
  let t := copy (wire+64) 0x624000 count r
  let t := Guest.ServiceHash.blocks (j+1024) 0x624000 count count 0 (count/64) t
  let offset := offset+count
  let t := store64 (j+1000) offset t
  if offset != total then t else
    let tail := count%64
    let t := zero 0x625000 16 t
    let t := copy (0x624000+count-tail) 0x625000 tail t
    let t := store8 (0x625000+tail) 128 t
    let n := if tail < 56 then 64 else 128
    let t := bigEndianLength (0x625000+n-8) (total*8) 8 t
    let t := Guest.ServiceHash.blocks (j+1024) 0x625000 n n 0 (n/64) t
    let t := Guest.ServiceHash.outputBytes (j+1024) 0x626000 0 t
    store64 (j+992) (if Guest.ProjectGraph.equal 0x626000 (j+96) 32 t then 2 else 3) t
partial def artifactWork (i t : UInt64) : Bool :=
  if i == 4 then false else load64 (job i+992) t == 1 || artifactWork (i+1) t
partial def pumpArtifacts (i t : UInt64) : UInt64 :=
  if i == 4 then t else pumpArtifacts (i+1) (artifactQuantum (job i) t)

def durableBind (j slot t : UInt64) : UInt64 :=
  if !Guest.ServiceSDK.validHandle slot || load64 j t != 1 then fail 1 t else
  if load64 (j+1008) t != 0 then fail (if load64 (j+1008) t == slot+1 then 6 else 2) t else
    let r := Guest.ServiceSDK.inspect slot t
    if r != 576 || status r != 0 || !Guest.ProjectGraph.equal (wire+192) (j+64) 32 r ||
      (load64 (wire+256) r != 3 && load64 (wire+256) r != 4) then fail 1 r else
      let t := copy (wire+160) 0x627000 32 r
      let t := copy (st+32) 0x627020 32 t
      let t := Guest.ServiceHash.sha256At 0x628000 0x627000 64 0x629000 t
      if !Guest.ProjectGraph.equal 0x629000 (wire+224) 32 t then fail 1 t else
      let t := store64 (j+1728) (load64 (wire+120) t) t
      let r := Guest.ServiceSDK.reserve slot 0 0 1 t
      if r != 64 || status r != 0 then fail 4 r else fail 0 (store64 (j+1008) (slot+1) r)
def durableRetry (j t : UInt64) : UInt64 :=
  if load64 j t != 1 || load64 (j+1008) t == 0 then fail 1 t else
  let slot := load64 (j+1008) t-1
  let r := Guest.ServiceSDK.inspect slot t
  if r != 576 || status r != 0 || load64 (wire+120) r <= load64 (j+1728) r then fail 6 r else
    let t := store64 (j+1728) (load64 (wire+120) r) r
    let r := Guest.ServiceSDK.reserve slot 0 0 1 t
    if r != 64 || status r != 0 then fail 4 r else fail 0 r

def verifyReceiptSignature (message signature publicKey t : UInt64) : UInt64 :=
  -- The existing public verifier has fixed private scratch602000..602c20.
  -- Preserve the two overlapping live job records while it runs serialized.
  let t := copy 0x602000 0x62e000 4096 t
  let verified := Guest.ServiceSignature.verify message 256 signature publicKey t
  let t := store64 0x62d000 (if verified then 1 else 0) t
  let t := copy 0x62e000 0x602000 4096 t
  Guest.Effects.effectValue (load64 0x62d000 t) t
def attachServiceReceipt (slot length t : UInt64) : UInt64 :=
  if !Guest.ServiceSDK.validHandle slot || length != 576 then fail 2 t else
  let t := copy (command+64) 0x62b000 512 t
  let r := Guest.ServiceSDK.callService 64 (header 297 slot 0 0 0 0 0 t)
  if r != 320 || status r != 0 then fail 1 r else
  let t := copy (wire+64) 0x62a000 256 r
  let r := Guest.ServiceSDK.callService 64 (header 294 slot 0 0 0 0 0 t)
  if r != 320 || status r != 0 || !Guest.ProjectGraph.equal (wire+64) 0x62b000 256 r then fail 2 r else
  let verified := verifyReceiptSignature 0x62b000 0x62b100 0x62a000 r
  if verified != 1 then fail 5 verified else
    let t := header 295 slot 0 0 0 0 0 verified
    Guest.ServiceSDK.callService 576 (copy 0x62b000 (wire+64) 512 t)
def readServiceReceipt (slot t : UInt64) : UInt64 :=
  if !Guest.ServiceSDK.validHandle slot then fail 2 t else
  let r := Guest.ServiceSDK.callService 64 (header 298 slot 0 0 0 0 0 t)
  if r != 832 || status r != 0 then fail 6 r else
  let t := copy (wire+64) 0x62a000 768 r
  let verified := verifyReceiptSignature 0x62a000 0x62a100 0x62a200 t
  if verified != 1 then fail 5 verified else
    let t := header 0 slot 1 0 0 0 0 verified
    832+copy 0x62a000 (wire+64) 768 t

def archiveSource (j grant t : UInt64) : UInt64 :=
  if load64 j t != 1 || grant == 0 || load64 (j+1008) t == 0 then fail 1 t else
  if Guest.ForgeArchive.active t then fail 7 t else
    let t := store64 0x610280 0x6f732d646c697562 t
    let t := store64 0x610288 0x65637275 t
    let t := Guest.ForgeArchive.save (load64 (j+24) t) grant 0x610280 12 (j+64) t
    if Guest.ForgeArchive.phase t != 1 then fail 4 t else
      let t := store64 sourceArchive j t
      let t := store64 (sourceArchive+8) (load64 (j+8) t) t
      let t := store64 (sourceArchive+16) 1 t
      fail 0 (store64 (j+1744) 1 t)
def recoverSource (slot grant t : UInt64) : UInt64 :=
  if !Guest.ServiceSDK.validHandle slot || grant == 0 || Guest.ForgeArchive.active t then fail 1 t else
  let r := Guest.ServiceSDK.callService 64 (header 292 slot 0 0 0 0 0 t)
  if r != 576 || status r != 0 then fail 1 r else
    let t := copy (wire+192) (sourceArchive+32) 32 r
    let t := Guest.ForgeArchive.inspect grant t
    if Guest.ForgeArchive.phase t != 3 then fail 4 t else
      let t := store64 sourceArchive 0 t
      let t := store64 (sourceArchive+24) 0 t
      fail 0 (store64 (sourceArchive+16) 2 t)
def pumpSourceArchive (t : UInt64) : UInt64 :=
  let t := if !Guest.ForgeArchive.active t then t else Guest.ForgeArchive.pump t
  if load64 (sourceArchive+16) t == 1 then
    let j := load64 sourceArchive t
    if j == 0 || load64 (j+8) t != load64 (sourceArchive+8) t then t else
    if Guest.ForgeArchive.phase t == 8 && load64 (j+1744) t == 1 then
      let r := Guest.ServiceSDK.reserve (load64 (j+1008) t-1) 0 1 0 t
      store64 (j+1744) (if r == 64 && status r == 0 then 2 else 3) r
    else
    if Guest.ForgeArchive.phase t == 9 then store64 (j+1744) 3 t else t
  else if load64 (sourceArchive+16) t == 2 && Guest.ForgeArchive.phase t == 4 then
    if !Guest.ProjectGraph.equal (Guest.ForgeArchive.bundleIndex+32) (sourceArchive+32) 32 t then
      Guest.ForgeArchive.fail 11 t
    else Guest.ForgeArchive.recover t
  else if load64 (sourceArchive+16) t == 2 && Guest.ForgeArchive.phase t == 8 && load64 (sourceArchive+24) t == 0 then
    let r := Guest.ProjectSDK.delegate (Guest.ForgeArchive.resultRoot t) (syscall 97 1 0 0 0 t) 127 t
    if r != 160 || status r != 0 then Guest.ForgeArchive.fail 12 r else
      store64 (sourceArchive+24) (result r) r
  else t
def archiveInspection (j t : UInt64) : UInt64 :=
  let t := header 0 (if j == 0 then Guest.ForgeArchive.phase t else load64 (j+1744) t)
    (Guest.ForgeArchive.progress t) (Guest.ForgeArchive.total t) (Guest.ForgeArchive.code t)
    (if j == 0 then load64 (sourceArchive+24) t else Guest.ForgeArchive.resultRoot t) 0 t
  64+t
def pumpSourceWaiter (t : UInt64) : UInt64 :=
  let token := load64 (sourceArchive+64) t
  if token == 0 then t else
  let j := load64 (sourceArchive+72) t
  let ready := if j == 0 then Guest.ForgeArchive.phase t == 8 || Guest.ForgeArchive.phase t == 9
    else load64 (j+1744) t >= 2
  if !ready && syscall 116 0 0 0 0 t < load64 (sourceArchive+80) t then t else
    let r := archiveInspection j t
    reply token r (store64 (sourceArchive+64) 0 r)
def pumpQueueWaiter (t : UInt64) : UInt64 :=
  let token := load64 (sourceArchive+96) t
  if token == 0 then t else
  let i := queuedFor (load64 (sourceArchive+104) t) 0 t
  if i == error && syscall 116 0 0 0 0 t < load64 (sourceArchive+112) t then t else
    let t := header 0 (if i == error then 0 else load64 (job i+8) t) 0 0 0 0 0 t
    reply token 64 (store64 (sourceArchive+96) 0 t)
def boundedReceive (endpoint t : UInt64) : UInt64 :=
  if Guest.ContentStore.hasWork 0 t || artifactWork 0 t || Guest.ForgeArchive.active t then syscall 36 endpoint incoming 1024 0 t else
  if load64 (sourceArchive+96) t == 0 then receive endpoint t else
    let t := syscall 117 (load64 (sourceArchive+112) t) 0 0 0 t
    syscall 36 endpoint incoming 1024 0 t

def completeJob (j length t : UInt64) : UInt64 :=
  if length >= 192 && length <= 704 &&
    load64 j t == 1 && load64 (command+16) t == self t && load64 (command+24) t >= 2 && load64 (command+24) t <= 3 && load64 (command+40) t == 2 &&
    Guest.ProjectGraph.equal (command+64) (j+64) 32 t &&
    Guest.ProjectGraph.equal (command+160) (st+32) 32 t && load64 (command+32) t == 0 && load64 (command+48) t == length-192 then
      let t := copy (command+96) (j+96) 32 t
      let t := copy (command+192) (j+256) (length-192) t
      let t := store64 (j+40) (length-192) t
      let t := copy (command+128) (j+192) 32 t
      let t := store64 j (load64 (command+24) t) t
      let attached := attachRecords j t
      if attached == error then
        let t := store64 j 3 attached
        fail 4 t
      else response j attached
  else fail 1 t

def workerCommand (j caller op length t : UInt64) : UInt64 :=
  if op == 3 then completeJob j length t else
  if op == 8 then artifactBegin j length t else
  if op == 9 then artifactAppend j length t else
  if op == 10 then artifactCommit j length t else
  if op == 12 then artifactContent j caller length t else
  if length != 64 then fail 2 t else
  if op == 27 then archiveSource j (load64 (command+16) t) t else
  if op == 28 then archiveInspection j t else
  if op == 13 then durableBind j (load64 (command+16) t) t else
  if op == 19 then durableRetry j t else
  if op == 14 then
    if load64 (j+992) t != 2 || load64 (j+1008) t == 0 then fail 6 t else
      Guest.ServiceSDK.complete (load64 (j+1008) t-1) (load64 (j+904) t) (j+928) t
  else if op == 15 then
    64+header 0 (load64 (j+8) t) (load64 (j+992) t) (load64 (j+1000) t) (load64 (j+904) t)
      (load64 (j+1008) t) (load64 (j+1728) t) t
  else if op == 16 then
    if load64 (j+1008) t == 0 then fail 6 t else
      Guest.ServiceSDK.fail (load64 (j+1008) t-1) (load64 (command+16) t) t
  else if op == 7 then
    let checked := validateJobAuthority j t
    if checked == error then fail 1 checked else authorityResponse j checked
  else if op == 6 then artifactGrants j caller t else fail 1 t

def dispatch (caller rights length t : UInt64) : UInt64 :=
  let op := load64 command t
  let id := load64 (command+8) t
  let admin := (rights &&& 0x100000000) != 0
  if length < 64 || load64 (command+56) t != 1 then fail 2 t else
  if op >= 20 && op <= 26 then Guest.BuildArtifact.dispatch caller rights length t else
  if op >= 300 && op <= 318 then Guest.ContentStore.dispatch caller rights length t else
  if op == 17 && admin then attachServiceReceipt id length t else
  if op == 18 && length == 64 && admin then readServiceReceipt id t else
  if op == 29 && length == 64 && admin then recoverSource id (load64 (command+16) t) t else
  if op == 30 && length == 64 && admin then archiveInspection 0 t else
  if op == 1 && length == 64 then enqueue caller id t else
  if op == 2 && length == 64 && admin then
    let i := nextJob 0 t
    if i == error then fail 6 t else
      let checked := validateJobAuthority (job i) t
      if checked == error then fail 6 (cancel (job i) checked) else response (job i) checked
  else
    let i := findJob id 0 t
    if i == error then fail 3 t else
      let j := job i
      if op == 11 && length == 64 && load64 (j+16) t == caller then artifactRead j caller t else
      if op == 4 && length == 64 && load64 (j+16) t == caller then response j t else
      if op == 5 && length == 64 && load64 (j+16) t == caller then cancel j t else
      if admin then workerCommand j caller op length t else fail 1 t

partial def serve (endpoint initial : UInt64) : UInt64 :=
  let t := pumpQueueWaiter (pumpSourceWaiter (pumpSourceArchive (pumpArtifacts 0 (Guest.ContentStore.pump initial))))
  let n := boundedReceive endpoint t
  if n == 0 then serve endpoint (syscall 9 0 0 0 0 n) else
  if n == error then serve endpoint n else
    let caller := load64 incoming n
    let token := load64 (incoming+8) n
    let rights := load64 (incoming+16) n
    if n == 96 && load64 (incoming+24) n == 2 && load64 command n == 32 &&
      (rights &&& 0x100000000) != 0 && load64 (command+56) n == 1 &&
      load64 (command+16) n > 0 && load64 (command+16) n <= 100 && load64 (sourceArchive+96) n == 0 &&
      syscall 34 (load64 (command+8) n) 0 0 0 n != error then
      let t := store64 (sourceArchive+96) token n
      let t := store64 (sourceArchive+104) (load64 (command+8) t) t
      let t := store64 (sourceArchive+112) (syscall 116 0 0 0 0 t+load64 (command+16) t) t
      serve endpoint t
    else
    if n == 96 && load64 (incoming+24) n == 2 && load64 command n == 31 &&
      (rights &&& 0x100000000) != 0 && load64 (command+56) n == 1 &&
      load64 (command+16) n > 0 && load64 (command+16) n <= 100 && load64 (sourceArchive+64) n == 0 then
      let id := load64 (command+8) n
      let i := if id == 0 then 4 else findJob id 0 n
      if i == error then serve endpoint (reply token (fail 3 n) n) else
        let t := store64 (sourceArchive+64) token n
        let t := store64 (sourceArchive+72) (if i == 4 then 0 else job i) t
        let t := store64 (sourceArchive+80) (syscall 116 0 0 0 0 t+load64 (command+16) t) t
        serve endpoint t
    else
    let r := if n >= 96 && load64 (incoming+24) n == 2 then dispatch caller rights (n-32) n else fail 2 n
    serve endpoint (reply token r r)
def main (initial : UInt64) : UInt64 :=
  let t := Guest.ForgeArchive.init (zero st 2048 initial)
  let fetched := syscall 100 0 (st+32) 32 0 t
  let t := store64 (st+64) (if fetched == 0 && !Guest.ProjectGraph.allZero (st+32) 32 fetched then 1 else 0) fetched
  serve (self t) (Guest.ContentStore.startStore (self t) t)
end Guest.BuildJobs
