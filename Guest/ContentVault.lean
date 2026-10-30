import Guest.ContentSDK
import Guest.ContentFormat
import Guest.ConsumerFormat
import Guest.VaultCrypto
namespace Guest.ContentVault
open Guest.LiveSDK
-- Additive v3: legacy v1/v2 roots and all their banks end at sector20991.
-- Exactly one explicitly selected complete root or private verified checkpoint
-- is retained here. Purpose2 is separately selected by ServerContent grants.
-- No capability, session key, execution approval or network job is serialized.
def st : UInt64 := 0x780000
def candidate : UInt64 := 0x781000
def rootA : UInt64 := 0x781200
def rootB : UInt64 := 0x781400
def plain : UInt64 := 0x782000
def cipher : UInt64 := 0x784000
def nonce : UInt64 := 0x786000
def aad : UInt64 := 0x786100
def hashScratch : UInt64 := 0x786400
def hashed : UInt64 := 0x786800
def metadata : UInt64 := 0x787000
def current : UInt64 := 0x788000
-- Only the trusted ServerContent frontend selects backend2. This context is
-- outside newJob's cleared header and never comes from an application domain.
def backend : UInt64 := 0x789000
def key : UInt64 := 0x620080
def magic : UInt64 := 0x3356434d544c
def serverMagic : UInt64 := 0x31524353544c
def isServer (t : UInt64) : Bool := load64 backend t == 2
def rootSector (t : UInt64) : UInt64 := if isServer t then 33088+load64 (backend+104) t*29464 else 20992
def bankSector (bank t : UInt64) : UInt64 := (if isServer t then 33096+load64 (backend+104) t*29464 else 21000)+bank*14728
def indexLength (r t : UInt64) : UInt64 := load64 (r+56) t
def chunkBase (r t : UInt64) : UInt64 := if indexLength r t == 512 then 2 else if indexLength r t == 2048 then 5 else 6
def selectionOffset (r t : UInt64) : UInt64 := if indexLength r t == 2560 then 768 else 512
def indexSectors (len : UInt64) : UInt64 := if len == 512 then 2 else if len == 2048 then 5 else 6
def checkedChunk (index t : UInt64) : Bool := ((load8 (metadata+384+index/8) t >>> (index%8)) &&& 1) == 1
def markChunk (index t : UInt64) : UInt64 :=
  let p := metadata+384+index/8
  store8 p (load8 p t ||| ((1 : UInt64) <<< (index%8))) t
partial def bitmapValid (count total i observed t : UInt64) : Bool :=
  if i == 1472 then observed == count else
    if checkedChunk i t then i < total && bitmapValid count total (i+1) (observed+1) t else bitmapValid count total (i+1) observed t
partial def bitmapBytes (total count i bytes t : UInt64) : UInt64 :=
  if i == count then bytes else
    bitmapBytes total count (i+1) (if checkedChunk i t then bytes+ContentFormat.chunkLength total i else bytes) t
def eq (a b n t : UInt64) : Bool := ContentFormat.equal a b n t
def allZero (p n t : UInt64) : Bool := ContentFormat.allZero p n t
def device (op sector ptr bytes t : UInt64) : UInt64 :=
  if isServer t then
    if op == 60 then syscall 65 sector ptr bytes 2 t else
    if op == 61 then syscall 66 sector ptr bytes 2 t else
    if op == 62 then syscall 67 2 0 0 0 t else error
  else syscall op sector ptr bytes 0 t
def backendAuthorized (t : UInt64) : Bool :=
  if !isServer t then load64 0x620000 t == 1 else
  let g := load64 (backend+112) t
  g >= 0x7a1000 && g < 0x7a1800 && g%128 == 0 &&
    load64 g t == load64 (backend+8) t && load64 (g+8) t == load64 (backend+16) t &&
    load64 (g+16) t == load64 (backend+104) t && load64 (g+16) t < 4 &&
    eq (g+32) (backend+24) 32 t && eq (g+64) (backend+56) 32 t &&
    load64 (g+24) t == load64 (backend+88) t
partial def transfer (op sector ptr remaining t : UInt64) : UInt64 :=
  if remaining == 0 then t else
    let n := if remaining < 4096 then remaining else 4096
    let t := if op == 61 then copy ptr chunk n t else t
    let result := device op sector chunk n t
    if result != 0 then error else
      let t := if op == 60 then copy chunk ptr n result else result
      transfer op (sector+n/512) (ptr+n) (remaining-n) t
def response (code t : UInt64) : UInt64 :=
  -- Retention progress advances only after the encrypted record's block writes
  -- complete. Plaintext staged for the next write is not reported as written.
  let progressed := if load64 st t == 1 && indexLength candidate t == 2560 then load64 (st+192) t else
    load64 (st+32) t*4096+(if load64 st t == 1 then 0 else load64 (st+40) t)
  let progressed := if progressed > load64 (st+56) t then load64 (st+56) t else progressed
  let t := header code (load64 (st+8) t) (load64 (st+80) t) progressed
    (load64 (st+56) t) (load64 (st+72) t) (load64 (st+88) t) t
  let t := store64 (wire+64) (load64 (st+104) t) t
  80+store64 (wire+72) (load64 (st+144) t) t
def active (t : UInt64) : Bool := load64 st t != 0 && load64 (st+80) t == 1
def clear (t : UInt64) : UInt64 := zero st 8192 t
def makeNonce (root part t : UInt64) : UInt64 :=
  let t := copy (root+96) nonce 12 t
  let n := VaultCrypto.le32 (nonce+8) t+part
  VaultCrypto.putLE (nonce+8) n 4 t
def chunkAAD (root index length t : UInt64) : UInt64 :=
  let t := copy root aad 128 t
  let t := if indexLength root t == 2560 then zero (aad+72) 3 t else t
  let t := copy (metadata+256) (aad+128) 32 t
  let t := store64 (aad+160) index t
  store64 (aad+168) length t
def writeStored (root part input len out t : UInt64) : UInt64 :=
  if isServer t then
    let t := copy input out len t
    ServiceHash.sha256At hashScratch out len (out+len) t
  else
    let t := makeNonce root part t
    if part == 0 then VaultCrypto.encrypt key nonce root 128 input len out t else
      let t := chunkAAD root (part-1) (load64 (input+8) t) t
      VaultCrypto.encrypt key nonce aad 176 input len out t
def openStored (root part len out t : UInt64) : UInt64 :=
  if isServer t then
    let t := ServiceHash.sha256At hashScratch cipher len hashed t
    if !eq hashed (cipher+len) 32 t then error else copy cipher out len t
  else
    let t := makeNonce root part t
    if part == 0 then VaultCrypto.decrypt key nonce root 128 cipher len out t else
      let t := chunkAAD root (part-1) (ContentFormat.chunkLength (load64 (st+56) t) (part-1)) t
      VaultCrypto.decrypt key nonce aad 176 cipher len out t
def validRoot (r t : UInt64) : Bool :=
  load64 r t == (if isServer t then serverMagic else magic) &&
  (if isServer t then load64 (r+8) t == 5 || load64 (r+8) t == 6 else load64 (r+8) t == 3 || load64 (r+8) t == 4 || load64 (r+8) t == 5) &&
  load64 (r+16) t == (if isServer t then 4 else 3) &&
  load64 (r+24) t > 0 && load64 (r+32) t == load64 (r+24) t%2 &&
  load64 (r+40) t > 0 && load64 (r+40) t <= ContentFormat.maxBytes &&
  load64 (r+48) t == (load64 (r+40) t+4095)/4096 &&
  (if !isServer t && load64 (r+8) t == 5 then load64 (r+56) t == 2560 && (load64 (r+64) t == 0 || load64 (r+64) t == 1536)
   else if load64 (r+8) t == 3 || load64 (r+8) t == 5 then load64 (r+56) t == 512 && load64 (r+64) t == 0
   else load64 (r+56) t == 2048 && load64 (r+64) t == 1536) &&
  (if indexLength r t == 2560 then load64 (r+72) t == 1 && load64 (r+80) t <= load64 (r+48) t && load64 (r+88) t == 0 else allZero (r+72) 24 t) &&
  allZero (r+108) 20 t &&
  (if isServer t then eq (r+176) (backend+24) 32 t && allZero (r+208) 304 t else allZero (r+176) 336 t)
def validSelection (offset t : UInt64) : Bool :=
  ConsumerFormat.valid (metadata+offset+768) t &&
  eq (metadata+offset+960) (metadata+256) 32 t &&
  eq (metadata+offset+992) (metadata+64) 32 t &&
  load64 (metadata+offset+1176) t == load64 (metadata+24) t
def selectionHash (offset t : UInt64) : UInt64 :=
  let t := ServiceHash.sha256At hashScratch (metadata+offset+768) 768 hashed t
  if !eq hashed (metadata+offset+400) 32 t || !validSelection offset t then error else t
def tryRoot (r t : UInt64) : UInt64 :=
  if !validRoot r t then error else
  let len := indexLength r t
  let bytes := indexSectors len*512
  let read := transfer 60 (bankSector (load64 (r+32) t) t) cipher bytes t
  if read == error || !eq (cipher+len) (r+128) 16 read then error else
  let t := ServiceHash.sha256At hashScratch cipher len hashed read
  if !eq hashed (r+144) 32 t then error else
  let result := openStored r 0 len metadata t
  if result != 0 || !ContentFormat.valid metadata result || load64 (metadata+24) result != load64 (r+40) result ||
    load64 (metadata+32) result != load64 (r+48) result ||
    !(if len == 2560 then allZero (metadata+360) 24 result && allZero (metadata+568) 200 result &&
      allZero (metadata+2304) 256 result && bitmapValid (load64 (r+80) result) (load64 (r+48) result) 0 0 result
      else allZero (metadata+360) 152 result) then error else
    let t := ServiceHash.sha256At hashScratch metadata 256 hashed result
    if !eq hashed (metadata+256) 32 t then error else
    if isServer t && !backendAuthorized t then error else
    let t := if load64 (r+64) t == 1536 then selectionHash (selectionOffset r t) t else
      if len == 2560 then if allZero (metadata+768) 1536 t then t else error else zero (metadata+512) 192 t
    if t == error then error else copy r current 512 t
def scan (t : UInt64) : UInt64 :=
  let a := transfer 60 (rootSector t) rootA 512 t
  if a == error then error else
  let b := transfer 60 (rootSector a+1) rootB 512 a
  if b == error then error else
  let high := if load64 (rootA+24) b >= load64 (rootB+24) b then rootA else rootB
  let low := if high == rootA then rootB else rootA
  let r := tryRoot high b
  if r != error then r else
  let r := tryRoot low b
  if r != error then r else
  if allZero rootA 512 b && allZero rootB 512 b then zero current 64 b else error
def finish (state code t : UInt64) : UInt64 :=
  let content := load64 (st+48) t
  let t := if state >= 5 && content != 0 then ContentSDK.release content t else t
  let t := if state >= 5 then store64 (st+48) 0 t else t
  let object := load64 (st+128) t
  let t := if state >= 5 && object != 0 then
    let r := LiveSDK.abortStage object t
    if r != error && status r == 0 then r else LiveSDK.drop object r
    else t
  let t := if state >= 5 then store64 (st+128) 0 t else t
  let t := store64 (st+80) state t
  let t := store64 (st+88) code t
  let t := zero plain 576 t
  let t := zero cipher 640 t
  let t := zero nonce 4 t
  zero aad 32 t
def newJob (caller operation mode recipient t : UInt64) : UInt64 :=
  let t := zero st 32 t
  let t := store64 st mode t
  let t := store64 (st+8) operation t
  let t := store64 (st+16) caller t
  let t := store64 (st+80) 1 t
  store64 (st+96) recipient t
def rejectRetain (code content t : UInt64) : UInt64 :=
  let t := if content == 0 || (active t && content == load64 (st+48) t) then t else ContentSDK.release content t
  response code t
def startRetain (caller content operation selectedMetadata t : UInt64) : UInt64 :=
  if load64 st t == 1 && load64 (st+8) t == operation && load64 (st+16) t == caller then response 0 t else
  if active t then rejectRetain 7 content t else
  if operation == 0 then rejectRetain 2 content t else
  let checked := scan t
  if checked == error then rejectRetain 4 content checked else
  let described := ContentSDK.describe content checked
  if described == error || status described != 0 ||
    (load64 (wire+16) described != 2 && !(load64 (wire+16) described == 1 && !isServer described)) ||
    described < 320 then rejectRetain 1 content described else
  let partialContent := load64 (wire+16) described == 1
  let total := load64 (wire+32) described
  let count := load64 (wire+48) described
  let t := zero metadata 384 described
  let t := copy (wire+64) metadata 256 t
  let t := ServiceHash.sha256At hashScratch metadata 256 (metadata+256) t
  -- These IDs describe local vault recovery only, never remote peer authority.
  let t := copy (metadata+256) (metadata+288) 32 t
  let t := copy (metadata+256) (metadata+320) 32 t
  let t := store64 (metadata+352) operation t
  let generation := load64 (current+24) t+1
  if generation == 0 || total > ContentFormat.maxBytes || count > ContentFormat.maxChunks then rejectRetain 4 content t else
  let t := zero candidate 64 t
  let t := store64 candidate (if isServer t then serverMagic else magic) t
  let t := store64 (candidate+8) (if partialContent then 5 else (if selectedMetadata == 0 then 3 else 4)+(if isServer t then 2 else 0)) t
  let t := store64 (candidate+16) (if isServer t then 4 else 3) t
  let t := store64 (candidate+24) generation t
  let t := store64 (candidate+32) (generation%2) t
  let t := store64 (candidate+40) total t
  let t := store64 (candidate+48) count t
  let t := store64 (candidate+56) (if partialContent then 2560 else if selectedMetadata == 0 then 512 else 2048) t
  let t := store64 (candidate+64) (if selectedMetadata == 0 then 0 else 1536) t
  let t := if partialContent then store64 (candidate+72) 1 t else t
  let t := if isServer t then copy (backend+24) (candidate+176) 32 t else t
  if isServer t && (!backendAuthorized t || !eq (metadata+256) (backend+56) 32 t || total > load64 (backend+88) t) then rejectRetain 1 content t else
  let entropy := if isServer t then zero chunk 2 t else device 63 0 chunk 12 t
  if entropy != 0 then rejectRetain 4 content entropy else
  let t := copy chunk (candidate+96) 12 entropy
  let t := newJob caller operation 1 0 t
  let t := store64 (st+48) content t
  let t := store64 (st+56) total t
  let t := store64 (st+64) count t
  let t := store64 (st+72) generation t
  let t := store64 (st+152) selectedMetadata t
  if selectedMetadata == 0 then response 0 t else
    let r := LiveSDK.metadata selectedMetadata t
    if r == error || status r != 0 || load64 (wire+16) r != 1536 || load64 (wire+32) r != 2 then response 1 (finish 6 1 r) else
      response 0 (store64 (st+24) 10 r)
def startRecover (caller recipient operation expectedGeneration expectedHash t : UInt64) : UInt64 :=
  if load64 st t == 2 && load64 (st+8) t == operation && load64 (st+16) t == caller then
    if load64 (st+96) t == recipient then response 0 t else response 2 t else
  if active t then response 7 t else
  if operation == 0 || syscall 34 recipient 0 0 0 t == error then response 1 t else
  let checked := scan t
  if checked == error || load64 current checked != (if isServer checked then serverMagic else magic) then response 5 checked else
  if isServer checked && (!backendAuthorized checked || !eq (metadata+256) (backend+56) 32 checked || load64 (metadata+24) checked > load64 (backend+88) checked) then response 1 checked else
  if (expectedGeneration != 0 && load64 (current+24) checked != expectedGeneration) ||
    (expectedHash != 0 && !eq expectedHash (metadata+256) 32 checked) then response 3 checked else
  let t := copy metadata plain 352 checked
  let t := ContentSDK.reserve plain operation (load64 (metadata+24) t) 3 0 t
  if t == error || status t != 0 then response 4 t else
  let content := result t
  let t := newJob caller operation 2 recipient t
  let t := store64 (st+48) content t
  let t := store64 (st+56) (load64 (metadata+24) t) t
  let t := store64 (st+64) (load64 (metadata+32) t) t
  let t := store64 (st+72) (load64 (current+24) t) t
  response 0 t
def retainQuantum (t : UInt64) : UInt64 :=
  let index := load64 (st+32) t
  let offset := load64 (st+40) t
  let phase := load64 (st+24) t
  if phase == 10 then
    let cursor := load64 (st+160) t
    if cursor < 1536 then
      let r := LiveSDK.read (load64 (st+152) t) cursor 512 t
      if r == error || status r != 0 || result r != 512 then finish 6 1 r else
        let t := copy (wire+64) (metadata+selectionOffset candidate r+cursor) 512 r
        store64 (st+160) (cursor+512) t
    else
      let r := selectionHash (selectionOffset candidate t) t
      if r == error then finish 6 5 r else store64 (st+24) 0 r
  else if index == load64 (st+64) t then
    if phase == 0 then
      let t := zero cipher 640 t
      let len := indexLength candidate t
      let r := writeStored candidate 0 metadata len cipher t
      if r != 0 then finish 6 5 r else
      let t := copy (cipher+len) (candidate+128) 16 r
      let t := ServiceHash.sha256At hashScratch cipher len (candidate+144) t
      let r := transfer 61 (bankSector (load64 (candidate+32) t) t) cipher (indexSectors len*512) t
      if r == error then finish 6 4 r else store64 (st+24) 1 r
    else if phase == 1 then
      let r := device 62 0 chunk 0 t
      if r != 0 then finish 6 4 r else store64 (st+24) 2 r
    else if phase == 2 then
      let live := syscall 34 (load64 (st+16) t) 0 0 0 t
      if live == error || !backendAuthorized live then finish 5 1 live else
      let r := transfer 61 (rootSector live+load64 (candidate+32) live) candidate 512 live
      if r == error then finish 6 4 r else store64 (st+24) 3 r
    else
      let r := device 62 0 chunk 0 t
      if r != 0 then finish 6 4 r else
        let t := copy candidate current 512 r
        let t := ContentSDK.release (load64 (st+48) t) t
        finish 4 0 (store64 (st+48) 0 t)
  else
    let length := ContentFormat.chunkLength (load64 (st+56) t) index
    if phase == 0 then
      let t := zero plain 576 t
      let r := ContentSDK.proof (load64 (st+48) t) index t
      if r != error && status r == 6 && indexLength candidate r == 2560 then store64 (st+32) (index+1) r else
      if r == error || status r != 0 || result r > 384 then finish 6 5 r else
      let t := copy (wire+64) (plain+32) (result r) r
      let t := store64 plain index t
      let t := store64 (plain+8) length t
      let t := store64 (plain+16) (load64 (metadata+48) t) t
      store64 (st+24) 1 t
    else if phase == 1 then
      if offset == length then store64 (st+24) 2 t else
      let count := if length-offset < 512 then length-offset else 512
      let r := ContentSDK.read (load64 (st+48) t) (index*4096+offset) count t
      if r == error || status r != 0 || result r != count then finish 6 5 r else
      let t := copy (wire+64) (plain+512+offset) count r
      store64 (st+40) (offset+count) t
    else
      let t := zero cipher 640 t
      let r := writeStored candidate (index+1) plain 4608 cipher t
      if r != 0 then finish 6 5 r else
      let r := transfer 61 (bankSector (load64 (candidate+32) r) r+chunkBase candidate r+index*10) cipher 5120 r
      if r == error then finish 6 4 r else
      let t := if indexLength candidate r == 2560 then
        let t := markChunk index r
        let t := store64 (candidate+80) (load64 (candidate+80) t+1) t
        store64 (st+192) (load64 (st+192) t+length) t
        else r
      let t := store64 (st+32) (index+1) t
      let t := store64 (st+40) 0 t
      store64 (st+24) 0 t
def shareRecovery (t : UInt64) : UInt64 :=
  let r := ContentSDK.share (load64 (st+48) t) (load64 (st+96) t) t
  if r == error || status r != 0 then finish 6 1 r else
  let t := store64 (st+104) (result r) r
  let t := ContentSDK.release (load64 (st+48) t) t
  finish 4 0 (store64 (st+48) 0 t)
def recoverQuantum (t : UInt64) : UInt64 :=
  let index := load64 (st+32) t
  let offset := load64 (st+40) t
  let phase := load64 (st+24) t
  if index == load64 (st+64) t then
    if phase == 0 then
      if indexLength current t == 2560 && load64 (current+80) t < load64 (current+48) t then
        if load64 (current+64) t == 0 then shareRecovery t else store64 (st+24) 2 t
      else
      let r := ContentSDK.publish (load64 (st+48) t) t
      if r == error || status r != 0 then finish 6 5 r else
      let t := store64 (st+112) (result r) r
      store64 (st+24) 1 t
    else if phase == 1 then
      let r := ContentSDK.inspectJob (load64 (st+112) t) t
      if r == error || status r != 0 || load64 (wire+16) r >= 5 then finish 6 5 r else
      if load64 (wire+16) r != 4 then r else
      let t := ContentSDK.control (load64 (st+112) r) 4 r
      if load64 (current+64) t == 0 then shareRecovery t else store64 (st+24) 2 t
    else if phase == 2 then
      let t := ServiceHash.sha256At hashScratch (metadata+selectionOffset current t) 1536 hashed t
      let r := LiveSDK.begin 1536 2 0 hashed t
      if r == error || status r != 0 then finish 6 4 r else
      let t := store64 (st+128) (result r) r
      let t := store64 (st+136) 0 t
      store64 (st+24) 3 t
    else if phase == 3 then
      let cursor := load64 (st+136) t
      if cursor < 1536 then
        let r := LiveSDK.append (load64 (st+128) t) cursor (metadata+selectionOffset current t+cursor) 512 t
        if r == error || status r != 0 then finish 6 4 r else store64 (st+136) (cursor+512) r
      else
        let t := ServiceHash.sha256At hashScratch (metadata+selectionOffset current t) 1536 hashed t
        let r := LiveSDK.commit (load64 (st+128) t) hashed t
        if r == error || status r != 0 then finish 6 5 r else store64 (st+24) 4 r
    else
      let actual := syscall 34 (load64 (st+96) t) 0 0 0 t
      if actual == error then finish 6 1 actual else
      let r := LiveSDK.share (load64 (st+128) actual) (load64 (st+96) actual) (1 ||| (actual &&& 24)) actual
      if r == error || status r != 0 then finish 6 1 r else
        shareRecovery (store64 (st+144) (result r) r)
  else
    if indexLength current t == 2560 && !checkedChunk index t then store64 (st+32) (index+1) t else
    let length := ContentFormat.chunkLength (load64 (st+56) t) index
    if phase == 0 then
      let r := transfer 60 (bankSector (load64 (current+32) t) t+chunkBase current t+index*10) cipher 5120 t
      if r == error then finish 6 4 r else
      let r := openStored current (index+1) 4608 plain r
      if r != 0 || load64 plain r != index || load64 (plain+8) r != length ||
        load64 (plain+16) r != load64 (metadata+48) r || load64 (plain+24) r != 0 || !allZero (plain+416) 96 r ||
        !allZero (plain+512+length) (4096-length) r then finish 6 5 r else
      let proofBytes := 32+load64 (metadata+48) r*32
      let r := ContentSDK.beginChunk (load64 (st+48) r) index (plain+32) proofBytes r
      if r == error || status r != 0 then finish 6 5 r else
      let t := store64 (st+112) (result r) r
      store64 (st+24) 1 t
    else if phase == 1 then
      if offset == length then
        let r := ContentSDK.validate (load64 (st+112) t) t
        if r == error || status r != 0 then finish 6 5 r else store64 (st+24) 2 r
      else
        let count := if length-offset < 512 then length-offset else 512
        let r := ContentSDK.append (load64 (st+112) t) offset (plain+512+offset) count t
        if r == error || status r != 0 then finish 6 5 r else store64 (st+40) (offset+count) r
    else
      let r := ContentSDK.inspectJob (load64 (st+112) t) t
      if r == error || status r != 0 || load64 (wire+16) r >= 5 then finish 6 5 r else
      if load64 (wire+16) r != 4 then r else
      let t := ContentSDK.control (load64 (st+112) r) 4 r
      let t := store64 (st+32) (index+1) t
      let t := store64 (st+40) 0 t
      store64 (st+24) 0 t
def pump (t : UInt64) : UInt64 :=
  if !active t then t else
  let live := syscall 34 (load64 (st+16) t) 0 0 0 t
  if live == error || !backendAuthorized live then finish 5 1 live else
  if load64 st live == 1 then retainQuantum live else recoverQuantum live
def abandon (t : UInt64) : UInt64 :=
  let content := load64 (st+48) t
  let t := if content == 0 then t else ContentSDK.release content t
  clear t
def abandonPersonal (t : UInt64) : UInt64 := if isServer t then t else abandon t
def inventory (t : UInt64) : UInt64 :=
  if active t then response 7 t else
  let r := scan t
  if r == error then response 5 r else
  if load64 current r != (if isServer r then serverMagic else magic) then response 6 r else
  if isServer r && (!eq (metadata+256) (backend+56) 32 r || load64 (metadata+24) r > load64 (backend+88) r) then response 1 r else
    let partialContent := indexLength current r == 2560
    let verified := if partialContent then bitmapBytes (load64 (current+40) r) (load64 (current+48) r) 0 0 r else load64 (current+40) r
    let t := header 0 (load64 (current+24) r) (if partialContent then 1 else 2) verified (load64 (current+40) r)
      (load64 (current+48) r) 3 r
    320+copy metadata (wire+64) 256 t
def delete (t : UInt64) : UInt64 :=
  let t := abandon t
  let t := zero rootA 64 t
  let a := transfer 61 (rootSector t) rootA 512 t
  let b := if a == error then error else transfer 61 (rootSector a+1) rootA 512 a
  let r := if b == error then error else device 62 0 chunk 0 b
  if r != 0 then response 4 r else response 0 (clear r)
def dispatch (caller op length t : UInt64) : UInt64 :=
  if length != 64 && !(op == 243 && length == 96) then response 2 t else
  if isServer t && active t then
    if op == 240 then rejectRetain 7 (load64 (command+8) t) t else response 7 t
  else
  let t := if isServer t then zero backend 16 t else t
  if op == 240 then startRetain caller (load64 (command+8) t) (load64 (command+24) t) (load64 (command+32) t) t else
  if op == 243 then startRecover caller (load64 (command+24) t) (load64 (command+32) t)
    (load64 (command+40) t) (if length == 96 then command+64 else 0) t else
  if op == 245 then delete t else
  if op == 246 then inventory t else
  if op == 241 || op == 244 then
    if load64 (st+16) t != 0 && load64 (st+16) t != caller then response 1 t else response 0 t
  else if op == 242 then
    if load64 (st+16) t != caller then response 1 t else response 0 (finish 5 0 t)
  else response 2 t
end Guest.ContentVault
