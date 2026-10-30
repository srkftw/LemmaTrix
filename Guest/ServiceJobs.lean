import Guest.ServerStore
namespace Guest.ServiceJobs
open Guest.LiveSDK
-- Bounded operator-only journal in legacy ServerStore's unused sectors24..55.
-- Personal data, transport keys, capability numbers and execution approvals
-- never enter these records. Each row has two independently flushed versions.
def st : UInt64 := 0x7c0000
def rows : UInt64 := 0x7c1000
def bindings : UInt64 := 0x7c4000
def working : UInt64 := 0x7c5000
def candidate : UInt64 := 0x7c5200
def scratch : UInt64 := 0x7c6000
def hashed : UInt64 := 0x7c7000
def keys : UInt64 := 0x7c8000
def receipt : UInt64 := 0x7ca000
def keyMagic : UInt64 := 0x3159454b5653544c
def receiptMagic : UInt64 := 0x315043525653544c
-- Purpose2 only. PrivateRecords uses a different, explicitly bound purpose1
-- device; the adapters reject binding one file to both storage purposes.
def receiptSector : UInt64 := 150944
def receiptCapacity : UInt64 := receiptSector+32
def key (role : UInt64) : UInt64 := keys+(role-1)*512
def magic : UInt64 := 0x31424f4a5653544c
def row (slot : UInt64) : UInt64 := rows+slot*512
def binding (slot : UInt64) : UInt64 := bindings+slot*16
-- Low byte identifies physical storage; upper56 bits identify its allocation.
-- Publication generation (row+24) is separate and never resets during reuse.
def index (handle : UInt64) : UInt64 := handle &&& 255
def handle (slot t : UInt64) : UInt64 := slot ||| (load64 (row slot+416) t <<< 8)
def current (identity slot t : UInt64) : Bool := slot < 16 && identity == handle slot t
def equal (a b n t : UInt64) : Bool := Guest.ProjectGraph.equal a b n t
def zeroBytes (p n t : UInt64) : Bool := Guest.ProjectGraph.allZero p n t
def response (code slot t : UInt64) : UInt64 :=
  if slot >= 16 then 64+header code slot 0 0 0 0 0 t else
  let p := row slot
  64+header code (handle slot t) (load64 (p+32) t) (load64 (p+40) t)
    (load64 (p+48) t) (load64 (p+56) t) (load64 (p+24) t) t
def disk (op sector p t : UInt64) : UInt64 :=
  let t := if op == 66 then copy p chunk 512 t else t
  let r := syscall op sector chunk 512 2 t
  if r != 0 then error else if op == 65 then copy chunk p 512 r else r
-- These are admitted work-quanta leases, not absolute wall-clock leases.
-- Absolute expiry cannot be established from boot uptime after a restart.
-- flags2 explicitly authorizes this basis; flags1 permits retained resumption.
def validTerms (p t : UInt64) : Bool :=
  !zeroBytes p 32 t && !zeroBytes (p+32) 32 t && !zeroBytes (p+64) 32 t &&
  !zeroBytes (p+96) 32 t && load64 (p+128) t > 0 && load64 (p+128) t <= 4 &&
  load64 (p+136) t > 0 && load64 (p+144) t == 3 &&
  load64 (p+152) t > 0 && load64 (p+152) t <= 1073741824 &&
  load64 (p+160) t > 0 && load64 (p+160) t <= 256 &&
  load64 (p+168) t > 0 && load64 (p+168) t <= 1000000000 &&
  (load64 (p+176) t == 2 || load64 (p+176) t == 3) &&
  load64 (p+184) t == 0 && !zeroBytes (p+192) 32 t
def valid (p slot t : UInt64) : Bool :=
  if load64 p t != magic || (load64 (p+8) t != 1 && load64 (p+8) t != 2) || load64 (p+16) t != slot ||
    load64 (p+24) t == 0 || load64 (p+32) t > 8 ||
    !validTerms (p+64) t || load64 (p+40) t > load64 (p+216) t ||
    load64 (p+48) t > load64 (p+216) t || load64 (p+56) t > load64 (p+224) t ||
    load64 (p+400) t > load64 (p+232) t || load64 (p+408) t > 0xffffffff ||
    (load64 (p+8) t == 1 && !zeroBytes (p+416) 16 t) || load64 (p+416) t > 0xffffffffffffff ||
    load64 (p+424) t > load64 (p+24) t || !zeroBytes (p+432) 16 t ||
    !zeroBytes (p+480) 32 t then false else
    let t := Guest.ServiceHash.sha256At scratch (p+64) 256 hashed t
    if !equal hashed (p+320) 32 t then false else
      let t := Guest.ServiceHash.sha256At scratch p 448 hashed t
      equal hashed (p+448) 32 t
def validKey (p role t : UInt64) : Bool :=
  if load64 p t != keyMagic || load64 (p+8) t != 1 || load64 (p+16) t != role ||
    load64 (p+24) t == 0 || (load8 (p+32) t &&& 128) == 0 ||
    (load8 (p+287) t &&& 1) == 0 || !zeroBytes (p+320) 192 t then false else
    let t := Guest.ServiceHash.sha256At scratch p 288 hashed t
    equal hashed (p+288) 32 t
partial def scanKeys (role t : UInt64) : UInt64 :=
  if role == 5 then t else
  let a := disk 65 (56+(role-1)*2) working t
  if a == error then error else
  let b := disk 65 (57+(role-1)*2) candidate a
  if b == error then error else
  let av := validKey working role b
  let bv := validKey candidate role b
  if !av && !bv then
    if zeroBytes working 512 b && zeroBytes candidate 512 b then scanKeys (role+1) (zero (key role) 64 b) else error
  else
    let p := if av && (!bv || load64 (working+24) b >= load64 (candidate+24) b) then working else candidate
    scanKeys (role+1) (copy p (key role) 512 b)
partial def scan (slot t : UInt64) : UInt64 :=
  if slot == 16 then t else
    let a := disk 65 (24+slot*2) working t
    if a == error then error else
    let b := disk 65 (25+slot*2) candidate a
    if b == error then error else
    let av := valid working slot b
    let bv := valid candidate slot b
    if !av && !bv then
      if zeroBytes working 512 b && zeroBytes candidate 512 b then scan (slot+1) (zero (row slot) 64 b) else error
    else
      let p := if av && (!bv || load64 (working+24) b >= load64 (candidate+24) b) then working else candidate
      let t := copy p (row slot) 512 b
      let t := if load64 (p+416) t != 0 then store64 (st+8) 1 t else t
      -- An interrupted attempt is distinct from fresh current authority.
      let t := if load64 (row slot+32) t == 2 then store64 (row slot+32) 6 t else t
      let t := Guest.ServiceHash.sha256At scratch (row slot) 448 hashed t
      let t := copy hashed (row slot+448) 32 t
      scan (slot+1) t
def mount (t : UInt64) : UInt64 :=
  if load64 st t == 1 then response 0 16 t else
  let capacity := syscall 64 2 0 0 0 t
  if capacity == error || capacity < 33088 then response 6 16 capacity else
  let r := disk 65 0 working capacity
  if r == error || load64 working r != Guest.ServerStore.formatMagic ||
    load64 (working+8) r != 1 || load64 (working+16) r != 33088 ||
    !zeroBytes (working+24) 488 r then response 6 16 r else
    let t := scanKeys 1 (zero bindings 32 (zero st 2 r))
    let t := if t == error then error else scan 0 t
    if t == error then response 5 16 t else response 0 16 (store64 st 1 t)
def persist (slot t : UInt64) : UInt64 :=
  let generation := load64 (row slot+24) t+1
  if generation == 0 then error else
  let t := store64 (working+24) generation t
  let t := Guest.ServiceHash.sha256At scratch working 448 hashed t
  let t := copy hashed (working+448) 32 t
  let r := disk 66 (24+slot*2+generation%2) working t
  if r == error then error else
    let r := syscall 67 2 0 0 0 r
    if r != 0 then error else copy working (row slot) 512 r
partial def locate (operation requester slot t : UInt64) : UInt64 :=
  if slot == 16 then error else
  if load64 (row slot) t == magic && equal operation (row slot+64) 32 t && equal requester (row slot+96) 32 t then slot
  else locate operation requester (slot+1) t
partial def vacant (slot t : UInt64) : UInt64 :=
  if slot == 16 then error else if load64 (row slot) t == 0 || load64 (row slot+32) t == 0 then slot else vacant (slot+1) t
def submit (identity length t : UInt64) : UInt64 :=
  let selected := index identity
  if length != 320 || (identity != 16 && selected >= 16) || load64 (command+40) t > 1 || !validTerms (command+64) t then response 2 16 t else
  let old := locate (command+64) (command+96) 0 t
  if old != error then
    response (if !equal (command+64) (row old+64) 256 t then 2 else if load64 (row old+32) t == 0 then 8 else 0) old t
  else
  -- After history reclamation, an unknown operation is not automatically a
  -- fresh allowance. Only an explicit new-operation admission may allocate it.
  if identity == 16 && load64 (st+8) t != 0 && load64 (command+40) t != 1 then response 8 16 t else
  let slot := if identity == 16 then vacant 0 t else selected
  if slot == error || (load64 (row slot) t != 0 && load64 (row slot+32) t != 0) then response 4 16 t else
  if identity != 16 && !current identity slot t then response 9 16 t else
  let used := load64 (row slot) t == magic
  let epoch := if used then load64 (row slot+416) t+1 else 0
  if epoch > 0xffffffffffffff then response 4 slot t else
    let generation := load64 (row slot+24) t
    let t := zero working 64 t
    let t := store64 working magic t
    let t := store64 (working+8) 2 t
    let t := store64 (working+16) slot t
    let t := store64 (working+24) generation t
    let t := store64 (working+32) 1 t
    let t := store64 (working+416) epoch t
    let t := store64 (working+424) (generation+1) t
    let t := copy (command+64) (working+64) 256 t
    let t := Guest.ServiceHash.sha256At scratch (working+64) 256 hashed t
    let t := copy hashed (working+320) 32 t
    let r := persist slot t
    if r == error then response 6 slot r else response 0 slot (if used then store64 (st+8) 1 r else r)
def terminal (state : UInt64) : Bool := state == 4 || state == 5 || state == 7 || state == 8
def bind (slot owner t : UInt64) : UInt64 :=
  let p := row slot
  let state := load64 (p+32) t
  let actual := syscall 34 owner 0 0 0 t
  if actual == error || (actual &&& 1025) == 0 || terminal state || state == 3 ||
    (state == 6 && (load64 (p+240) actual &&& 1) == 0) then response 6 slot actual else
  if load64 (binding slot) actual == owner && state == 2 then response 0 slot actual else
  if load64 (p+56) actual >= load64 (p+224) actual then response 4 slot actual else
    let t := copy p working 512 actual
    let t := store64 (working+32) 2 t
    let t := store64 (working+56) (load64 (p+56) t+1) t
    -- Audit the boot in which a live binding was issued. It is not a grant.
    let t := store64 (working+408) (self t >>> 32) t
    let r := persist slot t
    if r == error then response 6 slot r else
      response 0 slot (store64 (binding slot) owner r)
def owner (slot caller t : UInt64) : Bool := load64 (binding slot) t == caller && caller != 0
def newAttempt (slot caller t : UInt64) : UInt64 :=
  let p := row slot
  if !owner slot caller t || load64 (p+32) t != 2 then response 1 slot t else
  if load64 (p+56) t >= load64 (p+224) t then response 4 slot t else
    let t := copy p working 512 t
    let t := store64 (working+56) (load64 (p+56) t+1) t
    let r := persist slot t
    if r == error then response 6 slot r else response 0 slot r
def reserve (slot caller bytes checkpoint quanta t : UInt64) : UInt64 :=
  let p := row slot
  if !owner slot caller t then response 1 slot t else
  if load64 (p+32) t != 2 then response 6 slot t else
  if (bytes == 0 && quanta == 0 && checkpoint == 0) || bytes > load64 (p+216) t-load64 (p+40) t ||
    quanta > load64 (p+232) t-load64 (p+400) t ||
    (checkpoint != 0 && (checkpoint < load64 (p+48) t || checkpoint > load64 (p+216) t)) then response 4 slot t else
    if bytes == 0 && quanta == 0 && checkpoint == load64 (p+48) t then response 0 slot t else
    let t := copy p working 512 t
    let t := store64 (working+40) (load64 (p+40) t+bytes) t
    let t := store64 (working+400) (load64 (p+400) t+quanta) t
    let t := if checkpoint == 0 then t else store64 (working+48) checkpoint t
    let r := persist slot t
    if r == error then response 6 slot r else response 0 slot r
def control (slot state t : UInt64) : UInt64 :=
  let p := row slot
  if terminal (load64 (p+32) t) && !(load64 (p+32) t == 7 && state == 1 && load64 (p+56) t < load64 (p+224) t) then
    response (if load64 (p+32) t == state then 0 else 6) slot t else
    let t := copy p working 512 t
    let t := store64 (working+32) state t
    let t := if state == 1 then store64 (working+392) 0 t else t
    let r := persist slot t
    if r == error then response 6 slot r else
      response 0 slot (zero (binding slot) 2 r)
def complete (slot caller bytes length t : UInt64) : UInt64 :=
  let p := row slot
  if !owner slot caller t || length != 96 || zeroBytes (command+64) 32 t then response 1 slot t else
  if load64 (p+32) t == 4 then response (if bytes == load64 (p+384) t && equal (command+64) (p+352) 32 t then 0 else 2) slot t else
  if load64 (p+32) t != 2 || bytes > load64 (p+216) t ||
    (!zeroBytes (p+288) 32 t && !equal (p+288) (command+64) 32 t) then response 2 slot t else
    let t := copy p working 512 t
    let t := store64 (working+32) 4 t
    let t := store64 (working+384) bytes t
    let t := copy (command+64) (working+352) 32 t
    let r := persist slot t
    if r == error then response 6 slot r else response 0 slot r
def configureKey (role length t : UInt64) : UInt64 :=
  if role == 0 || role > 4 || length != 320 || (load8 (command+64) t &&& 128) == 0 ||
    (load8 (command+319) t &&& 1) == 0 then response 2 16 t else
  let p := key role
  -- A retained role's key cannot be silently substituted. Key rotation needs
  -- a separate future migration that preserves verification of old receipts.
  if load64 p t != 0 then response (if equal (command+64) (p+32) 256 t then 0 else 2) 16 t else
    let t := zero working 64 t
    let t := store64 working keyMagic t
    let t := store64 (working+8) 1 t
    let t := store64 (working+16) role t
    let t := store64 (working+24) 1 t
    let t := copy (command+64) (working+32) 256 t
    let t := Guest.ServiceHash.sha256At scratch working 288 hashed t
    let t := copy hashed (working+288) 32 t
    let r := disk 66 (57+(role-1)*2) working t
    let r := if r == error then error else syscall 67 2 0 0 0 r
    if r != 0 then response 6 16 r else response 0 16 (copy working p 512 r)
def prepareReceipt (slot t : UInt64) : UInt64 :=
  let p := row slot
  let t := zero receipt 32 t
  let t := store64 receipt receiptMagic t
  let t := store64 (receipt+8) 1 t
  let t := store64 (receipt+16) (load64 (p+32) t) t
  let t := store64 (receipt+24) (load64 (p+192) t) t
  let t := store64 (receipt+32) (load64 (p+24) t) t
  let t := store64 (receipt+40) (load64 (p+40) t) t
  let t := store64 (receipt+48) (load64 (p+48) t) t
  let t := store64 (receipt+56) (load64 (p+56) t) t
  let t := copy (p+64) (receipt+64) 96 t
  let t := copy (p+320) (receipt+160) 32 t
  let t := copy (p+352) (receipt+192) 32 t
  let t := store64 (receipt+224) (load64 (p+384) t) t
  let t := store64 (receipt+232) (load64 (p+400) t) t
  let t := store64 (receipt+240) (load64 (p+200) t) t
  -- Bit0 provider assertion. No client-acceptance, independent verification,
  -- settlement, remote-attestation or zero-knowledge flag is asserted.
  store64 (receipt+248) ((1 : UInt64) ||| (load64 (p+392) t <<< 32)) t
def attachReceipt (slot length t : UInt64) : UInt64 :=
  let capacity := syscall 64 2 0 0 0 t
  if length != 576 || capacity == error || capacity < receiptCapacity then response 6 slot capacity else
  let t := prepareReceipt slot capacity
  if !equal (command+64) receipt 256 t then response 2 slot t else
    let t := copy (command+64) receipt 512 t
    let r := disk 66 (receiptSector+slot*2+load64 (row slot+24) t%2) receipt t
    let r := if r == error then error else syscall 67 2 0 0 0 r
    if r != 0 then response 6 slot r else response 0 slot r
def receiptMatches (p slot t : UInt64) : Bool :=
  load64 p t == receiptMagic && load64 (p+8) t == 1 && load64 (p+24) t == load64 (row slot+192) t &&
  load64 (p+32) t >= load64 (row slot+424) t && load64 (p+32) t <= load64 (row slot+24) t &&
  equal (p+64) (row slot+64) 96 t && equal (p+160) (row slot+320) 32 t
def readReceipt (slot t : UInt64) : UInt64 :=
  let role := load64 (row slot+192) t
  let capacity := syscall 64 2 0 0 0 t
  if load64 (key role) t == 0 || capacity == error || capacity < receiptCapacity then response 6 slot capacity else
  let a := disk 65 (receiptSector+slot*2) receipt capacity
  if a == error then response 6 slot a else
  let b := disk 65 (receiptSector+1+slot*2) candidate a
  if b == error then response 6 slot b else
  let av := receiptMatches receipt slot b
  let bv := receiptMatches candidate slot b
  if !av && !bv then response 3 slot b else
    let p := if av && (!bv || load64 (receipt+32) b >= load64 (candidate+32) b) then receipt else candidate
    let t := response 0 slot b
    let t := copy p (wire+64) 512 t
    832+copy (key role+32) (wire+576) 256 t
def dispatch (caller rights length t : UInt64) : UInt64 :=
  let op := load64 command t
  let identity := load64 (command+8) t
  let slot := index identity
  let admin := (rights &&& 0x100000000) != 0
  if length < 64 || load64 (command+56) t != 1 then response 2 16 t else
  if op != 281 && op != 290 && op != 293 && op != 295 && length != 64 then response 2 16 t else
  if op == 280 && admin then mount t else
  if load64 st t != 1 then response 3 16 t else
  if op == 293 && admin then configureKey identity length t else
  if op == 281 && admin then submit identity length t else
  -- Inventory is explicitly index-addressed and read-only. Every ordinary
  -- operation, including administrative mutation, requires a current handle.
  if op == 296 && admin && identity < 16 then
    if load64 (row slot) t != magic || load64 (row slot+32) t == 0 then response 3 slot t else
      let t := response 0 slot t
      576+copy (row slot) (wire+64) 512 t
  else
  if slot >= 16 || load64 (row slot) t != magic then response 3 16 t else
  if !current identity slot t then response 9 16 t else
  if load64 (row slot+32) t == 0 then response 8 slot t else
  let worker := caller == syscall 97 5 0 0 0 t
  let readable := admin || owner slot caller t || worker
  if op == 299 && admin then
    -- Terminal tombstones preserve the last exact terms until this physical
    -- row is explicitly reused. Old handles then fail before owner checking.
    if !terminal (load64 (row slot+32) t) then response 6 slot t else
      let t := copy (row slot) working 512 t
      let t := store64 (working+32) 0 t
      let r := persist slot t
      if r == error then response 6 slot r else response 0 slot (zero (binding slot) 2 r)
  else
  if op == 294 && readable then
    let t := prepareReceipt slot t
    let t := response 0 slot t
    320+copy receipt (wire+64) 256 t
  else if op == 295 && worker then attachReceipt slot length t else
  if op == 297 && readable then
    let p := key (load64 (row slot+192) t)
    if load64 p t == 0 then response 6 slot t else
      let t := response 0 slot t
      320+copy (p+32) (wire+64) 256 t
  else if op == 298 && readable then readReceipt slot t else
  if op == 282 && admin then bind slot (load64 (command+16) t) t else
  if op == 283 then reserve slot caller (load64 (command+16) t) (load64 (command+24) t) (load64 (command+32) t) t else
  if op == 284 then newAttempt slot caller t else
  if (op == 285 || op == 292) && (admin || owner slot caller t || (op == 292 && worker)) then
    let t := response 0 slot t
    576+copy (row slot) (wire+64) 512 t
  else if op == 286 && admin then control slot 3 t else
  if op == 288 && admin then control slot 5 t else
  if op == 289 && admin then control slot 1 t else
  if op == 290 then complete slot caller (load64 (command+16) t) length t else
  if op == 291 && owner slot caller t then
    if terminal (load64 (row slot+32) t) then
      response (if load64 (row slot+32) t == 7 && load64 (row slot+392) t == load64 (command+16) t then 0 else 2) slot t
    else
    let t := copy (row slot) working 512 t
    let t := store64 (working+32) 7 t
    let t := store64 (working+392) (load64 (command+16) t) t
    let r := persist slot t
    if r == error then response 6 slot r else response 0 slot r
  else response 1 slot t
def clear (t : UInt64) : UInt64 := zero st 6144 t
end Guest.ServiceJobs
