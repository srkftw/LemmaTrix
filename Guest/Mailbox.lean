import Guest.MailboxSDK
import Guest.ServerSDK
import Guest.ServiceHash
import Guest.ProjectGraph
import Guest.WaitSDK
import Guest.MailboxReceipt
namespace Guest.Mailbox
open Guest.LiveSDK
-- A right2048 installed service owns opaque ciphertext and public capability
-- hashes. All durable access is through one explicitly granted ServerStore
-- namespace; this service has no raw block, personal vault or session keys.
def st : UInt64 := 0x650000
def active : UInt64 := 0x680000
def candidate : UInt64 := 0x6b0000
def staged : UInt64 := 0x6e0000
def scratch : UInt64 := 0x6e4000
def hashed : UInt64 := 0x6e5000
def serialized : UInt64 := 0x700000
def magic : UInt64 := 0x3158424d544c
def receiptBody : UInt64 := 0x730000
def bytes : UInt64 := 141312
def serializedLimit : UInt64 := 139776
def recipient (base i : UInt64) : UInt64 := base+512+i*256
def row (base i : UInt64) : UInt64 := base+4096+i*8448
def prekey (base i : UInt64) : UInt64 := base+139264+i*256
def eq (a b n t : UInt64) : Bool := Guest.ProjectGraph.equal a b n t
def zeros (a n t : UInt64) : Bool := Guest.ProjectGraph.allZero a n t
def hash (p n t : UInt64) : UInt64 := Guest.ServiceHash.sha256At scratch p n hashed t
def response (code h a b c t : UInt64) : UInt64 := 64+header code h a b c 0 0 t
def pending (t : UInt64) : Bool := load64 (st+16) t != 0
def initialized (t : UInt64) : Bool := load64 st t != 0
def allowance (count used limit attempts maximum : UInt64) : Bool :=
  used <= limit && count <= limit-used && attempts < maximum
theorem exhausted_attempts_deny (count used limit attempts : UInt64) :
    allowance count used limit attempts attempts = false := by simp [allowance]
theorem zero_attempts_deny (count used limit : UInt64) :
    allowance count used limit 0 0 = false := by simp [allowance]
def handle (p t : UInt64) : UInt64 := load64 (p+8) t
def makeReceipt (p destination t : UInt64) : UInt64 :=
  let t := zero destination 24 t
  let t := store64 destination Guest.ReceiptSDK.magic t
  let t := store64 (destination+8) 1 (store64 (destination+16) 1 t)
  let t := store64 (destination+24) (load64 (p+232) t) t
  let t := copy (p+64) (destination+32) 64 t
  let t := copy (active+416) (destination+96) 64 t
  let t := store64 (destination+160) (load64 (p+128) t) t
  store64 (destination+176) 1 (store64 (destination+168) (load64 (p+216) t) t)
def signedAcceptanceReady (profile receipt : UInt64) : Bool := profile == 1 && receipt == 2
theorem unsigned_configured_row_not_accepted : signedAcceptanceReady 1 1 = false := by decide
theorem rotating_profile_not_accepted (receipt : UInt64) : signedAcceptanceReady 2 receipt = false := by
  simp [signedAcceptanceReady]
def acceptance (p h a b c t : UInt64) : UInt64 :=
  if load64 (active+48) t == 0 then response 0 h a b c t else
  if !signedAcceptanceReady (load64 (active+48) t) (load64 (p+224) t) then response 6 h a b c t else
  let t := response 0 h a b c t
  let t := makeReceipt p (wire+64) t
  320+copy (p+152) (wire+256) 64 t
partial def receiptRow (i t : UInt64) : UInt64 :=
  if i == 16 then error else
  let p := row active i
  if load64 p t == 1 && load64 (p+224) t == 1 then p else receiptRow (i+1) t
partial def receiptsRemain (i t : UInt64) : Bool :=
  if i == 16 then false else load64 (row active i+224) t != 0 || receiptsRemain (i+1) t
partial def liveRows (i t : UInt64) : Bool :=
  if i == 16 then false else load64 (row active i) t == 1 || liveRows (i+1) t
partial def clearReceiptRows (i t : UInt64) : UInt64 :=
  if i == 16 then t else clearReceiptRows (i+1) (zero (row candidate i+152) 13 t)
partial def findRecipient (base id i t : UInt64) : UInt64 :=
  if i == 8 then error else
  let p := recipient base i
  if load64 p t == 1 && eq id (p+32) 32 t then p else findRecipient base id (i+1) t
partial def freeRecipient (i t : UInt64) : UInt64 :=
  if i == 8 then error else if load64 (recipient active i) t == 0 then i else freeRecipient (i+1) t
partial def findRequest (request id i t : UInt64) : UInt64 :=
  if i == 16 then error else
  let p := row active i
  if load64 p t != 0 && eq request (p+64) 32 t && eq id (p+32) 32 t then p
  else findRequest request id (i+1) t
partial def findHandle (h i t : UInt64) : UInt64 :=
  if i == 16 then error else
  let p := row active i
  if load64 p t != 0 && handle p t == h then p else findHandle h (i+1) t
partial def vacant (i chosen t : UInt64) : UInt64 :=
  if i == 16 then chosen else
  let p := row active i
  if load64 p t == 0 then i else
  vacant (i+1) (if load64 p t == 2 && (chosen == error || handle p t < handle (row active chosen) t) then i else chosen) t
def authorize (id token fetch t : UInt64) : UInt64 :=
  let p := findRecipient active id 0 t
  if p == error then error else
  let t := hash token 32 t
  if eq hashed (p+(if fetch == 1 then 96 else 64)) 32 t then p else error
def current (token t : UInt64) : Bool := syscall 131 token 0 0 0 t == 0
partial def packRows (i cursor t : UInt64) : UInt64 :=
  if i == 16 then
    let count := (cursor+511)/512*512
    store64 (st+240) count (store64 (serialized+24) count t)
  else
    let p := row candidate i
    let q := serialized+4608+i*256
    let t := copy p q 256 t
    if load64 p t == 1 then
      let n := load64 (p+128) t
      let t := store64 (q+144) cursor t
      packRows (i+1) (cursor+n) (copy (p+256) (serialized+cursor) n t)
    else packRows (i+1) cursor (store64 (q+144) 0 t)
def pack (t : UInt64) : UInt64 :=
  let t := zero serialized (serializedLimit/8) t
  let t := copy candidate serialized 2560 t
  let t := copy (prekey candidate 0) (serialized+2560) 2048 t
  packRows 0 8704 (store64 (serialized+8) 2 t)
partial def unpackRows (i cursor total t : UInt64) : UInt64 :=
  if i == 16 then
    if (cursor+511)/512*512 != total || !zeros (serialized+cursor) (total-cursor) t then error else t
  else
    let p := serialized+4608+i*256
    let q := row active i
    let state := load64 p t
    let n := load64 (p+128) t
    if state > 2 || (state == 0 && !zeros p 256 t) then error else
    let t := copy p q 256 t
    let t := store64 (q+144) 0 t
    if state != 1 then unpackRows (i+1) cursor total t else
    if cursor > total || n == 0 || n > 8192 || load64 (p+144) t != cursor || n > total-cursor then error else
    unpackRows (i+1) (cursor+n) total (copy (serialized+cursor) (q+256) n t)
def unpack (total t : UInt64) : UInt64 :=
  if load64 serialized t != magic then error else
  if load64 (serialized+8) t == 1 && total == bytes then copy serialized active bytes t else
  if load64 (serialized+8) t != 2 || total < 8704 || total > serializedLimit || total%512 != 0 ||
    load64 (serialized+24) t != total then error else
  let t := zero active (bytes/8) t
  let t := copy serialized active 2560 t
  let t := copy (serialized+2560) (prekey active 0) 2048 t
  let t := store64 (active+8) 1 (store64 (active+24) bytes t)
  unpackRows 0 8704 total t
-- ServerStore hashes its complete namespace and publishes an inactive-bank
-- root only after flushing ciphertext/index data. A response0 below is emitted
-- only after that native commit has returned success.
def preparePublication (resultHandle t : UInt64) : UInt64 :=
  let generation := load64 (active+16) t+1
  if generation == 0 then error else
  let t := store64 (candidate+16) generation t
  let t := pack t
  let count := load64 (st+240) t
  let t := hash serialized count t
  let r := Guest.ServerSDK.begin (load64 st t) count hashed t
  if r != 64 || status r != 0 then error else
  let t := store64 (st+16) 1 r
  let t := store64 (st+24) 0 t
  let t := store64 (st+32) resultHandle t
  store64 (st+40) 6 t
def failPublication (t : UInt64) : UInt64 :=
  let t := Guest.ServerSDK.cancel (load64 st t) t
  store64 (st+16) 0 (store64 (st+40) 5 t)
def pump (t : UInt64) : UInt64 :=
  if !pending t then t else
  let offset := load64 (st+24) t
  if offset < load64 (st+240) t then
    let r := Guest.ServerSDK.append (load64 st t) offset (serialized+offset) 512 t
    if r != 64 || status r != 0 then failPublication r else store64 (st+24) (offset+512) r
  else
    let r := Guest.ServerSDK.commit (load64 st t) t
    if r != 64 || status r != 0 then failPublication r else
    let t := copy candidate active bytes r
    let t := store64 (st+16) 0 t
    let t := store64 (st+40) 0 t
    -- A completed staging handle stays available to its exact local caller for
    -- poll; restart re-creates authority through a fresh request/token check.
    let t := store64 (st+96) (load64 (st+48) t) t
    let t := store64 (st+104) (load64 (st+56) t) t
    let t := store64 (st+48) 0 (store64 (st+56) 0 t)
    zero staged 1024 t
def receiptQuantum (t : UInt64) : UInt64 :=
  let t := Guest.MailboxReceipt.pump t
  if pending t || load64 (st+48) t != 0 || load64 (active+48) t != 1 then t else
  if Guest.MailboxReceipt.completed t then
    let p := receiptRow 0 t
    if p == error || handle p t != load64 (st+256) t then store64 (st+40) 5 t else
    let t := copy active candidate bytes t
    let q := candidate+(p-active)
    let t := Guest.MailboxReceipt.take (q+152) t
    let t := store64 (q+224) 2 (store64 (q+240) (Guest.MailboxReceipt.generation t) t)
    let r := preparePublication (handle q t) t
    if r == error then store64 (st+40) 5 r else r
  else if Guest.MailboxReceipt.pending t || Guest.MailboxReceipt.failed t || !Guest.MailboxReceipt.configured t then t else
  let p := receiptRow 0 t
  if p == error then t else
  if load64 (p+232) t != self t then
    -- An unsigned recovered admission was never externally accepted. Bind its
    -- fresh receipt to this incarnation before asking current finite authority.
    let t := copy active candidate bytes t
    let q := candidate+(p-active)
    let t := store64 (q+232) (self t) (store64 (q+216) (load64 (active+16) t+1) t)
    let r := preparePublication (handle q t) t
    if r == error then store64 (st+40) 5 r else r
  else
    let t := makeReceipt p receiptBody t
    let r := Guest.MailboxReceipt.begin receiptBody t
    if r == error then store64 (st+40) 5 r else store64 (st+256) (handle p t) r
partial def validRecipients (i t : UInt64) : Bool :=
  if i == 8 then true else
  let p := recipient active i
  load64 p t <= 2 && (load64 p t == 0 ||
    (!zeros (p+32) 32 t && !zeros (p+64) 32 t && !zeros (p+96) 32 t &&
    load64 (p+128) t > 0 && load64 (p+128) t <= 8388608 &&
    load64 (p+136) t <= load64 (p+128) t &&
    load64 (p+144) t > 0 && load64 (p+144) t <= 65536 &&
    load64 (p+152) t <= load64 (p+144) t)) && validRecipients (i+1) t
partial def validRows (i t : UInt64) : Bool :=
  if i == 16 then true else
  let p := row active i
  if load64 p t > 2 then false else
  if load64 p t == 0 then validRows (i+1) t else
  if handle p t == 0 || handle p t > load64 (active+32) t ||
    load64 (p+128) t == 0 || load64 (p+128) t > 8192 || zeros (p+64) 32 t then false else
  if load64 (active+48) t == 1 && load64 p t == 1 &&
    ((load64 (p+224) t != 1 && load64 (p+224) t != 2) || load64 (p+216) t == 0 ||
      load64 (p+216) t > load64 (active+16) t || load64 (p+232) t == 0 ||
      (load64 (p+224) t == 2 && zeros (p+152) 64 t)) then false else
  if load64 p t == 2 then validRows (i+1) t else
  let t := hash (p+256) (load64 (p+128) t) t
  eq hashed (p+96) 32 t && validRows (i+1) t
def validSnapshot (t : UInt64) : Bool :=
  load64 active t == magic && load64 (active+8) t == 1 && load64 (active+16) t > 0 &&
  load64 (active+24) t == bytes && load64 (active+40) t <= 1 && load64 (active+48) t <= 2 && validRecipients 0 t && validRows 0 t
partial def recover (offset t : UInt64) : UInt64 :=
  if offset == load64 (st+240) t then t else
  let r := Guest.ServerSDK.read (load64 st t) offset 512 t
  if r != 576 || status r != 0 then error else recover (offset+512) (copy (wire+64) (serialized+offset) 512 r)
def configure (grant t : UInt64) : UInt64 :=
  if pending t || load64 (st+48) t != 0 then response 4 0 0 0 0 t else
  let r := Guest.ServerSDK.describe grant t
  if r != 576 || status r != 0 then response 1 0 0 0 0 r else
  let present := load64 (wire+64) r != 0
  let total := load64 (wire+96) r
  if present && (total < 8704 || total > bytes || total%512 != 0) then response 5 0 0 0 0 r else
  let t := store64 (st+240) total (store64 st grant r)
  let t := if present then recover 0 t else zero active (bytes/8) t
  let t := if present && t != error then unpack total t else t
  if t == error || (present && !validSnapshot t) then response 5 0 0 0 0 (store64 st 0 t) else
  let t := if present then t else store64 (active+24) bytes (store64 (active+8) 1 (store64 active magic t))
  response 0 0 (load64 (active+16) t) 16 8192 t
def enroll (length t : UInt64) : UInt64 :=
  let limit := load64 (command+16) t
  let attempts := load64 (command+24) t
  if length != 160 || limit == 0 || limit > 8388608 || attempts == 0 || attempts > 65536 ||
    zeros (command+64) 32 t || zeros (command+96) 32 t || zeros (command+128) 32 t then response 2 0 0 0 0 t else
  let old := findRecipient active (command+64) 0 t
  if old != error then
    response (if eq (command+64) (old+32) 96 t && load64 (old+128) t == limit && load64 (old+144) t == attempts then 0 else 12) 0 0 0 0 t
  else
  let slot := freeRecipient 0 t
  if slot == error then response 4 0 0 0 0 t else
  let t := copy active candidate bytes t
  let p := recipient candidate slot
  let t := store64 p 1 t
  let t := copy (command+64) (p+32) 96 t
  let t := store64 (p+128) limit t
  let t := store64 (p+144) attempts t
  let r := preparePublication 0 t
  if r == error then response 5 0 0 0 0 r else response 6 0 0 0 0 r
def begin (caller length t : UInt64) : UInt64 :=
  let count := load64 (command+16) t
  let fresh := load64 (command+24) t
  if length != 192 || count == 0 || count > 8192 || fresh > 1 || zeros (command+128) 32 t then response 2 0 0 0 0 t else
  let rp := authorize (command+64) (command+96) 0 t
  if rp == error then response 1 0 0 0 0 t else
  let existing := findRequest (command+128) (command+64) 0 t
  if existing != error then
    if load64 (existing+128) t != count || !eq (existing+96) (command+160) 32 t then response 12 (handle existing t) count 0 (load64 (active+16) t) t else
    if load64 existing t == 2 && (load64 (active+48) t != 1 || load64 (existing+224) t != 2) then
      response 11 (handle existing t) count 0 (load64 (active+16) t) t else
    acceptance existing (handle existing t) count 0 (load64 (active+16) t) t
  else if load64 (st+48) t == caller && load64 (st+64) t == count &&
    eq (command+64) (st+128) 32 t && eq (command+128) (st+160) 64 t then
    response (if pending t then 6 else 0) (load64 (st+56) t) (load64 (st+72) t) count 0 t
  else if pending t || load64 (st+48) t != 0 || receiptRow 0 t != error then response 6 0 0 0 0 t else
  if load64 (active+40) t != 0 && fresh != 1 then response 11 0 0 0 0 t else
  if !allowance count (load64 (rp+136) t) (load64 (rp+128) t)
      (load64 (rp+152) t) (load64 (rp+144) t) then response 4 0 0 0 0 t else
  if load64 (active+48) t == 2 || (load64 (active+48) t == 1 && !Guest.MailboxReceipt.configured t) then response 9 0 0 0 0 t else
  let slot := vacant 0 error t
  let serial := load64 (active+32) t+1
  if slot == error || serial == 0 then response 4 0 0 0 0 t else
  let t := zero staged 1024 t
  let t := store64 (st+48) caller t
  let t := store64 (st+56) serial t
  let t := store64 (st+64) count t
  let t := store64 (st+72) 0 t
  let t := store64 (st+80) slot t
  let t := store64 (st+88) ((rp-active-512)/256) t
  let t := store64 (st+224) (Guest.WaitSDK.now t+1000) t
  let t := copy (command+64) (st+128) 32 t
  let t := copy (command+128) (st+160) 64 t
  response 0 serial 0 count 0 t
def append (caller length t : UInt64) : UInt64 :=
  let h := load64 (command+16) t
  let offset := load64 (command+24) t
  let count := length-128
  if load64 (st+48) t != caller || load64 (st+56) t != h || pending t ||
    length <= 128 || length > 640 || offset != load64 (st+72) t ||
    !eq (command+64) (st+128) 32 t || authorize (command+64) (command+96) 0 t == error ||
    count > load64 (st+64) t-offset then response 2 h 0 0 0 t else
  response 0 h (offset+count) 0 0 (store64 (st+72) (offset+count) (copy (command+128) (staged+offset) count t))
def commit (caller t : UInt64) : UInt64 :=
  let h := load64 (command+16) t
  if pending t then response 6 h 0 0 0 t else
  if load64 (st+48) t != caller || load64 (st+56) t != h || h == 0 || load64 (st+72) t != load64 (st+64) t ||
    !eq (command+64) (st+128) 32 t || authorize (command+64) (command+96) 0 t == error then response 2 h 0 0 0 t else
  let t := hash staged (load64 (st+64) t) t
  if !eq hashed (st+192) 32 t then response 5 h 0 0 0 t else
  let slot := load64 (st+80) t
  let t := copy active candidate bytes t
  let p := row candidate slot
  let t := if load64 p t != 0 then store64 (candidate+40) 1 t else t
  let t := zero p 1056 t
  let t := store64 p 1 t
  let t := store64 (p+8) h t
  let t := copy (st+128) (p+32) 96 t
  let count := load64 (st+64) t
  let t := store64 (p+128) count t
  let t := copy staged (p+256) count t
  let t := if load64 (active+48) t == 1 then
    store64 (p+224) 1 (store64 (p+232) (self t) (store64 (p+216) (load64 (active+16) t+1) t)) else t
  let t := store64 (candidate+32) h t
  let rp := recipient candidate (load64 (st+88) t)
  let t := store64 (rp+136) (load64 (rp+136) t+count) t
  let t := store64 (rp+152) (load64 (rp+152) t+1) t
  let r := preparePublication h t
  if r == error then response 5 h 0 0 0 r else response 6 h 0 0 0 r
partial def oldest (id after i chosen t : UInt64) : UInt64 :=
  if i == 16 then chosen else
  let p := row active i
  oldest id after (i+1) (if handle p t > after && load64 p t == 1 && eq id (p+32) 32 t &&
    (chosen == error || handle p t < handle chosen t) then p else chosen) t
def fetch (length t : UInt64) : UInt64 :=
  let h := load64 (command+16) t
  let offset := load64 (command+24) t
  let count := load64 (command+32) t
  if length != 128 || count == 0 || count > 512 then response 2 0 0 0 0 t else
  if authorize (command+64) (command+96) 1 t == error then response 1 0 0 0 0 t else
  let p := if h == 0 then oldest (command+64) (load64 (command+40) t) 0 error t else findHandle h 0 t
  if p == error then response 6 0 0 0 0 t else
  let total := load64 (p+128) t
  if load64 (active+48) t != 0 && load64 (p+224) t != 2 then response 6 h 0 0 0 t else
  if load64 p t != 1 || !eq (p+32) (command+64) 32 t then response 1 0 0 0 0 t else
  if offset >= total then response 2 h 0 0 0 t else
  let n := if count > total-offset then total-offset else count
  let r := response 0 (handle p t) total offset n t
  64+n+copy (p+256+offset) (wire+64) n r
def acknowledge (caller length t : UInt64) : UInt64 :=
  let h := load64 (command+16) t
  if length != 160 then response 2 h 0 0 0 t else
  if authorize (command+64) (command+96) 1 t == error then response 1 h 0 0 0 t else
  let p := findHandle h 0 t
  if p == error then response 11 h 0 0 0 t else
  if !eq (p+32) (command+64) 32 t || !eq (p+96) (command+128) 32 t then response 1 h 0 0 0 t else
  if load64 p t == 2 then response 0 h 0 0 (load64 (active+16) t) t else
  if pending t || load64 (st+48) t != 0 then response 6 h 0 0 0 t else
  let t := copy active candidate bytes t
  let q := candidate+(p-active)
  let t := store64 q 2 (zero (q+256) 1024 t)
  let t := store64 (st+48) caller (store64 (st+56) h t)
  let r := preparePublication h t
  if r == error then response 5 h 0 0 0 (store64 (st+48) 0 r) else response 6 h 0 0 0 r
def poll (caller t : UInt64) : UInt64 :=
  let h := load64 (command+16) t
  let p := findHandle h 0 t
  let identity := if p == error then st+128 else p+32
  if h != 0 && ((!eq (command+64) identity 32 t) ||
    (authorize (command+64) (command+96) 0 t == error && authorize (command+64) (command+96) 1 t == error) ||
    (p == error && (load64 (st+48) t != caller || load64 (st+56) t != h))) then response 1 h 0 0 0 t else
  if pending t then response 6 h (if p == error then 0 else load64 p t) (load64 (st+24) t) (load64 (active+16) t) t else
  if p != error && load64 p t != 0 && load64 (active+48) t != 0 then
    if Guest.MailboxReceipt.failed t then response (if Guest.MailboxReceipt.reason t == 0 then 5 else Guest.MailboxReceipt.reason t) h 0 0 0 t else
    acceptance p h (load64 p t) 0 (load64 (active+16) t) t
  else response (load64 (st+40) t) h (if p == error then 0 else load64 p t) (load64 (st+24) t) (load64 (active+16) t) t
def bundleResponse (p withOneTime t : UInt64) : UInt64 :=
  let t := response 0 0 256 0 (load64 (active+16) t) t
  let t := copy p (wire+64) 256 t
  let t := if withOneTime == 1 then t else store64 (wire+88) 0 (zero (wire+160) 4 t)
  320+t
def validPrekeyShape (bundle t : UInt64) : Bool :=
  load64 bundle t == 0x31424d544c && load64 (bundle+8) t == 1 &&
    load64 (bundle+16) t != 0 && !zeros (bundle+32) 32 t && !zeros (bundle+64) 32 t &&
    ((load64 (bundle+24) t == 0 && zeros (bundle+96) 32 t) ||
      (load64 (bundle+24) t == 1 && !zeros (bundle+96) 32 t))
-- Recipient-authenticated depletion may remove a single public OPK while all
-- identity, signed-prekey and device bytes remain fixed. It cannot replenish
-- that generation or erase the retained claim ledger.
def oneWayDepletion (old bundle t : UInt64) : Bool :=
  load64 (old+24) t == 1 && load64 (bundle+24) t == 0 &&
    zeros (bundle+96) 32 t && eq old bundle 24 t &&
    eq (old+32) (bundle+32) 64 t && eq (old+128) (bundle+128) 128 t
def prekeyGenerationAllowed (oldGeneration newGeneration : UInt64) (depleted : Bool) : Bool :=
  oldGeneration < newGeneration || depleted
theorem same_generation_requires_depletion (generation : UInt64) :
    prekeyGenerationAllowed generation generation false = false := by
  simp [prekeyGenerationAllowed]
def publishPrekey (length t : UInt64) : UInt64 :=
  if length != 384 then response 2 0 0 0 0 t else
  let p := authorize (command+64) (command+96) 1 t
  if p == error then response 1 0 0 0 0 t else
  let slot := (p-active-512)/256
  let old := prekey active slot
  let bundle := command+128
  if !validPrekeyShape bundle t then response 2 0 0 0 0 t else
  if eq old bundle 256 t then response 0 0 0 0 (load64 (active+16) t) t else
  let depleted := oneWayDepletion old bundle t
  if !prekeyGenerationAllowed (load64 (old+16) t) (load64 (bundle+16) t) depleted then response 12 0 0 0 0 t else
  if pending t || load64 (st+48) t != 0 then response 6 0 0 0 0 t else
  let t := copy active candidate bytes t
  let t := copy bundle (prekey candidate slot) 256 t
  let t := if depleted then t else zero (recipient candidate slot+160) 4 t
  let r := preparePublication 0 t
  if r == error then response 5 0 0 0 0 r else response 6 0 0 0 0 r
def claimPrekey (length t : UInt64) : UInt64 :=
  if length != 160 || zeros (command+128) 32 t then response 2 0 0 0 0 t else
  let p := authorize (command+64) (command+96) 0 t
  if p == error then response 1 0 0 0 0 t else
  let slot := (p-active-512)/256
  let bundle := prekey active slot
  if load64 bundle t == 0 then response 6 0 0 0 0 t else
  if load64 (bundle+24) t == 0 then bundleResponse bundle 0 t else
  if !zeros (p+160) 32 t then bundleResponse bundle (if eq (p+160) (command+128) 32 t then 1 else 0) t else
  if pending t || load64 (st+48) t != 0 then response 6 0 0 0 0 t else
  let t := copy active candidate bytes t
  let t := copy (command+128) (recipient candidate slot+160) 32 t
  let r := preparePublication 0 t
  if r == error then response 5 0 0 0 0 r else response 6 0 0 0 0 r
def admin (length t : UInt64) : UInt64 :=
  let action := load64 (command+8) t
  if action == 0 && length == 64 then configure (load64 (command+16) t) t else
  if !initialized t then response 9 0 0 0 0 t else
  if action == 2 && length == 64 then
    let i := load64 (command+16) t
    if i >= 16 then response 2 0 0 0 0 t else
    let p := row active i
    response 0 (handle p t) (load64 p t) (load64 (p+128) t) (load64 (active+16) t) t
  else if pending t || load64 (st+48) t != 0 then response 6 0 0 0 0 t else
  if action == 4 && length == 480 then
    if load64 (active+48) t != 1 && liveRows 0 t then response 4 0 0 0 0 t else
    let t := Guest.MailboxSDK.receiptTerms (receiptBody+256) t
    let t := hash (receiptBody+256) 64 t
    if !eq hashed (command+416) 32 t then response 12 0 0 0 0 t else
    if receiptsRemain 0 t && !eq (active+64) (command+64) 416 t then response 12 0 0 0 0 t else
    let r := Guest.MailboxReceipt.configure (load64 (command+16) t) (command+64) (command+416) (command+448) t
    if r == error then response 1 0 0 0 0 r else
    if load64 (active+48) r == 1 && eq (active+64) (command+64) 416 r then response 0 0 0 0 0 r else
    let t := copy active candidate bytes r
    let t := copy (command+64) (candidate+64) 416 (store64 (candidate+48) 1 t)
    let r := preparePublication 0 t
    if r == error then response 5 0 0 0 0 r else response 6 0 0 0 0 r
  else if action == 5 && length == 64 then
    if liveRows 0 t || Guest.MailboxReceipt.pending t then response 4 0 0 0 0 t else
    let t := copy active candidate bytes t
    let t := clearReceiptRows 0 (zero (candidate+64) 52 (store64 (candidate+48) 2 t))
    let t := Guest.MailboxReceipt.clear t
    let r := preparePublication 0 t
    if r == error then response 5 0 0 0 0 r else response 6 0 0 0 0 r
  else if action == 1 then enroll length t else
  if action == 3 && length == 96 then
    let p := findRecipient active (command+64) 0 t
    if p == error then response 3 0 0 0 0 t else
    let t := copy active candidate bytes t
    let t := store64 (candidate+(p-active)) 2 t
    let r := preparePublication 0 t
    if r == error then response 5 0 0 0 0 r else response 6 0 0 0 0 r
  else response 2 0 0 0 0 t
def dispatch (caller rights token length t : UInt64) : UInt64 :=
  let op := load64 command t
  let action := load64 (command+8) t
  if length < 64 || length > 1024 || load64 (command+56) t != 1 || !current token t then response 2 0 0 0 0 t else
  if op == 440 then if (rights &&& 0x100000000) != 0 then admin length t else response 1 0 0 0 0 t else
  if op != 441 then response 7 0 0 0 0 t else
  if !initialized t then response 9 0 0 0 0 t else
  if action == 10 && length == 64 then
    if load64 (active+48) t != 1 then response 7 0 0 0 0 t else
    480+copy (active+64) (wire+64) 416 (header 0 0 416 0 0 0 0 t)
  else if action == 1 then begin caller length t else
  if action == 2 then append caller length t else
  if action == 3 && length == 128 then commit caller t else
  if action == 4 && ((load64 (command+16) t == 0 && length == 64) || length == 128) then poll caller t else
  if action == 5 then fetch length t else
  if action == 6 then acknowledge caller length t else
  if action == 8 then publishPrekey length t else
  if action == 9 then claimPrekey length t else
  if action == 7 && length == 128 then
    if pending t then response 6 0 0 0 0 t else
    if load64 (st+48) t != caller || load64 (st+56) t != load64 (command+16) t ||
      !eq (command+64) (st+128) 32 t || authorize (command+64) (command+96) 0 t == error then response 3 0 0 0 0 t else
    response 0 0 0 0 0 (store64 (st+48) 0 (zero staged 1024 t))
  else response 7 0 0 0 0 t
partial def loop (t : UInt64) : UInt64 :=
  let n := syscall 36 (self t) incoming 1024 0 t
  let t := if n >= 96 && n <= 1056 then
    let token := load64 (incoming+8) n
    let size := dispatch (load64 incoming n) (load64 (incoming+16) n) token (n-32) n
    reply token size size
  else n
  let t := receiptQuantum (pump t)
  let now := Guest.WaitSDK.now t
  let t := if load64 (st+48) now != 0 && !pending now && now >= load64 (st+224) now then
    store64 (st+48) 0 (zero staged 1024 now) else now
  let t := zero scratch 80 (zero hashed 4 (zero command 124 (zero wire 128 t)))
  loop (Guest.WaitSDK.deadline (Guest.WaitSDK.now t+(if pending t || Guest.MailboxReceipt.pending t then 1 else 100)) t)
def main (t : UInt64) : UInt64 := loop (Guest.MailboxReceipt.clear (zero st 64 (zero active (bytes/8) (zero candidate (bytes/8) t))))
end Guest.Mailbox
