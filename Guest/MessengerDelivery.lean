import Guest.LiveSDK
import Guest.ServiceHash
import Guest.ProjectGraph
import Guest.WaitSDK
import Guest.MessengerForge
import Guest.ReceiptSDK
import Guest.MailboxSDK
namespace Guest.MessengerDelivery
open Guest.LiveSDK
-- Role4/right1024 is a narrow ciphertext coordinator. The UI has no Network
-- right. Session keys and plaintext remain in the rights-zero role2 owner.
-- Network38..41 is the protected terminal RPC over the actual mode1 circuit.
def st : UInt64 := 0x650000
def remote : UInt64 := 0x651000
def own : UInt64 := 0x652000
def attachment : UInt64 := 0x660000
def batch : UInt64 := 0x661000
def parked : UInt64 := 0x667000
def blob : UInt64 := 0x669000
def receiptProfile : UInt64 := 0x670000
def receiptNode : UInt64 := 0x671000
def receiptCache : UInt64 := 0x672000
def receiptArgs : UInt64 := 0x673000
-- One admitted initial-session preflight and one public prekey publication.
-- No private session key enters this network owner. All state fits1KiB.
def preflight : UInt64 := 0x674000
def publicPrekeys : UInt64 := preflight+160
def claimedPrekeys : UInt64 := preflight+448
def claimIdentity : UInt64 := preflight+736
def claimCaps : UInt64 := preflight+800
-- One frozen public foreground reference. It waits behind already admitted
-- work; it does not let a perpetual background fetch win every idle boundary.
def foreground : UInt64 := 0x675000
def forgePending (t : UInt64) : Bool := load64 foreground t == 1
def requestCallerAllowed (owner caller : UInt64) : Bool := owner != 0 && owner == caller
theorem zero_request_owner_denied (caller : UInt64) : requestCallerAllowed 0 caller = false := by rfl
theorem different_request_caller_denied (owner caller : UInt64) (different : (owner == caller) = false) :
    requestCallerAllowed owner caller = false := by
  unfold requestCallerAllowed
  rw [different]
  exact Bool.and_false _
-- This is a scheduling hint, not an admitted operation or saved authority.
-- Only another current, kernel-checked460 can start its owner request.
def attachmentHint : UInt64 := st+336
def attachmentWaiting (t : UInt64) : Bool := load64 attachmentHint t == 1
def clearAttachmentHint (t : UInt64) : UInt64 := zero attachmentHint 7 t
def attachmentHintMatches (caller h index contact fresh t : UInt64) : Bool :=
  requestCallerAllowed (load64 (attachmentHint+8) t) caller &&
  load64 (attachmentHint+16) t == h && load64 (attachmentHint+24) t == index &&
  load64 (attachmentHint+32) t == contact && load64 (attachmentHint+40) t == fresh
def deferAttachment (caller h index contact fresh t : UInt64) : UInt64 :=
  if attachmentWaiting t then t else
  let t := clearAttachmentHint t
  store64 attachmentHint 1 (store64 (attachmentHint+8) caller (store64 (attachmentHint+16) h
    (store64 (attachmentHint+24) index (store64 (attachmentHint+32) contact (store64 (attachmentHint+40) fresh t)))))
def attachmentHintQuantum (t : UInt64) : UInt64 :=
  if !attachmentWaiting t then t else
  let used := load64 (attachmentHint+48) t
  if used >= 8191 then store64 attachmentHint 2 (store64 (attachmentHint+48) 8192 t) else
  store64 (attachmentHint+48) (used+1) t
def attachmentReceiveAllowed (mode phase selected : UInt64) : Bool :=
  mode != 1 || phase != 0 || selected != 0
theorem attachment_wait_blocks_background : attachmentReceiveAllowed 1 0 0 = false := by decide
theorem attachment_expired_allows_background : attachmentReceiveAllowed 2 0 0 = true := by decide
theorem attachment_partial_receive_drains (mode selected : UInt64) :
    attachmentReceiveAllowed mode 1 selected = true := by simp [attachmentReceiveAllowed]
theorem attachment_ack_receive_drains (mode selected : UInt64) :
    attachmentReceiveAllowed mode 3 selected = true := by simp [attachmentReceiveAllowed]
theorem attachment_ack_poll_drains (mode selected : UInt64) :
    attachmentReceiveAllowed mode 4 selected = true := by simp [attachmentReceiveAllowed]
def preflightFailure (reason t : UInt64) : UInt64 := store64 preflight 9 (store64 (preflight+32) reason t)
def publicationFailure (reason t : UInt64) : UInt64 := store64 (preflight+128) 6 (store64 (preflight+136) reason t)
def blobMagic : UInt64 := 0x31424c424d544c
def ciphertext : UInt64 := 0x663000
def received : UInt64 := 0x665000
def requestId : UInt64 := 0x656000
def commitment : UInt64 := 0x656100
def combined : UInt64 := 0x656200
def receiveCommitment : UInt64 := 0x656300
def request : UInt64 := 0x657000
def answer : UInt64 := 0x658000
def scratch : UInt64 := 0x659000
def hashed : UInt64 := 0x65a000
def eq (a b n t : UInt64) : Bool := Guest.ProjectGraph.equal a b n t
def hash (p n out t : UInt64) : UInt64 := Guest.ServiceHash.sha256At scratch p n out t
def acknowledgeAllowed (code : UInt64) : Bool := code == 0 || code == 10
theorem failed_commit_never_acknowledges : acknowledgeAllowed 13 = false := by decide
theorem failed_auth_never_acknowledges : acknowledgeAllowed 9 = false := by decide
def response (code h state reason t : UInt64) : UInt64 :=
  64+header code h state reason (load64 (st+192) t) (load64 (st+160) t) 0 t
def failSend (reason t : UInt64) : UInt64 :=
  let t := clearAttachmentHint t
  let t := if load64 attachment t == 3 then store64 attachment 7 (store64 (attachment+64) reason t) else t
  store64 (st+24) 7 (store64 (st+112) reason t)
def failReceive (reason t : UInt64) : UInt64 := store64 (st+160) 7 (store64 (st+200) reason (clearAttachmentHint t))
def ownerSubmit (op h a source bytes purpose t : UInt64) : UInt64 :=
  if load64 (st+8) t != 0 then error else
  let target := syscall 128 2 op 0 0 t
  if target == error || target != load64 st target then error else
  let t := header op h a 0 0 0 0 target
  let t := if bytes == 0 then t else copy source (wire+64) bytes t
  let token := syscall 133 target wire (64+bytes) 1024 t
  if token == error then error else store64 (st+8) token (store64 (st+16) purpose token)
def ownerIndex (h index purpose t : UInt64) : UInt64 :=
  if load64 (st+8) t != 0 then error else
  let target := syscall 128 2 434 0 0 t
  if target == error || target != load64 st target then error else
  let t := header 434 h 18 index 0 0 0 target
  let token := syscall 133 target wire 64 1024 t
  if token == error then error else store64 (st+8) token (store64 (st+16) purpose token)
partial def blobValid (p bytes i offset t : UInt64) : Bool :=
  if i == load64 (p+56) t then offset == bytes else
  let n := load64 (p+offset+8) t
  offset+16 <= bytes && n > 16 && n <= 528 && n <= bytes-offset-16 &&
    load64 (p+offset) t == load64 (p+48) t+i && blobValid p bytes (i+1) (offset+16+n) t
partial def parkFind (h i t : UInt64) : UInt64 :=
  if i == 16 then 0 else if load64 (parked+i*128) t == h then parked+i*128 else parkFind h (i+1) t
partial def parkFree (i t : UInt64) : UInt64 :=
  if i == 16 then 0 else if load64 (parked+i*128) t == 0 then parked+i*128 else parkFree (i+1) t
partial def parkSelect (id index i t : UInt64) : UInt64 :=
  if i == 16 then 0 else
  let p := parked+i*128
  if load64 p t != 0 && eq id (p+8) 32 t && index >= load64 (p+80) t && index-load64 (p+80) t < load64 (p+88) t then p else parkSelect id index (i+1) t
partial def parkAck (i t : UInt64) : UInt64 :=
  if i == 16 then 0 else if load64 (parked+i*128+96) t == 1 then parked+i*128 else parkAck (i+1) t
partial def blobOffset (p index i offset t : UInt64) : UInt64 :=
  if i == load64 (p+56) t then 0 else if load64 (p+offset) t == index then offset else
  blobOffset p index (i+1) (offset+16+load64 (p+offset+8) t) t
partial def markAck (id i t : UInt64) : UInt64 :=
  if i == 16 then t else
  let p := parked+i*128
  markAck id (i+1) (if load64 p t != 0 && eq id (p+8) 32 t then store64 (p+96) 1 t else t)
def releaseParked (p t : UInt64) : UInt64 :=
  if p == 0 then t else
  let t := if load64 (st+296) t == p then store64 (st+296) 0 (zero blob 1024 t) else t
  let t := if load64 (st+280) t == p then store64 (st+280) 0 t else t
  zero p 16 t
def residentMatches (p id t : UInt64) : Bool :=
  load64 (st+296) t == p && eq (blob+16) id 32 t &&
    load64 (blob+48) t == load64 (p+80) t && load64 (blob+56) t == load64 (p+88) t
def fetchRetryAllowed (reason purpose attempts : UInt64) : Bool :=
  reason == 14 && purpose == 10 && attempts < 3
theorem failed_auth_cannot_retry_fetch (purpose attempts : UInt64) :
    fetchRetryAllowed 1 purpose attempts = false := by rfl
theorem failed_integrity_cannot_retry_fetch (purpose attempts : UInt64) :
    fetchRetryAllowed 9 purpose attempts = false := by rfl
theorem failed_ack_cannot_retry_fetch (attempts : UInt64) :
    fetchRetryAllowed 14 11 attempts = false := by rfl
def fetchAttachment (h index id explicit t : UInt64) : UInt64 :=
  if explicit > 1 then response 2 h 0 0 t else
  let failed := load64 (st+160) t == 7
  let p := parkSelect id index 0 t
  if p == 0 then response (if failed then 14 else 6) h 0 (if failed then load64 (st+200) t else 0) t else
  if failed && explicit == 0 then response 14 h 0 (load64 (st+200) t) t else
  if failed && (!fetchRetryAllowed (load64 (st+200) t) (load64 (st+96) t) (load64 (p+112) t) ||
      load64 (st+8) t != 0 || load64 (st+88) t != 0 || load64 (st+152) t != 1) then
    response 14 h 0 (load64 (st+200) t) t else
  -- Only a fresh, explicit GUI retry re-admits this already selected blob.
  -- It cannot replay an acknowledgment or override an authorization failure.
  let t := if !failed then t else
    store64 (p+112) (load64 (p+112) t+1) (store64 (st+160) 0 (store64 (st+200) 0
      (store64 (st+136) 0 (store64 (st+248) 0 (store64 (st+216) 0 (store64 (st+280) p t))))))
  if !residentMatches p id t then
    let t := if load64 (st+296) t == p then store64 (st+296) 0 (zero blob 1024 t) else t
    response 6 h 0 0 (store64 (st+280) p t) else
  let off := blobOffset blob index 0 64 t
  if off == 0 then response 9 h 0 0 t else
  let n := load64 (blob+off+8) t
  let t := header 0 h n index 0 0 0 t
  64+n+copy (blob+off+16) (wire+64) n t
def network (op h t : UInt64) : UInt64 :=
  syscall 30 6 wire 64 1024 (store64 (wire+56) 2 (header op h 0 0 0 0 0 t))
def ready (descriptor t : UInt64) : Bool :=
  let r := network 41 0 t
  r == 96 && status r == 0 && load64 (wire+16) r == 3 && eq descriptor (wire+64) 32 r
def makeRequest (action a b c t : UInt64) : UInt64 :=
  copy wire request 64 (header 441 action a b c 0 0 t)
-- The parent terminal bounds whole requests to100000 ticks. Leave10000
-- ticks for exact owned cleanup; a ready response wins the deadline boundary.
def rpcWaitBudget : UInt64 := 90000
def rpcDeadline (clock : UInt64) : UInt64 :=
  if clock > 0xffffffffffffffff-rpcWaitBudget then 0xffffffffffffffff else clock+rpcWaitBudget
def rpc (length purpose t : UInt64) : UInt64 :=
  if load64 (st+88) t != 0 || length < 64 || length > 960 || load64 (st+216) t >= 512 then error else
  let serial := load64 (st+80) t+1
  if serial == 0 then error else
  let t := store64 (st+80) serial t
  let t := store64 (wire+56) 2 (header 39 serial 0 0 0 0 0 t)
  let t := copy request (wire+64) length t
  let r := syscall 30 6 wire (64+length) 1024 t
  if r != 64 || status r != 0 then error else
  let t := store64 (st+88) serial r
  let t := store64 (st+96) purpose t
  let t := store64 (st+232) (rpcDeadline (Guest.WaitSDK.now t)) t
  store64 (st+216) (load64 (st+216) t+1) t
def mailboxAuth (p fetch dst t : UInt64) : UInt64 :=
  let t := copy p dst 32 t
  copy (p+(if fetch == 1 then 64 else 32)) (dst+32) 32 t
def configure (token length t : UInt64) : UInt64 :=
  let owner := load64 (command+8) t
  let selected := syscall 128 2 434 0 0 t
  if owner == 0 || owner != selected || syscall 131 token 0 0 0 selected != 0 then response 1 0 0 0 selected else
  if length == 64 && owner == load64 st selected && load64 (st+152) selected == 1 then response 0 0 0 0 (clearAttachmentHint selected) else
  if length != 64 || load64 (st+8) selected != 0 || load64 (st+88) selected != 0 then response 4 0 0 0 selected else
  let t := zero foreground 20 (zero st 64 (zero preflight 128 selected))
  let t := store64 (preflight+128) 1 (store64 st owner t)
  let r := ownerSubmit 434 0 11 0 0 11 t
  if r == error then response 1 0 0 0 r else response 0 0 0 0 r
def queuePreflight (caller length t : UInt64) : UInt64 :=
  let h := load64 (command+8) t
  let contact := load64 (command+32) t
  if length != 64 || h == 0 || contact == 0 || contact > 4 || load64 (command+24) t != 1 || load64 st t == 0 then response 2 h 0 0 t else
  if load64 preflight t != 0 && load64 (preflight+8) t == caller && load64 (preflight+16) t == h && load64 (preflight+24) t == contact then
    if load64 preflight t == 8 then response 0 h 6 0 t else
    if load64 preflight t != 9 then response 0 h 1 0 t else
    -- A new explicit user retry admits another finite claim attempt budget.
    -- The owner's exact claim identity remains unchanged across uncertainty.
    response 0 h 1 0 (store64 preflight 1 (store64 (preflight+40) 0 (store64 (preflight+32) 0 t)))
  else
  if (load64 preflight t > 0 && load64 preflight t < 8) ||
    (load64 (st+24) t > 0 && load64 (st+24) t <= 6) || load64 (st+24) t == 9 || load64 (st+24) t == 10 then response 6 h 1 0 t else
  let t := zero preflight 16 (zero claimedPrekeys 64 t)
  let t := store64 (preflight+8) caller (store64 (preflight+16) h (store64 (preflight+24) contact t))
  response 0 h 1 0 (store64 (st+216) 0 (store64 preflight 1 t))
def acceptClaimedPrekeys (t : UInt64) : UInt64 :=
  let target := syscall 128 2 434 0 0 t
  if target == error || target != load64 st target || load64 (st+8) target != 0 then error else
  let t := header 434 (load64 (preflight+24) target) 24 (load64 (preflight+16) target) 0 0 0 target
  let t := copy claimedPrekeys (wire+64) 256 t
  let token := syscall 133 target wire 320 1024 t
  if token == error then error else store64 (st+8) token (store64 (st+16) 24 token)
def queue (caller length t : UInt64) : UInt64 :=
  let h := load64 (command+8) t
  let n := load64 (command+16) t
  let contact := load64 (command+32) t
  if load64 st t == 0 then response 14 h 0 0 t else
  if h == 0 || n == 0 || n > 896 || length != 96+n || load64 (command+24) t != 1 || contact == 0 || contact > 4 || load64 (command+40) t > 1 then response 2 h 0 0 t else
  let t := hash (command+96) n hashed t
  if !eq hashed (command+64) 32 t then response 9 h 0 0 t else
  if load64 (st+32) t == h && load64 (st+40) t == caller then
    if !eq commitment hashed 32 t || load64 (st+48) t != n || load64 (st+64) t != contact then response 12 h 0 0 t else
    if load64 (st+24) t == 11 then response 0 h 2 0 t else
    if load64 (st+24) t != 7 && load64 (st+24) t != 8 then response 0 h 1 0 t else
    if load64 (st+8) t != 0 || load64 (st+88) t != 0 then response 6 h 1 0 t else
    response 0 h 1 0 (store64 (st+224) 0 (store64 (st+24) 1 (store64 (st+112) 0 t)))
  else if load64 (st+24) t > 0 && load64 (st+24) t <= 10 then response 4 h 0 0 t else
  let t := zero preflight 16 (copy (command+96) ciphertext n t)
  let t := copy hashed commitment 32 t
  let t := store64 (st+32) h t
  let t := store64 (st+40) caller t
  let t := store64 (st+48) n t
  let t := store64 (st+56) 0 t
  let t := store64 (st+64) contact t
  let t := store64 (st+72) 0 t
  let t := store64 (st+216) 0 t
  let t := store64 (st+224) (load64 (command+40) t) t
  response 0 h 1 0 (store64 (st+24) 1 t)
def reconciliationAdmissionAllowed (reason requested : UInt64) : Bool := reason == 11 && requested == 1
theorem reconciliation_integrity_cannot_fresh (requested : UInt64) :
    reconciliationAdmissionAllowed 9 requested = false := by rfl
theorem reconciliation_authorization_cannot_fresh (requested : UInt64) :
    reconciliationAdmissionAllowed 1 requested = false := by rfl
theorem reconciliation_without_confirmation_denied (reason : UInt64) :
    reconciliationAdmissionAllowed reason 0 = false := by simp [reconciliationAdmissionAllowed]
theorem reconciliation_confirmed_missing_receipt : reconciliationAdmissionAllowed 11 1 = true := by decide
def queueAttachment (caller length t : UInt64) : UInt64 :=
  let h := load64 (command+8) t
  let index := load64 (command+16) t
  let contact := load64 (command+32) t
  if length != 72 || load64 (command+64) t > 1 || h == 0 || contact == 0 || contact > 4 || load64 (command+24) t != 1 || load64 st t == 0 then response 2 h 0 0 t else
  if load64 attachment t != 0 && (load64 (attachment+8) t != h || load64 (attachment+16) t != caller || load64 (attachment+24) t != contact) then response 4 h 0 0 t else
  if load64 attachment t == 3 then response 0 h 1 0 t else
  if load64 attachment t == 7 && index != load64 (attachment+40) t-1 then response 12 h 0 0 t else
  let fresh := load64 (command+64) t
  let same := attachmentHintMatches caller h index contact fresh t
  if attachmentWaiting t && !same then response 4 h 0 0 t else
  if load64 attachmentHint t == 2 && same then response 14 h 0 14 (clearAttachmentHint t) else
  let t := if load64 attachmentHint t == 2 then clearAttachmentHint t else t
  if load64 attachment t == 7 then
    if load64 (st+8) t != 0 || load64 (st+88) t != 0 || load64 (st+24) t != 7 then
      response 6 h 1 0 (deferAttachment caller h index contact fresh t) else
    let fresh := if reconciliationAdmissionAllowed (load64 (attachment+64) t) (load64 (command+64) t) then 1 else 0
    response 0 h 1 0 (clearAttachmentHint (store64 attachment 3 (store64 (st+24) 2 (store64 (st+224) fresh (store64 (st+112) 0 t))))) else
  if load64 attachment t == 4 && index == load64 (attachment+40) t-1 then response 0 h 2 0 t else
  if load64 attachment t == 2 && index != load64 (attachment+40) t then response 12 h 0 0 t else
  if load64 (st+8) t != 0 || load64 (st+88) t != 0 || (load64 (st+24) t > 0 && load64 (st+24) t <= 6) || load64 (st+24) t == 9 || load64 (st+24) t == 10 then
    response 6 h 1 0 (deferAttachment caller h index contact fresh t) else
  let t := clearAttachmentHint t
  let first := if load64 attachment t == 0 || load64 attachment t == 4 then index else load64 (attachment+32) t
  let t := if load64 attachment t == 0 || load64 attachment t == 4 then
      let t := zero attachment 32 (zero batch 1024 t)
      let t := store64 (attachment+72) (load64 (command+64) t) (store64 (attachment+32) first (store64 (attachment+48) 64 t))
      let t := store64 batch blobMagic (store64 (batch+8) 1 t)
      store64 (batch+48) first t else t
  let t := store64 (attachment+8) h (store64 (attachment+16) caller (store64 (attachment+24) contact t))
  let t := store64 (attachment+56) index t
  let r := ownerIndex h index 18 (store64 attachment 1 t)
  if r == error then response 14 h 0 0 r else response 0 h 1 0 r
def ownerCompleted (purpose length t : UInt64) : UInt64 :=
  let code := status t
  if purpose == 23 then
    if code != 0 || length != 320 || load64 (wire+16) t != 256 || !eq (wire+288) own 32 t then publicationFailure (if code == 0 then 9 else code) t else
    store64 (preflight+128) 3 (copy (wire+64) publicPrekeys 256 t)
  else if purpose == 25 then
    if code != 0 || length != 96 || load64 (wire+8) t != load64 (preflight+24) t ||
      load64 (wire+24) t != load64 (preflight+16) t then preflightFailure (if code == 0 then 12 else code) t else
    if load64 (wire+16) t != 0 then store64 preflight 8 t else
    store64 preflight 3 (copy (wire+64) claimIdentity 32 t)
  else if purpose == 26 then
    if code != 0 || length != 160 || load64 (wire+16) t != 96 then preflightFailure (if code == 0 then 2 else code) t else
    store64 preflight 5 (copy (wire+64) claimCaps 96 t)
  else if purpose == 24 then
    if code != 0 || length != 64 then preflightFailure (if code == 0 then 2 else code) t else store64 preflight 8 t
  else if purpose == 20 then
    if code != 0 then failSend code t else store64 (st+24) 11 t
  else if purpose == 18 then
    let n := load64 (wire+16) t
    let index := load64 (attachment+56) t
    let off := load64 (attachment+48) t
    let count := load64 (batch+56) t
    if code != 0 || length != 96+n || n <= 16 || n > 528 || load64 (wire+24) t != index || count >= 14 || off+16+n > 8192 then
      store64 attachment 7 (store64 (attachment+64) (if code == 0 then 9 else code) t) else
    if count != 0 && !eq (wire+64) (batch+16) 32 t then store64 attachment 7 t else
    let t := copy (wire+64) (batch+16) 32 t
    let t := store64 (batch+off) index (store64 (batch+off+8) n t)
    let t := copy (wire+96) (batch+off+16) n t
    let t := store64 (batch+56) (count+1) (store64 (attachment+40) (index+1) (store64 (attachment+48) (off+16+n) t))
    if count+1 < 14 && (index+1)*512 < load64 (wire+32) t then store64 attachment 2 t else
    let t := copy batch ciphertext (off+16+n) t
    let t := hash ciphertext (off+16+n) commitment t
    let t := store64 (st+32) (load64 (attachment+8) t) (store64 (st+40) (load64 (attachment+16) t) t)
    let t := store64 (st+48) (off+16+n) (store64 (st+56) 0 (store64 (st+64) (load64 (attachment+24) t) t))
    let t := store64 (st+216) 0 (store64 (st+224) (load64 (attachment+72) t) (store64 attachment 3 t))
    let r := ownerSubmit 434 (load64 (st+64) t) 14 0 0 14 t
    if r == error then failSend 3 r else r
  else if purpose == 428 then
    if !acknowledgeAllowed code then failReceive code t else store64 (st+160) 3 t
  else if code != 0 then
    if purpose == 11 || purpose == 12 then failReceive code (zero own 16 t) else
    if purpose == 14 || purpose == 15 then failSend code (zero remote 12 t) else failSend code t
  else
  if purpose == 11 then
    if length != 192 || load64 (wire+16) t != 128 then failReceive 2 t else
    store64 (st+152) 1 (copy (wire+64) own 128 t)
  else if purpose == 427 then
    let n := load64 (wire+16) t
    if length != 64+n || n != load64 (st+48) t || load64 (wire+24) t != 2 || load64 (wire+32) t != load64 (st+64) t ||
      !eq (wire+64) ciphertext n t then failSend 9 t else
    let r := ownerSubmit 434 (load64 (st+64) t) 14 0 0 14 t
    if r == error then failSend 3 r else r
  else if purpose == 14 then
    if length != 160 || load64 (wire+16) t != 96 then failSend 2 t else
    let t := store64 (st+320) 0 (copy (wire+64) remote 96 t)
    let t := copy remote combined 32 t
    let t := copy commitment (combined+32) 32 t
    let t := hash combined 64 requestId t
    store64 (st+24) 2 t
  else if purpose == 15 then
    if length != 160 || !eq (wire+64) remote 96 t then failSend 8 (zero remote 12 t) else store64 (st+240) 1 t
  else if purpose == 12 then
    if length != 192 || !eq (wire+64) own 128 t then failReceive 5 (zero own 16 t) else store64 (st+248) 1 t
  else failSend 7 t
def collectOwner (t : UInt64) : UInt64 :=
  let token := load64 (st+8) t
  if token == 0 then t else
  let r := syscall 134 token wire 1024 0 t
  if r == 0 then r else
  let purpose := load64 (st+16) r
  let t := store64 (st+8) 0 r
  if r == error || r < 64 || r > 1024 then
    if purpose == 23 then publicationFailure 3 t else
    if purpose == 24 || purpose == 25 || purpose == 26 then preflightFailure 3 t else
    if purpose == 428 || purpose == 11 || purpose == 12 then failReceive 3 (zero own 16 t) else failSend 3 t
  else ownerCompleted purpose r t
def receiptEvidence (length profile : UInt64) : Bool := length == 320 && profile == 2
theorem unsigned_acceptance_denied (profile : UInt64) : receiptEvidence 64 profile = false := by simp [receiptEvidence]
theorem unverified_profile_denied (length : UInt64) : receiptEvidence length 0 = false := by simp [receiptEvidence]
def accepted (length t : UInt64) : UInt64 :=
  if !receiptEvidence length (load64 (st+320) t) then failSend 7 t else
  let t := store64 receiptArgs requestId t
  let t := store64 (receiptArgs+8) commitment t
  let t := store64 (receiptArgs+16) (receiptProfile+352) t
  let t := store64 (receiptArgs+24) (remote+64) t
  let t := store64 (receiptArgs+32) (load64 (st+48) t) (store64 (receiptArgs+40) 0 t)
  if !Guest.ReceiptSDK.verify receiptArgs (answer+64) (answer+256) receiptProfile t then failSend 9 t else
  store64 (st+24) 6 (copy (answer+64) receiptCache 256 t)
def rpcCompleted (purpose length t : UInt64) : UInt64 :=
  let code := load64 answer t
  let h := load64 (answer+8) t
  if purpose == 30 then
    if code == 6 then store64 (preflight+128) 3 t else
    if code != 0 || length != 64 then publicationFailure (if code == 0 then 2 else code) t else
    store64 (preflight+128) 5 t
  else if purpose == 31 then
    if code == 6 then store64 preflight 5 t else
    if code != 0 || length != 320 || load64 (answer+16) t != 256 then preflightFailure (if code == 0 then 2 else code) t else
    let t := copy (answer+64) claimedPrekeys 256 t
    let r := acceptClaimedPrekeys (store64 preflight 7 t)
    if r == error then preflightFailure 3 r else r
  else if purpose == 2 then
    if code == 6 then t else if code != 0 then failSend code t else
    let t := store64 (st+72) h t
    if load64 (answer+16) t == load64 (st+48) t && load64 (answer+24) t == 0 then accepted length t else
    let offset := load64 (answer+16) t
    if offset > load64 (st+48) t then failSend 9 t else
    store64 (st+56) offset (store64 (st+24) (if offset == load64 (st+48) t then 4 else 3) t)
  else if purpose == 3 then
    if code != 0 then failSend code t else
    let next := load64 (answer+16) t
    if next <= load64 (st+56) t || next > load64 (st+48) t then failSend 9 t else
    store64 (st+56) next (store64 (st+24) (if next == load64 (st+48) t then 4 else 3) t)
  else if purpose == 4 then
    if code == 6 then store64 (st+24) 5 t else if code == 0 then accepted length t else failSend code t
  else if purpose == 5 then
    if code == 6 then t else if code != 0 || (load64 (answer+16) t != 1 && load64 (answer+16) t != 2) then failSend code t else accepted length t
  else if purpose == 6 then
    let t := Guest.MailboxSDK.receiptTerms (receiptArgs+64) t
    let t := hash (receiptArgs+64) 64 hashed t
    if !eq hashed (answer+416) 32 t then failSend 7 t else
    if code != 0 || length != 480 || load64 (answer+16) t != 416 ||
      !eq (answer+448) (remote+64) 32 t ||
      !Guest.ReceiptSDK.declarationValid receiptNode (answer+64) (remote+64) t then failSend 9 t else
    store64 (st+320) 2 (copy (answer+64) receiptProfile 416 t)
  else if purpose == 7 then
    if code == 0 || code == 3 then store64 (st+24) 8 t else if code == 6 then t else failSend code t
  else if purpose == 10 then
    if code == 6 then t else if code != 0 then failReceive code t else
    let total := load64 (answer+16) t
    let offset := load64 (answer+24) t
    let count := load64 (answer+32) t
    if total == 0 || total > 8192 || offset != load64 (st+136) t || count == 0 || count > 512 || length != 64+count || count > total-offset then failReceive 9 t else
    if offset != 0 && (h != load64 (st+144) t || total != load64 (st+128) t) then failReceive 9 t else
    let t := store64 (st+144) h (store64 (st+128) total t)
    let t := copy (answer+64) (received+offset) count t
    let t := store64 (st+136) (offset+count) t
    if offset+count != total then store64 (st+160) 1 t else
    let t := hash received total receiveCommitment t
    if load64 received t == blobMagic then
      if load64 (received+8) t != 1 || load64 (received+56) t == 0 || load64 (received+56) t > 14 || !blobValid received total 0 64 t then failReceive 9 t else
      let existing := parkFind h 0 t
      let p := if existing == 0 then parkFree 0 t else existing
      if p == 0 then failReceive 4 t else
      let t := store64 p h (copy (received+16) (p+8) 32 (copy receiveCommitment (p+40) 32 t))
      let t := store64 (p+80) (load64 (received+48) t) (store64 (p+88) (load64 (received+56) t) (store64 (p+104) total t))
      let t := if load64 (st+280) t == p then copy received blob total (store64 (st+296) p (store64 (st+280) 0 t)) else t
      store64 (st+216) 0 (store64 (st+256) (if h > load64 (st+256) t then h else load64 (st+256) t) (store64 (st+160) 0 (store64 (st+136) 0 t)))
    else if total > 896 then failReceive 9 t else
    let r := ownerSubmit 428 0 total received total 428 (store64 (st+160) 2 t)
    if r == error then failReceive 3 r else r
  else if purpose == 11 then
    if code == 6 then store64 (st+160) 4 t else if code == 0 then
      let row := load64 (st+304) t
      let t := releaseParked row t
      store64 (st+216) 0 (store64 (st+304) 0 (store64 (st+192) (load64 (st+192) t+1) (store64 (st+160) 0 (store64 (st+136) 0 t))))
    else failReceive code t
  else if purpose == 12 then
    if code == 6 then t else if code == 0 && load64 (answer+16) t == 2 then
      let row := load64 (st+304) t
      let t := releaseParked row t
      store64 (st+216) 0 (store64 (st+304) 0 (store64 (st+192) (load64 (st+192) t+1) (store64 (st+160) 0 (store64 (st+136) 0 t))))
    else failReceive code t
  else failSend 7 t
def rpcFailure (reason t : UInt64) : UInt64 :=
  let t := store64 (st+88) 0 t
  if load64 (st+96) t == 30 then publicationFailure reason t else
  if load64 (st+96) t == 31 then preflightFailure reason t else
  if load64 (st+96) t >= 10 then failReceive reason t else failSend reason t
def abandonRPC (reason t : UInt64) : UInt64 :=
  let id := load64 (st+88) t
  -- A timeout cannot retract remote acceptance. Release only this exact
  -- transport request before dropping its local handle; stale cancellation
  -- cannot clear a replacement relationship. Ciphertext retry state remains.
  let t := if id == 0 then t else network 42 id t
  rpcFailure reason t
def collectRPC (t : UInt64) : UInt64 :=
  let id := load64 (st+88) t
  if id == 0 then t else
  let r := network 40 id t
  if r == error || r < 64 || status r != 0 then
    if r != error && r >= 64 && status r == 6 then
      let now := Guest.WaitSDK.now r
      if now >= load64 (st+232) now then abandonRPC 14 now else now
    else abandonRPC 14 r
  else
    let n := load64 (wire+16) r
    if n < 64 || n > 960 || r != 64+n then abandonRPC 9 r else
    let purpose := load64 (st+96) r
    let t := copy (wire+64) answer n r
    rpcCompleted purpose n (store64 (st+88) 0 t)
def sendQuantum (t : UInt64) : UInt64 :=
  if load64 (st+8) t != 0 || load64 (st+88) t != 0 then t else
  let phase := load64 (st+24) t
  if phase == 6 then
    if load64 attachment t == 3 then store64 attachment 4 (store64 (st+24) 11 t) else
    let r := ownerSubmit 434 (load64 (st+32) t) 20 commitment 32 20 (store64 (st+24) 10 t)
    if r == error then failSend 3 r else r
  else if phase == 1 then
    let r := ownerSubmit 427 (load64 (st+32) t) 0 0 0 427 (store64 (st+24) 9 t)
    if r == error then failSend 3 r else r
  else if phase < 2 || phase > 5 then t else
  if load64 (st+240) t == 0 then
    let r := ownerSubmit 434 (load64 (st+64) t) 14 0 0 15 t
    if r == error then failSend 3 r else r
  else
  if !ready (remote+64) t then failSend 14 t else
  if load64 (st+320) t != 2 then
    let r := network 47 0 t
    if r != 544 || status r != 0 then failSend 14 r else
    let t := copy (wire+64) receiptNode 480 r
    let t := hash receiptNode 480 hashed t
    if !eq hashed (remote+64) 32 t then failSend 9 t else
    let t := makeRequest 10 0 0 0 t
    let r := rpc 64 6 (store64 (st+240) 0 t)
    if r == error then failSend 14 r else r
  else
  let total := load64 (st+48) t
  let h := load64 (st+72) t
  let offset := load64 (st+56) t
  let t := if phase == 2 then
      let t := makeRequest 1 total (load64 (st+224) t) 0 t
      let t := copy remote (request+64) 64 t
      let t := copy requestId (request+128) 32 t
      copy commitment (request+160) 32 t
    else if phase == 3 then
      let count := if total-offset > 512 then 512 else total-offset
      let t := copy remote (request+64) 64 (makeRequest 2 h offset 0 t)
      copy (ciphertext+offset) (request+128) count t
    else if phase == 4 then copy remote (request+64) 64 (makeRequest 3 h 0 0 t)
    else copy remote (request+64) 64 (makeRequest 4 h 0 0 t)
  let n := if phase == 2 then 192 else if phase == 3 then 128+(if total-offset > 512 then 512 else total-offset) else 128
  let r := rpc n phase (store64 (st+240) 0 t)
  if r == error then failSend 14 r else r
def receiveQuantum (t : UInt64) : UInt64 :=
  if load64 st t == 0 || load64 (st+152) t != 1 || load64 (st+8) t != 0 || load64 (st+88) t != 0 ||
    (load64 (st+24) t >= 1 && load64 (st+24) t <= 5) || load64 (st+24) t == 9 then t else
  let t := if load64 (st+160) t == 0 then
    let p := parkAck 0 t
    if p == 0 then t else
    store64 (st+304) p (copy (p+40) receiveCommitment 32 (store64 (st+144) (load64 p t) (store64 (st+160) 3 t))) else t
  let phase := load64 (st+160) t
  if !attachmentReceiveAllowed (load64 attachmentHint t) phase (load64 (st+280) t) then t else
  if phase == 2 || phase == 7 then t else
  let now := Guest.WaitSDK.now t
  if phase == 0 && load64 (st+280) now == 0 && now < load64 (st+208) now then now else
  if load64 (st+248) t == 0 then
    let r := ownerSubmit 434 0 11 0 0 12 t
    if r == error then failReceive 3 (zero own 16 r) else r
  else
  if !ready (own+96) t then store64 (st+248) 0 (store64 (st+208) (now+100) t) else
  let t := store64 (st+208) (now+100) now
  let t := if phase == 3 then
      let t := makeRequest 6 (load64 (st+144) t) 0 0 t
      let t := mailboxAuth own 1 (request+64) t
      copy receiveCommitment (request+128) 32 t
    else if phase == 4 then mailboxAuth own 1 (request+64) (makeRequest 4 (load64 (st+144) t) 0 0 t)
    else
      let requested := load64 (st+280) t
      let h := if phase == 0 then (if requested == 0 then 0 else load64 requested t) else load64 (st+144) t
      let t := makeRequest 5 h (load64 (st+136) t) 512 t
      let t := store64 (request+40) (if h == 0 then load64 (st+256) t else 0) t
      mailboxAuth own 1 (request+64) t
  let r := rpc (if phase == 3 then 160 else 128)
    (if phase == 3 then 11 else if phase == 4 then 12 else 10) (store64 (st+248) 0 t)
  if r == error then failReceive 14 r else r
-- These jobs share the same one-RPC mailbox channel. Own publication precedes
-- initial sending, and each claim retry keeps the owner's stable claim token.
def prekeyQuantum (t : UInt64) : UInt64 :=
  if load64 st t == 0 || load64 (st+152) t != 1 || load64 (st+8) t != 0 || load64 (st+88) t != 0 then t else
  let publication := load64 (preflight+128) t
  if publication == 1 then
    let r := ownerSubmit 434 0 23 0 0 23 (store64 (preflight+128) 2 t)
    if r == error then publicationFailure 3 r else r
  else if publication == 3 then
    if !ready (own+96) t then t else
    if load64 (preflight+144) t >= 32 then publicationFailure 4 t else
    let t := copy publicPrekeys (request+128) 256 (mailboxAuth own 1 (request+64) (makeRequest 8 0 0 0 t))
    let t := store64 (preflight+144) (load64 (preflight+144) t+1) (store64 (preflight+128) 4 t)
    let r := rpc 384 30 t
    if r == error then publicationFailure 14 r else r
  else
  let phase := load64 preflight t
  if phase == 1 then
    let r := ownerSubmit 434 (load64 (preflight+24) t) 25 0 0 25 (store64 preflight 2 t)
    if r == error then preflightFailure 3 r else r
  else if phase == 3 then
    let r := ownerSubmit 434 (load64 (preflight+24) t) 14 0 0 26 (store64 preflight 4 t)
    if r == error then preflightFailure 3 r else r
  else if phase == 5 then
    if publication == 6 then preflightFailure (load64 (preflight+136) t) t else
    if publication != 5 then t else
    if !ready (claimCaps+64) t then preflightFailure 14 t else
    if load64 (preflight+40) t >= 32 then preflightFailure 4 t else
    let t := copy claimCaps (request+64) 64 (makeRequest 9 0 0 0 t)
    let t := copy claimIdentity (request+128) 32 t
    let t := store64 (preflight+40) (load64 (preflight+40) t+1) (store64 preflight 6 t)
    let r := rpc 160 31 t
    if r == error then preflightFailure 14 r else r
  else t
def queuedForgeReply (t : UInt64) : UInt64 :=
  let t := header 0 6 0 0 0 0 1 t
  128+copy (foreground+56) (wire+96) 32 (copy (foreground+24) (wire+64) 32 t)
def queueForge (caller t : UInt64) : UInt64 :=
  let policy := load64 (command+128) t
  if load64 st t == 0 || load64 (st+152) t != 1 then response 14 0 0 0 t else
  if (policy != 1 && policy != 2) || Guest.ProjectGraph.allZero (command+64) 32 t ||
      Guest.ProjectGraph.allZero (command+96) 32 t then response 2 0 0 0 t else
  if forgePending t then
    if requestCallerAllowed (load64 (foreground+8) t) caller && load64 (foreground+88) t == policy &&
      eq (foreground+24) (command+64) 32 t && eq (foreground+56) (command+96) 32 t then queuedForgeReply t
    else response 6 0 0 0 t
  else if Guest.MessengerForge.active t then
    if !requestCallerAllowed (load64 (foreground+96) t) caller then response 1 0 0 0 t else
    if eq Guest.ForgeRouted.root (command+64) 32 t && eq (Guest.ForgeFederation.st+160) (command+96) 32 t &&
      load64 (Guest.ForgeFederation.st+136) t == policy then Guest.MessengerForge.inspect t else response 6 0 0 0 t
  else
    let t := zero foreground 20 t
    let t := copy (command+64) (foreground+24) 64 t
    let t := store64 (foreground+8) caller (store64 (foreground+88) policy (store64 foreground 1 t))
    queuedForgeReply t
def queuedForgeQuantum (t : UInt64) : UInt64 :=
  if !forgePending t then t else
  if load64 (foreground+16) t >= 8192 then
    let caller := load64 (foreground+8) t
    Guest.ForgeRouted.failure 14 (store64 (foreground+96) caller (zero foreground 20 t)) else
  let t := store64 (foreground+16) (load64 (foreground+16) t+1) t
  let t := collectRPC (collectOwner t)
  if load64 (st+8) t != 0 || load64 (st+88) t != 0 then t else
  let sendPhase := load64 (st+24) t
  let prekeyPhase := load64 preflight t
  let publicationPhase := load64 (preflight+128) t
  if (sendPhase > 0 && sendPhase <= 6) || sendPhase == 9 || sendPhase == 10 ||
      (prekeyPhase > 0 && prekeyPhase < 8) || (publicationPhase > 0 && publicationPhase < 5) then
    sendQuantum (prekeyQuantum t)
  else
  let receivePhase := load64 (st+160) t
  if (receivePhase > 0 && receivePhase < 5) || parkAck 0 t != 0 then receiveQuantum t else
  -- No new background receive begins while a foreground request is queued.
  -- The shared request identity advances only after every admitted RPC drains.
  let t := store64 (Guest.ForgeRouted.st+16) (load64 (st+80) t) t
  let r := Guest.MessengerForge.begin (foreground+24) (foreground+56) (load64 (foreground+88) t) 0 t
  let caller := load64 (foreground+8) r
  let t := store64 (foreground+96) caller (zero foreground 20 r)
  if r == error then Guest.ForgeRouted.failure 14 t else
  store64 (st+80) (load64 (Guest.ForgeRouted.st+16) t) t
def dispatch (caller rights token length t : UInt64) : UInt64 :=
  let op := load64 command t
  let h := load64 (command+8) t
  if length < 64 || length > 1024 || load64 (command+56) t != 1 || syscall 131 token 0 0 0 t != 0 then response 1 h 0 0 t else
  if op == 463 && load64 (command+16) t == 3 && length == 136 then queueForge caller t
  else if op == 461 && load64 (command+16) t == 3 && length == 64 then
    if forgePending t then
      if requestCallerAllowed (load64 (foreground+8) t) caller then queuedForgeReply t else response 1 h 0 0 t
    else if Guest.ForgeRouted.phase t != 0 && !requestCallerAllowed (load64 (foreground+96) t) caller then response 1 h 0 0 t
    else Guest.MessengerForge.inspect t
  else
  if (Guest.MessengerForge.active t || forgePending t) && op == 460 then response 6 h 1 0 t else
  if op == 464 then
    if (rights &&& 0x100000000) == 0 then response 1 h 0 0 t else
    if load64 (command+16) t == 1 && length == 64 then
      64+header 0 (load64 (preflight+128) t) (load64 (preflight+136) t)
        (load64 preflight t) (load64 (preflight+32) t) (load64 (preflight+144) t) (load64 (preflight+40) t) t
    else if load64 (command+16) t == 2 && length == 64 then
      64+header 0 (Guest.ForgeRouted.phase t) (load64 (Guest.ForgeRouted.st+24) t)
        (if load64 (st+8) t == 0 then 0 else 1) (if load64 (st+88) t == 0 then 0 else 1)
        (load64 (st+24) t) (load64 (st+160) t) t
    else if load64 (command+16) t == 3 && length == 64 then
      64+header 0 (load64 (st+24) t) (load64 (st+112) t)
        (load64 attachment t) (load64 (attachment+64) t)
        (load64 attachmentHint t) (load64 (attachmentHint+48) t) t
    else if load64 (command+16) t == 4 && length == 64 then
      64+header 0 (load64 (st+96) t) (load64 (st+24) t)
        (load64 (st+48) t) (load64 (st+56) t)
        (load64 (st+72) t) (load64 (st+232) t) t
    else configure token length t
  else
  if op == 460 then if load64 (command+48) t == 3 then queuePreflight caller length t else
    if load64 (command+48) t == 2 then queueAttachment caller length t else queue caller length t else
  if op == 461 && length == 64 then
    if load64 preflight t != 0 && h == load64 (preflight+16) t && caller == load64 (preflight+8) t then
      response (if load64 preflight t == 9 then 14 else 0) h
        (if load64 preflight t == 8 then 6 else 1) (load64 (preflight+32) t) t else
    if h == load64 (attachment+8) t && caller == load64 (attachment+16) t && load64 attachment t != 0 then
      response (if load64 attachment t == 7 then 14 else 0) h
        (if load64 attachment t == 4 then 2 else if load64 attachment t == 2 then 5 else 1) (load64 (attachment+64) t) t else
    if h != load64 (st+32) t || caller != load64 (st+40) t then response 3 h 0 0 t else
    let phase := load64 (st+24) t
    response (if phase == 7 then 14 else 0) h (if phase == 11 then 2 else if phase == 8 then 4 else 1) (load64 (st+112) t) t
  else if op == 462 && length == 64 then
    let t := if h != 0 && load64 (attachmentHint+16) t == h &&
      requestCallerAllowed (load64 (attachmentHint+8) t) caller then clearAttachmentHint t else t
    if h == 0 then
      let t := zero foreground 20 (zero preflight 128 t)
      let owner := load64 st t
      let pending := load64 (st+8) t
      let t := if pending == 0 then t else syscall 135 pending 0 0 0 t
      let t := if Guest.MessengerForge.active t then Guest.MessengerForge.cancel t else t
      let t := Guest.ForgeRouted.init (Guest.ForgeRouted.failure 14 t)
      let t := network 42 0 t
      let t := zero own 16 (zero remote 12 (zero ciphertext 1024 (zero received 1024 (zero request 128 (zero answer 128 t)))))
      response 0 0 4 0 (store64 st owner (zero st 64 (zero attachment 32 (zero batch 1024 (zero parked 256 (zero blob 1024 (zero receiptProfile 52 (zero receiptNode 60 (zero receiptCache 32 (zero receiptArgs 6 t))))))))))
    else if forgePending t then
      if requestCallerAllowed (load64 (foreground+8) t) caller then response 0 h 4 0 (zero foreground 20 t) else response 1 h 0 0 t
    else if Guest.MessengerForge.active t then
      if requestCallerAllowed (load64 (foreground+96) t) caller then response 0 h 4 0 (Guest.MessengerForge.cancel t) else response 1 h 0 0 t
    else
    if h == load64 (preflight+16) t && caller == load64 (preflight+8) t && load64 preflight t != 0 then
      let pending := load64 (st+8) t
      let purpose := load64 (st+16) t
      let t := if pending != 0 && (purpose == 24 || purpose == 25 || purpose == 26) then
        store64 (st+8) 0 (syscall 135 pending 0 0 0 t) else t
      -- A claim may already have committed remotely. Closing the stream does
      -- not spend the private OPK and cannot assert remote cancellation.
      let t := if load64 (st+88) t != 0 && load64 (st+96) t == 31 then
        store64 (st+88) 0 (network 42 0 t) else t
      response 0 h 4 0 (zero preflight 16 t)
    else
    if h != load64 (st+32) t || caller != load64 (st+40) t then response 3 h 0 0 t else
    -- Once a terminal request is in flight, cancellation cannot assert that a
    -- remote durable acceptance did not happen. Preserve exact retry state.
    if load64 (st+24) t >= 2 && load64 (st+24) t != 9 then response 14 h (if load64 (st+24) t == 6 then 2 else 1) 0 t else
    let pending := load64 (st+8) t
    let t := if pending == 0 then t else syscall 135 pending 0 0 0 t
    response 0 h 4 0 (store64 (st+8) 0 (store64 (st+24) 8 t))
  else if op == 463 && load64 (command+16) t == 1 && length == 96 then
    fetchAttachment h (load64 (command+24) t) (command+64) (load64 (command+32) t) t
  else if op == 463 && load64 (command+16) t == 2 && length == 96 then
    response 0 h 0 0 (markAck (command+64) 0 t)
  else if op == 463 && length == 64 then response 0 (load64 (st+144) t) (load64 (st+192) t) (load64 (st+200) t) t
  else response 7 h 0 0 t
partial def loop (t : UInt64) : UInt64 :=
  let n := syscall 36 (self t) incoming 1024 0 t
  let t := if n >= 96 && n <= 1056 then
    let token := load64 (incoming+8) n
    let size := dispatch (load64 incoming n) (load64 (incoming+16) n) token (n-32) n
    reply token size size
  else n
  let t := attachmentHintQuantum t
  let t := if forgePending t then queuedForgeQuantum t else
    if Guest.MessengerForge.active t then Guest.MessengerForge.pump t else receiveQuantum (sendQuantum (prekeyQuantum (collectRPC (collectOwner t))))
  let t := zero command 124 (zero wire 128 (zero scratch 80 t))
  let work := attachmentWaiting t || forgePending t || (load64 preflight t > 0 && load64 preflight t < 8) ||
    (load64 (preflight+128) t > 0 && load64 (preflight+128) t < 5) || load64 (st+8) t != 0 || load64 (st+88) t != 0 ||
    (load64 (st+24) t > 0 && load64 (st+24) t <= 6) || load64 (st+24) t == 9 || load64 (st+24) t == 10 ||
    (load64 (st+160) t > 0 && load64 (st+160) t < 5)
  loop (Guest.WaitSDK.deadline (Guest.WaitSDK.now t+(if work then 1 else 100)) t)
def main (t : UInt64) : UInt64 := loop (zero foreground 20 (zero preflight 128 (zero st 64 (zero own 16 (zero remote 12 (zero attachment 32 (zero parked 256 t)))))))
end Guest.MessengerDelivery
