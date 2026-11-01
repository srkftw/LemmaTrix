import Guest.FeedAccountSDK
import Guest.IdentitySDK
import Guest.ServiceHash
import Guest.LiveMemory
import Guest.WaitSDK
import Guest.FeedRetentionSDK
import Guest.RegistrySDK
import Guest.FeedEvent
namespace Guest.FeedAccount
open Guest.LiveSDK
-- A separate account/network owner. Only Identity owns signing seeds. This
-- owner sees approved published plaintext, its draft and private local choices.
def st : UInt64 := 0x680000
def publicIdentity : UInt64 := 0x681000
def envelope : UInt64 := 0x682000
def canonical : UInt64 := 0x683000
def scope : UInt64 := 0x684000
def eventId : UInt64 := 0x684100
def refs : UInt64 := 0x684200
def preferences : UInt64 := 0x685000
def draft : UInt64 := 0x690000
def outboxBody : UInt64 := 0x695000
def requestBuffer : UInt64 := 0x69a000
def answer : UInt64 := 0x69b000
def portable : UInt64 := 0x69c000
def scratch : UInt64 := 0x6a0000
def hashed : UInt64 := 0x6a1000
def trustedEvent : UInt64 := 0x6a2000
def trustedId : UInt64 := 0x6a2200
-- Sealed material and unlock scratch never alias event IDs or causal references.
def sealedAuthor : UInt64 := 0x6a3000
def unlockSecret : UInt64 := 0x6a3100
def checkedBody : UInt64 := 0x6a4000
def reconciledEvent : UInt64 := 0x6a8000
def reconciledId : UInt64 := 0x6a8200
def retained : UInt64 := 0x6c0000
def eq (a b n t : UInt64) : Bool := Guest.LiveMemory.equal a b n t
def hash (p n out t : UInt64) : UInt64 := Guest.ServiceHash.sha256At scratch p n out t
def response (code h a b t : UInt64) : UInt64 :=
  64+header code h a b (load64 (st+32) t) (load64 (st+40) t) (load64 (st+56) t) t
def failed (reason t : UInt64) : UInt64 := store64 (st+32) 8 (store64 (st+40) reason (store64 (st+64) 0 t))
def localAllowed (stored caller : UInt64) : Bool := stored != 0 && stored == caller
 theorem another_owner_denied (stored caller : UInt64) (h : (stored == caller) = false) :
    localAllowed stored caller = false := by simp [localAllowed,h]
def recoveredGenerationAllowed (current observed : UInt64) : Bool := observed < current
theorem recovered_generation_not_reused (generation : UInt64) :
    recoveredGenerationAllowed generation generation = false := by
  simp [recoveredGenerationAllowed]
def net (op h t : UInt64) : UInt64 :=
  syscall 30 6 wire 64 1024 (store64 (wire+56) 2 (header op h 0 0 0 0 0 t))
def rpc (bytes purpose t : UInt64) : UInt64 :=
  if load64 (st+64) t != 0 || bytes > 960 || bytes < 64 then error else
  let serial := load64 (st+72) t+1
  if serial == 0 || load64 (st+160) t >= 8192 then error else
  let t := store64 (st+72) serial (store64 (st+160) (load64 (st+160) t+1) t)
  let t := store64 (wire+56) 2 (header 39 serial 0 0 0 0 0 t)
  let r := syscall 30 6 wire (64+bytes) 1024 (copy requestBuffer (wire+64) bytes t)
  if r != 64 || status r != 0 then error else
  store64 (st+64) serial (store64 (st+80) purpose (store64 (st+88) (Guest.WaitSDK.now r+10000) r))
def req (action h offset count t : UInt64) : UInt64 :=
  copy wire requestBuffer 64 (header 491 action h offset count 0 0 t)
def recordBytes : UInt64 := 19456
partial def writeRecord (offset t : UInt64) : UInt64 :=
  if offset == recordBytes then
    let r := Guest.FeedRetentionSDK.commit t
    if r != 64 || status r != 0 then error else r
  else
    let r := Guest.FeedRetentionSDK.append offset (retained+offset) 512 t
    if r != 64 || status r != 0 then error else writeRecord (offset+512) r
def persist (t : UInt64) : UInt64 :=
  if load64 (st+192) t == 0 then t else
  if load64 (st+192) t != 1 then error else
  let t := zero retained 2432 t
  let t := store64 retained 0x315443434146544c (store64 (retained+8) 1 t)
  let t := store64 (retained+24) (load64 (st+8) t) (store64 (retained+32) (load64 (st+32) t) t)
  let t := store64 (retained+40) (load64 (st+208) t) (store64 (retained+48) (load64 (st+216) t) t)
  let t := store64 (retained+56) (load64 (st+200) t) t
  let t := copy scope (retained+64) 64 (copy publicIdentity (retained+128) 288 t)
  let t := copy sealedAuthor (retained+416) 192 t
  let t := copy eventId (retained+608) 32 (copy envelope (retained+640) 480 t)
  let t := if (load64 (st+200) t &&& 2) != 0 then copy preferences (retained+1120) 1536 t else t
  -- The exact signed pending outbox is mandatory; optional drafts are separate.
  let t := if load64 (st+8) t != 0 && load64 (st+208) t <= 16384 then copy outboxBody (retained+2656) (load64 (st+208) t) t else t
  let t := hash retained recordBytes hashed t
  let r := Guest.FeedRetentionSDK.begin recordBytes hashed t
  if r != 64 || status r != 0 then error else writeRecord 0 r
partial def readRecord (offset t : UInt64) : UInt64 :=
  if offset == recordBytes then t else
  let r := Guest.FeedRetentionSDK.read offset 512 t
  if r != 576 || status r != 0 then error else readRecord (offset+512) (copy (wire+64) (retained+offset) 512 r)
def clearAccount (t : UInt64) : UInt64 :=
  let t := if load64 (st+64) t == 0 then t else net 42 (load64 (st+64) t) t
  let t := Guest.FeedRetentionSDK.lock t
  let r := Guest.IdentitySDK.lockFeed t
  let caller := load64 (st+128) r
  let r := zero sealedAuthor 24 (zero unlockSecret 4 r)
  let r := zero outboxBody 2048 (zero checkedBody 2048 (zero trustedEvent 60 (zero trustedId 4
    (zero reconciledEvent 60 (zero reconciledId 4 (zero retained 4096 (zero scratch 256 r)))))))
  store64 (st+128) caller (zero st 64 (zero publicIdentity 36 (zero envelope 60 (zero canonical 32 (zero draft 2048 r)))))
def retention (length t : UInt64) : UInt64 :=
  let mode := load64 (command+16) t
  let flags := load64 (command+24) t
  if mode == 2 && length == 64 then
    let r := Guest.FeedRetentionSDK.forget t
    let code := if r == 64 then status r else 13
    -- Forget removes publishing authority as well as the protected record.
    -- Even an unavailable backing cannot leave an accessible old signer key.
    response code 0 0 0 (zero preferences 192 (zero scope 8 (clearAccount r)))
  else if length != 96 || mode > 1 || flags > 1 then response 2 0 0 0 t else
  let t := copy (command+64) unlockSecret 32 t
  if mode == 0 then
    if load64 st t == 0 || load64 (st+64) t != 0 then response 4 0 0 0 (zero unlockSecret 4 t) else
    let t := store64 (st+192) 2 t
    let r := Guest.IdentitySDK.sealFeed (load64 st t) unlockSecret t
    if r != 256 || status r != 0 then response (if r == error then 1 else status r) 0 0 0 (zero unlockSecret 4 r) else
    let t := copy (wire+64) sealedAuthor 192 (zero unlockSecret 4 r)
    let t := store64 (st+192) 1 (store64 (st+200) (1+flags*2) t)
    let r := persist t
    response (if r == error then 13 else 0) 0 1 0 r
  else
    if load64 st t != 0 || load64 (st+64) t != 0 then response 4 0 0 0 (zero unlockSecret 4 t) else
    let r := Guest.FeedRetentionSDK.recover t
    if r != 64 || status r != 0 || result r != recordBytes then response 13 0 0 0 (zero unlockSecret 4 r) else
    let r := readRecord 0 r
    if r == error || load64 retained r != 0x315443434146544c || load64 (retained+8) r != 1 ||
        load64 (retained+40) r > 16384 || load64 (retained+48) r > 9 then response 13 0 0 0 (zero unlockSecret 4 r) else
    let r := Guest.IdentitySDK.recoverFeed unlockSecret (retained+128+96) (retained+416) r
    if r != 352 || status r != 0 then response (if r == error then 1 else status r) 0 0 0 (zero unlockSecret 4 r) else
    let t := store64 st (result r) (copy (wire+64) publicIdentity 288 r)
    let r := Guest.IdentitySDK.sealFeed (load64 st t) unlockSecret t
    let r := zero unlockSecret 4 r
    if r != 256 || status r != 0 then response (if r == error then 1 else status r) 0 0 0 r else
    let t := copy (retained+64) scope 64 (copy (wire+64) sealedAuthor 192 r)
    let t := store64 (st+8) (load64 (retained+24) t) (store64 (st+24) (load64 (retained+40) t) t)
    let t := store64 (st+16) (load64 (retained+48) t) (store64 (st+120) (load64 (retained+40) t) t)
    let t := store64 (st+192) 1 (store64 (st+200) (load64 (retained+56) t) t)
    let t := copy (retained+608) eventId 32 (copy (retained+640) envelope 480 t)
    let t := if flags == 1 && (load64 (retained+56) t &&& 2) != 0 then copy (retained+1120) preferences 1536 t else zero preferences 192 t
    let t := copy (retained+2656) outboxBody (load64 (st+24) t) t
    let t := store64 (st+208) (load64 (st+24) t) (store64 (st+216) (load64 (st+16) t) t)
    -- Even an identity-only backup may predate an accepted publication.
    -- Recovery never silently treats its local counter as a freshness anchor.
    let t := store64 (st+304) 1 (store64 (st+32) 8 (store64 (st+40) 12 t))
    let r := persist t
    response (if r == error then 13 else 0) (load64 st r) (load64 (st+8) r) 0 r
def beginUpload (t : UInt64) : UInt64 :=
  let t := req 1 0 0 0 t
  let t := copy envelope (requestBuffer+64) 480 t
  let r := rpc 544 1 t
  if r == error then failed 14 r else store64 (st+32) 2 r
def appendUpload (t : UInt64) : UInt64 :=
  let offset := load64 (st+104) t
  let n := if load64 (st+208) t-offset > 512 then 512 else load64 (st+208) t-offset
  let t := req 2 (load64 (st+96) t) offset n t
  let t := copy eventId (requestBuffer+64) 32 t
  let r := rpc (96+n) 2 (copy (outboxBody+offset) (requestBuffer+96) n t)
  if r == error then failed 14 r else store64 (st+112) n (store64 (st+32) 3 r)
def commitUpload (t : UInt64) : UInt64 :=
  let t := req 3 (load64 (st+96) t) 0 0 t
  let r := rpc 96 3 (copy eventId (requestBuffer+64) 32 t)
  if r == error then failed 14 r else store64 (st+32) 4 r
def pollUpload (t : UInt64) : UInt64 :=
  let t := req 4 0 0 0 t
  let r := rpc 96 4 (copy eventId (requestBuffer+64) 32 t)
  if r == error then failed 14 r else
  store64 (st+240) (load64 (st+240) r+1)
    (store64 (st+232) (Guest.WaitSDK.now r+500)
      (if load64 (st+32) r == 6 then r else store64 (st+32) 5 r))
-- A saved response belongs to one requested action. UI reads that action and
-- its completion generation explicitly; a later timeline cannot be its commit.
def saveAnswer (bytes purpose t : UInt64) : UInt64 :=
  store64 (st+136) bytes (store64 (st+144) purpose (store64 (st+152) (load64 (st+152) t+1)
    (copy wire answer bytes t)))
def reconcilePage (cursor t : UInt64) : UInt64 :=
  let t := req 5 cursor 0 0 (store64 (st+264) cursor t)
  let r := rpc 64 7 t
  if r == error then failed 14 r else r
def finishReconciliation (t : UInt64) : UInt64 :=
  let known := load64 (st+288) t
  let saved := load64 (st+8) t
  let hasPending := saved != 0 && load64 (st+208) t != 0
  -- A restored older descriptor must not claim an already observed generation.
  if known != 0 && !recoveredGenerationAllowed (load64 (publicIdentity+24) t) (load64 (reconciledEvent+32) t) then failed 12 t else
  if hasPending && (known < saved || (known == saved && eq eventId reconciledId 32 t)) then
    if !Guest.FeedEvent.valid envelope t || !Guest.FeedEvent.contentValid envelope outboxBody (load64 (st+208) t) t then failed 9 t else
    let r := persist (store64 (st+304) 0 (store64 (st+40) 0 t))
    if r == error then failed 13 r else beginUpload r
  else if known == 0 then
    -- No authenticated author history is evidence of absence only at this
    -- selected server. Keep the explicit recovery warning and refuse signing.
    failed 12 t
  else
    let t := copy reconciledEvent envelope 480 (copy reconciledId eventId 32 t)
    let t := store64 (st+8) known (store64 (st+208) 0 (store64 (st+216) (load64 (envelope+176) t) t))
    let r := persist (store64 (st+304) 0 (store64 (st+32) (load64 (st+296) t) (store64 (st+40) 0 t)))
    if r == error then failed 13 r else r
def reconcileAnswer (bytes t : UInt64) : UInt64 :=
  if bytes == 64 && status t == 6 then finishReconciliation t else
  if bytes != 576 || status t != 0 || !Guest.FeedEvent.valid (wire+96) t then failed 9 t else
  let t := hash (wire+96) 480 hashed t
  let cursor := load64 (wire+16) t
  let generation := load64 (wire+48) t
  if !eq hashed (wire+64) 32 t || cursor <= load64 (st+264) t || cursor > 64 ||
      (load64 (st+272) t != 0 && generation != load64 (st+280) t) then failed 12 t else
  let t := store64 (st+272) (load64 (st+272) t+1) (store64 (st+280) generation t)
  let author := eq (wire+208) (publicIdentity+96) 32 t && eq (wire+368) scope 32 t
  let sequence := load64 (wire+280) t
  let t := if author && sequence >= load64 (st+288) t then
      store64 (st+288) sequence
        (store64 (st+296) (if load64 (wire+24) t >= 3 then 7 else 6)
          (copy (wire+96) reconciledEvent 480 (copy (wire+64) reconciledId 32 t)))
    else t
  reconcilePage cursor t
def validateAnswer (bytes purpose t : UInt64) : UInt64 :=
  if status t != 0 then t else
  if purpose == 5 then
    if bytes != 576 || !Guest.FeedEvent.valid (wire+96) t then
      header 9 0 0 0 0 0 0 t
    else
      let t := hash (wire+96) 480 hashed t
      if !eq hashed (wire+64) 32 t then header 9 0 0 0 0 0 0 t else
      copy (wire+64) trustedId 32 (copy (wire+96) trustedEvent 480 (store64 (st+256) 0 t))
  else if purpose == 6 then
    let offset := load64 (requestBuffer+24) t
    let n := bytes-64
    let total := load64 (trustedEvent+256) t
    if bytes <= 64 || bytes > 576 || offset != load64 (st+256) t || offset > total || n > total-offset ||
        !eq (requestBuffer+64) trustedId 32 t then header 9 0 0 0 0 0 0 t else
    let t := copy (wire+64) (checkedBody+offset) n (store64 (st+256) (offset+n) t)
    if offset+n != total then t else
    let t := hash checkedBody total hashed t
    if eq hashed (trustedEvent+224) 32 t then t else header 9 0 0 0 0 0 0 t
  else t
def complete (bytes purpose t : UInt64) : UInt64 :=
  let t := validateAnswer bytes purpose t
  let code := status t
  let bytes := if code == 9 then 64 else bytes
  let t := store64 (st+64) 0 t
  -- GUI query completions retain their own response until outcome collection.
  -- Background publication receipts cannot replace that independently owned row.
  if purpose == 7 then reconcileAnswer bytes t else
  if purpose >= 5 then saveAnswer bytes purpose t else
  if code != 0 && code != 6 && code != 10 then failed code t else
  if purpose == 1 then
    if bytes != 64 then failed 9 t else
    if code == 6 then
      if result t == 0 then failed 4 t else store64 (st+32) 5 (store64 (st+40) 0 t)
    else
    if load64 (wire+16) t >= 2 then store64 (st+32) 6 (store64 (st+40) 0 t) else
    appendUpload (store64 (st+96) (result t) (store64 (st+104) 0 t))
  else if purpose == 2 then
    let t := store64 (st+104) (load64 (st+104) t+load64 (st+112) t) t
    if load64 (st+104) t == load64 (st+208) t then commitUpload t else appendUpload t
  else if purpose == 3 then
    if code == 6 then store64 (st+32) 5 t else store64 (st+32) 6 (store64 (st+40) 0 t)
  else if purpose == 4 then
    if code == 6 then t else store64 (st+32) (if load64 (wire+16) t >= 3 then 7 else 6) (store64 (st+40) 0 t)
  else t
 def pump (t : UInt64) : UInt64 :=
  let serial := load64 (st+64) t
  if serial == 0 then
    let phase := load64 (st+32) t
    if phase != 5 && phase != 6 then t else
    if phase == 6 && Guest.FeedEvent.zeroed (envelope+304) 32 t then t else
    let now := Guest.WaitSDK.now t
    if now < load64 (st+232) now || load64 (st+240) now >= 64 then now else pollUpload now
  else
  let r := net 40 serial t
  if r >= 64 && r <= 1024 && status r == 0 then
    let n := load64 (wire+16) r
    if n < 64 || n > 960 || r != 64+n then failed 9 r else
    let t := copy (wire+64) wire n r
    complete n (load64 (st+80) t) t
  else if r == 64 && status r == 6 then
    let now := Guest.WaitSDK.now r
    if now < load64 (st+88) now then now else
    let t := net 42 serial now
    failed 12 t
  else failed 14 r
partial def validText (p n i t : UInt64) : Bool :=
  if i == n then true else
  let c := load8 (p+i) t
  -- v1 deliberately supports printable ASCII and LF. Unsupported UTF8 is a
  -- typed refusal, never executable markup or silent replacement.
  (c == 10 || (c >= 32 && c <= 126)) && validText p n (i+1) t
 def createIdentity (token t : UInt64) : UInt64 :=
  if load64 st t != 0 || load64 (st+64) t != 0 then response 4 0 0 0 t else
  let t := copy (command+64) scope 64 t
  let t := store64 scratch (self t) (store64 (scratch+8) (Guest.WaitSDK.now t) t)
  let t := hash scratch 16 hashed t
  let r := Guest.IdentitySDK.feedCreate scope hashed t
  if r != 352 || status r != 0 then response (if r == error then 1 else status r) 0 0 0 r else
  if syscall 131 token 0 0 0 r != 0 then
    let r := Guest.IdentitySDK.feedRevoke (result r) r
    response 3 0 0 0 r else
  let t := store64 st (result r) (copy (wire+64) publicIdentity 288 r)
  response 0 (load64 st t) 1 0 (store64 (st+8) 0 (store64 (st+32) 0 t))
 def prepareDraft (length t : UInt64) : UInt64 :=
  let kind := load64 (command+16) t
  let bytes := load64 (command+24) t
  let audience := load64 (command+32) t
  if length != 160 || load64 st t == 0 || kind == 0 || kind > 9 || kind == 8 ||
      bytes == 0 || bytes > 16384 || audience > 1 || load64 (st+64) t != 0 ||
      (load64 (st+32) t >= 1 && load64 (st+32) t <= 5) || load64 (st+32) t == 8 ||
      load64 (st+304) t != 0 then response 4 0 0 0 t else
  -- The approved draft carries its exact audience. A prior publication's
  -- phase cannot leave a stale wider audience behind a new local preview.
  let t := store64 (st+176) audience
    (store64 (st+16) kind (store64 (st+24) bytes (store64 (st+120) 0 (store64 (st+32) 0 t))))
  response 0 bytes 0 0 (copy (command+64) refs 96 (zero draft 2048 t))
 def appendDraft (length t : UInt64) : UInt64 :=
  let offset := load64 (command+16) t
  let bytes := length-64
  if bytes == 0 || bytes > 512 || offset != load64 (st+120) t || offset > load64 (st+24) t ||
      bytes > load64 (st+24) t-offset || load64 (st+32) t != 0 then response 2 0 0 0 t else
  response 0 (offset+bytes) 0 0 (store64 (st+120) (offset+bytes) (copy (command+64) (draft+offset) bytes t))
 def publish (token t : UInt64) : UInt64 :=
  let bytes := load64 (st+24) t
  let sequence := load64 (st+8) t+1
  if load64 st t == 0 then response 5 0 0 0 t else
  if bytes == 0 || load64 (st+120) t != bytes || load64 (st+32) t != 0 ||
      !validText draft bytes 0 t || sequence == 0 then response 2 0 0 0 t else
  let kind := load64 (st+16) t
  let t := zero canonical 32 t
  let t := store64 canonical 0x3144564546544c (store64 (canonical+8) 1 t)
  let t := store64 (canonical+16) kind (store64 (canonical+24) sequence t)
  let t := copy refs (canonical+32) 32 t
  let t := hash draft bytes (canonical+64) t
  let t := store64 (canonical+96) bytes (store64 (canonical+104) 0 t)
  let t := copy scope (canonical+112) 32 t
  let t := if kind == 6 || kind == 7 || load64 (st+176) t == 0 then t else copy (scope+32) (canonical+144) 32 t
  let t := copy (refs+32) (canonical+176) 64 t
  let t := hash canonical 256 hashed t
  let r := Guest.IdentitySDK.feedApprove (load64 st t) hashed t
  if r != 64 || status r != 0 then response (if r == error then 1 else status r) 0 0 0 r else
  let r := Guest.IdentitySDK.certify (result r) canonical 256 r
  if r != 544 || status r != 0 then response (if r == error then 1 else status r) 0 0 0 r else
  if syscall 131 token 0 0 0 r != 0 then response 3 0 0 0 r else
  let t := copy (wire+64) envelope 480 r
  let t := hash envelope 480 eventId t
  let t := copy draft outboxBody bytes t
  let t := store64 (st+208) bytes (store64 (st+216) kind (store64 (st+8) sequence (store64 (st+40) 0 t)))
  let t := store64 (st+240) 0 (store64 (st+232) (Guest.WaitSDK.now t+500) t)
  let t := store64 (st+32) 1 t
  let r := persist t
  if r == error then response 13 sequence 12 0 (failed 13 r) else
  if syscall 131 token 0 0 0 r != 0 then response 3 sequence 12 0 (failed 12 r) else
  response 0 sequence 1 0 (beginUpload r)
partial def prefFind (author i t : UInt64) : UInt64 :=
  if i == 32 then error else
  let p := preferences+i*48
  if load64 p t == 0 || eq (p+16) author 32 t then p else prefFind author (i+1) t
 def preference (length t : UInt64) : UInt64 :=
  let kind := load64 (command+16) t
  let enabled := load64 (command+24) t
  let p := prefFind (command+64) 0 t
  if length != 96 || (kind != 1 && kind != 2 && kind != 4) || enabled > 2 then response 2 0 0 0 t else
  if p == error then response 4 0 0 0 t else
  let t := store64 p 1 (copy (command+64) (p+16) 32 t)
  let old := load64 (p+8) t
  let selected := if enabled == 2 then (if (old &&& kind) == 0 then 1 else 0) else enabled
  let bits := if selected == 1 then old ||| kind else old &&& (0xffffffffffffffff ^^^ kind)
  let r := persist (store64 (p+8) bits t)
  response (if r == error then 13 else 0) kind selected bits r
partial def blocked (author i t : UInt64) : Bool :=
  if i == 32 then false else
  let p := preferences+i*48
  (load64 p t != 0 && (load64 (p+8) t &&& 2) != 0 && eq (p+16) author 32 t) || blocked author (i+1) t
partial def followed (author i t : UInt64) : Bool :=
  if i == 32 then false else
  let p := preferences+i*48
  (load64 p t != 0 && (load64 (p+8) t &&& 1) != 0 && eq (p+16) author 32 t) || followed author (i+1) t
partial def followedProject (project i t : UInt64) : Bool :=
  if i == 32 then false else
  let p := preferences+i*48
  (load64 p t != 0 && (load64 (p+8) t &&& 4) != 0 && eq (p+16) project 32 t) || followedProject project (i+1) t
 def query (action length t : UInt64) : UInt64 :=
  if load64 (st+64) t != 0 then response 4 0 0 0 t else
  let t := if action == 5 then store64 (st+184) (load64 (command+24) t) t else t
  let t := if action == 5 then req 5 (load64 (command+16) t) 0 0 t else
    req 6 0 (load64 (command+16) t) (load64 (command+24) t) t
  let t := if action == 6 && length == 96 then copy (command+64) (requestBuffer+64) 32 t else t
  let r := rpc (if action == 5 then 64 else 96) action t
  if r == error then response 14 0 0 0 r else response 6 0 action 0 r
 def outcome (t : UInt64) : UInt64 :=
  let n := load64 (st+136) t
  if load64 (st+64) t != 0 then response 6 0 (load64 (st+80) t) 0 t else
  if n < 64 || n > 960 then response 6 0 0 0 t else
  -- A local block is independent of a federation appeal/reversal. Return a
  -- visible filtered marker and pagination, never another author's text.
  if load64 (st+144) t == 5 && n == 576 && blocked (answer+96+112) 0 t then
    response 15 (load64 (answer+8) t) (load64 (answer+16) t) 0 t else
  if load64 (st+144) t == 5 && n == 576 && load64 (st+184) t == 1 && !followed (answer+96+112) 0 t &&
      !(load64 (answer+96+176) t == 3 && followedProject (answer+96+368) 0 t) then
    response 15 (load64 (answer+8) t) (load64 (answer+16) t) 1 t else
  n+copy answer wire n t
 def lock (t : UInt64) : UInt64 :=
  let r := clearAccount t
  response (if r == error then 1 else 0) 0 0 0 r
def exportPortable (length t : UInt64) : UInt64 :=
  let includePreferences := load64 (command+16) t
  let offset := load64 (command+24) t
  let count := load64 (command+32) t
  if length != 64 || includePreferences > 1 || offset > 2048 || count == 0 || count > 512 || count > 2048-offset then response 2 0 0 0 t else
  let t := if offset == 0 then
      let t := zero portable 256 t
      let t := store64 portable 0x3154524f5046544c (store64 (portable+8) 1 t)
      let t := store64 (portable+16) includePreferences (store64 (portable+24) (load64 (st+8) t) t)
      let t := copy (publicIdentity+96) (portable+32) 32 (copy scope (portable+64) 64 t)
      let t := copy eventId (portable+128) 32
        (store64 (portable+160) (load64 (publicIdentity+24) t) t)
      if includePreferences == 1 then copy preferences (portable+256) 1536 t else t
    else t
  let t := header 0 2048 offset count 0 0 0 t
  64+count+copy (portable+offset) (wire+64) count t
partial def validPreferences (p i t : UInt64) : Bool :=
  if i == 32 then true else
  load64 (p+i*48) t <= 1 && load64 (p+i*48+8) t <= 7 && validPreferences p (i+1) t
 def importPortable (length t : UInt64) : UInt64 :=
  let offset := load64 (command+16) t
  let bytes := length-64
  if offset == 0 then
    if load64 st t != 0 then response 4 0 0 0 t else
    if bytes != 512 then response 2 0 0 0 t else
    response 0 512 0 0 (store64 (st+224) 512 (copy (command+64) portable 512 t))
  else if offset != load64 (st+224) t || bytes != 512 || offset > 1536 then response 2 0 0 0 t else
  let t := store64 (st+224) (offset+bytes) (copy (command+64) (portable+offset) bytes t)
  if offset+bytes < 2048 then response 0 (offset+bytes) 0 0 t else
  if load64 portable t != 0x3154524f5046544c || load64 (portable+8) t != 1 ||
      load64 (portable+16) t > 1 || !validPreferences (portable+256) 0 t then response 9 0 0 0 t else
  -- Profile import restores no key, no moderator role and no federation grant.
  -- The destination must admit a newly created scoped identity independently.
  let t := if load64 (portable+16) t == 1 then copy (portable+256) preferences 1536 t else t
  response 0 2048 0 0 (copy (portable+32) (scope+768) 128 t)
 def dispatch (caller token length t : UInt64) : UInt64 :=
  let op := load64 command t
  let action := load64 (command+8) t
  if syscall 131 token 0 0 0 t != 0 || length < 64 || length > 960 || load64 (command+56) t != 1 then response 1 0 0 0 t else
  if op == 481 then
    if (load64 (incoming+16) t &&& 0x100000000) == 0 || length != 128 then response 1 0 0 0 t else
    response 0 0 0 0 (copy (command+64) scope 64 t)
  else if op != 480 then response 7 0 0 0 t else
  if load64 (st+128) t != 0 && !localAllowed (load64 (st+128) t) caller then response 1 0 0 0 t else
  let t := store64 (st+128) caller t
  if action == 0 then
    let t := header 0 (load64 st t) (load64 (st+8) t) (load64 (st+24) t)
      (load64 (st+32) t) (load64 (st+40) t) (load64 (st+192) t) t
    96+t+copy (publicIdentity+96) (wire+64) 32 (copy scope (wire+96) 64 t)
  else if action == 1 && length == 128 then createIdentity token t
  else if action == 2 then prepareDraft length t
  else if action == 3 then appendDraft length t
  else if action == 4 && length == 64 then publish token t
  else if (action == 5 && length == 64) || (action == 6 && length == 96) then query action length t
  else if action == 7 then preference length t
  else if action == 9 && length == 64 then lock t
  else if action == 10 && length == 64 then
    if load64 (st+32) t != 8 || load64 (st+64) t != 0 then response 3 0 0 0 t else
    if load64 (st+304) t != 0 then
      let t := store64 (st+272) 0 (store64 (st+280) 0 (store64 (st+288) 0 t))
      response 0 0 1 0 (reconcilePage 0 t)
    else
    if load64 (st+8) t == 0 || load64 (st+208) t == 0 then response 3 0 0 0 t else
    let r := persist (store64 (st+40) 0 t)
    if r == error then response 13 0 12 0 r else response 0 0 1 0 (beginUpload r)
  else if action == 11 && length == 64 && load64 (st+32) t == 6 && load64 (st+64) t == 0 then
    response 0 0 0 0 (pollUpload t)
  else if action == 12 then exportPortable length t
  else if action == 13 then importPortable length t
  else if action == 14 then retention length t
  else if action == 19 && length == 64 then
    let r := Guest.RegistrySDK.query (load64 (command+16) t) t
    if r != 832 then response 14 0 0 0 r else r
  else if action == 20 && length == 864 then
    let r := Guest.RegistrySDK.verify (command+64) (command+832) t
    if r != 832 || status r != 0 || !Guest.RegistrySDK.admitted (result r) then response 11 0 0 0 r else r
  else if action == 18 && length == 64 && load64 (command+16) t <= 1 && load64 (st+32) t == 0 then
    response 0 0 0 0 (store64 (st+176) (load64 (command+16) t) t)
  else if action == 16 && length == 64 then outcome t
  else if action == 17 && length == 64 then
    let phase := load64 (st+32) t
    let sending := (phase >= 1 && phase <= 5) || (phase == 8 && load64 (st+8) t != 0)
    let t := if load64 (st+64) t == 0 then t else net 42 (load64 (st+64) t) t
    let t := store64 (st+64) 0 t
    response 0 0 0 0 (if sending then failed 12 t else t)
  else response 7 0 0 0 t
partial def loop (t : UInt64) : UInt64 :=
  let n := syscall 36 (self t) incoming 1024 0 t
  let t := if n >= 96 && n <= 1024 then
      let token := load64 (incoming+8) n
      let r := dispatch (load64 incoming n) token (n-32) n
      reply token r r
    else n
  let t := pump t
  loop (Guest.WaitSDK.deadline (Guest.WaitSDK.now t+1) t)
def main (t : UInt64) : UInt64 := loop (zero st 64 (zero publicIdentity 36 (zero preferences 192 (zero scope 8 t))))
end Guest.FeedAccount
