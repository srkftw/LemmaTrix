import Guest.AppIntent
import Guest.MessengerCrypto
import Guest.MessengerPolicy
import Guest.MessengerAttachment
import Guest.MessengerVault
import Guest.LiveSDK
import Guest.LiveMemory
import Guest.MessengerContactBinding
namespace Guest.MessengerSession
open Guest.LiveSDK
-- Rights-zero, non-networked role2. Four explicitly approved devices, eight
-- skipped keys/device, four volatile outboxes and eight volatile inbox records.
-- Personal retention requires an independently authorized domain2 credential.
-- Ephemeral restart destroys authority; history imports always require fresh keys.
def st : UInt64 := 0x650000
def bundle : UInt64 := 0x651000
-- Retained public certificate. The bundle's trailing draft area is deliberately
-- excluded by Vault.capture; this state-header extent is retained and cleared.
def contactCertificate : UInt64 := st+640
def contactAt (i : UInt64) : UInt64 := 0x652000+i*4096
def inboxAt (i : UInt64) : UInt64 := 0x656000+i*1024
def tentative : UInt64 := 0x658000
def packet : UInt64 := 0x659000
def plaintext : UInt64 := 0x659400
def associated : UInt64 := 0x659800
def temporary : UInt64 := 0x659a00
def messageKey : UInt64 := 0x659c00
def nextChain : UInt64 := 0x659c40
def random : UInt64 := 0x659d00
def hashed : UInt64 := 0x659e00
def bundleMagic : UInt64 := 0x31424d544c
def messageMagic : UInt64 := 0x314d4d544c
def err : UInt64 := 0xffffffffffffffff
def eq (a b n t : UInt64) : Bool := Guest.LiveMemory.equal a b n t
def hash (p n out t : UInt64) : UInt64 := Guest.MessengerCrypto.hash p n out t
def response (code h a b c d t : UInt64) : UInt64 := 64+header code h a b c d 0 t
def current (token t : UInt64) : Bool := syscall 131 token 0 0 0 t == 0
partial def authorizeAttachment (message i t : UInt64) : UInt64 :=
  if i == 2 then t else
  let a := Guest.MessengerAttachment.slotAt i
  let t := if load64 a t == 1 && load64 (a+24) t == message then store64 (a+120) 1 t else t
  authorizeAttachment message (i+1) t
def saveRollback (t : UInt64) : UInt64 :=
  let t := copy st 0x6e0000 32768 t
  copy (Guest.MessengerAttachment.slotAt 0) 0x6e8000 20480 t
def rollback (t : UInt64) : UInt64 :=
  let t := copy 0x6e0000 st 32768 t
  copy 0x6e8000 (Guest.MessengerAttachment.slotAt 0) 20480 t
def durable (t : UInt64) : UInt64 :=
  let r := Guest.MessengerVault.commit t
  if r == err then Guest.Effects.effectValue err (rollback r) else r
def clearWork (t : UInt64) : UInt64 :=
  let t := zero tentative 1024 t
  let t := zero associated 256 t
  let t := zero 0x6e0000 6656 t
  Guest.MessengerCrypto.clear (Guest.MessengerAttachment.clearScratch (Guest.MessengerContactBinding.clear t))
def fail (code t : UInt64) : UInt64 := response code 0 0 0 0 0 (clearWork t)
def draw (out t : UInt64) : UInt64 :=
  let r := syscall 130 0 out 32 0 t
  if r != 0 then err else r
partial def freeContact (i t : UInt64) : UInt64 :=
  if i == 4 then err else if load64 (contactAt i) t == 0 then i else freeContact (i+1) t
partial def findIdentity (identity i t : UInt64) : UInt64 :=
  if i == 4 then err else
  if load64 (contactAt i) t != 0 && eq identity (contactAt i+128) 32 t then i else findIdentity identity (i+1) t
partial def findOutbox (handle i t : UInt64) : UInt64 :=
  if i == 4 then err else
  if load64 (contactAt i+1600) t != 0 && load64 (contactAt i+1608) t == handle then i else findOutbox handle (i+1) t
partial def countContacts (i approved t : UInt64) : UInt64 :=
  if i == 4 then approved else countContacts (i+1) (approved+(if load64 (contactAt i) t == 2 then 1 else 0)) t
partial def countOutboxes (i count t : UInt64) : UInt64 :=
  if i == 4 then count else countOutboxes (i+1) (count+(if load64 (contactAt i+1600) t != 0 then 1 else 0)) t

def encodeKey (input out t : UInt64) : UInt64 := copy input (out+1) 32 (store8 out 5 t)
def exportBundle (t : UInt64) : UInt64 :=
  let t := header 0 1 256 0 0 0 0 t
  320+copy bundle (wire+64) 256 t

def create (caller token t : UInt64) : UInt64 :=
  if !Guest.MessengerPolicy.mayResumeSending true (load64 (st+416) t == 1) then fail 12 t else
  if load64 st t == 1 then exportBundle t else
  if Guest.Ed25519.nonzero (command+64) 32 0 t == 0 then fail 2 t else
  let t := zero st 512 t
  let t := copy (command+64) (st+256) 32 t
  let r := draw (st+32) t
  if r == err then fail 6 (zero st 512 r) else
  let r := draw (st+96) r
  if r == err then fail 6 (zero st 512 r) else
  let r := draw (st+160) r
  if r == err then fail 6 (zero st 512 r) else
  let r := draw (st+288) r
  if r == err then fail 6 (zero st 512 r) else
  let r := draw (st+512) r
  if r == err then fail 6 (zero st 512 r) else
  let r := draw (st+544) r
  if r == err then fail 6 (zero st 512 r) else
  let r := draw random r
  if r == err then fail 6 (zero st 512 r) else
  let r := draw (random+32) r
  if r == err || !current token r then fail 6 (zero st 512 r) else
  let t := Guest.MessengerCrypto.publicKey (st+32) (st+64) r
  let t := Guest.MessengerCrypto.publicKey (st+96) (st+128) t
  let t := Guest.MessengerCrypto.publicKey (st+160) (st+192) t
  let t := encodeKey (st+128) temporary t
  let t := Guest.MessengerCrypto.sign (st+32) temporary 33 random (st+320) t
  if t == err || !current token t then fail 6 (zero st 512 t) else
  let t := zero bundle 32 t
  let t := store64 bundle bundleMagic t
  let t := store64 (bundle+8) 1 t
  let t := store64 (bundle+16) 1 t
  let t := store64 (bundle+24) 1 t
  let t := copy (st+64) (bundle+32) 32 t
  let t := copy (st+128) (bundle+64) 32 t
  let t := copy (st+192) (bundle+96) 32 t
  let t := copy (st+320) (bundle+128) 64 t
  let t := copy (st+256) (bundle+192) 64 t
  let t := store64 st 1 t
  let t := store64 (st+224) 1 t
  let t := store64 (st+8) 1 t
  let t := store64 (st+24) caller t
  exportBundle (clearWork t)

def validBundle (b t : UInt64) : Bool :=
  load64 b t == bundleMagic && load64 (b+8) t == 1 && load64 (b+16) t > 0 &&
  load64 (b+24) t <= 1 && eq (b+192) (st+256) 32 t &&
  Guest.Ed25519.nonzero (b+32) 32 0 t != 0 && Guest.Ed25519.nonzero (b+64) 32 0 t != 0 &&
  Guest.Ed25519.nonzero (b+224) 32 0 t != 0

def importInvitation (token extended t : UInt64) : UInt64 :=
  let b := command+64
  let known := findIdentity (b+32) 0 t
  let slot := if known != err then known else freeContact 0 t
  if !validBundle b t then fail 2 t else
  if slot == err then fail 4 t else
  let c := contactAt slot
  if extended == 2 && !Guest.MessengerContactBinding.valid (b+320) b t then fail 9 t else
  if known != err && !Guest.MessengerContactBinding.refreshAllowed
      (Guest.MessengerContactBinding.nonzero (c+3200) 352 t)
      (extended == 2) (extended == 2 && eq (c+3200) (b+320) 352 t) then fail 8 t else
  -- Exact accepted device keys never change through a directory refresh.
  if known != err && (!eq (c+96) b 256 t ||
      (extended != 0 && Guest.Ed25519.nonzero (c+3072) 64 0 t != 0 && !eq (c+3072) (b+256) 64 t)) then fail 8 t else
  let t := encodeKey (b+64) temporary t
  if !Guest.MessengerCrypto.verify (b+32) temporary 33 (b+128) t || !current token t then fail 9 t else
  let t := copy (b+32) temporary 32 t
  let t := copy (b+192) (temporary+32) 64 t
  let t := hash temporary 96 hashed t
  let t := if known == err then zero c 512 t else t
  let t := copy b (c+96) 256 t
  let wasBound := Guest.MessengerContactBinding.nonzero (c+3200) 352 t
  let t := if extended != 0 then copy (b+256) (c+3072) 64 t else t
  let t := if extended == 2 then copy (b+320) (c+3200) 352 t else t
  let t := copy hashed (c+64) 32 t
  let t := if known == err || (extended == 2 && !wasBound && load64 c t == 2) then store64 c 1 t else t
  let t := header 0 (slot+1) 1 (if extended == 2 then 1 else 0) 0 0 0 t
  96+copy (c+64) (wire+64) 32 (clearWork t)

def approve (t : UInt64) : UInt64 :=
  let slot := load64 (command+8) t
  if slot == 0 || slot > 4 then fail 2 t else
  let c := contactAt (slot-1)
  if !Guest.MessengerPolicy.canApprove (load64 c t) (load64 st t) (eq (c+64) (command+64) 32 t) then fail 8 t else
  let t := saveRollback t
  let r := durable (store64 c 2 t)
  if r == err then fail 13 r else response 0 slot 2 0 0 0 (clearWork r)

def adHash (c sender t : UInt64) : UInt64 :=
  let t := encodeKey (if sender == 1 then st+64 else c+128) associated t
  let t := encodeKey (if sender == 1 then c+128 else st+64) (associated+33) t
  let t := copy (st+256) (associated+66) 32 t
  let t := copy (if sender == 1 then st+288 else c+320) (associated+98) 32 t
  let t := copy (if sender == 1 then c+320 else st+288) (associated+130) 32 t
  hash associated 162 (c+352) t

def initAlice (c t : UInt64) : UInt64 :=
  let r := draw random t
  if r == err then err else
  let t := Guest.MessengerCrypto.publicKey random (c+1536) r
  let r := Guest.MessengerCrypto.x3dh (st+32) random (c+128) (c+160) (c+192) (2+load64 (c+120) t) (c+384) t
  if r == err then err else
  let r := draw (c+416) r
  if r == err then err else
  let t := Guest.MessengerCrypto.publicKey (c+416) (c+448) r
  let t := copy (c+160) (c+480) 32 t
  let r := Guest.MessengerCrypto.root (c+384) (c+416) (c+480) temporary t
  if r == err then err else
  let t := copy temporary (c+384) 32 r
  -- root output is RK||CKs; private DH lives at416 and must be preserved.
  let t := copy (temporary+32) (c+512) 32 t
  let t := store64 (c+576) 1 t
  let t := store64 (c+16) 1 t
  adHash c 1 t

def queue (token t : UInt64) : UInt64 :=
  let slot := load64 (command+8) t
  let n := load64 (command+16) t
  if slot == 0 || slot > 4 || n == 0 || n > 512 then fail 2 t else
  let c := contactAt (slot-1)
  if !Guest.MessengerPolicy.contactAllowed (load64 c t) then fail 8 t else
  if !Guest.MessengerPolicy.mayResumeSending true (load64 (st+416) t == 1) then fail 12 t else
  if load64 (c+1600) t != 0 && load64 (c+2400) t != 1 then fail 4 t else
  let serial := load64 (st+16) t+1
  if serial > 0xffffffff || !current token t then fail 4 t else
  let t := store64 (st+16) serial t
  let t := store64 (c+1600) 1 t
  let t := store64 (c+1608) serial t
  let t := store64 (c+1616) n t
  let t := store64 (c+1624) 1 t
  let t := store64 (c+2400) 0 t
  let t := copy (command+64) (c+1664) n t
  response 0 serial 1 n 0 0 t

def makeHeader (c n t : UInt64) : UInt64 :=
  let t := zero packet 24 t
  let t := store64 packet messageMagic t
  let t := store64 (packet+8) 1 t
  let t := store64 (packet+16) (if load64 (c+16) t == 1 then 1 else 2) t
  let t := store64 (packet+24) n t
  let t := store64 (packet+32) (load64 (st+8) t) t
  let t := store64 (packet+40) (if load64 (c+16) t == 1 then load64 (c+120) t else 0) t
  let t := store64 (packet+48) (load64 (c+40) t) t
  let t := store64 (packet+56) (load64 (c+24) t) t
  let t := copy (c+448) (packet+64) 32 t
  let t := copy (st+64) (packet+96) 32 t
  let t := if load64 (c+16) t == 1 then copy (c+1536) (packet+128) 32 t else t
  let t := store64 (packet+160) 1 t
  store64 (packet+168) (load64 (c+1624) t) t

def aad (c t : UInt64) : UInt64 :=
  let t := copy (c+352) associated 32 t
  copy packet (associated+32) 192 t

def encryptPending (c token t : UInt64) : UInt64 :=
  -- Only a current exact network coordinator may install this claim marker.
  -- It and the authenticated public prekey are durably committed by434/24.
  if !Guest.MessengerPolicy.initialSendAllowed (load64 (c+16) t)
      (load64 (c+1608) t) (load64 (c+3136) t) then fail 12 t else
  let t := copy c tentative 4096 t
  let n := load64 (tentative+1616) t
  let t := copy (tentative+1664) plaintext n t
  let r := if load64 (tentative+16) t == 0 then initAlice tentative t else t
  if r == err then fail 6 r else
  if load64 (tentative+576) r != 1 || load64 (tentative+24) r >= 1048576 then fail 12 r else
  let t := makeHeader tentative n r
  let t := Guest.MessengerCrypto.chain (tentative+512) nextChain messageKey t
  let t := aad tentative t
  let t := zero Guest.MessengerCrypto.nonce 2 t
  let t := Guest.VaultCrypto.encrypt messageKey Guest.MessengerCrypto.nonce associated 224 plaintext n (packet+192) t
  let t := hash packet (208+n) hashed t
  let t := copy nextChain (tentative+512) 32 t
  let t := store64 (tentative+24) (load64 (tentative+24) t+1) t
  let t := copy hashed (tentative+1632) 32 t
  let t := copy packet (tentative+1664) (208+n) t
  let t := store64 (tentative+1616) (208+n) t
  let t := store64 (tentative+1600) 2 t
  -- Volatile commit installs next state and exact ciphertext before publication.
  -- Retained sends remain unavailable targetCount the isolated domain2 commit exists.
  if !current token t then fail 3 t else
  let t := saveRollback t
  let t := copy tentative c 4096 t
  let t := authorizeAttachment (load64 (c+1608) t) 0 t
  let r := durable t
  if r == err then fail 13 r else
  let t := r
  if !Guest.MessengerPolicy.canPublishSend (load64 st t == 1) (load64 c t == 2) (load64 (c+1600) t == 2) then fail 3 t else
  let t := header 0 (load64 (c+1608) t) (load64 (c+1616) t) 2 ((c-contactAt 0)/4096+1) 0 0 t
  let length := load64 (c+1616) t
  64+length+copy (c+1664) (wire+64) length (clearWork t)

def poll (token t : UInt64) : UInt64 :=
  let slot := findOutbox (load64 (command+8) t) 0 t
  if slot == err then fail 3 t else
  let c := contactAt slot
  if load64 (c+1600) t == 1 then encryptPending c token t else
  let n := load64 (c+1616) t
  let t := header 0 (load64 (c+1608) t) n 2 (slot+1) 0 0 t
  64+n+copy (c+1664) (wire+64) n t

def initBob (c t : UInt64) : UInt64 :=
  let hasOne := load64 (packet+40) t
  if hasOne > 1 || (hasOne == 1 && load64 (st+224) t != 1) || load64 (packet+160) t != 1 then err else
  let r := Guest.MessengerCrypto.x3dh (st+32) (st+96) (packet+96) (packet+128) (st+160) hasOne (c+384) t
  if r == err then err else
  let t := copy (st+96) (c+416) 32 r
  let t := copy (st+128) (c+448) 32 t
  let t := copy (packet+128) (c+1536) 32 t
  let t := store64 (c+16) 2 t
  adHash c 0 t

partial def freeSkipped (c i t : UInt64) : UInt64 :=
  if i == 8 then err else if load64 (c+640+i*96) t == 0 then c+640+i*96 else freeSkipped c (i+1) t
partial def findSkipped (c publicKey n i t : UInt64) : UInt64 :=
  if i == 8 then err else
  let p := c+640+i*96
  if load64 p t == 1 && load64 (p+8) t == n && eq (p+16) publicKey 32 t then p else findSkipped c publicKey n (i+1) t
partial def skip (c targetCount t : UInt64) : UInt64 :=
  let nr := load64 (c+32) t
  if targetCount < nr || targetCount-nr > 8 then err else
  if load64 (c+584) t != 1 || nr == targetCount then t else
  let slot := freeSkipped c 0 t
  if slot == err then err else
  let t := Guest.MessengerCrypto.chain (c+544) nextChain (slot+48) t
  let t := copy nextChain (c+544) 32 t
  let t := store64 slot 1 t
  let t := store64 (slot+8) nr t
  let t := copy (c+480) (slot+16) 32 t
  skip c targetCount (store64 (c+32) (nr+1) t)

def dhRatchet (c t : UInt64) : UInt64 :=
  let t := store64 (c+40) (load64 (c+24) t) t
  let t := store64 (c+24) 0 t
  let t := store64 (c+32) 0 t
  let t := copy (packet+64) (c+480) 32 t
  let r := Guest.MessengerCrypto.root (c+384) (c+416) (c+480) temporary t
  if r == err then err else
  let t := copy temporary (c+384) 32 r
  let t := copy (temporary+32) (c+544) 32 t
  let r := draw (c+416) t
  if r == err then err else
  let t := Guest.MessengerCrypto.publicKey (c+416) (c+448) r
  let r := Guest.MessengerCrypto.root (c+384) (c+416) (c+480) temporary t
  if r == err then err else
  let t := copy temporary (c+384) 32 r
  let t := copy (temporary+32) (c+512) 32 t
  let t := store64 (c+576) 1 t
  store64 (c+584) 1 t

partial def duplicate (commitment i t : UInt64) : UInt64 :=
  if i == 8 then err else
  let p := inboxAt i
  if load64 p t != 0 && eq (p+32) commitment 32 t then p else duplicate commitment (i+1) t

def finishReceive (c slot plen contentKind token fresh t : UInt64) : UInt64 :=
  let serial := load64 (st+400) t+1
  if serial == 0 || !current token t then fail 3 t else
  let p := inboxAt ((serial-1)%8)
  -- No mailbox acknowledgment may precede the authenticated state commit;
  -- retained mode durably publishes protocol, inbox policy and dedup together.
  let t := saveRollback t
  let attachmentHandle := if contentKind == 2 then 0x100000000+load64 (st+408) t+1 else 0
  let r := if contentKind == 2 then
    if plen <= 128 then err else Guest.MessengerAttachment.accept attachmentHandle plaintext t else t
  if r == err then fail 4 (rollback r) else
  let t := if contentKind == 2 then store64 (st+408) (attachmentHandle-0x100000000) r else r
  let t := store64 (tentative+16) 2 t
  let t := copy tentative c 4096 t
  let t := zero p 128 t
  let t := store64 p 1 t
  let t := store64 (p+8) serial t
  let t := store64 (p+16) (slot+1) t
  let shownLength := if contentKind == 2 then plen-128 else plen
  let t := store64 (p+24) shownLength t
  let t := store64 (p+576) attachmentHandle t
  let t := copy hashed (p+32) 32 t
  let t := copy (if contentKind == 2 then plaintext+128 else plaintext) (p+64) shownLength t
  let t := store64 (st+400) serial t
  let t := if fresh == 1 && load64 (packet+40) t == 1 then
    zero (st+160) 4 (zero (bundle+96) 4 (store64 (bundle+24) 0 (store64 (st+224) 0 t))) else t
  let r := durable t
  if r == err then fail 13 r else
  let t := r
  if !Guest.MessengerPolicy.canAcknowledge true (load64 p t == 1) then fail 3 t else
  response 0 serial 1 (slot+1) plen 0 (clearWork t)

def receiveMessage (token length t : UInt64) : UInt64 :=
  let n := load64 (command+16) t
  if n < 209 || n > 720 || length != 64+n then fail 2 t else
  let t := copy (command+64) packet n t
  let plen := load64 (packet+24) t
  let kind := load64 (packet+16) t
  let contentKind := load64 (packet+168) t
  let slot := findIdentity (packet+96) 0 t
  if load64 packet t != messageMagic || load64 (packet+8) t != 1 ||
      (kind != 1 && kind != 2) || (contentKind != 1 && contentKind != 2) || plen == 0 || plen > 512 || n != 208+plen || slot == err ||
      load64 (packet+56) t >= 1048576 || load64 (packet+48) t >= 1048576 then fail 2 t else
  let c := contactAt slot
  if load64 c t != 2 || load64 (packet+32) t != load64 (c+112) t then fail 8 t else
  let t := hash packet n hashed t
  let previous := duplicate hashed 0 t
  if previous != err then response 10 (load64 (previous+8) t) 1 0 0 0 (clearWork t) else
  let t := copy c tentative 4096 t
  let fresh := load64 (tentative+16) t == 0
  if fresh && kind != 1 then fail 12 t else
  if !fresh && kind == 1 && (load64 (tentative+16) t == 1 || !eq (packet+128) (tentative+1536) 32 t) then fail 12 t else
  let r := if fresh then initBob tentative t else t
  if r == err then fail 12 r else
  let skipped := findSkipped tentative (packet+64) (load64 (packet+56) r) 0 r
  let r := if skipped != err then copy (skipped+48) messageKey 32 r else
    let r := if eq (packet+64) (tentative+480) 32 r then r else
      let r := skip tentative (load64 (packet+48) r) r
      if r == err then err else dhRatchet tentative r
    if r == err then err else
    let r := skip tentative (load64 (packet+56) r) r
    if r == err || load64 (tentative+584) r != 1 then err else
    let t := Guest.MessengerCrypto.chain (tentative+544) nextChain messageKey r
    let t := copy nextChain (tentative+544) 32 t
    store64 (tentative+32) (load64 (tentative+32) t+1) t
  if r == err then fail 12 r else
  let t := aad tentative r
  let t := zero Guest.MessengerCrypto.nonce 2 t
  let authenticated := Guest.VaultCrypto.decrypt messageKey Guest.MessengerCrypto.nonce associated 224 (packet+192) plen plaintext t
  if authenticated == err then fail 9 authenticated else
  let t := if skipped != err then zero skipped 12 authenticated else authenticated
  finishReceive c slot plen contentKind token (if fresh then 1 else 0) t

def readMessage (t : UInt64) : UInt64 :=
  let cursor := load64 (command+8) t
  let newest := load64 (st+400) t
  let first := if newest > 8 then newest-7 else 1
  let serial := if cursor == 0 then first else cursor
  if serial < first then fail 12 t else
  if serial > newest then fail 3 t else
  let p := inboxAt ((serial-1)%8)
  if load64 (p+8) t != serial || load64 p t != 1 then fail 12 t else
  let n := load64 (p+24) t
  let t := header 0 serial n (load64 (p+16) t) 1 (load64 (p+576) t) 0 t
  64+n+copy (p+64) (wire+64) n t

-- Branch-local frames preserve the existing protocol and guards while keeping
-- the secret owner within the ordinary256KiB code profile.
@[noinline] def attachmentClaim (rights token length h t : UInt64) : UInt64 :=
  if (rights &&& 1024) == 0 then fail 1 t else
  if h == 0 || h > 4 || length != 320 then fail 2 t else
  let c := contactAt (h-1)
  let b := command+64
  if load64 c t != 2 then fail 8 t else
  if load64 (c+16) t != 0 || load64 (c+1600) t != 1 ||
    load64 (command+24) t != load64 (c+1608) t then fail 12 t else
  if !validBundle b t || !eq (b+32) (c+128) 32 t || !eq (b+192) (c+288) 64 t ||
    load64 (b+16) t != load64 (c+112) t ||
    (load64 (b+24) t == 1 && Guest.Ed25519.nonzero (b+96) 32 0 t == 0) then fail 8 t else
  let t := encodeKey (b+64) temporary t
  if !Guest.MessengerCrypto.verify (b+32) temporary 33 (b+128) t || !current token t then fail 9 t else
  let t := saveRollback t
  let t := copy (b+64) (c+160) 128 t
  let t := store64 (c+3136) (load64 (c+1608) t) t
  let r := durable (store64 (c+120) (load64 (b+24) t) t)
  if r == err then fail 13 r else response 0 h (load64 (c+120) r) 0 0 0 (clearWork r)

@[noinline] def attachmentBegin (token length h t : UInt64) : UInt64 :=
  let total := load64 (command+24) t
  let titleLength := length-64
  if h == 0 || h > 4 || titleLength == 0 || titleLength > 256 then fail 2 t else
  let c := contactAt (h-1)
  if !Guest.MessengerPolicy.contactAllowed (load64 c t) then fail 8 t else
  if load64 (c+1600) t != 0 && load64 (c+2400) t != 1 then fail 4 t else
  let serial := load64 (st+16) t+1
  let transferId := 0x100000000+load64 (st+408) t+1
  if serial > 0xffffffff || transferId >= 0x200000000 then fail 4 t else
  let t := saveRollback t
  let r := Guest.MessengerAttachment.create transferId total plaintext t
  if r == err || !current token r then fail 4 (rollback r) else
  let t := store64 (st+16) serial r
  let t := store64 (st+408) (transferId-0x100000000) t
  let a := Guest.MessengerAttachment.find transferId 0 t
  let t := store64 (a+16) h t
  let t := store64 (a+24) serial t
  let t := store64 (c+1600) 1 t
  let t := store64 (c+1608) serial t
  let t := store64 (c+1616) (128+titleLength) t
  let t := store64 (c+1624) 2 t
  let t := store64 (c+2400) 0 t
  let t := copy plaintext (c+1664) 128 t
  let t := copy (command+64) (c+1792) titleLength t
  response 0 serial transferId total 0 0 (clearWork t)

@[noinline] def attachmentSlots (rights _token length h action t : UInt64) : UInt64 :=
  let a := Guest.MessengerAttachment.find h 0 t
  let index := load64 (command+24) t
  let n := length-64
  if a == err then fail 3 t else
  if action == 22 && length == 96 then
    let contact := load64 (a+16) t
    if load64 a t != 1 || contact == 0 || contact > 4 || load64 (a+120) t != 0 ||
      Guest.Ed25519.nonzero (command+64) 32 0 t == 0 then fail 8 t else
    let c := contactAt (contact-1)
    if load64 c t != 2 || load64 (c+1600) t != 1 || load64 (c+1608) t != load64 (a+24) t then fail 3 t else
    let t := copy (command+64) (a+128) 32 t
    response 0 h 32 0 0 0 (copy (command+64) (c+1760) 32 t)
  else if action == 2 || action == 3 || action == 16 then
    if action != 3 && (n != Guest.MessengerAttachment.chunkLength a index t || n == 0) then fail 2 t else
    let t := saveRollback t
    let r := if action != 3 then Guest.MessengerAttachment.sealChunk a index (command+64) n plaintext t
      else Guest.MessengerAttachment.openChunk a index (command+64) n plaintext t
    if r == err then fail 9 r else
    if action == 16 then response 0 h 0 index (load64 (a+96) r) 0 (clearWork r) else
    let r := if action == 2 then durable (store64 (a+112) (load64 (a+104) r) r) else r
    if r == err then fail 13 r else
    let outputLength := if action == 3 then n-16 else n+16
    let t := header 0 h outputLength index (load64 (a+96) r) 0 0 r
    let t := copy plaintext (wire+64) outputLength t
    64+outputLength+clearWork t
  else if action == 4 then
    let t := saveRollback t
    let r := durable (zero a 1280 t)
    if r == err then fail 13 r else response 0 h 0 0 0 0 (clearWork r)
  else if action == 5 then
    let t := header 0 h (load64 a t) (load64 (a+96) t) (load64 (a+104) t) 512 (load64 (a+112) t) t
    let t := copy (a+64) (wire+64) 32 t
    128+copy (a+128) (wire+96) 32 t
  else if action == 17 && length == 64 && load64 a t == 1 then
    let t := saveRollback t
    let r := durable (store64 (a+112) (load64 (a+104) t) t)
    if r == err then fail 13 r else response 0 h (load64 (a+112) r) 0 0 0 (clearWork r)
  else if action == 18 && length == 64 then
    let contact := load64 (a+16) t
    if (rights &&& 1024) != 0 && (contact == 0 || contact > 4 || load64 (a+120) t != 1 ||
      load64 (contactAt (contact-1)) t != 2) then fail 8 t else
    let r := Guest.MessengerAttachment.committedChunk a index plaintext t
    if r == err then fail 12 r else
    let n := Guest.MessengerAttachment.chunkLength a index r+16
    let t := header 0 h n index (load64 (a+96) r) (load64 (a+112) r) 0 r
    let t := copy (a+64) (wire+64) 32 t
    let t := copy plaintext (wire+96) n t
    96+n+clearWork t
  else fail 2 t

def attachment (rights token length t : UInt64) : UInt64 :=
  let action := load64 (command+16) t
  let h := load64 (command+8) t
  -- A network coordinator's434 grant is only a scoped capability-export
  -- consumer. It can never invoke plaintext attachment decryption or creation.
  if !Guest.MessengerPolicy.attachmentActionAllowed rights action then fail 1 t else
  if action == 10 then
    let t := copy (bundle+224) (wire+64) 32 t
    let t := hash (st+512) 32 (wire+96) t
    let t := hash (st+544) 32 (wire+128) t
    160+header 0 0 96 0 0 0 0 (clearWork t)
  else if action == 11 then
    if (rights &&& 1024) == 0 then fail 1 t else
    let t := copy (bundle+224) (wire+64) 32 t
    let t := copy (st+512) (wire+96) 96 t
    192+header 0 0 128 0 0 0 0 (clearWork t)
  else if action == 12 then
    let t := copy bundle (wire+64) 256 t
    let t := copy (st+512) (wire+320) 32 t
    let t := copy (st+576) (wire+352) 32 t
    384+header 0 0 320 2 0 0 0 (clearWork t)
  else if action == 13 then
    if length != 96 || Guest.Ed25519.nonzero (command+64) 32 0 t == 0 then fail 2 t else
    let t := saveRollback t
    let r := durable (copy (command+64) (st+576) 32 t)
    if r == err then fail 13 r else response 0 0 32 0 0 0 (clearWork r)
  else if action == 14 then
    if (rights &&& 1024) == 0 then fail 1 t else
    if h == 0 || h > 4 then fail 2 t else
    let c := contactAt (h-1)
    if load64 c t != 2 || Guest.Ed25519.nonzero (c+3072) 64 0 t == 0 then fail 8 t else
    let t := copy (c+320) (wire+64) 32 t
    let t := copy (c+3072) (wire+96) 64 t
    160+header 0 h 96 0 0 0 0 (clearWork t)
  else if action == 15 then
    if h == 0 || h > 4 || length != 64 then fail 2 t else
    let c := contactAt (h-1)
    if load64 c t == 0 then fail 3 t else
    let committed := load64 c t == 2 && load64 (c+1600) t == 2 && load64 (c+1624) t == 1
    let t := header 0 h (load64 c t)
      (if Guest.MessengerContactBinding.nonzero (c+3200) 352 t then 1 else 0)
      (if committed then load64 (c+1608) t else 0)
      (if committed then 2 else 0) (if committed then load64 (c+1616) t else 0) t
    96+copy (c+64) (wire+64) 32 t
  else if action == 21 then
    if h >= 2 || length != 64 then fail 2 t else
    let a := Guest.MessengerAttachment.slotAt h
    if load64 a t == 0 then fail 3 t else
    let t := header 0 (load64 (a+8) t) (load64 a t) (load64 (a+16) t)
      (load64 (a+96) t) (load64 (a+104) t) (load64 (a+112) t) t
    let t := copy (a+64) (wire+64) 32 t
    128+copy (a+128) (wire+96) 32 t
  else if action == 26 then
    if length != 416 || !Guest.MessengerContactBinding.valid (command+64) bundle t then fail 9 t else
    if Guest.MessengerContactBinding.nonzero contactCertificate 352 t &&
        !eq contactCertificate (command+64) 352 t then fail 8 t else
    let t := saveRollback t
    let r := durable (copy (command+64) contactCertificate 352 t)
    if r == err then fail 13 r else response 0 0 352 2 0 0 (clearWork r)
  else if action == 27 then
    if length != 64 || !Guest.MessengerContactBinding.nonzero contactCertificate 352 t then fail 3 t else
    let t := copy bundle (wire+64) 256 t
    let t := copy (st+512) (wire+320) 32 t
    let t := copy (st+576) (wire+352) 32 t
    let t := copy contactCertificate (wire+384) 352 t
    736+header 0 0 672 3 0 0 0 (clearWork t)
  else if action == 23 then
    if length != 64 || Guest.Ed25519.nonzero (st+576) 32 0 t == 0 then fail 8 t else exportBundle t
  else if action == 25 then
    if h == 0 || h > 4 || length != 64 then fail 2 t else
    let c := contactAt (h-1)
    if load64 c t != 2 then fail 8 t else
    let t := zero temporary 16 t
    let t := store64 temporary 0x3344582d544c t
    let t := copy (st+288) (temporary+8) 32 t
    let t := copy (c+320) (temporary+40) 32 t
    let t := store64 (temporary+72) (load64 (c+1608) t) t
    let t := store64 (temporary+80) (load64 (st+8) t) t
    let t := hash temporary 88 (wire+64) t
    96+header 0 h (load64 (c+16) t) (load64 (c+1608) t)
      (load64 (c+112) t) (load64 (c+120) t) 0 (clearWork t)
  else if action == 24 then attachmentClaim rights token length h t
  else if action == 20 then
    if (rights &&& 1024) == 0 || length != 96 then fail 1 t else
    let slot := findOutbox h 0 t
    if slot == err then fail 3 t else
    let c := contactAt slot
    if load64 c t != 2 || load64 (c+1600) t != 2 || !eq (command+64) (c+1632) 32 t then fail 9 t else
    let t := saveRollback t
    let r := durable (store64 (c+2400) 1 t)
    if r == err then fail 13 r else response 0 h 2 0 0 0 (clearWork r)
  else if action == 1 then attachmentBegin token length h t
  else attachmentSlots rights token length h action t

def lock (t : UInt64) : UInt64 :=
  let t := Guest.AppIntent.clear t
  let t := Guest.MessengerAttachment.clear (zero st 4096 t)
  let t := Guest.MessengerVault.clear t
  response 0 0 0 0 0 0 (clearWork t)

def intentRefresh (t : UInt64) : UInt64 :=
  let p := Guest.AppIntent.find (load64 (command+16) t) 0 t
  if p == 0 || load64 p t < 3 || load64 p t > 5 then t else
  let target := syscall 128 4 461 0 0 t
  if target == err then t else
  let r := syscall 30 target wire 64 1024 (header 461 (load64 (p+56) target) 0 0 0 0 0 target)
  if r != 64 || status r != 0 then t else
  let evidence := load64 (wire+16) r
  Guest.AppIntent.evidence (load64 (p+8) r) (if evidence == 3 then 5 else if evidence == 2 then 4 else 3) evidence r
def intentApprove (token length t : UInt64) : UInt64 :=
  let handle := load64 (command+8) t
  let destination := load64 (command+24) t
  let bytes := length-64
  let p := Guest.AppIntent.approve (load64 (st+8) t) handle destination (command+64) bytes t
  if p == err then fail 9 t else
  if Guest.AppIntent.cacheFind (p+128) (load64 (p+24) t) 0 t == 0 && Guest.AppIntent.cacheVacant 0 t == 0 then fail 4 t else
  let t := store64 (command+8) destination (store64 (command+16) bytes t)
  let r := queue token t
  if status r != 0 then r else
  let t := Guest.AppIntent.reserveCommit p (load64 (st+16) r) r
  64+Guest.AppIntent.committed p (load64 (st+16) t) t
def dispatch (caller rights token length t : UInt64) : UInt64 :=
  let op := load64 command t
  if length < 64 || length > 784 || load64 (command+56) t != 1 || !current token t then fail 2 t else
  if op == 436 then Guest.AppIntent.request (load64 (st+8) t) caller token op length (intentRefresh t) else
  if op == 420 then response 0 (load64 st t) (countContacts 0 0 t) (countOutboxes 0 0 t)
    (load64 (st+400) t) (load64 Guest.MessengerVault.state t) t else
  if op == 421 then if length == 96 then create caller token t else fail 2 t else
  if op == 431 then lock t else
  if op == 433 then
    let r := Guest.MessengerVault.forget t
    if r == err then fail 13 r else lock r else
  if op == 432 then
    if length != 96 || load64 (command+8) t > 2 || load64 (command+16) t > 1 then fail 2 t else
    let mode := load64 (command+8) t
    if mode == 0 && load64 st t != 1 then fail 5 t else
    let r := Guest.MessengerVault.unlock (command+64) mode (load64 (command+16) t) t
    if r == err then fail 13 (Guest.MessengerVault.clear r) else
    if mode == 0 then response 0 1 1 0 0 0 (clearWork r) else
    let t := Guest.MessengerVault.restore r
    if mode == 2 then
      -- Supported older-backup import is history only: no stale identity,
      -- session, prekey, outbox, attachment nonce or sending authority survives.
      let retired := Guest.MessengerVault.retireForHistory t
      if retired == err then fail 13 (lock retired) else
      let historySerial := load64 (st+400) retired
      let t := zero st 3072 (Guest.AppIntent.clear retired)
      let t := store64 (st+400) historySerial t
      let t := store64 (st+416) 1 t
      let t := Guest.MessengerAttachment.clear t
      let t := Guest.MessengerVault.clear t
      response 0 0 0 0 0 1 (clearWork t)
    else response 0 1 1 0 0 0 (clearWork t) else
  if op == 429 && load64 (st+416) t == 1 then readMessage t else
  if load64 st t != 1 then fail 5 t else
  -- Kernel exact caller/service/operation grants are required independently.
  -- Administrative mediation and UI plaintext commands never export secrets.
  if rights == err || caller == 0 then fail 1 t else
  if op == 422 then exportBundle t
  else if op == 423 then if length == 320 || length == 384 || length == 736 then
    importInvitation token (if length == 736 then 2 else if length == 384 then 1 else 0) t else fail 2 t
  else if op == 424 then if length == 96 then approve t else fail 2 t
  else if op == 425 then
    let slot := load64 (command+8) t
    if slot == 0 || slot > 4 then fail 2 t else
    let t := saveRollback t
    let r := durable (zero (contactAt (slot-1)+352) 468 (store64 (contactAt (slot-1)) 3 t))
    if r == err then fail 13 r else response 0 slot 3 0 0 0 (clearWork r)
  else if op == 426 then if length == 64+load64 (command+16) t then queue token t else fail 2 t
  else if op == 427 || op == 435 then poll token t
  else if op == 428 then receiveMessage token length t
  else if op == 429 then readMessage t
  else if op == 430 then
    let slot := findOutbox (load64 (command+8) t) 0 t
    if slot == err then fail 3 t else
    let t := saveRollback t
    let r := durable (zero (contactAt slot+1600) 128 t)
    if r == err then fail 13 r else response 0 (load64 (command+8) r) 0 0 0 0 (clearWork r)
  else if op == 434 && load64 (command+16) t >= 28 && load64 (command+16) t <= 30 then
    if (rights &&& 1024) != 0 || (rights &&& 512) == 0 then fail 1 t else
    if load64 (command+16) t == 28 && length == 64 then Guest.AppIntent.review (load64 (st+8) t) t else
    if load64 (command+16) t == 29 && length > 64 then intentApprove token length t else
    if load64 (command+16) t == 30 && length == 64 then Guest.AppIntent.reject (load64 (command+8) t) t else fail 2 t
  else if op == 434 then attachment rights token length t
  else fail 7 t

partial def serve (t : UInt64) : UInt64 :=
  let n := receive (self t) t
  if n == err then serve (clearWork n) else
  let token := load64 (incoming+8) n
  let result := if n >= 96 && load64 (incoming+24) n == 2 then
    dispatch (load64 incoming n) (load64 (incoming+16) n) token (n-32) n else fail 2 n
  let t := reply token result result
  serve (zero incoming 128 (zero wire 128 (clearWork t)))
def main (t : UInt64) : UInt64 :=
  let t := Guest.AppIntent.clear t
  serve (lock t)
end Guest.MessengerSession
