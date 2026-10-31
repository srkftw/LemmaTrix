import Guest.LiveSDK
namespace Guest.MessengerSDK
open Guest.LiveSDK
-- Session-v1. This endpoint is a non-networked secret owner: callers submit
-- authorized content, never seeds, scalars or raw signing requests.
def profile : UInt64 := 1
def unsupported : UInt64 := 7
def identityChanged : UInt64 := 8
def unavailableRoute : UInt64 := 14
def locked : UInt64 := 5
def expiredAuthority : UInt64 := 3
def quota : UInt64 := 4
def integrity : UInt64 := 9
def reconciliation : UInt64 := 12
def invoke (operation length t : UInt64) : UInt64 :=
  let target := syscall 128 2 operation 0 0 t
  if target == error then error else syscall 30 target wire length 1024 target
-- Native asynchronous IPC preserves the same exact binding and generation as
-- invoke. One outstanding request per process; collect never blocks input.
def submit (role operation length t : UInt64) : UInt64 :=
  let target := syscall 128 role operation 0 0 t
  if target == error then error else syscall 133 target wire length 1024 target
def collect (token t : UInt64) : UInt64 := syscall 134 token wire 1024 0 t
def cancelRequest (token t : UInt64) : UInt64 := syscall 135 token 0 0 0 t
def inspect (t : UInt64) : UInt64 := invoke 420 64 (header 420 0 0 0 0 0 0 t)
def create (federation t : UInt64) : UInt64 :=
  invoke 421 96 (copy federation (wire+64) 32 (header 421 0 0 0 0 0 0 t))
def invitation (t : UInt64) : UInt64 := invoke 422 64 (header 422 0 0 0 0 0 0 t)
def importInvitation (bundle t : UInt64) : UInt64 :=
  invoke 423 320 (copy bundle (wire+64) 256 (header 423 0 0 0 0 0 0 t))
def importExtendedInvitation (bundle t : UInt64) : UInt64 :=
  invoke 423 384 (copy bundle (wire+64) 320 (header 423 0 0 0 0 0 0 t))
def importCertifiedInvitation (bundle t : UInt64) : UInt64 :=
  invoke 423 736 (copy bundle (wire+64) 672 (header 423 0 0 0 0 0 0 t))
def certifiedInvitation (t : UInt64) : UInt64 := invoke 434 64 (header 434 0 27 0 0 0 0 t)
def extendedInvitation (t : UInt64) : UInt64 := invoke 434 64 (header 434 0 12 0 0 0 0 t)
def approve (contact fingerprint t : UInt64) : UInt64 :=
  invoke 424 96 (copy fingerprint (wire+64) 32 (header 424 contact 0 0 0 0 0 t))
def block (contact t : UInt64) : UInt64 := invoke 425 64 (header 425 contact 0 0 0 0 0 t)
def compose (contact source bytes t : UInt64) : UInt64 :=
  if bytes == 0 || bytes > 512 then error else
  invoke 426 (64+bytes) (copy source (wire+64) bytes (header 426 contact bytes 0 0 0 0 t))
def outbox (message t : UInt64) : UInt64 := invoke 427 64 (header 427 message 0 0 0 0 0 t)
def receive (source bytes t : UInt64) : UInt64 :=
  if bytes == 0 || bytes > 960 then error else
  invoke 428 (64+bytes) (copy source (wire+64) bytes (header 428 0 bytes 0 0 0 0 t))
def read (cursor t : UInt64) : UInt64 := invoke 429 64 (header 429 cursor 0 0 0 0 0 t)
def cancel (message t : UInt64) : UInt64 := invoke 430 64 (header 430 message 0 0 0 0 0 t)
def lock (t : UInt64) : UInt64 := invoke 431 64 (header 431 0 0 0 0 0 0 t)
-- Domain2 uses independently authorized protected storage. mode0 creates,
-- mode1 recovers normal commits, mode2 imports history without old authority.
-- The32-byte unlock credential is not a messaging seed and is never exported.
def unlock (mode history credential t : UInt64) : UInt64 :=
  if mode > 2 || history > 1 then error else
  invoke 432 96 (copy credential (wire+64) 32 (header 432 mode history 0 0 0 0 t))
def forget (t : UInt64) : UInt64 := invoke 433 64 (header 433 0 0 0 0 0 0 t)
def beginAttachment (contact total title titleLength t : UInt64) : UInt64 :=
  if titleLength == 0 || titleLength > 256 then error else
  invoke 434 (64+titleLength) (copy title (wire+64) titleLength (header 434 contact 1 total 0 0 0 t))
def bindAttachmentRoot (attachment root t : UInt64) : UInt64 :=
  invoke 434 96 (copy root (wire+64) 32 (header 434 attachment 22 0 0 0 0 t))
def inspectTransfer (ordinal t : UInt64) : UInt64 :=
  if ordinal > 1 then error else invoke 434 64 (header 434 ordinal 21 0 0 0 0 t)
def sealAttachmentChunk (attachment index source bytes t : UInt64) : UInt64 :=
  if bytes == 0 || bytes > 512 then error else
  invoke 434 (64+bytes) (copy source (wire+64) bytes (header 434 attachment 2 index 0 0 0 t))
-- Staging exports no ciphertext. Commit once, then read exact cached bytes.
def stageAttachmentChunk (attachment index source bytes t : UInt64) : UInt64 :=
  if bytes == 0 || bytes > 512 then error else
  invoke 434 (64+bytes) (copy source (wire+64) bytes (header 434 attachment 16 index 0 0 0 t))
def commitAttachmentBatch (attachment t : UInt64) : UInt64 := invoke 434 64 (header 434 attachment 17 0 0 0 0 t)
def committedAttachmentChunk (attachment index t : UInt64) : UInt64 := invoke 434 64 (header 434 attachment 18 index 0 0 0 t)
-- A committed chunk response contains public random transferId32 followed by
-- ciphertext. Neither the UI nor coordinator receives the attachment key.
def openAttachmentChunk (attachment index source bytes t : UInt64) : UInt64 :=
  if bytes <= 16 || bytes > 528 then error else
  invoke 434 (64+bytes) (copy source (wire+64) bytes (header 434 attachment 3 index 0 0 0 t))
def forgetAttachment (attachment t : UInt64) : UInt64 := invoke 434 64 (header 434 attachment 4 0 0 0 0 t)
def inspectAttachment (attachment t : UInt64) : UInt64 := invoke 434 64 (header 434 attachment 5 0 0 0 0 t)
def publicPrekeyBundle (t : UInt64) : UInt64 := invoke 434 64 (header 434 0 23 0 0 0 0 t)
def prekeyClaimIdentity (contact t : UInt64) : UInt64 := invoke 434 64 (header 434 contact 25 0 0 0 0 t)
def acceptClaimedPrekey (contact message bundle t : UInt64) : UInt64 :=
  invoke 434 320 (copy bundle (wire+64) 256 (header 434 contact 24 message 0 0 0 t))
def retry (message t : UInt64) : UInt64 := invoke 435 64 (header 435 message 0 0 0 0 0 t)
-- Delivery-v1 is a separately admitted coordinator. These exact grants do not
-- expose raw Network.grant/send or mode selection to the graphical caller.
def delivery (operation length t : UInt64) : UInt64 :=
  let target := syscall 128 4 operation 0 0 t
  if target == error then error else syscall 30 target wire length 1024 target
-- Run before collecting a new initial ciphertext. Evidence6 means the broker
-- has durably claimed and the owner has authenticated the selected prekey;
-- an established session passes without spending another public OPK.
def prepareDelivery (message contact t : UInt64) : UInt64 :=
  delivery 460 64 (header 460 message 0 1 contact 0 3 t)
def deliver (message contact fresh commitment source bytes t : UInt64) : UInt64 :=
  if bytes == 0 || bytes > 896 then error else
  let t := header 460 message bytes 1 contact fresh 0 t
  let t := copy commitment (wire+64) 32 t
  delivery 460 (96+bytes) (copy source (wire+96) bytes t)
def deliveryStatus (message t : UInt64) : UInt64 := delivery 461 64 (header 461 message 0 0 0 0 0 t)
def cancelDelivery (message t : UInt64) : UInt64 := delivery 462 64 (header 462 message 0 0 0 0 0 t)
def fetchDelivery (t : UInt64) : UInt64 := delivery 463 64 (header 463 0 0 0 0 0 0 t)
def deliverAttachmentChunk (attachment index contact total fresh t : UInt64) : UInt64 :=
  if fresh > 1 then error else
  delivery 460 72 (store64 (wire+64) fresh (header 460 attachment index 1 contact total 2 t))
def fetchAttachmentChunk (attachment index id t : UInt64) : UInt64 :=
  delivery 463 96 (copy id (wire+64) 32 (header 463 attachment 1 index 0 0 0 t))
-- This acknowledgment is issued only after the separately authorized Objects
-- importer has completed canonical validation and atomic graph publication.
def acknowledgeImportedAttachment (attachment id t : UInt64) : UInt64 :=
  delivery 463 96 (copy id (wire+64) 32 (header 463 attachment 2 0 0 0 0 t))
def configureDelivery (owner t : UInt64) : UInt64 := delivery 464 64 (header 464 owner 0 0 0 0 0 t)
end Guest.MessengerSDK
