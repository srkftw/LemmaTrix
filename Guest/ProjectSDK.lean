import Guest.LiveSDK
import Guest.WaitSDK
namespace Guest.ProjectSDK
open Guest.LiveSDK
-- A stable ID is32 bytes of content identity. Operational handles remain caller-
-- and incarnation-bound. The wrappers contain all protocol token sequencing.
def nodeMetadata (node t : UInt64) : UInt64 := call 64 (header 21 node 0 0 0 0 0 t)
def publish (manifest root expected name nameLength t : UInt64) : UInt64 :=
  if nameLength == 0 || nameLength > 63 then error else
    let t := header 22 manifest root nameLength 0 0 0 t
    let t := copy expected (wire+64) 32 t
    let t := zero (wire+96) 8 t
    let t := copy name (wire+96) nameLength t
    call 160 t
def roots (cursor t : UInt64) : UInt64 := call 64 (header 23 0 cursor 0 0 0 0 t)
def openHead (root t : UInt64) : UInt64 := call 64 (header 24 root 0 0 0 0 0 t)
def resolve (root id t : UInt64) : UInt64 :=
  let t := header 25 root 0 0 0 0 0 t
  call 96 (copy id (wire+64) 32 t)
def closure (root cursor t : UInt64) : UInt64 := call 64 (header 26 root cursor 0 0 0 0 t)
def delegate (root recipient rights t : UInt64) : UInt64 := call 64 (header 27 root recipient rights 0 0 0 t)
def remove (root t : UInt64) : UInt64 := call 64 (header 28 root 0 0 0 0 0 t)
def describeRoot (root t : UInt64) : UInt64 := call 64 (header 29 root 0 0 0 0 0 t)
def projectIdentity (root t : UInt64) : UInt64 := call 64 (header 34 root 0 0 0 0 0 t)
def revoke (root delegated t : UInt64) : UInt64 := call 64 (header 31 root delegated 0 0 0 0 t)
def freeze (root expected t : UInt64) : UInt64 :=
  let t := header 32 root 0 0 0 0 0 t
  call 96 (copy expected (wire+64) 32 t)
def freezeExport (root expected t : UInt64) : UInt64 :=
  let t := header 33 root 0 0 0 0 0 t
  call 96 (copy expected (wire+64) 32 t)
-- Import-v1 root entries: zero:u64,nameLength:u64,head:32,name:80.
-- Node offer: id:32,parent:32,payloadHash:32. Records may arrive in any order.
def importBegin (selected count nodes bytes t : UInt64) : UInt64 :=
  if count == 0 || count > 6 then error else
    let t := header 35 0 count nodes bytes 0 0 t
    call (64+count*128) (copy selected (wire+64) (count*128) t)
def importOfferVersion (transaction ordinal kind bytes identities schema t : UInt64) : UInt64 :=
  let t := header 36 transaction ordinal kind bytes schema 0 t
  call 160 (copy identities (wire+64) 96 t)
def importOffer (transaction ordinal kind bytes identities t : UInt64) : UInt64 :=
  importOfferVersion transaction ordinal kind bytes identities 1 t
def importAppend (transaction ordinal offset bytes count t : UInt64) : UInt64 :=
  if count > 512 then error else
    let t := header 37 transaction ordinal offset 0 0 0 t
    call (64+count) (copy bytes (wire+64) count t)
def importSubmit (transaction operation t : UInt64) : UInt64 := call 64 (header 44 transaction operation 0 0 0 0 t)
def importInspect (transaction t : UInt64) : UInt64 := call 64 (header 45 transaction 0 0 0 0 0 t)
def importInspectDetail (transaction t : UInt64) : UInt64 := call 64 (header 45 transaction 1 0 0 0 0 t)
def importControl (transaction action t : UInt64) : UInt64 := call 64 (header 46 transaction action 0 0 0 0 t)
-- Compatibility wrapper waits in the calling process; Objects remains available
-- to other callers. New interactive consumers use submit/inspect in their loop.
partial def importAwait (transaction t : UInt64) : UInt64 :=
  let r := importInspect transaction t
  if r < 64 || r == error || status r != 0 then error else
  let state := load64 (wire+16) r
  if state == 4 then
    let count := (r-64)/8
    if count == 0 || count > 6 then error else
    let t := copy (wire+64) digest (count*8) r
    let t := importControl transaction 4 t
    let t := header 0 count 0 0 0 0 0 t
    64+count*8+copy digest (wire+64) (count*8) t
  else if state >= 5 then
    let code := load64 (wire+40) r
    let t := importControl transaction 4 r
    64+header (if code == 0 then 2 else code) 0 0 0 0 0 0 t
  else importAwait transaction (Guest.WaitSDK.deadline (Guest.WaitSDK.now r+1) r)
def importCommit (transaction t : UInt64) : UInt64 :=
  let r := importSubmit transaction transaction t
  if r == 64 && status r == 7 then call 64 (header 38 transaction 0 0 0 0 0 r) else
  if r == error || (r >= 64 && status r == 0) then importAwait transaction r else r
-- Complete staged bytes only: rehashes payload and canonical node ID; no caps,
-- graph publication or dependency-validation claim. Header includes total bytes,
-- offset, kind, schema and ordinal; verified payload starts at wire+64.
def importVerifiedRead (transaction ordinal offset count t : UInt64) : UInt64 :=
  call 64 (header 43 transaction ordinal offset count 0 0 t)
def importAbort (transaction t : UInt64) : UInt64 :=
  let r := importControl transaction 3 t
  if r == 64 && (status r == 7 || status r == 3) then call 64 (header 39 transaction 0 0 0 0 0 r) else r
def importStatus (transaction t : UInt64) : UInt64 := call 64 (header 40 transaction 0 0 0 0 0 t)
-- Explicit source-only archival checkpoint; response256 includes origin/head
-- commitments, created/reclaimed record counts and schema2 archive status.
def checkpoint (root expected t : UInt64) : UInt64 :=
  let t := header 41 root 1 0 0 0 0 t
  call 96 (copy expected (wire+64) 32 t)
-- Fork-v1: exact upstream head, explicitly selected publisher identity and alias.
-- Returns a new local root; lineage becomes signed only in a later real Release.
def forkProject (root expected publisher name nameLength t : UInt64) : UInt64 :=
  if nameLength == 0 || nameLength > 63 then error else
    let t := header 42 root nameLength 0 0 0 0 t
    let t := copy expected (wire+64) 32 t
    let t := copy publisher (wire+96) 32 t
    let t := zero (wire+128) 8 t
    call 192 (copy name (wire+128) nameLength t)
end Guest.ProjectSDK
