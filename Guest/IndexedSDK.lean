import Guest.LiveSDK
namespace Guest.IndexedSDK
open Guest.LiveSDK
-- Management's explicit selected-store portal. Invocations do not grant any
-- ambient path or block device. Only a current trusted administrator can issue
-- the permit; its recipient is the exact live acquisition principal.
def call (length t : UInt64) : UInt64 := syscall 30 1 wire length 1024 t
-- kind1 personal encrypted Objects store; kind2 explicit operator plaintext.
-- binding contains namespace32 and exact manifestSHA25632.
def permit (kind slot quota recipient binding t : UInt64) : UInt64 :=
  let t := header 260 kind slot quota recipient 3 0 t
  call 128 (copy binding (wire+64) 64 t)
-- One row/page, slot0..15. Returns state, verifiedBytes,total,generation and
-- immutable binding352. An empty page returns6; no payload reads are needed.
def inventory (kind slot scope t : UInt64) : UInt64 :=
  let t := header 261 kind slot 0 0 0 0 t
  call 96 (copy scope (wire+64) 32 t)
def openItem (permission recipient operation t : UInt64) : UInt64 :=
  call 64 (header 262 permission recipient operation 0 0 0 t)
def deleteItem (permission t : UInt64) : UInt64 := call 64 (header 263 permission 0 0 0 0 0 t)
def bindSelection (permission vaultOwnedSelection t : UInt64) : UInt64 := call 64 (header 264 permission vaultOwnedSelection 0 0 0 0 t)
def selectionRead (permission offset count t : UInt64) : UInt64 := call 64 (header 265 permission offset count 0 0 0 t)
def revoke (permission t : UInt64) : UInt64 := call 64 (header 266 permission 0 0 0 0 0 t)
end Guest.IndexedSDK
