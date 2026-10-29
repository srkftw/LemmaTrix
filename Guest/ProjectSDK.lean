import Guest.LiveSDK
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
def revoke (root delegated t : UInt64) : UInt64 := call 64 (header 31 root delegated 0 0 0 0 t)
def freeze (root expected t : UInt64) : UInt64 :=
  let t := header 32 root 0 0 0 0 0 t
  call 96 (copy expected (wire+64) 32 t)
def freezeExport (root expected t : UInt64) : UInt64 :=
  let t := header 33 root 0 0 0 0 0 t
  call 96 (copy expected (wire+64) 32 t)
end Guest.ProjectSDK
