import Guest.LiveSDK
namespace Guest.RegistrySDK
open Guest.LiveSDK
def admitted (classification : UInt64) : Bool := classification == 1 || classification == 2 || classification == 4 || classification == 5
def consumerAdmitted (classification : UInt64) : Bool := classification == 4 || classification == 5
def executableAdmitted (classification : UInt64) : Bool := classification == 2 || classification == 5
theorem rejected_unavailable : admitted 3 = false := by decide
-- The operator binds one isolated registry/verifier incarnation. A signed
-- networking right permits this narrow IPC path; display authority does not.
def endpoint (t : UInt64) : UInt64 := syscall 113 0 0 0 0 t
def call (length t : UInt64) : UInt64 :=
  let service := endpoint t
  if service == error then error else syscall 30 service wire length 1024 service
def admit (root t : UInt64) : UInt64 := call 64 (header 2 root 0 0 0 0 0 t)
def query (cursor t : UInt64) : UInt64 := call 64 (header 6 cursor 0 0 0 0 0 t)
def inspect (slot t : UInt64) : UInt64 := call 64 (header 7 slot 0 0 0 0 0 t)
def verify (descriptor expected t : UInt64) : UInt64 :=
  let t := header 11 0 0 0 0 0 0 t
  let t := copy descriptor (wire+64) 768 t
  call 864 (copy expected (wire+832) 32 t)
-- Fast current-knowledge check: exact cached descriptor+expected immutable root
-- only. It creates no admission or freshness. The cache must have been populated
-- by verify/own signed admission/recovery. Returns832 even on stale status3,
-- with latest known classification/reason/sequence and signed descriptor.
def current (descriptor expected t : UInt64) : UInt64 :=
  let t := header 22 0 0 0 0 0 0 t
  let t := copy descriptor (wire+64) 768 t
  call 864 (copy expected (wire+832) 32 t)
-- Exact originally signed ConsumerRelease-v1 for a current catalog slot.
def consumer (slot t : UInt64) : UInt64 := call 64 (header 20 slot 0 0 0 0 0 t)
-- Bounded case-insensitive printable-title search, optional facet0/all,1/media,
-- 2/game. Response pagination and admission shape match query.
def search (cursor facet query queryLength t : UInt64) : UInt64 :=
  if facet > 2 || queryLength > 64 then error else
    let t := header 21 cursor facet queryLength 0 0 0 t
    call (64+queryLength) (copy query (wire+64) queryLength t)
end Guest.RegistrySDK
