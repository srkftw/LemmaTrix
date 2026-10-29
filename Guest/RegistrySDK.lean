import Guest.LiveSDK
namespace Guest.RegistrySDK
open Guest.LiveSDK
def admitted (classification : UInt64) : Bool := classification == 1 || classification == 2
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
end Guest.RegistrySDK
