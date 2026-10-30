import Guest.LiveSDK
namespace Guest.ServiceSDK
open Guest.LiveSDK
-- Purpose2 operator jobs. `slot` is an opaque allocation handle: low8 bits
-- select storage, upper56 bind its reuse generation. Never truncate it.
-- Vault also checks the current caller against a fresh administrative bind.
def validHandle (handle : UInt64) : Bool := (handle &&& 255) < 16
def callService (length t : UInt64) : UInt64 := syscall 30 3 wire length 1024 t
def reserve (slot bytes checkpoint quanta t : UInt64) : UInt64 :=
  callService 64 (header 283 slot bytes checkpoint quanta 0 0 t)
def newAttempt (slot t : UInt64) : UInt64 := callService 64 (header 284 slot 0 0 0 0 0 t)
def inspect (slot t : UInt64) : UInt64 := callService 64 (header 285 slot 0 0 0 0 0 t)
def complete (slot bytes root t : UInt64) : UInt64 :=
  let t := header 290 slot bytes 0 0 0 0 t
  callService 96 (copy root (wire+64) 32 t)
def fail (slot reason t : UInt64) : UInt64 := callService 64 (header 291 slot reason 0 0 0 0 t)
end Guest.ServiceSDK
