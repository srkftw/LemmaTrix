import Guest.LiveSDK
namespace Guest.ServiceSDK
open Guest.LiveSDK
-- Purpose2 operator jobs. A slot is an identifier, never authority: Vault
-- checks the current calling incarnation against a fresh administrative bind.
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
