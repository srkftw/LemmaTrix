import Guest.ForgeRouted
namespace Guest.MessengerForge
open Guest.LiveSDK
-- Messenger hands the selected public reference to the existing Forge
-- federation consumer. Its signature verifier and immutable-root checks are
-- unchanged. No content import, install, execution or publication follows.
def active (t : UInt64) : Bool :=
  Guest.ForgeRouted.phase t == 1 || Guest.ForgeRouted.phase t == 2 || Guest.ForgeRouted.phase t == 5
def begin (root federation policy cursor t : UInt64) : UInt64 :=
  if active t || (policy != 1 && policy != 2) then error else
  let r := Guest.ForgeFederation.configure 1 policy federation t
  if r == error then error else Guest.ForgeRouted.begin root cursor 1 r
def pump (t : UInt64) : UInt64 := Guest.ForgeRouted.pump t
def cancel (t : UInt64) : UInt64 :=
  if !active t then t else
  let t := Guest.ForgeRouted.failure 9 t
  let network := syscall 97 6 0 0 0 t
  if network == error then network else
  let t := store64 (wire+56) 2 (header 42 0 0 0 0 0 0 network)
  -- A terminal stream cannot retract a request already forwarded. Closing its
  -- owned stream yields unavailable; retained mailbox/outbox work stays exact.
  syscall 30 network wire 64 1024 t
def inspect (t : UInt64) : UInt64 :=
  let t := header 0 (Guest.ForgeRouted.phase t) (load64 (Guest.ForgeRouted.st+24) t)
    (load64 (Guest.ForgeFederation.st+64) t) (load64 (Guest.ForgeFederation.st+72) t)
    (load64 (Guest.ForgeFederation.st+80) t) 1 t
  let t := copy Guest.ForgeRouted.root (wire+64) 32 t
  128+copy (Guest.ForgeFederation.st+160) (wire+96) 32 t
end Guest.MessengerForge
