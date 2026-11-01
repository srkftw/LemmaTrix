import Guest.LiveSDK
namespace Guest.IdentitySDK
open Guest.LiveSDK
-- Identity-v1 endpoints are discovered only through a current kernel binding.
-- This API never accepts, exports, or supplies a long-term private key.
def endpoint (operation t : UInt64) : UInt64 := syscall 128 1 operation 0 0 t
def invoke (operation length t : UInt64) : UInt64 :=
  let target := endpoint operation t
  if target == error then error else syscall 30 target wire length 1024 target
def create (role federation scope t : UInt64) : UInt64 :=
  let t := header 400 0 role 0 0 0 0 t
  let t := copy federation (wire+64) 32 t
  invoke 400 128 (copy scope (wire+96) 32 t)
-- Administrative export of one selected scope; ordinary applications cannot
-- enumerate/link the broker's public identities by guessing handles.
def exportPublic (key t : UInt64) : UInt64 := invoke 401 64 (header 401 key 0 0 0 0 0 t)
-- One-use authority binds exact body hash, purpose, current key generation and
-- actual requesting process. It is deliberately distinct from IPC binding.
def authorize (key requester purpose bodyLength bodyHash t : UInt64) : UInt64 :=
  let t := header 405 key requester purpose bodyLength 0 0 t
  invoke 405 96 (copy bodyHash (wire+64) 32 t)
def certify (permit body bodyLength t : UInt64) : UInt64 :=
  if bodyLength > 256 then error else
  let t := header 402 permit 0 0 0 0 0 t
  invoke 402 (64+bodyLength) (copy body (wire+64) bodyLength t)
def revokeKey (key t : UInt64) : UInt64 := invoke 403 64 (header 403 key 0 0 0 0 0 t)
def lock (t : UInt64) : UInt64 := invoke 404 64 (header 404 0 0 0 0 0 0 t)
def inspect (t : UInt64) : UInt64 := invoke 406 64 (header 406 0 0 0 0 0 0 t)
def cancelApproval (permit t : UInt64) : UInt64 := invoke 407 64 (header 407 permit 0 0 0 0 0 t)
-- Operator-only sealed retention: blob192 contains encrypted role3/4 seeds.
def sealOperator (node receipt credential t : UInt64) : UInt64 :=
  invoke 408 96 (copy credential (wire+64) 32 (header 408 0 node receipt 0 0 0 t))
def recoverOperator (credential nodePublic sealed t : UInt64) : UInt64 :=
  let t := copy credential (wire+64) 32 (header 408 1 0 0 0 0 0 t)
  let t := copy nodePublic (wire+96) 32 t
  invoke 408 320 (copy sealed (wire+128) 192 t)
def authorizeReceipt (receipt service limit context t : UInt64) : UInt64 :=
  invoke 409 128 (copy context (wire+64) 64 (header 409 0 receipt service limit 0 0 t))
def signReceipt (grant body t : UInt64) : UInt64 :=
  invoke 409 256 (copy body (wire+64) 192 (header 409 grant 0 0 0 0 0 t))
-- Feed-v1 lifecycle is restricted to a current exact registered account or
-- federation consumer. Scope and signing purpose are determined by that role.
def feedCreate (federation scope t : UInt64) : UInt64 :=
  invoke 410 128 (copy scope (wire+96) 32 (copy federation (wire+64) 32 (header 410 0 0 0 0 0 0 t)))
def feedApprove (key bodyHash t : UInt64) : UInt64 :=
  invoke 410 96 (copy bodyHash (wire+64) 32 (header 410 1 key 0 0 0 0 t))
def feedRevoke (key t : UInt64) : UInt64 := invoke 410 64 (header 410 2 key 0 0 0 0 t)
def sealFeed (key credential t : UInt64) : UInt64 :=
  invoke 410 96 (copy credential (wire+64) 32 (header 410 3 key 0 0 0 0 t))
def recoverFeed (credential publicKey sealed t : UInt64) : UInt64 :=
  let t := copy credential (wire+64) 32 (header 410 4 0 0 0 0 0 t)
  let t := copy publicKey (wire+96) 32 t
  invoke 410 320 (copy sealed (wire+128) 192 t)
def lockFeed (t : UInt64) : UInt64 := invoke 410 64 (header 410 5 0 0 0 0 0 t)
end Guest.IdentitySDK
