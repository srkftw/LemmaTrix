import Guest.LiveSDK
namespace Guest.AppIntentSDK
open Guest.LiveSDK
-- App-facing intent-v1. The512-byte UTF-8 payload is copied into the owner;
-- requests never acquire account/session management operations or secrets.
def limit : UInt64 := 512
def request (role operation source bytes destination identity t : UInt64) : UInt64 :=
  if bytes == 0 || bytes > limit || identity == 0 then error else
  let op := if role == 5 then 482 else if role == 2 then 436 else 0
  let target := syscall 128 role op 0 0 t
  if op == 0 || target == error then error else
  let t := header op 0 identity destination bytes 10000000 0 target
  syscall 30 target wire (64+bytes) 1024 (copy source (wire+64) bytes t)
def requestFeed (source bytes audience identity t : UInt64) : UInt64 :=
  if audience > 1 then error else request 5 482 source bytes audience identity t
def requestMessage (source bytes recipient identity t : UInt64) : UInt64 :=
  if recipient == 0 || recipient > 4 then error else request 2 436 source bytes recipient identity t
def control (role action handle t : UInt64) : UInt64 :=
  let op := if role == 5 then 482 else if role == 2 then 436 else 0
  let target := syscall 128 role op 0 0 t
  if op == 0 || target == error then error else
  syscall 30 target wire 64 1024 (header op action handle 0 0 0 0 target)
def inspect (role handle t : UInt64) : UInt64 := control role 1 handle t
def cancel (role handle t : UInt64) : UInt64 := control role 2 handle t
-- Result status:1 awaiting review,2 frozen in trusted review,3 committed,
-- 4 service accepted,5 confirmed by recipient/replication,6 cancelled before
-- commit,7 failed,8 outcome uncertain. A cancellation after commit returns12.
end Guest.AppIntentSDK
