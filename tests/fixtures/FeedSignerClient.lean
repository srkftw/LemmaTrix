import Guest.IdentitySDK
namespace Guest.FeedSignerClient
open Guest.LiveSDK
-- Installed boundary probe: the real kernel supplies this caller's role and
-- incarnation. Only typed broker requests are forwarded; no key is read.
def st : UInt64 := 0x680000
def pending : UInt64 := st+4096
def completed : UInt64 := st+8192
def runPending (t : UInt64) : UInt64 :=
  if load64 st t != 1 then t else
  let n := load64 (st+8) t
  let t := copy pending wire n t
  let r := Guest.IdentitySDK.invoke (load64 pending t) n t
  let r := if r == error then 64+header 90 0 0 0 0 0 0 r else r
  let t := copy wire completed r r
  store64 st 2 (store64 (st+16) r t)
def dispatch (n t : UInt64) : UInt64 :=
  let action := load64 (command+8) t
  if action == 0 && n >= 128 && n <= 384 then
    if load64 st t != 0 then 64+header 7 0 0 0 0 0 0 t else
    let id := load64 (st+24) t+1
    let t := copy (command+64) pending (n-64) t
    64+header 0 id 0 0 0 0 0
      (store64 st 1 (store64 (st+8) (n-64) (store64 (st+24) id t)))
  else if action == 1 && n == 64 then
    if load64 (command+16) t != load64 (st+24) t then 64+header 3 0 0 0 0 0 0 t else
    if load64 st t != 2 then 64+header 6 0 0 0 0 0 0 t else
    let n := load64 (st+16) t
    n+copy completed wire n (store64 st 0 t)
  else 64+header 2 0 0 0 0 0 0 t
partial def serve (t : UInt64) : UInt64 :=
  let n := receive (self t) t
  if n == error then serve n else
  let token := load64 (incoming+8) n
  let r := dispatch (n-32) n
  serve (runPending (reply token r r))
def main (t : UInt64) : UInt64 := serve (zero st 2048 t)
end Guest.FeedSignerClient
