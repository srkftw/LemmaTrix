import Guest.Library
import Guest.ServiceSDK
namespace Guest.LibraryOperator
open Guest.LiveSDK
-- Operator wrapper around the normal Library jobs, not a second acquisition
-- scheduler. Vault owns the durable terms, attempts and remaining resources.
def scopes : UInt64 := 0x728000
def attempts : UInt64 := 0x729000
def scope (ci : UInt64) : UInt64 := scopes+ci*128
def attempt (ji : UInt64) : UInt64 := attempts+ji*32
def configure (n t : UInt64) : UInt64 :=
  let token := load64 (incoming+8) t
  let ci := load64 (command+8) t
  let slot := load64 (command+16) t
  if (load64 incoming t &&& 255) != 1 || n != 160 || ci >= 8 || slot >= 16 then
    reply token 64 (header 2 0 0 0 0 0 0 t) else
  let r := Guest.ServiceSDK.inspect slot t
  let policy := Guest.LibraryCollections.record ci
  if r != 576 || status r != 0 || load64 (wire+96) r != 2 ||
    load64 (policy+88) r != 1 || load64 (policy+128) r == 0 ||
    load64 (wire+256) r != 2 || load64 (wire+264) r != load64 (policy+8) r ||
    !Guest.Library.eq (wire+192) (command+64) 32 r ||
    !Guest.Library.eq (wire+224) (command+96) 32 r then
    reply token 64 (header 1 0 0 0 0 0 0 r) else
  let t := copy (command+64) (scope ci+32) 64 r
  let t := store64 (scope ci+96) (load64 (policy+8) t) t
  let t := store64 (scope ci+104) (load64 (policy+128) t) t
  reply token 64 (header 0 ci slot 0 0 0 0 (store64 (scope ci) (slot+1) t))
def permitted (j t : UInt64) : UInt64 :=
  let ci := load64 (j+400) t-1
  if ci >= 8 then error else
  let p := scope ci
  if load64 p t == 0 || load64 (j+64) t != load64 (p+96) t || load64 (j+408) t != load64 (p+104) t ||
    !Guest.Library.eq (j+704) (p+32) 32 t then error else load64 p t-1
def retry (ji t : UInt64) : UInt64 :=
  let j := Guest.Library.job ji
  let a := attempt ji
  let slot := permitted j t
  if slot == error || !Guest.Library.policyLive j t then t else
  let r := Guest.ServiceSDK.inspect slot t
  if r != 576 || status r != 0 || load64 (wire+96) r != 2 then r else
  if load64 (a+24) r >= load64 (j+2152) r then
    let r := Guest.ServiceSDK.fail slot 4 r
    store64 j 14 r
  else
  let target := if load64 (j+16) r == 1 then 2 else 1
  if ((load64 (j+112) r >>> target) &&& 1) == 0 then r else
  let r := Guest.Library.availablePeer target r
  if r != 64 || status r != 0 || result r != 3 then r else
  let r := Guest.ServiceSDK.newAttempt slot r
  if r != 64 || status r != 0 then store64 j 14 r else
  let oldRow := load64 (Guest.Library.st+8) r
  let oldPeer := load64 (Guest.Library.st+136) r
  let t := store64 (Guest.Library.st+8) (load64 (j+8) r) r
  let t := store64 (Guest.Library.st+136) target t
  let t := Guest.Library.retry t
  let t := store64 (a+24) (load64 (a+24) t+1) (store64 (a+8) 0 t)
  store64 (Guest.Library.st+136) oldPeer (store64 (Guest.Library.st+8) oldRow t)
def waitingProvider (j t : UInt64) : UInt64 :=
  let selected := load64 (j+16) t
  let r := Guest.Library.availablePeer selected t
  if r == 64 && status r == 0 && result r == 3 then r else
  let alternate := if selected == 1 then 2 else 1
  if ((load64 (j+112) r >>> alternate) &&& 1) == 0 then r else
  let r := Guest.Library.availablePeer alternate r
  if r != 64 || status r != 0 || result r != 3 then r else
    store64 j 12 (store64 (j+96) 7 r)
def before (ji t : UInt64) : UInt64 :=
  let j := Guest.Library.job ji
  let phase := load64 j t
  let a := attempt ji
  if phase == 0 || phase >= 10 then
    if phase == 12 then retry ji t else t
  else
  let slot := permitted j t
  if slot == error then Guest.Library.jobFailure j error else
  let t := if phase == 1 then waitingProvider j t else t
  if load64 j t == 12 then retry ji t else
  let t := if load64 a t == load64 (j+80) t then t else
    store64 a (load64 (j+80) t) (zero (a+8) 3 t)
  if phase != 3 || load64 (j+32) t >= load64 (j+160) t || load64 (a+8) t == load64 (j+32) t+1 then t else
  let r := Guest.ContentSDK.inspectChunk (load64 (j+24) t) (load64 (j+32) t) t
  if r != 64 || status r != 0 then Guest.Library.jobFailure j r else
  if result r == 1 then r else
  let bytes := Guest.ContentFormat.chunkLength (load64 (j+920) r) (load64 (j+32) r)
  let r := Guest.ServiceSDK.reserve slot bytes 0 1 r
  if r != 64 || status r != 0 then Guest.Library.jobFailure j r else
    store64 (a+8) (load64 (j+32) r+1) r
def after (ji t : UInt64) : UInt64 :=
  let j := Guest.Library.job ji
  let a := attempt ji
  if load64 j t != 10 || load64 (a+16) t == 1 then t else
  let slot := permitted j t
  if slot == error then t else
  let r := Guest.ServiceSDK.complete slot (load64 (j+920) t) (j+704) t
  if r != 64 || status r != 0 then r else store64 (a+16) 1 r
partial def pump (ji t : UInt64) : UInt64 :=
  if ji == 4 then t else
  let t := before ji t
  let t := Guest.Library.jobPump ji t
  pump (ji+1) (after ji t)
partial def running (ji t : UInt64) : Bool :=
  if ji == 4 then false else
  let phase := load64 (Guest.Library.job ji) t
  (phase > 1 && phase < 10) || running (ji+1) t
partial def loop (initial : UInt64) : UInt64 :=
  let n := syscall 36 (self initial) incoming 1024 0 initial
  let t := if n < 96 || n > 1024 then n else
    if load64 command n == 728 then configure n n else Guest.Library.request n n
  let t := Guest.Library.receivePeers 0 (store64 (Guest.Library.st+640) 0 t)
  let t := Guest.Library.catalogPump t
  let t := pump 0 t
  let now := Guest.WaitSDK.now t
  let t := if now < load64 (Guest.Library.st+344) now then now else
    Guest.Library.providerStatus 0 (store64 (Guest.Library.st+344) (now+100) now)
  let active := load64 (Guest.Library.st+40) t != 0 || running 0 t
  let ready := load64 (Guest.Library.st+640) t == 1 && load64 (Guest.Library.st+648) t < 4
  let t := store64 (Guest.Library.st+648) (if ready then load64 (Guest.Library.st+648) t+1 else 0) t
  loop (Guest.WaitSDK.deadline (Guest.WaitSDK.now t+(if ready then 0 else if active then 1 else 20)) t)
def main (initial : UInt64) : UInt64 :=
  let t := zero Guest.Library.st 1024 initial
  let t := zero 0x700000 20480 t
  let t := zero scopes 1024 t
  let t := store64 (Guest.Library.st+136) 1 t
  let t := store64 (Guest.Library.st+184) (self t <<< 24) t
  loop t
end Guest.LibraryOperator
