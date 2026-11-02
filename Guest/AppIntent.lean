import Guest.LiveSDK
import Guest.LiveMemory
import Guest.WaitSDK
import Guest.FeedEvent
import Guest.ServiceHash
namespace Guest.AppIntent
open Guest.LiveSDK
-- Private owner queue: four independent requests,512-byte immutable payloads.
-- It contains public authorization snapshots, never seeds, ratchets or vault keys.
def base : UInt64 := 0x6d0000
def row (i : UInt64) : UInt64 := base+256+i*1024
-- Three durable committed-operation keys fit the existing account record's
--384-byte extension. These contain no caller incarnation, service generation,
-- IPC token or signing approval. Once full, further commits return quota.
def durable : UInt64 := base+8192
def cache (i : UInt64) : UInt64 := durable+i*128
def cacheMagic : UInt64 := 0x31544e494c544c
partial def cacheFind (release operation i t : UInt64) : UInt64 :=
  if i == 3 then 0 else
  let c := cache i
  if load64 c t == cacheMagic && load64 (c+72) t == operation && Guest.LiveMemory.equal (c+8) release 32 t then c
  else cacheFind release operation (i+1) t
partial def cacheVacant (i t : UInt64) : UInt64 :=
  if i == 3 then 0 else if load64 (cache i) t == 0 then cache i else cacheVacant (i+1) t
partial def cacheValid (i t : UInt64) : Bool :=
  if i == 3 then true else
  let c := cache i
  (load64 c t == 0 || (load64 c t == cacheMagic && load64 (c+72) t != 0 &&
    load64 (c+96) t >= 3 && load64 (c+96) t <= 8 && load64 (c+112) t <= 512 && load64 (c+120) t == 0)) && cacheValid (i+1) t
def response (code h phase evidence t : UInt64) : UInt64 :=
  64+header code h phase evidence 512 4 1 t
partial def find (handle i t : UInt64) : UInt64 :=
  if i == 4 then 0 else
  if load64 (row i) t != 0 && load64 (row i+8) t == handle then row i else find handle (i+1) t
partial def vacant (i t : UInt64) : UInt64 :=
  if i == 4 then 0 else if load64 (row i) t == 0 || load64 (row i) t >= 4 then row i else vacant (i+1) t
partial def duplicate (caller operation i t : UInt64) : UInt64 :=
  if i == 4 then 0 else
  let p := row i
  if load64 p t != 0 && load64 (p+16) t == caller && load64 (p+24) t == operation then p else duplicate caller operation (i+1) t
partial def pending (i t : UInt64) : UInt64 :=
  if i == 4 then 0 else if load64 (row i) t == 1 then row i else pending (i+1) t
def current (p t : UInt64) : Bool :=
  Guest.WaitSDK.now t < load64 (p+48) t && syscall 159 0 (p+96) 96 0 t == 0
def state (p t : UInt64) : UInt64 :=
  response 0 (load64 (p+8) t) (load64 p t) (load64 (p+64) t) t
def request (authority caller token op length t : UInt64) : UInt64 :=
  let action := load64 (command+8) t
  let selected := load64 (command+16) t
  if authority == 0 then response 5 0 0 0 t else
  if action == 0 then
    let bytes := load64 (command+32) t
    let destination := load64 (command+24) t
    let lifetime := load64 (command+40) t
    if selected == 0 || bytes == 0 || bytes > 512 || length != 64+bytes || lifetime == 0 || lifetime > 10000000 ||
        (op == 482 && destination > 1) || (op == 436 && (destination == 0 || destination > 4)) ||
        !Guest.FeedEvent.utf8 (command+64) bytes 0 0 0 0 t then response 2 0 0 0 t else
    let existing := duplicate caller selected 0 t
    if existing != 0 then
      if load64 (existing+80) t != authority || !current existing t then response 3 selected 7 3 (store64 existing 7 t) else
      if load64 (existing+32) t != destination || load64 (existing+40) t != bytes ||
          !Guest.LiveMemory.equal (existing+256) (command+64) bytes t then response 9 0 0 0 t else state existing t
    else
    let p := vacant 0 t
    let serial := load64 base t+1
    if p == 0 || serial == 0 then response 4 0 0 0 t else
    let auth := base+6144
    let r := syscall 158 caller auth op token t
    if r != 96 then response 3 0 0 0 r else
    let r := Guest.ServiceHash.sha256At (base+16384) (command+64) bytes (auth+96) r
    let cached := cacheFind (auth+32) selected 0 r
    if cached != 0 && (load64 (cached+80) r != destination || load64 (cached+112) r != bytes ||
        !Guest.LiveMemory.equal (cached+40) (auth+96) 32 r) then response 9 0 0 0 r else
    let t := zero p 128 r
    let t := copy auth (p+96) 96 (copy (auth+96) (p+192) 32 t)
    let t := store64 base serial t
    let t := store64 (p+80) authority t
    let t := store64 p 1 (store64 (p+8) serial (store64 (p+16) caller (store64 (p+24) selected t)))
    let t := store64 (p+32) destination (store64 (p+40) bytes (store64 (p+48) (Guest.WaitSDK.now t+lifetime) t))
    let t := copy (command+64) (p+256) bytes t
    let t := if cached == 0 then t else store64 p (load64 (cached+96) t)
      (store64 (p+56) (load64 (cached+88) t) (store64 (p+64) (load64 (cached+104) t) t))
    state p t
  else
    let p := find selected 0 t
    if length != 64 || p == 0 || load64 (p+16) t != caller then response 1 0 0 0 t else
    if load64 (p+80) t != authority || !current p t then response 3 selected 7 3 (store64 p 7 t) else
    if action == 1 then state p t else
    if action == 2 && load64 p t <= 2 then state p (store64 p 6 (zero (p+256) 64 t)) else
    if action == 2 then response 12 selected (load64 p t) (load64 (p+64) t) t else
    if action == 3 && load64 p t >= 4 then response 0 selected 0 0 (zero p 128 t) else response 7 selected 0 0 t
-- The owner UI retrieves the frozen payload only via its existing privileged
-- protocol. Selecting a request neither commits nor mutates the ordinary draft.
def review (authority t : UInt64) : UInt64 :=
  let p := pending 0 t
  if p == 0 then response 6 0 0 0 t else
  if load64 (p+80) t != authority || !current p t then response 3 (load64 (p+8) t) 7 3 (store64 p 7 t) else
  let t := store64 p 2 t
  let t := header 0 (load64 (p+8) t) (load64 (p+40) t) (load64 (p+32) t) (load64 (p+16) t) 0 1 t
  let t := copy (p+128) (wire+64) 32 t
  96+load64 (p+40) t+copy (p+256) (wire+96) (load64 (p+40) t) t
-- Approval carries the exact reviewed destination and bytes. Any changed
-- content/destination requires a new request and another trusted review.
def approve (authority handle destination source bytes t : UInt64) : UInt64 :=
  let p := find handle 0 t
  if p == 0 || load64 (p+80) t != authority || load64 p t != 2 || !current p t || load64 (p+32) t != destination || load64 (p+40) t != bytes ||
      !Guest.LiveMemory.equal (p+256) source bytes t then error else p
-- Install this association before the owner's atomic outbox retention. A crash
-- can then retry only the same immutable event/ciphertext; live authority is new.
def reserveCommit (p external t : UInt64) : UInt64 :=
  let prior := cacheFind (p+128) (load64 (p+24) t) 0 t
  let c := if prior == 0 then cacheVacant 0 t else prior
  if c == 0 then error else
  let t := zero c 16 t
  let t := store64 c cacheMagic (copy (p+128) (c+8) 32 (copy (p+192) (c+40) 32 t))
  let t := store64 (c+72) (load64 (p+24) t) (store64 (c+80) (load64 (p+32) t) t)
  let t := store64 (c+88) external (store64 (c+96) 3 (store64 (c+112) (load64 (p+40) t) t))
  store64 p 3 (store64 (p+56) external t)
def committed (p external t : UInt64) : UInt64 := store64 p 3 (store64 (p+56) external t)
def evidence (external phase evidence t : UInt64) : UInt64 :=
  let p := find external 0 t
  if p == 0 then t else
  let c := cacheFind (p+128) (load64 (p+24) t) 0 t
  let t := if c == 0 then t else store64 (c+96) phase (store64 (c+104) evidence t)
  store64 p phase (store64 (p+64) evidence t)
def reject (handle t : UInt64) : UInt64 :=
  let p := find handle 0 t
  if p == 0 || load64 p t > 2 then response 12 handle 0 0 t else state p (store64 p 6 (zero (p+256) 64 t))
def clear (t : UInt64) : UInt64 := zero durable 48 (zero base 544 t)
end Guest.AppIntent
