import Guest.LibraryPeerSDK
import Guest.RegistrySDK
import Guest.ContentSDK
import Guest.ContentFormat
import Guest.WaitSDK
import Guest.LibraryGraphServe
namespace Guest.LibraryPeer
open Guest.LiveSDK
-- Sixteen bounded service scopes over four relationships (at most four grants
-- per relationship). Every response and catalog snapshot
-- belongs to exactly one relationship/stream, never a remote-supplied handle.
def peer (slot : UInt64) : UInt64 := 0x600000+slot*4096
def request : UInt64 := 0x610000
def clock : UInt64 := 0x611000
def hashScratch : UInt64 := 0x612000
def hashOut : UInt64 := 0x613000
def response (code value t : UInt64) : UInt64 :=
  let t := zero wire 8 t
  let t := store64 wire code t
  64+store64 (wire+8) value t
-- Peer fields: grant,role,scopedContent,stream,sendJob,responseBytes,requestID,
-- snapshotID,snapshotNext; policy approved88, remaining payload budget96,
-- absolute expiry104, next retry112; immutable root128, response256,
-- metadata snapshot at1024 (admission768 + original consumer768).
def reply (p op code total value next n t : UInt64) : UInt64 :=
  let out := p+256
  let t := zero out 8 t
  let t := store64 out Guest.LibraryPeerSDK.magic t
  let t := store64 (out+8) 1 t
  let t := store64 (out+16) op t
  let t := store64 (out+24) code t
  let t := store64 (out+32) (load64 (p+48) t) t
  let t := store64 (out+40) total t
  let t := store64 (out+48) value t
  let t := store64 (out+56) next t
  let t := copy (wire+64) (out+64) n t
  store64 (p+40) (64+n) t

def catalog (p cursor t : UInt64) : UInt64 :=
  if cursor > 16 then reply p 1 2 0 0 0 0 t else
  let r := Guest.RegistrySDK.query cursor t
  if r != 832 || status r != 0 then reply p 1 (if r == error then 7 else status r) 0 0 0 0 r else
  let slot := load64 (wire+16) r
  let next := load64 (wire+24) r
  -- This role can expose only its approved federation's signed decisions.
  if !Guest.ContentFormat.equal (wire+64+288) (p+128) 32 r then reply p 1 1 0 0 next 0 r else
  let t := copy (wire+64) (p+1024) 768 r
  let r := Guest.RegistrySDK.consumer slot t
  if r != 832 || status r != 0 then reply p 1 6 0 0 next 0 r else
  let t := copy (wire+64) (p+1792) 768 r
  let id := load64 clock t+1
  let t := store64 clock id t
  let t := store64 (p+56) id t
  let t := store64 (p+64) next t
  reply p 1 0 1536 id next 0 t

def metadata (p id offset count t : UInt64) : UInt64 :=
  if id == 0 || id != load64 (p+56) t then reply p 2 3 0 0 0 0 t else
  if count == 0 || count > 640 || offset >= 1536 || count > 1536-offset then reply p 2 2 0 0 0 0 t else
  let t := copy (p+1024+offset) (wire+64) count t
  reply p 2 0 1536 id (load64 (p+64) t) count t

def seed (p op h count t : UInt64) : UInt64 :=
  let content := load64 (p+16) t
  if op == 3 || op == 6 then
    let r := Guest.ContentSDK.describe content t
    if r != 320 || status r != 0 then reply p op (if r == error then 7 else status r) 0 0 0 0 r else
    let state := load64 (wire+16) r
    let available := load64 (wire+24) r
    let total := load64 (wire+32) r
    reply p op 0 total state available 256 r
  else if op == 4 then
    let r := Guest.ContentSDK.callContent 64 (header 313 content h 0 0 0 0 t)
    if r < 96 || r > 448 || status r != 0 then reply p op (if r == error then 7 else status r) 0 0 0 0 r else
    reply p op 0 (r-64) h 0 (r-64) r
  else if op == 5 then
    let r := Guest.ContentSDK.read content h count t
    if r < 64 || r > 576 || status r != 0 then reply p op (if r == error then 7 else status r) 0 0 0 0 r else
    reply p op 0 (load64 (wire+32) r) h (load64 (wire+16) r) (r-64) r
  else reply p op 1 0 0 0 0 t

def answer (p t : UInt64) : UInt64 :=
  let op := load64 (request+16) t
  let h := load64 (request+24) t
  let a := load64 (request+32) t
  let b := load64 (request+40) t
  if load64 request t != Guest.LibraryPeerSDK.magic || load64 (request+8) t != 1 ||
    load64 (request+48) t != 0 || load64 (request+56) t != 0 || op == 0 || op > 9 then reply p op 2 0 0 0 0 t else
  if load64 (p+8) t == 1 then
    if op == 1 then catalog p h t else
    if op == 2 then metadata p h a b t else reply p op 1 0 0 0 0 t
  else if load64 (p+8) t == 3 then
    let scope := (p-0x600000)/4096
    let t := store64 (p+56) h t
    let r := Guest.LibraryGraphServe.answer scope op h a b t
    if r == error then
      let reason := load64 (Guest.LibraryGraphServe.table scope+3984) r
      let t := store64 (p+72) reason r
      reply p op (if reason == 0 then 1 else reason) 0 0 0 0 t else
    reply p op 0 (load64 (Guest.LibraryGraphServe.table scope+3968) r) (load64 (Guest.LibraryGraphServe.table scope+3976) r) 0 r r
  else seed p op h a t

partial def freeScope (slot stream i t : UInt64) : UInt64 :=
  if i == 16 then error else
  let p := peer i
  if load64 (p+88) t != 0 && load64 (p+80) t == slot && load64 (p+24) t == stream then error else
  if load64 (p+88) t == 0 then i else freeScope slot stream (i+1) t

def configure (length t : UInt64) : UInt64 :=
  let slot := load64 (command+8) t
  let role := load64 (command+16) t
  let stream := load64 (command+24) t
  let content := load64 (command+32) t
  let budget := load64 (command+40) t
  let lifetime := load64 (command+48) t
  if length != 160 || slot >= 4 || (role != 1 && role != 2 && role != 3) || stream == 0 ||
    budget == 0 || budget > 16777216 || lifetime == 0 || lifetime > 100000 then response 2 0 t else
  let selected := freeScope slot stream 0 t
  if selected == error then response 4 0 t else
  let p := peer selected
  let t := zero p 512 t
  let t := store64 (p+80) slot t
  let t := copy (command+64) (p+3072) 96 t
  let t := copy (command+128) (p+128) 32 t
  let t := store64 (p+8) role t
  let t := store64 (p+16) content t
  let t := store64 (p+24) stream t
  let r := if role == 2 then Guest.ContentSDK.describe content t else 320+t
  if role == 2 && (r != 320 || status r != 0) then response 1 0 r else
  let t := if role == 2 then Guest.ServiceHash.sha256At hashScratch (wire+64) 256 hashOut r else r
  if role == 2 && !Guest.ContentFormat.equal hashOut (p+128) 32 t then response 2 0 t else
  let prepared := if role == 3 then Guest.LibraryGraphServe.prepare selected content (p+128) t else t
  if prepared == error then response 2 0 prepared else
  let t := prepared
  -- Operator approval is independent of current connection availability.
  -- Authentication may begin later; work mints fresh epoch-bound authority.
  let t := store64 (p+88) 1 t
  let t := store64 (p+96) budget t
  let t := store64 (p+104) (Guest.WaitSDK.now t+lifetime) t
  response 0 selected t

partial def removeScopes (slot i t : UInt64) : UInt64 :=
  if i == 16 then t else
  let p := peer i
  let t := if load64 (p+88) t != 0 && load64 (p+80) t == slot then
    let r := if load64 p t == 0 then t else Guest.NetworkSDK.revokePeer slot (load64 p t) t
    zero p 512 r
    else t
  removeScopes slot (i+1) t

def dispatch (caller rights length t : UInt64) : UInt64 :=
  let op := load64 command t
  let slot := load64 (command+8) t
  let admin := (caller &&& 255) == 1 && (rights &&& 0x100000000) != 0
  if length < 64 || load64 (command+56) t != 1 then response 2 0 t else
  if op == 400 && admin then configure length t else
  if op == 401 && length == 64 && slot < 16 then
    let p := peer slot
    let t := response 0 slot t
    let t := store64 (wire+16) (if load64 (p+88) t == 0 then 0 else if load64 p t == 0 then 2 else 1) t
    let t := store64 (wire+24) (load64 (p+8) t) t
    let t := store64 (wire+32) (load64 (p+32) t) t
    let t := store64 (wire+40) (load64 (p+40) t) t
    let t := store64 (wire+48) (load64 (p+56) t) t
    64+store64 (wire+56) (load64 (p+72) t) t
  else if op == 402 && admin && length == 64 && slot < 4 then
    response 0 slot (removeScopes slot 0 t)
  else response 1 0 t

def lost (p t : UInt64) : UInt64 :=
  let slot := load64 (p+80) t
  let job := load64 (p+32) t
  let grant := load64 p t
  -- A response timeout can leave broker work live in the same epoch. Retire
  -- that authority before dropping local references or attempting renewal.
  let t := if job == 0 then t else Guest.NetworkSDK.cancelPeer slot job t
  let t := if grant == 0 then t else Guest.NetworkSDK.revokePeer slot grant t
  let t := zero (p+256) 288 t
  let t := zero p 1 t
  let t := zero (p+32) 5 t
  let t := store64 (p+72) 7 t
  store64 (p+112) (Guest.WaitSDK.now t+100) t

def renew (p t : UInt64) : UInt64 :=
  let now := Guest.WaitSDK.now t
  if now < load64 (p+112) now then now else
  let t := store64 (p+112) (now+100) now
  let slot := load64 (p+80) t
  let r := Guest.NetworkSDK.inspectPeer slot t
  if r != 64 || status r != 0 || result r != 3 then r else
  -- A loss may discard four already authenticated inbox records before this
  -- application consumes them. Reserve their worst-case704-byte payloads on
  -- every fresh grant, so reconnect cannot replenish unobserved charged work.
  if load64 (p+96) r <= 2816 then store64 (p+88) 0 (store64 (p+72) 4 r) else
  let r := Guest.LibraryPeerSDK.grant slot (p+3072) (load64 (p+24) r)
    (load64 (p+96) r) (load64 (p+104) r-now) r
  if r != 64 || status r != 0 then store64 (p+72) (if r == error then 7 else status r) r else
  let t := store64 (p+96) (load64 (p+96) r-2816) r
  store64 p (result r) (store64 (p+72) 0 t)

def work (scope t : UInt64) : UInt64 :=
  let p := peer scope
  let slot := load64 (p+80) t
  if load64 (p+88) t == 0 then t else
  let now := Guest.WaitSDK.now t
  if now >= load64 (p+104) now || load64 (p+96) now < 64 then
    let r := if load64 p now == 0 then now else Guest.NetworkSDK.revokePeer slot (load64 p now) now
    store64 (p+88) 0 (lost p r)
  else if load64 p now == 0 then renew p now else
  let t := now
  if load64 (p+32) t != 0 then
    let r := Guest.NetworkSDK.pollPeer slot (load64 (p+32) t) t
    let state := load64 (wire+16) r
    if r != 64 || status r != 0 || state >= 4 then
      lost p r
    else if state == 3 then store64 (p+32) 0 r else r
  else if load64 (p+40) t != 0 then
    if load64 (p+40) t > load64 (p+96) t then
      let r := Guest.NetworkSDK.revokePeer slot (load64 p t) t
      store64 (p+88) 0 (lost p r)
    else
    let r := Guest.NetworkSDK.sendPeer slot (load64 p t) 2 (load64 (p+48) t) (p+256) (load64 (p+40) t) t
    if r != 64 || status r != 0 then
      if r != error && status r == 4 then r else lost p r
    else
      let t := store64 (p+96) (load64 (p+96) r-load64 (p+40) r) r
      let t := store64 (p+32) (result r) t
      store64 (p+40) 0 t
  else
    let r := Guest.LibraryPeerSDK.receive slot (load64 p t) t
    let bytes := if r >= 64 && r <= 768 && status r == 0 then r-64 else 0
    let t := if bytes <= load64 (p+96) r then store64 (p+96) (load64 (p+96) r-bytes) r else store64 (p+88) 0 r
    if r != 128 || status r != 0 then
      if r != error && status r == 6 then t else lost p t
    else
      let t := store64 (p+48) (load64 (wire+24) r) t
      let t := copy (wire+64) request 64 t
      answer p t

partial def workAll (slot t : UInt64) : UInt64 :=
  if slot == 16 then t else workAll (slot+1) (work slot t)
partial def delay (scope t : UInt64) : UInt64 :=
  if scope == 16 then 20 else
  let p := peer scope
  if load64 (p+32) t != 0 || load64 (p+40) t != 0 then 1 else delay (scope+1) t
partial def serve (endpoint t : UInt64) : UInt64 :=
  let t := workAll 0 t
  let n := syscall 36 endpoint incoming 1024 0 t
  let t := if n >= 96 && n != error && load64 (incoming+24) n == 2 then
    let caller := load64 incoming n
    let token := load64 (incoming+8) n
    let rights := load64 (incoming+16) n
    let r := dispatch caller rights (n-32) n
    Guest.LiveSDK.reply token r r
    else n
  serve endpoint (Guest.WaitSDK.deadline (Guest.WaitSDK.now t+delay 0 t) t)
def main (t : UInt64) : UInt64 :=
  let t := zero 0x600000 16384 t
  serve (self t) t
end Guest.LibraryPeer
