import Guest.TorRouter
namespace Guest.OnionTerminal
open Guest.LiveSDK
-- Bounded authenticated terminal stream inside the three-hop circuit. The last
-- relay forwards these opaque Noise records; it never owns terminal keys.
-- At most one request and one response, fragmented into400-byte plaintext
-- pieces. No application header/token is outside this inner authenticated link.
def st : UInt64 := 0x710000
def noiseBank : UInt64 := 0x711000
def received : UInt64 := 0x712000
def outgoing : UInt64 := 0x713000
def fragment : UInt64 := 0x714000
def sealed : UInt64 := 0x715000
def fresh : UInt64 := 0x716000
def incomingCopy : UInt64 := 0x717000
def active (t : UInt64) : Bool := load64 st t != 0
def response (code value t : UInt64) : UInt64 := 64+header code value (load64 (st+8) t) 0 0 0 0 t
def save (t : UInt64) : UInt64 := copy Guest.Noise.state noiseBank 416 t
def restore (t : UInt64) : UInt64 := copy noiseBank Guest.Noise.state 416 t
def clear (t : UInt64) : UInt64 := zero st 4096 (Guest.Noise.disconnect t)
def fail (reason t : UInt64) : UInt64 :=
  let token := load64 (st+112) t
  let t := if token != 0 then syscall 135 token 0 0 0 t else t
  let t := clear t
  store64 (st+160) reason t

def writeOpaque (source n t : UInt64) : UInt64 :=
  if load64 st t == 1 then Guest.TorRouter.clientRelay 2 (load64 (st+24) t) source n 0 t else
  let ch := load64 (st+32) t
  Guest.TorRouter.queueTerminal ch (load64 (st+24) t) source n t

def beginClient (peer stream owner budget attempts t : UInt64) : UInt64 :=
  let p := Guest.NodeEnrollment.peer peer
  if peer >= 4 || stream == 0 || stream > 65535 || owner == 0 || budget == 0 || budget > 8388608 || attempts == 0 || attempts > 65536 ||
    !Guest.TorRouter.peerValid p t || load64 (p+208) t != 8 || budget > load64 (p+232) t || attempts > load64 (p+240) t || load64 (Guest.TorRouter.state+24) t != 3 then response 8 0 t else
  let t := clear t
  let t := store64 st 1 t
  let t := store64 (st+8) 1 t
  let t := store64 (st+16) peer t
  let t := store64 (st+24) stream t
  let t := store64 (st+128) owner t
  let t := store64 (st+136) budget t
  let t := store64 (st+144) attempts t
  let t := store64 (Guest.TorRouter.state+112) 0 t
  let t := copy (p+512) (st+192) 32 t
  let r := Guest.TorRouter.clientRelay 1 stream (p+144) 32 0 t
  if r == error then response 8 0 (fail 1 r) else response 0 stream r

def setupNoise (role descriptor t : UInt64) : UInt64 :=
  let r := syscall 104 0 fresh 32 0 t
  if r != 32 then error else
  let t := Guest.NoiseNK.init role Guest.NodeEnrollment.keys (descriptor+256) (descriptor+512) fresh r
  zero fresh 4 t

def envelope (kind n t : UInt64) : UInt64 :=
  let t := store64 sealed 1 t
  let t := store64 (sealed+8) kind t
  store64 (sealed+16) n t

def handshakeFirst (t : UInt64) : UInt64 :=
  let p := Guest.NodeEnrollment.peer (load64 (st+16) t)
  let r := setupNoise 1 p t
  if r == error then fail 2 r else
  let r := Guest.NoiseNK.writeFirst (sealed+24) r
  if r == error then fail 3 r else
  let t := save (envelope 1 48 r)
  let r := writeOpaque sealed 72 t
  if r == error then fail 4 r else store64 (st+8) 2 r

def receiveHandshake (kind n t : UInt64) : UInt64 :=
  if n != 48 then fail 5 t else
  if kind == 1 && load64 st t == 2 && load64 (st+8) t == 1 then
    let r := setupNoise 2 Guest.NodeEnrollment.localNode t
    if r == error then fail 6 r else
    let r := Guest.NoiseNK.readFirst (incomingCopy+24) r
    if r == error then fail 7 r else
    let r := Guest.NoiseNK.writeSecond (sealed+24) r
    if r == error then fail 8 r else
    let t := save (envelope 2 48 r)
    let r := writeOpaque sealed 72 t
    if r == error then fail 9 r else store64 (st+8) 3 r
  else if kind == 2 && load64 st t == 1 && load64 (st+8) t == 2 then
    let r := Guest.NoiseNK.readSecond (incomingCopy+24) (restore t)
    if r == error then fail 10 r else store64 (st+8) 3 (save r)
  else fail 11 t

-- Fragment header is four UInt64s: request, total, offset, direction(0/1).
-- Total/offset are authenticated. Ordered stream framing forbids holes/overlap.
def receiveRecord (n t : UInt64) : UInt64 :=
  if load64 (st+8) t != 3 || n < 48 || n > 448 then fail 12 t else
  let r := Guest.Noise.openRecord (incomingCopy+24) n fragment (restore t)
  if r == error then fail 13 r else
  let t := save r
  let request := load64 fragment t
  let total := load64 (fragment+8) t
  let offset := load64 (fragment+16) t
  let direction := load64 (fragment+24) t
  let count := n-48
  let expected := if load64 st t == 1 then 1 else 0
  if (load64 st t == 1 && request != load64 (st+64) t) || request == 0 || direction != expected || total < 64 || total > 1024 || count == 0 ||
    offset > total || count > total-offset || load64 (st+112) t != 0 then fail 14 t else
  if offset == 0 && load64 (st+48) t == 0 then
    let t := store64 (st+40) request t
    let t := store64 (st+48) total t
    let t := copy (fragment+32) received count t
    store64 (st+56) count t
  else if request != load64 (st+40) t || total != load64 (st+48) t || offset != load64 (st+56) t then fail 15 t else
    let t := copy (fragment+32) (received+offset) count t
    store64 (st+56) (offset+count) t

def processInput (t : UInt64) : UInt64 :=
  let n := load64 (Guest.TorRouter.state+80) t
  if n == 0 || (!active t && load64 (Guest.NodeEnrollment.localNode+208) t != 8) then t else
  let stream := load64 (Guest.TorRouter.state+88) t
  let source := load64 (Guest.TorRouter.state+96) t
  let t := copy Guest.TorRouter.inbox incomingCopy n t
  let t := store64 (Guest.TorRouter.state+80) 0 (zero Guest.TorRouter.inbox 64 t)
  let own := Guest.NodeEnrollment.localNode
  let t := if !active t && load64 own t == 1 && load64 (own+208) t == 8 then
    let t := store64 st 2 t
    let t := store64 (st+8) 1 t
    let t := store64 (st+24) stream t
    store64 (st+32) source t else t
  if !active t || n < 24 || load64 incomingCopy t != 1 || load64 (incomingCopy+16) t != n-24 || stream != load64 (st+24) t ||
    (load64 st t == 2 && source != load64 (st+32) t) then fail 16 t else
  let kind := load64 (incomingCopy+8) t
  if kind == 1 || kind == 2 then receiveHandshake kind (n-24) t else
  if kind == 3 then receiveRecord (n-24) t else fail 17 t

def sendQuantum (t : UInt64) : UInt64 :=
  let total := load64 (st+72) t
  let offset := load64 (st+80) t
  let channel := if load64 st t == 1 then 0 else load64 (st+32) t
  if total == 0 || offset >= total || !Guest.TorRouter.idleOutput channel t then t else
  let n := if total-offset > 400 then 400 else total-offset
  let t := store64 fragment (load64 (st+64) t) t
  let t := store64 (fragment+8) total t
  let t := store64 (fragment+16) offset t
  let t := store64 (fragment+24) (if load64 st t == 1 then 0 else 1) t
  let t := copy (outgoing+offset) (fragment+32) n t
  let r := Guest.Noise.sealRecord fragment (32+n) (sealed+24) (restore t)
  if r == error then fail 18 r else
  let t := save (envelope 3 (48+n) r)
  let r := writeOpaque sealed (72+n) t
  if r == error then fail 19 r else
  let t := store64 (st+80) (offset+n) r
  if offset+n != total then t else
    let t := store64 (st+72) 0 (store64 (st+80) 0 t)
    if load64 st t == 2 then store64 (st+48) 0 (store64 (st+56) 0 t) else t

def serverQuantum (t : UInt64) : UInt64 :=
  if load64 st t != 2 then t else
  let token := load64 (st+112) t
  if token != 0 then
    let r := syscall 134 token wire 1024 0 t
    if r == error || r > 960 then fail 20 r else
    if r == 0 then r else
    let t := store64 (st+112) 0 r
    let t := copy wire outgoing r t
    let t := store64 (st+64) (load64 (st+40) t) t
    store64 (st+72) r t
  else
  let n := load64 (st+48) t
  if n == 0 || load64 (st+56) t != n || load64 (st+72) t != 0 then t else
  let operation := load64 received t
  let registryRead := (operation == 6 || operation == 7) && n == 96 &&
    load64 (st+224) t != 0 && Guest.NodeEnrollment.eq (received+64) (st+256) 32 t
  if (operation != 441 && !registryRead) || load64 (received+56) t != 1 then fail 21 t else
  let target := if registryRead then syscall 113 0 0 0 0 t else syscall 128 3 441 0 0 t
  if registryRead && target != load64 (st+224) target then fail 25 target else
  if target == error then fail 22 target else
  let count := if registryRead then 64 else n
  let t := copy received wire count target
  let token := syscall 133 target wire count 1024 t
  if token == error then fail 23 token else store64 (st+112) token token

def pump (t : UInt64) : UInt64 :=
  let p := Guest.NodeEnrollment.peer (load64 (st+16) t)
  let t := if load64 st t == 1 && (!Guest.TorRouter.peerValid p t || !Guest.NodeEnrollment.eq (p+512) (st+192) 32 t) then fail 24 t else t
  let t := processInput t
  let t := if load64 st t == 1 && load64 (st+8) t == 1 && load64 (Guest.TorRouter.state+112) t == 1 && Guest.TorRouter.idleOutput 0 t then handshakeFirst t else t
  if !active t then t else sendQuantum (serverQuantum t)

def submitRequest (caller length t : UInt64) : UInt64 :=
  if caller != load64 (st+128) t || load64 st t != 1 || load64 (st+8) t != 3 then response 8 0 t else
  let request := load64 (command+8) t
  let n := length-64
  let operation := load64 (command+64) t
  let metadataRead := (operation == 6 || operation == 7) && n == 96
  if length < 128 || length > 1024 || request == 0 || load64 (st+72) t != 0 || load64 (st+48) t != 0 ||
    (operation != 441 && !metadataRead) || n > load64 (st+136) t || load64 (st+144) t == 0 then response 4 0 t else
  let t := copy (command+64) outgoing n t
  let t := store64 (st+64) request t
  let t := store64 (st+72) n t
  let t := store64 (st+136) (load64 (st+136) t-n) t
  let t := store64 (st+144) (load64 (st+144) t-1) t
  response 0 request t

def collectResponse (caller length t : UInt64) : UInt64 :=
  if caller != load64 (st+128) t || length != 64 then response 8 0 t else
  let n := load64 (st+48) t
  if n == 0 || load64 (st+56) t != n then response 6 0 t else
  if load64 (command+8) t != load64 (st+40) t then response 3 0 t else
  let t := header 0 (load64 (st+40) t) n 0 0 0 0 t
  let t := copy received (wire+64) n t
  64+n+store64 (st+48) 0 (store64 (st+56) 0 (zero received 128 t))

def statusResponse (t : UInt64) : UInt64 :=
  let t := header 0 (load64 st t) (load64 (st+8) t) (load64 (st+160) t) (load64 (st+136) t) (load64 (st+144) t) 0 t
  96+copy (st+192) (wire+64) 32 t

def dispatch (caller admin op length t : UInt64) : UInt64 :=
  if op == 46 && admin == 1 && length == 96 && !active t then
    let target := syscall 113 0 0 0 0 t
    if target == error || target != load64 (command+8) target ||
      Guest.Identity.zeros (command+64) 32 target then response 8 0 target else
    let t := store64 (st+224) target target
    response 0 target (copy (command+64) (st+256) 32 t)
  else if op == 38 && admin == 1 && length == 64 then
    beginClient (load64 (command+8) t) (load64 (command+16) t) (load64 (command+24) t)
      (load64 (command+32) t) (load64 (command+40) t) t
  else if op == 39 then submitRequest caller length t
  else if op == 40 then collectResponse caller length t
  else if op == 41 && length == 64 then
    if admin == 1 then statusResponse t else
    if caller == load64 (st+128) t then statusResponse t else response 8 0 t
  else if op == 42 && length == 64 then
    if admin == 1 then response 0 0 (clear t) else
    if caller == load64 (st+128) t then response 0 0 (clear t) else response 8 0 t
  else response 8 0 t
end Guest.OnionTerminal
