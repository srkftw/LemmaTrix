import Guest.NetworkSDK
import Guest.Noise
import Guest.PeerDescription
import Guest.Transport
namespace Guest.Network
open Guest.LiveSDK
-- Service6 owns this memory. No compiler/publisher key or graph root lives here.
def st : UInt64 := 0x603000
def tx : UInt64 := 0x604000
def rx : UInt64 := 0x605000
def plain : UInt64 := 0x606000
def pins : UInt64 := 0x607000
def grantAt (i : UInt64) : UInt64 := 0x608000+i*256
def jobAt (i : UInt64) : UInt64 := 0x609000+i*1024
def inbox (i : UInt64) : UInt64 := 0x60b000+i*1024
def failure (code t : UInt64) : UInt64 := 64+store64 wire code (zero wire 8 t)
def now (t : UInt64) : UInt64 := load64 st t
-- A serialized broker quantum loads one bank; no IPC/yield occurs until it is
-- saved. Every secret, grant, job, partial frame and signed pin is bank-private.
def contexts : UInt64 := 0x650000
def control : UInt64 := 0x64f000
def activeSlot (t : UInt64) : UInt64 := load64 control t
def bank (i : UInt64) : UInt64 := contexts+i*65536
-- Bounded aggregate operator diagnostics: no identities, roots, payloads or
-- history. Durations are local monotonic ticks including preemption, not CPU
-- cycles, billing units or a real-time throughput guarantee.
def measured (sum count began t : UInt64) : UInt64 :=
  let ended := syscall 110 0 0 0 0 t
  let t := store64 (control+sum) (load64 (control+sum) ended+ended-began) ended
  store64 (control+count) (load64 (control+count) t+1) t
-- Local handles bind the broker incarnation, context, type and counter. Broker
-- restart must not make a stale numeric grant/job name newly minted authority.
-- Kernel op56 forbids wrapping the low24 generation. The high30 token field
-- folds the randomized boot epoch with that incarnation; full caller identity
-- separately binds ownership. This finite token is not rollback freshness.
def localId (kind counter t : UInt64) : UInt64 :=
  (load64 (control+8) t <<< 34) ||| (activeSlot t <<< 32) ||| (kind <<< 31) ||| counter
def saveContext (i t : UInt64) : UInt64 :=
  let b := bank i
  let t := copy 0x600000 b 416 t
  let t := copy st (b+512) 136 t
  let t := copy tx (b+1024) 1024 t
  let t := copy rx (b+2048) 1024 t
  let t := copy pins (b+4096) 128 t
  let t := copy 0x608000 (b+4352) 1024 t
  let t := copy 0x609000 (b+6144) 8192 t
  let t := copy 0x60b000 (b+14336) 4096 t
  copy Guest.PeerDescription.publicKey (b+19456) 1792 t
def loadContext (i t : UInt64) : UInt64 :=
  let b := bank i
  let t := copy b 0x600000 416 t
  let t := copy (b+512) st 136 t
  let t := copy (b+1024) tx 1024 t
  let t := copy (b+2048) rx 1024 t
  let t := copy (b+4096) pins 128 t
  let t := copy (b+4352) 0x608000 1024 t
  let t := copy (b+6144) 0x609000 8192 t
  let t := copy (b+14336) 0x60b000 4096 t
  let t := copy (b+19456) Guest.PeerDescription.publicKey 1792 t
  let t := store64 control i t
  Guest.Transport.choose i t
-- Keep the selected relationship resident. A context is saved only when an
-- operation really switches relationships; dispatch and pump share residency.
-- Plaintext crypto scratch is fully overwritten by seal/open and is not state.
def selectContext (i t : UInt64) : UInt64 :=
  if activeSlot t == i then t else
  let began := syscall 110 0 0 0 0 t
  measured 32 64 began (loadContext i (saveContext (activeSlot began) began))
def networkStatus (t : UInt64) : UInt64 :=
  if Guest.Transport.enabled t then Guest.Transport.status t else syscall 101 0 0 0 0 t
def networkRead (p n t : UInt64) : UInt64 :=
  if Guest.Transport.enabled t then Guest.Transport.read p n t else syscall 102 0 p n 0 t
def networkWrite (p n t : UInt64) : UInt64 :=
  if Guest.Transport.enabled t then Guest.Transport.write p n t else syscall 103 0 p n 0 t
def networkReset (t : UInt64) : UInt64 :=
  if Guest.Transport.enabled t then Guest.Transport.close (activeSlot t) t else syscall 105 0 0 0 0 t
def protocol2 (t : UInt64) : Bool := load64 (st+128) t == 2
def session (t : UInt64) : UInt64 := load64 (Guest.Noise.state+8) t
-- Grant layout: active,handle,owner,direction,budget,used,rate,expiry,
-- rateTick,rateUsed,operation; peer/service/root hashes at96/128/160.
partial def freeGrant (i t : UInt64) : UInt64 :=
  if i == 4 then error else if load64 (grantAt i) t == 0 then i else freeGrant (i+1) t
partial def findGrant (id owner i t : UInt64) : UInt64 :=
  if i == 4 then error else
    let g := grantAt i
    if load64 g t == 1 && load64 (g+8) t == id && load64 (g+16) t == owner && now t < load64 (g+56) t then i else findGrant id owner (i+1) t
partial def findJob (id owner i t : UInt64) : UInt64 :=
  if i == 8 then error else
    let j := jobAt i
    if load64 j t != 0 && load64 (j+8) t == id && load64 (j+16) t == owner then i else findJob id owner (i+1) t
partial def freeJob (i t : UInt64) : UInt64 :=
  if i == 8 then error else if load64 (jobAt i) t == 0 || load64 (jobAt i) t >= 3 then i else freeJob (i+1) t
partial def queued (i t : UInt64) : UInt64 :=
  if i == 8 then error else if load64 (jobAt i) t == 1 then i else queued (i+1) t
partial def freeInbox (i t : UInt64) : UInt64 :=
  if i == 4 then error else if load64 (inbox i) t == 0 then i else freeInbox (i+1) t
partial def oldestInbox (id i selected t : UInt64) : UInt64 :=
  if i == 4 then selected else
    let p := inbox i
    let before := selected == error || load64 (p+1008) t < load64 (inbox selected+1008) t
    oldestInbox id (i+1) (if load64 p t == id && before then i else selected) t
def findInbox (id i t : UInt64) : UInt64 := oldestInbox id i error t
partial def inboxCount (i count t : UInt64) : UInt64 :=
  if i == 4 then count else inboxCount (i+1) (count+(if load64 (inbox i) t == 0 then 0 else 1)) t
partial def equal (a b n t : UInt64) : Bool :=
  if n == 0 then true else if load8 a t != load8 b t then false else equal (a+1) (b+1) (n-1) t
partial def nonzero (p n v t : UInt64) : UInt64 :=
  if n == 0 then v else nonzero (p+1) (n-1) (v ||| load8 p t) t
partial def failJobs (i t : UInt64) : UInt64 :=
  if i == 8 then t else
    let j := jobAt i
    let t := if load64 j t == 1 || load64 j t == 2 then store64 j 5 t else t
    failJobs (i+1) t
-- Session loss invalidates ciphertext and jobs. Validated application chunks may
-- be reused only after a new session and a new application authorization.
def disconnect (reason t : UInt64) : UInt64 :=
  let t := Guest.Noise.disconnect t
  let t := zero tx 256 t
  let t := zero rx 256 t
  let t := zero plain 256 t
  let t := zero 0x60b000 512 t
  let t := store64 (st+120) 0 t
  let t := failJobs 0 t
  let t := zero 0x608000 128 t
  let t := store64 (st+32) 0 t
  let t := store64 (st+40) 0 t
  let t := store64 (st+48) 0 t
  let t := store64 (st+56) 0 t
  let t := store64 (st+64) 0 t
  let t := store64 (st+80) reason t
  store64 (st+88) (now t+20) t

partial def activeForGrant (handle i t : UInt64) : Bool :=
  if i == 8 then false else
    let j := jobAt i
    ((load64 j t == 1 || load64 j t == 2) && load64 (j+24) t == handle) || activeForGrant handle (i+1) t
partial def cancelRevoked (i t : UInt64) : UInt64 :=
  if i == 8 then t else
    let j := jobAt i
    let active := load64 j t == 1 || load64 j t == 2
    let g := if active then findGrant (load64 (j+24) t) (load64 (j+16) t) 0 t else 0
    let t := if active && g == error then
      if load64 j g == 2 then disconnect 15 (networkReset g) else store64 j 5 g
      else g
    cancelRevoked (i+1) t
partial def visibleGrant (id i t : UInt64) : Bool :=
  if i == 4 then false else
    let g := grantAt i
    (load64 g t == 1 && load64 (g+8) t == id && now t < load64 (g+56) t) || visibleGrant id (i+1) t
partial def reclaimInbox (i t : UInt64) : UInt64 :=
  if i == 4 then t else
    let p := inbox i
    let id := load64 p t
    let t := if id != 0 && !visibleGrant id 0 t then zero p 128 t else t
    reclaimInbox (i+1) t

def fresh (t : UInt64) : UInt64 :=
  let r := syscall 104 0 Guest.Noise.privateKey 32 0 t
  if r != 32 then disconnect 11 r else
    let t := copy pins Guest.Noise.binding 96 r
    let t := copy (pins+96) Guest.Noise.psk 32 t
    let t := Guest.Noise.initHandshake (load64 (st+8) t) t
    let t := store64 (st+96) (now t+100000) t
    let t := store64 (st+104) (now t+100000) t
    if load64 (st+8) t == 1 then
      let t := Guest.Noise.writeFirst (tx+2) t
      let t := Guest.VaultCrypto.putLE tx 48 2 t
      store64 (st+40) 50 t
    else t

def chargeable (g bytes t : UInt64) : Bool :=
  load64 g t == 1 && now t < load64 (g+56) t &&
  bytes <= load64 (g+32) t && load64 (g+40) t <= load64 (g+32) t-bytes &&
  bytes <= load64 (g+48) t && (load64 (g+64) t != now t || load64 (g+72) t <= load64 (g+48) t-bytes)
def charge (g bytes t : UInt64) : UInt64 :=
  let rateUsed := if load64 (g+64) t == now t then load64 (g+72) t else 0
  let t := store64 (g+40) (load64 (g+40) t+bytes) t
  let t := store64 (g+64) (now t) t
  store64 (g+72) (rateUsed+bytes) t
partial def incomingGrant (root operation stream bytes i t : UInt64) : UInt64 :=
  if i == 4 then error else
    let g := grantAt i
    if (load64 (g+24) t &&& 2) != 0 && load64 (g+80) t == operation && load64 (g+88) t == stream && equal root (g+160) 32 t && chargeable g bytes t then i
    else incomingGrant root operation stream bytes (i+1) t

def acceptRecord (n t : UInt64) : UInt64 :=
  let began := syscall 110 0 0 0 0 t
  let raw := Guest.Noise.openRecord (rx+2) n plain began
  let r := measured 48 80 began raw
  if raw == error then disconnect 12 r else
    let overhead := if protocol2 r then 80 else 64
    if n < overhead || load64 (plain+40) r != n-overhead then disconnect 2 r else
      let length := n-overhead
      let stream := if protocol2 r then load64 (plain+48) r else 0
      let request := if protocol2 r then load64 (plain+56) r else 0
      if protocol2 r && (stream == 0 || request == 0) then disconnect 2 r else
      let selected := incomingGrant plain (load64 (plain+32) r) stream length 0 r
      let vacant := freeInbox 0 selected
      if selected == error || vacant == error then store64 (st+80) 1 vacant else
        let g := grantAt selected
        let p := inbox vacant
        let t := store64 p (load64 (g+8) vacant) vacant
        let sequence := load64 (st+120) t+1
        let t := store64 (st+120) sequence t
        let t := store64 (p+1008) sequence t
        let t := store64 (p+8) length t
        let t := store64 (p+16) request t
        let t := copy (plain+(if protocol2 t then 64 else 48)) (p+32) length t
        let t := charge g length t
        -- Coalesced readiness only: the full live grant owner receives no
        -- authority or remote payload through this kernel notification.
        syscall 126 (load64 (g+16) t) 0 0 0 t

def acceptFrame (n t : UInt64) : UInt64 :=
  let phase := session t
  if phase == 3 then acceptRecord n t else
  if n != 48 then disconnect 2 t else
  if load64 (st+8) t == 1 && phase == 2 then
    let r := Guest.Noise.readSecond (rx+2) t
    if r == error then disconnect 12 r else r
  else if load64 (st+8) t == 2 && phase == 1 then
    let r := Guest.Noise.readFirst (rx+2) t
    if r == error then disconnect 12 r else
      let r := Guest.Noise.writeSecond (tx+2) r
      if r == error then disconnect 12 r else
        let t := Guest.VaultCrypto.putLE tx 48 2 r
        let t := store64 (st+32) 0 t
        store64 (st+40) 50 t
  else disconnect 2 t

partial def readFrameReady (remaining t : UInt64) : UInt64 :=
  if remaining == 0 then t else
  let pos := load64 (st+48) t
  let length := load64 (st+56) t
  let want := if pos < 2 then 2-pos else length+2-pos
  if want == 0 || want > 786 then disconnect 2 t else
    let r := networkRead (rx+pos) want t
    if r == error then disconnect 10 r else
    if r == 0 then r else
      let pos := pos+r
      let t := store64 (control+24) (load64 (control+24) r+1) r
      let t := store64 (st+48) pos t
      let length := if pos == 2 then load8 rx t ||| (load8 (rx+1) t <<< 8) else length
      if length > 784 || (pos >= 2 && length < 16) then disconnect 2 t else
        let t := store64 (st+56) length t
        if pos == length+2 then
          let t := acceptFrame length t
          let t := store64 (st+48) 0 t
          store64 (st+56) 0 t
        else readFrameReady (remaining-1) t

def readFrame (t : UInt64) : UInt64 := readFrameReady 2 t

def writeFrame (t : UInt64) : UInt64 :=
  let pos := load64 (st+32) t
  let length := load64 (st+40) t
  if pos >= length then t else
    let r := networkWrite (tx+pos) (length-pos) t
    if r == error then disconnect 10 r else
      let pos := pos+r
      let t := if r == 0 then r else store64 (control+24) (load64 (control+24) r+1) r
      let t := store64 (st+32) pos t
      if pos == length then
        let active := load64 (st+64) t
        let t := if active == 0 then t else
          let j := jobAt (active-1)
          let t := store64 j 3 t
          syscall 126 (load64 (j+16) t) 0 0 0 t
        let t := store64 (st+32) 0 t
        let t := store64 (st+40) 0 t
        store64 (st+64) 0 t
      else t

def queueFrame (t : UInt64) : UInt64 :=
  let selected := queued 0 t
  if selected == error then t else
    let j := jobAt selected
    let found := findGrant (load64 (j+24) t) (load64 (j+16) t) 0 t
    if found == error then store64 j 5 found else
      let g := grantAt found
      let n := load64 (j+32) found
      let t := copy (g+160) plain 32 found
      let t := store64 (plain+32) (load64 (g+80) t) t
      let t := store64 (plain+40) n t
      let t := if protocol2 t then store64 (plain+48) (load64 (g+88) t) t else t
      let t := if protocol2 t then store64 (plain+56) (load64 (j+40) t) t else t
      let header := if protocol2 t then 64 else 48
      let t := copy (j+64) (plain+header) n t
      let began := syscall 110 0 0 0 0 t
      let raw := Guest.Noise.sealRecord plain (n+header) (tx+2) began
      let r := measured 40 72 began raw
      if raw == error then disconnect 12 r else
        let t := Guest.VaultCrypto.putLE tx (n+header+16) 2 r
        let t := store64 (st+40) (n+header+18) t
        let t := store64 (st+64) (selected+1) t
        store64 j 2 t

partial def expireGrants (i t : UInt64) : UInt64 :=
  if i == 4 then t else
    let g := grantAt i
    let caller := load64 (g+16) t
    let alive := if load64 g t == 1 then syscall 34 caller 0 0 0 t else 0
    let t := if load64 g alive == 1 && (now alive >= load64 (g+56) alive || alive == error) then store64 g 0 alive else alive
    expireGrants (i+1) t

def pump (initial : UInt64) : UInt64 :=
  let t := store64 st (syscall 110 0 0 0 0 initial) initial
  let t := expireGrants 0 t
  let t := cancelRevoked 0 t
  let t := reclaimInbox 0 t
  let device := networkStatus t
  if device == error || (device &&& 3) != 3 then
    if session device == 0 && load64 (st+80) device == 10 then device else disconnect 10 device
  else
    let epoch := device >>> 32
    let t := if epoch != load64 (st+24) device then store64 (st+24) epoch (disconnect 10 device) else device
    if load64 (st+8) t == 0 || now t < load64 (st+88) t then t else
      let t := if session t == 0 then fresh t else t
      -- Expiry terminates this transport epoch before fresh authentication. An
      -- asynchronous peer may still have ciphertext queued under the old key.
      if (session t != 3 && now t >= load64 (st+96) t) || (session t == 3 && now t >= load64 (st+104) t) then disconnect 13 (networkReset t) else
        let t := if load64 (st+40) t == 0 && session t == 3 then queueFrame t else t
        let t := writeFrame t
        if freeInbox 0 t == error then t else readFrame t

def jobResponse (j t : UInt64) : UInt64 :=
  let t := zero wire 8 t
  let t := store64 (wire+8) (load64 (j+8) t) t
  let t := store64 (wire+16) (load64 j t) t
  let t := store64 (wire+24) (if load64 j t == 3 then load64 (j+32) t else 0) t
  let t := store64 (wire+32) (load64 (j+32) t) t
  let t := store64 (wire+40) (session t) t
  64+store64 (wire+48) (load64 (st+80) t) t

def configure (role length t : UInt64) : UInt64 :=
  if length != 192 || (role != 1 && role != 2) || nonzero (command+160) 32 0 t == 0 ||
    nonzero (command+64) 32 0 t == 0 || nonzero (command+96) 32 0 t == 0 || nonzero (command+128) 32 0 t == 0 || equal (command+64) (command+96) 32 t ||
    (Guest.PeerDescription.selected t && !Guest.PeerDescription.matchesPins (command+64) t) then failure 2 t else
    let t := disconnect 0 t
    let t := zero 0x608000 2048 t
    let t := copy (command+64) pins 128 t
    let t := store64 (st+8) role t
    failure 0 t

partial def ambiguousReceive (root operation stream i t : UInt64) : Bool :=
  if i == 4 then false else
    let g := grantAt i
    (load64 g t == 1 && (load64 (g+24) t &&& 2) != 0 && now t < load64 (g+56) t &&
      load64 (g+80) t == operation && load64 (g+88) t == stream && equal root (g+160) 32 t) ||
      ambiguousReceive root operation stream (i+1) t

def grant (caller length t : UInt64) : UInt64 :=
  if length != (if protocol2 t then 176 else 168) then failure 2 t else
  let direction := load64 (command+16) t
  let mode := load64 (command+24) t
  let budget := load64 (command+32) t
  let rate := load64 (command+40) t
  let lifetime := load64 (command+48) t
  let operation := load64 (command+160) t
  let stream := if protocol2 t then load64 (command+168) t else 0
  let peer := pins+(if load64 (st+8) t == 1 then 32 else 0)
  let ceiling := if Guest.PeerDescription.verified t then load64 (Guest.PeerDescription.description+48) t else 16777216
  if !Guest.NetworkSDK.modeAvailable mode then failure 7 t else
  if !Guest.PeerDescription.permits operation t then failure 1 t else
  if (protocol2 t && stream == 0) || direction == 0 || direction > 3 || budget == 0 || budget > ceiling || rate == 0 || rate > 65536 || lifetime == 0 || lifetime > 100000 || operation == 0 || operation > 16 ||
    load64 (st+8) t == 0 || !equal (command+64) peer 32 t || !equal (command+96) (pins+64) 32 t then failure 2 t else
    if (direction &&& 2) != 0 && ambiguousReceive (command+128) operation stream 0 t then failure 4 t else
    let selected := freeGrant 0 t
    if selected == error || load64 (st+16) t >= 0x7fffffff || load64 (control+8) t > 0x3fffffff then failure 4 selected else
      let g := grantAt selected
      let counter := (load64 (st+16) selected &&& 0xffffffff)+1
      let id := localId 0 counter selected
      let t := store64 (st+16) counter selected
      let t := zero g 32 t
      let t := store64 g 1 t
      let t := store64 (g+8) id t
      let t := store64 (g+16) caller t
      let t := store64 (g+24) direction t
      let t := store64 (g+32) budget t
      let t := store64 (g+48) rate t
      let t := store64 (g+56) (now t+lifetime) t
      let t := store64 (g+80) operation t
      let t := store64 (g+88) stream t
      let t := copy (command+64) (g+96) 96 t
      let t := zero wire 8 t
      64+store64 (wire+8) id t

def sendMessage (caller handle operation n t : UInt64) : UInt64 :=
  let selected := findGrant handle caller 0 t
  if selected == error then failure 3 selected else
    let g := grantAt selected
    if (load64 (g+24) selected &&& 1) == 0 || load64 (g+80) selected != operation then failure 1 selected else
    if (protocol2 selected && (n > 704 || load64 (command+24) selected == 0)) then failure 2 selected else
    if activeForGrant handle 0 selected || !chargeable g n selected then failure 4 selected else
      let vacant := freeJob 0 selected
      if vacant == error || load64 (st+112) vacant >= 0x7fffffff || load64 (control+8) vacant > 0x3fffffff then failure 4 vacant else
        let j := jobAt vacant
        let counter := (load64 (st+112) vacant &&& 0xffffffff)+1
        let id := localId 1 counter vacant
        let t := store64 (st+112) counter vacant
        let t := zero j 128 t
        let t := store64 j 1 t
        let t := store64 (j+8) id t
        let t := store64 (j+16) caller t
        let t := store64 (j+24) handle t
        let t := store64 (j+32) n t
        let t := store64 (j+40) (load64 (command+24) t) t
        let t := copy (command+64) (j+64) n t
        let t := charge g n t
        -- Attempt one ready immutable output before replying. Completion still
        -- means opaque adapter acceptance only. Backpressure retains the same
        -- asynchronous job; nonce allocation and finite-byte charge happen once.
        let t := if Guest.Transport.enabled t then Guest.Transport.flush t else t
        let t := if load64 (st+40) t == 0 && session t == 3 then writeFrame (queueFrame t) else t
        let t := if Guest.Transport.enabled t then Guest.Transport.flush t else t
        jobResponse j t

def cancelJob (j t : UInt64) : UInt64 :=
  if load64 j t >= 3 then failure 6 t else
  if load64 j t == 2 then
    let t := networkReset t
    failure 0 (store64 j 4 (disconnect 14 t))
  else failure 0 (store64 j 4 t)

def receiveMessage (caller handle t : UInt64) : UInt64 :=
  let selected := findGrant handle caller 0 t
  if selected == error then failure 3 selected else
    let g := grantAt selected
    if (load64 (g+24) selected &&& 2) == 0 then failure 1 selected else
      let selected := findInbox handle 0 selected
      if selected == error then failure 6 selected else
        let p := inbox selected
        let n := load64 (p+8) selected
        let t := zero wire 8 selected
        let t := store64 (wire+8) handle t
        let t := store64 (wire+16) n t
        let t := store64 (wire+24) (load64 (p+16) t) t
        let t := copy (p+32) (wire+64) n t
        64+n+zero p 128 t

def dispatchSelected (caller rights length t : UInt64) : UInt64 :=
  let op := load64 command t
  let handle := load64 (command+8) t
  let admin := (rights &&& 0x100000000) != 0
  let t := store64 (control+96) (load64 (control+96) t+1) t
  if length < 64 || load64 (command+56) t != 1 then failure 2 t else
  if op == 13 && (admin || (rights &&& 1024) != 0) && length == 64 then
    if !Guest.PeerDescription.verified t || load64 (st+8) t == 0 then failure 1 t else
      let r := Guest.Transport.connect (activeSlot t) (load64 (st+8) t) (Guest.PeerDescription.description+168) (load64 (Guest.PeerDescription.description+160) t) t
      if r == error then failure 6 r else failure 0 r
  else if op == 14 && (admin || caller == syscall 119 0 0 0 0 t) && length == 64 then
    let r := networkReset t
    failure 0 (store64 (st+8) 0 (disconnect 16 r))
  else if op == 11 && admin then
    let t := store64 (st+8) 0 (disconnect 16 (networkReset t))
    Guest.PeerDescription.stage length t
  else
  if op == 12 && admin then Guest.PeerDescription.confirm length t else
  if op == 16 && admin && length == 64 then
    let t := zero wire 8 t
    160+copy (control+32) (wire+64) 96 t
  else
  if op == 1 && admin then configure (load64 (command+16) t) length t else
  if op == 9 && admin then failure 0 (disconnect 0 (networkReset t)) else
  if (rights &&& 1024) == 0 && !admin then failure 1 t else
  if op == 15 && length == 64 then
    if !Guest.PeerDescription.verified t then failure 3 t else
      let t := zero wire 8 t
      let t := store64 (wire+8) (activeSlot t) t
      let t := store64 (wire+16) 512 t
      let t := store64 (wire+24) 1 t
      576+copy Guest.PeerDescription.description (wire+64) 512 t
  else if op == 10 && length == 64 then
    let r := syscall 104 0 (wire+64) 32 0 t
    if r != 32 then failure 11 r else 96+zero wire 8 r
  else if op == 2 then grant caller length t else
  if op == 3 && length <= 784 then sendMessage caller handle (load64 (command+16) t) (length-64) t else
  if op == 6 && length == 64 then receiveMessage caller handle t else
  if op == 7 && length == 64 then
    let t := zero wire 8 t
    let t := store64 (wire+8) (session t) t
    let t := store64 (wire+16) (load64 (st+8) t) t
    let t := store64 (wire+24) (networkStatus t) t
    let t := store64 (wire+32) (now t) t
    let t := store64 (wire+56) (if Guest.PeerDescription.verified t then 1 else 0) t
    let t := store64 (wire+48) (inboxCount 0 0 t) t
    64+store64 (wire+40) (load64 (st+80) t) t
  else if op == 8 && length == 64 then
    let selected := findGrant handle caller 0 t
    if selected == error then failure 3 selected else
      failure 0 (store64 (grantAt selected) 0 selected)
  else if (op == 4 || op == 5) && length == 64 then
    let selected := findJob handle caller 0 t
    if selected == error then failure 3 selected else
      if op == 4 then jobResponse (jobAt selected) selected else cancelJob (jobAt selected) selected
  else failure 2 t

-- V2 selects a context in the high byte of version (2 | slot<<8). The
-- request operation/handles remain unchanged; legacy version1 selects slot0.
def dispatch (caller rights length t : UInt64) : UInt64 :=
  let version := load64 (command+56) t
  let slot : UInt64 := if version == 1 then 0 else version >>> 8
  if length < 64 || (version != 1 && ((version &&& 255) != 2 || slot >= 4)) then failure 2 t else
  if version == 1 && Guest.Transport.enabled t then failure 2 t else
  let t := if version != 1 then store64 Guest.Transport.st 1 t else t
  let t := selectContext slot t
  -- Maintenance may skip an idle peer, but an RPC never spends authority
  -- against a cached clock or extends a lease by the maintenance interval.
  let clock := syscall 110 0 0 0 0 t
  let t := store64 st clock clock
  let t := store64 (command+56) 1 t
  let t := if load64 command t == 1 then store64 (st+128) (if version == 1 then 1 else 2) t else t
  dispatchSelected caller rights length t

-- Idle authenticated peers need bounded lease/owner maintenance, not a full
-- context copy each broker turn. Actual adapter input, epoch changes and queued
-- sends are ready immediately. The auxiliary deadline carries no authority.
def contextWord (i offset t : UInt64) : UInt64 :=
  load64 ((if activeSlot t == i then st else bank i+512)+offset) t
partial def contextQueued (i j t : UInt64) : Bool :=
  if j == 8 then false else
  let p := (if activeSlot t == i then jobAt j else bank i+6144+j*1024)
  load64 p t == 1 || load64 p t == 2 || contextQueued i (j+1) t
def contextReady (i clock t : UInt64) : Bool :=
  let p := Guest.Transport.channel i
  let phase := load64 ((if activeSlot t == i then Guest.Noise.state else bank i)+8) t
  clock >= load64 (bank i+21504) t ||
    load64 (p+32) t != 0 || load64 p t != contextWord i 24 t ||
    contextWord i 40 t != 0 || contextQueued i 0 t ||
    (phase != 3 && clock >= contextWord i 88 t)
partial def pumpContexts (i clock t : UInt64) : UInt64 :=
  if i == 4 then store64 (control+16) ((load64 (control+16) t+1)%4) t else
    -- Rotate first access to the single bounded device output frame.
    let slot := (load64 (control+16) t+i)%4
    if contextWord slot 8 t == 0 || !contextReady slot clock t then pumpContexts (i+1) clock t else
    let t := selectContext slot t
    let t := pump t
    let t := store64 (bank slot+21504) (clock+20) t
    pumpContexts (i+1) clock t

partial def serveReady (endpoint remaining t : UInt64) : UInt64 :=
  let networkBefore := load64 (control+24) t
  let deviceBefore := load64 (Guest.Transport.st+56) t
  let began := syscall 110 0 0 0 0 t
  let t := Guest.Transport.pump began
  let t := if Guest.Transport.enabled t then
    let clock := syscall 110 0 0 0 0 t
    pumpContexts 0 clock clock
    else pump (selectContext 0 t)
  -- Flush a newly queued immutable adapter frame in this same bounded turn.
  let t := if Guest.Transport.enabled t then Guest.Transport.flush t else t
  let t := measured 56 88 began t
  let n := syscall 36 endpoint incoming 1024 0 t
  if n == 0 || n == error then
    let progressed := networkBefore != load64 (control+24) n || deviceBefore != load64 (Guest.Transport.st+56) n
    if progressed && remaining != 0 then serveReady endpoint (remaining-1) n
    else
      let t := store64 (control+104) (load64 (control+104) n+1) n
      let field := if progressed then 120 else 112
      let t := store64 (control+field) (load64 (control+field) t+1) t
      serveReady endpoint 3 (syscall 109 0 0 0 0 t)
  else
    let caller := load64 incoming n
    let token := load64 (incoming+8) n
    let rights := load64 (incoming+16) n
    let r := if n >= 96 && load64 (incoming+24) n == 2 then dispatch caller rights (n-32) n else failure 2 n
    let t := reply token r r
    -- Provisioning request input is sensitive: never retain it between turns.
    let t := zero incoming 128 t
    if remaining != 0 then serveReady endpoint (remaining-1) t
    else
      let t := store64 (control+104) (load64 (control+104) t+1) t
      let t := store64 (control+120) (load64 (control+120) t+1) t
      serveReady endpoint 3 (syscall 109 0 0 0 0 t)

def serve (endpoint t : UInt64) : UInt64 := serveReady endpoint 3 t

def main (initial : UInt64) : UInt64 :=
  let t := zero 0x600000 16384 initial
  let t := zero Guest.PeerDescription.publicKey 224 t
  let t := zero Guest.Transport.st 512 t
  let t := zero 0x641000 1024 t
  let t := zero control 16 t
  let t := zero contexts 32768 t
  let brokerInstance := self t
  let incarnation := (brokerInstance >>> 8) &&& 0xffffff
  let epoch := ((brokerInstance >>> 32)+incarnation) &&& 0x3fffffff
  let t := store64 (control+8) epoch t
  serve brokerInstance t
end Guest.Network
