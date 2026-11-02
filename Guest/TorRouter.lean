import Guest.LiveSDK
import Guest.Transport
import Guest.NoiseNK
import Guest.NodeEnrollment
import Guest.TorNtor
import Guest.TorCells
import Guest.TorPolicy
namespace Guest.TorRouter
open Guest.LiveSDK
-- Native bounded telescoping circuit engine. Twelve independently authenticated (adapter slots0..11)
-- adjacent channels; one circuit per channel; one buffered cell per direction.
-- This engine alone does not authorize application mode1 or terminal services.
-- Terminal bytes remain opaque. An authenticated end-to-end terminal protocol
-- must bind mailbox/object authority before a caller may claim routed delivery.
def state : UInt64 := 0x6f0000
def channel (i : UInt64) : UInt64 := 0x720000+i*16384
def circuit (i : UInt64) : UInt64 := state+1024+i*128
def hop (i : UInt64) : UInt64 := 0x6d0000+i*4096
def hopScratch : UInt64 := 0x6cf000
-- Only a personal client's three in-progress ntor transcripts use this bank;
-- keep its full bounded extent separate from all shared cell/argument scratch.
def ntorState (i : UInt64) : UInt64 := 0x760000+i*512
def args : UInt64 := state+8192
def fresh : UInt64 := state+12288
def temporary : UInt64 := state+12544
def body : UInt64 := state+16384
def cell : UInt64 := state+17408
def inbox : UInt64 := state+20480
def padding : UInt64 := state+22528
def enabled (t : UInt64) : Bool := load64 state t == 1
def ready (i t : UInt64) : Bool := i < 12 && load64 (channel i) t == 4
def idleOutput (i t : UInt64) : Bool := load64 (channel i+48) t == 0
def response (code value t : UInt64) : UInt64 := 64+header code value (load64 (state+24) t) (load64 (state+48) t) 0 0 0 t
def saveNoise (i t : UInt64) : UInt64 := copy Guest.Noise.state (channel i+512) 416 t
def loadNoise (i t : UInt64) : UInt64 := copy (channel i+512) Guest.Noise.state 416 t
partial def eraseChannels (i t : UInt64) : UInt64 :=
  if i == 12 then t else
    let t := Guest.Transport.close i t
    let t := zero (channel i) 2048 t
    let t := Guest.TorCells.teardown (hop i) t
    eraseChannels (i+1) t
def stop (reason t : UInt64) : UInt64 :=
  let t := eraseChannels 0 t
  let t := zero state 8192 t
  let t := zero 0x760000 1024 t
  let t := zero 0x6c0000 1024 t
  let t := zero hopScratch 256 t
  let t := Guest.Noise.disconnect t
  store64 (state+48) reason t
-- One route owns one incoming/outgoing pair. Invalid input, quota and link
-- loss retire only that pair; no unrelated admitted circuit is reset. Clients
-- have one three-hop route, so their route-wide stop remains appropriate.
def retireChannel (i t : UInt64) : UInt64 :=
  if i >= 12 then t else
  let t := Guest.Transport.close i t
  let t := zero (channel i) 2048 t
  let t := zero (circuit i) 128 t
  Guest.TorCells.teardown (hop i) t
def abort (reason t : UInt64) : UInt64 :=
  if load64 (state+8) t == 1 then stop reason t else
  let i := load64 (state+72) t
  let c := circuit i
  let phase := load64 c t
  let paired := if phase >= 2 && phase <= 6 then load64 (c+40) t
    else if phase == 1 then load64 (c+16) t else error
  let t := if load64 (state+96) t == i || load64 (state+96) t == paired then
    store64 (state+80) 0 (zero inbox 64 t) else t
  let t := retireChannel paired (retireChannel i t)
  -- Diagnostic is the latest isolated failure, not a router-stopped flag.
  store64 (state+48) reason t
-- Peer descriptor access is public. Private scalars remain broker-owned.
def peerValid (p t : UInt64) : Bool := load64 p t == 1 && load64 (p+360) t == 0
def localDescription (t : UInt64) : UInt64 := Guest.NodeEnrollment.localNode+Guest.Effects.effectValue 0 t
partial def findPeer (identity i t : UInt64) : UInt64 :=
  if i == 8 then error else
    let p := Guest.NodeEnrollment.peer i
    if peerValid p t && Guest.NodeEnrollment.eq identity (p+144) 32 t then i else findPeer identity (i+1) t
partial def freeChannel (i t : UInt64) : UInt64 :=
  if i == 12 then error else if load64 (channel i) t == 0 then i else freeChannel (i+1) t
-- Signed node terms are per authenticated adjacent channel, both directions
-- combined, in wire bytes and one work unit per Noise record. They are finite
-- admission allowances, not civil-time expiry, prices or durable receipts.
def accountRecord (i wireBytes t : UInt64) : UInt64 :=
  if i >= 12 then Guest.Effects.effectValue error (abort 55 t) else
  -- Output may originate in a terminal turn after another channel was pumped.
  -- The charged channel, rather than the last scheduler cursor, owns failure.
  let t := store64 (state+72) i t
  let p := channel i
  let byteLimit := load64 (p+112) t
  let workLimit := load64 (p+120) t
  let used := load64 (p+128) t
  let work := load64 (p+136) t
  if !Guest.TorPolicy.recordAllowed i wireBytes used byteLimit work workLimit then
    Guest.Effects.effectValue error (abort 55 t)
  else
    let t := store64 (p+128) (used+wireBytes) t
    store64 (p+136) (work+1) t
-- A connect is admitted per channel, then queued only after the one immutable
-- adapter frame and pending closes drain. Busy control output is backpressure,
-- not failed route authority. The existing setup deadline bounds this wait.
def connectPending (i t : UInt64) : UInt64 :=
  let c := channel i
  if load64 (c+144) t != 1 || !Guest.Transport.controlAvailable t then t else
  let role := load64 (c+8) t
  let p := if role == 2 then localDescription t else Guest.NodeEnrollment.peer (load64 (c+16) t)
  if (role == 1 && !peerValid p t) || (role == 2 && load64 p t != 1) then abort 52 t else
  let r := Guest.Transport.connect i role (p+376) (load64 (p+368) t) t
  if r == error then abort 47 r else store64 (c+144) 0 r
-- Listeners use the exact local installed declaration; initiators use an
-- explicitly approved responder descriptor. Channel state is banked separately.
def openChannel (i role peerIndex t : UInt64) : UInt64 :=
  let p := if role == 2 then localDescription t else Guest.NodeEnrollment.peer peerIndex
  if i >= 12 || (role != 1 && role != 2) || (role == 1 && (peerIndex >= 8 || !peerValid p t)) || (role == 2 && load64 p t != 1) then error else
    let t := zero (channel i) 2048 t
    let t := store64 (channel i+8) role t
    let t := store64 (channel i+16) peerIndex t
    let t := store64 (channel i+112) (load64 (p+232) t) t
    let t := store64 (channel i+120) (load64 (p+240) t) t
    let t := store64 (channel i) 1 t
    let clock := syscall 110 0 0 0 0 t
    let t := store64 (channel i+88) (clock+100000) clock
    connectPending i (store64 (channel i+144) 1 t)
-- Queue a48-byte Noise handshake. At most one immutable record is buffered.
def queueHandshake (i t : UInt64) : UInt64 :=
  let t := accountRecord i 50 t
  if t == error then t else
  let p := channel i
  let t := Guest.VaultCrypto.putLE (p+4096) 48 2 t
  store64 (p+48) 50 (store64 (p+56) 0 t)
def acceptedWindow (i t : UInt64) : UInt64 :=
  let p := channel i
  -- Waiting for an arrival is not part of that new link's setup lifetime.
  -- Only the accepted listener transition starts a fresh finite deadline;
  -- outgoing connects retain their original absolute setup deadline.
  if load64 p t == 1 && load64 (p+8) t == 2 then
    store64 (p+88) (load64 (p+160) t+100000) t else t
def startHandshake (i t : UInt64) : UInt64 :=
  let p := channel i
  let t := acceptedWindow i t
  let role := load64 (p+8) t
  let peerIndex := load64 (p+16) t
  let declared := if role == 2 then localDescription t else Guest.NodeEnrollment.peer peerIndex
  let r := syscall 104 0 fresh 32 0 t
  if r != 32 then abort 6 r else
    let t := Guest.NoiseNK.init role Guest.NodeEnrollment.keys (declared+256) (declared+512) fresh r
    let t := zero fresh 4 t
    let t := if role == 1 then Guest.NoiseNK.writeFirst (p+4098) t else t
    if t == error then abort 53 t else
    let t := if role == 1 then queueHandshake i t else t
    if t == error then t else
    let t := store64 p (if role == 1 then 3 else 2) t
    saveNoise i t
-- Frame encrypted514-byte fixed Tor cells in a length-prefixed Noise record.
def queueCell (i input t : UInt64) : UInt64 :=
  if t == error then Guest.Effects.effectValue error (abort 54 t) else
  let p := channel i
  if !ready i t || !idleOutput i t then error else
    let t := accountRecord i 532 t
    if t == error then t else
    let t := loadNoise i t
    let r := Guest.Noise.sealRecord input 514 (p+4098) t
    if r == error then abort 8 r else
      let t := Guest.VaultCrypto.putLE (p+4096) 530 2 r
      let t := store64 (p+48) 532 t
      saveNoise i (store64 (p+56) 0 t)
-- Terminal record adaptation: marker4d, BE stream2/length2, opaque bytes.
-- These bytes contain the independent client/mailbox NoiseNK handshake/records;
-- the final relay's adjacent NK key grants no authority over terminal answers.
def queueTerminal (i stream input n t : UInt64) : UInt64 :=
  if t == error then Guest.Effects.effectValue error (abort 54 t) else
  let t := if i < 12 then store64 (state+72) i t else t
  let p := channel i
  if !ready i t || !idleOutput i t || n == 0 || n > 498 || stream == 0 || stream > 65535 then error else
    let t := accountRecord i (n+23) t
    if t == error then t else
    let t := store8 (p+7168) 77 t
    let t := Guest.TorCells.putBE (p+7169) stream 2 0 t
    let t := Guest.TorCells.putBE (p+7171) n 2 0 t
    let t := copy input (p+7173) n t
    let t := loadNoise i t
    let r := Guest.Noise.sealRecord (p+7168) (n+5) (p+4098) t
    if r == error then abort 44 r else
      let t := Guest.VaultCrypto.putLE (p+4096) (n+21) 2 r
      let t := store64 (p+48) (n+23) t
      saveNoise i (store64 (p+56) 0 t)
def flushChannel (i t : UInt64) : UInt64 :=
  let p := channel i
  let n := load64 (p+48) t
  let pos := load64 (p+56) t
  if n == 0 then t else
    let t := Guest.Transport.choose i t
    let r := Guest.Transport.write (p+4096+pos) (n-pos) t
    if r == error then abort 9 r else
      let t := if r == 0 then r else store64 (p+152) (load64 (p+160) r+30000) r
      if pos+r == n then store64 (p+48) 0 (store64 (p+56) 0 t)
      else store64 (p+56) (pos+r) t
-- Public ntor inputs are pinned to the exact accepted descriptor commitment.
def ntorArgs (p t : UInt64) : UInt64 :=
  let t := store64 args (p+144) t
  let t := store64 (args+8) (p+288) t
  let t := store64 (args+16) fresh t
  let t := store64 (args+24) (p+512) t
  let t := store64 (args+32) 32 t
  let t := store8 (fresh+32) 0 t
  let t := store64 (args+40) (fresh+32) t
  let t := store64 (args+48) 1 t
  store64 (args+56) (Guest.NodeEnrollment.keys+32) t
-- Padding must be unpredictable. Draw32 bytes, then use SHAKE256 to generate
-- per-cell padding. This is an explicit guest adapter; no host fills cells.
def freshPadding (t : UInt64) : UInt64 :=
  let r := syscall 104 0 fresh 32 0 t
  if r != 32 then Guest.Effects.effectValue error (abort 6 r) else
    let t := Guest.SHA3.shake 0x6c0000 0x6c0100 fresh 32 padding 509 r
    zero 0x6c0000 64 (zero fresh 4 t)
partial def clientLayers (n direction t : UInt64) : UInt64 :=
  if n == 0 then t else
    let r := Guest.TorCells.cryptLayer (hop (n-1)) direction body t
    if r == error then r else clientLayers (n-1) direction r
def clientRelay (command stream data n early t : UInt64) : UInt64 :=
  let built := load64 (state+24) t
  if built == 0 || built > 3 || !idleOutput 0 t ||
    (command == 2 && (load64 (state+112) t != 1 || load64 (state+152) t != stream)) then error else
    let r := freshPadding t
    if r == error then error else
      let t := Guest.TorCells.prepare body command stream data n padding r
      if t == error then t else
      let t := Guest.TorCells.originate (hop (built-1)) hopScratch 0 body t
      if t == error then Guest.Effects.effectValue error (abort 54 t) else
      let t := clientLayers (built-1) 0 t
      if t == error then Guest.Effects.effectValue error (abort 54 t) else
      let t := Guest.TorCells.frame cell (load64 (circuit 0+8) t) (if early == 1 then 9 else 3) body t
      queueCell 0 cell t
-- Terminal relationships are serialized over one existing three-hop route.
-- END phase144:0none/1pending/2acknowledged/3busy;152active stream,
-- 160ending stream,168reason. These are live state, never retained authority.
def endTerminal (stream t : UInt64) : UInt64 :=
  if load64 (state+8) t != 1 || load64 (state+24) t != 3 || stream == 0 ||
    stream != load64 (state+152) t || load64 (state+80) t != 0 then error else
  if load64 (state+144) t == 1 || load64 (state+144) t == 2 then t else
  let t := store8 temporary 6 t
  let r := clientRelay 3 stream temporary 1 0 t
  if r == error then r else
    store64 (state+144) 1 (store64 (state+160) stream (store64 (state+112) 0 r))
def relayEnd (i stream reason t : UInt64) : UInt64 :=
  -- A terminal connect can fail while a circuit control cell is draining.
  -- Retain the exact END without advancing digest/cipher state until its
  -- immutable output slot is available. Per-circuit56/64 hold reason/stream.
  if !ready i t || !idleOutput i t then
    store64 (circuit i+56) reason (store64 (circuit i+64) stream t)
  else
  let r := freshPadding t
  if r == error then abort 6 r else
  let t := store8 temporary reason r
  let t := Guest.TorCells.prepare body 3 stream temporary 1 padding t
  let t := Guest.TorCells.originate (hop i) hopScratch 1 body t
  if t == error then abort 54 t else
  let t := Guest.TorCells.frame cell (load64 (circuit i+8) t) 3 body t
  let r := queueCell i cell t
  if r == error then r else
    Guest.TorCells.retireStream (hop i) stream (store64 (circuit i+56) 0 (store64 (circuit i+64) 0 r))
def retireTerminal (i stream t : UInt64) : UInt64 :=
  let c := circuit i
  let next := load64 (c+16) t
  if stream == 0 || load64 (c+48) t != stream || next >= 12 ||
    (load64 (circuit next) t != 5 && load64 (circuit next) t != 6) then abort 60 t else
  let t := retireChannel next t
  let t := store64 (c+16) error (store64 (c+48) 0 t)
  relayEnd i stream 6 t
-- Draw channel-local circuit identifiers independently of all DH scalars.
-- The connection initiator uses the high-bit half mandated by link-v4 rules.
def newCircuitId (record t : UInt64) : UInt64 :=
  let r := syscall 104 0 fresh 32 0 t
  if r != 32 then Guest.Effects.effectValue error (abort 6 r) else
    let id := (load64 fresh r &&& 0x7fffffff) ||| 0x80000000
    zero fresh 4 (store64 (record+8) id r)
-- Client builds one hop at a time. No later onion key is exposed to earlier hops.
def advanceClient (t : UInt64) : UInt64 :=
  let built := load64 (state+24) t
  if load64 (state+8) t != 1 || built >= 3 || load64 (state+40) t != 0 || !ready 0 t || !idleOutput 0 t then t else
    let p := Guest.NodeEnrollment.peer built
    if !peerValid p t then abort 10 t else
      let r := syscall 104 0 fresh 32 0 t
      if r != 32 then abort 6 r else
        let t := ntorArgs p r
        let r := Guest.TorNtor.clientStart 0x6c0000 (ntorState built) args temporary t
        let t := zero fresh 4 r
        if r == error then abort 11 t else
          if built == 0 then
            let t := Guest.TorCells.putBE body 3 2 0 (zero body 64 t)
            let t := Guest.TorCells.putBE (body+2) 129 2 0 t
            let t := copy temporary (body+4) 129 t
            let t := newCircuitId (circuit 0) t
            if t == error then t else
            let t := Guest.TorCells.frame cell (load64 (circuit 0+8) t) 10 body t
            store64 (state+40) 1 (queueCell 0 cell t)
          else
            -- EXTEND2 with one Ed25519 link specifier; approved directory gives
            -- its numeric endpoint. No unapproved directory lookup is allowed.
            let t := copy temporary (temporary+256) 129 t
            let t := store8 temporary 1 t
            let t := store8 (temporary+1) 3 t
            let t := store8 (temporary+2) 32 t
            let t := copy (p+144) (temporary+3) 32 t
            let t := Guest.TorCells.putBE (temporary+35) 3 2 0 t
            let t := Guest.TorCells.putBE (temporary+37) 129 2 0 t
            let t := copy (temporary+256) (temporary+39) 129 t
            let t := Guest.TorCells.relayEarly (hop 0) t
            store64 (state+40) 1 (clientRelay 14 0 temporary 168 1 t)
def clientCreated (input n t : UInt64) : UInt64 :=
  let built := load64 (state+24) t
  if built >= 3 || load64 (state+40) t != 1 || n != 67 || Guest.TorCells.be16 input t != 65 then abort 12 t else
    let p := Guest.NodeEnrollment.peer built
    let t := ntorArgs p t
    let r := Guest.TorNtor.clientFinish 0x6c0000 (ntorState built) args (input+2) 65 (temporary+512) t
    if r == error then abort 13 r else
      let t := Guest.TorCells.init (hop built) hopScratch (temporary+512) r
      let t := store64 (state+24) (built+1) t
      store64 (state+40) 0 t
-- Each relay installs exactly its own ntor hop state; it never sees client keys
-- for another hop or receives a complete source route in CREATE2/EXTEND2.
def relayCreate (i input t : UInt64) : UInt64 :=
  let c := circuit i
  if load64 (localDescription t+208) t != 7 || load64 c t != 0 || Guest.TorCells.be16 (input+5) t != 3 || Guest.TorCells.be16 (input+7) t != 129 then abort 14 t else
    let r := syscall 104 0 fresh 32 0 t
    if r != 32 then abort 6 r else
      let t := ntorArgs (localDescription r) r
      let r := Guest.TorNtor.serverRespond 0x6c0000 args (input+9) 129 temporary (temporary+512) t
      let t := zero fresh 4 r
      if r == error then abort 15 t else
        let t := Guest.TorCells.init (hop i) hopScratch (temporary+512) t
        let t := store64 c 1 t
        let id := (load8 input t <<< 24) ||| (load8 (input+1) t <<< 16) ||| (load8 (input+2) t <<< 8) ||| load8 (input+3) t
        let t := store64 (c+8) id t
        let t := store64 (c+16) error t
        let t := Guest.TorCells.putBE body 65 2 0 t
        let t := copy temporary (body+2) 65 t
        let t := Guest.TorCells.frame cell id 11 body t
        queueCell i cell t
-- EXTEND2 may select only an operator-approved enrolled relay, independently
-- checked at each adjacency. Failed/unsupported extension destroys the circuit.
def relayExtend (i input n t : UInt64) : UInt64 :=
  let c := circuit i
  if n != 168 || load8 input t != 1 || load8 (input+1) t != 3 || load8 (input+2) t != 32 || Guest.TorCells.be16 (input+35) t != 3 || Guest.TorCells.be16 (input+37) t != 129 || load64 (c+16) t != error then abort 16 t else
    let target := findPeer (input+3) 0 t
    let next := freeChannel 0 t
    if target == error || next == error || load64 (Guest.NodeEnrollment.peer target+208) t != 7 ||
      Guest.NodeEnrollment.eq (input+3) (localDescription t+144) 32 t ||
      !Guest.NodeEnrollment.eq (input+3) (input+39) 32 t then abort 17 t else
      let t := store64 (c+16) next t
      let t := store64 (circuit next) 2 t
      let t := newCircuitId (circuit next) t
      if t == error then t else
      let t := store64 (c+24) (load64 (circuit next+8) t) t
      let t := store64 (circuit next+40) i t
      let r := openChannel next 1 target t
      if r == error then abort 40 r else copy (input+39) (channel next+8192) 129 r
def relayBegin (i stream input n t : UInt64) : UInt64 :=
  let c := circuit i
  if n != 32 || stream == 0 || load64 (c+16) t != error then abort 45 t else
    let target := findPeer input 0 t
    let next := freeChannel 0 t
    if target == error || (load64 (Guest.NodeEnrollment.peer target+208) t != 8 && load64 (Guest.NodeEnrollment.peer target+208) t != 16) then abort 46 t else
    if next == error then relayEnd i stream 4 t else
      let t := store64 (c+16) next t
      let t := store64 (c+48) stream t
      let t := store64 (circuit next) 5 t
      let t := store64 (circuit next+40) i t
      let t := store64 (circuit next+48) stream t
      let r := openChannel next 1 target t
      if r == error then
        let t := retireChannel next r
        relayEnd i stream 4 (store64 (c+16) error (store64 (c+48) 0 t))
      else r
-- Only an authenticated adjacent mailbox may contribute terminal proxy bytes;
-- innerNK still authenticates its actual service answer for the client.
def terminalFrame (i input n t : UInt64) : UInt64 :=
  let c := circuit i
  let size := Guest.TorCells.be16 (input+3) t
  let stream := Guest.TorCells.be16 (input+1) t
  if n < 6 || load8 input t != 77 || size != n-5 || size > 498 || stream == 0 then abort 48 t else
    if load64 c t == 6 then
      let origin := load64 (c+40) t
      if stream != load64 (c+48) t || origin >= 12 then abort 49 t else
        let t := copy (input+5) (temporary+256) size t
        let r := freshPadding t
        if r == error then abort 6 r else
          let t := Guest.TorCells.prepare body 2 stream (temporary+256) size padding r
          let t := Guest.TorCells.originate (hop origin) hopScratch 1 body t
          let t := Guest.TorCells.frame cell (load64 (circuit origin+8) t) 3 body t
          queueCell origin cell t
    else if (load64 (localDescription t+208) t == 8 || load64 (localDescription t+208) t == 16) && (load64 c t == 0 || load64 c t == 7) && load64 (state+80) t == 0 then
      let t := store64 c 7 t
      let t := store64 (c+48) stream t
      let t := store64 (state+96) i t
      let t := store64 (state+88) stream t
      let t := copy (input+5) inbox size t
      store64 (state+80) size t
    else abort 50 t
def relayExtended (i input t : UInt64) : UInt64 :=
  let origin := load64 (circuit i+40) t
  if origin >= 12 || load64 (circuit i) t != 3 || Guest.TorCells.be16 (input+5) t != 65 then abort 18 t else
    let r := freshPadding t
    if r == error then abort 6 r else
      let t := copy (input+5) (temporary+256) 67 r
      let t := Guest.TorCells.prepare body 15 0 (temporary+256) 67 padding t
      let t := Guest.TorCells.originate (hop origin) hopScratch 1 body t
      let t := Guest.TorCells.frame cell (load64 (circuit origin+8) t) 3 body t
      let t := store64 (circuit i) 4 t
      queueCell origin cell t
-- One terminal ciphertext chunk is retained until the authorized consumer takes
-- it. This is backpressure, not a delivery receipt or mailbox acceptance.
def acceptTerminal (body t : UInt64) : UInt64 :=
  let n := Guest.TorCells.be16 (body+9) t
  if load64 (state+80) t != 0 || n == 0 then error else
    let t := copy (body+11) inbox n t
    let t := store64 (state+88) (Guest.TorCells.be16 (body+3) t) t
    store64 (state+80) n t
partial def clientPeel (i built t : UInt64) : UInt64 :=
  if i == built then abort 19 t else
    let t := Guest.TorCells.peel (hop i) hopScratch 1 body t
    let status := load64 (hopScratch+1000) t
    if status == 1 then clientPeel (i+1) built t else
      if status != 0 then abort 20 t else
        let command := load8 body t
        if command == 15 && i+1 == built then clientCreated (body+11) (Guest.TorCells.be16 (body+9) t) t else
        if command == 4 && i+1 == built && Guest.TorCells.be16 (body+3) t == load64 (state+152) t then
          if load64 (state+144) t == 0 then store64 (state+112) 1 t else
          -- A locally cancelled BEGIN can race its authenticated CONNECTED.
          -- The ordered END acknowledgement, rather than CONNECTED, releases
          -- the selected stream and permits the next relationship.
          if load64 (state+144) t == 1 && Guest.TorCells.be16 (body+3) t == load64 (state+160) t then t
          else abort 61 t
        else
        if command == 3 && i+1 == built && Guest.TorCells.be16 (body+9) t == 1 then
          let stream := Guest.TorCells.be16 (body+3) t
          let reason := load8 (body+11) t
          let ack := load64 (state+144) t == 1 && stream == load64 (state+160) t && reason == 6
          let busy := stream == load64 (state+152) t && load64 (state+112) t == 0 && reason == 4
          if !ack && !busy then abort 61 t else
          let r := Guest.TorCells.retireStream (hop i) stream t
          if r == error then abort 61 r else
            store64 (state+168) reason (store64 (state+144) (if ack then 2 else 3) (store64 (state+112) 0 r))
        else if command == 2 && i+1 == built && Guest.TorCells.be16 (body+3) t == load64 (state+152) t then
          if load64 (state+112) t == 1 then acceptTerminal body t else
          -- Peeling already authenticated and charged this exact stream's
          -- DATA. Drain a response racing cancellation without exposing it to
          -- a newly selected client or resetting circuit credit/counters.
          if load64 (state+144) t == 1 && Guest.TorCells.be16 (body+3) t == load64 (state+160) t then t
          else abort 61 t
        else
        if command == 5 && i+1 == built then
          let stream := Guest.TorCells.be16 (body+3) t
          let r := if stream == 0 then Guest.TorCells.acceptSendme (hop i) 0 (body+11) (Guest.TorCells.be16 (body+9) t) t
            else Guest.TorCells.acceptStreamSendme (hop i) 0 stream (Guest.TorCells.be16 (body+9) t) t
          if r == error then abort 41 r else r
        else abort 21 t
-- Forwarding encrypts/decrypts exactly one layer at each independently owned
-- relay. CircIDs are rewritten only for that authenticated adjacent channel.
def relayCell (i command input t : UInt64) : UInt64 :=
  let c := circuit i
  if load64 c t == 4 then
    let origin := load64 (c+40) t
    let t := copy (input+5) body 509 t
    let t := Guest.TorCells.cryptLayer (hop origin) 1 body t
    if t == error then abort 54 t else
    let t := Guest.TorCells.frame cell (load64 (circuit origin+8) t) 3 body t
    queueCell origin cell t
  else if load64 c t != 1 then abort 22 t else
    let t := if command == 9 then Guest.TorCells.relayEarly (hop i) t else t
    if t == error then abort 23 t else
      let t := copy (input+5) body 509 t
      let t := Guest.TorCells.peel (hop i) hopScratch 0 body t
      let status := load64 (hopScratch+1000) t
      if status == 1 then
        let next := load64 (c+16) t
        if next >= 12 || load64 (circuit next) t != 4 then abort 24 t else
          queueCell next cell (Guest.TorCells.frame cell (load64 (c+24) t) command body t)
      else if status != 0 then abort 25 t else
        let relayCommand := load8 body t
        if relayCommand == 14 && command == 9 then relayExtend i (body+11) (Guest.TorCells.be16 (body+9) t) t else
        if relayCommand == 3 && Guest.TorCells.be16 (body+9) t == 1 && load8 (body+11) t == 6 then
          retireTerminal i (Guest.TorCells.be16 (body+3) t) t else
        if relayCommand == 1 && load64 (c+16) t == error then
          relayBegin i (Guest.TorCells.be16 (body+3) t) (body+11) (Guest.TorCells.be16 (body+9) t) t
        else if relayCommand == 2 && load64 (c+16) t < 12 && load64 (circuit (load64 (c+16) t)) t == 6 then
          queueTerminal (load64 (c+16) t) (Guest.TorCells.be16 (body+3) t) (body+11) (Guest.TorCells.be16 (body+9) t) t
        else if relayCommand == 5 then
          let stream := Guest.TorCells.be16 (body+3) t
          let r := if stream == 0 then Guest.TorCells.acceptSendme (hop i) 1 (body+11) (Guest.TorCells.be16 (body+9) t) t
            else Guest.TorCells.acceptStreamSendme (hop i) 1 stream (Guest.TorCells.be16 (body+9) t) t
          if r == error then abort 42 r else r
        else if relayCommand == 2 && load64 (c+16) t == error then
          let t := store64 (state+96) i t
          acceptTerminal body t
        else abort 26 t
-- Conservative per-circuit credit: do not decrypt while its output or terminal
-- slot is blocked, because replaying decryption would spend CTR state twice.
def canProcess (i t : UInt64) : Bool :=
  let c := circuit i
  if load64 (state+8) t == 1 then load64 (state+80) t == 0 && idleOutput 0 t else
    if load64 c t == 4 || load64 c t == 6 then idleOutput (load64 (c+40) t) t else
      if load64 c t == 1 then
        let next := load64 (c+16) t
        load64 (c+56) t == 0 && idleOutput i t && (if next < 12 then idleOutput next t else load64 (state+80) t == 0)
      else if load64 c t == 7 || (load64 (localDescription t+208) t == 8 || load64 (localDescription t+208) t == 16) then idleOutput i t && load64 (state+80) t == 0 else idleOutput i t
-- All fixed cells are carried on authenticated Noise records. Unknown command,
-- ID substitution, terminal integrity failure and unavailable extension fail shut.
def processCell (i input t : UInt64) : UInt64 :=
  let command := load8 (input+4) t
  let id := (load8 input t <<< 24) ||| (load8 (input+1) t <<< 16) ||| (load8 (input+2) t <<< 8) ||| load8 (input+3) t
  if id == 0 || (command == 10 && (id &&& 0x80000000) == 0) then abort 27 t else
    if command == 10 && load64 (state+8) t == 2 then relayCreate i input t else
    if id != load64 (circuit i+8) t then abort 28 t else
    if command == 4 then abort 29 t else
    if command == 11 then
      if load64 (state+8) t == 1 then clientCreated (input+5) 67 t else relayExtended i input t
    else if command == 3 || command == 9 then
      if load64 (state+8) t == 1 then
        clientPeel 0 (load64 (state+24) t) (copy (input+5) body 509 t)
      else relayCell i command input t
    else abort 30 t
-- Handle one complete ordered frame. No loop can drain unlimited cell work.
def processFrame (i n t : UInt64) : UInt64 :=
  let p := channel i
  let phase := load64 p t
  let t := loadNoise i t
  if phase == 2 && n == 48 then
    let r := Guest.NoiseNK.readFirst (p+2050) t
    if r == error then abort 31 r else
      let r := accountRecord i 50 r
      if r == error then r else
      let r := Guest.NoiseNK.writeSecond (p+4098) r
      if r == error then abort 32 r else
        let r := queueHandshake i r
        if r == error then r else saveNoise i (store64 p 4 r)
  else if phase == 3 && n == 48 then
    let r := Guest.NoiseNK.readSecond (p+2050) t
    if r == error then abort 33 r else
      let r := accountRecord i 50 r
      if r == error then r else saveNoise i (store64 p 4 r)
  else if phase == 4 && n >= 22 && n <= 530 then
    let r := Guest.Noise.openRecord (p+2050) n (p+6144) t
    if r == error then abort 34 r else
      let r := accountRecord i (n+2) r
      if r == error then r else
      let t := saveNoise i r
      if n == 530 then processCell i (p+6144) t
      else terminalFrame i (p+6144) (n-16) t
  else abort 35 t
-- Returns after at most one adapter read; partial header/body remains banked.
def readChannel (i t : UInt64) : UInt64 :=
  let p := channel i
  let pos := load64 (p+40) t
  let n : UInt64 := if pos < 2 then 2 else (2 : UInt64)+load8 (p+2048) t+(load8 (p+2049) t <<< 8)
  if n > 786 || pos > n then abort 36 t else
    if pos == n && pos >= 2 then
      if !canProcess i t then t else
        let t := processFrame i (n-2) t
        store64 (p+40) 0 t
    else
      let t := Guest.Transport.choose i t
      let r := Guest.Transport.read (p+2048+pos) (n-pos) t
      if r == error then abort 37 r else
      let t := if r == 0 then r else store64 (p+152) (load64 (p+160) r+30000) r
      store64 (p+40) (pos+r) t
-- Once the extending relay's adjacent channel authenticates, CREATE2 passes
-- only that next node's ntor transcript and a fresh channel-local CircID.
def advanceRelay (i t : UInt64) : UInt64 :=
  if !ready i t || !idleOutput i t then t else
  if load64 (circuit i) t == 5 then
    let origin := load64 (circuit i+40) t
    let stream := load64 (circuit i+48) t
    let r := freshPadding t
    if r == error then abort 6 r else
      let t := Guest.TorCells.prepare body 4 stream temporary 0 padding r
      let t := Guest.TorCells.originate (hop origin) hopScratch 1 body t
      let t := Guest.TorCells.frame cell (load64 (circuit origin+8) t) 3 body t
      store64 (circuit i) 6 (queueCell origin cell t)
  else if load64 (circuit i) t != 2 then t else
    let t := Guest.TorCells.putBE body 3 2 0 (zero body 64 t)
    let t := Guest.TorCells.putBE (body+2) 129 2 0 t
    let t := copy (channel i+8192) (body+4) 129 t
    let t := Guest.TorCells.frame cell (load64 (circuit i+8) t) 10 body t
    store64 (circuit i) 3 (queueCell i cell t)
def listenerLost (i t : UInt64) : Bool :=
  let p := channel i
  load64 p t == 1 && load64 (p+8) t == 2 && load64 (p+144) t == 0 &&
    load64 (Guest.Transport.channel i+8) t == 0 && load64 (Guest.Transport.channel i+24) t == 0
def listenerFailure (i clock t : UInt64) : UInt64 :=
  let attempts := load64 (state+128) t
  let attempts := if attempts < 32 then attempts+1 else 32
  let delay := if attempts == 1 then 200 else if attempts == 2 then 400 else
    if attempts == 3 then 800 else if attempts == 4 then 1600 else 3000
  let t := retireChannel i t
  store64 (state+48) 58 (store64 (state+128) attempts (store64 (state+136) (clock+delay) t))
def pumpChannel (i t : UInt64) : UInt64 :=
  let t := store64 (state+72) i t
  let p := channel i
  if load64 p t == 0 then t else
    let clock := syscall 110 0 0 0 0 t
    let t := store64 (p+160) clock clock
    let moving := load64 (p+40) t != 0 || load64 (p+48) t != 0
    let t := if !moving then store64 (p+152) 0 t else
      if load64 (p+152) t == 0 then store64 (p+152) (clock+30000) t else t
    if moving && clock >= load64 (p+152) t then abort 57 t else
    let phase := load64 p t
    -- ACCEPTED8 clears creation intent. An accepted listener may reach
    -- startHandshake, which starts its new finite window, after a long idle.
    if phase < 4 && !(phase == 1 && load64 (p+8) t == 2 &&
        (load64 (Guest.Transport.channel i+24) t == 2 ||
         load64 (Guest.Transport.channel i+8) t == 1)) && clock >= load64 (p+88) t then abort 51 t else
    let t := connectPending i t
    if !enabled t || load64 (p+144) t == 1 then t else
    if load64 p t == 4 && load64 (p+8) t == 1 &&
      (!peerValid (Guest.NodeEnrollment.peer (load64 (p+16) t)) t ||
       !Guest.NodeEnrollment.eq (p+850) (Guest.NodeEnrollment.peer (load64 (p+16) t)+512) 32 t) then abort 52 t else
    let t := Guest.Transport.choose i t
    let status := Guest.Transport.status t
    let epoch := status >>> 32
    if (status &&& 3) != 3 then
      let transport := Guest.Transport.channel i
      let failedConnect := load64 p status == 1 && load64 (p+8) status == 1 &&
        load64 (transport+24) status == 0 && load64 (transport+16) status != 0 &&
        (load64 (transport+1104) status == 5 || load64 (transport+1104) status == 6)
      if failedConnect then
        if load64 (state+8) status == 2 && load64 (circuit i) status == 5 then
          let origin := load64 (circuit i+40) status
          let stream := load64 (circuit i+48) status
          let t := retireChannel i status
          if origin >= 12 then abort 59 t else
          relayEnd origin stream 4 (store64 (circuit origin+16) error (store64 (circuit origin+48) 0 t))
        else abort 59 status
      else if listenerLost i status then
        if load64 (Guest.Transport.channel i+1104) status == 6 then listenerFailure i clock status
        else abort 38 status
      else if load64 p status == 1 then status else abort 38 status
    else if load64 (p+24) status != epoch then
      if load64 p status != 1 then abort 39 status else
        startHandshake i (store64 (p+24) epoch status)
    else
      let t := flushChannel i status
      let t := if load64 (circuit i) t == 1 && load64 (circuit i+56) t != 0 then
        relayEnd i (load64 (circuit i+64) t) (load64 (circuit i+56) t) t else t
      let t := readChannel i t
      if load64 (state+8) t == 2 then advanceRelay i t else t
-- Circuit-level authenticated SENDME is control work and may proceed even
-- while an unrelated terminal chunk is awaiting its consumer. Stream windows
-- are independently enforced for the selected endpoint stream (500/50).
def flowControlAt (selected t : UInt64) : UInt64 :=
  let client := load64 (state+8) t == 1
  let built := load64 (state+24) t
  let i := if client then (if built == 0 then 0 else built-1) else selected
  let d := if client then 1 else 0
  let ch := if client then 0 else i
  if i >= 12 || (client && built == 0) || !ready ch t || !idleOutput ch t then t else
    let circuitPending := load64 (Guest.TorCells.needAck (hop i) d) t
    let streamPending := load64 (Guest.TorCells.streamAck (hop i) d) t
    if circuitPending == 0 && streamPending == 0 then t else
    let stream := if circuitPending != 0 then 0 else load64 (Guest.TorCells.streamId (hop i)) t
    let n := if circuitPending != 0 then 23 else 0
    let t := if stream == 0 then Guest.TorCells.sendme (hop i) d temporary t else Guest.TorCells.sendmeStream (hop i) d t
    if t == error then abort 43 t else
      if client then clientRelay 5 stream temporary n 0 t else
        let r := freshPadding t
        if r == error then abort 6 r else
          let t := Guest.TorCells.prepare body 5 stream temporary n padding r
          let t := Guest.TorCells.originate (hop i) hopScratch 1 body t
          let t := Guest.TorCells.frame cell (load64 (circuit i+8) t) 3 body t
          queueCell i cell t
partial def flowControls (n t : UInt64) : UInt64 :=
  if load64 (state+8) t == 1 then flowControlAt 0 t else
  if n == 12 then t else
  let i := (load64 (state+64) t+n)%12
  let t := if load64 (circuit i) t == 1 then
    flowControlAt i (store64 (state+72) i t) else t
  flowControls (n+1) t
partial def pumpChannels (n t : UInt64) : UInt64 :=
  if n == 12 || !enabled t then t else
    let i := (load64 (state+64) t+n)%12
    pumpChannels (n+1) (pumpChannel i t)
partial def listenerPending (i t : UInt64) : Bool :=
  if i == 12 then false else
  (load64 (channel i) t == 1 && load64 (channel i+8) t == 2) || listenerPending (i+1) t
partial def availableChannels (i count t : UInt64) : UInt64 :=
  if i == 12 then count else availableChannels (i+1) (count+(if load64 (channel i) t == 0 then 1 else 0)) t
def replenish (t : UInt64) : UInt64 :=
  if load64 (state+8) t != 2 || load64 (state+120) t != 1 || listenerPending 0 t then t else
  if load64 (state+128) t >= 32 then t else
  let t := if load64 (state+128) t == 0 then t else syscall 110 0 0 0 0 t
  if load64 (state+128) t != 0 && t < load64 (state+136) t then t else
  let terminal := load64 (localDescription t+208) t != 7
  if availableChannels 0 0 t < (if terminal then 1 else 2) then t else
  let next := freeChannel 0 t
  if next == error then t else
  let t := store64 (state+72) next t
  let r := openChannel next 2 4 t
  if r == error then abort 56 r else r
def pump (t : UInt64) : UInt64 :=
  if !enabled t then t else
    let t := Guest.Transport.pump t
    let t := pumpChannels 0 t
    let t := store64 (state+64) ((load64 (state+64) t+1)%12) t
    replenish (advanceClient (flowControls 0 t))
-- Route policy uses3distinct approved relay identities and declared families.
-- Family declarations are an operator constraint, not a Sybil-independence proof.
def routeValid (t : UInt64) : Bool :=
  let a := Guest.NodeEnrollment.peer 0
  let b := Guest.NodeEnrollment.peer 1
  let c := Guest.NodeEnrollment.peer 2
  peerValid a t && peerValid b t && peerValid c t &&
  load64 (a+208) t == 7 && load64 (b+208) t == 7 && load64 (c+208) t == 7 &&
  !Guest.NodeEnrollment.eq (a+144) (b+144) 32 t && !Guest.NodeEnrollment.eq (a+144) (c+144) 32 t && !Guest.NodeEnrollment.eq (b+144) (c+144) 32 t &&
  !Guest.NodeEnrollment.eq (a+320) (b+320) 32 t && !Guest.NodeEnrollment.eq (a+320) (c+320) 32 t && !Guest.NodeEnrollment.eq (b+320) (c+320) 32 t &&
  Guest.NodeEnrollment.eq (a+80) (b+80) 32 t && Guest.NodeEnrollment.eq (a+80) (c+80) 32 t
-- Root Network authorizes these management/typed consumer operations exactly.
-- No arbitrary native app receives these raw private circuit operations.
def dispatch (op slot length t : UInt64) : UInt64 :=
  if op == 30 && slot < 12 && length == 64 then
    let t := if enabled t && load64 (state+8) t == 2 && load64 (channel slot) t == 0 then t else stop 0 t
    let t := store64 state 1 t
    let t := store64 (state+8) 2 t
    let t := store64 (state+120) 1 (store64 (state+128) 0 (store64 (state+136) 0 t))
    let r := openChannel slot 2 4 t
    response (if r == error then 2 else 0) slot r
  else if op == 31 && length == 64 then
    if !routeValid t then response 2 0 t else
      let t := stop 0 t
      let t := store64 state 1 t
      let t := store64 (state+8) 1 t
      let r := openChannel 0 1 0 t
      response (if r == error then 2 else 0) 0 r
  else if op == 32 && length == 64 then
    64+header 0 (if enabled t then 1 else 0) (load64 (state+24) t) (load64 (state+48) t)
      (load64 (channel 0) t) (load64 (channel 1) t) (load64 (state+40) t) t
  else if op == 33 && length > 64 && length <= 562 && load64 (state+24) t == 3 && load64 (state+8) t == 1 then
    let r := clientRelay 2 (load64 (command+16) t) (command+64) (length-64) 0 t
    response (if r == error then 4 else 0) (length-64) r
  else if op == 34 && length == 64 then
    let n := load64 (state+80) t
    if n == 0 then response 4 0 t else
      let t := header 0 n (load64 (state+88) t) 0 0 0 0 t
      let t := copy inbox (wire+64) n t
      64+n+store64 (state+80) 0 (zero inbox 64 t)
  else if op == 35 && length == 64 then response 0 0 (stop 0 t)
  else if op == 37 && length == 96 && load64 (state+24) t == 3 && load64 (state+8) t == 1 then
    let stream := load64 (command+16) t
    if stream == 0 || stream > 65535 || load64 (state+144) t == 1 || load64 (state+112) t != 0 ||
      (load64 (state+152) t != 0 && load64 (state+144) t == 0) then response 4 0 t else
    let r := clientRelay 1 stream (command+64) 32 0 t
    if r == error then response 4 0 r else
      response 0 0 (store64 (state+144) 0 (store64 (state+168) 0 (store64 (state+152) stream r)))
  else if op == 36 && length > 64 && length <= 562 && load64 (state+8) t == 2 then
    let i := load64 (state+96) t
    if i >= 12 || !idleOutput i t then response 4 0 t else
    if load64 (circuit i) t == 7 then
      let r := queueTerminal i (load64 (command+16) t) (command+64) (length-64) t
      response (if r == error then 4 else 0) (length-64) r
    else
      let r := freshPadding t
      if r == error then response 6 0 r else
        let t := Guest.TorCells.prepare body 2 (load64 (command+16) t) (command+64) (length-64) padding r
        let t := Guest.TorCells.originate (hop i) hopScratch 1 body t
        let t := Guest.TorCells.frame cell (load64 (circuit i+8) t) 3 body t
        let r := queueCell i cell t
        response (if r == error then 4 else 0) (length-64) r
  else response 2 0 t
end Guest.TorRouter
