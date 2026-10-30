import Guest.LibraryPeerSDK
import Guest.ContentFormat
import Guest.WaitSDK
namespace Guest.Retrievability
open Guest.LiveSDK
-- A bounded fresh challenge over the ordinary authenticated Library protocol.
-- This is qualified evidence of sampled responses, not preservation/attestation.
-- Uses33KiB of the existing profile2 private arena, apart from constructor heap.
def st : UInt64 := 0x600000
def manifest : UInt64 := 0x601000
def proof : UInt64 := 0x601200
def payload : UInt64 := 0x602000
def seed : UInt64 := 0x603000
def hashOut : UInt64 := 0x603100
def node : UInt64 := 0x603200
def hashInput : UInt64 := 0x603400
def scratch : UInt64 := 0x604000
def evidence : UInt64 := 0x606000
def history : UInt64 := 0x607000
def description : UInt64 := 0x608000
def pins : UInt64 := 0x608200
def eq (a b n t : UInt64) : Bool := Guest.ContentFormat.equal a b n t
def sha (p n out t : UInt64) : UInt64 := Guest.ServiceHash.sha256At scratch p n out t
def sample (i : UInt64) : UInt64 := evidence+320+i*48
def active (t : UInt64) : Bool := load64 st t == 1
def response (code t : UInt64) : UInt64 :=
  64+header code (load64 (st+16) t) (load64 st t) (load64 (st+40) t)
    (load64 (st+32) t) (load64 (st+48) t) (load64 (st+136) t) t
partial def prior (operation i t : UInt64) : Bool :=
  if i == 16 then false else load64 (history+i*8) t == operation || prior operation (i+1) t
def finish (state reason initial : UInt64) : UInt64 :=
  let slot := load64 (st+24) initial
  let grant := load64 (st+64) initial
  let job := load64 (st+112) initial
  let t := if job == 0 then initial else Guest.NetworkSDK.cancelPeer slot job initial
  let t := if grant == 0 then t else Guest.NetworkSDK.revokePeer slot grant t
  let t := store64 st state (store64 (st+136) reason t)
  let t := store64 evidence 0x315254455254544c t
  let t := store64 (evidence+8) 1 t
  let t := store64 (evidence+16) (load64 (st+16) t) t
  let t := store64 (evidence+24) state t
  let t := store64 (evidence+32) (load64 (st+32) t) t
  let t := store64 (evidence+40) (load64 (st+40) t) t
  let t := store64 (evidence+48) (load64 (st+48) t) t
  let t := store64 (evidence+56) 3 t
  let t := store64 (evidence+256) (Guest.WaitSDK.now t) t
  let t := store64 (evidence+264) reason t
  let t := sha evidence 704 (evidence+704) t
  let waiter := load64 (st+160) t
  if waiter == 0 then t else
    let t := store64 (st+160) 0 t
    let r := response 0 t
    reply waiter 800 (copy evidence (wire+64) 736 r)
def sameRequest (t : UInt64) : Bool :=
  load64 (command+8) t == load64 (st+24) t &&
  load64 (command+24) t == load64 (st+32) t &&
  load64 (command+32) t == load64 (st+144) t && eq (command+64) manifest 256 t
def begin (caller n t : UInt64) : UInt64 :=
  let slot := load64 (command+8) t
  let operation := load64 (command+16) t
  let count := load64 (command+24) t
  let lifetime := load64 (command+32) t
  if n != 352 || slot == 0 || slot > 2 || operation == 0 || count < 3 || count > 8 ||
    lifetime == 0 || lifetime > 10000 || load64 (command+40) t != 3 || load64 (command+48) t != 0 ||
    !Guest.ContentFormat.valid (command+64) t || load64 (command+96) t < count then response 2 t else
  if operation == load64 (st+16) t then
    response (if caller == load64 (st+8) t && sameRequest t then 0 else 1) t
  else if active t then response 4 t else if prior operation 0 t then response 3 t else
  let serial := load64 (st+152) t
  let t := zero st 21 t
  let t := zero evidence 92 t
  let t := store64 (history+(serial%16)*8) operation t
  let t := store64 (st+152) (serial+1) t
  let t := copy (command+64) manifest 256 t
  let t := store64 st 1 t
  let t := store64 (st+8) caller t
  let t := store64 (st+16) operation t
  let t := store64 (st+24) slot t
  let t := store64 (st+32) count t
  let t := store64 (st+144) lifetime t
  let now := Guest.WaitSDK.now t
  let t := store64 (st+80) (now+lifetime) (store64 (st+88) now now)
  let t := store64 (evidence+232) (self t) t
  let t := store64 (evidence+240) now t
  let t := store64 (evidence+248) (now+lifetime) t
  let t := store64 (evidence+272) 1 t
  let t := store64 (evidence+280) (load64 (manifest+24) t) t
  let t := store64 (evidence+288) (load64 (manifest+32) t) t
  let t := store64 (evidence+296) (load64 (manifest+40) t) t
  let t := sha manifest 256 (evidence+96) t
  let t := copy (manifest+96) (evidence+128) 32 t
  response 0 (store64 (st+56) 1 t)
def setup (t : UInt64) : UInt64 :=
  let slot := load64 (st+24) t
  let r := Guest.NetworkSDK.inspectPeer slot t
  if r != 64 || status r != 0 || result r != 3 then finish 7 1 r else
  let t := store64 (st+72) (load64 (wire+24) r) r
  let t := store64 (evidence+224) (load64 (wire+24) r >>> 32) t
  let r := Guest.NetworkSDK.describePeer slot t
  if r != 576 || status r != 0 || load64 (wire+80) r != 6 then finish 7 2 r else
  let t := copy (wire+64) description 512 r
  let t := copy (description+96) pins 32 t
  let t := copy pins (evidence+160) 32 t
  let t := sha description 512 (pins+32) t
  let t := copy (pins+32) (evidence+192) 32 t
  let t := copy (evidence+96) (pins+64) 32 t
  let r := Guest.NetworkSDK.callPeer slot 64 (header 10 0 0 0 0 0 0 t)
  if r != 96 || status r != 0 || Guest.ContentFormat.allZero (wire+64) 32 r then finish 7 11 r else
  let t := copy (wire+64) (evidence+64) 32 r
  let t := copy (wire+64) seed 32 t
  if load64 seed t == 0 || load64 seed t > 0xffffffffffffffc0 then finish 7 11 t else
  let t := store64 (st+96) (load64 seed t ||| 1) t
  -- Includes each full chunk, its proof, seven response envelopes and requests.
  let budget := load64 (st+32) t*6144+4096
  let r := Guest.LibraryPeerSDK.grant slot pins (load64 (pins+64) t ||| 1) budget (load64 (st+144) t) t
  if r != 64 || status r != 0 then finish 7 3 r else
    store64 (st+56) 2 (store64 (st+64) (result r) (store64 (evidence+304) (result r >>> 34) r))
partial def used (index i count t : UInt64) : Bool :=
  if i == count then false else load64 (sample i) t == index || used index (i+1) count t
def choose (t : UInt64) : UInt64 :=
  let attempt := load64 (st+128) t
  if attempt >= 256 then finish 7 12 t else
  let t := store64 (seed+32) attempt t
  let t := store64 (seed+40) 0x31504d4153544c t
  let t := sha seed 48 hashOut t
  let index := load64 hashOut t % load64 (manifest+32) t
  let done := load64 (st+40) t
  let t := store64 (st+128) (attempt+1) t
  if used index 0 done t then t else
  let t := store64 (sample done) index t
  let t := store64 (sample done+8) (Guest.ContentFormat.chunkLength (load64 (manifest+24) t) index) t
  store64 (st+56) 3 (store64 (st+104) 0 t)
def sendRequest (operation h count next t : UInt64) : UInt64 :=
  let id := load64 (st+96) t+2
  let r := Guest.LibraryPeerSDK.request (load64 (st+24) t) (load64 (st+64) t) id operation h count 0 t
  if r != 64 || status r != 0 then
    if r == 64 && status r == 4 then r else finish 7 4 r
  else store64 (st+56) next (store64 (st+96) id (store64 (st+112) (result r) r))
def receiveProof (t : UInt64) : UInt64 :=
  let r := Guest.LibraryPeerSDK.receive (load64 (st+24) t) (load64 (st+64) t) t
  if r == 64 && status r == 6 then r else
  let n := 32+load64 (manifest+48) r*32
  let index := load64 (sample (load64 (st+40) r)) r
  if !Guest.LibraryPeerSDK.valid 4 (load64 (st+96) r) r || Guest.LibraryPeerSDK.remoteStatus r > 16 then finish 7 5 r else
  if Guest.LibraryPeerSDK.remoteStatus r != 0 then finish 7 (100+Guest.LibraryPeerSDK.remoteStatus r) r else
  if r != 128+n || Guest.LibraryPeerSDK.total r != n || Guest.LibraryPeerSDK.resultId r != index || Guest.LibraryPeerSDK.next r != 0 then
      finish 7 5 r else
  store64 (st+56) 5 (copy Guest.LibraryPeerSDK.data proof n r)
def receiveData (t : UInt64) : UInt64 :=
  let r := Guest.LibraryPeerSDK.receive (load64 (st+24) t) (load64 (st+64) t) t
  if r == 64 && status r == 6 then r else
  let selected := sample (load64 (st+40) r)
  let index := load64 selected r
  let length := load64 (selected+8) r
  let offset := load64 (st+104) r
  let n := if r >= 128 && r <= 768 then r-128 else 0
  if !Guest.LibraryPeerSDK.valid 10 (load64 (st+96) r) r || Guest.LibraryPeerSDK.remoteStatus r > 16 then finish 7 6 r else
  if Guest.LibraryPeerSDK.remoteStatus r != 0 then finish 7 (200+Guest.LibraryPeerSDK.remoteStatus r) r else
  if n == 0 || n > 640 || offset >= length || n > length-offset ||
    Guest.LibraryPeerSDK.total r != load64 (manifest+24) r ||
    Guest.LibraryPeerSDK.resultId r != index*4096+offset || Guest.LibraryPeerSDK.next r != length-offset-n then
    finish 7 6 r else
  let t := copy Guest.LibraryPeerSDK.data (payload+offset) n r
  store64 (st+56) (if offset+n == length then 7 else 6) (store64 (st+104) (offset+n) t)
def verify (t : UInt64) : UInt64 :=
  let selected := sample (load64 (st+40) t)
  let index := load64 selected t
  let length := load64 (selected+8) t
  let t := sha payload length hashOut t
  if !eq hashOut proof 32 t then finish 7 7 t else
  let t := copy hashOut (selected+16) 32 t
  let t := Guest.ContentFormat.leaf hashInput scratch node index length hashOut t
  store64 (st+56) 8 (store64 (st+120) 0 t)
def walk (t : UInt64) : UInt64 :=
  let level := load64 (st+120) t
  let done := load64 (st+40) t
  if level == load64 (manifest+48) t then
    if !eq node (manifest+96) 32 t then finish 7 8 t else
    let t := store64 (st+48) (load64 (st+48) t+load64 (sample done+8) t) t
    let t := store64 (st+40) (done+1) t
    if done+1 == load64 (st+32) t then finish 4 0 t else store64 (st+56) 2 t
  else
  let sibling := proof+32+level*32
  let index := load64 (sample done) t
  let t := if ((index >>> level) &&& 1) == 0 then
      Guest.ContentFormat.branch hashInput scratch node node sibling t
    else Guest.ContentFormat.branch hashInput scratch node sibling node t
  store64 (st+120) (level+1) t
def pump (t : UInt64) : UInt64 :=
  if !active t then t else
  if Guest.WaitSDK.now t >= load64 (st+80) t then finish 7 9 t else
  let phase := load64 (st+56) t
  let s := sample (load64 (st+40) t)
  if phase == 1 then setup t else
  if phase == 2 then choose t else
  if phase == 3 then sendRequest 4 (load64 s t) 0 4 t else
  if phase == 4 then receiveProof t else
  if phase == 5 then sendRequest 10 (load64 s t*4096) (load64 (s+8) t) 6 t else
  if phase == 6 then receiveData t else
  if phase == 7 then verify t else
  if phase == 8 then walk t else finish 7 10 t
def dispatch (n t : UInt64) : UInt64 :=
  let caller := load64 incoming t
  let token := load64 (incoming+8) t
  let admin := (caller &&& 255) == 1 && (load64 (incoming+16) t &&& 0x100000000) != 0
  let op := load64 command t
  if n < 96 || load64 (command+56) t != 1 || !admin then reply token (response 1 t) t else
  if op == 740 then
    let r := begin caller n t
    reply token r r
  else if (op == 741 || op == 743) && n == 96 && load64 (command+8) t == load64 (st+16) t then
    if op == 743 && active t then
      if load64 (st+160) t == 0 then store64 (st+160) token t else reply token (response 4 t) t
    else
    let r := response 0 t
    let n := if active r || load64 st r == 0 then 64 else 800
    reply token n (if n == 64 then r else copy evidence (wire+64) 736 r)
  else if op == 742 && n == 96 && load64 (command+8) t == load64 (st+16) t && active t then
    let r := finish 5 0 t
    reply token (response 0 r) r
  else reply token (response 3 t) t
partial def loop (t : UInt64) : UInt64 :=
  let n := syscall 36 (self t) incoming 1024 0 t
  let t := if n >= 96 && n <= 1024 then dispatch n n else n
  let phase := load64 (st+56) t
  let offset := load64 (st+104) t
  let done := load64 (st+40) t
  let level := load64 (st+120) t
  let attempt := load64 (st+128) t
  let t := pump t
  let ready := active t && (phase != load64 (st+56) t || offset != load64 (st+104) t ||
    done != load64 (st+40) t || level != load64 (st+120) t || attempt != load64 (st+128) t)
  loop (Guest.WaitSDK.deadline (if ready then Guest.WaitSDK.now t else if active t then load64 (st+80) t else Guest.WaitSDK.now t+100) t)
def main (initial : UInt64) : UInt64 := loop (zero st 4224 initial)
end Guest.Retrievability
