import Guest.NetworkSDK
import Guest.Noise
import Guest.PeerDescription
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
      if load64 j g == 2 then disconnect 15 (syscall 105 0 0 0 0 g) else store64 j 5 g
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
partial def incomingGrant (root operation bytes i t : UInt64) : UInt64 :=
  if i == 4 then error else
    let g := grantAt i
    if (load64 (g+24) t &&& 2) != 0 && load64 (g+80) t == operation && equal root (g+160) 32 t && chargeable g bytes t then i
    else incomingGrant root operation bytes (i+1) t

def acceptRecord (n t : UInt64) : UInt64 :=
  let r := Guest.Noise.openRecord (rx+2) n plain t
  if r == error then disconnect 12 r else
    if n < 64 || load64 (plain+40) r != n-64 then disconnect 2 r else
      let length := n-64
      let selected := incomingGrant plain (load64 (plain+32) r) length 0 r
      let vacant := freeInbox 0 selected
      if selected == error || vacant == error then store64 (st+80) 1 vacant else
        let g := grantAt selected
        let p := inbox vacant
        let t := store64 p (load64 (g+8) vacant) vacant
        let sequence := load64 (st+120) t+1
        let t := store64 (st+120) sequence t
        let t := store64 (p+1008) sequence t
        let t := store64 (p+8) length t
        let t := copy (plain+48) (p+16) length t
        charge g length t

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

def readFrame (t : UInt64) : UInt64 :=
  let pos := load64 (st+48) t
  let length := load64 (st+56) t
  let want := if pos < 2 then 2-pos else length+2-pos
  if want == 0 || want > 786 then disconnect 2 t else
    let r := syscall 102 0 (rx+pos) want 0 t
    if r == error then disconnect 10 r else
    if r == 0 then r else
      let pos := pos+r
      let t := store64 (st+48) pos r
      let length := if pos == 2 then load8 rx t ||| (load8 (rx+1) t <<< 8) else length
      if length > 784 || (pos >= 2 && length < 16) then disconnect 2 t else
        let t := store64 (st+56) length t
        if pos == length+2 then
          let t := acceptFrame length t
          let t := store64 (st+48) 0 t
          store64 (st+56) 0 t
        else t

def writeFrame (t : UInt64) : UInt64 :=
  let pos := load64 (st+32) t
  let length := load64 (st+40) t
  if pos >= length then t else
    let r := syscall 103 0 (tx+pos) (length-pos) 0 t
    if r == error then disconnect 10 r else
      let pos := pos+r
      let t := store64 (st+32) pos r
      if pos == length then
        let active := load64 (st+64) t
        let t := if active == 0 then t else store64 (jobAt (active-1)) 3 t
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
      let t := copy (j+64) (plain+48) n t
      let r := Guest.Noise.sealRecord plain (n+48) (tx+2) t
      if r == error then disconnect 12 r else
        let t := Guest.VaultCrypto.putLE tx (n+64) 2 r
        let t := store64 (st+40) (n+66) t
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
  let t := store64 st (now initial+1) initial
  let t := expireGrants 0 t
  let t := cancelRevoked 0 t
  let t := reclaimInbox 0 t
  let device := syscall 101 0 0 0 0 t
  if device == error || (device &&& 3) != 3 then disconnect 10 device else
    let epoch := device >>> 32
    let t := if epoch != load64 (st+24) device then store64 (st+24) epoch (disconnect 10 device) else device
    if load64 (st+8) t == 0 || now t < load64 (st+88) t then t else
      let t := if session t == 0 then fresh t else t
      if (session t != 3 && now t >= load64 (st+96) t) || (session t == 3 && now t >= load64 (st+104) t) then disconnect 13 t else
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

def grant (caller length t : UInt64) : UInt64 :=
  if length != 168 then failure 2 t else
  let direction := load64 (command+16) t
  let mode := load64 (command+24) t
  let budget := load64 (command+32) t
  let rate := load64 (command+40) t
  let lifetime := load64 (command+48) t
  let operation := load64 (command+160) t
  let peer := pins+(if load64 (st+8) t == 1 then 32 else 0)
  if !Guest.NetworkSDK.modeAvailable mode then failure 7 t else
  if !Guest.PeerDescription.permits operation t then failure 1 t else
  if length != 168 || direction == 0 || direction > 3 || budget == 0 || budget > 16777216 || rate == 0 || rate > 65536 || lifetime == 0 || lifetime > 100000 || operation == 0 || operation > 16 ||
    load64 (st+8) t == 0 || !equal (command+64) peer 32 t || !equal (command+96) (pins+64) 32 t then failure 2 t else
    let selected := freeGrant 0 t
    if selected == error || load64 (st+16) t >= 0xffffffff then failure 4 selected else
      let g := grantAt selected
      let id := load64 (st+16) selected+1
      let t := store64 (st+16) id selected
      let t := zero g 32 t
      let t := store64 g 1 t
      let t := store64 (g+8) id t
      let t := store64 (g+16) caller t
      let t := store64 (g+24) direction t
      let t := store64 (g+32) budget t
      let t := store64 (g+48) rate t
      let t := store64 (g+56) (now t+lifetime) t
      let t := store64 (g+80) operation t
      let t := copy (command+64) (g+96) 96 t
      let t := zero wire 8 t
      64+store64 (wire+8) id t

def sendMessage (caller handle operation n t : UInt64) : UInt64 :=
  let selected := findGrant handle caller 0 t
  if selected == error then failure 3 selected else
    let g := grantAt selected
    if (load64 (g+24) selected &&& 1) == 0 || load64 (g+80) selected != operation then failure 1 selected else
    if activeForGrant handle 0 selected || !chargeable g n selected then failure 4 selected else
      let vacant := freeJob 0 selected
      if vacant == error || load64 (st+112) vacant >= 0xffffffff then failure 4 vacant else
        let j := jobAt vacant
        let id := load64 (st+112) vacant+1
        let t := store64 (st+112) id vacant
        let t := zero j 128 t
        let t := store64 j 1 t
        let t := store64 (j+8) id t
        let t := store64 (j+16) caller t
        let t := store64 (j+24) handle t
        let t := store64 (j+32) n t
        let t := copy (command+64) (j+64) n t
        jobResponse j (charge g n t)

def cancelJob (j t : UInt64) : UInt64 :=
  if load64 j t >= 3 then failure 6 t else
  if load64 j t == 2 then
    let t := syscall 105 0 0 0 0 t
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
        let t := copy (p+16) (wire+64) n t
        64+n+zero p 128 t

def dispatch (caller rights length t : UInt64) : UInt64 :=
  let op := load64 command t
  let handle := load64 (command+8) t
  let admin := (rights &&& 0x100000000) != 0
  if length < 64 || load64 (command+56) t != 1 then failure 2 t else
  if op == 11 && admin then
    let t := store64 (st+8) 0 (disconnect 16 (syscall 105 0 0 0 0 t))
    Guest.PeerDescription.stage length t
  else
  if op == 12 && admin then Guest.PeerDescription.confirm length t else
  if op == 1 && admin then configure (load64 (command+16) t) length t else
  if op == 9 && admin then failure 0 (disconnect 0 (syscall 105 0 0 0 0 t)) else
  if (rights &&& 1024) == 0 && !admin then failure 1 t else
  if op == 10 && length == 64 then
    let r := syscall 104 0 (wire+64) 32 0 t
    if r != 32 then failure 11 r else 96+zero wire 8 r
  else if op == 2 then grant caller length t else
  if op == 3 && length <= 784 then sendMessage caller handle (load64 (command+16) t) (length-64) t else
  if op == 6 && length == 64 then receiveMessage caller handle t else
  if op == 7 && length == 64 then
    let t := zero wire 8 t
    let t := store64 (wire+8) (session t) t
    let t := store64 (wire+16) (load64 (st+8) t) t
    let t := store64 (wire+24) (syscall 101 0 0 0 0 t) t
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

partial def serve (endpoint t : UInt64) : UInt64 :=
  let t := pump t
  let n := syscall 36 endpoint incoming 1024 0 t
  if n == 0 || n == error then serve endpoint (syscall 109 0 0 0 0 n) else
    let caller := load64 incoming n
    let token := load64 (incoming+8) n
    let rights := load64 (incoming+16) n
    let r := if n >= 96 && load64 (incoming+24) n == 2 then dispatch caller rights (n-32) n else failure 2 n
    let t := reply token r r
    -- Provisioning request input is sensitive: never retain it between turns.
    let t := zero incoming 128 t
    serve endpoint (syscall 109 0 0 0 0 t)

def main (initial : UInt64) : UInt64 :=
  let t := zero 0x600000 16384 initial
  let t := zero Guest.PeerDescription.publicKey 200 t
  serve (self t) t
end Guest.Network
