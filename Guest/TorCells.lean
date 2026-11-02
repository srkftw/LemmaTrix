import Guest.Effects
import Guest.AES
import Guest.SHA1
namespace Guest.TorCells
-- Ordinary Tor RELAY profile: 509-byte body, AES128-CTR per direction,
-- running SHA1 seeded by ntor-v3 Df/Db. Context2560; private scratch2048.
-- Direction0 forward,1 backward. Caller keeps adjacent channel-local CircIDs.
-- scratch+1000 stores structured status:0 recognized/success,1 not recognized,
-- 2 malformed,3 lifetime exhausted,4 backpressure,5 integrity/window failure.
-- Recognition failure preserves running SHA state and the original digest bytes.
-- A terminal unrecognized cell MUST destroy the circuit; transit may forward.
-- Lower-level cryptLayer never authenticates a body or grants stream authority.
def err : UInt64 := 0xffffffffffffffff
def hashContext (c d : UInt64) : UInt64 := c+1152+d*128
def aesContext (c d : UInt64) : UInt64 := c+d*576
def count (c d : UInt64) : UInt64 := c+1408+d*8
def packageWindow (c d : UInt64) : UInt64 := c+1432+d*8
def deliverWindow (c d : UInt64) : UInt64 := c+1448+d*8
def sent (c d : UInt64) : UInt64 := c+1464+d*8
def received (c d : UInt64) : UInt64 := c+1480+d*8
def queueHead (c d : UInt64) : UInt64 := c+1496+d*8
def queueCount (c d : UInt64) : UInt64 := c+1512+d*8
def needAck (c d : UInt64) : UInt64 := c+1528+d*8
def lastDigest (c d : UInt64) : UInt64 := c+1544+d*20
def ackQueue (c d : UInt64) : UInt64 := c+2048+d*200
def ackHead (c d : UInt64) : UInt64 := c+2448+d*8
def digestQueue (c d : UInt64) : UInt64 := c+1648+d*200
-- One admitted endpoint stream per hop, multiplexing bounded terminal RPCs.
-- Transit hops never see/bind this stream. No context/capacity increase.
def streamId (c : UInt64) : UInt64 := c+2480
def streamPackage (c d : UInt64) : UInt64 := c+2488+d*8
def streamDeliver (c d : UInt64) : UInt64 := c+2504+d*8
def streamAck (c d : UInt64) : UInt64 := c+2520+d*8
partial def zero (p n t : UInt64) : UInt64 :=
  if n == 0 then t else zero (p+1) (n-1) (store8 p 0 t)
partial def copy (a b n t : UInt64) : UInt64 :=
  if n == 0 then t else copy (a+1) (b+1) (n-1) (store8 b (load8 a t) t)
partial def difference (a b n v t : UInt64) : UInt64 :=
  if n == 0 then v else difference (a+1) (b+1) (n-1) (v ||| (load8 a t ^^^ load8 b t)) t
partial def putBE (p value n i t : UInt64) : UInt64 :=
  if i == n then t else putBE p value n (i+1) (store8 (p+i) ((value >>> ((n-1-i)*8)) &&& 255) t)
def be16 (p t : UInt64) : UInt64 := (load8 p t <<< 8) ||| load8 (p+1) t
def control (command : UInt64) : Bool := command == 6 || command == 7 || command == 8 || command == 9 || command == 10 || command == 14 || command == 15
def validHeader (body t : UInt64) : Bool :=
  let cmd := load8 body t
  let stream := be16 (body+3) t
  let n := be16 (body+9) t
  cmd >= 1 && cmd <= 15 && n <= 498 &&
  (if control cmd then stream == 0 else if cmd == 5 then true else stream != 0)
def init (c s keys t : UInt64) : UInt64 :=
  let t := zero c 2560 t
  let t := Guest.AES.init c (keys+40) 16 t
  let t := Guest.AES.init (c+576) (keys+56) 16 t
  let t := Guest.SHA1.update (c+1152) s keys 20 (Guest.SHA1.init (c+1152) t)
  let t := Guest.SHA1.update (c+1280) s (keys+20) 20 (Guest.SHA1.init (c+1280) t)
  let t := store64 (packageWindow c 0) 1000 t
  let t := store64 (packageWindow c 1) 1000 t
  let t := store64 (deliverWindow c 0) 1000 t
  let t := store64 (deliverWindow c 1) 1000 t
  store64 (c+1424) 1 (zero s 2048 t)
/-- Caller supplies509 bytes of independently generated padding. No secrets alias it. -/
def prepare (body command stream data n padding t : UInt64) : UInt64 :=
  if n > 498 || command < 1 || command > 15 || stream > 65535 then err else
    let t := copy padding body 509 t
    let t := store8 body command t
    let t := putBE (body+1) 0 2 0 t
    let t := putBE (body+3) stream 2 0 t
    let t := zero (body+5) 4 t
    let t := putBE (body+9) n 2 0 t
    let t := copy data (body+11) n t
    let paddingLen := 498-n
    let t := zero (body+11+n) (if paddingLen < 4 then paddingLen else 4) t
    if validHeader body t then t else Guest.Effects.effectValue err t
def frame (cell circuit command body t : UInt64) : UInt64 :=
  if circuit == 0 || circuit > 0xffffffff || command > 255 then err else
    let t := putBE cell circuit 4 0 t
    copy body (cell+5) 509 (store8 (cell+4) command t)
def cryptLayer (c d body t : UInt64) : UInt64 :=
  if d > 1 || load64 (c+1424) t != 1 || load64 (count c d) t >= 1048576 then err else
    let t := Guest.AES.crypt (aesContext c d) body body 509 t
    store64 (count c d) (load64 (count c d) t+1) t
-- Finalize a clone: the persistent digest remains live, with no padding appended.
def digest (c s d out t : UInt64) : UInt64 :=
  let t := copy (hashContext c d) (s+832) 128 t
  Guest.SHA1.finish (s+832) s out t
-- DATA flow-control accounting retains at most10 outstanding SENDME digests.
def recordSent (c s d body t : UInt64) : UInt64 :=
  if load8 body t != 2 then t else
    let n := load64 (sent c d) t+1
    let t := store64 (sent c d) n t
    let t := store64 (packageWindow c d) (load64 (packageWindow c d) t-1) t
    let t := store64 (streamPackage c d) (load64 (streamPackage c d) t-1) t
    if n%100 != 0 then t else
      let qn := load64 (queueCount c d) t
      let index := (load64 (queueHead c d) t+qn)%10
      let t := digest c s d (digestQueue c d+index*20) t
      store64 (queueCount c d) (qn+1) t
-- Only an authenticated/locally authorized endpoint message may bind a stream.
-- A second live stream cannot evict authority. An ordered authenticated
-- END/ack exchange may retire precisely the selected stream while preserving
-- circuit credit, digests, counters and keys.
def retireStream (c expected t : UInt64) : UInt64 :=
  if expected == 0 || load64 (streamId c) t != expected then err else zero (streamId c) 56 t
def selectStream (c body t : UInt64) : UInt64 :=
  let id := be16 (body+3) t
  let selected := load64 (streamId c) t
  if id == 0 then t else
  if selected == id then t else
  if selected != 0 || load8 body t == 5 then err else
    let t := store64 (streamId c) id t
    let t := store64 (streamPackage c 0) 500 t
    let t := store64 (streamPackage c 1) 500 t
    let t := store64 (streamDeliver c 0) 500 t
    store64 (streamDeliver c 1) 500 t
/-- Originate at this hop: digest covers all509 bytes including unpredictable padding. -/
def originate (c s d body t : UInt64) : UInt64 :=
  if d > 1 || load64 (c+1424) t != 1 || !validHeader body t then err else
    let t := selectStream c body t
    if t == err then t else
    if load8 body t == 2 && (load64 (packageWindow c d) t == 0 || load64 (streamPackage c d) t == 0 || load64 (queueCount c d) t >= 10) then err else
      if load64 (count c d) t >= 1048576 then err else
        let t := zero (body+1) 2 (zero (body+5) 4 t)
        let t := Guest.SHA1.update (hashContext c d) s body 509 t
        let t := digest c s d (s+960) t
        let t := copy (s+960) (body+5) 4 t
        let t := recordSent c s d body t
        cryptLayer c d body (zero s 2048 t)
def recordReceived (c d body t : UInt64) : UInt64 :=
  if load8 body t != 2 then t else
    let n := load64 (received c d) t+1
    let t := store64 (received c d) n t
    let t := store64 (deliverWindow c d) (load64 (deliverWindow c d) t-1) t
    let remaining := load64 (streamDeliver c d) t-1
    let t := store64 (streamDeliver c d) remaining t
    let t := if remaining%50 == 0 then store64 (streamAck c d) (load64 (streamAck c d) t+1) t else t
    if n%100 != 0 then t else
      let qn := load64 (needAck c d) t
      let index := (load64 (ackHead c d) t+qn)%10
      let t := copy (lastDigest c d) (ackQueue c d+index*20) 20 t
      store64 (needAck c d) (qn+1) t
/-- Recognize an already decrypted layer; status at scratch1000, token preserved. -/
def recognize (c s d body t : UInt64) : UInt64 :=
  if d > 1 || load64 (c+1424) t != 1 then store64 (s+1000) 2 t else
    if be16 (body+1) t != 0 then store64 (s+1000) 1 t else
      let t := copy (body+5) (s+980) 4 t
      let t := zero (body+5) 4 t
      let t := copy (hashContext c d) (s+704) 128 t
      let t := Guest.SHA1.update (s+704) s body 509 t
      let t := copy (s+704) (s+832) 128 t
      let t := Guest.SHA1.finish (s+832) s (s+960) t
      let good := difference (s+980) (s+960) 4 0 t == 0
      let t := copy (s+980) (body+5) 4 t
      if !good then store64 (s+1000) 1 (zero s 1000 t) else
        if !validHeader body t then store64 (s+1000) 2 (zero s 1000 t) else
          let t := selectStream c body t
          if t == err then store64 (s+1000) 2 (zero s 1000 t) else
          if load8 body t == 2 && (load64 (deliverWindow c d) t == 0 || load64 (streamDeliver c d) t == 0) then store64 (s+1000) 5 (zero s 1000 t) else
            let t := copy (s+704) (hashContext c d) 128 t
            let t := copy (s+960) (lastDigest c d) 20 t
            let t := recordReceived c d body t
            store64 (s+1000) 0 (zero s 1000 t)
def peel (c s d body t : UInt64) : UInt64 :=
  let r := cryptLayer c d body t
  if r == err then store64 (s+1000) 3 r else recognize c s d body r
/-- Build authenticated circuit SENDME body after endpoint consumption drains data. -/
def sendme (c d out t : UInt64) : UInt64 :=
  if d > 1 || load64 (needAck c d) t == 0 || load64 (deliverWindow c d) t > 900 then err else
    let t := store8 out 1 t
    let t := putBE (out+1) 20 2 0 t
    let index := load64 (ackHead c d) t
    let t := copy (ackQueue c d+index*20) (out+3) 20 t
    let t := zero (ackQueue c d+index*20) 20 t
    let t := store64 (ackHead c d) ((index+1)%10) t
    let t := store64 (needAck c d) (load64 (needAck c d) t-1) t
    store64 (deliverWindow c d) (load64 (deliverWindow c d) t+100) t
/-- Call only for a recognized/authenticated circuit SENDME on the reverse direction. -/
def acceptSendme (c d data n t : UInt64) : UInt64 :=
  if d > 1 || n < 23 || load8 data t != 1 || be16 (data+1) t < 20 || be16 (data+1) t > n-3 || load64 (queueCount c d) t == 0 then err else
    let p := digestQueue c d+load64 (queueHead c d) t*20
    if difference (data+3) p 20 0 t != 0 || load64 (packageWindow c d) t > 900 then err else
      let t := zero p 20 t
      let t := store64 (queueHead c d) ((load64 (queueHead c d) t+1)%10) t
      let t := store64 (queueCount c d) (load64 (queueCount c d) t-1) t
      store64 (packageWindow c d) (load64 (packageWindow c d) t+100) t
-- Stream-level SENDME has this selected stream ID and an empty body. The
-- bounded edge retains fewer than10 cells (one chunk plus≤3 RPC fragments).
def sendmeStream (c d t : UInt64) : UInt64 :=
  if d > 1 || load64 (streamId c) t == 0 || load64 (streamAck c d) t == 0 || load64 (streamDeliver c d) t > 450 then err else
    let t := store64 (streamAck c d) (load64 (streamAck c d) t-1) t
    store64 (streamDeliver c d) (load64 (streamDeliver c d) t+50) t
def acceptStreamSendme (c d id n t : UInt64) : UInt64 :=
  if d > 1 || id == 0 || n != 0 || load64 (streamId c) t != id || load64 (streamPackage c d) t > 450 then err else
    store64 (streamPackage c d) (load64 (streamPackage c d) t+50) t
def relayEarly (c t : UInt64) : UInt64 :=
  if load64 (c+1608) t >= 8 then err else store64 (c+1608) (load64 (c+1608) t+1) t
def teardown (c t : UInt64) : UInt64 := zero c 2560 t
end Guest.TorCells
