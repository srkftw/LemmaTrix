import Guest.ContentStore
import Guest.ProjectSDK
import Guest.ServiceSDK
namespace Guest.BuildArtifact
open Guest.LiveSDK
open Guest.ProjectSDK
-- Four independent live requester compartments. Network/session grants remain
-- in the requesting application. This service receives already authenticated
-- messages and can use only that caller's ContentStore handles.
def selection : UInt64 := 0x750000
def callers : UInt64 := 0x750100
def st (t : UInt64) : UInt64 := 0x760000+load64 selection t*16384
def provider (t : UInt64) : UInt64 := st t+1024
def pins (t : UInt64) : UInt64 := st t+1088
def source (t : UInt64) : UInt64 := st t+1152
def requestBytes (t : UInt64) : UInt64 := st t+1280
def output (t : UInt64) : UInt64 := st t+2048
def incomingBytes (t : UInt64) : UInt64 := st t+3072
def artifactManifest (t : UInt64) : UInt64 := st t+4096
def artifactBinding (t : UInt64) : UInt64 := st t+4352
def artifactProof (t : UInt64) : UInt64 := st t+4864
def nodeDigest (t : UInt64) : UInt64 := st t+6144
def artifactData (t : UInt64) : UInt64 := st t+8192
def state (t : UInt64) : UInt64 := load64 (st t+32) t
def statusCode (code t : UInt64) : UInt64 := store64 (st t+112) code t
def equal (a b n t : UInt64) : Bool := Guest.ContentFormat.equal a b n t
namespace Content
-- Calls are internal to endpoint5; they retain the actual requesting caller
-- and rights from the current authenticated IPC, avoiding a self-IPC deadlock.
def callContent (length t : UInt64) : UInt64 :=
  let t := copy wire command length t
  Guest.ContentStore.dispatch (load64 (callers+load64 selection t*8) t) (load64 (selection+8) t) length t
def reserve (binding operation budget mode durable t : UInt64) : UInt64 :=
  let t := header 300 0 operation budget mode durable 0 t
  callContent 416 (copy binding (wire+64) 352 t)
def beginChunk (content index proof proofBytes t : UInt64) : UInt64 :=
  if proofBytes > 480 then error else
    let t := header 301 content index 0 0 0 0 t
    callContent (64+proofBytes) (copy proof (wire+64) proofBytes t)
def append (job offset source length t : UInt64) : UInt64 :=
  if length == 0 || length > 640 then error else
    let t := header 302 job offset 0 0 0 0 t
    callContent (64+length) (copy source (wire+64) length t)
def validate (job t : UInt64) : UInt64 := callContent 64 (header 303 job 0 0 0 0 0 t)
def inspectJob (job t : UInt64) : UInt64 := callContent 64 (header 304 job 0 0 0 0 0 t)
def control (job action t : UInt64) : UInt64 := callContent 64 (header 305 job action 0 0 0 0 t)
def describe (content t : UInt64) : UInt64 := callContent 64 (header 306 content 0 0 0 0 0 t)
def read (content offset count t : UInt64) : UInt64 := callContent 64 (header 307 content offset count 0 0 0 t)
def publish (content t : UInt64) : UInt64 := callContent 64 (header 310 content 0 0 0 0 0 t)
def proof (content index t : UInt64) : UInt64 := callContent 64 (header 313 content index 0 0 0 0 t)
end Content
def sendPacket (kind n t : UInt64) : UInt64 :=
  let t := copy (requestBytes t) (output t) 256 t
  let t := store64 (output t+16) kind t
  let t := copy (provider t) (output t+224) 32 t
  store64 (st t+344) n t
def artifactPacket (p n _clock t : UInt64) : UInt64 :=
  let kind := load64 (p+16) t
  let role := load64 (st t) t
  let index := load64 (p+256) t
  let phase := load64 ((st t)+304) t
  if role >= 2 && state t == 3 && load64 ((st t)+312) t == 2 then
    let t := if load64 ((st t)+360) t == 0 then t else Guest.ServiceHash.sha256At (nodeDigest t) (artifactManifest t) 256 (artifactProof t) t
    if load64 ((st t)+360) t != 0 && !equal (artifactProof t) ((st t)+384) 32 t then statusCode 2 t else
    if kind == 6 && n == 256 then
      sendPacket 8 512 (copy (artifactManifest t) ((output t)+256) 256 t)
    else if kind == 7 && n == 264 then
      let r := Content.proof (load64 ((st t)+80) t) index t
      if r < 96 || r > 288 || status r != 0 then statusCode 2 r else
        let t := store64 ((output t)+256) index r
        sendPacket 9 (264+r-64) (copy (wire+64) ((output t)+264) (r-64) t)
    else if kind == 10 && n == 280 then
      let offset := load64 (p+264) t
      let count := load64 (p+272) t
      if index >= load64 ((artifactManifest t)+32) t || count == 0 || count > 384 ||
        offset >= Guest.ContentFormat.chunkLength (load64 ((st t)+88) t) index ||
        count > Guest.ContentFormat.chunkLength (load64 ((st t)+88) t) index-offset then statusCode 2 t else
      let r := Content.read (load64 ((st t)+80) t) (index*4096+offset) count t
      if r != 64+count || status r != 0 then statusCode 2 r else
      let t := copy (wire+64) ((output t)+280) count r
      let t := if load64 ((st t)+360) t == 0 then t else Guest.ServiceSDK.reserve (load64 ((st t)+360) t-1) count 0 1 t
      if load64 ((st t)+360) t != 0 && (t != 64 || status t != 0) then statusCode 4 t else
        let t := store64 ((output t)+256) index t
        let t := store64 ((output t)+264) offset t
        sendPacket 11 (280+count) (store64 ((output t)+272) count t)
    else statusCode 2 t
  else if role == 1 && state t == 3 && load64 ((st t)+312) t == 2 then
    if kind == 8 && n == 512 && phase == 2 then
      if !Guest.ContentFormat.valid (p+256) t || load64 (p+296) t != 2 ||
        load64 (p+280) t != load64 ((st t)+88) t || !equal (p+320) ((st t)+128) 32 t ||
        !equal (p+384) (source t) 32 t then statusCode 2 t else
      let t := copy (p+256) (artifactManifest t) 256 t
      let t := copy (artifactManifest t) (artifactBinding t) 256 t
      let t := Guest.ServiceHash.sha256At (nodeDigest t) (artifactManifest t) 256 ((artifactBinding t)+256) t
      let t := copy (pins t) ((artifactBinding t)+288) 64 t
      let r := Content.reserve (artifactBinding t) (load64 ((requestBytes t)+32) t ||| 1) (load64 ((st t)+88) t) 3 0 t
      if r != 64 || status r != 0 then statusCode 4 r else
        let t := store64 ((st t)+104) (result r) r
        store64 ((st t)+304) 3 (store64 ((st t)+320) 0 t)
    else if kind == 9 && phase == 4 && index == load64 ((st t)+320) t && n == 296+load64 ((artifactManifest t)+48) t*32 then
      let t := copy (p+264) (artifactProof t) (n-264) t
      let r := Content.beginChunk (load64 ((st t)+104) t) index (artifactProof t) (n-264) t
      if r != 64 || status r != 0 then statusCode 2 r else
        if result r == 0 && load64 (wire+16) r == 4 then
          store64 ((st t)+304) 3 (store64 ((st t)+320) (index+1) r)
        else
          let t := store64 ((st t)+328) (result r) r
          let t := store64 ((st t)+336) 0 t
          store64 ((st t)+304) 5 t
    else if kind == 11 && phase == 6 && index == load64 ((st t)+320) t &&
      load64 (p+264) t == load64 ((st t)+336) t && load64 (p+272) t > 0 &&
      load64 (p+272) t <= 384 && n == 280+load64 (p+272) t then
      let count := load64 (p+272) t
      let offset := load64 ((st t)+336) t
      let r := Content.append (load64 ((st t)+328) t) offset (p+280) count t
      if r != 64 || status r != 0 then statusCode 2 r else
        let t := store64 ((st t)+336) (offset+count) r
        store64 ((st t)+304) 5 t
    else statusCode 2 t
  else statusCode 2 t

def artifactTick (clock t : UInt64) : UInt64 :=
  if load64 (st t) t != 1 || state t != 3 || load64 ((st t)+312) t != 2 then t else
  let phase := load64 ((st t)+304) t
  let index := load64 ((st t)+320) t
  if phase == 7 then
    let r := Content.inspectJob (load64 ((st t)+328) t) t
    if r != 64 || status r != 0 || load64 (wire+16) r >= 5 then statusCode 2 (store64 ((st t)+304) 11 r) else
    if load64 (wire+16) r != 4 then r else
      let r := Content.control (load64 ((st t)+328) r) 4 r
      store64 ((st t)+304) 3 (store64 ((st t)+320) (index+1) r)
  else if phase == 9 then
    let r := Content.inspectJob (load64 ((st t)+328) t) t
    if r != 64 || status r != 0 || load64 (wire+16) r >= 5 then statusCode 2 (store64 ((st t)+304) 11 r) else
    if load64 (wire+16) r != 4 then r else
      let r := Content.control (load64 ((st t)+328) r) 4 r
      store64 ((st t)+304) 10 r
  else if phase == 3 && index == load64 ((artifactManifest t)+32) t then
    let r := Content.publish (load64 ((st t)+104) t) t
    if r != 64 || status r != 0 then statusCode 2 (store64 ((st t)+304) 11 r) else
      if result r == load64 ((st t)+104) r then store64 ((st t)+304) 10 r else
        store64 ((st t)+304) 9 (store64 ((st t)+328) (result r) r)
  else if phase == 5 && load64 ((st t)+336) t == Guest.ContentFormat.chunkLength (load64 ((st t)+88) t) index then
    let r := Content.validate (load64 ((st t)+328) t) t
    if r != 64 || status r != 0 then statusCode 2 (store64 ((st t)+304) 11 r) else store64 ((st t)+304) 7 r
  else if (phase == 2 || phase == 4 || phase == 6) && clock >= load64 ((st t)+352) t then
    if load64 ((st t)+376) t >= 16 then statusCode 7 (store64 ((st t)+304) 11 t) else
      store64 ((st t)+304) (phase-1) (store64 ((st t)+376) (load64 ((st t)+376) t+1) t)
  else if load64 ((st t)+24) t != 0 then t else
  if phase == 1 then
    let t := sendPacket 6 256 t
    store64 ((st t)+304) 2 (store64 ((st t)+352) (clock+2000) t)
  else if phase == 3 then
    let t := store64 ((output t)+256) index t
    let t := sendPacket 7 264 t
    store64 ((st t)+304) 4 (store64 ((st t)+352) (clock+2000) t)
  else if phase == 5 then
    let offset := load64 ((st t)+336) t
    let remaining := Guest.ContentFormat.chunkLength (load64 ((st t)+88) t) index-offset
    let count := if remaining > 384 then 384 else remaining
    let t := store64 ((output t)+256) index t
    let t := store64 ((output t)+264) offset t
    let t := store64 ((output t)+272) count t
    let t := sendPacket 10 280 t
    store64 ((st t)+304) 6 (store64 ((st t)+352) (clock+2000) t)
  else t

partial def appendNode (h length offset t : UInt64) : UInt64 :=
  if offset == length then t else
    let count := if length-offset > 512 then 512 else length-offset
    let r := Guest.LiveSDK.append h offset (artifactData t+offset) count t
    if r != 64 || status r != 0 then error else appendNode h length (offset+count) r
def genericMetadata (t : UInt64) : UInt64 :=
  let r := Content.describe (load64 ((st t)+80) t) t
  if r != 320 || status r != 0 || load64 (wire+16) r != 2 then error else
    let t := copy (wire+64) (artifactManifest t) 256 r
    let t := copy (artifactManifest t) (artifactData t) 256 t
    let r := stage 256 10 0 t
    if r != 64 || status r != 0 then error else
      let h := result r
      let r := appendNode h 256 0 r
      if r == error then error else
        let r := stageDigest h r
        if r != 96 || status r != 0 then error else
          let r := commit h (wire+64) r
          if r != 96 || status r != 0 then error else
            let h := result r
            let r := Guest.LiveSDK.share h (load64 (callers+load64 selection r*8) r) 1 r
            if r != 64 || status r != 0 then error else nodeMetadata h r

def inspectArtifact (t : UInt64) : UInt64 :=
  let t := header 0 (load64 ((st t)+104) t) (load64 ((st t)+304) t) (load64 ((st t)+312) t)
    (load64 ((st t)+320) t) (load64 ((st t)+336) t) (load64 ((st t)+376) t) t
  let t := copy (pins t) (wire+64) 64 t
  384+copy (artifactManifest t) (wire+128) 256 t

def bindArtifactService (slot t : UInt64) : UInt64 :=
  let r := Guest.ServiceSDK.inspect slot t
  if r != 576 || status r != 0 || load64 (wire+256) r != 1 then error else
  let t := copy (wire+192) ((st t)+384) 32 r
  store64 ((st t)+360) (slot+1) t

partial def locate (caller i t : UInt64) : UInt64 :=
  if i == 4 then error else if load64 (callers+i*8) t == caller then i else locate caller (i+1) t
partial def vacant (i t : UInt64) : UInt64 :=
  if i == 4 then error else if load64 (callers+i*8) t == 0 then i else vacant (i+1) t
def setup (caller length t : UInt64) : UInt64 :=
  if length != 480 || load64 (command+8) t == 0 || load64 (command+8) t > 3 ||
    load64 (command+24) t == 0 || load64 (command+24) t > 262144 then error else
  let found := locate caller 0 t
  let slot := if found == error then vacant 0 t else found
  if slot == error then error else
  let t := store64 selection slot t
  let t := store64 (callers+slot*8) caller t
  if found != error && equal (command+64+32) (requestBytes t+32) 192 t && load64 (st t) t != 0 then t else
    let t := zero (st t) 2048 t
    let t := store64 (st t) (load64 (command+8) t) t
    let t := store64 (st t+32) 3 t
    let t := store64 (st t+80) (load64 (command+16) t) t
    let t := store64 (st t+88) (load64 (command+24) t) t
    let t := store64 (st t+312) 2 t
    let t := store64 (st t+304) (if load64 (st t) t == 1 then 1 else 0) t
    let t := copy (command+64) (requestBytes t) 256 t
    let t := copy (command+320) (pins t) 64 t
    let t := copy (command+384) (provider t) 32 t
    let t := copy (command+416) (source t) 32 t
    copy (command+448) (st t+128) 32 t
def response (t : UInt64) : UInt64 :=
  let n := load64 (st t+344) t
  let t := header (load64 (st t+112) t) n (load64 (st t+304) t) (load64 (st t+104) t)
    (load64 (st t+320) t) (load64 (st t+336) t) (load64 (st t+376) t) t
  let t := copy (output t) (wire+64) n t
  64+n+store64 (st t+344) 0 t
def dispatch (caller rights length t : UInt64) : UInt64 :=
  let op := load64 command t
  let clock := load64 (command+16) t
  if op == 26 && length == 64 && (rights &&& 0x100000000) != 0 && load64 (command+56) t == 1 then
    let selected := load64 (command+8) t
    let slot := locate selected 0 t
    if slot == error then 64+header 3 0 0 0 0 0 0 t else
    let t := store64 selection slot t
    if load64 (st t) t != 1 || load64 (st t+304) t != 10 then 64+header 6 0 0 0 0 0 0 t else
      Guest.ContentStore.share selected 8 (load64 (st t+104) t) caller t
  else if (rights &&& 1024) == 0 || length < 64 || length > 768 || load64 (command+56) t != 1 then
    64+header 1 0 0 0 0 0 0 t
  else if op == 20 then
    let r := setup caller length t
    if r == error then 64+header 4 0 0 0 0 0 0 r else 64+header 0 0 0 0 0 0 0 r
  else
    let slot := locate caller 0 t
    if slot == error then 64+header 3 0 0 0 0 0 0 t else
    let t := store64 selection slot t
    let t := store64 (selection+8) rights t
    let t := store64 (st t+112) 0 t
    if op == 21 && length >= 320 && length <= 768 then
      let n := length-64
      let t := copy (command+64) (incomingBytes t) n t
      if !equal (incomingBytes t+32) (requestBytes t+32) 192 t ||
        !equal (incomingBytes t+224) (pins t) 32 t then 64+header 2 0 0 0 0 0 0 t else
        response (artifactPacket (incomingBytes t) n clock t)
    else if op == 22 && length == 64 then response (artifactTick clock t)
    else if op == 23 && length == 64 then inspectArtifact t
    else if op == 24 && length == 64 then
      let r := bindArtifactService clock t
      64+header (if r == error then 1 else 0) 0 0 0 0 0 0 r
    else if op == 25 && length == 64 then
      genericMetadata t
    else 64+header 2 0 0 0 0 0 0 t
end Guest.BuildArtifact
