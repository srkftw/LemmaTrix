import Guest.ProjectSDK
import Guest.ProjectGraph
import Guest.NetworkSDK
import Guest.ContentSDK
import Guest.ContentFormat
import Guest.ServiceSDK
namespace Guest.RemoteBuild
open Guest.LiveSDK
open Guest.ProjectSDK
-- RemoteBuild-v1: one explicitly selected source scope per application. The
-- provider owns admission/quote/approval and BuildJobs owns frozen execution.
-- Existing host sandbox is a disclosed executor, never an admission authority.
def st : UInt64 := 0x740000
def provider : UInt64 := 0x740400
def compiler : UInt64 := 0x740440
def pins : UInt64 := 0x740480
def source : UInt64 := 0x740500
def project : UInt64 := 0x740540
def requestBytes : UInt64 := 0x741000
def output : UInt64 := 0x742000
def incomingBytes : UInt64 := 0x742400
def artifactData : UInt64 := 0x743000
def nodeDigest : UInt64 := 0x743800
def artifactManifest : UInt64 := 0x744000
def artifactBinding : UInt64 := 0x744200
def artifactProof : UInt64 := 0x745000
def magic : UInt64 := 0x31424a4252544c
def equal (a b n t : UInt64) : Bool := Guest.ProjectGraph.equal a b n t
-- Native build executor uses fixed hard limits: CPU60s,wall120s,16GiB address
-- space,128MiB writable work,16MiB temp; no network or signing keys. This
-- version1 accepts64KiB; the generic-artifact profile accepts256KiB.
def budgetAccepted (input cpu wall out recipe profile terms : UInt64) : Bool :=
  input > 0 && input <= 4194304 && cpu == 60 && wall == 120 && (out == 65536 || out == 262144) && recipe == 1 && profile == 2 && terms == 0
theorem paid_contract_unavailable : budgetAccepted 1 60 120 65536 1 2 1 = false := by decide

def statusCode (code t : UInt64) : UInt64 := store64 (st+112) code t
def state (t : UInt64) : UInt64 := load64 (st+32) t
def acceptsQuote (s : UInt64) : Bool := s == 7 || s == 1
def acceptsResult (s : UInt64) : Bool := s == 2 || s == 3
-- Assumes the accepted packet names the current exact request. Terminal local
-- cancellation/expiry still cannot be reversed by an authenticated late packet.
theorem cancelled_packets_do_not_revive : acceptsQuote 5 = false ∧ acceptsResult 5 = false ∧ acceptsQuote 6 = false ∧ acceptsResult 6 = false := by decide
-- roles1client,2builder,3verifier; identity/toolchain/pinned peer/service are
-- deliberately configured by the operator and never supplied by a request.
def configure (role identity toolchain peerService t : UInt64) : UInt64 :=
  if role < 1 || role > 3 || state t == 2 || state t == 7 || Guest.ProjectGraph.allZero identity 32 t || Guest.ProjectGraph.allZero toolchain 32 t then error else
    let old := load64 (st+8) t
    let t := if old == 0 then t else Guest.NetworkSDK.revoke old t
    let t := zero st 128 t
    let t := copy identity provider 32 t
    let t := copy toolchain compiler 32 t
    let t := copy peerService pins 64 t
    store64 st role t

def select (root t : UInt64) : UInt64 :=
  if load64 st t == 0 || state t == 2 || state t == 7 then error else
    let r := describeRoot root t
    if r != 160 || status r != 0 then error else
      let t := copy (wire+64) source 32 r
      let r := projectIdentity root t
      if r != 192 || status r != 0 then error else
        let t := copy (wire+160) project 32 r
        let t := copy source (pins+64) 32 t
        let old := load64 (st+8) t
        let t := if old == 0 then t else Guest.NetworkSDK.revoke old t
        let r := Guest.NetworkSDK.grant pins 3 3 4194304 65536 100000 2 t
        if r != 64 || status r != 0 then error else
          let grant := result r
          let t := zero (st+24) 37 r
          let t := store64 (st+8) grant t
          store64 (st+16) root (store64 (st+32) 0 t)

def validPacket (p n t : UInt64) : Bool :=
  n >= 256 && n <= 704 && load64 p t == magic && load64 (p+8) t == 1 &&
  (load64 (p+24) t == 2 || load64 (p+24) t == 3) &&
  !Guest.ProjectGraph.allZero (p+32) 32 t && equal (p+64) source 32 t && equal (p+96) project 32 t && equal (p+128) compiler 32 t &&
  budgetAccepted (load64 (p+176) t) (load64 (p+184) t) (load64 (p+192) t) (load64 (p+200) t) (load64 (p+160) t) (load64 (p+168) t) (load64 (p+216) t) &&
  load64 (p+208) t > 0 && load64 (p+208) t <= 100000 && equal (p+224) pins 32 t

def sendPacket (kind n t : UInt64) : UInt64 :=
  if load64 (st+24) t != 0 then statusCode 4 t else
    let t := copy requestBytes output 256 t
    let t := store64 (output+16) kind t
    let t := copy provider (output+224) 32 t
    let t := if kind == 5 then
      let t := copy (st+128) (output+256) 128 t
      let t := copy (st+256) (output+288) 32 t
      let t := store64 (output+384) (state t) t
      store64 (output+392) (load64 (st+88) t) t
      else t
    let t := if kind == 5 && load64 (st+312) t == 2 then store64 (output+400) 2 t else t
    let n := if kind == 5 && load64 (st+312) t == 2 then 408 else n
    let r := Guest.NetworkSDK.send (load64 (st+8) t) 2 output n t
    if r != 64 || status r != 0 then statusCode 7 r else store64 (st+24) (result r) r

-- Called by the requester after a physical choice of provider/source/budget.
-- jobId is fresh public entropy supplied by the broker's nonce operation.
def request (jobId input role clock t : UInt64) : UInt64 :=
  if load64 st t != 1 || load64 (st+16) t == 0 || state t == 2 || state t == 7 || Guest.ProjectGraph.allZero jobId 32 t || input == 0 || input > 4194304 || (role != 2 && role != 3) then error else
    let t := zero requestBytes 64 t
    let t := store64 requestBytes magic t
    let t := store64 (requestBytes+8) 1 t
    let t := store64 (requestBytes+24) role t
    let t := copy jobId (requestBytes+32) 32 t
    let t := copy source (requestBytes+64) 32 t
    let t := copy project (requestBytes+96) 32 t
    let t := copy compiler (requestBytes+128) 32 t
    let t := store64 (requestBytes+160) 1 t
    let t := store64 (requestBytes+168) 2 t
    let t := store64 (requestBytes+176) input t
    let t := store64 (requestBytes+184) 60 t
    let t := store64 (requestBytes+192) 120 t
    let t := store64 (requestBytes+200) 262144 t
    let t := store64 (requestBytes+208) 100000 t
    let t := store64 (st+40) (clock+100000) t
    let t := store64 (st+32) 7 t
    sendPacket 1 256 t

def approve (t : UInt64) : UInt64 :=
  if load64 st t != 1 || (state t != 1 && state t != 2) then error else
    let t := store64 (st+32) 2 t
    sendPacket 3 256 t

partial def scopeFits (root cursor bytes fuel t : UInt64) : UInt64 :=
  if fuel == 0 then error else
    let r := closure root cursor t
    if r < 64 || status r != 0 then error else
    if result r == 0 then r else
      let n := load64 (wire+16) r
      let next := load64 (wire+24) r
      let limit := load64 (requestBytes+176) r
      if next <= cursor || bytes > limit || n > limit-bytes then error else scopeFits root next (bytes+n) (fuel-1) r

def enqueue (t : UInt64) : UInt64 :=
  let t := scopeFits (load64 (st+16) t) 0 0 65 t
  if t == error then statusCode 4 t else
  let r := describeRoot (load64 (st+16) t) t
  if r != 160 || status r != 0 || !equal (wire+64) source 32 r then statusCode 2 r else
    let r := projectIdentity (load64 (st+16) r) r
    if r != 192 || status r != 0 || !equal (wire+160) project 32 r then statusCode 2 r else
      let broker := syscall 97 5 0 0 0 r
      let r := delegate (load64 (st+16) broker) broker 73 broker
      if r != 160 || status r != 0 then statusCode 3 r else
      let t := store64 (st+120) (result r) r
      let t := header 1 (result r) 0 0 0 0 0 t
      let r := syscall 30 broker wire 64 1024 t
      if r != 256 || status r != 0 || !equal (wire+64) source 32 r || !equal (wire+128) compiler 32 r then statusCode 3 r else
        let t := store64 (st+48) (result r) r
        let t := store64 (st+56) (load64 (wire+24) t) t
        let t := store64 (st+32) 2 t
        statusCode 0 t

-- Artifact-v2 uses the same approved request/root/role/toolchain tuple. The
-- manifest, proofs and bounded ranges are generic content, not audio or a
-- large Project record. Only actual verified bytes enter the client cache.
def setupArtifact (t : UInt64) : UInt64 :=
  let t := header 20 (load64 st t) (load64 (st+80) t) (load64 (st+88) t) 0 0 0 t
  let t := copy requestBytes (wire+64) 256 t
  let t := copy pins (wire+320) 64 t
  let t := copy provider (wire+384) 32 t
  let t := copy source (wire+416) 32 t
  let t := copy (st+128) (wire+448) 32 t
  syscall 30 5 wire 480 1024 t

def artifactResponse (r : UInt64) : UInt64 :=
  if r < 64 || status r != 0 || load64 (wire+8) r > 704 || r != 64+load64 (wire+8) r then statusCode 2 r else
    let n := load64 (wire+8) r
    let t := store64 (st+304) (load64 (wire+16) r) r
    let t := store64 (st+104) (load64 (wire+24) t) t
    let t := store64 (st+320) (load64 (wire+32) t) t
    let t := store64 (st+336) (load64 (wire+40) t) t
    let t := store64 (st+376) (load64 (wire+48) t) t
    if n == 0 then t else
      store64 (st+344) n (copy (wire+64) 0x747000 n t)

def artifactPacket (p n clock t : UInt64) : UInt64 :=
  let t := header 21 0 clock 0 0 0 0 t
  let t := copy p (wire+64) n t
  artifactResponse (syscall 30 5 wire (64+n) 1024 t)

def accept (p n clock t : UInt64) : UInt64 :=
  if !validPacket p n t then statusCode 2 t else
  let kind := load64 (p+16) t
  let role := load64 st t
  if kind == 1 && role >= 2 && load64 (p+24) t == role then
    let same := equal (p+32) (requestBytes+32) 192 t
    if state t >= 3 && same then
      if state t == 3 || state t == 4 then sendPacket 5 400 t else sendPacket 4 256 t
    else
    if state t > 0 && state t < 3 && !same then statusCode 3 t else
      let t := if state t >= 3 then zero (st+128) 24 (zero (st+32) 12 t) else t
      let t := copy p requestBytes 256 t
      let t := if state t == 0 then store64 (st+40) (clock+load64 (p+208) t) t else t
      let t := if state t == 0 then store64 (st+32) 1 t else t
      sendPacket 2 256 t
  else if !equal (p+32) (requestBytes+32) 192 t then statusCode 3 t else
  if kind >= 6 then artifactPacket p n clock t else
  if kind == 2 && role == 1 then
    if acceptsQuote (state t) then store64 (st+32) 1 t else t
  else
  if kind == 3 && role >= 2 && clock < load64 (st+40) t then
    if state t == 1 then enqueue t else t
  else if kind == 4 then
    let localJob := load64 (st+48) t
    let t := if role == 1 || localJob == 0 then t else syscall 30 5 wire 64 1024 (header 5 localJob 0 0 0 0 0 t)
    store64 (st+32) 5 t
  else if kind == 5 && role == 1 && (n == 400 || (n == 408 && load64 (p+400) t == 2)) && (load64 (p+384) t == 3 || load64 (p+384) t == 4) then
    if !acceptsResult (state t) then t else
    if state t == 3 then
      if load64 (p+384) t == 3 && equal (p+256) (st+128) 128 t && load64 (p+392) t == load64 (st+88) t then t else statusCode 2 t
    else
      let t := copy (p+256) (st+128) 128 t
      let t := store64 (st+88) (load64 (p+392) t) t
      let t := if n == 408 then store64 (st+312) 2 (store64 (st+304) 1 t) else t
      let t := store64 (st+32) (load64 (p+384) t) t
      if n == 408 then
        let r := setupArtifact t
        if r != 64 || status r != 0 then statusCode 4 r else r
      else t
  else statusCode 2 t

def cancel (t : UInt64) : UInt64 :=
  let j := load64 (st+48) t
  let t := if load64 st t >= 2 && j != 0 && state t == 2 then
    syscall 30 5 wire 64 1024 (header 5 j 0 0 0 0 0 t)
    else t
  let t := store64 (st+32) 5 t
  sendPacket 4 256 t

def inspect (t : UInt64) : UInt64 :=
  let t := zero wire 8 t
  let t := copy st (wire+64) 256 t
  let t := copy source (wire+320) 32 t
  let t := copy project (wire+352) 32 t
  let t := copy compiler (wire+384) 32 t
  let t := copy provider (wire+416) 32 t
  704+copy requestBytes (wire+448) 256 t

def resultRoot (t : UInt64) : UInt64 := load64 (st+96) t

def pollSend (t : UInt64) : UInt64 :=
  let j := load64 (st+24) t
  if j == 0 then t else
    let r := Guest.NetworkSDK.poll j t
    if r != 64 || status r != 0 || load64 (wire+16) r >= 4 then statusCode 7 (store64 (st+24) 0 r) else
    if load64 (wire+16) r == 3 then store64 (st+24) 0 r else r

partial def appendNode (h length offset t : UInt64) : UInt64 :=
  if offset == length then t else
    let count := if length-offset > 512 then 512 else length-offset
    let r := append h offset (artifactData+offset) count t
    if r != 64 || status r != 0 then error else appendNode h length (offset+count) r
def entry (p kind id name length t : UInt64) : UInt64 :=
  let t := zero p 16 t
  let t := store64 p kind t
  let t := store64 (p+8) length t
  let t := copy id (p+16) 32 t
  copy name (p+48) length t
def publishArtifact (t : UInt64) : UInt64 :=
  let t := zero artifactData 128 t
  let t := store64 artifactData 0x31464e4d544c t
  let t := store64 (artifactData+8) 1 t
  let t := store64 (artifactData+16) 3 t
  let t := store64 (artifactData+24) 192 t
  -- Canonical Manifest names must remain sorted before build/evidence.
  let generic := load64 (st+312) t == 2
  let t := store64 nodeDigest (if generic then 0x7463616669747261 else 0x006e69622e707061) t
  let t := entry (artifactData+32) 10 (st+160) nodeDigest (if generic then 8 else 7) t
  let t := store64 nodeDigest 0x646c697562 t
  let t := entry (artifactData+160) 12 (st+192) nodeDigest 5 t
  let t := store64 nodeDigest 0x65636e6564697665 t
  let t := entry (artifactData+288) 14 (st+224) nodeDigest 8 t
  let t := copy source (artifactData+416) 32 t
  let t := copy project (artifactData+448) 32 t
  let t := copy provider (artifactData+480) 32 t
  let t := copy compiler (artifactData+512) 32 t
  let t := copy (requestBytes+32) (artifactData+544) 32 t
  let t := store64 (artifactData+576) (load64 st t) t
  let t := store64 (artifactData+584) 2 t
  let t := store64 (artifactData+600) 1 t
  let r := stage 608 11 0 t
  if r != 64 || status r != 0 then error else
    let h := result r
    let r := appendNode h 608 0 r
    if r == error then Guest.Effects.effectValue error (abortStage h r) else
      let r := stageDigest h r
      if r != 96 || status r != 0 then Guest.Effects.effectValue error (abortStage h r) else
        let r := commit h (wire+64) r
        if r != 96 || status r != 0 then Guest.Effects.effectValue error (abortStage h r) else
          let h := result r
          let t := zero nodeDigest 16 r
          let t := store64 nodeDigest 0x722d65746f6d6572 t
          let t := store64 (nodeDigest+8) 0x746c757365 t
          let r := publish h 0 (nodeDigest+32) nodeDigest 13 t
          if r != 160 || status r != 0 then Guest.Effects.effectValue error (drop h r) else
            let t := store64 (st+96) (result r) r
            copy (wire+64) (st+256) 32 t

def genericMetadata (t : UInt64) : UInt64 :=
  let r := setupArtifact t
  if r != 64 || status r != 0 then error else
    let r := if load64 (st+360) r == 0 then r else
      syscall 30 5 wire 64 1024 (header 24 0 (load64 (st+360) r-1) 0 0 0 0 r)
    if r != 64 || status r != 0 then error else
      syscall 30 5 wire 64 1024 (header 25 0 0 0 0 0 0 r)

def pollResult (t : UInt64) : UInt64 :=
  if load64 st t < 2 || state t != 2 || load64 (st+48) t == 0 then t else
    let t := header 4 (load64 (st+48) t) 0 0 0 0 0 t
    let r := syscall 30 5 wire 64 1024 t
    if r < 128 || status r != 0 then statusCode 3 r else
    if load64 (wire+16) r == 1 then r else
    if load64 (wire+16) r != 2 then
      let t := store64 (st+32) 4 r
      sendPacket 5 400 t
    else
      let t := copy (wire+96) (st+128) 32 r
      let t := store64 (st+64) (load64 (wire+48) t) t
      let t := store64 (st+72) (load64 (wire+56) t) t
      let r := if load64 (st+80) t == 0 then
        syscall 30 5 wire 64 1024 (header 11 (load64 (st+48) t) 0 0 0 0 0 t)
        else
          let t := zero wire 8 t
          let t := store64 (wire+8) (load64 (st+80) t) t
          96+store64 (wire+16) (load64 (st+88) t) t
      if r != 96 || status r != 0 then r else
        let t := store64 (st+80) (result r) r
        let t := store64 (st+88) (load64 (wire+16) t) t
        let t := store64 (st+312) (load64 (wire+24) t) t
        let r := if load64 (st+312) t == 2 then genericMetadata t else nodeMetadata (load64 (st+80) t) t
        if r != 128 || status r != 0 then statusCode 3 r else
          let t := copy (wire+64) (st+160) 32 r
          let r := nodeMetadata (load64 (st+64) t) t
          if r != 128 || status r != 0 then statusCode 3 r else
            let t := copy (wire+64) (st+192) 32 r
            let r := nodeMetadata (load64 (st+72) t) t
            if r != 128 || status r != 0 then statusCode 3 r else
              let t := copy (wire+64) (st+224) 32 r
              let r := publishArtifact t
              if r == error then sendPacket 5 400 (store64 (st+32) 4 (statusCode 3 r)) else
                let t := store64 (st+32) 3 r
                sendPacket 5 400 t

def artifactTick (clock t : UInt64) : UInt64 :=
  let t := if load64 st t != 1 || state t != 3 || load64 (st+312) t != 2 then t else
    artifactResponse (syscall 30 5 wire 64 1024 (header 22 0 clock 0 0 0 0 t))
  if load64 (st+344) t == 0 || load64 (st+24) t != 0 then t else
    let n := load64 (st+344) t
    let r := Guest.NetworkSDK.send (load64 (st+8) t) 2 0x747000 n t
    if r != 64 || status r != 0 then statusCode 7 r else
      store64 (st+344) 0 (store64 (st+24) (result r) r)

def inspectArtifact (t : UInt64) : UInt64 :=
  if load64 (st+312) t == 2 then syscall 30 5 wire 64 1024 (header 23 0 0 0 0 0 0 t) else
    let t := header 0 0 0 0 0 0 0 t
    let t := copy pins (wire+64) 64 t
    384+zero (wire+128) 32 t

def bindArtifactService (slot t : UInt64) : UInt64 :=
  if !Guest.ServiceSDK.validHandle slot then error else
    let t := store64 (st+360) (slot+1) t
    if load64 (st+312) t != 2 then 64+header 0 0 0 0 0 0 0 t else
      let r := syscall 30 5 wire 64 1024 (header 24 0 slot 0 0 0 0 t)
      if r != 64 || status r != 0 then error else r

def tick (clock t : UInt64) : UInt64 :=
  if load64 st t == 0 || load64 (st+8) t == 0 then t else
    let t := pollSend t
    let r := Guest.NetworkSDK.receive (load64 (st+8) t) t
    let lost := r == 64 && status r == 3
    let t := if lost && (state r == 1 || state r == 2 || state r == 7) then
      store64 (st+32) 6 (statusCode 3 (cancel r))
      else r
    let t := if !lost && r >= 64 && status r == 0 && load64 (wire+16) r <= 704 && r == 64+load64 (wire+16) r then
      let n := load64 (wire+16) r
      accept incomingBytes n clock (copy (wire+64) incomingBytes n t)
      else t
    if ((state t >= 1 && state t <= 2) || state t == 7) && clock >= load64 (st+40) t then
      store64 (st+32) 6 (cancel t)
    else artifactTick clock (pollResult t)
end Guest.RemoteBuild
