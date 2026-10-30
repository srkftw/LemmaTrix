import Guest.ProjectSDK
import Guest.ProjectGraph
import Guest.NetworkSDK
import Guest.Raster
import Guest.ForgeArchive
import Guest.RemoteBuild
import Guest.RemoteIngest
import Guest.ForgeFederation
import Guest.ForgeSubscription
import Guest.ForgeCache
namespace Guest.Forge
open Guest.LiveSDK
open Guest.ProjectSDK
-- Forge-v1 is an application protocol over authenticated broker records. The
-- broker owns transport; Objects owns validation and publication. This service
-- owns neither signing credentials nor execution approval.
def st : UInt64 := 0x6e0000
def localHead : UInt64 := 0x6e1000
def remoteHead : UInt64 := 0x6e1100
def localName : UInt64 := 0x6e1200
def remoteName : UInt64 := 0x6e1300
def logical : UInt64 := 0x6e1400
def importedName : UInt64 := 0x6e1500
def offeredHead : UInt64 := 0x6e1600
def offeredName : UInt64 := 0x6e1640
def remoteLogical : UInt64 := 0x6e1680
def packet : UInt64 := 0x6f4000
def received : UInt64 := 0x6f5000
def pins : UInt64 := 0x6f6000
def selectedRoot : UInt64 := 0x6f7000
def record (i : UInt64) : UInt64 := 0x6f8000+i*128
def magic : UInt64 := 0x3145475246544c
def equal (a b n t : UInt64) : Bool := Guest.ProjectGraph.equal a b n t
def message (code t : UInt64) : UInt64 := store64 (st+136) code (store64 (st+248) 1 t)
def networkGrant (root t : UInt64) : UInt64 :=
  let t := copy root (pins+64) 32 t
  let r := Guest.NetworkSDK.grant pins 3 3 16777216 65536 100000 1 t
  if r != 64 || status r != 0 then error else result r
def packetHeader (kind transaction a b c d root t : UInt64) : UInt64 :=
  let t := zero packet 90 t
  let t := store64 packet magic t
  let t := store64 (packet+8) 1 t
  let t := store64 (packet+16) kind t
  let t := store64 (packet+24) transaction t
  let t := store64 (packet+32) a t
  let t := store64 (packet+40) b t
  let t := store64 (packet+48) c t
  let t := store64 (packet+56) d t
  copy root (packet+64) 32 t
def progress (t : UInt64) : UInt64 := store64 (st+408) (load64 (st+400) t+1000000) t
def sendPacket (grant bytes t : UInt64) : UInt64 :=
  if load64 (st+80) t != 0 then message 7 t else
    let r := Guest.NetworkSDK.send grant 1 packet bytes t
    if r != 64 || status r != 0 then message 8 r else progress (store64 (st+80) (result r) r)
def pollSend (t : UInt64) : UInt64 :=
  let handle := load64 (st+80) t
  if handle == 0 then t else
    let r := Guest.NetworkSDK.poll handle t
    if r != 64 || status r != 0 || load64 (wire+16) r >= 4 then
      message 8 (store64 (st+56) 0 (store64 (st+80) 0 r))
    else if load64 (wire+16) r == 3 then store64 (st+80) 0 r else r

partial def enumerate (root cursor i bytes t : UInt64) : UInt64 :=
  if i > 24 || cursor > 64 then error else
    let r := closure root cursor t
    if r < 64 || status r != 0 then error else
    if result r == 0 then
      let t := store64 (st+40) i r
      store64 (st+48) bytes t
    else if i == 24 || r != 128 || load64 (wire+24) r <= cursor || load64 (wire+16) r > 1048576-bytes then error else
      let handle := result r
      let next := load64 (wire+24) r
      let n := load64 (wire+16) r
      let row := record i
      let t := store64 row handle r
      let t := store64 (row+8) n t
      let t := store64 (row+16) (load64 (wire+32) t) t
      let t := store64 (row+120) (load64 (wire+40) t) t
      let t := copy (wire+64) (row+24) 64 t
      let r := metadata handle t
      if r != 96 || status r != 0 then error else
        enumerate root next (i+1) (bytes+n) (copy (wire+64) (row+88) 32 r)
-- An unsuccessful replacement must not expose a removed frozen cap or a
-- partially overwritten enumeration as an available offer.
def withdrawOffer (t : UInt64) : UInt64 :=
  let oldGrant := load64 (st+16) t
  let oldRoot := load64 (st+32) t
  let t := store64 (st+16) 0 (store64 (st+32) 0 t)
  let t := store64 (st+40) 0 (store64 (st+48) 0 t)
  let t := if oldGrant == 0 then t else Guest.NetworkSDK.revoke oldGrant t
  if oldRoot == 0 then t else remove oldRoot t
def prepare (t : UInt64) : UInt64 :=
  if load64 (st+24) t == 0 || load64 (st+192) t != 0 || load64 (st+56) t != 0 || load64 (st+80) t != 0 || load64 (st+112) t != 0 then message 2 t else
    let t := withdrawOffer t
    let r := describeRoot (load64 (st+24) t) t
    if r != 160 || status r != 0 then message 2 r else
      let t := copy (wire+64) localHead 32 r
      let t := copy (wire+96) localName 64 t
      let t := Guest.ForgeFederation.reuseRemote localHead t
      let t := store64 (st+168) (load64 (wire+16) t) t
      let r := projectIdentity (load64 (st+24) t) t
      if r != 192 || status r != 0 then message 2 r else
      let t := copy (wire+160) logical 32 r
      let r := freeze (load64 (st+24) t) localHead t
      if r != 160 || status r != 0 then message 2 r else
        let root := result r
        let t := copy localHead offeredHead 32 r
        let t := copy localName offeredName 64 t
        let t := store64 (st+480) (load64 (st+168) t) t
        let r := enumerate root 0 0 0 t
        if r == error then message 3 (remove root r) else
          let grant := networkGrant localHead r
          if grant == error then message 8 (withdrawOffer (remove root grant)) else
            message 4 (store64 (st+32) root (store64 (st+16) grant grant))
def metadataOnly (t : UInt64) : Bool := load64 (st+32) t == 0 && load64 (st+200) t == 1
def advertisedHead (t : UInt64) : UInt64 :=
  if metadataOnly t then Guest.ForgeFederation.localDescriptor+320 else offeredHead
def sendMetadata (t : UInt64) : UInt64 :=
    let only := metadataOnly t
    let head := advertisedHead t
    let t := packetHeader 2 0 (if only then 0 else load64 (st+40) t)
      (if only then 0 else load64 (st+48) t) (if only then 24 else load64 (st+480) t) (if only then 2 else 3) head t
    let t := copy (if only then Guest.ForgeFederation.catalogName else offeredName) (packet+96) 64 t
    let t := copy (if only then Guest.ForgeFederation.localDescriptor+64 else logical) (packet+160) 32 t
    let t := sendPacket (load64 (st+8) t) 192 t
    if load64 (st+80) t != 0 && Guest.ForgeFederation.ready head t then
      store64 (Guest.ForgeFederation.st+32) 2 t else t
def advertise (t : UInt64) : UInt64 :=
  let t := prepare t
  if load64 (st+136) t != 4 then t else sendMetadata t
def discovery (t : UInt64) : UInt64 :=
  let t := zero selectedRoot 16 t
  sendPacket (load64 (st+8) t) 96 (packetHeader 1 0 0 0 0 0 selectedRoot t)
partial def hexName (p i t : UInt64) : UInt64 :=
  if i == 16 then t else
    let c := load8 (remoteHead+i/2) t
    let d := if i%2 == 0 then c >>> 4 else c &&& 15
    hexName p (i+1) (store8 (p+i) (if d < 10 then d+48 else d+87) t)
def fetch (t : UInt64) : UInt64 :=
  if load64 (st+448) t == 2 then message 15 t else
  let t := Guest.ForgeFederation.refreshAuthorization remoteHead t
  let upload := load64 (st+200) t == 1 && load64 (Guest.ForgeFederation.st+208) t == 1 &&
    equal (Guest.ForgeFederation.st+224) remoteHead 32 t
  if !Guest.ForgeFederation.mayFetch t && !upload && Guest.RemoteIngest.phase t != 10 then message 14 t else
  if load64 (st+144) t == 0 || load64 (st+80) t != 0 || load64 (st+112) t != 0 then message 2 t else
    let old := load64 (st+16) t
    let t := if old == 0 then t else Guest.NetworkSDK.revoke old t
    let grant := networkGrant remoteHead t
    if grant == error then message 8 grant else
      let t := store64 (st+16) grant grant
      let t := zero selectedRoot 16 t
      -- Preserve the offered alias while separating same-name incoming roots.
      -- The suffix is a display disambiguator; authority remains the fresh cap.
      let nameLength := if load64 (st+160) t > 45 then 45 else load64 (st+160) t
      let t := store64 (selectedRoot+8) (nameLength+17) t
      let t := copy remoteHead (selectedRoot+16) 32 t
      let t := copy remoteName (selectedRoot+48) nameLength t
      let t := store8 (selectedRoot+48+nameLength) 45 t
      let t := hexName (selectedRoot+49+nameLength) 0 t
      let t := copy (selectedRoot+48) importedName (nameLength+17) (zero importedName 8 t)
      let r := importBegin selectedRoot 1 (load64 (st+144) t) (load64 (st+152) t) t
      if r < 64 || status r != 0 then message 3 r else
        let t := Guest.ForgeCache.begin remoteHead r
        let t := store64 (st+112) (result r) t
        let id := load64 (st+96) t+1
        let t := store64 (st+96) id t
        let t := store64 (st+232) id t
        let t := store64 (st+120) 0 t
        let t := store64 (st+432) 0 t
        let t := store64 (st+224) 0 t
        let t := store64 (st+128) 0 t
        let profile := if load64 (st+448) t == 3 then 2 else 0
        let t := store64 (st+464) profile t
        let t := packetHeader 3 id profile 0 0 0 remoteHead t
        message 5 (sendPacket grant 96 t)

def requestFetch (t : UInt64) : UInt64 :=
  if load64 (st+448) t == 2 then message 15 t else
  let upload := load64 (st+200) t == 1 && load64 (Guest.ForgeFederation.st+208) t == 1 &&
    equal (Guest.ForgeFederation.st+224) remoteHead 32 t
  if !Guest.ForgeFederation.mayFetch t && !upload && Guest.RemoteIngest.phase t != 10 then message 14 t else
  if load64 (st+144) t == 0 then message 2 t else
  if load64 (st+112) t != 0 then message 7 t else
  if load64 (st+80) t != 0 then message 7 (store64 (st+176) 1 t) else fetch t

def sender (t : UInt64) : UInt64 :=
  if load64 (st+80) t != 0 then t else
  let phase := load64 (st+56) t
  let ordinal := load64 (st+64) t
  let transaction := load64 (st+104) t
  if phase == 1 then
    let t := packetHeader 4 transaction (load64 (st+40) t) (load64 (st+48) t) 0 0 offeredHead t
    store64 (st+56) 2 (sendPacket (load64 (st+16) t) 96 t)
  else if phase == 2 then
    if ordinal == load64 (st+40) t then
      let t := packetHeader 7 transaction ordinal (load64 (st+48) t) 0 0 offeredHead t
      store64 (st+56) 4 (sendPacket (load64 (st+16) t) 96 t)
    else
      let row := record ordinal
      let t := packetHeader 5 transaction ordinal (load64 (row+16) t) (load64 (row+8) t) (load64 (row+120) t) offeredHead t
      let t := copy (row+24) (packet+96) 96 t
      let t := store64 (st+72) 0 t
      store64 (st+56) (if load64 (st+456) t == 2 then 5 else 3) (sendPacket (load64 (st+16) t) 192 t)
  else if phase == 3 then
    let row := record ordinal
    let offset := load64 (st+72) t
    let total := load64 (row+8) t
    if offset == total then store64 (st+56) 2 (store64 (st+64) (ordinal+1) t) else
      let n := if total-offset > 512 then 512 else total-offset
      let r := read (load64 row t) offset n t
      if r != 64+n || status r != 0 then message 8 (store64 (st+56) 0 r) else
        let t := copy (wire+64) (received+1024) n r
        let t := packetHeader 6 transaction ordinal offset n 0 offeredHead t
        let t := copy (received+1024) (packet+96) n t
        store64 (st+72) (offset+n) (sendPacket (load64 (st+16) t) (96+n) t)
  else t

def failImport (t : UInt64) : UInt64 :=
  let t := store64 (st+352) (load64 wire t) t
  let t := store64 (st+360) (load64 (st+120) t) t
  let t := store64 (st+368) (load64 (st+224) t) t
  let transaction := load64 (st+112) t
  let t := if transaction == 0 then t else importAbort transaction t
  let t := Guest.ForgeCache.abort t
  message 9 (store64 (st+112) 0 t)
def validFrame (length t : UInt64) : Bool :=
  length >= 96 && length <= 720 && load64 received t == magic && load64 (received+8) t == 1
def observeAdmission (t : UInt64) : UInt64 :=
  let phase := Guest.ForgeFederation.remotePhase t
  if phase != 2 && !(phase == 3 && load64 (Guest.ForgeFederation.st+72) t <= 6) then t else
    let t := Guest.ForgeSubscription.observe Guest.ForgeFederation.remote pins (load64 (st+400) t) t
    if Guest.ForgeSubscription.status t != 3 then t else
      store64 (Guest.ForgeFederation.st+56) 3 (store64 (Guest.ForgeFederation.st+72) 9 t)
def accept1 (length transaction a b c t : UInt64) : UInt64 :=
  if length != 96 || load64 (st+80) t != 0 then message 9 t else
  if load64 (st+32) t != 0 then sendMetadata t else
  if load64 (st+200) t != 1 then message 9 t else
    let r := Guest.ForgeFederation.catalog t
    if r == error then message 9 r else sendMetadata r

def accept2 (length transaction a b c t : UInt64) : UInt64 :=
  let mode := load64 (received+56) t
  let sizes := if mode == 2 then a == 0 && b == 0 else a > 0 && a <= 24 && b > 0 && b <= 1048576
  if length != 192 || mode > 3 || !sizes || c == 0 || c > 63 ||
    !Guest.ProjectGraph.validName (received+96) c 63 t then message 9 t else
  if load64 (st+112) t != 0 then message 7 t else
  let t := if equal (received+64) remoteHead 32 t then t else store64 (st+176) 0 t
  let t := Guest.ForgeFederation.metadata (received+64) t
  let t := copy (received+64) remoteHead 32 t
  let t := copy (received+160) remoteLogical 32 t
  let t := copy (received+96) remoteName 64 t
  let t := store64 (st+448) (load64 (received+56) t) t
  let t := store64 (st+144) a t
  let t := store64 (st+152) b t
  message 6 (store64 (st+160) c t)

def accept9 (length transaction a b c t : UInt64) : UInt64 :=
  if length != 608 || load64 (st+160) t == 0 || !equal (received+64) remoteHead 32 t then message 9 t else
  let t := Guest.ForgeFederation.decision (received+96) remoteHead transaction t
  store64 (st+248) 1 t

def accept10 (length transaction a b c t : UInt64) : UInt64 :=
  if length != 352 || load64 (st+160) t == 0 || !equal (received+64) remoteHead 32 t then message 9 t else
  let t := Guest.ForgeFederation.signature (received+96) remoteHead transaction t
  store64 (st+248) 1 (observeAdmission t)

def accept13 (length transaction a b c t : UInt64) : UInt64 :=
  if length != 128 || load64 (st+200) t != 1 || !Guest.ForgeFederation.enabled t ||
    Guest.ProjectGraph.allZero (received+96) 32 t || transaction != load64 (received+96) t then message 9 t else
  let active := load64 (Guest.ForgeFederation.st+208) t
  let same := equal (received+64) (Guest.ForgeFederation.st+224) 32 t && equal (received+96) (Guest.ForgeFederation.st+256) 32 t
  if active > 0 && active < 4 && !same then message 7 t else
  if active == 4 && same && Guest.ForgeFederation.ready localHead t then
    store64 (Guest.ForgeFederation.st+32) 1 t
  else if active > 0 && active < 4 && same then t else
    let t := copy (received+64) (Guest.ForgeFederation.st+224) 32 t
    let t := copy (received+96) (Guest.ForgeFederation.st+256) 32 t
    store64 (Guest.ForgeFederation.st+208) 1 t

def accept3 (length transaction a b c t : UInt64) : UInt64 :=
  if length != 96 || load64 (st+32) t == 0 || !equal (received+64) offeredHead 32 t ||
    load64 (st+56) t != 0 || load64 (st+80) t != 0 then message 9 t else
  let t := store64 (st+456) (if a == 2 then 2 else 0) t
  let t := store64 (st+104) transaction t
  let t := store64 (st+64) 0 t
  message 5 (store64 (st+56) 1 t)

def accept8 (length transaction a b c t : UInt64) : UInt64 :=
  if length != 96 || load64 (st+56) t != 4 || transaction != load64 (st+104) t || !equal (received+64) offeredHead 32 t then message 9 t else
  message 10 (store64 (st+56) 0 t)

def accept12 (length transaction a b c t : UInt64) : UInt64 :=
  if length != 96 || transaction != load64 (st+104) t || !equal (received+64) offeredHead 32 t then t else
    let t := store64 (st+56) 0 t
    let t := copy offeredHead (st+512) 32 t
    store64 (st+424) transaction (store64 (st+416) 2 t)

def accept11 (length transaction a b c t : UInt64) : UInt64 :=
  if length != 96 || transaction != load64 (st+424) t || !equal (received+64) (st+512) 32 t then t else store64 (st+416) 0 t

def accept14 (kind length transaction a b c t : UInt64) : UInt64 :=
  if length != 128 || transaction != load64 (st+104) t || !equal (received+64) offeredHead 32 t || load64 (st+56) t != 5 ||
    a != load64 (st+64) t || !equal (received+96) (record a+24) 32 t then message 9 t else
  if kind == 14 then store64 (st+56) 3 t else
    store64 (st+56) 2 (store64 (st+64) (a+1) t)

def accept4 (length transaction a b c t : UInt64) : UInt64 :=
  if length == 96 && a == load64 (st+144) t && b == load64 (st+152) t then t else failImport t

def accept5 (length transaction a b c t : UInt64) : UInt64 :=
  if length != 192 || a != load64 (st+120) t || load64 (st+224) t != 0 then failImport t else
  let r := importOfferVersion (load64 (st+112) t) a b c (received+96) (load64 (received+56) t) t
  if r != 64 || status r != 0 then failImport r else
    let t := store64 (st+128) c r
    if load64 (st+464) t != 2 then
      if c == 0 then store64 (st+120) (a+1) t else t
    else
      let t := Guest.ForgeCache.offer a b (load64 (received+56) t) c (received+96) t
      if Guest.ForgeCache.active t then t else
        let t := store64 (st+432) 14 t
        let t := store64 (st+440) a t
        if c != 0 then t else
          let t := Guest.ForgeCache.complete a t
          if Guest.ForgeCache.active t then t else store64 (st+120) (a+1) t

def accept6 (length transaction a b c t : UInt64) : UInt64 :=
  if length != 96+c || c == 0 || c > 512 || a != load64 (st+120) t || b != load64 (st+224) t then failImport t else
  let r := importAppend (load64 (st+112) t) a b (received+96) c t
  if r != 64 || status r != 0 then failImport r else
    let offset := b+c
    let t := store64 (st+224) (if offset == load64 (st+128) r then 0 else offset) r
    if offset != load64 (st+128) t then t else
    if load64 (st+464) t != 2 then store64 (st+120) (a+1) t else
      let t := Guest.ForgeCache.complete a t
      if Guest.ForgeCache.active t then t else store64 (st+120) (a+1) t

def accept7 (length transaction a b c t : UInt64) : UInt64 :=
  if length != 96 || a != load64 (st+144) t || a != load64 (st+120) t || load64 (st+224) t != 0 then failImport t else
  let r := importCommit (load64 (st+112) t) t
  if r != 72 || status r != 0 || result r != 1 then failImport r else
    let root := load64 (wire+64) r
    let t := store64 (st+24) root r
    let t := copy remoteHead localHead 32 t
    let t := copy importedName localName 64 t
    let t := store64 (st+168) ((if load64 (st+160) t > 45 then 45 else load64 (st+160) t)+17) t
    let t := store64 (st+112) 0 t
    let t := if load64 (st+200) t == 1 && load64 (Guest.ForgeFederation.st+208) t == 2 && equal remoteHead (Guest.ForgeFederation.st+224) 32 t then
      store64 (Guest.ForgeFederation.st+208) 3 t else t
    let shell := syscall 97 4 0 0 0 t
    let t := delegate root shell 127 shell
    let launcher := syscall 97 1 0 0 0 t
    let t := delegate root launcher 127 launcher
    let t := packetHeader 8 transaction 0 0 0 0 remoteHead t
    message 11 (sendPacket (load64 (st+16) t) 96 t)

def accept16 (length t : UInt64) : UInt64 :=
  if load64 (received+40) t != load64 (st+144) t || load64 (received+48) t != load64 (st+152) t then message 9 t else
    Guest.RemoteIngest.acceptUpload received length (load64 (st+200) t)
      remoteHead remoteLogical (load64 (st+400) t) t

def accept (length t : UInt64) : UInt64 :=
  if !validFrame length t then message 9 t else
  let kind := load64 (received+16) t
  let transaction := load64 (received+24) t
  let a := load64 (received+32) t
  let b := load64 (received+40) t
  let c := load64 (received+48) t
  let t := progress t
  let t := store64 (st+320) kind t
  let t := store64 (st+328) a t
  let t := store64 (st+336) b t
  let t := store64 (st+344) c t
  if kind == 1 then accept1 length transaction a b c t else
  if kind == 2 then accept2 length transaction a b c t else
  if kind == 9 then accept9 length transaction a b c t else
  if kind == 10 then accept10 length transaction a b c t else
  if kind == 13 then accept13 length transaction a b c t else
  if kind == 3 then accept3 length transaction a b c t else
  if kind == 8 then accept8 length transaction a b c t else
  if kind == 12 then accept12 length transaction a b c t else
  if kind == 11 then accept11 length transaction a b c t else
  if kind == 14 || kind == 15 then accept14 kind length transaction a b c t else
  if kind == 16 then accept16 length t else
  if kind == 17 then Guest.RemoteIngest.acceptReady received length t else
  if load64 (st+112) t == 0 || transaction != load64 (st+232) t || !equal (received+64) remoteHead 32 t then message 9 t else
  if kind == 4 then accept4 length transaction a b c t else
  if kind == 5 then accept5 length transaction a b c t else
  if kind == 6 then accept6 length transaction a b c t else
  if kind == 7 then accept7 length transaction a b c t else
  failImport t
def receiveOne (grant t : UInt64) : UInt64 :=
  if grant == 0 then t else
    let r := Guest.NetworkSDK.receive grant t
    if r < 64 || status r != 0 then r else
      let n := load64 (wire+16) r
      if n > 720 || r != n+64 then message 9 r else accept n (copy (wire+64) received n r)
def requestProject (t : UInt64) : UInt64 :=
  let nonce := load64 (st+184) t+1
  let t := store64 (st+184) nonce t
  let t := store64 (st+192) 1 t
  let shell := syscall 97 4 0 0 0 t
  let t := header 3 0 nonce 0 0 0 0 shell
  let r := syscall 30 shell wire 64 1024 t
  if r != 64 || status r != 0 then message 2 (store64 (st+192) 0 r) else r
def projectPortal (t : UInt64) : UInt64 :=
  if load64 (st+192) t == 0 then t else
    let shell := syscall 97 4 0 0 0 t
    let t := header 4 0 (load64 (st+184) shell) 0 0 0 0 shell
    let r := syscall 30 shell wire 64 1024 t
    if r != 64 || status r != 0 then store64 (st+192) 0 r else
      if load64 (wire+16) r != 2 || result r == 0 then r else
        let root := result r
        let t := store64 (st+24) root (store64 (st+192) 0 r)
        let r := describeRoot root t
        if r != 160 || status r != 0 then message 2 r else
          let t := copy (wire+64) localHead 32 r
          let t := copy (wire+96) localName 64 t
          message 1 (store64 (st+168) (load64 (wire+16) t) t)
def configure (length t : UInt64) : UInt64 :=
  if length != 128 || load64 (st+80) t != 0 || load64 (st+112) t != 0 || load64 (st+56) t != 0 || Guest.ForgeArchive.active t ||
    load64 (command+40) t > 1 || (load64 (command+40) t == 1 && (load64 (command+16) t != 2 || load64 (command+32) t == 0)) then error else
    let t := store64 (st+176) 0 (Guest.RemoteIngest.init (Guest.ForgeSubscription.disable t))
    let oldMetadata := load64 (st+8) t
    let oldRoot := load64 (st+16) t
    let t := if oldMetadata == 0 then t else Guest.NetworkSDK.revoke oldMetadata t
    let t := if oldRoot == 0 then t else Guest.NetworkSDK.revoke oldRoot t
    let t := copy (command+64) pins 64 t
    let t := zero (pins+64) 4 t
    let t := store64 (st+200) (load64 (command+16) t) t
    let t := store64 (st+208) (load64 (command+24) t) t
    let t := store64 (st+216) (load64 (command+32) t) t
    let t := store64 (st+280) (load64 (command+40) t) t
    let g := networkGrant (pins+64) t
    if g == error then error else
      let t := store64 (st+8) g g
      let t := store64 st 1 t
      let t := if load64 (st+32) t == 0 then t else
        let grant := networkGrant offeredHead t
        if grant == error then store64 (st+16) 0 grant else store64 (st+16) grant grant
      let t := if load64 (st+280) t == 1 then Guest.ForgeArchive.inspect (load64 (st+216) t) t else t
      let t := zero wire 8 t
      64+message 0 t
def archiveInspection (t : UInt64) : UInt64 :=
  let t := zero wire 26 t
  let t := store64 (wire+64) (Guest.ForgeArchive.phase t) t
  let t := store64 (wire+72) (Guest.ForgeArchive.progress t) t
  let t := store64 (wire+80) (Guest.ForgeArchive.total t) t
  let t := store64 (wire+88) (Guest.ForgeArchive.code t) t
  let t := store64 (wire+96) (Guest.ForgeArchive.resultRoot t) t
  let t := copy (Guest.ForgeArchive.bundleIndex+32) (wire+104) 32 t
  let t := store64 (wire+136) (load64 (Guest.ForgeArchive.bundleIndex+64) t) t
  208+copy (Guest.ForgeArchive.bundleIndex+72) (wire+144) 64 t
-- Keeping bounded operations separate also avoids inflating the freestanding
-- register frame merely by adding another public inspection operation.
def controlRead (op t : UInt64) : UInt64 :=
  if op == 58 then Guest.ForgeFederation.inspect t else
  if op == 59 then Guest.ForgeFederation.inspectLocal t else
  if op == 60 then Guest.ForgeSubscription.inspect t else
  if op == 63 then Guest.RemoteIngest.inspect t else
  if op == 62 then 144+copy Guest.ForgeCache.st (wire+64) 80 (zero wire 8 t) else
  if op == 56 then 192+copy (st+256) (wire+64) 128 (zero wire 8 t) else
  if op == 55 then archiveInspection t else
  if op == 2 then 320+copy st (wire+64) 256 (zero wire 8 t) else error

def controlAdmin (op n t : UInt64) : UInt64 :=
  if op == 1 then configure (n-32) t else
  if op == 50 && n == 160 then
    let r := Guest.RemoteBuild.configure (load64 (command+16) t) (command+64) (command+96) pins t
    if r == error then error else
      let t := Guest.RemoteIngest.init r
      let t := store64 (st+288) (if load64 (command+24) t == 3 then 3 else 2) t
      64+zero wire 8 t
  else if op == 54 && n == 96 then Guest.RemoteBuild.inspect t else
  if op == 57 && n == 128 then
    let r := Guest.ForgeFederation.configure (load64 (command+16) t) (load64 (command+24) t) (command+64) t
    if r == error then error else 64+zero wire 8 (store64 (st+248) 1 r)
  else if op == 61 && n == 96 then
    if Guest.ForgeArchive.active t || load64 (st+264) t != 0 then error else
      let t := Guest.ForgeArchive.init t
      let t := store64 (st+216) (load64 (command+16) t) t
      64+zero wire 8 (store64 (st+248) 1 t)
  else error

def pollControl (t : UInt64) : UInt64 :=
  let n := syscall 36 (self t) incoming 1024 0 t
  if n < 96 || n > 1024 then n else
    let token := load64 (incoming+8) n
    let op := load64 command n
    let admin := (load64 incoming n &&& 255) == 1
    let r := if op == 1 || op == 50 || op == 54 || op == 57 || op == 61 then
      if admin then controlAdmin op n n else error
      else if n == 96 then controlRead op n else error
    let t := if r == error then store64 wire 1 (zero wire 8 r) else r
    reply token (if r == error then 64 else r) t

def label (id x y color t : UInt64) : UInt64 :=
  if id == 0 then
    let t := store64 (0x414000+0) 2318544865087082310 t
    let t := store64 (0x414000+8) 7598819853104084321 t
    let t := store64 (0x414000+16) 7309377810793259363 t
    let t := store64 (0x414000+24) 8316866959935304293 t
    let t := store64 (0x414000+32) 1701011824 t
    Guest.Raster.text 0x414000 36 x y color 0x101b25 t
  else
  if id == 1 then
    let t := store64 (0x414000+0) 8317989530370060870 t
    let t := store64 (0x414000+8) 7162247809296506981 t
    let t := store64 (0x414000+16) 5557498316454895732 t
    let t := store64 (0x414000+24) 2333274043599385701 t
    let t := store64 (0x414000+32) 521610294641 t
    Guest.Raster.text 0x414000 37 x y color 0x101b25 t
  else
  if id == 2 then
    let t := store64 (0x414000+0) 7596554927462167622 t
    let t := store64 (0x414000+8) 7162249965381642355 t
    let t := store64 (0x414000+16) 8317986209777608052 t
    let t := store64 (0x414000+24) 3838791054734488181 t
    let t := store64 (0x414000+32) 114776363845152 t
    Guest.Raster.text 0x414000 38 x y color 0x101b25 t
  else
  if id == 3 then
    let t := store64 (0x414000+0) 7164770998127129413 t
    let t := store64 (0x414000+8) 2337172631513492581 t
    let t := store64 (0x414000+16) 7809644653794452848 t
    let t := store64 (0x414000+24) 7017488290243240992 t
    let t := store64 (0x414000+32) 6645859 t
    Guest.Raster.text 0x414000 35 x y color 0x101b25 t
  else
  if id == 4 then
    let t := store64 (0x414000+0) 7306080083580904784 t
    let t := store64 (0x414000+8) 64293318521966 t
    Guest.Raster.text 0x414000 14 x y color 0x101b25 t
  else
  if id == 5 then
    let t := store64 (0x414000+0) 2334381286471394643 t
    let t := store64 (0x414000+8) 8751735924676977769 t
    let t := store64 (0x414000+16) 58 t
    Guest.Raster.text 0x414000 17 x y color 0x101b25 t
  else
  if id == 6 then
    let t := store64 (0x414000+0) 7234316346692756819 t
    let t := store64 (0x414000+8) 8223692085114399776 t
    let t := store64 (0x414000+16) 980709231 t
    Guest.Raster.text 0x414000 20 x y color 0x101b25 t
  else
  if id == 7 then
    let t := store64 (0x414000+0) 7863396500148938066 t
    let t := store64 (0x414000+8) 2333274043599385701 t
    let t := store64 (0x414000+16) 7379555244527482152 t
    let t := store64 (0x414000+24) 7593469619724379497 t
    let t := store64 (0x414000+32) 975795053 t
    Guest.Raster.text 0x414000 36 x y color 0x101b25 t
  else
  if id == 8 then
    let t := store64 (0x414000+0) 2338323074193253714 t
    let t := store64 (0x414000+8) 2336349459412426799 t
    let t := store64 (0x414000+16) 2334097638073917808 t
    let t := store64 (0x414000+24) 64267297782114 t
    Guest.Raster.text 0x414000 30 x y color 0x101b25 t
  else
  if id == 9 then
    let t := store64 (0x414000+0) 8243107338930713172 t
    let t := store64 (0x414000+8) 2334116329619288608 t
    let t := store64 (0x414000+16) 8387236764689834031 t
    let t := store64 (0x414000+24) 58 t
    Guest.Raster.text 0x414000 25 x y color 0x101b25 t
  else
  if id == 10 then
    let t := store64 (0x414000+0) 16452496950129747 t
    Guest.Raster.text 0x414000 7 x y color 0x101b25 t
  else
  if id == 11 then
    let t := store64 (0x414000+0) 7310591762041630277 t
    let t := store64 (0x414000+8) 2322568146409627748 t
    let t := store64 (0x414000+16) 8389759083185729125 t
    let t := store64 (0x414000+24) 8746942062486777888 t
    let t := store64 (0x414000+32) 7811882189719500064 t
    let t := store64 (0x414000+40) 1701601889 t
    Guest.Raster.text 0x414000 44 x y color 0x101b25 t
  else
  if id == 12 then
    let t := store64 (0x414000+0) 7022836301648127302 t
    let t := store64 (0x414000+8) 2338324182060001644 t
    let t := store64 (0x414000+16) 4284170527560331107 t
    let t := store64 (0x414000+24) 7812726606361684256 t
    let t := store64 (0x414000+32) 7022923206234235168 t
    let t := store64 (0x414000+40) 8099006088108122220 t
    let t := store64 (0x414000+48) 435744240225 t
    Guest.Raster.text 0x414000 53 x y color 0x101b25 t
  else
  if id == 13 then
    let t := store64 (0x414000+0) 7234316346692756819 t
    let t := store64 (0x414000+8) 8027793262296068896 t
    let t := store64 (0x414000+16) 7238811150377885812 t
    let t := store64 (0x414000+24) 8223699863395660645 t
    let t := store64 (0x414000+32) 2334102031773561957 t
    let t := store64 (0x414000+40) 7954874742130894180 t
    let t := store64 (0x414000+48) 1936025955 t
    Guest.Raster.text 0x414000 52 x y color 0x101b25 t
  else
  if id == 14 then
    let t := store64 (0x414000+0) 6998705298730217299 t
    let t := store64 (0x414000+8) 7306080452725466222 t
    let t := store64 (0x414000+16) 7166187310837752686 t
    let t := store64 (0x414000+24) 7935454085697990508 t
    let t := store64 (0x414000+32) 8104338719502525797 t
    let t := store64 (0x414000+40) 3766733822698416492 t
    Guest.Raster.text 0x414000 48 x y color 0x101b25 t
  else
  if id == 15 then
    let t := store64 (0x414000+0) 8245937404618567759 t
    let t := store64 (0x414000+8) 2319107953102123552 t
    let t := store64 (0x414000+16) 3395847586914791280 t
    let t := store64 (0x414000+24) 2338042715958506272 t
    let t := store64 (0x414000+32) 64271742497383 t
    Guest.Raster.text 0x414000 38 x y color 0x101b25 t
  else
  t

def statusLabel (id x y color t : UInt64) : UInt64 :=
  if id == 15 then
    let t := store64 4276224 4707459271918634317 t
    let t := store64 4276232 2318544951070052128 t
    let t := store64 4276240 5989863728517957699 t
    let t := store64 4276248 4474181 t
    Guest.Raster.text 0x414000 27 x y color 0x101b25 t
  else
  if id == 14 then Guest.ForgeFederation.label 17 x y t else
  if id == 0 then
    let t := store64 (0x414000+0) 7142774401570792786 t
    let t := store64 (0x414000+8) 2333181702055096168 t
    let t := store64 (0x414000+16) 2338603393740665456 t
    let t := store64 (0x414000+24) 7310874250626232943 t
    let t := store64 (0x414000+32) 7233190455505089651 t
    let t := store64 (0x414000+40) 6386785 t
    Guest.Raster.text 0x414000 43 x y color 0x101b25 t
  else
  if id == 1 then
    let t := store64 (0x414000+0) 2338603393740665424 t
    let t := store64 (0x414000+8) 7234316346692756851 t
    let t := store64 (0x414000+16) 7523110824066970656 t
    let t := store64 (0x414000+24) 7234316415681066016 t
    let t := store64 (0x414000+32) 30506450248757280 t
    Guest.Raster.text 0x414000 39 x y color 0x101b25 t
  else
  if id == 2 then
    let t := store64 (0x414000+0) 8511914842195454019 t
    let t := store64 (0x414000+8) 8030604369980910689 t
    let t := store64 (0x414000+16) 8007451953902871914 t
    let t := store64 (0x414000+24) 7957695015158965616 t
    let t := store64 (0x414000+32) 7811882189719500064 t
    let t := store64 (0x414000+40) 1701601889 t
    Guest.Raster.text 0x414000 44 x y color 0x101b25 t
  else
  if id == 3 then
    let t := store64 (0x414000+0) 8462580807739994695 t
    let t := store64 (0x414000+8) 7575180394847368303 t
    let t := store64 (0x414000+16) 2338042707369226349 t
    let t := store64 (0x414000+24) 7234316346692625778 t
    let t := store64 (0x414000+32) 7810121858852353056 t
    let t := store64 (0x414000+40) 435711996783 t
    Guest.Raster.text 0x414000 45 x y color 0x101b25 t
  else
  if id == 4 then
    let t := store64 (0x414000+0) 7810121863046199365 t
    let t := store64 (0x414000+8) 8243311788032357231 t
    let t := store64 (0x414000+16) 7236828443149957743 t
    let t := store64 (0x414000+24) 7234314156275822368 t
    let t := store64 (0x414000+32) 7957413521911673888 t
    let t := store64 (0x414000+40) 32199633692288101 t
    Guest.Raster.text 0x414000 47 x y color 0x101b25 t
  else
  if id == 5 then
    let t := store64 (0x414000+0) 8243107338930713172 t
    let t := store64 (0x414000+8) 7453301734227470624 t
    let t := store64 (0x414000+16) 1936942450 t
    Guest.Raster.text 0x414000 20 x y color 0x101b25 t
  else
  if id == 6 then
    let t := store64 (0x414000+0) 7022344802737087821 t
    let t := store64 (0x414000+8) 7311146929262785056 t
    let t := store64 (0x414000+16) 8675375670380998244 t
    let t := store64 (0x414000+24) 8749496172062272624 t
    let t := store64 (0x414000+32) 8315167063373342240 t
    let t := store64 (0x414000+40) 7019267274303434016 t
    let t := store64 (0x414000+48) 108 t
    Guest.Raster.text 0x414000 49 x y color 0x101b25 t
  else
  if id == 7 then
    let t := store64 (0x414000+0) 2334956330750469456 t
    let t := store64 (0x414000+8) 8316298529456878196 t
    let t := store64 (0x414000+16) 7309940584803690867 t
    let t := store64 (0x414000+24) 7310580662471848564 t
    let t := store64 (0x414000+32) 7308339910637985906 t
    let t := store64 (0x414000+40) 1852795252 t
    Guest.Raster.text 0x414000 44 x y color 0x101b25 t
  else
  if id == 8 then
    let t := store64 (0x414000+0) 7378707224642020688 t
    let t := store64 (0x414000+8) 8675375632251513196 t
    let t := store64 (0x414000+16) 8243593258495797616 t
    let t := store64 (0x414000+24) 2338053340534173281 t
    let t := store64 (0x414000+32) 8245933083814097524 t
    let t := store64 (0x414000+40) 8247617492460380276 t
    let t := store64 (0x414000+48) 101 t
    Guest.Raster.text 0x414000 49 x y color 0x101b25 t
  else
  if id == 9 then
    let t := store64 (0x414000+0) 7234316346692625746 t
    let t := store64 (0x414000+8) 7306916068917079328 t
    let t := store64 (0x414000+16) 8386114176404168763 t
    let t := store64 (0x414000+24) 8390891584407281765 t
    let t := store64 (0x414000+32) 7214878097738593056 t
    let t := store64 (0x414000+40) 7234298818863526761 t
    Guest.Raster.text 0x414000 48 x y color 0x101b25 t
  else
  if id == 10 then
    let t := store64 (0x414000+0) 7957688057596306768 t
    let t := store64 (0x414000+8) 7022836349060409702 t
    let t := store64 (0x414000+16) 2334102057409341804 t
    let t := store64 (0x414000+24) 7310579611546251107 t
    let t := store64 (0x414000+32) 114831880513312 t
    Guest.Raster.text 0x414000 38 x y color 0x101b25 t
  else
  if id == 11 then
    let t := store64 (0x414000+0) 7022836353455191367 t
    let t := store64 (0x414000+8) 2334102057409341804 t
    let t := store64 (0x414000+16) 7885649433053130337 t
    let t := store64 (0x414000+24) 8079591238084420457 t
    let t := store64 (0x414000+32) 7234303221339808373 t
    let t := store64 (0x414000+40) 7234303152804423200 t
    let t := store64 (0x414000+48) 114831880513312 t
    Guest.Raster.text 0x414000 54 x y color 0x101b25 t
  else
  if id == 12 then
    let t := store64 (0x414000+0) 7308335478031147331 t
    let t := store64 (0x414000+8) 7599372963416128356 t
    let t := store64 (0x414000+16) 7089074235350676847 t
    let t := store64 (0x414000+24) 8319396936106927468 t
    let t := store64 (0x414000+32) 8534995790118154272 t
    let t := store64 (0x414000+40) 25701 t
    Guest.Raster.text 0x414000 42 x y color 0x101b25 t
  else
  t

def drawSummary (t : UInt64) : UInt64 :=
  let t := label 0 10 8 0xd8e6ed t
  let t := label 1 10 28 0x9fc6a5 t
  let t := label 2 10 42 0x9fc6a5 t
  let t := label 3 10 56 0x9fc6a5 t
  let t := label 4 10 80 0xd8e6ed t
  let t := Guest.Raster.hex (load64 pins t) 16 140 80 0xd8e6ed 0x101b25 t
  let t := Guest.Raster.hex (load64 (pins+8) t) 16 240 80 0xd8e6ed 0x101b25 t
  let t := Guest.Raster.hex (load64 (pins+16) t) 16 340 80 0xd8e6ed 0x101b25 t
  let t := Guest.Raster.hex (load64 (pins+24) t) 16 440 80 0xd8e6ed 0x101b25 t
  let t := label 5 10 96 0xd8e6ed t
  let t := Guest.Raster.hex (load64 (pins+32) t) 16 140 96 0xd8e6ed 0x101b25 t
  let t := Guest.Raster.hex (load64 (pins+40) t) 16 240 96 0xd8e6ed 0x101b25 t
  let t := Guest.Raster.hex (load64 (pins+48) t) 16 340 96 0xd8e6ed 0x101b25 t
  let t := Guest.Raster.hex (load64 (pins+56) t) 16 440 96 0xd8e6ed 0x101b25 t
  let t := label 6 10 120 0xd8e6ed t
  let t := Guest.Raster.text localName (load64 (st+168) t) 140 120 0xd8e6ed 0x101b25 t
  let t := Guest.Raster.hex (load64 localHead t) 16 10 136 0xd8e6ed 0x101b25 t
  let t := Guest.Raster.hex (load64 (localHead+8) t) 16 112 136 0xd8e6ed 0x101b25 t
  let t := Guest.Raster.hex (load64 (localHead+16) t) 16 214 136 0xd8e6ed 0x101b25 t
  let t := Guest.Raster.hex (load64 (localHead+24) t) 16 316 136 0xd8e6ed 0x101b25 t
  let t := label 7 10 156 0xd8e6ed t
  let t := Guest.Raster.text remoteName (load64 (st+160) t) 270 156 0xd8e6ed 0x101b25 t
  let t := Guest.Raster.hex (load64 remoteHead t) 16 10 172 0xd8e6ed 0x101b25 t
  let t := Guest.Raster.hex (load64 (remoteHead+8) t) 16 112 172 0xd8e6ed 0x101b25 t
  let t := Guest.Raster.hex (load64 (remoteHead+16) t) 16 214 172 0xd8e6ed 0x101b25 t
  let t := Guest.Raster.hex (load64 (remoteHead+24) t) 16 316 172 0xd8e6ed 0x101b25 t
  let t := label 8 10 192 0xd8e6ed t
  let t := Guest.Raster.hex (load64 (st+144) t) 4 220 192 0xd8e6ed 0x101b25 t
  let t := Guest.Raster.hex (load64 (st+152) t) 8 280 192 0xd8e6ed 0x101b25 t
  let t := label 9 10 208 0xd8e6ed t
  let t := Guest.Raster.hex (load64 (st+120) t) 4 220 208 0xd8e6ed 0x101b25 t
  let t := Guest.Raster.hex (load64 (st+224) t) 8 280 208 0xd8e6ed 0x101b25 t
  let t := label 10 10 230 0xd8e6ed t
  let t := statusLabel (load64 (st+136) t) 60 230 0xe9bc75 t
  t

def drawFooter (t : UInt64) : UInt64 :=
  let t := store64 (0x414000+0) 7311156824594462790 t
  let t := store64 (0x414000+8) 2314961767583916146 t
  let t := store64 (0x414000+16) 7309469112732760390 t
  let t := store64 (0x414000+24) 2321964186929755235 t
  let t := store64 (0x414000+32) 32199706694346066 t
  let t := Guest.Raster.text 0x414000 39 10 244 0x9fc6a5 0x101b25 t
  let t := Guest.Raster.hex (Guest.ForgeArchive.phase t) 2 260 244 0xd8e6ed 0x101b25 t
  let t := Guest.Raster.hex (Guest.ForgeArchive.progress t) 8 284 244 0xd8e6ed 0x101b25 t
  let t := Guest.Raster.hex (Guest.ForgeArchive.total t) 8 340 244 0xd8e6ed 0x101b25 t
  let t := Guest.Raster.hex (Guest.ForgeArchive.code t) 2 398 244 0xd8e6ed 0x101b25 t
  let t := if Guest.ForgeArchive.phase t == 4 then
    let t := Guest.Raster.text (Guest.ForgeArchive.bundleIndex+72) (load64 (Guest.ForgeArchive.bundleIndex+64) t) 10 258 0xe9bc75 0x101b25 t
    Guest.Raster.hex (load64 (Guest.ForgeArchive.bundleIndex+32) t) 16 420 258 0xe9bc75 0x101b25 t
    else label 11 10 258 0x9fc6a5 t
  let t := if Guest.ForgeFederation.enabled t then
    let t := Guest.ForgeFederation.label (if Guest.ForgeSubscription.enabled t then 15 else 14) 10 274 t
    Guest.Raster.hex (Guest.ForgeSubscription.status t) 2 350 274 0xe9bc75 0x101b25 t
    else label 12 10 274 0x9fc6a5 t
  let t := if Guest.ForgeFederation.enabled t && load64 Guest.RemoteBuild.st t == 0 then Guest.ForgeFederation.label 12 10 290 t else
    if load64 Guest.RemoteBuild.st t == 0 then label 13 10 290 0x9fc6a5 t else
    let t := store64 (0x414000+0) 8295742064376505682 t
    let t := store64 (0x414000+8) 7599297041066521967 t
    let t := store64 (0x414000+16) 4836930207080409459 t
    let t := store64 (0x414000+24) 7023117823009772880 t
    let t := store64 (0x414000+32) 8007526788302466156 t
    let t := store64 (0x414000+40) 5419016125447959669 t
    let t := store64 (0x414000+48) 3273961234287837801 t
    let t := store64 (0x414000+56) 435459551856 t
    Guest.Raster.text 0x414000 61 10 290 0xe9bc75 0x101b25 t
  let t := if Guest.ForgeFederation.enabled t && load64 Guest.RemoteBuild.st t == 0 then
    let t := Guest.Raster.hex (load64 (Guest.ForgeFederation.st+136) t) 2 10 306 0xe9bc75 0x101b25 t
    let t := Guest.Raster.hex (Guest.ForgeFederation.remotePhase t) 2 70 306 0xe9bc75 0x101b25 t
    let t := Guest.Raster.hex (load64 (Guest.ForgeFederation.st+64) t) 2 130 306 0xe9bc75 0x101b25 t
    Guest.Raster.hex (load64 (Guest.ForgeFederation.st+72) t) 2 190 306 0xe9bc75 0x101b25 t
    else if load64 Guest.RemoteBuild.st t == 0 then label 14 10 306 0x9fc6a5 t else
    let t := store64 (0x414000+0) 7020949574351075142 t
    let t := store64 (0x414000+8) 7305808869231632484 t
    let t := store64 (0x414000+16) 8097788996346060859 t
    let t := store64 (0x414000+24) 5989838517716349552 t
    let t := store64 (0x414000+32) 7286876013273047412 t
    let t := store64 (0x414000+40) 251028009586 t
    Guest.Raster.text 0x414000 45 10 306 0xe9bc75 0x101b25 t
  let t := if load64 Guest.RemoteBuild.st t == 0 then t else
    let t := Guest.Raster.hex (Guest.RemoteBuild.state t) 2 284 306 0xe9bc75 0x101b25 t
    Guest.Raster.hex (load64 (Guest.RemoteBuild.st+112) t) 2 306 306 0xe9bc75 0x101b25 t
  let t := label 15 10 328 0xd8e6ed t
  let t := Guest.Raster.hex (load64 (st+200) t) 2 330 328 0xd8e6ed 0x101b25 t
  let t := Guest.Raster.hex (load64 (st+208) t) 2 360 328 0xd8e6ed 0x101b25 t
  let t := Guest.Raster.hex (load64 (st+216) t) 16 390 328 0xd8e6ed 0x101b25 t
  t

def draw (surface t : UInt64) : UInt64 :=
  if Guest.ForgeFederation.enabled t && load64 (Guest.ForgeFederation.st+128) t == 1 then Guest.ForgeFederation.view surface t else
  let t := Guest.Raster.fill 0 0 640 352 0x101b25 t
  let t := drawSummary t
  let t := drawFooter t
  let t := Guest.ForgeCache.view t
  let t := store64 (st+248) 0 t
  Guest.Raster.upload surface 0 901120 0 t

def cancel (t : UInt64) : UInt64 :=
  let t := Guest.RemoteIngest.stop 5 t
  let rs := Guest.RemoteBuild.state t
  let t := if rs == 1 || rs == 2 || rs == 7 then Guest.RemoteBuild.cancel t else t
  let t := if Guest.ForgeArchive.active t then Guest.ForgeArchive.cancel t else t
  let transaction := load64 (st+112) t
  let t := if transaction == 0 then t else importAbort transaction t
  let t := if transaction == 0 then t else
    let t := copy remoteHead (st+512) 32 t
    store64 (st+424) (load64 (st+232) t) (store64 (st+416) 1 t)
  let t := Guest.ForgeCache.abort t
  let t := store64 (st+112) 0 t
  message 12 (store64 (st+176) 0 (store64 (st+56) 0 t))
def cancellationTick (clock t : UInt64) : UInt64 :=
  let deadline := load64 (st+408) t
  let t := if deadline != 0 && clock >= deadline then
    let t := store64 (st+408) 0 t
    let transaction := load64 (st+112) t
    let t := if transaction == 0 then t else importAbort transaction t
    let t := Guest.ForgeCache.abort t
    message 12 (store64 (st+112) 0 (store64 (st+56) 0 (store64 (st+416) 0 t)))
    else t
  let phase := load64 (st+416) t
  if phase == 0 || load64 (st+80) t != 0 then t else
    let t := packetHeader (if phase == 1 then 12 else 11) (load64 (st+424) t) 0 0 0 0 (st+512) t
    let t := sendPacket (load64 (st+16) t) 96 t
    if load64 (st+80) t == 0 then t else store64 (st+416) 0 t
def cacheTick (t : UInt64) : UInt64 :=
  let transaction := load64 (st+112) t
  if transaction == 0 || load64 (st+464) t != 2 then t else
    let phase := load64 (Guest.ForgeCache.st+32) t
    let r := if phase == 0 then t else Guest.ForgeCache.pump transaction t
    if r == error then failImport r else
    let t := if phase != 0 && !Guest.ForgeCache.active r then
      let ordinal := load64 (Guest.ForgeCache.st+16) r
      let t := store64 (st+120) (ordinal+1) r
      if phase != 2 then t else store64 (st+432) 15 (store64 (st+440) ordinal t)
      else r
    let ack := load64 (st+432) t
    if ack == 0 || load64 (st+80) t != 0 then t else
      let ordinal := load64 (st+440) t
      let t := packetHeader ack (load64 (st+232) t) ordinal 0 0 0 remoteHead t
      let t := copy (Guest.ForgeCache.row ordinal) (packet+96) 32 t
      let t := sendPacket (load64 (st+16) t) 128 t
      if load64 (st+80) t == 0 then t else store64 (st+432) 0 t
def inspectInstall (t : UInt64) : UInt64 :=
  let root := load64 (st+24) t
  if root == 0 || load64 (st+192) t != 0 then message 2 t else
    let r := describeRoot root t
    if r != 160 || status r != 0 then message 2 r else
    let t := copy (wire+64) localHead 32 r
    let t := Guest.ForgeFederation.refreshAuthorization localHead t
    if !Guest.ForgeFederation.mayInstall localHead t then message 14 t else
    let shell := syscall 97 4 0 0 0 t
    let r := delegate root shell 127 shell
    if r != 160 || status r != 0 then message 2 r else
      let t := header 6 (result r) 0 0 0 0 0 r
      let r := syscall 30 shell wire 64 1024 t
      if r != 64 || status r != 0 then message 2 r else r
def archiveSave (t : UInt64) : UInt64 :=
  if load64 (st+216) t == 0 || load64 (st+24) t == 0 || load64 (st+192) t != 0 || Guest.ForgeArchive.active t then message 2 t else
    let r := describeRoot (load64 (st+24) t) t
    if r != 160 || status r != 0 then message 2 r else
    let t := copy (wire+64) localHead 32 r
    let t := copy (wire+96) localName 64 t
    let t := store64 (st+168) (load64 (wire+16) t) t
    let r := freeze (load64 (st+24) t) localHead t
    if r != 160 || status r != 0 then message 3 r else
      let frozen := result r
      let t := store64 (st+264) frozen r
      Guest.ForgeArchive.save frozen (load64 (st+216) t) localName (load64 (st+168) t) localHead t
def archiveRecover (t : UInt64) : UInt64 :=
  if load64 (st+216) t == 0 || Guest.ForgeArchive.active t then message 2 t else
    if Guest.ForgeArchive.phase t == 4 then Guest.ForgeArchive.recover t else
      Guest.ForgeArchive.inspect (load64 (st+216) t) t
def archiveTick (t : UInt64) : UInt64 :=
  let before := Guest.ForgeArchive.phase t
  let previousBytes := Guest.ForgeArchive.progress t
  let t := Guest.ForgeArchive.pump t
  let t := if load64 (st+280) t == 1 && Guest.ForgeArchive.phase t == 4 then Guest.ForgeArchive.recover t else t
  let after := Guest.ForgeArchive.phase t
  let advanced := previousBytes/4096 != Guest.ForgeArchive.progress t/4096
  let t := if before == after && !advanced then t else store64 (st+248) 1 t
  let root := Guest.ForgeArchive.resultRoot t
  let t := if after == 8 && root != 0 && load64 (st+272) t != root then
    let t := store64 (st+24) root (store64 (st+272) root t)
    let r := describeRoot root t
    if r != 160 || status r != 0 then message 2 r else
      let t := copy (wire+64) localHead 32 r
      let t := copy (wire+96) localName 64 t
      let t := message 11 (store64 (st+168) (load64 (wire+16) t) t)
      if load64 (st+280) t == 1 then advertise t else t
    else t
  let frozen := load64 (st+264) t
  if frozen != 0 && (after == 8 || after == 9) then
    let t := remove frozen t
    store64 (st+264) 0 t
  else t
def remoteRequest (t : UInt64) : UInt64 :=
  let state := Guest.RemoteBuild.state t
  if load64 Guest.RemoteBuild.st t != 1 || Guest.RemoteIngest.phase t != 0 || state == 1 || state == 2 || state == 7 then message 2 t else
    let t := prepare t
    if load64 (st+136) t != 4 then t else
      let r := Guest.RemoteBuild.select (load64 (st+32) t) t
      if r == error then message 2 r else
        let r := Guest.NetworkSDK.nonce r
        if r != 96 || status r != 0 then message 8 r else
          let role := if load64 (st+288) r == 3 then 3 else 2
          let r := Guest.RemoteIngest.client (wire+64) role
            (load64 (st+40) r) (load64 (st+48) r) (load64 (st+400) r) r
          if r == error then message 2 r else store64 (st+248) 1 r

def ingestPacket (kind t : UInt64) : UInt64 :=
  let p := Guest.RemoteIngest.st
  let t := packetHeader kind (load64 Guest.RemoteIngest.nonce t) (load64 (p+8) t)
    (load64 (p+24) t) (load64 (p+32) t) 1 Guest.RemoteIngest.root t
  let t := copy Guest.RemoteIngest.nonce (packet+96) 32 t
  sendPacket (load64 (st+8) t) 192 (copy Guest.RemoteIngest.project (packet+128) 64 t)
def ingestSelect (t : UInt64) : UInt64 :=
  let root := load64 (st+24) t
  let r := describeRoot root t
  if r != 160 || status r != 0 || !equal (wire+64) Guest.RemoteIngest.root 32 r then error else
    let r := projectIdentity root r
    if r != 192 || status r != 0 || !equal (wire+160) Guest.RemoteIngest.project 32 r then error else
      let r := Guest.RemoteBuild.select root r
      if r == error then error else store64 Guest.RemoteIngest.st 12 r
def ingestTick (clock t : UInt64) : UInt64 :=
  let p := Guest.RemoteIngest.st
  let phase := Guest.RemoteIngest.phase t
  if phase == 0 then t else
  if Guest.RemoteIngest.expired clock t then cancel (Guest.RemoteIngest.stop 6 t) else
  if phase == 4 then
    let r := Guest.RemoteBuild.request Guest.RemoteIngest.nonce (load64 (p+32) t) (load64 (p+8) t) clock t
    if r == error then message 8 (Guest.RemoteIngest.stop 7 r) else Guest.RemoteIngest.stop 0 r
  else if phase == 11 then
    if load64 (st+112) t != 0 || load64 (st+80) t != 0 then t else
      let r := ingestSelect t
      if r == error then message 9 (Guest.RemoteIngest.stop 7 r) else r
  else if load64 (st+80) t != 0 || load64 (st+56) t != 0 then t else
  if phase == 1 then
    let t := sendMetadata t
    if load64 (st+80) t == 0 then t else store64 p 2 t
  else if phase == 2 || phase == 12 then
    let t := ingestPacket (if phase == 2 then 16 else 17) t
    if load64 (st+80) t == 0 then t else store64 p (if phase == 2 then 3 else 13) t
  else if phase == 10 then
    if !equal remoteHead Guest.RemoteIngest.root 32 t || !equal remoteLogical Guest.RemoteIngest.project 32 t ||
       load64 (st+144) t != load64 (p+24) t || load64 (st+152) t != load64 (p+32) t then
      message 9 (Guest.RemoteIngest.stop 1 t)
    else
      let reused := if load64 (st+24) t == 0 then error else ingestSelect t
      if reused != error then reused else
      let r := requestFetch reused
      if load64 (st+112) r == 0 then Guest.RemoteIngest.stop 7 r else store64 p 11 r
  else t
def remoteTick (clock t : UInt64) : UInt64 :=
  let t := store64 (st+296) clock t
  let role := load64 Guest.RemoteBuild.st t
  if role == 0 then t else
    let root := load64 (st+24) t
    let current := load64 (Guest.RemoteBuild.st+16) t
    let resultRoot := Guest.RemoteBuild.resultRoot t
    let state := Guest.RemoteBuild.state t
    let t := if role >= 2 && Guest.RemoteIngest.phase t == 0 && root != 0 && root != current && root != resultRoot && state != 2 && state != 7 then
      let r := Guest.RemoteBuild.select root t
      if r == error then message 8 r else r
      else t
    let before := Guest.RemoteBuild.state t
    let t := Guest.RemoteBuild.tick clock t
    let after := Guest.RemoteBuild.state t
    let t := if before != after then store64 (st+248) 1 t else t
    let root := Guest.RemoteBuild.resultRoot t
    if role >= 2 && after == 3 && root != 0 && root != load64 (st+304) t && load64 (st+80) t == 0 then
      let t := store64 (st+24) root t
      let t := advertise t
      if load64 (st+136) t == 4 || load64 (st+80) t != 0 then store64 (st+304) root t else t
    else t

def federationPublish (t : UInt64) : UInt64 :=
  if !Guest.ForgeFederation.enabled t then message 2 t else
    let t := prepare t
    if load64 (st+136) t != 4 then t else
    if load64 (st+200) t != 1 then
      let r := Guest.NetworkSDK.nonce t
      if r != 96 || status r != 0 then message 8 r else
        let t := copy (wire+64) (Guest.ForgeFederation.st+256) 32 r
        let t := copy localHead (Guest.ForgeFederation.st+288) 32 t
        let t := store64 (Guest.ForgeFederation.st+192) 1 t
        let t := sendMetadata t
        store64 (Guest.ForgeFederation.st+32) 4 t
    else
      let r := Guest.ForgeFederation.begin (load64 (st+32) t) localHead t
      if r == error then message 14 r else
        let t := store64 (Guest.ForgeFederation.st+128) 1 r
        store64 (st+248) 1 t
def federationTick (t : UInt64) : UInt64 :=
  if !Guest.ForgeFederation.enabled t then t else
    let phase := load64 (Guest.ForgeFederation.st+208) t
    let t := if load64 (st+200) t == 1 && phase == 1 && load64 (st+80) t == 0 && load64 (st+112) t == 0 &&
       load64 (st+144) t > 0 && equal remoteHead (Guest.ForgeFederation.st+224) 32 t then
      let t := requestFetch t
      if load64 (st+112) t == 0 then t else store64 (Guest.ForgeFederation.st+208) 2 t
      else t
    let t := if load64 (st+200) t == 1 && phase == 3 && load64 (st+80) t == 0 then
      let t := prepare t
      if load64 (st+136) t != 4 || !equal localHead (Guest.ForgeFederation.st+224) 32 t then t else
        let r := Guest.ForgeFederation.begin (load64 (st+32) t) localHead t
        if r == error then message 14 r else store64 (Guest.ForgeFederation.st+208) 4 r
      else t
    let before := Guest.ForgeFederation.localPhase t
    let t := Guest.ForgeFederation.poll (advertisedHead t) t
    let t := if before != Guest.ForgeFederation.localPhase t then store64 (st+248) 1 t else t
    if load64 (st+80) t != 0 then t else
    let phase := Guest.ForgeFederation.sendPhase t
    if phase == 4 then
      if !equal localHead (Guest.ForgeFederation.st+288) 32 t then message 14 (store64 (Guest.ForgeFederation.st+32) 0 t) else
        let t := packetHeader 13 (load64 (Guest.ForgeFederation.st+256) t) 0 0 0 0 localHead t
        let t := copy (Guest.ForgeFederation.st+256) (packet+96) 32 t
        let t := sendPacket (load64 (st+8) t) 128 t
        if load64 (st+80) t == 0 then t else store64 (Guest.ForgeFederation.st+32) 0 t
    else if !Guest.ForgeFederation.ready (advertisedHead t) t then t else
    if phase == 1 then sendMetadata t else
    if phase == 2 then
      let t := packetHeader 9 (load64 (Guest.ForgeFederation.st+24) t) 0 0 0 0 (advertisedHead t) t
      let t := copy Guest.ForgeFederation.localDescriptor (packet+96) 512 t
      let t := sendPacket (load64 (st+8) t) 608 t
      if load64 (st+80) t == 0 then t else store64 (Guest.ForgeFederation.st+32) 3 t
    else if phase == 3 then
      let t := packetHeader 10 (load64 (Guest.ForgeFederation.st+24) t) 0 0 0 0 (advertisedHead t) t
      let t := copy (Guest.ForgeFederation.localDescriptor+512) (packet+96) 256 t
      let t := sendPacket (load64 (st+8) t) 352 t
      if load64 (st+80) t == 0 then t else store64 (Guest.ForgeFederation.st+32) 0 t
    else t

def subscribe (t : UInt64) : UInt64 :=
  if !Guest.ForgeSubscription.enabled t && (Guest.ForgeFederation.remotePhase t != 2 || load64 (Guest.ForgeFederation.remote+16) t != 2) then message 14 t else
    let r := Guest.ForgeSubscription.toggle Guest.ForgeFederation.remote pins (load64 (st+400) t) t
    if r == error then message 14 r else store64 (st+248) 1 r
def subscriptionTick (clock t : UInt64) : UInt64 :=
  if !Guest.ForgeSubscription.due clock t || load64 (st+80) t != 0 || load64 (st+112) t != 0 || load64 (st+56) t != 0 then t else
    discovery (Guest.ForgeSubscription.queried clock t)

def key (code value t : UInt64) : UInt64 :=
  if value != 1 then t else
  let t := store64 (st+240) code t
  if Guest.ForgeArchive.active t && code != 1 then t else
  if code == 31 && load64 (Guest.ForgeFederation.st+128) t == 0 then subscribe t else
  if code == 59 && Guest.ForgeFederation.enabled t then
    store64 (st+248) 1 (store64 (Guest.ForgeFederation.st+128) (if load64 (Guest.ForgeFederation.st+128) t == 0 then 1 else 0) t)
  else
  if code == 60 then requestProject t else
  if code == 66 then archiveSave t else
  if code == 67 then archiveRecover t else
  if load64 st t == 0 then message 2 t else
  if code == 61 then discovery t else
  if code == 62 then advertise t else
  if code == 63 then requestFetch t else
  if code == 64 then inspectInstall t else
  if code == 65 then remoteRequest t else
  if code == 68 then
    let r := Guest.RemoteBuild.approve t
    if r == error then message 2 r else store64 (st+248) 1 r
  else
  if code == 87 then federationPublish t else
  if code == 1 then cancel t else t
partial def loop (surface count t : UInt64) : UInt64 :=
  let t := pollControl t
  let t := if count%32 != 0 || load64 st t == 0 then t else
    let t := archiveTick t
    let t := store64 (st+400) count t
    let t := remoteTick count t
    let t := ingestTick count t
    let t := pollSend t
    let t := cancellationTick count t
    let t := cacheTick t
    let t := federationTick t
    let t := subscriptionTick count t
    let t := if load64 (st+176) t == 1 && load64 (st+80) t == 0 then requestFetch (store64 (st+176) 0 t) else t
    let t := projectPortal t
    let t := receiveOne (load64 (st+8) t) t
    let t := if Guest.ForgeCache.active t then t else receiveOne (load64 (st+16) t) t
    sender t
  let t := if count%512 == 0 && (load64 (st+112) t != 0 || load64 (st+56) t != 0) then store64 (st+248) 1 t else t
  let event := if surface == 0 then Guest.Effects.effectValue 0 t else syscall 90 (self t) 0 0 0 t
  let t := if event >>> 48 == 1 then key ((event >>> 32) &&& 65535) (event &&& 0xffffffff) event else event
  let t := if surface != 0 && load64 (st+248) t != 0 then draw surface t else t
  loop surface (count+1) (syscall 9 0 0 0 0 t)
def main (initial : UInt64) : UInt64 :=
  let t := Guest.RemoteIngest.init (Guest.ForgeSubscription.disable (Guest.ForgeArchive.init (Guest.ForgeFederation.init (Guest.ForgeCache.init (zero st 128 initial)))))
  let surface := syscall 80 0 0 0 0 t
  if surface == error then syscall 10 1 0 0 0 surface else loop surface 0 (draw surface surface)
def serverMain (initial : UInt64) : UInt64 := loop 0 0 (Guest.RemoteIngest.init (Guest.ForgeSubscription.disable (Guest.ForgeArchive.init (Guest.ForgeFederation.init (Guest.ForgeCache.init (zero st 128 initial))))))
end Guest.Forge
