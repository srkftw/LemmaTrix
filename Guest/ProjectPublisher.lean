import Guest.ProjectSDK
import Guest.IdentitySDK
import Guest.ReleaseFormat
import Guest.SourceDependencyPolicy
namespace Guest.ProjectPublisher
open Guest.LiveSDK
open Guest.ProjectSDK
def equal (a b n t : UInt64) : Bool := Guest.LiveMemory.equal a b n t
-- Private to the native Launcher coordinator. The compiler transports only
-- inert proposal bytes; this module constructs the authoritative Release node.
def st : UInt64 := 0x6a0000
def candidate : UInt64 := 0x6a1000
def payload : UInt64 := 0x6e0000
def history (i : UInt64) : UInt64 := 0x6d0000+i*128
def h : UInt64 := candidate+64
def creator : UInt64 := st+512
def creatorKey (i : UInt64) : UInt64 := 0x7d1000+i*64
def creatorReply (t : UInt64) : UInt64 :=
  let t := header 0 (load64 creator t) (load64 (creator+8) t) (load64 (creator+16) t)
    (load64 (creator+24) t) (load64 (creator+32) t) (load64 (creator+40) t) t
  let t := store64 (wire+56) (load64 (creator+48) t) t
  let t := copy (creator+64) (wire+64) 64 t
  128+copy wire 0x410000 128 t
partial def selectedCreatorKey (i t : UInt64) : UInt64 :=
  if i == 4 then error else
  if load64 (creatorKey i+32) t != 0 && equal (creatorKey i) (creator+64) 32 t then i else selectedCreatorKey (i+1) t
partial def vacantCreatorKey (i t : UInt64) : UInt64 :=
  if i == 4 then error else if load64 (creatorKey i+32) t == 0 then i else vacantCreatorKey (i+1) t
def creatorPoll (t : UInt64) : UInt64 :=
  if load64 creator t != 1 then creatorReply t else
  let r := syscall 134 (load64 (creator+56) t) wire 1024 0 t
  if r == 0 then creatorReply r else
  if r != 352 || status r != 0 || load64 (wire+80) r != 1 || !equal (wire+128) (creator+64) 32 r then
    creatorReply (store64 creator 4 (store64 (creator+48) 1 r)) else
  let slot := vacantCreatorKey 0 r
  if slot == error then creatorReply (store64 creator 4 (store64 (creator+48) 4 r)) else
  let key := result r
  let t := copy (creator+64) (creatorKey slot) 32 r
  let t := store64 (creatorKey slot+32) key t
  creatorReply (store64 creator 2 (store64 (creator+8) key t))
def response (code t : UInt64) : UInt64 :=
  let t := header code (load64 st t) (load64 (st+8) t) (load64 (st+24) t) (load64 (st+40) t) 0 (load64 (st+56) t) t
  let t := copy h (wire+64) 512 t
  let t := copy (st+160) (wire+576) 32 t
  640+copy (st+128) (wire+608) 32 t
def hash (p n out t : UInt64) : UInt64 := Guest.ServiceHash.sha256At 0x600200 p n out t
partial def readAll (handle dst bytes offset t : UInt64) : UInt64 :=
  if offset == bytes then t else
  let n := if bytes-offset > 512 then 512 else bytes-offset
  let r := read handle offset n t
  if r != 64+n || status r != 0 then error else readAll handle dst bytes (offset+n) (copy (wire+64) (dst+offset) n r)
partial def sourceOrigin (root id fuel t : UInt64) : UInt64 :=
  if fuel == 0 then error else
  let r := resolve root id t
  if r != 128 || status r != 0 || load64 (wire+32) r != 11 then error else
  if load64 (wire+40) r == 2 || Guest.ReleaseFormat.zeros (wire+96) 32 r then result r else
    sourceOrigin root (wire+96) (fuel-1) r
partial def forkScopeMatches (root i count t : UInt64) : Bool :=
  if i == count then false else
  let e := 0x6c0020+i*128
  if load64 e t != 15 then forkScopeMatches root (i+1) count t else
  let r := resolve root (e+16) t
  if r != 128 || status r != 0 || load64 (wire+32) r != 15 || load64 (wire+40) r != 1 ||
    load64 (wire+16) r != 208 then false else
  let r := readAll (result r) 0x6c4000 208 0 r
  r != error && load64 0x6c4020 r == 0x314b524f46544c && load64 0x6c4028 r == 1 &&
    equal 0x6c4030 (st+384) 32 r && equal 0x6c4090 (h+96) 32 r
def adoptForkScope (t : UInt64) : UInt64 :=
  let root := load64 (st+16) t
  let origin := sourceOrigin root (st+160) 64 t
  if origin == error || load64 (wire+40) origin != 2 || load64 (wire+16) origin > 8224 then error else
  let r := readAll origin 0x6c0000 (load64 (wire+16) origin) 0 origin
  let count := load64 0x6c0010 r
  if r == error || count == 0 || count > 32 || !forkScopeMatches root 0 count r then error else
  Guest.IdentitySDK.adoptUnpublishedProject (load64 st r) (st+384) (st+128) r
def buildCall (op job t : UInt64) : UInt64 := syscall 30 5 wire 64 1024 (header op job 0 0 0 0 0 t)
def creatorRequest (length t : UInt64) : UInt64 :=
  if length != 24 || load64 creator t == 1 || load64 creator t == 2 || load64 (st+24) t == 2 then creatorReply t else
  let root := load64 0x410000 t
  let job := load64 0x410008 t
  let requester := load64 0x410010 t
  let nonce := load64 (creator+24) t+1
  let t := zero creator 32 t
  let t := store64 (creator+16) job (store64 (creator+24) nonce (store64 (creator+32) root (store64 (creator+40) requester t)))
  let r := describeRoot root t
  if r != 160 || status r != 0 then creatorReply (store64 creator 4 (store64 (creator+48) 1 r)) else
  let binding := load64 (wire+56) r
  let r := projectIdentity root r
  if r != 192 || status r != 0 then creatorReply (store64 creator 4 (store64 (creator+48) 1 r)) else
  let t := copy (wire+160) (creator+64) 32 r
  let r := buildCall 7 job t
  if r != 256 || status r != 0 || load64 (wire+16) r != 2 || load64 (wire+192) r != binding ||
    load64 (wire+200) r != requester || !equal (wire+160) (creator+64) 32 r then
    creatorReply (store64 creator 4 (store64 (creator+48) 3 r)) else
  let t := copy (wire+64) (creator+96) 32 r
  let selected := selectedCreatorKey 0 t
  if selected != error then creatorReply (store64 creator 2 (store64 (creator+8) (load64 (creatorKey selected+32) t) t)) else
  if vacantCreatorKey 0 t == error then creatorReply (store64 creator 4 (store64 (creator+48) 4 t)) else
  let target := Guest.IdentitySDK.endpoint 400 t
  if target == error then creatorReply (store64 creator 4 (store64 (creator+48) 7 target)) else
  let t := hash (creator+64) 32 (creator+128) target
  let t := copy (creator+128) (wire+64) 32 (header 400 0 1 0 0 0 0 t)
  let t := copy (creator+64) (wire+96) 32 t
  let token := syscall 133 target wire 128 1024 t
  if token == error then creatorReply (store64 creator 4 (store64 (creator+48) 7 token)) else
  creatorReply (store64 creator 1 (store64 (creator+56) token token))
def creatorResult (length t : UInt64) : UInt64 :=
  if length != 16 || load64 creator t != 2 || load64 0x410000 t != load64 (creator+24) t then creatorReply t else
  let failure := load64 0x410008 t
  if failure == 0 && load64 (st+24) t == 1 && load64 st t == load64 (creator+8) t && load64 (st+8) t == load64 (creator+16) t then
    creatorReply (store64 creator 3 t) else creatorReply (store64 creator 4 (store64 (creator+48) (if failure == 0 then 3 else failure) t))
def validJob (t : UInt64) : Bool :=
  let r := buildCall 7 (load64 (st+8) t) t
  r == 256 && status r == 0 && load64 (wire+16) r == 2 &&
    equal (wire+64) (st+160) 32 r && equal (wire+96) (h+192) 32 r &&
    equal (wire+160) (st+128) 32 r && load64 (wire+192) r == load64 (st+64) r &&
    load64 (wire+200) r == load64 (st+72) r && load64 (wire+208) r == load64 (st+72) r &&
    syscall 34 (load64 (st+72) r) 0 0 0 r != error
partial def known (i t : UInt64) : UInt64 :=
  if i == 4 then error else if load64 (history i) t == 1 && equal (history i+8) (h+128) 32 t then i else known (i+1) t
partial def vacant (i t : UInt64) : UInt64 :=
  if i == 4 then error else if load64 (history i) t == 0 then i else vacant (i+1) t
def newer (p q t : UInt64) : Bool :=
  load64 (p+72) t > load64 (q+72) t || (load64 (p+72) t == load64 (q+72) t &&
    (load64 (p+80) t > load64 (q+80) t || (load64 (p+80) t == load64 (q+80) t && load64 (p+88) t > load64 (q+88) t)))
def lineageCurrent (t : UInt64) : Bool :=
  let k := known 0 t
  if k == error then Guest.ReleaseFormat.zeros (h+288) 32 t && vacant 0 t != error else
  let p := history k
  equal (p+40) (h+288) 32 t && newer h p t && equal (p+96) (h+96) 32 t
def makeEntry (p kind id name n t : UInt64) : UInt64 :=
  let t := zero p 16 t
  let t := store64 p kind t
  let t := store64 (p+8) n t
  let t := store64 (p+48) name t
  copy id (p+16) 32 t
partial def appendAll (handle bytes offset t : UInt64) : UInt64 :=
  if offset == bytes then t else
  let n := if bytes-offset > 512 then 512 else bytes-offset
  let r := append handle offset (payload+offset) n t
  if r != 64 || status r != 0 then error else appendAll handle bytes (offset+n) r
def assemble (t : UInt64) : UInt64 :=
  let native := Guest.ReleaseFormat.executable h t
  let count := if native then 4 else 1
  let bytes := 32+count*128+load64 (st+32) t
  let t := zero payload 68 t
  let t := store64 payload 0x31464e4d544c t
  let t := store64 (payload+8) 1 t
  let t := store64 (payload+16) count t
  let t := store64 (payload+24) (load64 (st+32) t) t
  let t := if native then
    let t := makeEntry (payload+32) 12 (st+256) 0x646c697562 5 t
    let t := makeEntry (payload+160) 11 (st+320) 0x65646f63 4 t
    let t := makeEntry (payload+288) 14 (st+288) 0x65636e6564697665 8 t
    makeEntry (payload+416) 11 (st+160) 0x656372756f73 6 t
    else makeEntry (payload+32) 11 (st+160) 0x656372756f73 6 t
  let t := copy candidate (payload+32+count*128) (load64 (st+32) t) t
  let r := stage bytes 13 0 t
  if r != 64 || status r != 0 then error else
  let handle := result r
  let r := appendAll handle bytes 0 r
  if r == error then Guest.Effects.effectValue error (abortStage handle r) else
  let r := stageDigest handle r
  if r != 96 || status r != 0 then Guest.Effects.effectValue error (abortStage handle r) else
  let r := commit handle (wire+64) r
  if r != 96 || status r != 0 then Guest.Effects.effectValue error (abortStage handle r) else Guest.Effects.effectValue handle r
partial def copyPublicationEntries (i count used t : UInt64) : UInt64 :=
  if i == count then Guest.Effects.effectValue used t else
  let e := 0x6c0020+i*128
  let reserved := load64 (e+8) t == 13 && load64 (e+48) t == 3343205160543085938 && load64 (e+56) t == 465558467692
  if reserved && load64 e t != 13 then error else
  if reserved || (load64 e t != 10 && load64 e t != 13 && load64 e t != 15) then copyPublicationEntries (i+1) count used t else
  if used == 31 then error else copyPublicationEntries (i+1) count (used+1) (copy e (payload+32+used*128) 128 t)
partial def nameLess (a an b bn i t : UInt64) : Bool :=
  if i == an then an < bn else if i == bn then false else
  if load8 (a+i) t == load8 (b+i) t then nameLess a an b bn (i+1) t else load8 (a+i) t < load8 (b+i) t
partial def sortPublication (i t : UInt64) : UInt64 :=
  if i == 0 then t else
  let a := payload+32+(i-1)*128
  let b := a+128
  if !nameLess (b+48) (load64 (b+8) t) (a+48) (load64 (a+8) t) 0 t then t else
  let t := copy a 0x6c8000 128 t
  let t := copy b a 128 t
  sortPublication (i-1) (copy 0x6c8000 b 128 t)
partial def publicationName (i t : UInt64) : UInt64 :=
  if i == 16 then t else
  let b := load8 (h+160+i/2) t
  let n := if i%2 == 0 then b/16 else b%16
  publicationName (i+1) (store8 (0x6c810a+i) (if n < 10 then 48+n else 87+n) t)
def publicationReply (code t : UInt64) : UInt64 :=
  let t := header code (load64 (st+88) t) (load64 (st+40) t) 26 0 0 0 t
  let t := copy (st+96) (wire+64) 32 t
  let t := copy 0x6c8100 (wire+96) 32 t
  128+copy wire 0x410000 128 t
def publishSigned (length t : UInt64) : UInt64 :=
  if length != 0 || load64 (st+24) t != 3 then publicationReply 3 t else
  let t := zero 0x6c8100 4 t
  let t := store64 0x6c8100 7307217292035782000 t
  let t := publicationName 0 (store64 0x6c8108 11620 t)
  if load64 (st+88) t != 0 then
    let shell := syscall 97 4 0 0 0 t
    let r := delegate (load64 (st+88) shell) shell 127 shell
    publicationReply (if r == error || status r != 0 then 4 else 0) r
  else
  let r := resolve (load64 (st+16) t) (st+160) t
  if r != 128 || status r != 0 || load64 (wire+16) r > 8224 then publicationReply 1 r else
  let parent := result r
  let r := readAll parent 0x6c0000 (load64 (wire+16) r) 0 r
  let count := load64 0x6c0010 r
  if r == error || count > 32 then publicationReply 2 r else
  let used := copyPublicationEntries 0 count 0 r
  if used == error then publicationReply 2 used else
  let r := nodeMetadata (load64 (st+40) used) used
  if r != 128 || status r != 0 then publicationReply 3 r else
  let t := copy (wire+64) (st+416) 32 r
  let t := makeEntry (payload+32+used*128) 13 (st+416) 3343205160543085938 13 t
  let t := store64 (payload+32+used*128+56) 465558467692 t
  let t := sortPublication used t
  let t := store64 payload 0x31464e4d544c t
  let t := store64 (payload+8) 1 t
  let t := store64 (payload+16) (used+1) t
  let t := store64 (payload+24) 0 t
  let bytes := 32+(used+1)*128
  let r := stage bytes 11 parent t
  if r != 64 || status r != 0 then publicationReply 4 r else
  let handle := result r
  let r := appendAll handle bytes 0 r
  if r == error then publicationReply 4 (abortStage handle r) else
  let r := stageDigest handle r
  if r != 96 || status r != 0 then publicationReply 4 (abortStage handle r) else
  let r := commit handle (wire+64) r
  if r != 96 || status r != 0 then publicationReply 4 (abortStage handle r) else
  let r := nodeMetadata handle r
  if r != 128 || status r != 0 then publicationReply 4 r else
  let t := copy (wire+64) (st+96) 32 r
  let t := zero 0x6c8000 4 t
  let r := publish handle 0 0x6c8000 0x6c8100 26 t
  if r != 64 || status r != 0 then publicationReply 4 r else
  let root := result r
  let t := store64 (st+88) root r
  let shell := syscall 97 4 0 0 0 t
  let r := delegate root shell 127 shell
  publicationReply (if r == error || status r != 0 then 4 else 0) r
def reviewMetadata (length t : UInt64) : UInt64 :=
  let offset := load64 0x410000 t
  let total := load64 (candidate+24) t
  if length != 8 || load64 (st+24) t == 0 || offset > total then publicationReply 2 t else
  let count := if total-offset > 512 then 512 else total-offset
  let t := header 0 total offset count 0 0 0 t
  let t := copy (h+608+offset) (wire+64) count t
  64+count+copy wire 0x410000 (64+count) t
def prepare (length t : UInt64) : UInt64 :=
  if length != 40 || load64 (st+24) t == 2 then response 4 t else
  let root := load64 0x410000 t
  let key := load64 0x410008 t
  let job := load64 0x410010 t
  let proposal := load64 0x410018 t
  let code := load64 0x410020 t
  let t := zero st 64 t
  let t := store64 st key t
  let t := store64 (st+8) job t
  let t := store64 (st+80) code t
  let r := metadata proposal t
  if r != 96 || status r != 0 || load64 (wire+32) r != 10 || load64 (wire+16) r < 672 || load64 (wire+16) r > 49152 then response 2 r else
  let bytes := load64 (wire+16) r
  let r := readAll proposal candidate bytes 0 r
  if r == error then response 2 r else
  let t := store64 (st+32) bytes r
  if load64 candidate t != 0x31544e43524c544c || load64 (candidate+8) t != 1 || load64 (candidate+16) t != 608 ||
    load64 (candidate+56) t != 0 || load64 (h+8) t != 4 || !Guest.ReleaseFormat.validHeader h t ||
    load64 (candidate+24) t > 49152 || load64 (candidate+32) t > 49152 ||
    load64 (candidate+40) t > 49152 || load64 (candidate+48) t > 512 ||
    bytes != 672+load64 (candidate+24) t+load64 (candidate+32) t+load64 (candidate+40) t+load64 (candidate+48) t then response 2 t else
  let r := describeRoot root t
  if r != 160 || status r != 0 then response 1 r else
  let t := store64 (st+64) (load64 (wire+56) r) r
  let t := copy (wire+64) (st+160) 32 t
  let r := projectIdentity root t
  if r != 192 || status r != 0 then response 1 r else
  let t := copy (wire+160) (st+128) 32 r
  let r := if Guest.ReleaseFormat.executable h t then buildCall 7 job t else header 0 0 0 0 0 0 0 t
  let t := if Guest.ReleaseFormat.executable h r then
      if r != 256 || status r != 0 || load64 (wire+16) r != 2 ||
        load64 (wire+192) r != load64 (st+64) r || !equal (wire+160) (st+128) 32 r then error else
      let t := store64 (st+16) (load64 (wire+32) r) r
      let t := store64 (st+72) (load64 (wire+200) t) t
      copy (wire+64) (st+160) 32 t
    else if job != 0 || code != 0 then error else
      let frozen := freeze root (st+160) r
      if frozen != 160 || status frozen != 0 then error else store64 (st+16) (result frozen) frozen
  if t == error || !lineageCurrent t then response 3 t else
  let r := Guest.IdentitySDK.exportPublic key t
  if r != 352 || status r != 0 || load64 (wire+80) r != 1 ||
    load64 (wire+88) r != load64 (h+392) r then response 1 r else
  let r := if equal (wire+128) (st+128) 32 r then r else
    adoptForkScope (copy (wire+128) (st+384) 32 r)
  if r != 352 || status r != 0 || !equal (wire+128) (st+128) 32 r then response 1 r else
  let t := hash (wire+160) 32 (st+192) r
  if !equal (st+192) (h+96) 32 t then response 1 t else
  let t := copy (wire+160) (h+576) 32 t
  let t := zero (h+512) 8 t
  let t := if Guest.ReleaseFormat.executable h t then
    let r := buildCall 6 job t
    if r < 128 || status r != 0 || !equal (wire+64) (st+160) 32 r || !equal (wire+96) (h+192) 32 r then error else
    let build := load64 (wire+48) r
    let evidence := load64 (wire+56) r
    let r := nodeMetadata build r
    if r != 128 || status r != 0 || load64 (wire+32) r != 12 then error else
    let t := copy (wire+64) (st+256) 32 r
    let r := nodeMetadata evidence t
    if r != 128 || status r != 0 || load64 (wire+32) r != 14 then error else
    let t := copy (wire+64) (st+288) 32 r
    let r := nodeMetadata code t
    if r != 128 || status r != 0 || load64 (wire+32) r != 11 then error else copy (wire+64) (st+320) 32 r
    else t
  if t == error then response 1 t else
  let t := Guest.SourceDependencyPolicy.check (load64 (st+16) t) (st+160) (h+608) (load64 (candidate+24) t) t
  if t == error then response 6 t else
  -- Objects hashes the actual code closure and reconstructs source/evidence
  -- metadata before this unsigned, inert candidate can reach native review.
  let unsigned := assemble t
  if unsigned == error then response 5 unsigned else
  let t := releaseReference unsigned unsigned
  let t := hash h 512 (st+224) t
  response 0 (store64 (st+24) 1 t)
def approve (length t : UInt64) : UInt64 :=
  if length != 32 || load64 (st+24) t != 1 || !equal 0x410000 (h+160) 32 t || !lineageCurrent t then response 3 t else
  if Guest.ReleaseFormat.executable h t && !validJob t then response 3 t else
  let r := describeRoot (load64 (st+16) t) t
  if r != 160 || status r != 0 || !equal (wire+64) (st+160) 32 r then response 3 r else
  let t := r
  let t := hash h 512 (st+352) t
  if !equal (st+352) (st+224) 32 t then response 3 t else
  let r := Guest.IdentitySDK.authorize (load64 st t) (self t) 6 512 (st+224) t
  if r != 64 || status r != 0 then response 1 r else
  let permit := result r
  let target := Guest.IdentitySDK.endpoint 402 r
  let t := header 402 permit 0 0 0 0 0 target
  let t := copy h (wire+64) 512 t
  let token := syscall 133 target wire 576 1024 t
  if token == error then response 3 token else
  response 0 (store64 (st+48) token (store64 (st+24) 2 token))
def finish (t : UInt64) : UInt64 :=
  if load64 (st+24) t != 2 then response 0 t else
  let r := syscall 134 (load64 (st+48) t) wire 1024 0 t
  if r == 0 then response 0 r else
  if r != 168 || status r != 0 || load64 (wire+160) r != load64 (h+392) r || !equal (wire+128) (h+576) 32 r then
    response 5 (store64 (st+24) 4 r) else
  let t := copy (wire+64) (h+512) 64 r
  if !Guest.ReleaseFormat.verify h (h+576) t then response 5 (store64 (st+24) 4 t) else
  let signed := assemble t
  if signed == error then response 5 (store64 (st+24) 4 signed) else
  let t := store64 (st+40) signed (store64 (st+24) 3 signed)
  let existing := known 0 t
  let slot := if existing == error then vacant 0 t else existing
  if slot == error then response 4 t else
  let p := history slot
  let t := store64 p 1 t
  let t := copy (h+128) (p+8) 32 t
  let t := copy (h+160) (p+40) 32 t
  let t := copy (h+72) (p+72) 24 t
  response 0 (copy (h+96) (p+96) 32 t)
def cancel (t : UInt64) : UInt64 :=
  let t := if load64 creator t == 1 then syscall 135 (load64 (creator+56) t) 0 0 0 t else t
  let t := store64 creator 0 t
  -- A submitted signing operation may have completed. Reconcile its exact
  -- result; cancellation never promises to undo a committed release.
  if load64 (st+24) t == 2 then finish t else
  if load64 (st+24) t == 3 then response 3 t else response 0 (store64 (st+24) 0 t)
def dispatch (op length t : UInt64) : UInt64 :=
  if op == 186 then creatorRequest length t else
  if op == 187 || op == 188 then creatorPoll t else
  if op == 189 then creatorResult length t else
  if op == 190 then publishSigned length t else
  if op == 191 then reviewMetadata length t else
  let r := if op == 226 then prepare length t else if op == 227 then approve length t else
    if op == 228 && length == 0 then finish t else if op == 229 && length == 0 then cancel t else response 2 t
  r+copy wire 0x410000 r r
end Guest.ProjectPublisher
