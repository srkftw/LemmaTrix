import Guest.FeedEvent
import Guest.FeedPolicy
import Guest.FeedSDK
import Guest.ServerSDK
import Guest.NetworkSDK
import Guest.WaitSDK
import Guest.IdentitySDK
namespace Guest.FeedFederation
open Guest.LiveSDK
-- Fixed index is deliberately separate from immutable content segments. One
-- segment bank and then a small index bank are committed for each publication.
-- Content accepted by an old index remains readable throughout writer work.
def st : UInt64 := 0x633000
def active : UInt64 := 0x640000
def candidate : UInt64 := 0x650000
def stages : UInt64 := 0x700000
def segment : UInt64 := 0x740000
def scratch : UInt64 := 0x6d2000
def hashed : UInt64 := 0x6d3000
def replicaPolicy : UInt64 := 0x784000
def replicaGrantPolicy : UInt64 := 0x784200
def metaBytes : UInt64 := 37888
def segmentBytes : UInt64 := 131072
def magic : UInt64 := 0x3154534646544c
def row (base i : UInt64) : UInt64 := base+512+i*576
def stage (i : UInt64) : UInt64 := stages+i*17408
def eq (a b n t : UInt64) : Bool := Guest.FeedEvent.eq a b n t
def grant (i t : UInt64) : UInt64 := load64 (st+64+i*8) t
def count (t : UInt64) : UInt64 := load64 (active+24) t
def replicaEventBytes (bytes : UInt64) : UInt64 := (bytes+1024+((bytes+511)/512)*288+128*288)*9
def replicaEventWork (bytes : UInt64) : UInt64 := (((bytes+511)/512)+130)*9
def replicaPolicyValid (t : UInt64) : Bool :=
  if load64 (active+240) t == 0 then Guest.FeedEvent.zeroed (active+168) 88 t else
  load64 (active+240) t == 1 && (load64 (active+248) t == 1 || load64 (active+248) t == 2) &&
  load64 (active+200) t > 0 && load64 (active+200) t <= 16777216 &&
  load64 (active+208) t <= load64 (active+200) t && load64 (active+216) t <= load64 (active+200) t &&
  load64 (active+224) t == load64 (active+200) t/64 && load64 (active+232) t <= load64 (active+224) t
def response (code h a b c d t : UInt64) : UInt64 := 64+header code h a b c d 0 t
def current (token t : UInt64) : Bool := syscall 131 token 0 0 0 t == 0
partial def find (id i t : UInt64) : UInt64 :=
  if i == count t then error else if eq id (row active i+32) 32 t then i else find id (i+1) t
partial def freeStage (i t : UInt64) : UInt64 :=
  if i == 4 then error else if load64 (stage i) t == 0 then i else freeStage (i+1) t
partial def stageFor (caller origin h id i t : UInt64) : UInt64 :=
  if i == 4 then error else
  let p := stage i
  if load64 p t != 0 && Guest.FeedPolicy.stageOwned caller origin h (load64 (p+16) t) (load64 (p+24) t) (load64 (p+8) t) && eq (p+64) id 32 t then i else stageFor caller origin h id (i+1) t
partial def pendingFor (caller origin id i t : UInt64) : UInt64 :=
  if i == 4 then error else
  let p := stage i
  if load64 p t >= 1 && load64 p t <= 3 && load64 (p+16) t == caller &&
      load64 (p+24) t == origin && eq (p+64) id 32 t then i
  else pendingFor caller origin id (i+1) t
partial def queued (start offset t : UInt64) : UInt64 :=
  if offset == 4 then error else
  let i := (start+offset)%4
  if load64 (stage i) t == 2 then i else queued start (offset+1) t
-- Finite public admission: no event can expand its signed audience. Replicated
-- private reports and moderation are forbidden even when their author is valid.
def allowedScope (event t : UInt64) : Bool :=
  let body := event+160
  let home := eq (body+112) (active+64) 32 t
  let peer := eq (body+112) (active+96) 32 t && eq (body+144) (active+64) 32 t
  let kind := load64 (body+16) t
  let audience := Guest.FeedEvent.zeroed (body+144) 32 t || eq (body+144) (active+96) 32 t
  Guest.FeedEvent.scopePermits home peer audience true &&
  (home || (kind != 6 && kind != 7 && kind != 8))
partial def authorCheck (event i greatest generation t : UInt64) : UInt64 :=
  if i == count t then
    if load64 (event+32) t < generation then 15 else
    if load64 (event+184) t <= greatest then 12 else 0
  else
  let old := row active i+64
  if eq (event+112) (old+112) 32 t then
    authorCheck event (i+1) (if load64 (old+184) t > greatest then load64 (old+184) t else greatest)
      (if load64 (old+32) t > generation then load64 (old+32) t else generation) t
  else authorCheck event (i+1) greatest generation t

partial def authorUsage (event i records bytes t : UInt64) : UInt64 :=
  if i == count t then (bytes <<< 32) ||| records else
  let p := row active i
  if eq (event+112) (p+176) 32 t then
    authorUsage event (i+1) (records+1) (bytes+load64 (p+24) t) t
  else authorUsage event (i+1) records bytes t
def authorWithinBudget (event t : UInt64) : Bool :=
  let usage := authorUsage event 0 0 0 t
  (usage &&& 0xffffffff) < 16 && (usage >>> 32) <= 262144 &&
  load64 (event+256) t <= (262144 : UInt64)-(usage >>> 32)

def referencesValid (event t : UInt64) : Bool :=
  let kind := load64 (event+176) t
  let parent := if kind == 2 then find (event+192) 0 t else 0
  let target := if kind >= 4 && kind <= 8 then find (event+368) 0 t else 0
  parent != error && target != error &&
  ((kind != 4 && kind != 5 && kind != 7) || eq (event+112) (row active target+176) 32 t) &&
  (kind != 8 || Guest.FeedPolicy.authorizedDecision event (active+64) (active+128) (load64 (active+56) t) t)

def begin (caller origin length t : UInt64) : UInt64 :=
  if length != 544 then response 2 0 0 0 0 0 t else
  let event := command+64
  if !Guest.FeedEvent.valid event t then response 10 0 0 0 0 0 t else
  if !allowedScope event t then response 11 0 0 0 0 0 t else
  let t := Guest.FeedEvent.identity event hashed t
  let old := find hashed 0 t
  if old != error then response 0 (old+1) 2 (load64 (row active old+544) t &&& 1) 0 0 t else
  let pending := pendingFor caller origin hashed 0 t
  if pending != error then
    let p := stage pending
    if load64 p t != 1 then response 6 (load64 (p+8) t) 1 0 0 0 t else
    -- A newly authenticated retry revalidates these exact signed bytes above.
    -- Restart only this still-uncommitted upload, never its authority or quota.
    response 0 (load64 (p+8) t) 1 0 0 0
      (zero (p+1024) 2048 (store64 (p+32) 0 (store64 (p+40) (Guest.WaitSDK.now t+30000) t)))
  else
  let conflict := authorCheck event 0 0 0 t
  if conflict != 0 then response conflict 0 0 0 0 0 t else
  if !referencesValid event t then response 14 0 0 0 0 0 t else
  if !authorWithinBudget event t || count t >= load64 (active+40) t || load64 (event+256) t > load64 (active+48) t-load64 (active+32) t then response 4 0 0 0 0 0 t else
  let slot := freeStage 0 t
  if slot == error then response 6 0 0 0 0 0 t else
  let p := stage slot
  let serial := load64 (st+56) t+1
  if serial == 0 || serial > 0xffffffff then response 4 0 0 0 0 0 t else
  let h := ((self t &&& 0xffffffff) <<< 32) ||| serial
  let t := zero p 2176 (store64 (st+56) serial t)
  let t := store64 p 1 (store64 (p+8) h t)
  let t := store64 (p+16) caller (store64 (p+24) origin t)
  let t := store64 (p+40) (Guest.WaitSDK.now t+30000) t
  let t := copy hashed (p+64) 32 t
  response 0 h 1 0 0 0 (copy event (p+96) 480 t)

def append (caller origin length t : UInt64) : UInt64 :=
  let i := stageFor caller origin (load64 (command+16) t) (command+64) 0 t
  let offset := load64 (command+24) t
  let n := load64 (command+32) t
  if i == error || length < 97 || n == 0 || n > 512 || length != 96+n then response 3 0 0 0 0 0 t else
  let p := stage i
  if load64 p t != 1 || offset != load64 (p+32) t || offset > load64 (p+352) t || n > load64 (p+352) t-offset then response 2 0 0 0 0 0 t else
  let t := copy (command+96) (p+1024+offset) n t
  response 0 (load64 (p+8) t) (offset+n) 0 0 0
    (store64 (p+32) (offset+n) (store64 (p+40) (Guest.WaitSDK.now t+30000) t))

def commit (caller origin length t : UInt64) : UInt64 :=
  let i := stageFor caller origin (load64 (command+16) t) (command+64) 0 t
  if i == error || length != 96 then response 3 0 0 0 0 0 t else
  let p := stage i
  if load64 p t == 2 || load64 p t == 3 then response 6 (load64 (p+8) t) 1 0 0 0 t else
  if load64 p t != 1 || !Guest.FeedEvent.contentValid (p+96) (p+1024) (load64 (p+32) t) t then response 10 0 0 0 0 0 t else
  response 6 (load64 (p+8) t) 1 0 0 0 (store64 p 2 t)

partial def failedStage (id i t : UInt64) : UInt64 :=
  if i == 4 then 0 else
  let p := stage i
  if load64 p t == 5 && eq (p+64) id 32 t then load64 (p+48) t else failedStage id (i+1) t
def publication (id t : UInt64) : UInt64 :=
  let i := find id 0 t
  if i == error then
    let failure := failedStage id 0 t
    response (if failure == 0 then 6 else failure) 0 1 0 0 0 t
  else
  let p := row active i
  response 0 (i+1) (if (load64 (p+544) t &&& 1) == 1 then 3 else 2) (load64 (active+16) t) 0 0 t

partial def decisionFor (id i value t : UInt64) : UInt64 :=
  if i == count t then value else
  let p := row active i+64
  let value := if load64 (p+176) t == 8 && eq (p+368) id 32 t then load64 (p+400) t else value
  decisionFor id (i+1) value t
partial def tombstoned (id i t : UInt64) : Bool :=
  if i == count t then false else
  let p := row active i+64
  (load64 (p+176) t == 5 && eq (p+368) id 32 t) || tombstoned id (i+1) t
partial def timeline (cursor admin t : UInt64) : UInt64 :=
  if cursor >= count t then response 6 0 0 (count t) 0 0 t else
  let p := row active cursor
  let kind := load64 (p+240) t
  if admin == 0 && (kind == 6 || kind == 7) then timeline (cursor+1) admin t else
  let decision := decisionFor (p+32) 0 0 t
  let visible := !tombstoned (p+32) 0 t && Guest.FeedPolicy.visible false decision
  let t := header 0 (cursor+1) (cursor+1) (if (load64 (p+544) t &&& 1) == 1 then 3 else 2)
    (load64 (p+24) t) (if visible then 1 else 0) (load64 (active+16) t) t
  576+copy (p+32) (wire+64) 512 t

def read (length admin t : UInt64) : UInt64 :=
  let i := find (command+64) 0 t
  let offset := load64 (command+24) t
  let n := load64 (command+32) t
  if i == error || length != 96 || n == 0 || n > 512 then response 2 0 0 0 0 0 t else
  let p := row active i
  let kind := load64 (p+240) t
  if admin == 0 && ((kind == 6 || kind == 7) || tombstoned (p+32) 0 t ||
    !Guest.FeedPolicy.visible false (decisionFor (p+32) 0 0 t)) then response 1 0 0 0 0 0 t else
  if offset >= load64 (p+24) t then response 2 0 0 0 0 0 t else
  let n := if n > load64 (p+24) t-offset then load64 (p+24) t-offset else n
  -- Segment offsets and body extents are512 aligned; a read never crosses an
  -- underlying verified4KiB page. Requesters assemble checked bounded chunks.
  let diskOffset := load64 (p+16) t+offset
  if diskOffset%4096+n > 4096 then response 2 0 0 0 0 0 t else
  Guest.ServerSDK.read (grant (load64 (p+8) t+1) t) diskOffset n t

partial def segmentFor (n i t : UInt64) : UInt64 :=
  if i == 7 then error else if n <= segmentBytes-load64 (active+256+i*8) t then i else segmentFor n (i+1) t

def writerFail (reason t : UInt64) : UInt64 :=
  let i := load64 (st+40) t
  let phase := load64 (st+16) t
  let t := if phase == 2 || phase == 3 then
    Guest.ServerSDK.cancel (grant (if phase == 3 then 0 else load64 (st+32) t+1) t) t else t
  let t := if i < 4 then store64 (stage i) 5 (store64 (stage i+48) reason (store64 (stage i+40) (Guest.WaitSDK.now t+30000) t)) else t
  let t := if load64 (st+400) t == 7 then store64 (st+400) 5 (store64 (st+416) reason t) else t
  store64 (st+16) 0 (store64 (st+8) 0 t)
def startWriter (i t : UInt64) : UInt64 :=
  let p := stage i
  let n := (load64 (p+352) t+511)/512*512
  let target := segmentFor n 0 t
  let conflict := authorCheck (p+96) 0 0 0 t
  if target == error || conflict != 0 || !authorWithinBudget (p+96) t || count t >= load64 (active+40) t ||
    load64 (p+352) t > load64 (active+48) t-load64 (active+32) t then
    store64 p 5 (store64 (p+48) (if conflict != 0 then conflict else 4) (store64 (p+40) (Guest.WaitSDK.now t+30000) t))
  else
  let t := zero segment (segmentBytes/8) t
  let t := copy active candidate metaBytes t
  let r := row candidate (count t)
  let offset := load64 (active+256+target*8) t
  let t := store64 r (count t+1) (store64 (r+8) target t)
  let t := store64 (r+16) offset (store64 (r+24) (load64 (p+352) t) t)
  let t := copy (p+64) (r+32) 32 (copy (p+96) (r+64) 480 t)
  let t := store64 (candidate+24) (count t+1) (store64 (candidate+16) (load64 (active+16) t+1) t)
  let t := store64 (candidate+32) (load64 (active+32) t+load64 (p+352) t) t
  let t := store64 (candidate+256+target*8) (offset+n) t
  let t := store64 (st+8) (load64 (p+8) t) (store64 (st+16) 1 t)
  let t := store64 (st+24) 0 (store64 (st+32) target (store64 (st+40) i t))
  store64 p 3 t

def beginBank (which bytes source t : UInt64) : UInt64 :=
  let t := Guest.ServiceHash.sha256At scratch source bytes hashed t
  let r := Guest.ServerSDK.begin (grant which t) bytes hashed t
  if r != 64 || status r != 0 then error else r

def pumpWriter (t : UInt64) : UInt64 :=
  let phase := load64 (st+16) t
  if phase == 0 then
    let i := queued (load64 (st+448) t) 0 t
    if i == error then t else startWriter i (store64 (st+448) ((i+1)%4) t)
  else
  let target := load64 (st+32) t
  let offset := load64 (st+24) t
  let oldBytes := load64 (active+256+target*8) t
  let total := load64 (candidate+256+target*8) t
  let p := stage (load64 (st+40) t)
  if phase == 1 then
    if offset < oldBytes then
      let r := Guest.ServerSDK.read (grant (target+1) t) offset 512 t
      if r != 576 || status r != 0 then writerFail 5 r else
      store64 (st+24) (offset+512) (copy (wire+64) (segment+offset) 512 r)
    else
      let t := copy (p+1024) (segment+oldBytes) (load64 (p+352) t) t
      let r := beginBank (target+1) (if total == 0 then 512 else total) segment t
      if r == error then writerFail 5 r else store64 (st+16) 2 (store64 (st+24) 0 r)
  else if phase == 2 then
    let extent := if total == 0 then 512 else total
    if offset < extent then
      let r := Guest.ServerSDK.append (grant (target+1) t) offset (segment+offset) 512 t
      if r != 64 || status r != 0 then writerFail 5 r else store64 (st+24) (offset+512) r
    else
      let r := Guest.ServerSDK.commit (grant (target+1) t) t
      if r != 64 || status r != 0 then writerFail 5 r else
      let r := beginBank 0 metaBytes candidate r
      if r == error then writerFail 5 r else store64 (st+16) 3 (store64 (st+24) 0 r)
  else if phase == 3 then
    if offset < metaBytes then
      let r := Guest.ServerSDK.append (grant 0 t) offset (candidate+offset) 512 t
      if r != 64 || status r != 0 then writerFail 5 r else store64 (st+24) (offset+512) r
    else
      let r := Guest.ServerSDK.commit (grant 0 t) t
      if r != 64 || status r != 0 then writerFail 5 r else
      let t := copy candidate active metaBytes r
      let t := if load64 (st+40) t < 4 then zero p 2176 t else t
      let t := if load64 (st+400) t == 7 then store64 (st+432) 0 t else t
      store64 (st+16) 0 (store64 (st+8) 0 t)
  else writerFail 5 t

partial def recoverIndex (offset t : UInt64) : UInt64 :=
  if offset == metaBytes then t else
  let r := Guest.ServerSDK.read (grant 0 t) offset 512 t
  if r != 576 || status r != 0 then error else recoverIndex (offset+512) (copy (wire+64) (active+offset) 512 r)
partial def validIndex (i t : UInt64) : Bool :=
  if i == count t then true else
  let p := row active i
  let valid := load64 p t == i+1 && load64 (p+8) t < 7 && load64 (p+24) t <= 16384 &&
  load64 (p+16) t%512 == 0 && load64 (p+16) t <= segmentBytes &&
  load64 (p+24) t <= segmentBytes-load64 (p+16) t &&
  Guest.FeedEvent.valid (p+64) t && allowedScope (p+64) t &&
  (load64 (p+240) t != 8 || Guest.FeedPolicy.authorizedDecision (p+64) (active+64) (active+128) (load64 (active+56) t) t) &&
  load64 (p+544) t <= 3 && load64 (p+568) t <= 9 &&
  (if (load64 (p+544) t &&& 2) == 0 then Guest.FeedEvent.zeroed (p+552) 24 t else
    load64 (p+552) t == replicaEventBytes (load64 (p+24) t) && load64 (p+560) t == replicaEventWork (load64 (p+24) t))
  if !valid then false else
  let t := Guest.FeedEvent.identity (p+64) hashed t
  eq (p+32) hashed 32 t && validIndex (i+1) t

def configure (length t : UInt64) : UInt64 :=
  if length != 256 || load64 (st+16) t != 0 then response 2 0 0 0 0 0 t else
  let t := copy (command+64) (st+64) 64 t
  let r := Guest.ServerSDK.describe (grant 0 t) t
  if r != 576 || status r != 0 then response 1 0 0 0 0 0 r else
  let present := load64 (wire+64) r != 0
  let t := if present then recoverIndex 0 r else zero active (metaBytes/8) r
  if t == error then response 5 0 0 0 0 0 t else
  if present then
    if load64 active t != magic || load64 (active+8) t != 1 || count t > 64 || load64 (active+32) t > load64 (active+48) t ||
      !eq (active+64) (command+128) 96 t || !replicaPolicyValid t || !validIndex 0 t then response 5 0 0 0 0 0 t else
    response 0 (count t) (load64 (active+16) t) 64 4 16384 (store64 st 1 t)
  else
    let maximum := load64 (command+224) t
    let budget := load64 (command+232) t
    let policy := load64 (command+240) t
    if maximum == 0 || maximum > 64 || budget == 0 || budget > 917504 || policy == 0 ||
      !Guest.FeedEvent.nonzero (command+128) 32 t || !Guest.FeedEvent.nonzero (command+160) 32 t || eq (command+128) (command+160) 32 t ||
      !Guest.FeedEvent.nonzero (command+192) 32 t then response 2 0 0 0 0 0 t else
    let t := store64 active magic (store64 (active+8) 1 t)
    let t := store64 (active+40) maximum (store64 (active+48) budget (store64 (active+56) policy t))
    response 0 0 0 64 4 16384 (copy (command+128) (active+64) 96 (store64 st 1 t))

-- One finite native moderator signature consumer. Public commands state the
-- exact target/action/reason; only Identity holds the moderator seed.
def moderatorPublic : UInt64 := 0x782000
def moderationBody : UInt64 := 0x783000
def moderationText : UInt64 := 0x783600
def moderatorPending (t : UInt64) : Bool := load64 (st+400) t != 0

def identityJob (operation length next t : UInt64) : UInt64 :=
  let target := Guest.IdentitySDK.endpoint operation t
  if target == error then error else
  let token := syscall 133 target wire length 1024 t
  if token == error then error else store64 (st+400) next (store64 (st+408) token token)

def moderatorInit (length t : UInt64) : UInt64 :=
  if length != 128 || moderatorPending t || load64 (st+384) t != 0 then response 6 0 0 0 0 0 t else
  let t := copy (command+64) (wire+64) 64 (header 410 0 0 0 0 0 0 t)
  let r := identityJob 410 128 1 t
  if r == error then response 3 0 0 0 0 0 r else response 6 0 0 0 0 0 r
partial def moderatorSequence (i maximum t : UInt64) : UInt64 :=
  if i == count t then maximum else
  let p := row active i
  let n := load64 (p+248) t
  moderatorSequence (i+1) (if eq (p+176) (moderatorPublic+96) 32 t && n > maximum then n else maximum) t

partial def relatedPolicy (kind target i t : UInt64) : UInt64 :=
  if i == count t then error else
  let p := row active i
  if load64 (p+240) t == kind && eq (p+432) target 32 t then i else relatedPolicy kind target (i+1) t
partial def latestDecision (target i latest t : UInt64) : UInt64 :=
  if i == count t then latest else
  let p := row active i
  latestDecision target (i+1) (if load64 (p+240) t == 8 && eq (p+432) target 32 t then i else latest) t

-- Durable operator retry uses exact application scope/content. A repeated
-- decision with the same moderator, policy, target, action and reason returns
-- its original signed event. A new intentional decision needs a new reason or
-- policy version; reconnect never revives a consumed Identity approval.
partial def matchingDecision (target action reason i t : UInt64) : UInt64 :=
  if i == count t then error else
  let p := row active i
  if load64 (p+240) t == 8 && load64 (p+464) t == action &&
      load64 (p+328) t == load64 (active+56) t && eq (p+432) target 32 t &&
      eq (p+288) reason 32 t && eq (p+176) (moderatorPublic+96) 32 t then i
  else matchingDecision target action reason (i+1) t

def moderate (length t : UInt64) : UInt64 :=
  let action := load64 (command+16) t
  let n := length-96
  if moderatorPending t || load64 (st+384) t == 0 || load64 st t != 1 then response 6 0 0 0 0 0 t else
  if load64 (st+432) t != 0 then response 13 0 0 0 0 0 t else
  if length < 97 || length > 608 || action < 1 || action > 3 || find (command+64) 0 t == error ||
    !eq (moderatorPublic+96) (active+128) 32 t || !Guest.FeedEvent.utf8 (command+96) n 0 0 0 0 t then response 2 0 0 0 0 0 t else
  let t := Guest.ServiceHash.sha256At scratch (command+96) n hashed t
  let old := matchingDecision (command+64) action hashed 0 t
  if old != error then
    response 6 0 0 0 0 0 (copy (row active old+32) (moderationBody+512) 32 (store64 (st+400) 4 t))
  else
  let previous := latestDecision (command+64) 0 error t
  let report := relatedPolicy 6 (command+64) 0 t
  let appeal := relatedPolicy 7 (command+64) 0 t
  if report == error || (action != 1 && (previous == error || appeal == error)) then response 14 0 0 0 0 0 t else
  let t := copy (command+96) moderationText n (zero moderationBody 32 t)
  let t := if previous == error then t else copy (row active previous+32) (moderationBody+32) 32 t
  let t := store64 moderationBody Guest.FeedEvent.magic (store64 (moderationBody+8) 1 t)
  let t := store64 (moderationBody+16) 8 (store64 (moderationBody+24) (moderatorSequence 0 0 t+1) t)
  let t := Guest.ServiceHash.sha256At scratch moderationText n (moderationBody+64) t
  let t := store64 (moderationBody+96) n (store64 (moderationBody+104) (load64 (active+56) t) t)
  let t := copy (active+64) (moderationBody+112) 32 (copy (command+64) (moderationBody+208) 32 t)
  let t := store64 (moderationBody+240) action t
  let t := Guest.ServiceHash.sha256At scratch moderationBody 256 hashed t
  let t := copy hashed (wire+64) 32 (header 410 1 (load64 (st+384) t) 0 0 0 0 t)
  let r := identityJob 410 96 2 (store64 (st+424) n t)
  if r == error then response 3 0 0 0 0 0 r else response 6 0 0 0 0 0 r

def moderatorPump (t : UInt64) : UInt64 :=
  let phase := load64 (st+400) t
  if phase == 0 || phase == 4 || phase == 5 || phase == 7 then t else
  let n := syscall 134 (load64 (st+408) t) wire 1024 0 t
  if n == 0 then n else
  if status n != 0 then store64 (st+400) 5 (store64 (st+416) (status n) n) else
  if phase == 1 then
    if n != 352 then store64 (st+400) 5 n else
    let t := store64 (st+384) (load64 (wire+8) n) n
    store64 (st+400) 0 (copy (wire+64) moderatorPublic 256 t)
  else if phase == 2 then
    if n != 64 then store64 (st+400) 5 n else
    let t := copy moderationBody (wire+64) 256 (header 402 (load64 (wire+8) n) 0 0 0 0 0 n)
    let r := identityJob 402 320 3 t
    if r == error then store64 (st+400) 5 r else r
  else if phase == 3 then
    if n != 544 then store64 (st+400) 5 n else
    let t := copy (wire+64) (command+64) 480 n
    let answer := begin (self t) 0 544 t
    if status answer != 0 then store64 (st+400) 5 (store64 (st+416) (status answer) answer) else
    let h := load64 (wire+8) answer
    let t := Guest.FeedEvent.identity (command+64) (moderationBody+512) answer
    let i := stageFor (self t) 0 h (moderationBody+512) 0 t
    if i == error then store64 (st+400) 5 t else
    let p := stage i
    let n := load64 (st+424) t
    let t := copy moderationText (p+1024) n t
    store64 (st+400) 4 (store64 p 2 (store64 (p+32) n t))
  else t

def moderationStatus (t : UInt64) : UInt64 :=
  let phase := load64 (st+400) t
  if phase == 5 then response (if load64 (st+416) t == 0 then 9 else load64 (st+416) t) 0 0 0 0 0 (store64 (st+400) 0 t) else
  if phase == 4 then
    let i := find (moderationBody+512) 0 t
    if i == error then response 6 0 0 0 0 0 t else
    let t := store64 (st+400) 0 t
    96+copy (moderationBody+512) (wire+64) 32 (header 0 (i+1) 2 0 0 0 0 t)
  else if phase != 0 then response 6 0 0 0 0 0 t else
  if load64 (st+384) t == 0 then response 3 0 0 0 0 0 t else
  320+copy moderatorPublic (wire+64) 256 (header 0 (load64 (st+384) t) 0 0 0 0 0 t)

-- Optional operator retention seals the exact moderator key through Identity;
-- only the authenticated ciphertext blob is committed to plaintext server
-- metadata. The unlock credential and raw seed never enter that metadata.
def retainModerator (length t : UInt64) : UInt64 :=
  if length != 96 || load64 (st+384) t == 0 || moderatorPending t || load64 (st+16) t != 0 then response 6 0 0 0 0 0 t else
  let r := Guest.IdentitySDK.sealFeed (load64 (st+384) t) (command+64) t
  if r != 256 || status r != 0 then response 3 0 0 0 0 0 r else
  let t := copy active candidate metaBytes r
  let t := copy (wire+64) (candidate+320) 192 t
  let t := store64 (candidate+16) (load64 (active+16) t+1) t
  let r := beginBank 0 metaBytes candidate t
  if r == error then response 5 0 0 0 0 0 r else
  response 6 0 0 0 0 0 (store64 (st+400) 7 (store64 (st+40) 4 (store64 (st+16) 3 (store64 (st+24) 0 r))))
def recoverModerator (length t : UInt64) : UInt64 :=
  if length != 96 || load64 st t != 1 || load64 (st+384) t != 0 || moderatorPending t then response 6 0 0 0 0 0 t else
  let r := Guest.IdentitySDK.recoverFeed (command+64) (active+128) (active+320) t
  if r != 352 || status r != 0 then response 3 0 0 0 0 0 r else
  let t := store64 (st+384) (load64 (wire+8) r) r
  let t := copy (wire+64) moderatorPublic 256 (store64 (st+432) 1 t)
  -- The fresh generation must itself be retained before restored policy
  -- authority becomes usable. Reusing the old seal would repeat its generation
  -- on every restart. The credential stays only in this live command buffer.
  retainModerator length t

-- A transport allocation is burned durably before Network receives it. Even
-- invalid incoming frames are bounded across restarts; unused old allocations
-- are conservatively lost. Event reservations below separately bound semantic
-- work/retries, rather than pretending Network counters survived a reboot.
-- Cached policy bytes are populated only by an explicit current operator
-- configuration. Mode2 opts into finite rolling grants; mode1 remains manual.
-- The extra flag is hashed, so a retained manual policy cannot silently upgrade.
def replicaPolicyFailure (reason t : UInt64) : UInt64 :=
  let job := load64 (st+144) t
  let t := if job == 0 then t else Guest.NetworkSDK.cancelPeer (load64 (st+136) t) job t
  let t := store64 (st+144) 0 (store64 (st+192) 0 (store64 (st+208) 0 (store64 (st+216) 0 t)))
  store64 (st+464) 0 (store64 (st+312) 2
    (store64 (st+240) reason (store64 (st+160) 6 t)))

def allocateReplication (t : UInt64) : UInt64 :=
  if load64 (st+16) t != 0 then 6 else
  let bytes := load64 (st+456) t
  let mode := if bytes == 128 && load64 (replicaPolicy+120) t == 1 then 2 else 1
  if (bytes != 120 && bytes != 128) || (bytes == 128 && mode != 2) then 2 else
  let t := Guest.ServiceHash.sha256At scratch replicaPolicy bytes hashed t
  let known := load64 (active+240) t != 0
  if known && (!eq hashed (active+168) 32 t || load64 (active+248) t != mode) then 11 else
  let total := load64 (replicaPolicy+96) t
  if total == 0 || total > 16777216 || load64 (replicaPolicy+104) t == 0 || load64 (replicaPolicy+104) t > 65536 ||
      load64 (replicaPolicy+112) t == 0 || load64 (replicaPolicy+112) t > 100000 then 2 else
  let spent := if known then load64 (active+216) t else 0
  if spent >= total then 4 else
  let budget := if total-spent > 1048576 then 1048576 else total-spent
  if !Guest.FeedPolicy.reserveWithin total spent budget then 4 else
  let t := copy active candidate metaBytes t
  let t := if known then t else
    store64 (candidate+200) total (store64 (candidate+224) (total/64)
      (store64 (candidate+240) 1 (store64 (candidate+248) mode (copy hashed (candidate+168) 32 t))))
  let t := store64 (candidate+216) (spent+budget) (store64 (candidate+16) (load64 (active+16) t+1) t)
  let t := store64 (st+304) budget t
  let r := beginBank 0 metaBytes candidate t
  if r == error then 5 else
  Guest.Effects.effectValue 0 (store64 (st+312) 1
    (store64 (st+40) 4 (store64 (st+16) 3 (store64 (st+24) 0 r))))

def configureReplication (length t : UInt64) : UInt64 :=
  let bytes := length-64
  if (bytes != 120 && bytes != 128) || (bytes == 128 && load64 (command+184) t != 1) then response 2 0 0 0 0 0 t else
  let t := Guest.ServiceHash.sha256At scratch (command+64) bytes hashed t
  let known := load64 (active+240) t != 0
  if known && !eq hashed (active+168) 32 t then response 11 0 0 0 0 0 t else
  if load64 (st+312) t != 0 then response 6 0 0 0 0 0 t else
  if load64 (st+128) t != 0 && load64 (st+160) t != 6 then response 0 (load64 (st+128) t) 0 0 0 0 t else
  if load64 (st+16) t != 0 then response 6 0 0 0 0 0 t else
  let t := zero (replicaPolicy+120) 1 t
  let t := copy (command+64) replicaPolicy bytes t
  let t := store64 (st+456) bytes (store64 (st+136) (load64 (command+16) t) t)
  let code := allocateReplication t
  if code != 0 then response code 0 0 0 0 0 code else response 6 0 0 0 0 0 code

def replicaPolicyPump (t : UInt64) : UInt64 :=
  if load64 (st+312) t != 1 || load64 (st+16) t != 0 then t else
  -- Failure latches stop automatic allocation. Even a failed grant may have
  -- burned one conservative slice, but it cannot burn the remaining pool.
  let budget := load64 (st+304) t
  if load64 (active+216) t != load64 (candidate+216) t || !eq (active+168) (candidate+168) 32 t then
    replicaPolicyFailure 5 t
  else
  let oldJob := load64 (st+144) t
  let t := if oldJob == 0 then t else Guest.NetworkSDK.cancelPeer (load64 (st+136) t) oldJob t
  let t := store64 (st+144) 0 t
  let t := store64 replicaGrantPolicy 3 (store64 (replicaGrantPolicy+8) 3 t)
  let t := store64 (replicaGrantPolicy+16) budget (store64 (replicaGrantPolicy+24) (load64 (replicaPolicy+104) t) t)
  let t := store64 (replicaGrantPolicy+32) (load64 (replicaPolicy+112) t)
    (store64 (replicaGrantPolicy+40) 3 (store64 (replicaGrantPolicy+48) 1 t))
  let r := Guest.NetworkSDK.grantPeer (load64 (st+136) t) replicaPolicy replicaGrantPolicy t
  if r != 64 || status r != 0 then replicaPolicyFailure 3 r else
  store64 (st+128) (load64 (wire+8) r) (store64 (st+312) 0
    (store64 (st+464) (if load64 (active+248) r == 2 then 1 else 0)
      (store64 (st+272) 0 (store64 (st+296) 0 (zero (st+144) 16 r)))))

def replicaAutoRenew (t : UInt64) : UInt64 :=
  if load64 (st+464) t != 1 || load64 (active+248) t != 2 || load64 (st+456) t != 128 ||
      load64 (st+160) t != 6 || load64 (st+240) t != 3 || load64 (st+312) t != 0 || load64 (st+16) t != 0 then t else
  let code := allocateReplication t
  if code == 0 || code == 6 then code else replicaPolicyFailure code code

def dispatch (caller rights token length t : UInt64) : UInt64 :=
  let op := load64 command t
  let action := load64 (command+8) t
  let admin := (rights &&& 0x100000000) != 0
  -- The kernel sends the current process incarnation, not a bare slot.  The
  -- exact incarnation remains part of stageOwned; only Network's protected
  -- terminal dispatch can supply a transport origin for its built-in slot.
  let networkCaller := (caller &&& 255) == 6
  let origin := if networkCaller then load64 (command+48) t else 0
  if length < 64 || length > 960 || load64 (command+56) t != 1 || !current token t then response 2 0 0 0 0 0 t else
  if op == 490 then
    if !admin then response 1 0 0 0 0 0 t else
    if action == 0 then configure length t else
    if action == 4 then moderatorInit length t else
    if action == 5 then moderate length t else
    if action == 6 && length == 64 then
      if load64 (st+400) t == 7 then
        if load64 (st+16) t != 0 then response 6 0 0 0 0 0 t else response 0 0 1 0 0 0 (store64 (st+400) 0 t)
      else moderationStatus t
    else if action == 7 then retainModerator length t else
    if action == 8 then recoverModerator length t else
    if action == 9 && length == 64 then
      let t := header 0 (count t) (load64 (active+32) t) (load64 (active+40) t)
        (load64 (active+48) t) (load64 (active+56) t) (load64 (active+16) t) t
      160+copy (active+64) (wire+64) 96 t
    else if action == 10 then read length 1 t
    else if action == 1 && length == 64 then timeline (load64 (command+16) t) 1 t else
    if action == 2 && (length == 184 || length == 192) && load64 (command+16) t < 4 then
      if load64 (st+312) t == 2 then response (load64 (st+240) t) 0 0 0 0 0 (store64 (st+312) 0 t)
      else configureReplication length t
    else if action == 3 && length == 64 then
      response 0 (load64 (st+160) t) (load64 (st+152) t) (load64 (st+240) t)
        (load64 (active+160) t) (load64 (st+192) t) t
    else if action == 12 && length == 64 then
      let t := header 0 (load64 (active+200) t) (load64 (active+208) t) (load64 (active+216) t)
        (load64 (active+224) t) (load64 (active+232) t) (load64 (active+240) t) t
      96+copy (active+168) (wire+64) 32 t
    else if action == 13 && length == 64 then
      64+header 0 (load64 (active+248) t) (load64 (st+464) t) (load64 (st+312) t)
        (load64 (st+240) t) (load64 (st+456) t) (load64 (st+128) t) t
    else if action == 14 && length == 64 && load64 (command+16) t < count t then
      let p := row active (load64 (command+16) t)
      let t := header 0 (load64 (command+16) t+1) (load64 (p+544) t) (load64 (p+568) t)
        (load64 (p+552) t) (load64 (p+560) t) 0 t
      96+copy (p+32) (wire+64) 32 t
    else response 2 0 0 0 0 0 t
  else if op != 491 then response 7 0 0 0 0 0 t else
  if load64 st t != 1 then response 9 0 0 0 0 0 t else
  if networkCaller && origin == 0 then response 3 0 0 0 0 0 t else
  if action == 1 then begin caller origin length t else
  if action == 2 then append caller origin length t else
  if action == 3 then commit caller origin length t else
  if action == 4 && length == 96 then publication (command+64) t else
  if action == 5 && length == 64 then timeline (load64 (command+16) t) 0 t else
  if action == 6 then read length 0 t else
  if action == 7 && length == 96 then
    let i := stageFor caller origin (load64 (command+16) t) (command+64) 0 t
    if i == error then response 3 0 0 0 0 0 t else
    if load64 (stage i) t == 3 then response 6 0 0 0 0 0 t else response 0 0 0 0 0 0 (zero (stage i) 2176 t)
  else if action == 8 && length == 64 then response 0 (count t) (load64 (active+32) t) (load64 (active+40) t) (load64 (active+48) t) (load64 (st+16) t) t
  else response 2 0 0 0 0 0 t

-- Authenticated mode3 inter-operator replication has its own explicit grant.
-- It never satisfies a mode1 client request. The operator must configure an
-- independent approved peer context and grant operation3, finite byte/work
-- limits, and disclose this bulk relationship to participating authors.
def replicaMagic : UInt64 := 0x315250464c54
def replicaOut : UInt64 := 0x780000
def replicaAnswer : UInt64 := 0x780400
def replicaIn : UInt64 := 0x780800
partial def replicable (i t : UInt64) : UInt64 :=
  if i >= count t then error else
  let p := row active i
  if (load64 (p+544) t &&& 1) == 0 && eq (p+368) (active+96) 32 t &&
    eq (p+112) (active+64) 32 t && load64 (p+240) t != 6 && load64 (p+240) t != 7 && load64 (p+240) t != 8
  then i else replicable (i+1) t

def replicaFrame (p kind request bytes t : UInt64) : UInt64 :=
  let t := zero p 8 t
  let t := store64 p replicaMagic (store64 (p+8) kind t)
  store64 (p+16) request (store64 (p+24) bytes t)
def replicaQueue (bytes t : UInt64) : UInt64 :=
  let serial := load64 (st+184) t+1
  let t := replicaFrame replicaOut 1 serial bytes t
  let t := store64 (st+184) serial (store64 (st+192) serial t)
  store64 (st+216) (64+bytes) t

-- Link failure retries the immutable application event, not an old IPC job or
-- terminal grant. This allowance belongs to the whole event and is reset only
-- when a different committed row starts replication.
def replicaRetry (reason t : UInt64) : UInt64 :=
  let attempts := load64 (row active (load64 (st+152) t)+568) t
  let t := store64 (st+192) 0 (store64 (st+216) 0 (store64 (st+144) 0 t))
  if attempts >= 9 then store64 (st+240) reason (store64 (st+160) 6 t) else
  let t := store64 (st+296) 0 t
  let t := store64 (st+264) (Guest.WaitSDK.now t+500*attempts) t
  store64 (st+160) 1 (store64 (st+168) 0 (store64 (st+176) 0 t))

def reserveReplicaAttempt (t : UInt64) : UInt64 :=
  if load64 (st+16) t != 0 then t else
  let i := load64 (st+152) t
  let p := row active i
  let attempts := load64 (p+568) t
  let first := (load64 (p+544) t &&& 2) == 0
  let bytes := replicaEventBytes (load64 (p+24) t)
  let work := replicaEventWork (load64 (p+24) t)
  if (load64 (active+248) t != 1 && load64 (active+248) t != 2) || attempts >= 9 ||
      (first && (!Guest.FeedPolicy.reserveWithin (load64 (active+200) t) (load64 (active+208) t) bytes ||
        !Guest.FeedPolicy.reserveWithin (load64 (active+224) t) (load64 (active+232) t) work)) then
    store64 (st+240) 4 (store64 (st+160) 6 t)
  else
  let t := copy active candidate metaBytes t
  let c := row candidate i
  let t := if first then
    store64 (c+544) (load64 (c+544) t ||| 2) (store64 (c+552) bytes (store64 (c+560) work
      (store64 (candidate+208) (load64 (active+208) t+bytes)
        (store64 (candidate+232) (load64 (active+232) t+work) t)))) else t
  let t := store64 (c+568) (attempts+1) (store64 (candidate+16) (load64 (active+16) t+1) t)
  let r := beginBank 0 metaBytes candidate t
  if r == error then store64 (st+240) 5 (store64 (st+160) 6 r) else
  store64 (st+304) (attempts+1) (store64 (st+160) 8
    (store64 (st+40) 4 (store64 (st+16) 3 (store64 (st+24) 0 r))))

def replicaResponse (length t : UInt64) : UInt64 :=
  let action := load64 (command+8) t
  let origin := load64 (st+128) t
  if length < 64 || length > 608 || load64 command t != 491 || load64 (command+56) t != 1 then response 2 0 0 0 0 0 t else
  if action == 1 then begin (self t) origin length t else
  if action == 2 then append (self t) origin length t else
  if action == 3 then commit (self t) origin length t else
  if action == 4 && length == 96 then publication (command+64) t else
  response 7 0 0 0 0 0 t

def replicaReceive (t : UInt64) : UInt64 :=
  if load64 (st+208) t != 0 then t else
  let n := Guest.NetworkSDK.receivePeer (load64 (st+136) t) (load64 (st+128) t) t
  if n == 64 && status n == 3 then
    if load64 (st+160) n == 6 && load64 (st+240) n != 3 then n else
    store64 (st+240) 3 (store64 (st+160) 6 n) else
  if n < 128 || n > 768 || status n != 0 then n else
  let bytes := load64 (wire+16) n
  let t := copy (wire+64) replicaIn bytes n
  let size := load64 (replicaIn+24) t
  let request := load64 (replicaIn+16) t
  if load64 replicaIn t != replicaMagic || size+64 != bytes || size < 64 || size > 608 then t else
  if load64 (replicaIn+8) t == 1 then
    let t := copy (replicaIn+64) command size t
    let answer := replicaResponse size t
    let t := copy wire (replicaAnswer+64) answer answer
    let t := replicaFrame replicaAnswer 2 request answer t
    store64 (st+208) (answer+64) t
  else if load64 (replicaIn+8) t != 2 || request != load64 (st+192) t then t else
  let phase := load64 (st+160) t
  let code := load64 (replicaIn+64) t
  let t := store64 (st+192) 0 t
  if code == 3 && phase >= 2 && phase <= 4 then replicaRetry 3 t else
  if code != 0 && code != 6 then store64 (st+240) code (store64 (st+160) 6 t) else
  if phase == 1 then
    if code == 6 then
      if load64 (replicaIn+72) t == 0 then replicaRetry 4 t else store64 (st+160) 4 t
    else
    let t := store64 (st+176) (load64 (replicaIn+72) t) (store64 (st+168) 0 t)
    store64 (st+160) (if load64 (replicaIn+80) t == 2 then 5 else 2) t
  else if phase == 2 then
    if code == 6 then t else store64 (st+168) (load64 (replicaIn+80) t) t
  else if phase == 3 then store64 (st+160) (if code == 0 then 5 else 4) t
  else if phase == 4 then store64 (st+160) (if code == 0 then 5 else 4) t
  else t

def replicaPrepare (t : UInt64) : UInt64 :=
  if load64 (st+192) t != 0 || load64 (st+216) t != 0 then t else
  let phase := load64 (st+160) t
  if phase == 6 || Guest.WaitSDK.now t < load64 (st+264) t then t else
  if phase == 0 then
    let i := replicable 0 t
    if i == error then t else
    let t := if load64 (st+272) t == i+1 then t else store64 (st+296) 0 t
    store64 (st+152) i (store64 (st+272) (i+1) (store64 (st+160) 1 (store64 (st+240) 0 t)))
  else
  let p := row active (load64 (st+152) t)
  if phase == 1 then
    if load64 (st+296) t == 0 then reserveReplicaAttempt t else
    replicaQueue 544 (Guest.FeedSDK.begin (replicaOut+64) (p+64) t)
  else if phase == 2 then
    let offset := load64 (st+168) t
    let total := load64 (p+24) t
    if offset == total then store64 (st+160) 3 t else
    let n := if total-offset > 512 then 512 else total-offset
    let r := Guest.ServerSDK.read (grant (load64 (p+8) t+1) t) (load64 (p+16) t+offset) n t
    if r != 64+n || status r != 0 then store64 (st+240) 5 (store64 (st+160) 6 r) else
    let t := Guest.FeedSDK.append (replicaOut+64) (load64 (st+176) r) (p+32) offset (wire+64) n r
    replicaQueue (96+n) t
  else if phase == 3 then
    replicaQueue 96 (Guest.FeedSDK.commit (replicaOut+64) (load64 (st+176) t) (p+32) t)
  else if phase == 4 then
    if load64 (st+288) t >= 128 then replicaRetry 16 t else
    replicaQueue 96 (Guest.FeedSDK.poll (replicaOut+64) (p+32) (store64 (st+288) (load64 (st+288) t+1) t))
  else if phase == 5 && load64 (st+16) t == 0 then
    let t := copy active candidate metaBytes t
    let r := row candidate (load64 (st+152) t)
    let t := store64 (r+544) (load64 (r+544) t ||| 1) t
    let t := store64 (candidate+160) (load64 (st+152) t+1) (store64 (candidate+16) (load64 (active+16) t+1) t)
    let r := beginBank 0 metaBytes candidate t
    if r == error then store64 (st+240) 5 r else
    let t := store64 (st+40) 4 (store64 (st+16) 3 (store64 (st+24) 0 r))
    store64 (st+160) 7 t
  else if phase == 7 && load64 (st+16) t == 0 then
    if (load64 (p+544) t &&& 1) == 1 then store64 (st+160) 0 t else replicaRetry 5 t
  else if phase == 8 && load64 (st+16) t == 0 then
    if load64 (p+568) t != load64 (st+304) t then store64 (st+240) 5 (store64 (st+160) 6 t) else
    store64 (st+160) 1 (store64 (st+296) 1 (store64 (st+288) 0 t))
  else t

def replicaPump (t : UInt64) : UInt64 :=
  if load64 (st+128) t == 0 then t else
  let job := load64 (st+144) t
  let t := if job == 0 then t else
    let r := Guest.NetworkSDK.pollPeer (load64 (st+136) t) job t
    if r != 64 || status r != 0 then store64 (st+240) 9 (store64 (st+160) 6 (store64 (st+144) 0 r)) else
    if load64 (wire+16) r == 3 then store64 (st+144) 0 r else
    if load64 (wire+16) r >= 4 then
      -- An unacknowledged response may simply be requested again by its peer.
      -- Only failure of our own request restarts our current signed event.
      if load64 (st+280) r == 1 then store64 (st+144) 0 r else replicaRetry 9 r
    else r
  let t := replicaAutoRenew (replicaReceive t)
  let now := Guest.WaitSDK.now t
  let t := if load64 (st+192) now != 0 && load64 (st+216) now == 0 &&
      load64 (st+144) now == 0 && now >= load64 (st+200) now+5000 then
    replicaRetry 16 now
    else now
  let t := replicaPrepare t
  if load64 (st+144) t != 0 then t else
  let responseBytes := load64 (st+208) t
  let requestBytes := load64 (st+216) t
  let bytes := if responseBytes != 0 then responseBytes else requestBytes
  if bytes == 0 then t else
  let r := Guest.NetworkSDK.sendPeer (load64 (st+136) t) (load64 (st+128) t) 3
    (if responseBytes != 0 then load64 (replicaAnswer+16) t else load64 (st+192) t)
    (if responseBytes != 0 then replicaAnswer else replicaOut) bytes t
  if r != 64 then store64 (st+240) 9 (store64 (st+160) 6 r) else
  if status r != 0 then
    if status r == 4 then
      if responseBytes != 0 then store64 (st+208) 0 (store64 (st+240) 4 r)
      else replicaRetry 4 r
    else store64 (st+240) (status r) (store64 (st+160) 6 r)
  else
  let t := store64 (st+280) (if responseBytes != 0 then 1 else 2)
    (store64 (st+144) (load64 (wire+8) r) r)
  if responseBytes != 0 then store64 (st+208) 0 t else store64 (st+216) 0 (store64 (st+200) (Guest.WaitSDK.now t) t)

partial def expire (i now t : UInt64) : UInt64 :=
  if i == 4 then t else
  let p := stage i
  let t := if (load64 p t == 1 || load64 p t == 5) && now >= load64 (p+40) t then zero p 2176 t else t
  expire (i+1) now t
partial def loop (t : UInt64) : UInt64 :=
  let n := syscall 36 (self t) incoming 1024 0 t
  let t := if n >= 96 && n <= 992 then
    let token := load64 (incoming+8) n
    let size := dispatch (load64 incoming n) (load64 (incoming+16) n) token (n-32) n
    reply token size size
  else n
  let t := expire 0 (Guest.WaitSDK.now t) (replicaPump (replicaPolicyPump (moderatorPump (pumpWriter t))))
  let t := zero command 120 (zero wire 128 (zero scratch 80 (zero hashed 4 t)))
  loop (Guest.WaitSDK.deadline (Guest.WaitSDK.now t+(if load64 (st+16) t == 0 then 50 else 1)) t)
def main (t : UInt64) : UInt64 := loop (zero st 128 (zero active (metaBytes/8) (zero stages (69632/8) t)))
end Guest.FeedFederation
