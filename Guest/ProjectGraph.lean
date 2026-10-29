import Guest.LiveSDK
import Guest.ServiceHash
namespace Guest.ProjectGraph
open Guest.LiveSDK
-- Objects owns this private arena. Stable IDs never encode slots or capabilities.
def state : UInt64 := 0xd10000
def rootCaps : UInt64 := 0xd11000
def roots : UInt64 := 0xd13000
def scratch : UInt64 := 0xd16000
def marks : UInt64 := 0xd17000
def rootAt (i : UInt64) : UInt64 := roots+i*192
def rootCapAt (i : UInt64) : UInt64 := rootCaps+i*64
def recordAt (i : UInt64) : UInt64 := 0x610000+i*0x11000
def capAt (i : UInt64) : UInt64 := 0x602000+i*64
partial def equal (a b n t : UInt64) : Bool :=
  if n == 0 then true else load8 a t == load8 b t && equal (a+1) (b+1) (n-1) t
partial def allZero (p n t : UInt64) : Bool :=
  if n == 0 then true else load8 p t == 0 && allZero (p+1) (n-1) t
partial def nameLoop (p n i segment t : UInt64) : Bool :=
  if i == n then segment > 0 && !(segment == 1 && load8 (p+i-1) t == 46) &&
    !(segment == 2 && load8 (p+i-1) t == 46 && load8 (p+i-2) t == 46)
  else
    let c := load8 (p+i) t
    if c == 47 then
      segment > 0 && !(segment == 1 && load8 (p+i-1) t == 46) &&
      !(segment == 2 && load8 (p+i-1) t == 46 && load8 (p+i-2) t == 46) && nameLoop p n (i+1) 0 t
    else c >= 33 && c <= 126 && c != 92 && c != 58 && nameLoop p n (i+1) (segment+1) t

def validName (p n limit t : UInt64) : Bool := n > 0 && n <= limit && nameLoop p n 0 0 t
partial def lessName (a an b bn i t : UInt64) : Bool :=
  if i == an then an < bn else if i == bn then false else
    let x := load8 (a+i) t
    let y := load8 (b+i) t
    if x == y then lessName a an b bn (i+1) t else x < y
partial def findNode (id kind i t : UInt64) : UInt64 :=
  if i == 64 then error else
    let r := recordAt i
    if load64 r t == 2 && load64 (r+224) t == 1 &&
      (kind == 0 || load64 (r+40) t == kind) && equal id (r+160) 32 t then i else findNode id kind (i+1) t
partial def visible (caller i slot t : UInt64) : Bool :=
  if slot == 256 then false else
    let c := capAt slot
    if load64 (c+40) t == 1 && load64 (c+8) t == caller && load64 (c+16) t == i &&
      load64 (c+24) t == load64 (recordAt i+16) t && (load64 (c+32) t &&& 1) == 1 then true
    else visible caller i (slot+1) t
partial def findVisibleNode (caller id kind i t : UInt64) : UInt64 :=
  if i == 64 then error else
    let r := recordAt i
    if load64 r t == 2 && load64 (r+224) t == 1 && load64 (r+40) t == kind &&
      equal id (r+160) 32 t && visible caller i 0 t then i else findVisibleNode caller id kind (i+1) t

-- A logical project is the oldest schema1 Manifest in its validated stable
-- predecessor chain. Named aliases and mutable head capabilities are separate.
-- A malformed or overlong chain fails closed; no lookup here grants a record.
partial def projectOrigin (i fuel t : UInt64) : UInt64 :=
  if i >= 64 || fuel == 0 then error else
    let r := recordAt i
    if load64 r t != 2 || load64 (r+224) t != 1 || load64 (r+40) t != 11 then error else
      if allZero (r+192) 32 t then i else
        let parent := findNode (r+192) 11 0 t
        if parent == error then error else projectOrigin parent (fuel-1) t

-- Resolving a content ID alone never creates authority.
def edgeAllowed (kind child : UInt64) : Bool :=
  if kind == 11 then child == 10 || child == 12 || child == 13 || child == 14 else
  if kind == 12 then child == 11 || child == 14 else
  if kind == 13 then child == 11 || child == 12 || child == 14 else
  kind == 14 && (child == 10 || child == 11)
partial def validateEntries (caller r i count required t : UInt64) : Bool :=
  if i == count then required > 0 || load64 (r+40) t == 14 else
    let e := r+288+i*128
    let kind := load64 e t
    let n := load64 (e+8) t
    let found := findVisibleNode caller (e+16) kind 0 t
    if !edgeAllowed (load64 (r+40) t) kind || !validName (e+48) n 80 t ||
       !allZero (e+48+n) (80-n) t || found == error then false else
    if i > 0 && !lessName (e-128+48) (load64 (e-128+8) t) (e+48) n 0 t then false else
    let required := if (load64 (r+40) t == 11 && kind == 10) ||
      (load64 (r+40) t == 12 && kind == 11) || (load64 (r+40) t == 13 && kind == 12) then required+1 else required
    validateEntries caller r (i+1) count required t

def validPayload (caller r t : UInt64) : Bool :=
  if load64 (r+40) t == 10 then true else
    let p := r+256
    let n := load64 (r+32) t
    let count := load64 (p+16) t
    n >= 32 && load64 p t == 0x31464e4d544c && load64 (p+8) t == 1 && count <= 32 &&
      load64 (p+24) t <= 65536 && n == 32+count*128+load64 (p+24) t && validateEntries caller r 0 count 0 t

-- Release content is inert. These checks bind present material to the signed
-- header commitments; Launcher separately verifies publisher and local authority.
def releaseHash : UInt64 := 0xd16800
def binaryBuffer : UInt64 := 0xd20000

def releaseEdge (r i kind nameWord nameLength t : UInt64) : Bool :=
  let e := r+288+i*128
  load64 e t == kind && load64 (e+8) t == nameLength && load64 (e+48) t == nameWord

partial def collectBinary (r i count used t : UInt64) : UInt64 :=
  if i == count then Guest.Effects.effectValue used t else
    let e := r+288+i*128
    let found := findNode (e+16) 10 0 t
    if found == error || load64 e t != 10 then error else
      let source := recordAt found
      let n := load64 (source+32) t
      if n == 0 || n > 65536 || used > 262144 || n > 262144-used then error else
        collectBinary r (i+1) count (used+n) (copy (source+256) (binaryBuffer+used) n t)

def hashMatches (p n expected t : UInt64) : UInt64 :=
  let t := ServiceHash.sha256At 0xd00000 p n releaseHash t
  if equal releaseHash expected 32 t then t else error

def validBuildDetail (r t : UInt64) : Bool :=
  let n := load64 (r+280) t
  let d := r+288+load64 (r+272) t*128
  n >= 200 && n <= 712 && load64 d t == 0x31444c4942544c && load64 (d+8) t == 1 &&
    load64 (d+16) t == 2 && load64 (d+192) t <= 512 && n == 200+load64 (d+192) t

-- The guest serializes this fixed canonical metadata subset from actual graph
-- records. It never treats a publisher JSON array as fetched source/evidence.
-- Scratch is private and bounded to8192 bytes, immediately after binaryBuffer.
def jsonBuffer : UInt64 := 0xd60000
def jsonByte (pos byte t : UInt64) : UInt64 :=
  if pos >= 8192 then error else Guest.Effects.effectValue (pos+1) (store8 (jsonBuffer+pos) byte t)
-- Emit bytes rather than unaligned SD: every byte stays within the budget.
partial def jsonWord (value n pos t : UInt64) : UInt64 :=
  if n == 0 then Guest.Effects.effectValue pos t else
    let pos := jsonByte pos (value &&& 255) t
    if pos == error then error else jsonWord (value >>> 8) (n-1) pos pos
def jsonLiteral (id pos t : UInt64) : UInt64 :=
  if id == 0 then
    if pos > 8191 then error else
      let pos := jsonWord 91 1 pos t
      pos
  else
  if id == 1 then
    if pos > 8191 then error else
      let pos := jsonWord 44 1 pos t
      pos
  else
  if id == 2 then
    if pos > 8183 then error else
      let pos := jsonWord 4189025452468216443 8 pos t
      let pos := jsonWord 34 1 pos pos
      pos
  else
  if id == 3 then
    if pos > 8180 then error else
      let pos := jsonWord 3833233334081825826 8 pos t
      let pos := jsonWord 574235190 4 pos pos
      pos
  else
  if id == 4 then
    if pos > 8183 then error else
      let pos := jsonWord 2478521763259100194 8 pos t
      let pos := jsonWord 58 1 pos pos
      pos
  else
  if id == 5 then
    if pos > 8191 then error else
      let pos := jsonWord 125 1 pos t
      pos
  else
  if id == 6 then
    if pos > 8191 then error else
      let pos := jsonWord 93 1 pos t
      pos
  else
  if id == 7 then
    if pos > 8173 then error else
      let pos := jsonWord 8241990191961766747 8 pos t
      let pos := jsonWord 3906083645759381369 8 pos pos
      let pos := jsonWord 2243106 3 pos pos
      pos
  else
  if id == 8 then
    if pos > 8180 then error else
      let pos := jsonWord 7592895727431461922 8 pos t
      let pos := jsonWord 574235236 4 pos pos
      pos
  else
  if id == 9 then
    if pos > 8144 then error else
      let pos := jsonWord 2478227094008638498 8 pos t
      let pos := jsonWord 8299417727452848698 8 pos pos
      let pos := jsonWord 7074443009456369249 8 pos pos
      let pos := jsonWord 8224184395757283701 8 pos pos
      let pos := jsonWord 7232627565552562533 8 pos pos
      let pos := jsonWord 2466321629486344041 8 pos pos
      pos
  else
  if id == 10 then
    if pos > 8175 then error else
      let pos := jsonWord 7165919078633319458 8 pos t
      let pos := jsonWord 4189038625367940965 8 pos pos
      let pos := jsonWord 34 1 pos pos
      pos
  else
  if id == 11 then
    if pos > 8142 then error else
      let pos := jsonWord 7165919078633319458 8 pos t
      let pos := jsonWord 7955998378758004581 8 pos pos
      let pos := jsonWord 7959305549529051745 8 pos pos
      let pos := jsonWord 7234304265017255286 8 pos pos
      let pos := jsonWord 7164223631720066082 8 pos pos
      let pos := jsonWord 2478221553555825000 8 pos pos
      let pos := jsonWord 8762 2 pos pos
      pos
  else
  if id == 12 then
    if pos > 8189 then error else
      let pos := jsonWord 6126882 3 pos t
      pos
  else
  error

partial def jsonHex (p n pos t : UInt64) : UInt64 :=
  if n == 0 then Guest.Effects.effectValue pos t else
    let byte := load8 p t
    let high := byte >>> 4
    let next := jsonByte pos (if high < 10 then high+48 else high+87) t
    let low := byte &&& 15
    let next := jsonByte next (if low < 10 then low+48 else low+87) next
    if next == error then error else jsonHex (p+1) (n-1) next next

partial def jsonDecimal (value pos t : UInt64) : UInt64 :=
  let pos := if value >= 10 then jsonDecimal (value/10) pos t else Guest.Effects.effectValue pos t
  jsonByte pos (value%10+48) pos

partial def jsonName (p n pos t : UInt64) : UInt64 :=
  if n == 0 then Guest.Effects.effectValue pos t else
    let byte := load8 p t
    let pos := if byte == 34 || byte == 92 then jsonByte pos 92 t else Guest.Effects.effectValue pos t
    let pos := jsonByte pos byte pos
    if pos == error then error else jsonName (p+1) (n-1) pos pos

partial def jsonSources (r i count emitted pos t : UInt64) : UInt64 :=
  if pos == error then error else
  if i == count then jsonLiteral 6 pos t else
    let entry := r+288+i*128
    if load64 entry t != 10 then jsonSources r (i+1) count emitted pos t else
      let found := findNode (entry+16) 10 0 t
      if found == error then error else
        let source := recordAt found
        let pos := if emitted == 0 then Guest.Effects.effectValue pos t else jsonLiteral 1 pos t
        let pos := jsonLiteral 2 pos pos
        let pos := jsonName (entry+48) (load64 (entry+8) pos) pos pos
        let pos := jsonLiteral 3 pos pos
        let pos := jsonHex (source+128) 32 pos pos
        let pos := jsonLiteral 4 pos pos
        let pos := jsonDecimal (load64 (source+32) pos) pos pos
        let pos := jsonLiteral 5 pos pos
        jsonSources r (i+1) count (emitted+1) pos pos

def canonicalSources (r t : UInt64) : UInt64 :=
  let pos := jsonLiteral 0 0 t
  jsonSources r 0 (load64 (r+272) pos) 0 pos pos

def canonicalEvidence (detail t : UInt64) : UInt64 :=
  let pos := jsonLiteral 7 0 t
  let pos := jsonHex (detail+80) 32 pos pos
  let pos := jsonLiteral 8 pos pos
  let pos := jsonDecimal (load64 (detail+24) pos) pos pos
  let pos := jsonLiteral 9 pos pos
  let pos := jsonHex (detail+112) 32 pos pos
  let pos := jsonLiteral 10 pos pos
  let pos := jsonHex (detail+48) 32 pos pos
  let pos := jsonLiteral 11 pos pos
  let pos := jsonHex (detail+144) 32 pos pos
  jsonLiteral 12 pos pos

def checkRelease (r t : UInt64) : UInt64 :=
  if load64 (r+272) t != 4 ||
    !releaseEdge r 0 12 0x646c697562 5 t || !releaseEdge r 1 11 0x65646f63 4 t ||
    !releaseEdge r 2 14 0x65636e6564697665 8 t || !releaseEdge r 3 11 0x656372756f73 6 t then error else
    let details := r+800
    let n := load64 (r+280) t
    if n < 832 || load64 details t != 0x31544e43524c544c || load64 (details+8) t != 1 ||
      load64 (details+16) t != 768 || load64 (details+56) t != 0 then error else
      let mn := load64 (details+24) t
      let sn := load64 (details+32) t
      let en := load64 (details+40) t
      let ln := load64 (details+48) t
      if mn > 65536 || sn > 65536 || en > 65536 || ln > 65536 || n != 832+mn+sn+en+ln then error else
        let h := details+64
        if load64 h t != 0x3253454c544c || load64 (h+8) t != 2 || load64 (h+16) t != 512 then error else
          let t := copy h scratch 512 t
          let t := zero (scratch+160) 4 t
          let checked := hashMatches scratch 512 (h+160) t
          if checked == error then error else
            let checked := hashMatches (h+768) mn (h+256) checked
            if checked == error then error else
              let checked := hashMatches (h+768+mn) sn (h+224) checked
              if checked == error then error else
                let checked := hashMatches (h+768+mn+sn) en (h+352) checked
                if checked == error then error else
                  let checked := hashMatches (h+768+mn+sn+en) ln (h+320) checked
                  if checked == error then error else
                    let bi := findNode (r+432) 11 0 checked
                    let build := findNode (r+304) 12 0 checked
                    if bi == error || build == error then error else
                      let binary := recordAt bi
                      let count := load64 (binary+272) checked
                      if count == 0 || count > 4 then error else
                        let bytes := collectBinary binary 0 count 0 checked
                        if bytes == error || bytes != load64 (h+24) bytes then error else
                          let checked := hashMatches binaryBuffer bytes (h+192) bytes
                          if checked == error then error else
                            let b := recordAt build
                            let ei := findNode (r+560) 14 0 checked
                            if ei == error then error else
                              let e := recordAt ei
                              if load64 (b+272) checked != 2 || load64 (e+272) checked != 1 ||
                                !releaseEdge b 0 14 0x65636e6564697665 8 checked || !releaseEdge b 1 11 0x656372756f73 6 checked ||
                                !releaseEdge e 0 11 0x656372756f73 6 checked || !validBuildDetail b checked || !validBuildDetail e checked then error else
                                let bd := b+544
                                let ed := e+416
                                if !equal (b+304) (r+560) 32 checked || !equal (b+432) (r+688) 32 checked ||
                                  !equal (e+304) (r+688) 32 checked || load64 (b+280) checked != load64 (e+280) checked ||
                                  !equal bd ed (load64 (b+280) checked) checked ||
                                  load64 (bd+40) checked != load64 (h+400) checked ||
                                  !equal (bd+48) (r+688) 32 checked || !equal (bd+80) (h+192) 32 checked then error else
                                  let source := findNode (r+688) 11 0 checked
                                  if source == error then error else
                                    let generated := canonicalSources (recordAt source) checked
                                    if generated == error || generated != sn || !equal jsonBuffer (h+768+mn) sn generated then error else
                                      let generated := canonicalEvidence bd generated
                                      if generated == error || generated != en || !equal jsonBuffer (h+768+mn+sn) en generated then error else
                                        zero jsonBuffer 1024 (zero binaryBuffer 32768 generated)

def sealNode (caller r t : UInt64) : UInt64 :=
  if !validPayload caller r t then error else
    let checked := if load64 (r+40) t == 13 then checkRelease r t else t
    if checked == error then error else
    let t := zero scratch 12 checked
    let t := store64 scratch 0x3145444f4e544c t
    let t := store64 (scratch+8) 1 t
    let t := store64 (scratch+16) (load64 (r+40) t) t
    let t := store64 (scratch+24) 1 t
    let t := copy (r+128) (scratch+32) 32 t
    let t := copy (r+192) (scratch+64) 32 t
    let t := ServiceHash.sha256At 0xd00000 scratch 96 (r+160) t
    store64 (r+224) 1 t

def rootHandle (slot t : UInt64) : UInt64 :=
  (load64 state t <<< 32) ||| (load64 (rootCapAt slot) t <<< 8) ||| slot

def rootValid (caller h right t : UInt64) : Bool :=
  let c := rootCapAt (h &&& 255)
  let i := load64 (c+16) t
  (h &&& 255) < 64 && h >>> 32 == load64 state t && ((h >>> 8) &&& 0xffffff) == load64 c t &&
    load64 (c+40) t == 1 && load64 (c+8) t == caller && (load64 (c+32) t &&& right) == right &&
    i < 16 && load64 (rootAt i) t == 1 && load64 (rootAt i+16) t == load64 (c+24) t

def grantedRoot (h t : UInt64) : UInt64 := rootAt (load64 (rootCapAt (h &&& 255)+16) t)
partial def ownerRoots (caller temporary i count t : UInt64) : UInt64 :=
  if i == 16 then count else
    let r := rootAt i
    let owned := load64 r t == 1 && load64 (r+8) t == caller && load64 (r+48) t == temporary
    ownerRoots caller temporary (i+1) (count+(if owned then 1 else 0)) t

partial def freeRoot (i t : UInt64) : UInt64 :=
  if i == 16 then error else if load64 (rootAt i) t == 0 then i else freeRoot (i+1) t
partial def freeRootCap (i t : UInt64) : UInt64 :=
  if i == 64 then error else
    let c := rootCapAt i
    if load64 (c+40) t == 0 && load64 c t < 0xffffff then i else
      let alive := if load64 (c+40) t == 1 then syscall 34 (load64 (c+8) t) 0 0 0 t else t
      if alive == error && load64 c alive < 0xffffff then
        Guest.Effects.effectValue i (store64 (c+40) 0 alive)
      else freeRootCap (i+1) alive

def grantRoot (slot caller r rights issuer t : UInt64) : UInt64 :=
  let c := rootCapAt slot
  let t := store64 c (load64 c t+1) t
  let t := store64 (c+8) caller t
  let t := store64 (c+16) ((r-roots)/192) t
  let t := store64 (c+24) (load64 (r+16) t) t
  let t := store64 (c+32) rights t
  let t := store64 (c+48) issuer t
  store64 (c+40) 1 t
partial def duplicateRoot (caller name n excluded i t : UInt64) : Bool :=
  if i == 16 then false else
    let r := rootAt i
    (r != excluded && load64 r t == 1 && load64 (r+48) t == 0 && load64 (r+8) t == caller && load64 (r+40) t == n && equal name (r+64) n t) ||
      duplicateRoot caller name n excluded (i+1) t
-- Mark before descent bounds traversal to64 nodes, even for malformed restored cycles.
partial def markNode (i budget t : UInt64) : UInt64 :=
  if i >= 64 || budget == 0 || load64 (marks+i*8) t == 1 then t else
    let r := recordAt i
    if load64 r t != 2 || load64 (r+224) t != 1 then t else
      let t := store64 (marks+i*8) 1 t
      let parent := if allZero (r+192) 32 t then error else findNode (r+192) 0 0 t
      let t := if parent == error then t else markNode parent (budget-1) t
      if load64 (r+40) t == 10 then t else markEdges r 0 (load64 (r+272) t) (budget-1) t
where
  markEdges (r j count budget t : UInt64) : UInt64 :=
    if j == count || j == 32 then t else
      let e := r+288+j*128
      let i := findNode (e+16) (load64 e t) 0 t
      let t := if i == error then t else markNode i budget t
      markEdges r (j+1) count budget t

def markRoot (r t : UInt64) : UInt64 :=
  let i := findNode (r+128) 11 0 t
  if i == error then t else markNode i 64 t
partial def markRoots (i t : UInt64) : UInt64 :=
  if i == 16 then t else
    let r := rootAt i
    markRoots (i+1) (if load64 r t == 1 then markRoot r t else t)
def markAll (t : UInt64) : UInt64 := markRoots 0 (zero marks 64 t)
def pinned (i t : UInt64) : Bool := load64 (marks+i*8) t == 1
partial def nextMarked (i t : UInt64) : UInt64 :=
  if i == 64 then error else if pinned i t then i else nextMarked (i+1) t

partial def presentEdges (r j count t : UInt64) : Bool :=
  if j == count then true else
    let e := r+288+j*128
    count <= 32 && findNode (e+16) (load64 e t) 0 t != error && presentEdges r (j+1) count t
partial def markedComplete (i t : UInt64) : Bool :=
  if i == 64 then true else
    let r := recordAt i
    (!pinned i t || ((allZero (r+192) 32 t || findNode (r+192) (load64 (r+40) t) 0 t != error) &&
      (load64 (r+40) t == 10 || presentEdges r 0 (load64 (r+272) t) t))) && markedComplete (i+1) t

def completeNode (i t : UInt64) : UInt64 :=
  let t := markNode i 64 (zero marks 64 t)
  if markedComplete 0 t then t else error

-- This transition is also used by root publication after exact expected-head
-- comparison. It proves only the denied transition, not hash or memory safety.
def publishAllowed (hasAuthority expectedMatches : Bool) : Bool := hasAuthority && expectedMatches

theorem stale_head_denied (authority : Bool) : publishAllowed authority false = false := by
  unfold publishAllowed
  exact Bool.and_false _

def startGraph (epoch t : UInt64) : UInt64 := store64 state epoch (zero state 4096 t)
end Guest.ProjectGraph
