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
def rootCapAt (i : UInt64) : UInt64 := rootCaps+i*48
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

-- Resolving a content ID alone never creates authority.
def edgeAllowed (kind child : UInt64) : Bool :=
  if kind == 11 then child == 10 else
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

def sealNode (caller r t : UInt64) : UInt64 :=
  if !validPayload caller r t then error else
    let t := zero scratch 12 t
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
partial def freeRoot (i t : UInt64) : UInt64 :=
  if i == 16 then error else if load64 (rootAt i) t == 0 then i else freeRoot (i+1) t
partial def freeRootCap (i t : UInt64) : UInt64 :=
  if i == 64 then error else
    let c := rootCapAt i
    if load64 (c+40) t == 0 && load64 c t < 0xffffff then i else freeRootCap (i+1) t

def grantRoot (slot caller r rights t : UInt64) : UInt64 :=
  let c := rootCapAt slot
  let t := store64 c (load64 c t+1) t
  let t := store64 (c+8) caller t
  let t := store64 (c+16) ((r-roots)/192) t
  let t := store64 (c+24) (load64 (r+16) t) t
  let t := store64 (c+32) rights t
  store64 (c+40) 1 t
partial def duplicateRoot (caller name n excluded i t : UInt64) : Bool :=
  if i == 16 then false else
    let r := rootAt i
    (r != excluded && load64 r t == 1 && load64 (r+8) t == caller && load64 (r+40) t == n && equal name (r+64) n t) ||
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
