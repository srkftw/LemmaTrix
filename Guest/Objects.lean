import Guest.LiveSDK
import Guest.ServiceHash
import Guest.Policy
import Guest.ProjectGraph
namespace Guest.Objects
open Guest.LiveSDK
-- Private VA600000..dfffff belongs only to this user service.
-- 256 generation-tagged grants, 64 immutable records, 64KiB content each.
def state : UInt64 := 0x600000
def caps : UInt64 := 0x602000
def records : UInt64 := 0x610000
def hashScratch : UInt64 := 0xd00000
def hashResult : UInt64 := 0xd01000
def capAt (i : UInt64) : UInt64 := caps+i*64
def recordAt (i : UInt64) : UInt64 := records+i*0x11000
def admin (rights : UInt64) : Bool := (rights &&& 0x100000000) != 0
def has (rights requested : UInt64) : Bool := (rights &&& requested) == requested
partial def equal (a b n t : UInt64) : Bool :=
  if n == 0 then true else load8 a t == load8 b t && equal (a+1) (b+1) (n-1) t
-- Handle upper32 bits mix the random boot prefix and bounded service incarnation.
def handle (slot t : UInt64) : UInt64 :=
  (load64 state t <<< 32) ||| (load64 (capAt slot) t <<< 8) ||| slot
def objectId (r t : UInt64) : UInt64 :=
  (load64 state t <<< 32) ||| (load64 (r+16) t <<< 6) ||| ((r-records)/0x11000)
def grantValid (caller h right t : UInt64) : Bool :=
  let c := capAt (h &&& 255)
  let i := load64 (c+16) t
  h >>> 32 == load64 state t &&
  Policy.permits (load64 c t) ((h >>> 8) &&& 0xffffff) (load64 (c+40) t) (load64 (c+32) t) right &&
  load64 (c+8) t == caller && i < 64 &&
  load64 (recordAt i) t != 0 && load64 (recordAt i+16) t == load64 (c+24) t

def grantedRecord (h t : UInt64) : UInt64 := recordAt (load64 (capAt (h &&& 255)+16) t)
partial def findCap (slot t : UInt64) : UInt64 :=
  if slot == 256 then error else
    let c := capAt slot
    if load64 (c+40) t == 0 && load64 c t < 0xffffff then slot else findCap (slot+1) t
partial def findRecord (i t : UInt64) : UInt64 :=
  if i == 64 then error else
    let r := recordAt i
    if load64 r t == 0 && load64 (r+16) t < 0x3ffffff then i else findRecord (i+1) t
partial def reservedLoop (caller i acc t : UInt64) : UInt64 :=
  if i == 64 then acc else
    let r := recordAt i
    let n := if load64 r t != 0 && load64 (r+8) t == caller then load64 (r+32) t else 0
    reservedLoop caller (i+1) (acc+n) t
def reservedBytes (caller i t : UInt64) : UInt64 := reservedLoop caller i 0 t
partial def ownedLoop (caller i acc t : UInt64) : UInt64 :=
  if i == 64 then acc else
    let r := recordAt i
    let n := if load64 r t != 0 && load64 (r+8) t == caller then 1 else 0
    ownedLoop caller (i+1) (acc+n) t
def ownedCount (caller i t : UInt64) : UInt64 := ownedLoop caller i 0 t
partial def capLoop (caller i acc t : UInt64) : UInt64 :=
  if i == 256 then acc else
    let c := capAt i
    let n := if load64 (c+40) t == 1 && load64 (c+8) t == caller then 1 else 0
    capLoop caller (i+1) (acc+n) t
def capCount (caller i t : UInt64) : UInt64 := capLoop caller i 0 t

def newGrant (slot caller r rights issuer t : UInt64) : UInt64 :=
  let c := capAt slot
  let t := store64 c (load64 c t+1) t
  let t := store64 (c+8) caller t
  let t := store64 (c+16) ((r-records)/0x11000) t
  let t := store64 (c+24) (load64 (r+16) t) t
  let t := store64 (c+32) rights t
  let t := store64 (c+48) issuer t
  let t := store64 (c+56) 0 t
  store64 (c+40) 1 t
-- Every reply is initialized, including errors; unrelated content is never copied.
def respond (status result r rights t : UInt64) : UInt64 :=
  let t := zero wire 8 t
  let t := store64 wire status t
  let t := store64 (wire+8) result t
  if r == 0 then 64+t else
    let t := store64 (wire+16) (load64 (r+32) t) t
    let t := store64 (wire+24) (load64 (r+48) t) t
    let t := store64 (wire+32) (load64 (r+40) t) t
    let t := store64 (wire+40) (load64 r t) t
    let t := store64 (wire+48) rights t
    let t := store64 (wire+56) (objectId r t) t
    64+t

def beginObject (caller rights length t : UInt64) : UInt64 :=
  let parent := load64 (command+8) t
  let n := load64 (command+16) t
  let kind := load64 (command+24) t
  let schema := load64 (command+32) t
  let derive := load64 (command+40) t
  if n > 65536 || kind < 1 || kind > 14 || schema != 1 ||
      !((length == 96 && derive == 0) || (length == 64 && derive == 1)) then respond 2 0 0 0 t
  else if (parent == 0 && !has rights 2) || (parent != 0 && (!has rights 4 || !grantValid caller parent 4 t)) then respond 1 0 0 0 t
  else if parent != 0 && load64 (grantedRecord parent t) t != 2 then respond 2 0 0 0 t
  else if parent != 0 && kind >= 10 && (load64 (grantedRecord parent t+224) t != 1 || load64 (grantedRecord parent t+40) t != kind) then respond 2 0 0 0 t
  else
    let count := ownedCount caller 0 t
    let reserved := reservedBytes caller 0 t
    if (!admin rights && (count >= (if kind >= 10 then 24 else 8) || reserved+n > (if kind >= 10 then 1048576 else 262144) || capCount caller 0 t >= 64)) then respond 4 0 0 0 t
    else
      let i := findRecord 0 t
      let slot := findCap 0 t
      if i == error || slot == error then respond 4 0 0 0 t else
        let r := recordAt i
        let generation := load64 (r+16) t+1
        let parentId := if parent == 0 then 0 else objectId (grantedRecord parent t) t
        let t := zero r 32 t
        let t := if parent != 0 && kind >= 10 && load64 (grantedRecord parent t+224) t == 1 then copy (grantedRecord parent t+160) (r+192) 32 t else t
        let t := store64 (r+8) caller t
        let t := store64 (r+16) generation t
        let t := store64 (r+32) n t
        let t := store64 (r+40) kind t
        let t := store64 (r+48) parentId t
        let t := store64 (r+56) (if parent == 0 then 2 else 4) t
        let t := store64 (r+64) (if derive == 0 then 1 else 0) t
        let t := if derive == 0 then copy (command+64) (r+96) 32 t else t
        let t := newGrant slot caller r (rights &&& 127) caller t
        let t := store64 r 1 t
        respond 0 (handle slot t) r (rights &&& 127) t

def appendObject (caller rights length t : UInt64) : UInt64 :=
  let h := load64 (command+8) t
  if !grantValid caller h 0 t then respond 3 0 0 0 t else
    let r := grantedRecord h t
    let required := load64 (r+56) t
    if load64 (r+8) t != caller || !has rights required || !has (load64 (capAt (h &&& 255)+32) t) required then respond 1 0 0 0 t
    else
      let offset := load64 (command+16) t
      let n := length-64
      let used := load64 (r+24) t
      let total := load64 (r+32) t
      if load64 r t != 1 || n > 512 || offset != used || used > total || n > total-used then respond 2 0 0 0 t else
        let t := copy (command+64) (r+256+used) n t
        let t := store64 (r+24) (used+n) t
        respond 0 (used+n) r (load64 (capAt (h &&& 255)+32) t) t

def digestStage (caller rights t : UInt64) : UInt64 :=
  let h := load64 (command+8) t
  if !grantValid caller h 0 t then respond 3 0 0 0 t else
    let r := grantedRecord h t
    if load64 (r+8) t != caller || !has rights (load64 (r+56) t) || !has (load64 (capAt (h &&& 255)+32) t) (load64 (r+56) t) then respond 1 0 0 0 t
    else if load64 r t != 1 || load64 (r+24) t != load64 (r+32) t then respond 6 0 0 0 t else
      let t := ServiceHash.sha256At hashScratch (r+256) (load64 (r+32) t) hashResult t
      let t := respond 0 32 r (load64 (capAt (h &&& 255)+32) t) t
      96+copy hashResult (wire+64) 32 t

def commitObject (caller rights length t : UInt64) : UInt64 :=
  let h := load64 (command+8) t
  if length != 96 then respond 2 0 0 0 t else
  if !grantValid caller h 0 t then respond 3 0 0 0 t else
    let r := grantedRecord h t
    if load64 (r+8) t != caller || !has rights (load64 (r+56) t) || !has (load64 (capAt (h &&& 255)+32) t) (load64 (r+56) t) then respond 1 0 0 0 t
    else if load64 r t != 1 || load64 (r+24) t != load64 (r+32) t then respond 6 0 0 0 t else
      let t := ServiceHash.sha256At hashScratch (r+256) (load64 (r+32) t) hashResult t
      if !equal hashResult (command+64) 32 t || (load64 (r+64) t == 1 && !equal hashResult (r+96) 32 t) then respond 5 0 0 0 t else
        let t := copy hashResult (r+128) 32 t
        let sealed := if load64 (r+40) t >= 10 then ProjectGraph.sealNode caller r t else t
        if sealed == error then respond 2 0 0 0 t else
        let t := store64 r 2 sealed
        let t := respond 0 h r (load64 (capAt (h &&& 255)+32) t) t
        96+copy hashResult (wire+64) 32 t

def readObject (caller rights required t : UInt64) : UInt64 :=
  let h := load64 (command+8) t
  if !has rights required then respond 1 0 0 0 t else
  if !grantValid caller h required t then respond 3 0 0 0 t else
    let r := grantedRecord h t
    let offset := load64 (command+16) t
    let n := load64 (command+24) t
    let total := load64 (r+32) t
    if load64 r t != 2 || n > 512 || offset > total then respond 2 0 0 0 t else
      let count := if n <= total-offset then n else total-offset
      let t := respond 0 count r (load64 (capAt (h &&& 255)+32) t) t
      if count == 0 then t else 64+count+copy (r+256+offset) (wire+64) count t

def metadataObject (caller rights t : UInt64) : UInt64 :=
  let h := load64 (command+8) t
  if !has rights 1 then respond 1 0 0 0 t else
  if !grantValid caller h 1 t then respond 3 0 0 0 t else
    let r := grantedRecord h t
    if load64 r t != 2 then respond 6 0 0 0 t else
      let t := respond 0 h r (load64 (capAt (h &&& 255)+32) t) t
      96+copy (r+128) (wire+64) 32 t

def shareObject (caller rights t : UInt64) : UInt64 :=
  let h := load64 (command+8) t
  if !has rights 8 then respond 1 0 0 0 t else
  if !grantValid caller h 8 t then respond 3 0 0 0 t else
    let r := grantedRecord h t
    let target := load64 (command+16) t
    let requested := load64 (command+24) t
    let actual := syscall 34 target 0 0 0 t
    if load64 r t != 2 || requested == 0 || requested > 127 || actual == error ||
       !has actual requested || !has (load64 (capAt (h &&& 255)+32) t) requested then respond 1 0 0 0 actual else
      if !admin actual && capCount target 0 actual >= 32 then respond 4 0 0 0 actual else
      let slot := findCap 0 actual
      if slot == error then respond 4 0 0 0 actual else
        let t := newGrant slot target r requested caller actual
        respond 0 (handle slot t) r requested t

def revokeObject (caller rights t : UInt64) : UInt64 :=
  let h := load64 (command+8) t
  let target := load64 (command+16) t
  if !has rights 16 then respond 1 0 0 0 t else
  if !grantValid caller h 16 t then respond 3 0 0 0 t else
    let r := grantedRecord h t
    let c := capAt (target &&& 255)
    if target >>> 32 != load64 state t || ((target >>> 8) &&& 0xffffff) != load64 c t ||
        load64 (c+40) t != 1 || load64 (c+16) t != (r-records)/0x11000 ||
        load64 (c+24) t != load64 (r+16) t ||
        (load64 (r+8) t != caller && load64 (c+48) t != caller) then respond 1 0 0 0 t
    else respond 0 0 r (load64 (capAt (h &&& 255)+32) t) (store64 (c+40) 0 t)

partial def invalidate (i generation slot t : UInt64) : UInt64 :=
  if slot == 256 then t else
    let c := capAt slot
    let t := if load64 (c+16) t == i && load64 (c+24) t == generation then store64 (c+40) 0 t else t
    invalidate i generation (slot+1) t

def dropObject (caller rights t : UInt64) : UInt64 :=
  let h := load64 (command+8) t
  if !has rights 16 then respond 1 0 0 0 t else
  if !grantValid caller h 16 t then respond 3 0 0 0 t else
    let r := grantedRecord h t
    let t := ProjectGraph.markAll t
    if ProjectGraph.pinned ((r-records)/0x11000) t then respond 8 0 0 0 t else
    if load64 (r+8) t != caller && !admin rights then respond 1 0 0 0 t else
      let t := invalidate ((r-records)/0x11000) (load64 (r+16) t) 0 t
      respond 0 0 0 0 (store64 r 0 t)

def abortStage (caller rights t : UInt64) : UInt64 :=
  let h := load64 (command+8) t
  if !grantValid caller h 0 t then respond 3 0 0 0 t else
    let r := grantedRecord h t
    let required := load64 (r+56) t
    if load64 r t != 1 || load64 (r+8) t != caller || !has rights required ||
       !has (load64 (capAt (h &&& 255)+32) t) required then respond 1 0 0 0 t else
      let t := invalidate ((r-records)/0x11000) (load64 (r+16) t) 0 t
      respond 0 0 0 0 (store64 r 0 t)

partial def findVisible (caller slot t : UInt64) : UInt64 :=
  if slot >= 256 then error else
    let h := handle slot t
    if grantValid caller h 1 t && load64 (grantedRecord h t) t == 2 then slot else findVisible caller (slot+1) t

def listObjects (caller rights t : UInt64) : UInt64 :=
  if !has rights 32 then respond 1 0 0 0 t else
    let cursor := load64 (command+16) t
    if cursor > 256 then respond 2 0 0 0 t else
      let slot := findVisible caller cursor t
      if slot == error then respond 0 0 0 0 t else
        let h := handle slot t
        respond 0 h (grantedRecord h t) (load64 (capAt slot+32) t) t

partial def cleanDeadGrants (slot t : UInt64) : UInt64 :=
  if slot == 256 then t else
    let c := capAt slot
    let t := if load64 (c+40) t == 1 then
      let alive := syscall 34 (load64 (c+8) t) 0 0 0 t
      if alive == error then store64 (c+40) 0 alive else alive
    else t
    cleanDeadGrants (slot+1) t
partial def survivingGrant (i generation slot t : UInt64) : Bool :=
  if slot == 256 then false else
    let c := capAt slot
    if load64 (c+40) t == 1 && load64 (c+16) t == i && load64 (c+24) t == generation then true
    else survivingGrant i generation (slot+1) t
partial def collectDead (i t : UInt64) : UInt64 :=
  if i == 64 then t else
    let r := recordAt i
    let t := if load64 r t != 0 then
      let alive := syscall 34 (load64 (r+8) t) 0 0 0 t
      if alive == error && !ProjectGraph.pinned i alive && !survivingGrant i (load64 (r+16) alive) 0 alive then
        let t := invalidate i (load64 (r+16) alive) 0 alive
        store64 r 0 t
      else alive
    else t
    collectDead (i+1) t

def graphMetadata (h r rights t : UInt64) : UInt64 :=
  let t := respond 0 h r rights t
  let t := copy (r+160) (wire+64) 32 t
  128+copy (r+192) (wire+96) 32 t

def rootReply (h r cursor t : UInt64) : UInt64 :=
  let t := respond 0 h 0 0 t
  let t := store64 (wire+16) (load64 (r+40) t) t
  let t := store64 (wire+24) cursor t
  let t := copy (r+128) (wire+64) 32 t
  160+copy (r+64) (wire+96) 64 t

def publishRoot (caller rights length t : UInt64) : UInt64 :=
  let h := load64 (command+8) t
  let old := load64 (command+16) t
  let n := load64 (command+24) t
  if length != 160 || !has rights 4 || !grantValid caller h 4 t then respond 1 0 0 0 t else
  if old == 0 && !admin rights && ProjectGraph.ownerRoots caller 0 0 0 t >= 4 then respond 4 0 0 0 t else
    let source := grantedRecord h t
    if load64 (source+40) t != 11 || load64 (source+224) t != 1 ||
      !ProjectGraph.validName (command+96) n 63 t || !ProjectGraph.allZero (command+96+n) (64-n) t then respond 2 0 0 0 t else
    if old != 0 && !ProjectGraph.rootValid caller old 4 t then respond 3 0 0 0 t else
      let i := if old == 0 then ProjectGraph.freeRoot 0 t else (ProjectGraph.grantedRoot old t-ProjectGraph.roots)/192
      let slot := if old == 0 then ProjectGraph.freeRootCap 0 t else old &&& 255
      if i == error || slot == error then respond 4 0 0 0 t else
        let r := ProjectGraph.rootAt i
        let headMatches := if old == 0 then ProjectGraph.allZero (command+64) 32 t else equal (command+64) (r+128) 32 t
        if !ProjectGraph.publishAllowed true headMatches then respond 8 0 0 0 t else
        let checked := ProjectGraph.completeNode ((source-records)/0x11000) t
        if checked == error then respond 2 0 0 0 t else
        let t := checked
        let nameOwner := if old == 0 then caller else load64 (r+8) t
        if ProjectGraph.duplicateRoot nameOwner (command+96) n (if old == 0 then 0 else r) 0 t then respond 8 0 0 0 t else
          let generation := if old == 0 then load64 (r+16) t+1 else load64 (r+16) t
          let t := if old == 0 then zero r 24 t else t
          let t := store64 r 1 t
          let t := if old == 0 then store64 (r+8) caller t else t
          let t := store64 (r+16) generation t
          let t := store64 (r+40) n t
          let t := zero (r+64) 8 t
          let t := copy (command+96) (r+64) n t
          let t := copy (source+160) (r+128) 32 t
          let t := if old == 0 then ProjectGraph.grantRoot slot caller r (rights &&& 127) t else t
          rootReply (ProjectGraph.rootHandle slot t) r (slot+1) t

partial def nextRoot (caller cursor t : UInt64) : UInt64 :=
  if cursor >= 64 then error else
    if ProjectGraph.rootValid caller (ProjectGraph.rootHandle cursor t) 1 t && load64 (ProjectGraph.grantedRoot (ProjectGraph.rootHandle cursor t) t+48) t == 0 then cursor else nextRoot caller (cursor+1) t

partial def existingGrant (caller i requested slot t : UInt64) : UInt64 :=
  if slot == 256 then error else
    let c := capAt slot
    if load64 (c+40) t == 1 && load64 (c+8) t == caller && load64 (c+16) t == i &&
      load64 (c+24) t == load64 (recordAt i+16) t && has (load64 (c+32) t) requested then slot
    else existingGrant caller i requested (slot+1) t

def grantGraphObject (caller root i cursor t : UInt64) : UInt64 :=
  let rights := load64 (ProjectGraph.rootCapAt (root &&& 255)+32) t
  let previous := existingGrant caller i rights 0 t
  let slot := if previous == error then findCap 0 t else previous
  if slot == error || (previous == error && capCount caller 0 t >= 64) then respond 4 0 0 0 t else
    let r := recordAt i
    let t := if previous == error then newGrant slot caller r rights caller t else t
    let t := if previous == error then store64 (capAt slot+56) root t else t
    let t := graphMetadata (handle slot t) r rights t
    128+store64 (wire+24) cursor t

partial def existingRootGrant (caller root requested slot t : UInt64) : UInt64 :=
  if slot == 64 then error else
    let c := ProjectGraph.rootCapAt slot
    if load64 (c+40) t == 1 && load64 (c+8) t == caller && load64 (c+16) t == (root-ProjectGraph.roots)/192 &&
      load64 (c+24) t == load64 (root+16) t && has (load64 (c+32) t) requested then slot
    else existingRootGrant caller root requested (slot+1) t
partial def freeRootsCount (i count t : UInt64) : UInt64 :=
  if i == 16 then count else freeRootsCount (i+1) (count+(if load64 (ProjectGraph.rootAt i) t == 0 then 1 else 0)) t
partial def freeRootCapsCount (i count t : UInt64) : UInt64 :=
  if i == 64 then count else
    let c := ProjectGraph.rootCapAt i
    freeRootCapsCount (i+1) (count+(if load64 (c+40) t == 0 && load64 c t < 0xffffff then 1 else 0)) t
partial def validRestoreNames (entry i t : UInt64) : Bool :=
  if i == 0 then true else
    let earlier := command+64+(i-1)*128
    !(load64 (earlier+8) t == load64 (entry+8) t && equal (earlier+48) (entry+48) (load64 (entry+8) t) t) && validRestoreNames entry (i-1) t
partial def validRestoreEntries (caller i count t : UInt64) : Bool :=
  if i == count then true else
    let e := command+64+i*128
    let h := load64 e t
    let n := load64 (e+8) t
    if !grantValid caller h 4 t || !ProjectGraph.validName (e+48) n 63 t || !ProjectGraph.allZero (e+48+n) (80-n) t ||
      !validRestoreNames e i t || ProjectGraph.duplicateRoot caller (e+48) n 0 0 t then false else
      let r := grantedRecord h t
      load64 (r+40) t == 11 && load64 (r+224) t == 1 && equal (r+160) (e+16) 32 t && validRestoreEntries caller (i+1) count t
partial def publishRestoreEntries (caller rights i count t : UInt64) : UInt64 :=
  if i == count then 64+count*8+t else
    let e := command+64+i*128
    let source := grantedRecord (load64 e t) t
    let slot := ProjectGraph.freeRootCap 0 t
    let r := ProjectGraph.rootAt (ProjectGraph.freeRoot 0 t)
    let generation := load64 (r+16) t+1
    let t := zero r 24 t
    let t := store64 r 1 t
    let t := store64 (r+8) caller t
    let t := store64 (r+16) generation t
    let t := store64 (r+40) (load64 (e+8) t) t
    let t := copy (e+48) (r+64) 64 t
    let t := copy (e+16) (r+128) 32 t
    let t := ProjectGraph.grantRoot slot caller r (rights &&& 127) t
    let t := store64 (wire+64+i*8) (ProjectGraph.rootHandle slot t) t
    let _ := source
    publishRestoreEntries caller rights (i+1) count t
-- All validation and reservation precedes this bounded single-threaded publication.
-- A malformed/missing member cannot publish a prefix of a restored root set.
partial def checkRestoreClosures (i count t : UInt64) : UInt64 :=
  if i == count then t else
    let r := grantedRecord (load64 (command+64+i*128) t) t
    let checked := ProjectGraph.completeNode ((r-records)/0x11000) t
    if checked == error then error else checkRestoreClosures (i+1) count checked

def restoreRoots (caller rights length t : UInt64) : UInt64 :=
  let count := load64 (command+16) t
  if !has rights 4 || count == 0 || count > 6 || length != 64+count*128 then respond 2 0 0 0 t else
  if freeRootsCount 0 0 t < count || freeRootCapsCount 0 0 t < count then respond 4 0 0 0 t else
  if !validRestoreEntries caller 0 count t then respond 2 0 0 0 t else
    let checked := checkRestoreClosures 0 count t
    if checked == error then respond 2 0 0 0 t else
    let t := respond 0 count 0 0 checked
    publishRestoreEntries caller rights 0 count t

partial def revokeRootObjects (root slot t : UInt64) : UInt64 :=
  if slot == 256 then t else
    let c := capAt slot
    let t := if load64 (c+56) t == root then store64 (c+40) 0 t else t
    revokeRootObjects root (slot+1) t
partial def revokeRootGrants (root slot t : UInt64) : UInt64 :=
  if slot == 64 then t else
    let c := ProjectGraph.rootCapAt slot
    let t := if load64 (c+40) t == 1 && load64 (c+16) t == (root-ProjectGraph.roots)/192 && load64 (c+24) t == load64 (root+16) t then
      let t := revokeRootObjects (ProjectGraph.rootHandle slot t) 0 t
      store64 (c+40) 0 t
      else t
    revokeRootGrants root (slot+1) t

def graphDispatch (op caller rights length t : UInt64) : UInt64 :=
  let h := load64 (command+8) t
  if op == 30 then restoreRoots caller rights length t else
  if op == 22 then publishRoot caller rights length t else
  if (op == 25 || op == 32 || op == 33) && length != 96 then respond 2 0 0 0 t else
  if op != 25 && op != 32 && op != 33 && length != 64 then respond 2 0 0 0 t else
  if op == 20 || op == 21 then
    if !has rights 1 || !grantValid caller h 1 t then respond 3 0 0 0 t else
      let r := grantedRecord h t
      if load64 r t != 2 || load64 (r+224) t != 1 then respond 2 0 0 0 t else
        graphMetadata h r (load64 (capAt (h &&& 255)+32) t) t
  else if op == 23 then
    if !has rights 32 || load64 (command+16) t > 64 then respond 1 0 0 0 t else
      let slot := nextRoot caller (load64 (command+16) t) t
      if slot == error then respond 0 0 0 0 t else
        let root := ProjectGraph.rootHandle slot t
        rootReply root (ProjectGraph.grantedRoot root t) (slot+1) t
  else if !has rights 1 || !ProjectGraph.rootValid caller h 1 t then respond 3 0 0 0 t else
    let root := ProjectGraph.grantedRoot h t
    if op == 32 || op == 33 then
      let required := if op == 33 then 73 else 25
      let granted := if op == 33 then 89 else 25
      if op == 33 && (rights &&& 0x200000000) == 0 then respond 1 0 0 0 t else
      if !has rights 2 || !ProjectGraph.rootValid caller h required t || !equal (command+64) (root+128) 32 t then respond 8 0 0 0 t else
      if !admin rights && ProjectGraph.ownerRoots caller 1 0 0 t >= 2 then respond 4 0 0 0 t else
        let free := ProjectGraph.freeRoot 0 t
        let slot := ProjectGraph.freeRootCap 0 t
        if free == error || slot == error then respond 4 0 0 0 t else
          let r := ProjectGraph.rootAt free
          let generation := load64 (r+16) t+1
          let t := zero r 24 t
          let t := store64 r 1 t
          let t := store64 (r+8) caller t
          let t := store64 (r+16) generation t
          let t := store64 (r+40) (load64 (root+40) t) t
          let t := store64 (r+48) 1 t
          let t := copy (root+64) (r+64) 96 t
          let t := ProjectGraph.grantRoot slot caller r (rights &&& granted) t
          rootReply (ProjectGraph.rootHandle slot t) r (slot+1) t
    else if op == 29 then rootReply h root 0 t else
    if op == 31 then
      let target := load64 (command+16) t
      let c := ProjectGraph.rootCapAt (target &&& 255)
      if !has rights 16 || !ProjectGraph.rootValid caller h 16 t || target >>> 32 != load64 ProjectGraph.state t ||
         (target &&& 255) >= 64 || load64 c t != ((target >>> 8) &&& 0xffffff) ||
         load64 (c+16) t != (root-ProjectGraph.roots)/192 || load64 (c+24) t != load64 (root+16) t then respond 1 0 0 0 t
      else respond 0 0 0 0 (store64 (c+40) 0 (revokeRootObjects target 0 t))
    else if op == 27 then
      let target := load64 (command+16) t
      let requested := load64 (command+24) t
      let current := load64 (ProjectGraph.rootCapAt (h &&& 255)+32) t
      if !has rights 8 || !has current 8 || requested == 0 || requested > 127 || !has current requested then respond 1 0 0 0 t else
        let actual := syscall 34 target 0 0 0 t
        if actual == error || !has actual requested then respond 1 0 0 0 actual else
          let previous := existingRootGrant target root requested 0 actual
          let slot := if previous == error then ProjectGraph.freeRootCap 0 actual else previous
          if slot == error then respond 4 0 0 0 actual else
            let t := if previous == error then ProjectGraph.grantRoot slot target root requested actual else actual
            rootReply (ProjectGraph.rootHandle slot t) root (slot+1) t
    else if op == 28 then
      if !has rights 16 || !ProjectGraph.rootValid caller h 16 t || (load64 (root+8) t != caller && !admin rights) then respond 1 0 0 0 t else
        respond 0 0 0 0 (store64 root 0 (revokeRootGrants root 0 t))
    else
      let t := zero ProjectGraph.marks 64 t
      let t := ProjectGraph.markRoot root t
      let i := if op == 24 then ProjectGraph.findNode (root+128) 11 0 t else
        if op == 25 then ProjectGraph.findNode (command+64) 0 0 t else
        if op == 26 && load64 (command+16) t < 64 then ProjectGraph.nextMarked (load64 (command+16) t) t else error
      if i == error then
        if op == 26 then respond 0 0 0 0 t else respond 2 0 0 0 t
      else if !ProjectGraph.pinned i t then respond 1 0 0 0 t else grantGraphObject caller h i (i+1) t

def validReserved (op t : UInt64) : Bool :=
  let h := load64 (command+8) t
  let a := load64 (command+16) t
  let b := load64 (command+24) t
  let c := load64 (command+32) t
  let d := load64 (command+40) t
  let e := load64 (command+48) t
  if e != 0 then false else
  if op >= 20 && op <= 33 then true else
  if op == 1 then true else
  if c != 0 || d != 0 then false else
  if op == 4 || op == 6 || op == 14 then true else
  if b != 0 then false else
  if op == 2 || op == 7 then true else
  if op == 9 then h == 0 else
  if a != 0 then false else
  if op == 10 || op == 11 then h == 0 else true

def dispatch (caller rights length t : UInt64) : UInt64 :=
  if length < 64 || length > 1024 || load64 (command+56) t != 1 then respond 2 0 0 0 t else
    let op := load64 command t
    if !validReserved op t then respond 2 0 0 0 t else
    if op == 1 then beginObject caller rights length t
    else if op == 2 then appendObject caller rights length t
    else if op == 3 then commitObject caller rights length t
    else if op >= 20 && op <= 33 then graphDispatch op caller rights length t
    else if length != 64 then respond 2 0 0 0 t
    else if op == 4 then readObject caller rights 1 t
    else if op == 5 then metadataObject caller rights t
    else if op == 6 then shareObject caller rights t
    else if op == 7 then revokeObject caller rights t
    else if op == 8 then dropObject caller rights t
    else if op == 9 then listObjects caller rights t
    else if op == 10 then
      if has rights 32 then
        let count := ownedCount caller 0 t
        let bytes := reservedBytes caller 0 t
        let grants := capCount caller 0 t
        let t := respond 0 count 0 0 t
        let t := store64 (wire+16) bytes t
        64+store64 (wire+24) grants t
      else respond 1 0 0 0 t
    else if op == 11 then
      if admin rights then respond 0 0 0 0 (collectDead 0 (ProjectGraph.markAll (cleanDeadGrants 0 t))) else respond 1 0 0 0 t
    else if op == 12 then digestStage caller rights t
    else if op == 13 then abortStage caller rights t
    else if op == 14 then readObject caller rights 64 t
    else respond 7 0 0 0 t

partial def serve (t : UInt64) : UInt64 :=
  let n := receive 2 t
  if n == error then serve n else
    let caller := load64 incoming n
    let requestToken := load64 (incoming+8) n
    let rights := load64 (incoming+16) n
    let abi := load64 (incoming+24) n
    let length := if n >= 32 && abi == 2 then dispatch caller rights (n-32) n else respond 2 0 0 0 n
    let t := reply requestToken length length
    serve t

partial def initializeRecords (i t : UInt64) : UInt64 :=
  if i == 64 then t else initializeRecords (i+1) (zero (recordAt i) 32 t)

def main (initial : UInt64) : UInt64 :=
  let t := initializeRecords 0 (zero state 8192 initial)
  let currentInstance := self t
  let incarnation := (currentInstance >>> 8) &&& 0xffffff
  let epoch := ((currentInstance >>> 32)+incarnation) &&& 0xffffffff
  if incarnation == 0 then error else
    serve (ProjectGraph.startGraph epoch (store64 state epoch t))
end Guest.Objects
