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
    if load64 (c+40) t == 0 && load64 c t < 0xffffff then slot else
      let alive := if load64 (c+40) t == 1 then syscall 34 (load64 (c+8) t) 0 0 0 t else t
      if alive == error && load64 c alive < 0xffffff then
        Guest.Effects.effectValue slot (store64 (c+40) 0 alive)
      else findCap (slot+1) alive
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

partial def invalidate (i generation slot t : UInt64) : UInt64 :=
  if slot == 256 then t else
    let c := capAt slot
    let t := if load64 (c+16) t == i && load64 (c+24) t == generation then store64 (c+40) 0 t else t
    invalidate i generation (slot+1) t

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


def beginObject (caller rights length t : UInt64) : UInt64 :=
  let parent := load64 (command+8) t
  let n := load64 (command+16) t
  let kind := load64 (command+24) t
  let schema := load64 (command+32) t
  let derive := load64 (command+40) t
  if n > 65536 || kind < 1 || kind > 15 || schema != 1 ||
      !((length == 96 && derive == 0) || (length == 64 && derive == 1)) then respond 2 0 0 0 t
  else if (parent == 0 && !has rights 2) || (parent != 0 && (!has rights 4 || !grantValid caller parent 4 t)) then respond 1 0 0 0 t
  else if parent != 0 && load64 (grantedRecord parent t) t != 2 then respond 2 0 0 0 t
  else if parent != 0 && kind >= 10 && (load64 (grantedRecord parent t+224) t != 1 || load64 (grantedRecord parent t+40) t != kind) then respond 2 0 0 0 t
  else
    let count := ownedCount caller 0 t
    let reserved := reservedBytes caller 0 t
    if (!admin rights && (count >= (if kind >= 10 then 24 else 8) || reserved+n > (if kind >= 10 then 1048576 else 262144) || capCount caller 0 t >= 64)) then respond 4 0 0 0 t
    else
      let first := findRecord 0 t
      let t := if first == error then collectDead 0 (ProjectGraph.markAll (cleanDeadGrants 0 t)) else t
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


def graphMetadata (h r rights t : UInt64) : UInt64 :=
  let t := respond 0 h r rights t
  let t := store64 (wire+40) (ProjectGraph.nodeSchema r t) t
  let t := copy (r+160) (wire+64) 32 t
  128+copy (r+192) (wire+96) 32 t

def rootReply (h r cursor t : UInt64) : UInt64 :=
  let t := respond 0 h 0 0 t
  let t := store64 (wire+16) (load64 (r+40) t) t
  let t := store64 (wire+24) cursor t
  let t := store64 (wire+32) (load64 (r+8) t) t
  let t := store64 (wire+40) (load64 (r+48) t) t
  let t := store64 (wire+48) (load64 (ProjectGraph.rootCapAt (h &&& 255)+48) t) t
  let t := store64 (wire+56) (ProjectGraph.rootBinding r t) t
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
        if old != 0 && !equal (source+160) (r+128) 32 t && !equal (source+192) (r+128) 32 t then respond 8 0 0 0 t else
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
          let t := if old == 0 then ProjectGraph.grantRoot slot caller r (rights &&& 127) caller t else t
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

partial def existingRootGrant (caller root requested issuer slot t : UInt64) : UInt64 :=
  if slot == 64 then error else
    let c := ProjectGraph.rootCapAt slot
    if load64 (c+40) t == 1 && load64 (c+8) t == caller && load64 (c+16) t == (root-ProjectGraph.roots)/192 &&
      load64 (c+24) t == load64 (root+16) t && load64 (c+48) t == issuer && has (load64 (c+32) t) requested then slot
    else existingRootGrant caller root requested issuer (slot+1) t
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
    let t := ProjectGraph.grantRoot slot caller r (rights &&& 127) caller t
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
      if !admin rights && ProjectGraph.ownerRoots caller 1 0 0 t >= (if op == 33 then 4 else 2) then respond 4 0 0 0 t else
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
          let t := store64 (r+24) (ProjectGraph.rootBinding root t) t
          let t := copy (root+64) (r+64) 96 t
          let t := ProjectGraph.grantRoot slot caller r (rights &&& granted) caller t
          rootReply (ProjectGraph.rootHandle slot t) r (slot+1) t
    else if op == 34 then
      let origin := ProjectGraph.projectOrigin (ProjectGraph.findNode (root+128) 11 0 t) 64 t
      if origin == error then respond 2 0 0 0 t else
        let t := rootReply h root 0 t
        192+copy (ProjectGraph.logicalIdAt (recordAt origin) t) (wire+160) 32 t
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
          let previous := existingRootGrant target root requested caller 0 actual
          let slot := if previous == error then ProjectGraph.freeRootCap 0 actual else previous
          if slot == error then respond 4 0 0 0 actual else
            let t := if previous == error then ProjectGraph.grantRoot slot target root requested caller actual else actual
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

-- Transactional graph import v1. Private stages have no Object capabilities.
-- The caller supplies opaque records in any order; dependency ordering, closure
-- checking and all-or-nothing root publication are entirely guest operations.
def importBase : UInt64 := 0xd70000
def importAt (i : UInt64) : UInt64 := importBase+i*2048
def importHandle (i t : UInt64) : UInt64 :=
  (load64 state t <<< 32) ||| (load64 (importAt i+8) t <<< 8) ||| i
def importValid (caller h t : UInt64) : Bool :=
  (h &&& 255) < 4 && h >>> 32 == load64 state t &&
  load64 (importAt (h &&& 255)) t == 1 && load64 (importAt (h &&& 255)+16) t == caller &&
  ((h >>> 8) &&& 0xffffff) == load64 (importAt (h &&& 255)+8) t
partial def eraseImportRecords (j i t : UInt64) : UInt64 :=
  if i == load64 (j+32) t then t else
    let r := recordAt (load64 (j+832+i*8) t)
    let t := zero (r+256) (load64 (r+32) t/8+1) t
    let t := store64 r 0 t
    eraseImportRecords j (i+1) t
def eraseImport (j t : UInt64) : UInt64 :=
  store64 j 0 (store64 ProjectGraph.importScope 0 (eraseImportRecords j 0 t))
partial def freeImport (i t : UInt64) : UInt64 :=
  if i == 4 then error else
    let j := importAt i
    if load64 j t == 0 && load64 (j+8) t < 0xffffff then Guest.Effects.effectValue i t else
      let alive := syscall 34 (load64 (j+16) t) 0 0 0 t
      if alive == error && load64 (j+8) alive < 0xffffff then Guest.Effects.effectValue i (eraseImport j alive)
      else freeImport (i+1) alive
partial def importNames (caller i count t : UInt64) : Bool :=
  if i == count then true else
    let e := command+64+i*128
    let n := load64 (e+8) t
    load64 e t == 0 && ProjectGraph.validName (e+48) n 63 t &&
      ProjectGraph.allZero (e+48+n) (80-n) t && !ProjectGraph.allZero (e+16) 32 t &&
      validRestoreNames e i t && !ProjectGraph.duplicateRoot caller (e+48) n 0 0 t && importNames caller (i+1) count t

def beginImport (caller rights length t : UInt64) : UInt64 :=
  let count := load64 (command+16) t
  let nodes := load64 (command+24) t
  let bytes := load64 (command+32) t
  if !has rights 6 then respond 1 0 0 0 t else
  if count == 0 || count > 6 || nodes == 0 || nodes > 64 || bytes > 4194304 || length != 64+count*128 ||
    (!admin rights && (rights &&& 0x400000000) == 0 && (count > 4 || nodes > 24 || bytes > 1048576 || ProjectGraph.ownerRoots caller 0 0 0 t+count > 4)) then respond 4 0 0 0 t else
  if !importNames caller 0 count t then respond 2 0 0 0 t else
    let slot := freeImport 0 t
    if slot == error then respond 4 0 0 0 t else
      let j := importAt slot
      let generation := load64 (j+8) slot+1
      let t := zero j 256 slot
      let t := store64 j 1 t
      let t := store64 (j+8) generation t
      let t := store64 (j+16) caller t
      let t := store64 (j+24) nodes t
      let t := store64 (j+48) bytes t
      let t := store64 (j+56) count t
      let t := copy (command+64) (j+64) (count*128) t
      respond 0 (importHandle slot t) 0 0 t

partial def duplicateImportId (j id i t : UInt64) : Bool :=
  if i == load64 (j+32) t then false else
    equal (recordAt (load64 (j+832+i*8) t)+160) id 32 t || duplicateImportId j id (i+1) t

def offerImport (caller h length t : UInt64) : UInt64 :=
  let j := importAt (h &&& 255)
  let index := load64 (command+16) t
  let kind := load64 (command+24) t
  let n := load64 (command+32) t
  let schema := if load64 (command+40) t == 0 then 1 else load64 (command+40) t
  if length != 160 || index != load64 (j+32) t || index >= load64 (j+24) t || kind < 10 || kind > 15 || n > 65536 ||
    (schema != 1 && schema != 2) || (schema == 2 && kind != 10 && kind != 11) ||
    n > load64 (j+48) t-load64 (j+40) t || duplicateImportId j (command+64) 0 t then respond 2 0 0 0 (eraseImport j t) else
    let i := findRecord 0 t
    if i == error then respond 4 0 0 0 (eraseImport j t) else
      let r := recordAt i
      let generation := load64 (r+16) t+1
      let t := zero r 32 t
      let t := store64 r 3 t
      let t := store64 (r+8) caller t
      let t := store64 (r+16) generation t
      let t := store64 (r+32) n t
      let t := store64 (r+40) kind t
      let t := store64 (r+64) h t
      let t := store64 (r+232) schema t
      let t := copy (command+64) (r+160) 64 t
      let t := copy (command+128) (r+96) 32 t
      let t := store64 (j+832+index*8) i t
      let t := store64 (j+32) (index+1) t
      let t := store64 (j+40) (load64 (j+40) t+n) t
      respond 0 index 0 0 t

def appendImport (h length t : UInt64) : UInt64 :=
  let j := importAt (h &&& 255)
  let index := load64 (command+16) t
  let offset := load64 (command+24) t
  let n := length-64
  if index >= load64 (j+32) t || length < 64 || n > 512 then respond 2 0 0 0 (eraseImport j t) else
    let r := recordAt (load64 (j+832+index*8) t)
    if load64 r t != 3 || offset != load64 (r+24) t || offset > load64 (r+32) t || n > load64 (r+32) t-offset then respond 2 0 0 0 (eraseImport j t) else
      let t := copy (command+64) (r+256+offset) n t
      let t := store64 (r+24) (offset+n) t
      let t := store64 (j+1344) (load64 (j+1344) t+n) t
      respond 0 (offset+n) 0 0 t

-- A pass seals only records whose typed references and predecessor are already
-- validated in this transaction or visible through the caller's current grants.
partial def sealImportPass (caller j i progress t : UInt64) : UInt64 :=
  if i == load64 (j+32) t then Guest.Effects.effectValue progress t else
    let r := recordAt (load64 (j+832+i*8) t)
    if load64 r t == 4 then sealImportPass caller j (i+1) progress t else
    if load64 (r+24) t != load64 (r+32) t then error else
      let t := ServiceHash.sha256At hashScratch (r+256) (load64 (r+32) t) (r+128) t
      if !equal (r+128) (r+96) 32 t then error else
      let parent := if ProjectGraph.nodeSchema r t == 2 || ProjectGraph.allZero (r+192) 32 t then 0 else ProjectGraph.findVisibleNode caller (r+192) (load64 (r+40) t) 0 t
      if parent == error then sealImportPass caller j (i+1) progress t else
        let t := copy (r+160) hashResult 32 t
        let sealed := ProjectGraph.sealNode caller r t
        if sealed == error then sealImportPass caller j (i+1) progress t else
          if !equal hashResult (r+160) 32 sealed then error else
            sealImportPass caller j (i+1) (progress+1) (store64 r 4 sealed)
partial def sealImport (caller j remaining t : UInt64) : UInt64 :=
  if remaining == 0 then t else
    let progress := sealImportPass caller j 0 0 t
    if progress == error || progress == 0 || progress > remaining then error else sealImport caller j (remaining-progress) progress
partial def importSelected (caller j i t : UInt64) : UInt64 :=
  if i == load64 (j+56) t then t else
    let e := j+64+i*128
    let found := ProjectGraph.findVisibleNode caller (e+16) 11 0 t
    if found == error || ProjectGraph.duplicateRoot caller (e+48) (load64 (e+8) t) 0 0 t then error else
      let t := ProjectGraph.markNode found 64 t
      importSelected caller j (i+1) t
partial def importInScope (j i t : UInt64) : Bool :=
  if i == load64 (j+32) t then true else
    ProjectGraph.pinned (load64 (j+832+i*8) t) t && importInScope j (i+1) t
partial def commitImportRecords (j i t : UInt64) : UInt64 :=
  if i == load64 (j+32) t then t else
    commitImportRecords j (i+1) (store64 (recordAt (load64 (j+832+i*8) t)) 2 t)
partial def commitImportRoots (caller rights j i t : UInt64) : UInt64 :=
  if i == load64 (j+56) t then 64+i*8+t else
    let e := j+64+i*128
    let r := ProjectGraph.rootAt (ProjectGraph.freeRoot 0 t)
    let slot := ProjectGraph.freeRootCap 0 t
    let generation := load64 (r+16) t+1
    let t := zero r 24 t
    let t := store64 r 1 t
    let t := store64 (r+8) caller t
    let t := store64 (r+16) generation t
    let t := store64 (r+40) (load64 (e+8) t) t
    let t := copy (e+48) (r+64) 64 t
    let t := copy (e+16) (r+128) 32 t
    let t := ProjectGraph.grantRoot slot caller r (rights &&& 127) caller t
    let t := store64 (wire+64+i*8) (ProjectGraph.rootHandle slot t) t
    commitImportRoots caller rights j (i+1) t

def finishImport (caller rights h t : UInt64) : UInt64 :=
  let j := importAt (h &&& 255)
  let count := load64 (j+56) t
  if load64 (j+32) t != load64 (j+24) t || load64 (j+40) t != load64 (j+48) t ||
    freeRootsCount 0 0 t < count || freeRootCapsCount 0 0 t < count then respond 4 0 0 0 (eraseImport j t) else
    let checked := sealImport caller j (load64 (j+32) t) (store64 ProjectGraph.importScope h t)
    if checked == error then respond 2 0 0 0 (eraseImport j checked) else
      let checked := importSelected caller j 0 (zero ProjectGraph.marks 64 checked)
      if checked == error || !ProjectGraph.importCommitAllowed (importInScope j 0 checked) (ProjectGraph.markedComplete 0 checked) then respond 2 0 0 0 (eraseImport j checked) else
        let t := commitImportRecords j 0 checked
        let t := store64 ProjectGraph.importScope 0 t
        let t := respond 0 count 0 0 t
        let result := commitImportRoots caller rights j 0 t
        Guest.Effects.effectValue result (store64 j 0 result)

def importDispatch (op caller rights length t : UInt64) : UInt64 :=
  let h := load64 (command+8) t
  if op == 35 then beginImport caller rights length t else
  if !importValid caller h t then respond 3 0 0 0 t else
  if op == 36 then offerImport caller h length t else
  if op == 37 then appendImport h length t else
  if length != 64 then respond 2 0 0 0 t else
  if op == 38 then finishImport caller rights h t else
  if op == 39 then respond 0 0 0 0 (eraseImport (importAt (h &&& 255)) t) else
    let j := importAt (h &&& 255)
    let t := respond 0 h 0 0 t
    let t := store64 (wire+16) (load64 (j+32) t) t
    let t := store64 (wire+24) (load64 (j+24) t) t
    let t := store64 (wire+32) (load64 (j+1344) t) t
    64+store64 (wire+40) (load64 (j+48) t) t

-- Checkpoint-v2 is an explicit source-only history transaction. It keeps signed
-- origin/archive commitments and current file bytes, while schema1 ancestry and
-- every other named/frozen root remain unchanged. No predecessor is zeroed.
def checkpointTxn : UInt64 := 0xd74000
def checkpointMarks : UInt64 := 0xd75000
def checkpointOriginal : UInt64 := 0xd76000

def checkpointRecord (caller source kind scope j t : UInt64) : UInt64 :=
  let i := findRecord 0 t
  if i == error then error else
    let r := recordAt i
    let generation := load64 (r+16) t+1
    let t := zero r 32 t
    let t := store64 r 3 t
    let t := store64 (r+8) caller t
    let t := store64 (r+16) generation t
    let t := store64 (r+40) kind t
    let t := store64 (r+64) scope t
    let t := store64 (r+232) 2 t
    let t := if source == 0 then t else copy (source+160) (r+192) 32 t
    let count := load64 (j+32) t
    let t := store64 (j+832+count*8) i t
    Guest.Effects.effectValue r (store64 (j+32) (count+1) t)
partial def checkpointFiles (caller old fresh scope index count bytes t : UInt64) : UInt64 :=
  if index == load64 (old+272) t then
    if count == 0 || count > 24 || bytes > 1048576 then error else
      let t := store64 (fresh+272) count t
      store64 (fresh+280) 128 t
  else
    let e := old+288+index*128
    if load64 e t == 15 then
      if load64 (checkpointTxn+48) t != 1 then checkpointFiles caller old fresh scope (index+1) count bytes t else
        checkpointFiles caller old fresh scope (index+1) (count+1) bytes (copy e (fresh+288+count*128) 128 t)
    else if load64 e t != 10 then checkpointFiles caller old fresh scope (index+1) count bytes t else
      let found := ProjectGraph.findNode (e+16) 10 0 t
      if found == error then error else
        let source := recordAt found
        let r := checkpointRecord caller source 10 scope checkpointTxn t
        if r == error then error else
          let n := load64 (source+32) r
          let t := store64 (r+32) n r
          let t := store64 (r+24) n t
          let t := copy (source+256) (r+256) n t
          let t := copy (source+128) (r+128) 32 t
          let sealed := ProjectGraph.sealNode caller r t
          if sealed == error then error else
            let t := store64 r 4 sealed
            let to := fresh+288+count*128
            let t := copy e to 128 t
            let t := copy (r+160) (to+16) 32 t
            checkpointFiles caller old fresh scope (index+1) (count+1) (bytes+n) t
partial def foreignRecordGrant (i caller slot t : UInt64) : Bool :=
  if slot == 256 then false else
    let c := capAt slot
    (load64 (c+40) t == 1 && load64 (c+16) t == i && load64 (c+24) t == load64 (recordAt i+16) t && load64 (c+8) t != caller) || foreignRecordGrant i caller (slot+1) t
partial def reclaimCheckpoint (caller i count t : UInt64) : UInt64 :=
  if i == 64 then Guest.Effects.effectValue count t else
    let r := recordAt i
    if load64 (checkpointMarks+i*8) t == 1 && !ProjectGraph.pinned i t && load64 (r+8) t == caller && !foreignRecordGrant i caller 0 t then
      let t := invalidate i (load64 (r+16) t) 0 t
      let t := zero (r+256) (load64 (r+32) t/8+1) t
      reclaimCheckpoint caller (i+1) (count+1) (store64 r 0 t)
    else reclaimCheckpoint caller (i+1) count t

def checkpointRoot (caller rights length t : UInt64) : UInt64 :=
  let h := load64 (command+8) t
  if length != 96 || load64 (command+16) t != 1 || !has rights 22 || !ProjectGraph.rootValid caller h 20 t then respond 1 0 0 0 t else
    let root := ProjectGraph.grantedRoot h t
    if load64 (root+48) t != 0 || !equal (command+64) (root+128) 32 t then respond 8 0 0 0 t else
      let found := ProjectGraph.findNode (root+128) 11 0 t
      let origin := ProjectGraph.projectOrigin found 64 t
      if found == error || origin == error then respond 2 0 0 0 t else
        let old := recordAt found
        let j := checkpointTxn
        let t := store64 (j+48) 1 (zero j 256 t)
        let t := copy (root+128) checkpointOriginal 32 t
        let t := copy (ProjectGraph.logicalIdAt (recordAt origin) t) (checkpointOriginal+32) 32 t
        let originHash := if ProjectGraph.nodeSchema (recordAt origin) t == 2 then ProjectGraph.checkpointDetail (recordAt origin) t+48 else recordAt origin+128
        let t := copy originHash (checkpointOriginal+64) 32 t
        let t := ProjectGraph.markRoot root (zero ProjectGraph.marks 64 t)
        let t := copy ProjectGraph.marks checkpointMarks 512 t
        let scope := ProjectGraph.rootBinding root t
        let t := store64 ProjectGraph.importScope scope t
        let fresh := checkpointRecord caller old 11 scope j t
        if fresh == error then respond 4 0 0 0 (eraseImport j fresh) else
          let copied := checkpointFiles caller old fresh scope 0 0 0 fresh
          if copied == error then respond 4 0 0 0 (eraseImport j copied) else
            let t := store64 (fresh+256) 0x31464e4d544c copied
            let t := store64 (fresh+264) 2 t
            let n := 32+load64 (fresh+272) t*128+128
            let t := store64 (fresh+32) n t
            let t := store64 (fresh+24) n t
            let d := ProjectGraph.checkpointDetail fresh t
            let t := zero d 16 t
            let t := store64 d 0x3254504b4843544c t
            let t := store64 (d+8) 2 t
            let t := copy (checkpointOriginal+32) (d+16) 32 t
            let t := copy (checkpointOriginal+64) (d+48) 32 t
            let t := copy checkpointOriginal (d+80) 32 t
            let t := store64 (d+112) 1 t
            let t := ServiceHash.sha256At hashScratch (fresh+256) n (fresh+128) t
            let sealed := ProjectGraph.sealNode caller fresh t
            if sealed == error then respond 2 0 0 0 (eraseImport j sealed) else
              let t := store64 fresh 4 sealed
              let t := commitImportRecords j 0 t
              let t := copy (fresh+160) (root+128) 32 t
              let t := store64 ProjectGraph.importScope 0 t
              let reclaimed := reclaimCheckpoint caller 0 0 (ProjectGraph.markAll t)
              let t := rootReply h root 0 reclaimed
              let t := copy (checkpointOriginal+32) (wire+160) 32 t
              let t := copy checkpointOriginal (wire+192) 32 t
              let t := store64 (wire+224) (load64 (j+32) t) t
              let t := store64 (wire+232) reclaimed t
              let t := store64 (wire+240) 1 t
              256+store64 (wire+248) 2 t

partial def sortForkEntries (r count i j t : UInt64) : UInt64 :=
  if i >= count then t else
  if j >= count then sortForkEntries r count (i+1) (i+2) t else
    let a := r+288+i*128
    let b := r+288+j*128
    let t := if ProjectGraph.lessName (b+48) (load64 (b+8) t) (a+48) (load64 (a+8) t) 0 t then
      let t := copy a (checkpointOriginal+256) 128 t
      let t := copy b a 128 t
      copy (checkpointOriginal+256) b 128 t else t
    sortForkEntries r count i (j+1) t

-- Only a Release directly selected by this immutable Manifest names the fork
-- point. Sealed typed records have already passed checkRelease; archival parents
-- and arbitrary incoming display claims never supply the release commitment.
partial def selectedForkRelease (manifest index found t : UInt64) : UInt64 :=
  if index == load64 (manifest+272) t then Guest.Effects.effectValue found t else
    let e := manifest+288+index*128
    if load64 e t != 13 then selectedForkRelease manifest (index+1) found t else
    if found != error then error else
      let node := ProjectGraph.findNode (e+16) 13 0 t
      if node == error then error else
        let r := recordAt node
        if load64 (r+224) t != 1 || ProjectGraph.nodeSchema r t != 1 ||
          load64 (r+32) t < 1376 || load64 (r+272) t != 4 || load64 (r+280) t < 832 ||
          load64 (r+800) t != 0x31544e43524c544c || load64 (r+808) t != 1 ||
          load64 (r+816) t != 768 || load64 (r+864) t != 0x3253454c544c || load64 (r+872) t != 2 then error else
            selectedForkRelease manifest (index+1) r t

def forkRoot (caller rights length t : UInt64) : UInt64 :=
  let h := load64 (command+8) t
  let n := load64 (command+16) t
  if length != 192 || !has rights 6 || !ProjectGraph.rootValid caller h 1 t then respond 1 0 0 0 t else
  if !ProjectGraph.validName (command+128) n 63 t || !ProjectGraph.allZero (command+128+n) (64-n) t || ProjectGraph.allZero (command+96) 32 t ||
    ProjectGraph.duplicateRoot caller (command+128) n 0 0 t then respond 2 0 0 0 t else
    let root := ProjectGraph.grantedRoot h t
    let oldIndex := ProjectGraph.findNode (root+128) 11 0 t
    let origin := ProjectGraph.projectOrigin oldIndex 64 t
    let slot := ProjectGraph.freeRootCap 0 t
    let free := ProjectGraph.freeRoot 0 t
    if oldIndex == error || origin == error || !equal (command+64) (root+128) 32 t then respond 8 0 0 0 t else
    if slot == error || free == error || (!admin rights && ProjectGraph.ownerRoots caller 0 0 0 t >= 4) then respond 4 0 0 0 t else
      let old := recordAt oldIndex
      let j := checkpointTxn
      let t := zero j 256 t
      let t := copy (root+128) checkpointOriginal 32 t
      let t := copy (ProjectGraph.logicalIdAt (recordAt origin) t) (checkpointOriginal+32) 32 t
      let upstreamRelease := selectedForkRelease old 0 error t
      let t := zero (checkpointOriginal+64) 4 t
      let t := if upstreamRelease == error then t else copy (upstreamRelease+1024) (checkpointOriginal+64) 32 t
      let t := copy (command+96) (checkpointOriginal+96) 32 t
      let entropy := syscall 111 0 (checkpointOriginal+128) 32 0 t
      if entropy != 0 then respond 7 0 0 0 entropy else
        let scope := ProjectGraph.rootBinding root entropy
        let t := store64 ProjectGraph.importScope scope entropy
        let fresh := checkpointRecord caller 0 11 scope j t
        if fresh == error then respond 4 0 0 0 (eraseImport j fresh) else
          let copied := checkpointFiles caller old fresh scope 0 0 0 fresh
          if copied == error then respond 4 0 0 0 (eraseImport j copied) else
            let lineage := checkpointRecord caller 0 15 scope j copied
            if lineage == error then respond 4 0 0 0 (eraseImport j lineage) else
              let t := store64 (lineage+232) 1 lineage
              let t := store64 (lineage+32) 208 t
              let t := store64 (lineage+24) 208 t
              let t := store64 (lineage+256) 0x31464e4d544c t
              let t := store64 (lineage+264) 1 t
              let t := store64 (lineage+280) 176 t
              let d := lineage+288
              let t := store64 d 0x314b524f46544c t
              let t := store64 (d+8) 1 t
              let t := copy (checkpointOriginal+32) (d+16) 32 t
              let t := copy checkpointOriginal (d+48) 32 t
              let t := copy (checkpointOriginal+64) (d+80) 32 t
              let t := copy (checkpointOriginal+96) (d+112) 32 t
              let t := copy (checkpointOriginal+128) (d+144) 32 t
              let t := ServiceHash.sha256At hashScratch (lineage+256) 208 (lineage+128) t
              let sealed := ProjectGraph.sealNode caller lineage t
              if sealed == error then respond 2 0 0 0 (eraseImport j sealed) else
                let t := store64 lineage 4 sealed
                let count := load64 (fresh+272) t
                let e := fresh+288+count*128
                let t := zero e 16 t
                let t := store64 e 15 t
                let t := store64 (e+8) 5 t
                let t := copy (lineage+160) (e+16) 32 t
                let t := store64 (e+48) 0x6b726f662e t
                let t := store64 (fresh+232) 1 t
                let t := store64 (fresh+256) 0x31464e4d544c t
                let t := store64 (fresh+264) 1 t
                let t := store64 (fresh+272) (count+1) t
                let t := store64 (fresh+280) 0 t
                let bytes := 32+(count+1)*128
                let t := store64 (fresh+32) bytes t
                let t := store64 (fresh+24) bytes t
                let t := sortForkEntries fresh (count+1) 0 1 t
                let t := ServiceHash.sha256At hashScratch (fresh+256) bytes (fresh+128) t
                let sealed := ProjectGraph.sealNode caller fresh t
                if sealed == error then respond 2 0 0 0 (eraseImport j sealed) else
                  let t := commitImportRecords j 0 (store64 fresh 4 sealed)
                  let r := ProjectGraph.rootAt free
                  let generation := load64 (r+16) t+1
                  let t := zero r 24 t
                  let t := store64 r 1 t
                  let t := store64 (r+8) caller t
                  let t := store64 (r+16) generation t
                  let t := store64 (r+40) n t
                  let t := copy (command+128) (r+64) n t
                  let t := copy (fresh+160) (r+128) 32 t
                  let t := ProjectGraph.grantRoot slot caller r (rights &&& 127) caller t
                  let t := store64 ProjectGraph.importScope 0 t
                  let t := rootReply (ProjectGraph.rootHandle slot t) r 0 t
                  let t := copy (lineage+160) (wire+160) 32 t
                  let t := copy (checkpointOriginal+32) (wire+192) 32 t
                  256+copy checkpointOriginal (wire+224) 32 t

def validReserved (op t : UInt64) : Bool :=
  let h := load64 (command+8) t
  let a := load64 (command+16) t
  let b := load64 (command+24) t
  let c := load64 (command+32) t
  let d := load64 (command+40) t
  let e := load64 (command+48) t
  if e != 0 then false else
  if op >= 20 && op <= 42 then true else
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
    else if op == 41 then checkpointRoot caller rights length t
    else if op == 42 then forkRoot caller rights length t
    else if op >= 35 && op <= 40 then importDispatch op caller rights length t
    else if op >= 20 && op <= 34 then graphDispatch op caller rights length t
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
  let t := zero importBase 1024 (initializeRecords 0 (zero state 8192 initial))
  let currentInstance := self t
  let incarnation := (currentInstance >>> 8) &&& 0xffffff
  let epoch := ((currentInstance >>> 32)+incarnation) &&& 0xffffffff
  if incarnation == 0 then error else
    serve (ProjectGraph.startGraph epoch (store64 state epoch t))
end Guest.Objects
