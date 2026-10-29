import Guest.LiveSDK
import Guest.ServiceHash
import Guest.Policy
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
  if n > 65536 || kind < 1 || kind > 9 || schema != 1 ||
      !((length == 96 && derive == 0) || (length == 64 && derive == 1)) then respond 2 0 0 0 t
  else if (parent == 0 && !has rights 2) || (parent != 0 && (!has rights 4 || !grantValid caller parent 4 t)) then respond 1 0 0 0 t
  else if parent != 0 && load64 (grantedRecord parent t) t != 2 then respond 2 0 0 0 t
  else
    let count := ownedCount caller 0 t
    let reserved := reservedBytes caller 0 t
    if (!admin rights && (count >= 8 || reserved+n > 262144 || capCount caller 0 t >= 32)) then respond 4 0 0 0 t
    else
      let i := findRecord 0 t
      let slot := findCap 0 t
      if i == error || slot == error then respond 4 0 0 0 t else
        let r := recordAt i
        let generation := load64 (r+16) t+1
        let parentId := if parent == 0 then 0 else objectId (grantedRecord parent t) t
        let t := zero r 32 t
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
        let t := store64 r 2 t
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
      if alive == error && !survivingGrant i (load64 (r+16) alive) 0 alive then
        let t := invalidate i (load64 (r+16) alive) 0 alive
        store64 r 0 t
      else alive
    else t
    collectDead (i+1) t

def validReserved (op t : UInt64) : Bool :=
  let h := load64 (command+8) t
  let a := load64 (command+16) t
  let b := load64 (command+24) t
  let c := load64 (command+32) t
  let d := load64 (command+40) t
  let e := load64 (command+48) t
  if e != 0 then false else
  if op == 1 then true else
  if c != 0 || d != 0 then false else
  if op == 4 || op == 6 || op == 14 then true else
  if b != 0 then false else
  if op == 2 || op == 7 then true else
  if op == 9 then h == 0 else
  if a != 0 then false else
  if op == 10 || op == 11 then h == 0 else true

def dispatch (caller rights length t : UInt64) : UInt64 :=
  if length < 64 || length > 576 || load64 (command+56) t != 1 then respond 2 0 0 0 t else
    let op := load64 command t
    if !validReserved op t then respond 2 0 0 0 t else
    if op == 1 then beginObject caller rights length t
    else if op == 2 then appendObject caller rights length t
    else if op == 3 then commitObject caller rights length t
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
      if admin rights then respond 0 0 0 0 (collectDead 0 (cleanDeadGrants 0 t)) else respond 1 0 0 0 t
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
    serve (store64 state epoch t)
end Guest.Objects
