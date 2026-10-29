import Guest.LiveSDK
import Guest.ProjectSDK
import Guest.ProjectGraph
import Guest.ServiceHash
import Guest.VaultCrypto
namespace Guest.ProjectVault
open Guest.LiveSDK
-- Version2 is additive: v1 roots/banks are never reformatted. Two5MiB banks
-- contain independently authenticated4096-byte records and an encrypted index.
def state : UInt64 := 0x670000
def index : UInt64 := 0x680000
def staged : UInt64 := 0x684000
def cipher : UInt64 := 0x688000
def blockPlain : UInt64 := 0x68d000
def aad : UInt64 := 0x68e000
def nonce : UInt64 := 0x68e200
def rootA : UInt64 := 0x68f000
def rootB : UInt64 := 0x68f200
def current : UInt64 := 0x68f400
def candidate : UInt64 := 0x68f600
def selected : UInt64 := 0x690000
def handles : UInt64 := 0x690100
def recordPlain : UInt64 := 0x700000
def key : UInt64 := 0x620080
def hashScratch : UInt64 := 0x600200
def hashResult : UInt64 := 0x690400
def magic : UInt64 := 0x32564a4f5250544c
def bankSector (bank : UInt64) : UInt64 := 512+bank*10240
def rootAt (base i : UInt64) : UInt64 := base+32+i*128
def nodeAt (base i : UInt64) : UInt64 := base+2080+i*192
def indexLength : UInt64 := 14368
def nodeSchema (n t : UInt64) : UInt64 := if load64 (n+128) t == 2 then 2 else 1

def device (op sector ptr bytes t : UInt64) : UInt64 := syscall op sector ptr bytes 0 t
partial def transfer (op sector ptr remaining t : UInt64) : UInt64 :=
  if remaining == 0 then t else
    let n := if remaining < 4096 then remaining else 4096
    let t := if op == 61 then copy ptr chunk n t else t
    let result := device op sector chunk n t
    if result != 0 then error else
      let t := if op == 60 then copy chunk ptr n result else result
      transfer op (sector+n/512) (ptr+n) (remaining-n) t

def response (status value t : UInt64) : UInt64 :=
  let t := zero wire 8 t
  let t := store64 wire status t
  let t := store64 (wire+8) value t
  let t := store64 (wire+16) (load64 (state+16) t) t
  let t := store64 (wire+24) (load64 (state+24) t) t
  let t := store64 (wire+32) (load64 (state+32) t) t
  let t := store64 (wire+40) (load64 state t) t
  let t := store64 (wire+48) 2 t
  64+store64 (wire+56) (load64 (state+8) t) t

def clear (t : UInt64) : UInt64 := zero state 81920 t

def makeNonce (root part t : UInt64) : UInt64 :=
  let t := copy (root+96) nonce 12 t
  let n := load8 (nonce+8) t+load8 (nonce+9) t*256+load8 (nonce+10) t*65536+load8 (nonce+11) t*16777216+part
  let t := store8 (nonce+8) (n &&& 255) t
  let t := store8 (nonce+9) ((n >>> 8) &&& 255) t
  let t := store8 (nonce+10) ((n >>> 16) &&& 255) t
  store8 (nonce+11) ((n >>> 24) &&& 255) t

def chunkAAD (root node part count t : UInt64) : UInt64 :=
  let t := copy root aad 128 t
  let t := copy (node+16) (aad+128) 32 t
  let t := store64 (aad+160) part t
  store64 (aad+168) count t

partial def uniqueNodes (base id i t : UInt64) : Bool :=
  if i == 0 then true else !ProjectGraph.equal (nodeAt base (i-1)+16) id 32 t && uniqueNodes base id (i-1) t
partial def validNodes (base i count chunks bytes t : UInt64) : Bool :=
  if i == count then chunks == load64 (current+64) t && bytes == load64 (current+72) t else
    let n := nodeAt base i
    let len := load64 (n+8) t
    let blocks := (len+4095)/4096
    load64 n t >= 10 && load64 n t <= 15 && len <= 65536 && !ProjectGraph.allZero (n+16) 32 t &&
      load64 (n+112) t == chunks && load64 (n+120) t == blocks && chunks+blocks <= 1024 &&
      load64 (n+128) t <= 2 && ProjectGraph.allZero (n+136) 56 t && uniqueNodes base (n+16) i t && validNodes base (i+1) count (chunks+blocks) (bytes+len) t
partial def findNode (base id kind i count t : UInt64) : UInt64 :=
  if i == count then error else
    let n := nodeAt base i
    if (kind == 0 || load64 n t == kind) && ProjectGraph.equal id (n+16) 32 t then i else findNode base id kind (i+1) count t
partial def uniqueRoot (base r i t : UInt64) : Bool :=
  if i == 0 then true else
    let other := rootAt base (i-1)
    !(load64 other t == load64 r t && ProjectGraph.equal (other+40) (r+40) (load64 r t) t) && uniqueRoot base r (i-1) t
partial def validRoots (base i count nodes t : UInt64) : Bool :=
  if i == count then true else
    let r := rootAt base i
    let n := load64 r t
    ProjectGraph.validName (r+40) n 63 t && ProjectGraph.allZero (r+40+n) (88-n) t && uniqueRoot base r i t &&
      findNode base (r+8) 11 0 nodes t != error && validRoots base (i+1) count nodes t

def validIndex (t : UInt64) : Bool :=
  load64 index t == magic && load64 (index+8) t == 2 && load64 (index+16) t == load64 (current+48) t &&
  load64 (index+24) t == load64 (current+56) t && load64 (index+16) t <= 64 && load64 (index+24) t <= 6 &&
    validNodes index 0 (load64 (index+16) t) 0 0 t && validRoots index 0 (load64 (index+24) t) (load64 (index+16) t) t &&
    ProjectGraph.allZero (index+32+load64 (index+24) t*128) (2048-load64 (index+24) t*128) t &&
    ProjectGraph.allZero (nodeAt index (load64 (index+16) t)) ((64-load64 (index+16) t)*192) t

def validRoot (r t : UInt64) : Bool :=
  load64 r t == magic && load64 (r+8) t == 2 && load64 (r+16) t == 3 && load64 (r+24) t > 0 &&
  load64 (r+32) t == load64 (r+24) t%2 && load64 (r+40) t == indexLength &&
  load64 (r+48) t > 0 && load64 (r+48) t <= 64 && load64 (r+56) t > 0 && load64 (r+56) t <= 6 &&
  load64 (r+64) t <= 1024 && load64 (r+72) t <= 4194304 && ProjectGraph.allZero (r+80) 16 t &&
  ProjectGraph.allZero (r+108) 20 t && ProjectGraph.allZero (r+176) 336 t

def tryRoot (r t : UInt64) : UInt64 :=
  if !validRoot r t then error else
    let t := copy r current 512 t
    let read := transfer 60 (bankSector (load64 (r+32) t)) cipher 14848 t
    if read != 0 || !ProjectGraph.equal (cipher+indexLength) (r+128) 16 read then error else
      let t := ServiceHash.sha256At hashScratch cipher indexLength hashResult read
      if !ProjectGraph.equal hashResult (r+144) 32 t then error else
        let t := makeNonce current 0 t
        let decrypted := VaultCrypto.decrypt key nonce current 128 cipher indexLength index t
        if decrypted != 0 || !validIndex decrypted then error else
          let t := store64 (state+8) (load64 (current+24) decrypted) decrypted
          let t := store64 (state+16) (load64 (current+48) t) t
          let t := store64 (state+24) (load64 (current+56) t) t
          let t := store64 (state+32) (load64 (current+72) t) t
          store64 state 1 t

def scan (t : UInt64) : UInt64 :=
  let t := store64 (state+56) 0 t
  let t := store64 (state+40) 0 t
  let a := transfer 60 2 rootA 512 t
  if a != 0 then error else
    let b := transfer 60 3 rootB 512 a
    if b != 0 then error else
      let high := if load64 (rootA+24) b >= load64 (rootB+24) b then rootA else rootB
      let low := if high == rootA then rootB else rootA
      let tried := tryRoot high b
      if tried == 0 then tried else
        let tried := tryRoot low b
        if tried == 0 then tried else
          if ProjectGraph.allZero rootA 512 b && ProjectGraph.allZero rootB 512 b then
            let t := zero index 2048 b
            let t := zero state 16 t
            let t := store64 index magic t
            store64 (index+8) 2 t
          else error

partial def readChunks (node part blocks t : UInt64) : UInt64 :=
  if part == blocks then t else
    let start := load64 (node+112) t+part
    let len := load64 (node+8) t
    let bytes := if len-part*4096 < 4096 then len-part*4096 else 4096
    let read := transfer 60 (bankSector (load64 (current+32) t)+32+start*9) cipher 4608 t
    if read != 0 then error else
      let t := makeNonce current (start+1) read
      let t := chunkAAD current node part bytes t
      let decrypted := VaultCrypto.decrypt key nonce aad 176 cipher 4096 blockPlain t
      if decrypted != 0 then error else
        readChunks node (part+1) blocks (copy blockPlain (recordPlain+part*4096) bytes decrypted)

partial def validEdges (node i count t : UInt64) : Bool :=
  if i == count then true else
    let e := recordPlain+32+i*128
    let kind := load64 e t
    let n := load64 (e+8) t
    ProjectGraph.edgeAllowed (load64 node t) kind && ProjectGraph.validName (e+48) n 80 t &&
      ProjectGraph.allZero (e+48+n) (80-n) t && findNode index (e+16) kind 0 (load64 (state+16) t) t != error &&
      (i == 0 || ProjectGraph.lessName (e-80) (load64 (e-120) t) (e+48) n 0 t) && validEdges node (i+1) count t

partial def requiredEdge (kind i count t : UInt64) : Bool :=
  if i == count then kind == 14 || kind == 15 else
    let child := load64 (recordPlain+32+i*128) t
    (kind == 11 && child == 10) || (kind == 12 && child == 11) || (kind == 13 && child == 12) || requiredEdge kind (i+1) count t

def validRecord (node t : UInt64) : Bool :=
  let kind := load64 node t
  if nodeSchema node t == 1 && !ProjectGraph.allZero (node+48) 32 t && findNode index (node+48) kind 0 (load64 (state+16) t) t == error then false else
  if kind == 10 then true else
    let n := load64 (node+8) t
    let count := load64 (recordPlain+16) t
    n >= 32 && load64 recordPlain t == 0x31464e4d544c && load64 (recordPlain+8) t == nodeSchema node t && count <= 32 &&
      n == 32+count*128+load64 (recordPlain+24) t && requiredEdge kind 0 count t && validEdges node 0 count t

def checkRecord (node t : UInt64) : UInt64 :=
  let t := ServiceHash.sha256At hashScratch recordPlain (load64 (node+8) t) hashResult t
  if !ProjectGraph.equal hashResult (node+80) 32 t then error else
    let t := zero aad 12 t
    let t := store64 aad 0x3145444f4e544c t
    let t := store64 (aad+8) 1 t
    let t := store64 (aad+16) (load64 node t) t
    let t := store64 (aad+24) (nodeSchema node t) t
    let t := copy (node+80) (aad+32) 32 t
    let t := copy (node+48) (aad+64) 32 t
    let t := ServiceHash.sha256At hashScratch aad 96 hashResult t
    if !ProjectGraph.equal hashResult (node+16) 32 t then error else t

def readRecord (i t : UInt64) : UInt64 :=
  if i >= load64 (state+16) t then error else
    let n := nodeAt index i
    let t := zero recordPlain 8192 t
    let result := readChunks n 0 (load64 (n+120) t) t
    if result != 0 then error else
      let checked := checkRecord n result
      if checked != 0 || !validRecord n checked then error else
        let t := store64 (state+48) i checked
        store64 (state+40) 1 t

partial def authenticateAll (i t : UInt64) : UInt64 :=
  if i == load64 (state+16) t then t else
    let checked := readRecord i t
    if checked != 0 then error else authenticateAll (i+1) checked

partial def findRoot (base name n i count t : UInt64) : UInt64 :=
  if i == count then error else
    let r := rootAt base i
    if load64 r t == n && ProjectGraph.equal (r+40) name n t then i else findRoot base name n (i+1) count t
partial def fetchObject (h offset len t : UInt64) : UInt64 :=
  if offset == len then t else
    let n := if len-offset < 512 then len-offset else 512
    let received := LiveSDK.read h offset n t
    if received != 64+n || load64 wire received != 0 || load64 (wire+8) received != n then error else
      fetchObject h (offset+n) len (copy (wire+64) (recordPlain+offset) n received)

partial def gatherNodes (root cursor t : UInt64) : UInt64 :=
  let received := ProjectSDK.closure root cursor t
  if received < 64 || load64 wire received != 0 then error else
    let h := load64 (wire+8) received
    if h == 0 then received-received else
      let next := load64 (wire+24) received
      let count := load64 (staged+16) received
      let existing := findNode staged (wire+64) 0 0 count received
      let i := if existing == error then count else existing
      if i >= 64 || next <= cursor || next > 64 then error else
        let n := nodeAt staged i
        let t := if existing == error then zero n 24 received else received
        let t := store64 n (load64 (wire+32) t) t
        let t := store64 (n+8) (load64 (wire+16) t) t
        let t := copy (wire+64) (n+16) 64 t
        let t := store64 (n+128) (load64 (wire+40) t) t
        let t := store64 (handles+i*8) h t
        let t := if existing == error then store64 (staged+16) (count+1) t else t
        let received := metadata h t
        if received != 96 || load64 wire received != 0 then error else
          let t := copy (wire+64) (n+80) 32 received
          gatherNodes root next t

partial def gatherRoots (i count t : UInt64) : UInt64 :=
  if i == count then t else
    let h := load64 (selected+i*8) t
    let received := ProjectSDK.describeRoot h t
    if received != 160 || load64 wire received != 0 then error else
      let names := load64 (staged+24) received
      let n := load64 (wire+16) received
      let existing := findRoot staged (wire+96) n 0 names received
      let slot := if existing == error then names else existing
      if slot >= 6 then error else
        let r := rootAt staged slot
        let t := zero r 16 received
        let t := store64 r n t
        let t := copy (wire+64) (r+8) 32 t
        let t := copy (wire+96) (r+40) 64 t
        let t := if existing == error then store64 (staged+24) (names+1) t else t
        let gathered := gatherNodes h 0 t
        if gathered != 0 then error else
          let checked := ProjectSDK.describeRoot h gathered
          if checked != 160 || load64 wire checked != 0 || !ProjectGraph.equal (wire+64) (r+8) 32 checked then error else
            gatherRoots (i+1) count (checked-checked)

partial def numberNodes (i count blocks bytes t : UInt64) : UInt64 :=
  if i == count then
    let t := store64 (candidate+64) blocks t
    store64 (candidate+72) bytes t
  else
    let n := nodeAt staged i
    let len := load64 (n+8) t
    let chunks := (len+4095)/4096
    let t := store64 (n+112) blocks t
    let t := store64 (n+120) chunks t
    numberNodes (i+1) count (blocks+chunks) (bytes+len) t

partial def writeChunks (node part blocks t : UInt64) : UInt64 :=
  if part == blocks then t else
    let start := load64 (node+112) t+part
    let len := load64 (node+8) t
    let bytes := if len-part*4096 < 4096 then len-part*4096 else 4096
    let t := zero blockPlain 512 t
    let t := copy (recordPlain+part*4096) blockPlain bytes t
    let t := zero cipher 576 t
    let t := makeNonce candidate (start+1) t
    let t := chunkAAD candidate node part bytes t
    let encrypted := VaultCrypto.encrypt key nonce aad 176 blockPlain 4096 cipher t
    if encrypted != 0 then error else
      let written := transfer 61 (bankSector (load64 (candidate+32) encrypted)+32+start*9) cipher 4608 encrypted
      if written != 0 then error else writeChunks node (part+1) blocks written

partial def writeNodes (i count t : UInt64) : UInt64 :=
  if i == count then t else
    let node := nodeAt staged i
    let h := load64 (handles+i*8) t
    let loaded := if h == 0 then
      let old := findNode index (node+16) 0 0 (load64 (state+16) t) t
      if old == error then error else readRecord old t
      else fetchObject h 0 (load64 (node+8) t) t
    if loaded != 0 then error else
      let checked := checkRecord node loaded
      if checked != 0 then error else
        let written := writeChunks node 0 (load64 (node+120) checked) checked
        if written != 0 then error else writeNodes (i+1) count written

def save (count length t : UInt64) : UInt64 :=
  if count == 0 || count > 6 || length != 64+count*8 then response 2 0 t else
    let t := copy (command+64) selected (count*8) t
    let scanned := scan t
    if scanned != 0 then response 5 0 scanned else
      let t := copy index staged indexLength scanned
      let t := zero handles 64 t
      let gathered := gatherRoots 0 count t
      if gathered != 0 then response 1 0 gathered else
        let generation := load64 (state+8) gathered+1
        if generation == 0 then response 6 0 gathered else
          let t := zero candidate 64 gathered
          let t := store64 candidate magic t
          let t := store64 (candidate+8) 2 t
          let t := store64 (candidate+16) 3 t
          let t := store64 (candidate+24) generation t
          let t := store64 (candidate+32) (generation%2) t
          let t := store64 (candidate+40) indexLength t
          let t := store64 (candidate+48) (load64 (staged+16) t) t
          let t := store64 (candidate+56) (load64 (staged+24) t) t
          let t := numberNodes 0 (load64 (staged+16) t) 0 0 t
          let random := device 63 0 chunk 12 t
          if random != 0 then response 4 1 random else
            let t := copy chunk (candidate+96) 12 random
            let written := writeNodes 0 (load64 (staged+16) t) t
            if written != 0 then response 4 2 written else
              let t := zero cipher 2048 written
              let t := makeNonce candidate 0 t
              let encrypted := VaultCrypto.encrypt key nonce candidate 128 staged indexLength cipher t
              if encrypted != 0 then response 5 0 encrypted else
                let t := copy (cipher+indexLength) (candidate+128) 16 encrypted
                let t := ServiceHash.sha256At hashScratch cipher indexLength (candidate+144) t
                let written := transfer 61 (bankSector (generation%2)) cipher 14848 t
                if written != 0 then response 4 3 written else
                  let flushed := device 62 0 chunk 0 written
                  if flushed != 0 then response 4 4 flushed else
                    let committed := transfer 61 (2+generation%2) candidate 512 flushed
                    if committed != 0 then response 4 5 committed else
                      let flushed := device 62 0 chunk 0 committed
                      if flushed != 0 then response 4 6 flushed else
                        let t := copy staged index indexLength flushed
                        let t := copy candidate current 512 t
                        let t := store64 state 1 t
                        let t := store64 (state+8) generation t
                        let t := store64 (state+16) (load64 (candidate+48) t) t
                        let t := store64 (state+24) (load64 (candidate+56) t) t
                        let t := store64 (state+32) (load64 (candidate+72) t) t
                        response 0 generation t

def recover (t : UInt64) : UInt64 :=
  let scanned := scan t
  if scanned != 0 then response 5 0 scanned else
    let checked := authenticateAll 0 scanned
    if checked == 0 then response 0 (load64 (state+8) checked) (store64 (state+56) 1 checked) else
      let other := if ProjectGraph.equal current rootA 128 checked then rootB else rootA
      let retried := tryRoot other checked
      if retried != 0 then response 5 0 retried else
        let verified := authenticateAll 0 retried
        if verified != 0 then response 5 0 verified else response 0 (load64 (state+8) verified) (store64 (state+56) 1 verified)

def inspectRoot (i t : UInt64) : UInt64 :=
  if load64 state t != 1 || i >= load64 (state+24) t then response 2 0 t else
    let t := response 0 i t
    192+copy (rootAt index i) (wire+64) 128 t

def inspectNode (i t : UInt64) : UInt64 :=
  if load64 state t != 1 || i >= load64 (state+16) t then response 2 0 t else
    let t := response 0 i t
    200+copy (nodeAt index i) (wire+64) 136 t

def readNode (i offset count t : UInt64) : UInt64 :=
  if load64 state t != 1 || i >= load64 (state+16) t || count > 512 then response 2 0 t else
    let total := load64 (nodeAt index i+8) t
    if offset > total || count > total-offset then response 2 0 t else
      let loaded := if load64 (state+40) t == 1 && load64 (state+48) t == i then store64 (state+48) i t else readRecord i t
      if loaded != 0 then response 5 0 loaded else
        let t := response 0 count loaded
        64+count+copy (recordPlain+offset) (wire+64) count t

def delete (t : UInt64) : UInt64 :=
  let t := zero chunk 64 t
  let first := device 61 2 chunk 512 t
  if first != 0 then response 4 0 (clear first) else
    let second := device 61 3 chunk 512 first
    if second != 0 then response 4 0 (clear second) else
      let flushed := device 62 0 chunk 0 second
      if flushed != 0 then response 4 0 (clear flushed) else response 0 0 (clear flushed)

-- Recovery invokes the same native transaction API used by peer/local imports.
-- Only selected reachable records are disclosed to Objects; no host orders or
-- reconstructs graph records, and recovered capabilities contain no admin bits.
def recoveryMarks : UInt64 := 0x694000
def recoveryRoots : UInt64 := 0x695000
def recoveryMeta : UInt64 := 0x696000
def markRecovery (id kind t : UInt64) : UInt64 :=
  let i := findNode index id kind 0 (load64 (state+16) t) t
  if i == error then error else
    if load64 (recoveryMarks+i*8) t != 0 then t else store64 (recoveryMarks+i*8) 1 t
partial def selectRecoveryRoots (mask i count t : UInt64) : UInt64 :=
  if i == load64 (state+24) t then Guest.Effects.effectValue count t else
    if ((mask >>> i) &&& 1) == 0 then selectRecoveryRoots mask (i+1) count t else
      let r := rootAt index i
      let e := recoveryRoots+count*128
      let t := zero e 16 t
      let t := store64 (e+8) (load64 r t) t
      let t := copy (r+8) (e+16) 32 t
      let t := copy (r+40) (e+48) (load64 r t) t
      let t := markRecovery (r+8) 11 t
      if t == error then error else selectRecoveryRoots mask (i+1) (count+1) t
partial def markRecoveryEdges (i count t : UInt64) : UInt64 :=
  if i == count then t else
    let e := recordPlain+32+i*128
    let t := markRecovery (e+16) (load64 e t) t
    if t == error then error else markRecoveryEdges (i+1) count t
partial def nextRecovery (i t : UInt64) : UInt64 :=
  if i == load64 (state+16) t then error else
    if load64 (recoveryMarks+i*8) t == 1 then i else nextRecovery (i+1) t
partial def expandRecovery (fuel count bytes t : UInt64) : UInt64 :=
  let i := nextRecovery 0 t
  if i == error then
    let t := store64 recoveryMeta count t
    store64 (recoveryMeta+8) bytes t
  else if fuel == 0 then error else
    let n := nodeAt index i
    let loaded := readRecord i t
    if loaded != 0 then error else
      let t := store64 (recoveryMarks+i*8) 2 loaded
      let t := if nodeSchema n t == 2 || ProjectGraph.allZero (n+48) 32 t then t else markRecovery (n+48) (load64 n t) t
      let t := if t == error || load64 n t == 10 then t else markRecoveryEdges 0 (load64 (recordPlain+16) t) t
      if t == error then error else expandRecovery (fuel-1) (count+1) (bytes+load64 (n+8) t) t
partial def importRecoveryBytes (transaction ordinal offset total t : UInt64) : UInt64 :=
  if offset == total then t else
    let count := if total-offset > 512 then 512 else total-offset
    let r := ProjectSDK.importAppend transaction ordinal offset (recordPlain+offset) count t
    if r != 64 || status r != 0 then error else importRecoveryBytes transaction ordinal (offset+count) total r
partial def importRecoveryNodes (transaction i ordinal t : UInt64) : UInt64 :=
  if i == load64 (state+16) t then t else
  if load64 (recoveryMarks+i*8) t != 2 then importRecoveryNodes transaction (i+1) ordinal t else
    let n := nodeAt index i
    let t := copy (n+16) (recoveryMeta+32) 64 t
    let t := copy (n+80) (recoveryMeta+96) 32 t
    let r := ProjectSDK.importOfferVersion transaction ordinal (load64 n t) (load64 (n+8) t) (recoveryMeta+32) (nodeSchema n t) t
    if r != 64 || status r != 0 then error else
      let loaded := readRecord i r
      if loaded != 0 then error else
        let appended := importRecoveryBytes transaction ordinal 0 (load64 (n+8) loaded) loaded
        if appended == error then error else importRecoveryNodes transaction (i+1) (ordinal+1) appended
partial def grantRecoveryRoots (recipient count i t : UInt64) : UInt64 :=
  if i == count then t else
    let root := load64 (recoveryMeta+256+i*8) t
    let r := ProjectSDK.delegate root recipient 127 t
    if r != 160 || status r != 0 then error else
      let t := store64 (recoveryMeta+512+i*8) (result r) r
      grantRecoveryRoots recipient count (i+1) t

def importRecovery (recipient mask expectedGeneration t : UInt64) : UInt64 :=
  let scanned := recover t
  if scanned != 64 || status scanned != 0 then response 5 0 scanned else
  if expectedGeneration != 0 && expectedGeneration != load64 (state+8) scanned then response 6 0 scanned else
  if mask == 0 || mask >>> load64 (state+24) scanned != 0 then response 2 0 scanned else
    let t := zero recoveryMarks 64 scanned
    let count := selectRecoveryRoots mask 0 0 t
    if count == error then response 2 0 count else
      let t := store64 (recoveryMeta+16) count count
      let selected := expandRecovery 64 0 0 t
      if selected == error then response 5 0 selected else
        let r := ProjectSDK.importBegin recoveryRoots count (load64 recoveryMeta selected) (load64 (recoveryMeta+8) selected) selected
        if r != 64 || status r != 0 then response 4 0 r else
          let transaction := result r
          let copied := importRecoveryNodes transaction 0 0 r
          if copied == error then response 5 0 (ProjectSDK.importAbort transaction copied) else
            let committed := ProjectSDK.importCommit transaction copied
            if committed != 64+count*8 || status committed != 0 then response 5 0 committed else
              let t := copy (wire+64) (recoveryMeta+256) (count*8) committed
              let shell := syscall 97 4 0 0 0 t
              let t := if shell == error then t else grantRecoveryRoots shell count 0 t
              let granted := if t == error then error else grantRecoveryRoots recipient count 0 t
              if granted == error then response 1 0 granted else
                let t := response 0 count granted
                64+count*8+copy (recoveryMeta+512) (wire+64) (count*8) t

def dispatch (op length t : UInt64) : UInt64 :=
  if op == 210 then save (load64 (command+24) t) length t else
  if length != 64 then response 2 0 t else
  if op == 211 then recover t else
  if op == 212 then response 0 (load64 (state+8) t) t else
  if op == 213 then inspectRoot (load64 (command+8) t) t else
  if op == 214 then inspectNode (load64 (command+8) t) t else
  if op == 215 then readNode (load64 (command+8) t) (load64 (command+24) t) (load64 (command+32) t) t else
  if op == 216 then delete t else
  if op == 217 then importRecovery (load64 incoming t) (load64 (command+24) t) (load64 (command+32) t) t else response 2 0 t
end Guest.ProjectVault
