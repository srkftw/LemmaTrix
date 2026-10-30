import Guest.ContentFormat
namespace Guest.ContentStore
open Guest.LiveSDK
-- ContentJobs' dedicated volatile mapping. No backing-device syscall, host path,
-- ProjectGraph.importScope, global graph marks or graph hash scratch is used.
def base : UInt64 := 0xe00000
def state : UInt64 := base
def roots : UInt64 := base+0x1000
def grants : UInt64 := base+0x3000
def maps : UInt64 := base+0x5000
def jobs : UInt64 := base+0x18000
def pages : UInt64 := base+0x20000
def backing : UInt64 := base+0x40000
-- Authenticated tree cache follows the first6MiB mapping; each selected root
-- has at most4096 nodes. Payload capacity remains explicitly5.75MiB.
def tree (ri index : UInt64) : UInt64 := base+0x600000+ri*131072+index*32
def capacity : UInt64 := 1472
def root (i : UInt64) : UInt64 := roots+i*1024
def grant (i : UInt64) : UInt64 := grants+i*64
def job (i : UInt64) : UInt64 := jobs+i*8192
def page (i : UInt64) : UInt64 := pages+i*64
def payload (i : UInt64) : UInt64 := backing+i*4096
def entry (r i : UInt64) : UInt64 := maps+r*16384+i*8
def eq (a b n t : UInt64) : Bool := ContentFormat.equal a b n t
def allZero (p n t : UInt64) : Bool := ContentFormat.allZero p n t
def now (t : UInt64) : UInt64 := syscall 116 0 0 0 0 t
def response (code value a b c d e t : UInt64) : UInt64 :=
  let t := header code value a b c d e t
  64+t
def denied (t : UInt64) : UInt64 := response 1 0 0 0 0 0 0 t
def malformed (t : UInt64) : UInt64 := response 2 0 0 0 0 0 0 t
def stale (t : UInt64) : UInt64 := response 3 0 0 0 0 0 0 t
def quota (t : UInt64) : UInt64 := response 4 0 0 0 0 0 0 t
def token (slot t : UInt64) : UInt64 :=
  let generation := load64 (state+8) t+1
  if generation == 0 || generation > 0xffffff then error else
    (load64 state t <<< 32) ||| (generation <<< 8) ||| (slot+1)
def takeToken (slot t : UInt64) : UInt64 :=
  let h := token slot t
  if h == error then error else store64 (state+8) (load64 (state+8) t+1) t
partial def freeRoot (i t : UInt64) : UInt64 :=
  if i == 4 then error else if load64 (root i) t == 0 then i else freeRoot (i+1) t
partial def freeGrant (i t : UInt64) : UInt64 :=
  if i == 64 then error else if load64 (grant i) t == 0 then i else freeGrant (i+1) t
partial def freeJob (i t : UInt64) : UInt64 :=
  if i == 4 then error else if load64 (job i) t == 0 then i else freeJob (i+1) t
partial def freePage (i t : UInt64) : UInt64 :=
  if i == capacity then error else if load64 (page i) t == 0 then i else freePage (i+1) t
def grantRoot (slot ri caller permission t : UInt64) : UInt64 :=
  let h := token slot t
  if h == error then error else
    let t := takeToken slot t
    let g := grant slot
    let t := zero g 8 t
    let t := store64 g h t
    let t := store64 (g+8) caller t
    let t := store64 (g+16) ri t
    let t := store64 (g+24) (load64 (root ri+8) t) t
    let t := store64 (g+32) permission t
    store64 (g+40) caller t
def authorized (caller h permission t : UInt64) : UInt64 :=
  let slot := (h &&& 255)-1
  if h == 0 || slot >= 64 then error else
    let g := grant slot
    let ri := load64 (g+16) t
    if ri >= 4 || load64 g t != h || load64 (g+8) t != caller ||
      (load64 (g+32) t &&& permission) != permission ||
      load64 (root ri) t == 0 || load64 (root ri+8) t != load64 (g+24) t then error else ri
def ownedJob (caller h t : UInt64) : UInt64 :=
  let i := (h &&& 255)-65
  if h == 0 || i >= 4 || load64 (job i) t != h || load64 (job i+8) t != caller then error else i
partial def callerJobs (caller i count t : UInt64) : UInt64 :=
  if i == 4 then count else callerJobs caller (i+1) (if load64 (job i) t != 0 && load64 (job i+8) t == caller then count+1 else count) t
partial def duplicateOperation (caller operation i t : UInt64) : UInt64 :=
  if i == 4 then error else
    if load64 (root i) t != 0 && load64 (root i+16) t == caller && load64 (root i+80) t == operation then i
    else duplicateOperation caller operation (i+1) t
partial def ownerGrant (caller ri i t : UInt64) : UInt64 :=
  if i == 64 then error else
    if load64 (grant i) t != 0 && load64 (grant i+8) t == caller && load64 (grant i+16) t == ri &&
      load64 (grant i+24) t == load64 (root ri+8) t && (load64 (grant i+32) t &&& 2) == 2 then load64 (grant i) t
    else ownerGrant caller ri (i+1) t
def reserve (caller rights length t : UInt64) : UInt64 :=
  let op := load64 (command+16) t
  let budget := load64 (command+24) t
  let mode := load64 (command+32) t
  let durable := load64 (command+40) t
  if length != 416 || op == 0 || (rights &&& 2) == 0 then denied t else
  if mode != 3 then response 7 0 0 0 0 0 0 t else
  if durable != 0 then response 8 0 0 0 0 0 0 t else
  if !ContentFormat.valid (command+64) t || allZero (command+352) 32 t || allZero (command+384) 32 t then malformed t else
    let total := load64 (command+88) t
    if total > budget || budget > ContentFormat.maxBytes then quota t else
    let t := ServiceHash.sha256At (base+0x400) (command+64) 256 (base+0x700) t
    if !eq (base+0x700) (command+320) 32 t then response 5 0 0 0 0 0 0 t else
    let previous := duplicateOperation caller op 0 t
    if previous != error then
      if !eq (root previous+128) (command+320) 32 t || !eq (root previous+160) (command+352) 64 t ||
        load64 (root previous+88) t != budget then malformed t else
        let existing := ownerGrant caller previous 0 t
        if existing == error || load64 (root previous+96) t != 0 then denied t else
        response 0 existing (load64 (root previous) t) (load64 (root previous+48) t) total 0 0 t
    else
    let ri := freeRoot 0 t
    let gi := freeGrant 0 t
    let count := load64 (command+96) t
    if ri == error || gi == error || token gi t == error || load64 (state+32) t > capacity ||
      count > capacity-load64 (state+32) t then quota t else
      let r := root ri
      let generation := load64 (r+8) t+1
      if generation == 0 then quota t else
      let t := zero r 128 t
      let t := zero (entry ri 0) 2048 t
      let t := store64 r 1 t
      let t := store64 (r+8) generation t
      let t := store64 (r+16) caller t
      let t := store64 (r+32) total t
      let t := store64 (r+40) (load64 (command+96) t) t
      let t := store64 (r+64) (load64 (command+104) t) t
      let t := store64 (r+72) (load64 (command+112) t) t
      let t := store64 (r+80) op t
      let t := store64 (r+88) budget t
      let t := store64 (r+112) mode t
      let t := store64 (state+32) (load64 (state+32) t+count) t
      let t := copy (command+320) (r+128) 96 t
      let t := copy (command+64) (r+256) 256 t
      let t := grantRoot gi ri caller 3 t
      response 0 (load64 (grant gi) t) 1 0 total 0 0 t
def liveRoot (j t : UInt64) : Bool :=
  let ri := load64 (j+32) t
  ri < 4 && load64 (root ri) t != 0 && load64 (root ri+8) t == load64 (j+40) t &&
    load64 (root ri+96) t == 0 && load64 (root ri+16) t == load64 (j+8) t
def initializeJob (ji ri caller kind index t : UInt64) : UInt64 :=
  let j := job ji
  let h := token (ji+64) t
  if h == error then error else
  let t := takeToken (ji+64) t
  let t := zero j 1024 t
  let t := store64 j h t
  let t := store64 (j+8) caller t
  let t := store64 (j+16) (if kind == 1 then 1 else 2) t
  let t := store64 (j+24) kind t
  let t := store64 (j+32) ri t
  let t := store64 (j+40) (load64 (root ri+8) t) t
  let t := store64 (j+48) index t
  let t := store64 (j+56) (ContentFormat.chunkLength (load64 (root ri+32) t) index) t
  let t := store64 (j+88) (load64 (root ri+72) t) t
  let t := copy (root ri+160) (j+544) 64 t
  let t := store64 (j+608) (load64 (root ri+80) t) t
  let t := store64 (j+616) (load64 (root ri+112) t) t
  let t := store64 (j+624) (load64 (root ri+88) t) t
  store64 (j+632) (now t) t
partial def chunkBusy (ri index i t : UInt64) : Bool :=
  if i == 4 then false else
    (load64 (job i) t != 0 && load64 (job i+32) t == ri && load64 (job i+48) t == index &&
      load64 (job i+24) t == 1 && load64 (job i+16) t <= 3) || chunkBusy ri index (i+1) t
def beginChunk (caller h length t : UInt64) : UInt64 :=
  let ri := authorized caller h 2 t
  if ri == error then denied t else
  let index := load64 (command+16) t
  let count := load64 (root ri+40) t
  let proofDepth := load64 (root ri+72) t
  if length != 96+proofDepth*32 || index >= count then malformed t else
  if load64 (root ri+96) t != 0 then denied t else
  if load64 (entry ri index) t != 0 then
    let pi := load64 (entry ri index) t-1
    if pi >= capacity || !eq (page pi+24) (command+64) 32 t then response 5 0 0 0 0 0 0 t
    else response 0 0 4 index 0 0 0 t else
  if chunkBusy ri index 0 t || callerJobs caller 0 0 t >= 2 then quota t else
    let ji := freeJob 0 t
    if ji == error || load64 (state+24) t >= capacity then quota t else
      let t := initializeJob ji ri caller 1 index t
      if t == error then quota t else
      let t := copy (command+64) (job ji+128) 32 t
      let t := copy (command+96) (job ji+192) (proofDepth*32) t
      response 0 (load64 (job ji) t) 1 0 (load64 (job ji+56) t) 0 0 t
def append (caller h length t : UInt64) : UInt64 :=
  let ji := ownedJob caller h t
  if ji == error then stale t else
  let j := job ji
  let offset := load64 (command+16) t
  let n := length-64
  let total := load64 (j+56) t
  if !liveRoot j t then denied t else
  if length <= 64 || length > 576 || load64 (j+16) t != 1 || load64 (j+24) t != 1 ||
    offset != load64 (j+64) t || offset > total || n > total-offset then malformed t else
    let t := copy (command+64) (j+2048+offset) n t
    response 0 h 1 (offset+n) total 0 0 (store64 (j+64) (offset+n) t)
def validate (caller h length t : UInt64) : UInt64 :=
  let ji := ownedJob caller h t
  if ji == error then stale t else
  let j := job ji
  if length != 64 || !liveRoot j t then denied t else
  if load64 (j+16) t == 2 || load64 (j+16) t == 4 then response 0 h (load64 (j+16) t) (load64 (j+72) t) (load64 (j+56) t) 0 0 t else
  if load64 (j+16) t != 1 || load64 (j+64) t != load64 (j+56) t then malformed t else
    let t := ServiceHash.initialState (j+1024) t
    response 0 h 2 0 (load64 (j+56) t) 0 0 (store64 (j+16) 2 t)
def wipeJob (j t : UInt64) : UInt64 :=
  let t := zero (j+128) 1008 t
  store64 (j+64) 0 t
def terminal (j result code t : UInt64) : UInt64 :=
  let t := wipeJob j t
  let t := store64 (j+16) result t
  store64 (j+112) code t
def inspectJob (caller h t : UInt64) : UInt64 :=
  let ji := ownedJob caller h t
  if ji == error then stale t else
    let j := job ji
    response 0 h (load64 (j+16) t) (load64 (j+72) t) (load64 (j+56) t) (load64 (j+112) t) (load64 (j+24) t) t
def control (caller h action t : UInt64) : UInt64 :=
  let ji := ownedJob caller h t
  if ji == error then stale t else
  let j := job ji
  let s := load64 (j+16) t
  if action == 1 && (s == 1 || s == 2) then
    let t := store64 (j+104) s t
    response 0 h 3 0 0 0 0 (store64 (j+16) 3 t)
  else if action == 2 && s == 3 && liveRoot j t then
    response 0 h (load64 (j+104) t) 0 0 0 0 (store64 (j+16) (load64 (j+104) t) t)
  else if action == 3 && s < 4 then response 0 h 5 0 0 0 0 (terminal j 5 0 t)
  else if action == 4 && s >= 4 then response 0 h s 0 0 0 0 (zero j 1024 t)
  else if action >= 1 && action <= 4 then inspectJob caller h t else malformed t
def describe (caller h t : UInt64) : UInt64 :=
  let ri := authorized caller h 1 t
  if ri == error then denied t else
    let r := root ri
    let t := response 0 h (load64 r t) (load64 (r+48) t) (load64 (r+32) t) (load64 (r+56) t) (load64 (r+40) t) t
    320+copy (r+256) (wire+64) 256 t
def read (caller h offset count t : UInt64) : UInt64 :=
  let ri := authorized caller h 1 t
  if ri == error then denied t else
  let r := root ri
  let total := load64 (r+32) t
  if count == 0 || count > 512 || offset >= total || count > total-offset || offset%4096+count > 4096 then malformed t else
    let index := offset/4096
    let found := load64 (entry ri index) t
    if found == 0 then response 6 h (load64 r t) 0 total index 0 t else
    let pi := found-1
    if pi >= capacity || load64 (page pi) t != ri+1 || load64 (page pi+8) t != load64 (r+8) t ||
      load64 (page pi+16) t != index then response 5 0 0 0 0 0 0 t else
      let t := response 0 count (load64 r t) offset total index 0 t
      64+count+copy (payload pi+offset%4096) (wire+64) count t
def share (caller rights h target t : UInt64) : UInt64 :=
  let ri := authorized caller h 1 t
  let actual := syscall 34 target 0 0 0 t
  if ri == error || (rights &&& 8) == 0 || actual == error || (actual &&& 1) == 0 then denied actual else
    let gi := freeGrant 0 actual
    if gi == error || token gi actual == error then quota actual else
      let t := grantRoot gi ri target 1 actual
      let t := store64 (grant gi+40) caller t
      response 0 (load64 (grant gi) t) 0 0 0 0 0 t
-- A service accepting a delegated read scope must check its exact issuer.
-- Possession of the numeric handle by another caller grants no authority.
def checkDelegation (caller h issuer t : UInt64) : UInt64 :=
  let ri := authorized caller h 1 t
  if ri == error || load64 (grant ((h &&& 255)-1)+40) t != issuer then denied t
  else response 0 h 0 0 0 0 0 t
def release (caller h t : UInt64) : UInt64 :=
  let ri := authorized caller h 1 t
  if ri == error then denied t else
    let g := grant ((h &&& 255)-1)
    let t := if (load64 (g+32) t &&& 2) != 0 then store64 (root ri+96) 1 t else t
    response 0 h 0 0 0 0 0 (zero g 8 t)
partial def finalizing (ri i t : UInt64) : UInt64 :=
  if i == 4 then error else
    if load64 (job i) t != 0 && load64 (job i+32) t == ri && load64 (job i+24) t == 2 && load64 (job i+16) t <= 4 then load64 (job i) t
    else finalizing ri (i+1) t
def publish (caller h t : UInt64) : UInt64 :=
  let ri := authorized caller h 2 t
  if ri == error || load64 (root ri+96) t != 0 then denied t else
  let existing := finalizing ri 0 t
  if existing != error then inspectJob caller existing t else
  if load64 (root ri) t == 2 then response 0 h 4 0 0 0 2 t else
  if load64 (root ri+56) t != load64 (root ri+40) t then response 6 h 1 (load64 (root ri+48) t) (load64 (root ri+32) t) 0 0 t else
    let ji := freeJob 0 t
    if ji == error || callerJobs caller 0 0 t >= 2 then quota t else
      let t := initializeJob ji ri caller 2 0 t
      response 0 (load64 (job ji) t) 2 0 (load64 (root ri+40) t) 0 2 t
def revoke (caller h t : UInt64) : UInt64 :=
  let ri := authorized caller h 2 t
  if ri == error then denied t else response 0 h 0 0 0 0 0 (store64 (root ri+96) 1 t)
partial def cachePath (j ri node cursor depth t : UInt64) : UInt64 :=
  let t := copy (j+6144+cursor*32) (tree ri node) 32 t
  if cursor == depth then t else
    let sibling := if (node &&& 1) == 0 then node+1 else node-1
    let t := copy (j+192+cursor*32) (tree ri sibling) 32 t
    cachePath j ri (node/2) (cursor+1) depth t
partial def copyProof (ri node cursor depth t : UInt64) : UInt64 :=
  if cursor == depth then t else
    let sibling := if (node &&& 1) == 0 then node+1 else node-1
    let t := copy (tree ri sibling) (wire+96+cursor*32) 32 t
    copyProof ri (node/2) (cursor+1) depth t
def proof (caller h index t : UInt64) : UInt64 :=
  let ri := authorized caller h 1 t
  if ri == error then denied t else
  let r := root ri
  if index >= load64 (r+40) t then malformed t else
  if load64 (entry ri index) t == 0 then response 6 h (load64 r t) 0 0 0 0 t else
  let pi := load64 (entry ri index) t-1
  let depth := load64 (r+72) t
  if pi >= capacity || load64 (page pi) t != ri+1 || load64 (page pi+8) t != load64 (r+8) t ||
    load64 (page pi+16) t != index || !eq (tree ri 1) (r+352) 32 t then response 5 0 0 0 0 0 0 t else
    let t := response 0 (32+depth*32) (load64 r t) index (load64 (r+32) t) depth 0 t
    let t := copy (page pi+24) (wire+64) 32 t
    let node := ((1 : UInt64) <<< depth)+index
    let t := copyProof ri node 0 depth t
    96+depth*32+t
-- A committed chunk is immutable. Validated pages are installed in one short
-- non-yielding transition; a cancelled or dead owner's job cannot install one.
def commitChunk (j t : UInt64) : UInt64 :=
  let ri := load64 (j+32) t
  let index := load64 (j+48) t
  if !liveRoot j t || load64 (root ri+48) t > load64 (root ri+88) t ||
    load64 (j+56) t > load64 (root ri+88) t-load64 (root ri+48) t then terminal j 6 1 t else
  if load64 (entry ri index) t != 0 then terminal j 6 2 t else
  let pi := freePage 0 t
  if pi == error then terminal j 6 4 t else
    let t := zero (payload pi) 512 t
    let t := copy (j+2048) (payload pi) (load64 (j+56) t) t
    let t := store64 (page pi) (ri+1) t
    let t := store64 (page pi+8) (load64 (root ri+8) t) t
    let t := store64 (page pi+16) index t
    let t := copy (j+128) (page pi+24) 32 t
    let t := cachePath j ri (((1 : UInt64) <<< load64 (j+88) t)+index) 0 (load64 (j+88) t) t
    let t := store64 (entry ri index) (pi+1) t
    let t := store64 (root ri+48) (load64 (root ri+48) t+load64 (j+56) t) t
    let t := store64 (root ri+56) (load64 (root ri+56) t+1) t
    let t := store64 (state+24) (load64 (state+24) t+1) t
    terminal j 4 0 t
def hashQuantum (j t : UInt64) : UInt64 :=
  let phase := load64 (j+80) t
  if phase == 0 then
    let n := load64 (j+56) t
    let cursor := load64 (j+72) t
    let blocks := (n+72)/64
    if cursor < blocks then
      let next := if blocks-cursor < 8 then blocks else cursor+8
      let t := ServiceHash.blocks (j+1024) (j+2048) n (blocks*64) cursor next t
      store64 (j+72) next t
    else
      let t := ServiceHash.outputBytes (j+1024) (j+800) 0 t
      if !eq (j+800) (j+128) 32 t then terminal j 6 5 t else
        let t := ContentFormat.leaf (j+704) (j+1024) (j+160) (load64 (j+48) t) n (j+128) t
        let t := copy (j+160) (j+6144) 32 t
        store64 (j+80) 1 t
  else
    let cursor := load64 (j+96) t
    if cursor < load64 (j+88) t then
      let sibling := j+192+cursor*32
      let index := load64 (j+48) t >>> cursor
      let t := if (index &&& 1) == 0 then ContentFormat.branch (j+704) (j+1024) (j+800) (j+160) sibling t
        else ContentFormat.branch (j+704) (j+1024) (j+800) sibling (j+160) t
      let t := copy (j+800) (j+160) 32 t
      let t := copy (j+800) (j+6144+(cursor+1)*32) 32 t
      store64 (j+96) (cursor+1) t
    else
      let ri := load64 (j+32) t
      if !eq (j+160) (root ri+352) 32 t then terminal j 6 5 t else commitChunk j t
def finalQuantum (j t : UInt64) : UInt64 :=
  let ri := load64 (j+32) t
  let r := root ri
  let cursor := load64 (j+72) t
  if cursor < load64 (r+40) t then
    let found := load64 (entry ri cursor) t
    let pi := found-1
    if found == 0 || pi >= capacity || load64 (page pi) t != ri+1 ||
      load64 (page pi+8) t != load64 (r+8) t || load64 (page pi+16) t != cursor then terminal j 6 5 t else
      store64 (j+72) (cursor+1) t
  else
    let current := syscall 34 (load64 (j+8) t) 0 0 0 t
    if !ContentFormat.publicationAllowed (load64 (r+48) current == load64 (r+32) current && load64 (r+56) current == load64 (r+40) current && eq (tree ri 1) (r+352) 32 current)
      (liveRoot j current) (current != error && (current &&& 2) == 2) (load64 (r+48) current <= load64 (r+88) current) then terminal j 6 1 current else
      terminal j 4 0 (store64 r 2 current)
def quantum (ji t : UInt64) : UInt64 :=
  let j := job ji
  if load64 j t == 0 || load64 (j+16) t >= 4 then t else
  let alive := syscall 34 (load64 (j+8) t) 0 0 0 t
  if alive == error || (alive &&& 2) == 0 || !liveRoot j alive then terminal j 5 1 alive else
  if load64 (j+16) alive != 2 then alive else
  if load64 (j+24) alive == 1 then hashQuantum j alive else finalQuantum j alive
-- Round-robin, at most eight SHA blocks per private validation quantum. The
-- caller may wait on the service deadline; input/other RPCs run between turns.
partial def runnable (cursor fuel t : UInt64) : UInt64 :=
  if fuel == 0 then error else
  if load64 (job cursor) t != 0 && load64 (job cursor+16) t == 2 then cursor
  else runnable ((cursor+1)%4) (fuel-1) t
def jobPump (t : UInt64) : UInt64 :=
  let cursor := runnable (load64 (state+16) t%4) 4 t
  if cursor == error then t else
    let t := store64 (state+16) ((cursor+1)%4) t
    quantum cursor t
partial def jobWork (i t : UInt64) : Bool :=
  if i == 4 then false else (load64 (job i) t != 0 && load64 (job i+16) t == 2) || jobWork (i+1) t
partial def rootReferenced (ri i t : UInt64) : Bool :=
  if i == 64 then false else
    (load64 (grant i) t != 0 && load64 (grant i+16) t == ri && load64 (grant i+24) t == load64 (root ri+8) t) || rootReferenced ri (i+1) t
partial def cleanGrants (i t : UInt64) : UInt64 :=
  if i == 64 then t else
    let g := grant i
    let alive := if load64 g t == 0 then 0 else syscall 34 (load64 (g+8) t) 0 0 0 t
    let t := if alive == error then zero g 8 alive else alive
    cleanGrants (i+1) t
def gcQuantum (t : UInt64) : UInt64 :=
  if load64 (state+40) t == 0 then t else
    let i := load64 (state+48) t
    if i == capacity then store64 (state+40) 0 t else
    let p := page i
    let ri := load64 p t-1
    let t := if ri < 4 && (load64 (root ri) t == 0 || load64 (page i+8) t != load64 (root ri+8) t) then
      let t := zero (payload i) 512 t
      let t := zero p 8 t
      store64 (state+24) (load64 (state+24) t-1) t
    else t
    store64 (state+48) (i+1) t
partial def collectRoots (i t : UInt64) : UInt64 :=
  if i == 4 then t else
    let t := if load64 (root i) t != 0 && !rootReferenced i 0 t then
      let t := store64 (state+32) (load64 (state+32) t-load64 (root i+40) t) t
      store64 (root i) 0 t else t
    collectRoots (i+1) t
def collect (rights t : UInt64) : UInt64 :=
  if (rights &&& 32) == 0 then denied t else
    let t := cleanGrants 0 t
    let t := collectRoots 0 t
    let t := store64 (state+40) 1 t
    let t := store64 (state+48) 0 t
    response 0 (load64 (state+24) t) capacity 0 0 0 0 t
def pump (t : UInt64) : UInt64 := gcQuantum (jobPump t)
def hasWork (i t : UInt64) : Bool := load64 (state+40) t != 0 || jobWork i t
partial def pendingForRoot (ri i t : UInt64) : Bool :=
  if i == 4 then false else
  (load64 (job i) t != 0 && load64 (job i+32) t == ri && load64 (job i+16) t <= 3) || pendingForRoot ri (i+1) t
-- A fresh provider selection does not inherit transport/session authority.
-- Only the acquisition owner can choose it, after completing/cancelling all
-- old quanta. Immutable commitments/federation/budget remain unchanged.
def reauthorize (caller h length t : UInt64) : UInt64 :=
  let ri := authorized caller h 2 t
  if ri == error then denied t else
  if length != 160 || allZero (command+64) 32 t ||
    !eq (command+96) (root ri+192) 32 t || !eq (command+128) (root ri+128) 32 t then malformed t else
  if load64 (root ri+96) t != 0 then denied t else
  if pendingForRoot ri 0 t then response 7 0 0 0 0 0 0 t else
    response 0 h 0 0 0 0 0 (copy (command+64) (root ri+160) 32 t)
partial def downgradeWriters (ri i t : UInt64) : UInt64 :=
  if i == 64 then t else
  let g := grant i
  let t := if load64 g t != 0 && load64 (g+16) t == ri then store64 (g+32) 1 t else t
  downgradeWriters ri (i+1) t
-- A retained read-only checkpoint can be reused only through a new explicit
-- acquisition operation. The former acquisition must already be revoked.
-- Existing reader scopes survive; every old writer scope loses write rights.
def adopt (caller rights h length t : UInt64) : UInt64 :=
  let ri := authorized caller h 1 t
  let operation := load64 (command+16) t
  let budget := load64 (command+24) t
  let mode := load64 (command+32) t
  if ri == error || (rights &&& 2) == 0 then denied t else
  if length != 160 || operation == 0 || mode != 3 || budget < load64 (root ri+32) t || budget > ContentFormat.maxBytes ||
    allZero (command+64) 32 t || allZero (command+96) 32 t || !eq (command+128) (root ri+128) 32 t then malformed t else
  if load64 (root ri+96) t != 1 || pendingForRoot ri 0 t then response 7 0 0 0 0 0 0 t else
  let previous := duplicateOperation caller operation 0 t
  if previous != error then malformed t else
  let gi := freeGrant 0 t
  if gi == error || token gi t == error then quota t else
  let t := downgradeWriters ri 0 t
  let t := store64 (root ri+16) caller t
  let t := store64 (root ri+80) operation t
  let t := store64 (root ri+88) budget t
  let t := store64 (root ri+112) mode t
  let t := copy (command+64) (root ri+160) 64 t
  let t := store64 (root ri+96) 0 t
  let t := grantRoot gi ri caller 3 t
  response 0 (load64 (grant gi) t) (load64 (root ri) t) (load64 (root ri+48) t) (load64 (root ri+32) t) 0 0 t
def dispatch (caller rights length t : UInt64) : UInt64 :=
  let op := load64 command t
  let h := load64 (command+8) t
  if length < 64 || length > 1024 || load64 (command+56) t != 1 || load64 (command+48) t != 0 then malformed t else
  if op == 300 then reserve caller rights length t else
  if op == 301 then beginChunk caller h length t else
  if op == 302 then append caller h length t else
  if op == 303 then validate caller h length t else
  if op == 314 then reauthorize caller h length t else
  if op == 315 then adopt caller rights h length t else
  if length != 64 then malformed t else
  if op == 304 then inspectJob caller h t else
  if op == 305 then control caller h (load64 (command+16) t) t else
  if op == 306 then describe caller h t else
  if op == 307 then read caller h (load64 (command+16) t) (load64 (command+24) t) t else
  if op == 308 then share caller rights h (load64 (command+16) t) t else
  if op == 309 then release caller h t else
  if op == 310 then publish caller h t else
  if op == 311 then revoke caller h t else
  if op == 312 then collect rights t else
  if op == 313 then proof caller h (load64 (command+16) t) t else
  if op == 316 then checkDelegation caller h (load64 (command+16) t) t else malformed t
def startStore (serviceInstance t : UInt64) : UInt64 :=
  -- Token high32 must include the randomized kernel boot epoch. Shifting the
  -- full process identity directly would discard those high bits and reuse
  -- the same token sequence in every fresh service5 instance. Match Objects
  -- by folding boot epoch and process incarnation before token generation.
  let incarnation := (serviceInstance >>> 8) &&& 0xffffff
  let epoch := ((serviceInstance >>> 32)+incarnation) &&& 0xffffffff
  let t := zero base 32768 t
  store64 state epoch t
end Guest.ContentStore
