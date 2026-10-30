import Guest.ProjectGraph
namespace Guest.ImportJobs
open Guest.LiveSDK
def base : UInt64 := 0xd78000
def ctx (slot : UInt64) : UInt64 := base+slot*8192
def txn (c t : UInt64) : UInt64 := 0xd70000+(load64 (c+8) t &&& 255)*2048
def rec (c i t : UInt64) : UInt64 := Guest.ProjectGraph.recordAt (load64 (txn c t+832+i*8) t)
def sha (c : UInt64) : UInt64 := c+3072
def tmp (c : UInt64) : UInt64 := c+4096
def step (c phase t : UInt64) : UInt64 := store64 (c+40) phase t
def scope (c t : UInt64) : UInt64 := store64 Guest.ProjectGraph.importContext c (store64 Guest.ProjectGraph.importScope (load64 (c+8) t) t)
def clearScope (t : UInt64) : UInt64 :=
  let t := store64 Guest.ProjectGraph.importContext 0 (store64 Guest.ProjectGraph.importScope 0 t)
  zero Guest.ProjectGraph.marks 64 (zero Guest.ProjectGraph.scratch 128 (zero 0xd00000 80 (zero Guest.ProjectGraph.releaseHash 4 (zero Guest.ProjectGraph.jsonBuffer 1024 t))))
def fail (c code t : UInt64) : UInt64 := step c 90 (store64 c 6 (store64 (c+80) code (store64 (c+208) 0 (store64 (c+216) 0 t))))
def validRecord (c r gen t : UInt64) : Bool :=
  load64 (r+16) t == gen && ((load64 r t == 4 && load64 (r+64) t == load64 (c+8) t && load64 (r+8) t == load64 (c+16) t) ||
    (load64 r t == 2 && Guest.ProjectGraph.cachedVisible (load64 (c+16) t) ((r-0x610000)/0x11000) t))
partial def stagedIndex (c index i t : UInt64) : Bool :=
  if i == load64 (txn c t+32) t then false else
  if load64 (txn c t+832+i*8) t == index then
    let r := Guest.ProjectGraph.recordAt index
    load64 r t == 4 && load64 (r+64) t == load64 (c+8) t && load64 (r+8) t == load64 (c+16) t &&
      load64 (r+16) t == load64 (c+1280+i*8) t && load64 (r+224) t == 1
  else stagedIndex c index (i+1) t
def usableIndex (c index t : UInt64) : Bool :=
  stagedIndex c index 0 t || Guest.ProjectGraph.cachedVisible (load64 (c+16) t) index t
def nextRecord (c t : UInt64) : UInt64 := step c 5 (store64 (c+48) (load64 (c+48) t+1) t)
def setupHash (c p n expected next t : UInt64) : UInt64 :=
  let t := store64 (c+88) p (store64 (c+96) n (store64 (c+104) next (store64 (c+56) 0 t)))
  let t := copy expected (c+3808) 32 t
  step c 2 (Guest.ServiceHash.initialState (sha c) t)
def hashStep (c t : UInt64) : UInt64 :=
  let n := load64 (c+96) t
  let count := (n+72)/64
  let cursor := load64 (c+56) t
  if cursor < count then
    let stop := if count-cursor < 8 then count else cursor+8
    store64 (c+56) stop (Guest.ServiceHash.blocks (sha c) (load64 (c+88) t) n (count*64) cursor stop t)
  else
    let t := Guest.ServiceHash.outputBytes (sha c) (c+3776) 0 t
    if !Guest.ProjectGraph.equal (c+3776) (c+3808) 32 t then fail c 5 t else step c (load64 (c+104) t) t
partial def witnesses (c i stop t : UInt64) : UInt64 :=
  if i == stop then t else
  let cap := Guest.ProjectGraph.capAt i
  let ri := load64 (cap+16) t
  let t := if ri < 64 && load64 (cap+40) t == 1 && load64 (cap+8) t == load64 (c+16) t &&
    (load64 (cap+32) t &&& 1) != 0 && load64 (Guest.ProjectGraph.recordAt ri) t == 2 && load64 (Guest.ProjectGraph.recordAt ri+16) t == load64 (cap+24) t then
      let h := (load64 Guest.ProjectGraph.state t <<< 32) ||| (load64 cap t <<< 8) ||| i
      store64 (c+264+ri*16) (load64 (cap+24) t) (store64 (c+256+ri*16) h t)
    else t
  witnesses c (i+1) stop t
partial def capture (c i t : UInt64) : UInt64 :=
  if i == load64 (txn c t+32) t then t else capture c (i+1) (store64 (c+1280+i*8) (load64 (rec c i t+16) t) t)
def begin (slot h owner rights operation t : UInt64) : UInt64 :=
  let c := ctx slot
  let t := zero c 1024 t
  let t := store64 c 2 (store64 (c+8) h (store64 (c+16) owner (store64 (c+24) rights (store64 (c+32) operation t))))
  capture c 0 (store64 (c+72) (load64 (txn c t+48) t) t)
def stagedValid (c r t : UInt64) : Bool :=
  let ordinal := load64 (c+48) t
  load64 (r+16) t == load64 (c+1280+ordinal*8) t && load64 (r+8) t == load64 (c+16) t &&
    load64 (r+64) t == load64 (c+8) t && (load64 r t == 3 || load64 r t == 4) && load64 (r+24) t == load64 (r+32) t
def payloadStart (c t : UInt64) : UInt64 :=
  if load64 (c+48) t == load64 (txn c t+32) t then step c 5 (store64 (c+48) 0 t) else
  let r := rec c (load64 (c+48) t) t
  if !stagedValid c r t then fail c 3 t else setupHash c (r+256) (load64 (r+32) t) (r+96) 3 t
def identityStart (c t : UInt64) : UInt64 :=
  let r := rec c (load64 (c+48) t) t
  let p := tmp c
  let t := copy (c+3776) (r+128) 32 t
  let t := store64 p 0x3145444f4e544c (store64 (p+8) 1 (store64 (p+16) (load64 (r+40) t) (store64 (p+24) (Guest.ProjectGraph.nodeSchema r t) t)))
  let t := copy (r+128) (p+32) 32 (copy (r+192) (p+64) 32 t)
  setupHash c p 96 (r+160) 4 t
def payloadDone (c t : UInt64) : UInt64 :=
  let r := rec c (load64 (c+48) t) t
  let t := store64 (r+240) (load64 (r+16) t) t
  step c 1 (store64 (c+64) (load64 (c+64) t+load64 (r+32) t) (store64 (c+48) (load64 (c+48) t+1) t))
def typeStart (c t : UInt64) : UInt64 :=
  let j := txn c t
  if load64 (c+48) t == load64 (j+32) t then
    if load64 (c+120) t == load64 (j+32) t then step c 20 (store64 (c+56) 0 (store64 (c+128) 0 t)) else
    if load64 (c+112) t == 0 then fail c 2 t else step c 5 (store64 (c+48) 0 (store64 (c+112) 0 t))
  else
  let r := rec c (load64 (c+48) t) t
  if !stagedValid c r t then fail c 3 t else
  if load64 r t == 4 then nextRecord c t else
  let kind := load64 (r+40) t
  let n := load64 (r+32) t
  let count := load64 (r+272) t
  if kind != 10 && (n < 32 || load64 (r+256) t != 0x31464e4d544c || load64 (r+264) t != Guest.ProjectGraph.nodeSchema r t ||
    count > 32 || load64 (r+280) t > 65536 || n != 32+count*128+load64 (r+280) t) then fail c 2 t else
  let parent := if Guest.ProjectGraph.nodeSchema r t == 2 || Guest.ProjectGraph.allZero (r+192) 32 t then 0 else Guest.ProjectGraph.findVisibleNode (load64 (c+16) t) (r+192) kind 0 t
  if parent == error then nextRecord c t else
    step c (if kind == 10 then 7 else 6) (store64 (c+56) 0 (store64 (c+136) 0 t))
def typeEdge (c t : UInt64) : UInt64 :=
  let r := rec c (load64 (c+48) t) t
  let i := load64 (c+56) t
  if i == load64 (r+272) t then
    if load64 (c+136) t == 0 && load64 (r+40) t != 14 && load64 (r+40) t != 15 then fail c 2 t else step c 7 t
  else
  let e := r+288+i*128
  let kind := load64 e t
  let n := load64 (e+8) t
  if !Guest.ProjectGraph.edgeAllowed (load64 (r+40) t) kind || !Guest.ProjectGraph.validName (e+48) n 80 t || !Guest.ProjectGraph.allZero (e+48+n) (80-n) t ||
    (i > 0 && !Guest.ProjectGraph.lessName (e-80) (load64 (e-120) t) (e+48) n 0 t) then fail c 2 t else
  if Guest.ProjectGraph.findVisibleNode (load64 (c+16) t) (e+16) kind 0 t == error then nextRecord c t else
  let required := (load64 (r+40) t == 11 && kind == 10) || (load64 (r+40) t == 12 && kind == 11) || (load64 (r+40) t == 13 && kind == 12)
  store64 (c+56) (i+1) (store64 (c+136) (load64 (c+136) t+(if required then 1 else 0)) t)
def sealRecord (c t : UInt64) : UInt64 :=
  let r := rec c (load64 (c+48) t) t
  let checked := Guest.ProjectGraph.checkCheckpoint r t
  let checked := if checked == error then error else Guest.ProjectGraph.checkFork r checked
  if checked == error then fail c 2 checked else
  let t := store64 (r+224) 1 (store64 r 4 checked)
  nextRecord c (store64 (c+120) (load64 (c+120) t+1) (store64 (c+112) (load64 (c+112) t+1) t))
def releaseStart (c t : UInt64) : UInt64 :=
  let r := rec c (load64 (c+48) t) t
  let d := r+800
  let h := d+64
  let n := load64 (r+280) t
  if load64 (r+272) t != 4 || !Guest.ProjectGraph.releaseEdge r 0 12 0x646c697562 5 t || !Guest.ProjectGraph.releaseEdge r 1 11 0x65646f63 4 t ||
    !Guest.ProjectGraph.releaseEdge r 2 14 0x65636e6564697665 8 t || !Guest.ProjectGraph.releaseEdge r 3 11 0x656372756f73 6 t ||
    n < 832 || load64 d t != 0x31544e43524c544c || load64 (d+8) t != 1 || load64 (d+16) t != 768 || load64 (d+56) t != 0 ||
    load64 (d+24) t > 65536 || load64 (d+32) t > 65536 || load64 (d+40) t > 65536 || load64 (d+48) t > 65536 ||
    n != 832+load64 (d+24) t+load64 (d+32) t+load64 (d+40) t+load64 (d+48) t ||
    load64 h t != 0x3253454c544c || load64 (h+8) t != 2 || load64 (h+16) t != 512 then fail c 2 t else
  step c 9 (store64 (c+152) h (store64 (c+144) 0 t))
def releaseHash (c t : UInt64) : UInt64 :=
  let h := load64 (c+152) t
  let i := load64 (c+144) t
  if i == 0 then
    let t := zero (tmp c+160) 4 (copy h (tmp c) 512 t)
    setupHash c (tmp c) 512 (h+160) 10 t
  else
    let d := h-64
    let offset := if i == 1 then 0 else load64 (d+24) t+(if i == 2 then 0 else load64 (d+32) t+(if i == 3 then 0 else load64 (d+40) t))
    let size := load64 (d+16+i*8) t
    let expected := h+(if i == 1 then 256 else if i == 2 then 224 else if i == 3 then 352 else 320)
    setupHash c (h+768+offset) size expected 10 t
partial def binaryParts (c binary i used t : UInt64) : UInt64 :=
  if i == load64 (binary+272) t then Guest.Effects.effectValue used t else
  let e := binary+288+i*128
  let found := Guest.ProjectGraph.findNode (e+16) 10 0 t
  if found == error || load64 e t != 10 then error else
  let r := Guest.ProjectGraph.recordAt found
  let n := load64 (r+32) t
  if n == 0 || n > 65536 || used > 262144 || n > 262144-used then error else
  let p := c+1792+i*24
  let t := store64 p r (store64 (p+8) n (store64 (p+16) (load64 (r+16) t) t))
  binaryParts c binary (i+1) (used+n) t
def binaryStart (c t : UInt64) : UInt64 :=
  let r := rec c (load64 (c+48) t) t
  let found := Guest.ProjectGraph.findNode (r+432) 11 0 t
  if found == error then fail c 2 t else
  let b := Guest.ProjectGraph.recordAt found
  if load64 (b+272) t == 0 || load64 (b+272) t > 4 then fail c 2 t else
  let n := binaryParts c b 0 0 t
  if n == error || n != load64 (load64 (c+152) n+24) n then fail c 2 n else
  step c 12 (Guest.ServiceHash.initialState (sha c) (store64 (c+168) n (store64 (c+160) (load64 (b+272) n) (store64 (c+56) 0 n))))
partial def binaryValid (c i t : UInt64) : Bool :=
  if i == load64 (c+160) t then true else
  let p := c+1792+i*24
  validRecord c (load64 p t) (load64 (p+16) t) t && binaryValid c (i+1) t
partial def binaryByte (c offset i t : UInt64) : UInt64 :=
  if i == load64 (c+160) t then 0 else
  let p := c+1792+i*24
  let n := load64 (p+8) t
  if offset < n then load8 (load64 p t+256+offset) t else binaryByte c (offset-n) (i+1) t
partial def binaryBlock (c offset i t : UInt64) : UInt64 :=
  if i == 64 then t else
  let position := offset+i
  let n := load64 (c+168) t
  let total := (n+72)/64*64
  let value := if position < n then binaryByte c position 0 t else if position == n then 128 else if position >= total-8 then ((n*8) >>> ((total-1-position)*8)) &&& 255 else 0
  binaryBlock c offset (i+1) (store8 (c+3840+i) value t)
partial def binaryBlocks (c cursor stop t : UInt64) : UInt64 :=
  if cursor == stop then t else
  let t := binaryBlock c (cursor*64) 0 t
  let t := Guest.ServiceHash.firstWords (sha c) (c+3840) 64 64 0 0 t
  let t := Guest.ServiceHash.expandWords (sha c) 16 t
  let t := Guest.ServiceHash.initRound (sha c) 0 t
  let t := Guest.ServiceHash.rounds (sha c) 0 t
  binaryBlocks c (cursor+1) stop (Guest.ServiceHash.combine (sha c) 0 t)
def binaryStep (c t : UInt64) : UInt64 :=
  if !binaryValid c 0 t then fail c 3 t else
  let cursor := load64 (c+56) t
  let count := (load64 (c+168) t+72)/64
  if cursor < count then
    let stop := if count-cursor < 8 then count else cursor+8
    store64 (c+56) stop (binaryBlocks c cursor stop t)
  else
    let t := Guest.ServiceHash.outputBytes (sha c) (c+3776) 0 t
    if !Guest.ProjectGraph.equal (c+3776) (load64 (c+152) t+192) 32 t then fail c 5 t else step c 13 t
def compareJSON (c n t : UInt64) : UInt64 :=
  let h := load64 (c+152) t
  let size := load64 (h-32) t
  let offset := load64 (c+200) t
  if n == error || offset > size || n > size-offset || !Guest.ProjectGraph.equal Guest.ProjectGraph.jsonBuffer (h+768+load64 (h-40) t+offset) n t then fail c 2 t else
  store64 (c+200) (offset+n) t
def sourceStep (c t : UInt64) : UInt64 :=
  let r := rec c (load64 (c+48) t) t
  let source := Guest.ProjectGraph.findNode (r+688) 11 0 t
  if source == error then fail c 2 t else
  let s := Guest.ProjectGraph.recordAt source
  let i := load64 (c+192) t
  if i == load64 (s+272) t then
    let n := Guest.ProjectGraph.jsonLiteral 6 0 t
    let t := compareJSON c n n
    if load64 (c+40) t == 90 then t else
    if load64 (c+200) t != load64 (load64 (c+152) t-32) t then fail c 2 t else step c 16 t
  else
  let e := s+288+i*128
  let t := store64 (c+192) (i+1) t
  if load64 e t != 10 then t else
  let found := Guest.ProjectGraph.findNode (e+16) 10 0 t
  if found == error then fail c 2 t else
  let source := Guest.ProjectGraph.recordAt found
  let pos := if load64 (c+136) t == 0 then t else Guest.ProjectGraph.jsonLiteral 1 0 t
  let pos := Guest.ProjectGraph.jsonLiteral 2 (if load64 (c+136) t == 0 then 0 else pos) pos
  let pos := Guest.ProjectGraph.jsonName (e+48) (load64 (e+8) pos) pos pos
  let pos := Guest.ProjectGraph.jsonLiteral 3 pos pos
  let pos := Guest.ProjectGraph.jsonHex (source+128) 32 pos pos
  let pos := Guest.ProjectGraph.jsonLiteral 4 pos pos
  let pos := Guest.ProjectGraph.jsonDecimal (load64 (source+32) pos) pos pos
  let pos := Guest.ProjectGraph.jsonLiteral 5 pos pos
  compareJSON c pos (store64 (c+136) (load64 (c+136) pos+1) pos)
def enqueue (c i t : UInt64) : UInt64 :=
  let count := load64 (c+128) t
  if i >= 64 || load64 (c+2304+i*8) t != 0 then t else
  if count == 64 then fail c 2 t else
  store64 (c+128) (count+1) (store64 (c+2304+i*8) 1 (store64 (c+1792+count*8) i t))
def closureStep (c t : UInt64) : UInt64 :=
  let p := load64 (c+40) t
  let cursor := load64 (c+56) t
  if p == 20 then
    if cursor == load64 (txn c t+56) t then step c 21 (store64 (c+56) 0 t) else
    let found := Guest.ProjectGraph.findVisibleNode (load64 (c+16) t) (txn c t+80+cursor*128) 11 0 t
    if found == error then fail c 2 t else enqueue c found (store64 (c+56) (cursor+1) t)
  else if p == 21 then
    if cursor == load64 (c+128) t then step c 23 (store64 (c+56) 0 t) else
    let index := load64 (c+1792+cursor*8) t
    let r := Guest.ProjectGraph.recordAt index
    if !usableIndex c index t then fail c 3 t else
    let parent := if Guest.ProjectGraph.nodeSchema r t == 2 || Guest.ProjectGraph.allZero (r+192) 32 t then 64 else Guest.ProjectGraph.findNode (r+192) (load64 (r+40) t) 0 t
    if parent == error then fail c 2 t else
    let t := enqueue c parent t
    step c 22 (store64 (c+136) 0 t)
  else if p == 22 then
    let index := load64 (c+1792+cursor*8) t
    let r := Guest.ProjectGraph.recordAt index
    if !usableIndex c index t then fail c 3 t else
    let i := load64 (c+136) t
    if load64 (r+40) t == 10 || i == load64 (r+272) t then step c 21 (store64 (c+56) (cursor+1) t) else
    let e := r+288+i*128
    let found := Guest.ProjectGraph.findNode (e+16) (load64 e t) 0 t
    if found == error then fail c 2 t else enqueue c found (store64 (c+136) (i+1) t)
  else
    if cursor == load64 (txn c t+32) t then step c 99 t else
    let index := load64 (txn c t+832+cursor*8) t
    if load64 (c+2304+index*8) t == 0 then fail c 2 t else store64 (c+56) (cursor+1) t
def cleanup (c t : UInt64) : UInt64 :=
  let i := load64 (c+208) t
  let j := txn c t
  if i == load64 (j+32) t then
    let t := store64 j 0 (step c 91 t)
    if load64 (c+240) t != 0 then zero c 1024 t else t
  else
  let r := rec c i t
  if load64 (r+16) t != load64 (c+1280+i*8) t || load64 (r+64) t != load64 (c+8) t || load64 (r+8) t != load64 (c+16) t then
    store64 (c+208) (i+1) (store64 (c+216) 0 t)
  else
  let offset := load64 (c+216) t
  let bytes := load64 (r+32) t
  if offset >= bytes then store64 (c+208) (i+1) (store64 (c+216) 0 (store64 r 0 t)) else
  let n := if bytes-offset < 512 then bytes-offset else 512
  -- Byte tail is bounded; never wipe the next record or its generation.
  let t := zero (r+256+offset) ((n+7)/8) t
  store64 (c+216) (offset+n) t
def work (c t : UInt64) : UInt64 :=
  let p := load64 (c+40) t
  if p == 90 then cleanup c t else
  let rights := syscall 34 (load64 (c+16) t) 0 0 0 t
  if rights == error || (rights &&& load64 (c+24) rights) != load64 (c+24) rights then fail c 1 rights else
  let t := rights
  if p > 0 && p < 20 && load64 (c+48) t < load64 (txn c t+32) t && !stagedValid c (rec c (load64 (c+48) t) t) t then fail c 3 t else
  if p == 0 then
    let cursor := load64 (c+128) t
    let stop := if 256-cursor < 32 then 256 else cursor+32
    let t := witnesses c cursor stop t
    if stop == 256 then step c 1 t else store64 (c+128) stop t
  else if p == 1 then payloadStart c t else
  if p == 2 then hashStep c t else
  if p == 3 then identityStart c t else
  if p == 4 then payloadDone c t else
  if p == 5 then typeStart c t else
  if p == 6 then typeEdge c t else
  if p == 7 then
    if load64 (rec c (load64 (c+48) t) t+40) t == 13 then releaseStart c t else sealRecord c t
  else if p == 9 then releaseHash c t else
  if p == 10 then
    let next := load64 (c+144) t+1
    step c (if next > 4 then 11 else 9) (store64 (c+144) next t)
  else if p == 11 then binaryStart c t else
  if p == 12 then binaryStep c t else
  if p == 13 then
    let r := Guest.ProjectGraph.releaseRelations (rec c (load64 (c+48) t) t) t
    if r == error then fail c 2 r else step c 14 r
  else if p == 14 then
    let n := Guest.ProjectGraph.jsonLiteral 0 0 t
    let t := compareJSON c n (store64 (c+192) 0 (store64 (c+200) 0 (store64 (c+136) 0 n)))
    if load64 (c+40) t == 90 then t else step c 15 t
  else if p == 15 then sourceStep c t else
  if p == 16 then
    let r := rec c (load64 (c+48) t) t
    let build := Guest.ProjectGraph.findNode (r+304) 12 0 t
    if build == error then fail c 2 t else
    let n := Guest.ProjectGraph.canonicalEvidence (Guest.ProjectGraph.recordAt build+544) t
    let h := load64 (c+152) n
    if n == error || n != load64 (h-24) n || !Guest.ProjectGraph.equal Guest.ProjectGraph.jsonBuffer (h+768+load64 (h-40) n+load64 (h-32) n) n n then fail c 2 n else sealRecord c n
  else if p >= 20 && p <= 23 then closureStep c t else t
partial def runnable (i fuel t : UInt64) : UInt64 :=
  if fuel == 0 then error else
  let c := ctx i
  if (load64 c t == 2 && load64 (c+40) t != 99) || load64 (c+40) t == 90 then i else runnable ((i+1)%4) (fuel-1) t
-- At most four liveness checks; paused jobs need no timer. The next Objects
-- request or active-job turn reclaims a dead owner's unpublished state.
partial def reap (i t : UInt64) : UInt64 :=
  if i == 4 then t else
  let c := ctx i
  let t := if load64 c t == 0 || load64 (c+40) t == 90 then t else
    let alive := syscall 34 (load64 (c+16) t) 0 0 0 t
    if alive != error then alive else
    if load64 c alive == 4 || load64 (c+40) alive == 91 then zero c 1024 alive else fail c 1 alive
  reap (i+1) t
def pump (initial : UInt64) : UInt64 :=
  let t := reap 0 initial
  let selected := runnable (load64 (base+32768) t%4) 4 t
  if selected == error then clearScope t else
  let c := ctx selected
  let t := store64 (base+32768) ((selected+1)%4) t
  clearScope (work c (scope c t))
def hasWork (t : UInt64) : Bool := runnable 0 4 t != error
partial def ready (i t : UInt64) : UInt64 :=
  if i == 4 then error else if load64 (ctx i) t == 2 && load64 (ctx i+40) t == 99 then i else ready (i+1) t
end Guest.ImportJobs
