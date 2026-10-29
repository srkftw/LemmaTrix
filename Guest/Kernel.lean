import Guest.Primitives
import Guest.Policy
import Guest.Package
import Guest.SHA256
namespace Guest
-- All mutable state lives in bounded supervisor-only RAM. Tokens sequence primitive effects.
def state : UInt64 := 0x80900000
def err : UInt64 := 0xffffffffffffffff
def emit (c t : UInt64) : UInt64 := store8 0x10000000 c t
partial def hex (v n t : UInt64) : UInt64 :=
  if n == 0 then emit 10 t else
    let d := (v >>> ((n-1)*4)) &&& 15
    let t := emit (if d < 10 then d+48 else d+87) t
    hex v (n-1) t
partial def zero (p n t : UInt64) : UInt64 :=
  if n == 0 then t else zero (p+8) (n-1) (store64 p 0 t)
partial def copy (src dst n t : UInt64) : UInt64 :=
  if n == 0 then t else
    let b := load8 src t
    copy (src+1) (dst+1) (n-1) (store8 dst b t)
def frame (pid : UInt64) : UInt64 := state+4096+pid*512
def cap (pid slot : UInt64) : UInt64 := state+65536+pid*256+slot*32
def obj (id : UInt64) : UInt64 := state+131072+id*512
def userPhys (pid ptr : UInt64) : UInt64 := 0x80600000+(pid-1)*65536+ptr-0x410000
def validBuffer (ptr len : UInt64) : Bool := ptr >= 0x410000 && ptr <= 0x411000 && len <= 256 && len <= 0x411000-ptr
-- Generation, object scope and requested right are checked using kernel-owned pid.
def authorized (pid handle right t : UInt64) : Bool :=
  let slot := handle &&& 255
  if slot >= 4 then false else
    let c := cap pid slot
    Policy.permits (load64 c t) (handle >>> 8) (load64 (c+24) t) (load64 (c+16) t) right

def pte (pa flags : UInt64) : UInt64 := (pa >>> 12)*1024+flags
partial def mapText (tab pa n t : UInt64) : UInt64 :=
  if n == 0 then t else mapText (tab+8) (pa+4096) (n-1) (store64 tab (pte pa 219) t)
def tables (pid t : UInt64) : UInt64 :=
  let root := 0x80100000+pid*4096
  let mid := 0x80110000+pid*4096
  let leaf := 0x80120000+pid*4096
  let t := store64 (root+16) (pte 0x80000000 207) t
  let t := store64 root (pte mid 1) t
  let t := store64 mid (pte 0 207) t
  let t := store64 (mid+1024) (pte 0x10000000 207) t
  let t := store64 (mid+16) (pte leaf 1) t
  let t := mapText leaf (0x80400000+(pid-1)*0x100000) 16 t
  let t := store64 (leaf+128) (pte (0x80600000+(pid-1)*65536) 215) t
  store64 (leaf+256) (pte (0x80700000+(pid-1)*65536) 215) t

def grant (pid slot object rights generation t : UInt64) : UInt64 :=
  let c := cap pid slot
  let t := store64 c generation t
  let t := store64 (c+8) object t
  let t := store64 (c+16) rights t
  store64 (c+24) 1 t

def initFrame (pid t : UInt64) : UInt64 :=
  let f := frame pid
  let t := zero f 34 t
  let t := zero (0x80600000+(pid-1)*65536) 512 t
  let t := zero (0x80700000+(pid-1)*65536) 512 t
  let t := store64 (f+16) 0x421000 t
  let t := store64 (f+256) 0x400000 t
  let t := store64 (f+264) 0x20 t
  store64 (state+pid*8) 1 t

def say_boot (t : UInt64) : UInt64 :=
  let t := emit 76 t
  let t := emit 84 t
  let t := emit 32 t
  let t := emit 115 t
  let t := emit 101 t
  let t := emit 115 t
  let t := emit 115 t
  let t := emit 105 t
  let t := emit 111 t
  let t := emit 110 t
  let t := emit 32 t
  let t := emit 101 t
  let t := emit 112 t
  let t := emit 104 t
  let t := emit 101 t
  let t := emit 109 t
  let t := emit 101 t
  let t := emit 114 t
  let t := emit 97 t
  let t := emit 108 t
  let t := emit 32 t
  let t := emit 65 t
  let t := emit 66 t
  let t := emit 73 t
  let t := emit 49 t
  let t := emit 10 t
  t

def say_fault (t : UInt64) : UInt64 :=
  let t := emit 70 t
  let t := emit 65 t
  let t := emit 85 t
  let t := emit 76 t
  let t := emit 84 t
  let t := emit 32 t
  let t := emit 112 t
  let t := emit 105 t
  let t := emit 100 t
  let t := emit 61 t
  t

def say_done (t : UInt64) : UInt64 :=
  let t := emit 83 t
  let t := emit 69 t
  let t := emit 83 t
  let t := emit 83 t
  let t := emit 73 t
  let t := emit 79 t
  let t := emit 78 t
  let t := emit 32 t
  let t := emit 80 t
  let t := emit 65 t
  let t := emit 83 t
  let t := emit 83 t
  let t := emit 10 t
  t

def say_timer (t : UInt64) : UInt64 :=
  let t := emit 80 t
  let t := emit 82 t
  let t := emit 69 t
  let t := emit 69 t
  let t := emit 77 t
  let t := emit 80 t
  let t := emit 84 t
  let t := emit 32 t
  let t := emit 112 t
  let t := emit 105 t
  let t := emit 100 t
  let t := emit 61 t
  t

def say_denied (t : UInt64) : UInt64 :=
  let t := emit 68 t
  let t := emit 69 t
  let t := emit 78 t
  let t := emit 73 t
  let t := emit 69 t
  let t := emit 68 t
  let t := emit 32 t
  let t := emit 112 t
  let t := emit 105 t
  let t := emit 100 t
  let t := emit 61 t
  t

def say_lineage (t : UInt64) : UInt64 :=
  let t := emit 82 t
  let t := emit 69 t
  let t := emit 86 t
  let t := emit 73 t
  let t := emit 83 t
  let t := emit 73 t
  let t := emit 79 t
  let t := emit 78 t
  let t := emit 32 t
  let t := emit 112 t
  let t := emit 97 t
  let t := emit 114 t
  let t := emit 101 t
  let t := emit 110 t
  let t := emit 116 t
  let t := emit 61 t
  t

def say_revoked (t : UInt64) : UInt64 :=
  let t := emit 82 t
  let t := emit 69 t
  let t := emit 86 t
  let t := emit 79 t
  let t := emit 75 t
  let t := emit 69 t
  let t := emit 32 t
  let t := emit 111 t
  let t := emit 98 t
  let t := emit 106 t
  let t := emit 101 t
  let t := emit 99 t
  let t := emit 116 t
  let t := emit 61 t
  t

def say_shared (t : UInt64) : UInt64 :=
  let t := emit 83 t
  let t := emit 72 t
  let t := emit 65 t
  let t := emit 82 t
  let t := emit 69 t
  let t := emit 32 t
  let t := emit 111 t
  let t := emit 98 t
  let t := emit 106 t
  let t := emit 101 t
  let t := emit 99 t
  let t := emit 116 t
  let t := emit 61 t
  t

def say_install (t : UInt64) : UInt64 :=
  let t := emit 73 t
  let t := emit 78 t
  let t := emit 83 t
  let t := emit 84 t
  let t := emit 65 t
  let t := emit 76 t
  let t := emit 76 t
  let t := emit 32 t
  let t := emit 103 t
  let t := emit 101 t
  let t := emit 110 t
  let t := emit 101 t
  let t := emit 114 t
  let t := emit 97 t
  let t := emit 116 t
  let t := emit 105 t
  let t := emit 111 t
  let t := emit 110 t
  let t := emit 61 t
  t

def say_update (t : UInt64) : UInt64 :=
  let t := emit 85 t
  let t := emit 80 t
  let t := emit 68 t
  let t := emit 65 t
  let t := emit 84 t
  let t := emit 69 t
  let t := emit 32 t
  let t := emit 103 t
  let t := emit 101 t
  let t := emit 110 t
  let t := emit 101 t
  let t := emit 114 t
  let t := emit 97 t
  let t := emit 116 t
  let t := emit 105 t
  let t := emit 111 t
  let t := emit 110 t
  let t := emit 61 t
  t

def say_rollback (t : UInt64) : UInt64 :=
  let t := emit 82 t
  let t := emit 79 t
  let t := emit 76 t
  let t := emit 76 t
  let t := emit 66 t
  let t := emit 65 t
  let t := emit 67 t
  let t := emit 75 t
  let t := emit 32 t
  let t := emit 103 t
  let t := emit 101 t
  let t := emit 110 t
  let t := emit 101 t
  let t := emit 114 t
  let t := emit 97 t
  let t := emit 116 t
  let t := emit 105 t
  let t := emit 111 t
  let t := emit 110 t
  let t := emit 61 t
  t

def say_reject (t : UInt64) : UInt64 :=
  let t := emit 82 t
  let t := emit 69 t
  let t := emit 74 t
  let t := emit 69 t
  let t := emit 67 t
  let t := emit 84 t
  let t := emit 32 t
  let t := emit 112 t
  let t := emit 97 t
  let t := emit 99 t
  let t := emit 107 t
  let t := emit 97 t
  let t := emit 103 t
  let t := emit 101 t
  let t := emit 61 t
  t

def say_preemptions (t : UInt64) : UInt64 :=
  let t := emit 80 t
  let t := emit 82 t
  let t := emit 69 t
  let t := emit 69 t
  let t := emit 77 t
  let t := emit 80 t
  let t := emit 84 t
  let t := emit 73 t
  let t := emit 79 t
  let t := emit 78 t
  let t := emit 83 t
  let t := emit 61 t
  t

def say_alive (t : UInt64) : UInt64 :=
  let t := emit 72 t
  let t := emit 69 t
  let t := emit 65 t
  let t := emit 76 t
  let t := emit 84 t
  let t := emit 72 t
  let t := emit 89 t
  let t := emit 32 t
  let t := emit 97 t
  let t := emit 102 t
  let t := emit 116 t
  let t := emit 101 t
  let t := emit 114 t
  let t := emit 32 t
  let t := emit 102 t
  let t := emit 97 t
  let t := emit 117 t
  let t := emit 108 t
  let t := emit 116 t
  let t := emit 10 t
  t

-- Full validation precedes the synchronous activation; only supervisor code can call this.
def activate (capsule t : UInt64) : UInt64 :=
  let allowed := Package.valid capsule (load64 0x80811000 t) t && load64 (state+32) t < 7
  if allowed then
    let old := load64 (state+48) t
    let proposed := load64 (capsule+56) t
    let t := zero 0x80400000 8192 t
    let t := copy (capsule+128) 0x80400000 (load64 (capsule+40) t) t
    let t := store64 (state+56) old t
    let t := store64 (state+48) (Policy.nextGeneration allowed old proposed) t
    let t := store64 (state+136) capsule t
    let id := load64 (state+32) t+1
    let record := obj id
    let t := copy (capsule+64) (record+64) 32 t
    let t := store64 (record+96) proposed t
    let t := store64 (record+104) (load64 (capsule+48) t) t
    let t := store64 (record+112) 1 t
    let t := store64 (record+120) 1 t
    let t := store64 record 64 t
    let t := store64 (record+8) (load64 (state+112) t) t
    let t := store64 (record+16) 4 t
    let t := Hash.sha256 (record+64) 64 (record+32) t
    let t := store64 (state+32) id t
    let t := store64 (state+112) id t
    let t := grant 1 3 id 1 (load64 (cap 1 3) t+1) t
    let t := store64 (cap 1 2+24) 0 t
    grant 1 0 1 (load64 (capsule+48) t) 1 t
  else err

def kernelMain (initial : UInt64) : UInt64 :=
  let t := zero state 32768 initial
  let t := zero 0x80100000 20000 t
  let t := tables 1 t
  let t := tables 2 t
  let t := initFrame 1 t
  let t := if load64 0x80811008 t == 1 then initFrame 2 t else t
  let t := store64 state 1 t
  let t := store64 (state+32) 1 t
  let len := load64 0x80800000 t
  let t := store64 (obj 1+16) 1 t
  let t := store64 (obj 1) (if len <= 256 then len else 0) t
  let t := copy 0x80800008 (obj 1+64) (if len <= 256 then len else 0) t
  let t := Hash.sha256 (obj 1+64) (load64 (obj 1) t) (obj 1+32) t
  let t := grant 1 0 1 7 1 t
  let t := say_boot t
  let t := activate 0x80a00000 t
  let t := if t == err then finish 1 else t
  let t := hex (load64 (state+48) t) 1 (say_install t)
  frame (1+t)

partial def console (p n t : UInt64) : UInt64 :=
  if n == 0 then t else console (p+1) (n-1) (emit (load8 p t) t)

def deniedResult (pid t : UInt64) : UInt64 :=
  let t := hex pid 1 (say_denied t)
  err+t

def dispatch (pid op h p n v t : UInt64) : UInt64 :=
  if op == 1 then
    if validBuffer p n then console (userPhys pid p) n t else deniedResult pid t
  else if op == 2 then
    if authorized pid h 1 t && validBuffer p n then
      let o := obj (load64 (cap pid (h &&& 255)+8) t)
      let len := load64 o t
      if len <= n && len <= 256 && Package.equalDigest (o+32) 0x80970000 32 (Hash.sha256 (o+64) len 0x80970000 t) then len + copy (o+64) (userPhys pid p) len t else err
    else deniedResult pid t
  else if op == 3 then
    if authorized pid h 2 t && validBuffer p n then
      let count := load64 (state+32) t
      if count >= 7 || load64 (cap pid 2) t >= 0x00ffffffffffffff then err else
        let id := count+1
        let o := obj id
        let parent := load64 (cap pid (h &&& 255)+8) t
        let t := copy (userPhys pid p) (o+64) n t
        let t := store64 o n t
        let t := store64 (o+8) parent t
        let t := store64 (o+16) 2 t
        let t := store64 (o+24) pid t
        let t := Hash.sha256 (o+64) n (o+32) t
        let t := store64 (state+32) id t
        let generation := load64 (cap pid 2) t+1
        let t := grant pid 2 id (load64 (cap pid (h &&& 255)+16) t) generation t
        let t := hex parent 1 (say_lineage t)
        generation*256+2+t
    else deniedResult pid t
  else if op == 4 then
    if authorized pid h 5 t && v == 2 && n == 1 && load64 (cap 2 1) t < 0x00ffffffffffffff then
      let id := load64 (cap pid (h &&& 255)+8) t
      let gen := load64 (cap 2 1) t+1
      let t := grant 2 1 id 1 gen t
      let t := hex id 1 (say_shared t)
      gen*256+1+t
    else deniedResult pid t
  else if op == 5 then
    if authorized pid h 4 t then
      let id := load64 (cap pid (h &&& 255)+8) t
      let c := cap 2 1
      if load64 (c+8) t == id && load64 c t < 0x00ffffffffffffff then
        let t := store64 c (load64 c t+1) t
        let t := store64 (c+24) 0 t
        let t := hex id 1 (say_revoked t)
        t
      else err
    else deniedResult pid t
  else if op == 6 then
    if authorized pid h 1 t then load64 (obj (load64 (cap pid (h &&& 255)+8) t)+8) t else deniedResult pid t
  else if op == 12 then
    if authorized pid h 1 t then store64 (state+96) 1 t else deniedResult pid t
  else if op == 13 then
    if pid == 1 then load64 (state+96) t else deniedResult pid t
  else if op == 14 then
    if pid == 1 then load64 (state+16) t else deniedResult pid t
  else if op == 15 then
    if pid == 1 then load64 (cap pid 3) t*256+3 else deniedResult pid t
  else if op == 7 || op == 8 then deniedResult pid t
  else deniedResult pid t

def choose (pid t : UInt64) : UInt64 :=
  let other := if pid == 1 then 2 else 1
  if load64 (state+other*8) t == 1 then other
  else if load64 (state+pid*8) t == 1 then pid
  else 0

-- Rejection evidence checks the previous executable, generation, quota and grants.
def rejectExpected (capsule label t : UInt64) : UInt64 :=
  let generation := load64 (state+48) t
  let count := load64 (state+32) t
  let old := load64 (state+136) t
  let t := Hash.sha256 (cap 1 0) 512 0x80978000 t
  let result := activate capsule t
  if result == err && load64 (state+48) result == generation && load64 (state+32) result == count then
    let t := Hash.sha256 (cap 1 0) 512 0x80979000 result
    let grantsUnchanged := Package.equalDigest 0x80978000 0x80979000 32 t
    let t := Hash.sha256 0x80400000 (load64 (old+40) t) 0x80979000 t
    if grantsUnchanged && Package.equalDigest (old+64) 0x80979000 32 t then hex label 1 (say_reject t)
    else finish 1
  else finish 1

-- The development launcher drives 1 -> 2 -> rollback1 and validates failed updates.
def lifecycle (t : UInt64) : UInt64 :=
  let stage := load64 (state+72) t
  if load64 0x80811008 t == 0 then t
  else if stage == 0 then
    let t := rejectExpected 0x80a40000 1 t
    let t := rejectExpected 0x80a60000 2 t
    let t := rejectExpected 0x80a80000 3 t
    let t := rejectExpected 0x80aa0000 4 t
    let result := activate 0x80a20000 t
    if result == err then store64 (state+128) 1 (say_reject t) else
      let t := store64 (state+72) 1 result
      let t := initFrame 1 t
      hex (load64 (state+48) t) 1 (say_update t)
  else if stage == 1 then
    let result := activate 0x80a00000 t
    if result == err then store64 (state+128) 1 (say_reject t) else
      let t := store64 (state+72) 2 result
      let t := initFrame 1 t
      hex (load64 (state+48) t) 1 (say_rollback t)
  else
    let handle := load64 (cap 1 2) t*256+2
    let quota := dispatch 1 3 handle 0x410000 1 0 t
    let t := if quota == err then t else finish 1
    let t := say_alive t
    hex (load64 (state+40) t) 8 (say_preemptions t)

-- Assembly only captures architectural state; policy, dispatch and scheduling are Lean.
def trapDispatch (f cause value : UInt64) : UInt64 :=
  let pid := load64 state f
  let t := copy f (frame pid) 272 0
  let saved := frame pid
  let op := load64 (saved+136) t
  let t :=
    if cause == 8 then
      let t := store64 (saved+256) (load64 (saved+256) t+4) t
      if op == 10 then
        let t := store64 (state+pid*8) 0 t
        if pid == 1 then lifecycle t else t
      else if op == 9 then t
      else
        let result := dispatch pid op (load64 (saved+80) t) (load64 (saved+88) t) (load64 (saved+96) t) (load64 (saved+104) t) t
        store64 (saved+80) result t
    else if cause == 0x8000000000000001 then
      let t := store64 (state+40) (load64 (state+40) t+1) t
      t
    else
      let t := hex pid 1 (say_fault t)
      let t := hex cause 16 t
      let t := hex value 16 t
      if (load64 (saved+264) t &&& 256) == 0 then store64 (state+pid*8) 0 t else finish 1
  let next := if cause == 8 && op != 9 && op != 10 then pid else choose pid t
  if next == 0 then
    if load64 (state+128) t == 0 then finish (say_done t) else finish 1
  else
    let t := store64 state next t
    frame next+t
end Guest
