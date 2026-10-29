import Guest.LiveMemory
import Guest.Devices
namespace Guest.Live
open Guest.LiveMemory
@[never_extract, extern "lt_idle_pc"] opaque idlePC : UInt64 → UInt64
def state : UInt64 := 0x80900000
def proc (p : UInt64) : UInt64 := state+4096+p*512
def frame (p : UInt64) : UInt64 := state+65536+p*512
def queue (p : UInt64) : UInt64 := 0x80c00000+p*16384
def rx : UInt64 := 0x80d00000
def code (p : UInt64) : UInt64 := 0x81000000+p*262144
def physical (p v : UInt64) : UInt64 := code p+65536+v-0x410000
def valid (ptr len bound : UInt64) : Bool := ptr >= 0x410000 && ptr <= 0x420000 && len <= bound && len <= 0x420000-ptr
def identity (p t : UInt64) : UInt64 := Guest.load64 (proc p+8) t*256+p
def ready (p t : UInt64) : Bool := Guest.load64 (proc p) t == 1
def emit (c t : UInt64) : UInt64 := Guest.store8 0x10000000 c t
partial def digits (v count t : UInt64) : UInt64 :=
  if count == 0 then t else
    let d := (v >>> ((count-1)*4)) &&& 15
    digits v (count-1) (emit (if d < 10 then d+48 else d+87) t)
partial def encoded (p n t : UInt64) : UInt64 :=
  if n == 0 then t else encoded (p+1) (n-1) (digits (Guest.load8 p t) 2 t)
def live (who t : UInt64) : Bool :=
  let p := who &&& 255
  p > 0 && p < 12 && Guest.load64 (proc p) t > 0 && Guest.load64 (proc p) t < 5 && identity p t == who

def pte (pa flags : UInt64) : UInt64 := (pa >>> 12)*1024+flags
partial def pages (tab pa count flags t : UInt64) : UInt64 :=
  if count == 0 then t else pages (tab+8) (pa+4096) (count-1) flags (Guest.store64 tab (pte pa flags) t)
partial def privatePages (mid pa count t : UInt64) : UInt64 :=
  if count == 0 then t else privatePages (mid+8) (pa+0x200000) (count-1) (Guest.store64 mid (pte pa 215) t)
def tables (p t : UInt64) : UInt64 :=
  let root := 0x80100000+p*4096
  let mid := 0x80110000+p*4096
  let leaf := 0x80120000+p*4096
  let t := zero root 512 t
  let t := zero mid 512 t
  let t := zero leaf 512 t
  let t := Guest.store64 (root+16) (pte 0x80000000 207) t
  let t := Guest.store64 root (pte mid 1) t
  let t := Guest.store64 mid (pte 0 207) t
  let t := Guest.store64 (mid+1024) (pte 0x10000000 207) t
  let t := Guest.store64 (mid+16) (pte leaf 1) t
  let t := pages leaf (code p) 16 219 t
  let t := pages (leaf+128) (code p+65536) 16 215 t
  let t := pages (leaf+256) (code p+131072) 4 215 t
  if p == 1 then privatePages (mid+24) 0x83000000 2 t
  else if p == 2 then privatePages (mid+24) 0x84000000 4 t
  else if p == 3 then privatePages (mid+24) 0x85000000 2 t
  else if p == 4 && Guest.load64 (proc p+24) t == 4 then privatePages (mid+24) 0x86000000 8 t
  else t

partial def cancelWaiters (target p t : UInt64) : UInt64 :=
  if p == 12 then t else
    let t := if Guest.load64 (proc p) t == 2 && Guest.load64 (proc p+32) t == target then
      let t := Guest.store64 (frame p+80) err t
      Guest.store64 (proc p) 1 t
    else t
    cancelWaiters target (p+1) t

def clearPrivate (p t : UInt64) : UInt64 :=
  if p == 1 then zero 0x83000000 524288 t
  else if p == 2 then zero 0x84000000 1048576 t
  else if p == 3 then zero 0x85000000 524288 t
  else t

def teardown (p why t : UInt64) : UInt64 :=
  let old := identity p t
  let t := Guest.store64 (proc p) 5 t
  let t := Guest.store64 (proc p+72) why t
  let t := cancelWaiters old 1 t
  let t := zero (queue p) 2048 t
  let t := clearPrivate p t
  let t := zero (code p+65536) 18432 t
  zero (frame p) 34 t

def start (p source len rights entry service t : UInt64) : UInt64 :=
  let generation := Guest.load64 (proc p+8) t
  if generation >= 0x00ffffffffffffff || (generation &&& 0xffffff) == 0xffffff || len == 0 || len > 65536 || entry < 0x400000 || entry >= 0x400000+len then err else
    let t := zero (proc p) 64 t
    let t := zero (queue p) 2048 t
    let t := zero (code p) 32768 t
    let t := copy source (code p) len t
    let t := zero (frame p) 34 t
    let t := Guest.store64 (proc p+8) (generation+1) t
    let t := Guest.store64 (proc p+16) rights t
    let t := Guest.store64 (proc p+24) service t
    let t := Guest.store64 (proc p+80) entry t
    let t := Guest.store64 (proc p+88) len t
    let t := Guest.store64 (frame p+16) 0x424000 t
    let t := Guest.store64 (frame p+256) entry t
    let t := Guest.store64 (frame p+264) 0x20 t
    let t := tables p t
    Guest.store64 (proc p) 1 t

partial def freeSlot (p t : UInt64) : UInt64 :=
  if p == 12 then 0 else
    if Guest.load64 (proc p) t == 0 || Guest.load64 (proc p) t >= 5 then p else freeSlot (p+1) t

partial def choose (p count t : UInt64) : UInt64 :=
  if count == 0 then 0 else
    let next := if p >= 11 then 1 else p+1
    if ready next t then next else choose next (count-1) t

partial def pollRx (fuel t : UInt64) : UInt64 :=
  if fuel == 0 || (Guest.load8 0x10000005 t &&& 1) == 0 then t else
    let head := Guest.load64 rx t
    let tail := Guest.load64 (rx+8) t
    if tail-head >= 8192 then t else
      let byte := Guest.load8 0x10000000 t
      let t := Guest.store8 (rx+64+tail%8192) byte t
      pollRx (fuel-1) (Guest.store64 (rx+8) (tail+1) t)
partial def rxRead (p ptr n copied t : UInt64) : UInt64 :=
  let head := Guest.load64 rx t
  let tail := Guest.load64 (rx+8) t
  if copied == n || head == tail then copied else
    let t := Guest.store8 (physical p (ptr+copied)) (Guest.load8 (rx+64+head%8192) t) t
    let t := Guest.store8 (rx+64+head%8192) 0 t
    let t := Guest.store64 rx (head+1) t
    rxRead p ptr n (copied+1) t

@[noinline] def cancelManagement (t : UInt64) : UInt64 :=
  let waiting : Bool := Guest.load64 (proc 1) t == 2
  let isClient : Bool := (Guest.load64 (proc 1+32) t &&& 255) > 3
  let available : Bool := Guest.load64 rx t < Guest.load64 (rx+8) t
  if waiting && isClient && available then
    let t := Guest.store64 (proc 1+40) 0 t
    let t := Guest.store64 (frame 1+80) err t
    Guest.store64 (proc 1) 1 t
  else t

def wakeSerial (initial : UInt64) : UInt64 :=
  let t := cancelManagement initial
  if Guest.load64 (proc 1) t == 4 && Guest.load64 rx t < Guest.load64 (rx+8) t then
    let n := rxRead 1 (Guest.load64 (proc 1+48) t) (Guest.load64 (proc 1+56) t) 0 t
    let t := Guest.store64 (frame 1+80) n t
    Guest.store64 (proc 1) 1 t
  else t

-- Each caller has one live request. Endpoint queues and reply tokens are kernel-owned.
def allowedEndpoint (caller target h t : UInt64) : Bool :=
  if target == 2 then (h == 2 || h == identity target t) && (Guest.load64 (proc caller+16) t &&& 127) != 0
  else if target == 3 then caller == 1 && (h == 3 || h == identity target t)
  else if target == 1 then false
  else caller == 1 && h == identity target t

def deliver (caller target token src len dst t : UInt64) : UInt64 :=
  let out := physical target dst
  let t := Guest.store64 out (identity caller t) t
  let t := Guest.store64 (out+8) token t
  let t := Guest.store64 (out+16) (Guest.load64 (proc caller+16) t) t
  let t := Guest.store64 (out+24) 2 t
  copy src (out+32) len t

def call (p endpoint ptr len capacity t : UInt64) : UInt64 :=
  let target := endpoint &&& 255
  if target == 0 || target >= 12 || target == p || !valid ptr len 1024 || capacity > 1024 || !valid ptr capacity 1024 then err else
    if !live (identity target t) t || !allowedEndpoint p target endpoint t then err else
      let q := queue target
      let count := Guest.load64 (q+16) t
      if count >= 8 || Guest.load64 (state+8) t == err then err else
        let serial := Guest.load64 (state+8) t+1
        let t := Guest.store64 (state+8) serial t
        let t := Guest.store64 (proc p+32) (identity target t) t
        let t := Guest.store64 (proc p+40) serial t
        let t := Guest.store64 (proc p+120) (Guest.load64 (state+16) t+(if target == 3 then 30000 else 5000)) t
        let t := Guest.store64 (proc p+48) ptr t
        let t := Guest.store64 (proc p+56) capacity t
        let t := Guest.store64 (proc p) 2 t
        if Guest.load64 (proc target) t == 3 then
          let dst := Guest.load64 (proc target+48) t
          let cap := Guest.load64 (proc target+56) t
          if len+32 > cap then
            let t := Guest.store64 (proc p) 1 t
            err+t
          else
            let t := deliver p target serial (physical p ptr) len dst t
            let t := Guest.store64 (frame target+80) (len+32) t
            Guest.store64 (proc target) 1 t
        else
          let tail := Guest.load64 (q+8) t
          let slot := q+64+(tail%8)*1088
          let t := Guest.store64 slot (identity p t) t
          let t := Guest.store64 (slot+8) serial t
          let t := Guest.store64 (slot+16) (Guest.load64 (proc p+16) t) t
          let t := Guest.store64 (slot+24) len t
          let t := copy (physical p ptr) (slot+32) len t
          let t := Guest.store64 (q+8) (tail+1) t
          Guest.store64 (q+16) (count+1) t

partial def receive (p ptr capacity fuel t : UInt64) : UInt64 :=
  if !valid ptr capacity 2048 || capacity < 32 then err else
    let q := queue p
    let count := Guest.load64 (q+16) t
    if count == 0 || fuel == 0 then
      let t := Guest.store64 (proc p+48) ptr t
      let t := Guest.store64 (proc p+56) capacity t
      Guest.store64 (proc p) 3 t
    else
      let head := Guest.load64 q t
      let slot := q+64+(head%8)*1088
      let caller := Guest.load64 slot t
      let callerPID := caller &&& 255
      let token := Guest.load64 (slot+8) t
      let len := Guest.load64 (slot+24) t
      let t := Guest.store64 q (head+1) t
      let t := Guest.store64 (q+16) (count-1) t
      if !live caller t || Guest.load64 (proc callerPID) t != 2 || Guest.load64 (proc callerPID+40) t != token || Guest.load64 (proc callerPID+32) t != identity p t then receive p ptr capacity (fuel-1) (zero slot 136 t)
      else if len+32 > capacity then
        let t := Guest.store64 (proc callerPID) 1 t
        let t := Guest.store64 (frame callerPID+80) err t
        receive p ptr capacity (fuel-1) (zero slot 136 t)
      else
        let t := deliver callerPID p token (slot+32) len ptr t
        let t := zero slot 136 t
        len+32+t

partial def reply (sender token ptr len p t : UInt64) : UInt64 :=
  if p == 12 || !valid ptr len 1024 then err else
    if Guest.load64 (proc p) t == 2 && Guest.load64 (proc p+40) t == token && Guest.load64 (proc p+32) t == identity sender t then
      let capacity := Guest.load64 (proc p+56) t
      if len > capacity then err else
        let dst := Guest.load64 (proc p+48) t
        let t := copy (physical sender ptr) (physical p dst) len t
        let t := Guest.store64 (frame p+80) len t
        Guest.store64 (proc p) 1 t
    else reply sender token ptr len (p+1) t

def release (index : UInt64) : UInt64 := 0x80b10000+index*256
def releaseCode (index : UInt64) : UInt64 := 0x87000000+index*65536
partial def usedRelease (index p t : UInt64) : Bool :=
  if p == 12 then false else
    (Guest.load64 (proc p) t > 0 && Guest.load64 (proc p) t < 5 && Guest.load64 (proc p+112) t == index+1) || usedRelease index (p+1) t

partial def output (p n t : UInt64) : UInt64 :=
  if n == 0 then t else output (p+1) (n-1) (emit (Guest.load8 p t) t)

def console (p ptr n t : UInt64) : UInt64 :=
  if (Guest.load64 (proc p+16) t &&& 128) == 0 || !valid ptr n 1024 then err else
    let t := emit 80 (emit 80 (emit 65 t))
    let t := emit 32 t
    let t := digits (identity p t) 16 t
    let t := emit 32 t
    let t := encoded (physical p ptr) n t
    emit 10 t

partial def inspectProcesses (p dst t : UInt64) : UInt64 :=
  if p == 12 then t else
    let row := dst+p*32
    let t := Guest.store64 row (identity p t) t
    let t := Guest.store64 (row+8) (Guest.load64 (proc p) t) t
    let t := Guest.store64 (row+16) (Guest.load64 (proc p+16) t) t
    let t := Guest.store64 (row+24) (Guest.load64 (proc p+72) t) t
    inspectProcesses (p+1) dst t

def dispatch (p op h ptr n v t : UInt64) : UInt64 :=
  if op == 1 then console p ptr n t
  else if op == 9 then t
  else if op == 10 then teardown p h t
  else if op == 30 then call p h ptr n v t
  else if op == 31 then
    if h == p || h == identity p t then receive p ptr n 8 t else err
  else if op == 32 then reply p h ptr n 1 t
  else if op == 34 then
    if p <= 3 && live h t then Guest.load64 (proc (h &&& 255)+16) t else err
  else if op == 35 then identity p t
  else if op == 40 then
    if p != 1 || !valid ptr n 256 || n == 0 then err else
      let t := pollRx 64 t
      let count := rxRead p ptr n 0 t
      if count > 0 then count else
        let t := Guest.store64 (proc p+48) ptr t
        let t := Guest.store64 (proc p+56) n t
        let t := Guest.store64 (proc p+120) (Guest.load64 (state+16) t+500) t
        Guest.store64 (proc p) 4 t
  else if op == 41 then
    if p == 1 && valid ptr n 4096 then output (physical p ptr) n t else err
  else if op == 42 then
    if p == 1 && valid ptr 384 384 then 384+inspectProcesses 0 (physical p ptr) t else err
  else if op == 50 then
    if p != 1 || h >= 16 || Guest.load64 (release h) t != 1 then err else
      let slot := if ptr == 0 then freeSlot 4 t else ptr &&& 255
      if slot < 4 || slot >= 12 || (ptr != 0 && ptr != identity slot t) || (Guest.load64 (proc slot) t > 0 && Guest.load64 (proc slot) t < 5) then err else
        let r := release h
        let result := start slot (releaseCode h) (Guest.load64 (r+8) t) (Guest.load64 (r+16) t) (Guest.load64 (r+24) t) 0 t
        if result == err then err else
          let t := Guest.store64 (proc slot+112) (h+1) result
          identity slot t
  else if op == 51 then
    if p == 1 && live h t && (h &&& 255) >= 4 then teardown (h &&& 255) 0 t else err
  else if op == 52 then
    if p != 1 || h >= 16 || !valid ptr 64 64 || usedRelease h 4 t then err else
      let src := physical p ptr
      let size := Guest.load64 src t
      let rights := Guest.load64 (src+8) t
      let entry := Guest.load64 (src+16) t
      if size == 0 || size > 65536 || (size &&& 3) != 0 || rights > 255 || entry < 0x400000 || entry >= 0x400000+size then err else
        let t := zero (release h) 32 t
        let t := Guest.store64 (release h+8) size t
        let t := Guest.store64 (release h+16) rights t
        let t := Guest.store64 (release h+24) entry t
        zero (releaseCode h) 8192 t
  else if op == 53 then
    if p != 1 || h >= 16 || Guest.load64 (release h) t != 0 || !valid ptr n 1024 then err else
      let done := Guest.load64 (release h+32) t
      let size := Guest.load64 (release h+8) t
      if done != v || done > size || n > size-done then err else
        let t := copy (physical p ptr) (releaseCode h+done) n t
        Guest.store64 (release h+32) (done+n) t
  else if op == 54 then
    if p == 1 && h < 16 && Guest.load64 (release h+8) t > 0 && Guest.load64 (release h+32) t == Guest.load64 (release h+8) t then Guest.store64 (release h) 1 t else err
  else if op == 55 then
    if p == 1 && h < 16 && !usedRelease h 4 t then
      let t := zero (releaseCode h) 8192 t
      zero (release h) 32 t
    else err
  else if op == 56 then
    let slot := h &&& 255
    if p != 1 || slot < 2 || slot > 3 || identity slot t != h || ptr > 1 then err else
      if ptr == 1 && (Guest.load64 (proc slot+8) t &&& 0xffffff) == 0xffffff then err else
      let t := teardown slot 0 t
      if ptr == 0 then t else
        let descriptor := 0x80200000+slot*32
        let result := start slot (0x80300000+(slot-1)*65536) (Guest.load64 descriptor t) (Guest.load64 (descriptor+8) t) 0x400000 slot t
        if result == err then err else identity slot result
  else if op == 60 || op == 61 then
    if p != 3 || n == 0 || n > 4096 || n%512 != 0 || !valid ptr n 4096 then err else
      let t := if op == 61 then copy (physical p ptr) 0x80e08000 n t else t
      let result := Devices.block (if op == 60 then 0 else 1) h 0x80e08000 n t
      if result != 0 then err else
        if op == 60 then copy 0x80e08000 (physical p ptr) n result else result
  else if op == 62 then
    if p == 3 then Devices.block 4 0 0x80e08000 0 t else err
  else if op == 63 then
    if p != 3 || n == 0 || n > 256 || !valid ptr n 256 then err else
      let result := Devices.random 0x80e0a000 n t
      if result == 0 then copy 0x80e0a000 (physical p ptr) n result else err
  else if op == 70 then if p == 1 then Guest.finish 0 else err
  else err

partial def expire (p now t : UInt64) : UInt64 :=
  if p == 12 then t else
    let t := if (Guest.load64 (proc p) t == 2 || Guest.load64 (proc p) t == 4) && Guest.load64 (proc p+120) t <= now then
      let t := Guest.store64 (proc p+40) 0 t
      let t := Guest.store64 (frame p+80) err t
      Guest.store64 (proc p) 1 t
    else t
    expire (p+1) now t

partial def seedInstances (p seed t : UInt64) : UInt64 :=
  if p == 12 then t else seedInstances (p+1) seed (Guest.store64 (proc p+8) seed t)

partial def bootServices (p t : UInt64) : UInt64 :=
  if p == 4 then t else
    let descriptor := 0x80200000+p*32
    let t := clearPrivate p t
    let result := start p (0x80300000+(p-1)*65536) (Guest.load64 descriptor t) (Guest.load64 (descriptor+8) t) 0x400000 p t
    if result == err then Guest.finish 1 else bootServices (p+1) result

def kernelMain (initial : UInt64) : UInt64 :=
  let t := zero state 16384 initial
  let t := zero 0x80100000 24576 t
  let t := zero 0x80b10000 512 t
  let t := zero 0x80c00000 24576 t
  let t := zero rx 2048 t
  let t := Guest.store8 0x10000002 7 t
  let t := Devices.init t
  let result := Devices.random 0x80e0a000 8 t
  if result != 0 then Guest.finish 1 else
  let seed := (Guest.load64 0x80e0a000 result &&& 0xffffffff) <<< 24
  let t := seedInstances 1 seed result
  let t := zero 0x80e0a000 32 t
  let t := tables 0 t
  let t := Guest.store64 (frame 0+16) 0x800cf000 t
  let t := Guest.store64 (frame 0+256) (idlePC t) t
  let t := Guest.store64 (frame 0+264) 0x120 t
  let t := bootServices 1 t
  let t := Guest.store64 state 1 t
  frame 1+t

def trapDispatch (f cause value : UInt64) : UInt64 :=
  let p := Guest.load64 state f
  let t := copy f (frame p) 272 0
  let saved := frame p
  let op := Guest.load64 (saved+136) t
  let t :=
    if cause == 8 then
      let t := Guest.store64 (saved+256) (Guest.load64 (saved+256) t+4) t
      let result := dispatch p op (Guest.load64 (saved+80) t) (Guest.load64 (saved+88) t) (Guest.load64 (saved+96) t) (Guest.load64 (saved+104) t) t
      Guest.store64 (saved+80) result t
    else if cause == 0x8000000000000001 then
      let now := Guest.load64 (state+16) t+1
      expire 1 now (Guest.store64 (state+16) now t)
    else if p != 0 && (Guest.load64 (saved+264) t &&& 256) == 0 then
      let t := emit 69 (emit 86 t)
      let t := emit 32 t
      let t := digits (identity p t) 16 t
      let t := emit 32 t
      let t := digits cause 16 t
      let t := emit 32 t
      let t := digits value 16 t
      teardown p cause (emit 10 t)
    else Guest.finish 1
  let t := wakeSerial (pollRx 256 t)
  let next := if cause == 8 && op != 9 && ready p t then p else choose p 11 t
  let t := Guest.store64 state next t
  frame next+t
end Guest.Live
