import Guest.LiveMemory
import Guest.Devices
import Guest.GraphicsDevice
import Guest.AudioDevice
namespace Guest.Live
open Guest.LiveMemory
@[never_extract, extern "lt_idle_pc"] opaque idlePC : UInt64 → UInt64
def state : UInt64 := 0x80900000
def proc (p : UInt64) : UInt64 := state+4096+p*512
def frame (p : UInt64) : UInt64 := state+65536+p*512
def queue (p : UInt64) : UInt64 := 0x80c00000+p*16384
def rx : UInt64 := 0x80d00000
def code (p : UInt64) : UInt64 := 0x81000000+p*524288
def arena (p : UInt64) : UInt64 := 0x81800000+p*0x200000
-- Built-in Objects/Vault profile3 uses the same private512KiB physical slot. Native
-- signed application profile2 retains its256KiB ceiling and existing mapping.
def codeLimit (p service : UInt64) : UInt64 := if (p == 2 && service == 2) || (p == 3 && service == 3) then 393216 else 262144
def dataOffset (p : UInt64) : UInt64 := if p == 2 || p == 3 then 393216 else 262144
def stackOffset (p : UInt64) : UInt64 := if p == 2 || p == 3 then 458752 else 327680
def serviceSource (p : UInt64) : UInt64 := if p == 2 then 0x80480000 else if p == 3 then 0x80500000 else 0x80300000+(p-1)*262144
theorem ordinary_application_code_limit (p : UInt64) : codeLimit p 0 = 262144 := by
  simp [codeLimit]
def physical (p v : UInt64) : UInt64 :=
  if v >= 0x600000 then arena p+v-0x600000 else code p+dataOffset p+v-0x410000
def valid (ptr len bound : UInt64) : Bool := ptr >= 0x410000 && ptr <= 0x420000 && len <= bound && len <= 0x420000-ptr
def validFor (p ptr len bound t : UInt64) : Bool :=
  valid ptr len bound || (Guest.load64 (proc p+96) t == 2 && ptr >= 0x600000 && ptr <= 0x800000 && len <= bound && len <= 0x800000-ptr)
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
  let wide := p > 0 && Guest.load64 (proc p+80) t < 0x400000
  let wideLeaf := 0x80130000+p*4096
  let t := zero wideLeaf 512 t
  let t := Guest.store64 (mid+8) (pte wideLeaf 1) t
  let t := if wide then pages wideLeaf (code p) (codeLimit p (Guest.load64 (proc p+24) t)/4096) 219 t else pages leaf (code p) 16 219 t
  let t := pages (leaf+128) (code p+dataOffset p) 16 215 t
  let t := pages (leaf+384) (code p+stackOffset p) 4 215 t
  if p == 1 then privatePages (mid+24) 0x83000000 2 t
  else if p == 2 then privatePages (mid+24) 0x84000000 4 t
  else if p == 3 then privatePages (mid+24) 0x85000000 2 t
  else if p == 5 then
    let t := privatePages (mid+24) (arena p) 1 t
    privatePages (mid+56) 0x89000000 4 t
  else if p >= 4 && Guest.load64 (proc p+96) t == 2 then privatePages (mid+24) (arena p) 1 t
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
  else if p == 5 then zero 0x89000000 1048576 (zero (arena p) 262144 t)
  else if p >= 4 && Guest.load64 (proc p+96) t == 2 then zero (arena p) 262144 t
  else t

def teardown (p why t : UInt64) : UInt64 :=
  let old := identity p t
  let t := Guest.AudioDevice.died old t
  let t := if Guest.load64 (state+216) t == old then Guest.store64 (state+216) 0 t else t
  let t := if Guest.load64 (state+128) t == old then Guest.store64 (state+128) 0 t else t
  let t := Guest.store64 (proc p) 5 t
  let t := Guest.store64 (proc p+72) why t
  let t := cancelWaiters old 1 t
  let t := zero (queue p) 2048 t
  let t := clearPrivate p t
  let t := if p >= 6 then zero (0x87200000+(p-5)*0x100000) 112640 t else t
  let t := if p == 2 || p == 3 then zero (code p+stackOffset p) 2048 (zero (code p+dataOffset p) 8192 t)
    else zero (code p+262144) 18432 t
  zero (frame p) 34 t

def start (p source len rights entry service t : UInt64) : UInt64 :=
  let generation := Guest.load64 (proc p+8) t
  if generation >= 0x00ffffffffffffff || (generation &&& 0xffffff) == 0xffffff ||
    ((p == 2 || p == 3) && service != p) || len == 0 || len > codeLimit p service ||
    (entry != 0x200000 && entry != 0x400000) || (entry == 0x400000 && len > 65536) then err else
    let t := zero (proc p) 64 t
    let t := zero (queue p) 2048 t
    let t := zero (code p) 65536 t
    let t := copy source (code p) len t
    let t := zero (frame p) 34 t
    let t := Guest.store64 (proc p+8) (generation+1) t
    let t := Guest.store64 (proc p+16) rights t
    let t := Guest.store64 (proc p+24) service t
    let t := Guest.store64 (proc p+80) entry t
    let t := Guest.store64 (proc p+88) len t
    let t := Guest.store64 (proc p+96) (if service >= 4 then 2 else 1) t
    let t := Guest.store64 (frame p+16) 0x434000 t
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
  else if target == 3 then (caller == 1 || (Guest.load64 (proc caller+16) t &&& 2048) != 0) && (h == 3 || h == identity target t)
  else if target == 1 then caller == 4 && (h == 1 || h == identity target t)
  else if target == 5 then (h == 5 || h == identity target t) && (caller == 1 || (Guest.load64 (proc caller+16) t &&& 256) != 0 || identity caller t == Guest.load64 (state+208) t)
  else if target == 6 then (h == 6 || h == identity target t) && (caller == 1 || (Guest.load64 (proc caller+16) t &&& 1024) != 0)
  else if target == 4 then (h == 4 || h == identity target t) && (Guest.load64 (proc caller+16) t &&& 256) != 0
  else (caller == 1 || caller == 4 || identity caller t == Guest.load64 (state+216) t || (h == Guest.load64 (state+200) t && (Guest.load64 (proc caller+16) t &&& 1024) != 0)) && h == identity target t

def callerRights (caller t : UInt64) : UInt64 :=
  Guest.load64 (proc caller+16) t ||| (if Guest.load64 (proc caller+24) t == 5 then 0x200000000 else if Guest.load64 (proc caller+24) t == 3 then 0x400000000 else 0)

def deliver (caller target token src len dst t : UInt64) : UInt64 :=
  let out := physical target dst
  let t := Guest.store64 out (identity caller t) t
  let t := Guest.store64 (out+8) token t
  let t := Guest.store64 (out+16) (callerRights caller t) t
  let t := Guest.store64 (out+24) 2 t
  copy src (out+32) len t

-- Native approval rechecks bounded code/hash/RSA material before publication.
-- The assembly backends advance timer ticks by retired instruction quanta;
-- their ordinary 5,000-tick RPC deadline can expire before this work replies.
-- Extend only these authenticated local service operations. Remote transfers
-- remain asynchronous broker jobs, and all other ordinary calls keep 5,000.
def rpcBudget (caller target endpoint ptr len t : UInt64) : UInt64 :=
  let operation := if len >= 8 then Guest.load64 (physical caller ptr) t else err
  if caller == 4 && target == 1 && ((operation == 24 && len == 8) || (operation == 180 && len == 16)) then 30000
  else if caller >= 7 && target == 4 && len == 64 && operation == 6 &&
      Guest.load64 (physical caller ptr+56) t == 1 then 60000
  else if target == 2 && len == 64 && (operation == 38 || operation == 43) &&
      Guest.load64 (physical caller ptr+56) t == 1 then 30000
  else if target == 6 && operation == 12 && len == 320 &&
      (Guest.load64 (physical caller ptr+56) t &&& 255) == 2 then 30000
  else if target == 3 || endpoint == Guest.load64 (state+200) t then 30000
  else 5000

def call (p endpoint ptr len capacity t : UInt64) : UInt64 :=
  let target := endpoint &&& 255
  if target == 0 || target >= 12 || target == p || !validFor p ptr len 1024 t || capacity > 1024 || !validFor p ptr capacity 1024 t then err else
    let operation := if len >= 64 then Guest.load64 (physical p ptr) t else err
    let contentCall := target == 5 && (endpoint == 5 || endpoint == identity 5 t) &&
      ((operation >= 300 && operation <= 316) || operation == 318) && (Guest.load64 (proc p+16) t &&& 127) != 0
    -- Trusted compositor progress never calls back through a Launcher that
    -- may itself be inspecting the Library. This single read-only operation
    -- neither grants a vault mount nor changes the caller's domain rights.
    -- Only the content compartment may resolve a retained locator. Vault owns
    -- keys/block I/O; an application cannot turn a locator into a disk mount.
    let retainedRead := p == 5 && target == 3 && (endpoint == 3 || endpoint == identity 3 t) &&
      (operation == 268 || operation == 269) && len >= 64 && len <= 1024 &&
      Guest.load64 (physical p ptr+56) t == 1
    -- Attaching metadata creates fresh read authority, never old grant numbers.
    let retainedSelection := identity p t == Guest.load64 (state+216) t && target == 3 &&
      (endpoint == 3 || endpoint == identity 3 t) && operation == 264 && len == 64 &&
      Guest.load64 (physical p ptr+56) t == 1
    let retainedAttach := p == 3 && target == 5 && (endpoint == 5 || endpoint == identity 5 t) &&
      operation == 317 && len >= 64 && len <= 1024 && Guest.load64 (physical p ptr+56) t == 1
    -- A serving app can charge/inspect only an already bound service job.
    -- Vault validates the exact fresh owner, request and policy on each call.
    let serviceProgress := target == 3 && (endpoint == 3 || endpoint == identity 3 t) &&
      (Guest.load64 (proc p+16) t &&& 1025) == 1025 && len == 64 &&
      (operation == 283 || operation == 284 || operation == 285) && Guest.load64 (physical p ptr+56) t == 1
    let contentProgress := p == 4 && Guest.load64 (proc p+24) t == 4 && target == 3 &&
      (endpoint == 3 || endpoint == identity 3 t) && len == 64 && operation == 247 &&
      Guest.load64 (physical p ptr+16) t == 3 && Guest.load64 (physical p ptr+56) t == 1
    if !live (identity target t) t || (!contentCall && !contentProgress && !retainedRead && !retainedAttach && !retainedSelection && !serviceProgress && !allowedEndpoint p target endpoint t) then err else
      let t := if Guest.load64 (proc target) t == 4 then
        let t := Guest.store64 (frame target+80) 0 t
        Guest.store64 (proc target) 1 t else t
      let q := queue target
      let count := Guest.load64 (q+16) t
      if count >= 8 || Guest.load64 (state+8) t == err then err else
        let serial := Guest.load64 (state+8) t+1
        let t := Guest.store64 (state+8) serial t
        let t := Guest.store64 (proc p+32) (identity target t) t
        let t := Guest.store64 (proc p+40) serial t
        let t := Guest.store64 (proc p+120) (Guest.load64 (state+16) t+rpcBudget p target endpoint ptr len t) t
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
          let t := Guest.store64 (slot+16) (callerRights p t) t
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
def releaseCode (index : UInt64) : UInt64 := 0x86400000+index*262144
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
  else if op == 36 then
    if (h == p || h == identity p t) && Guest.load64 (queue p+16) t > 0 then receive p ptr n 8 t else 0
  else if op == 31 then
    if h == p || h == identity p t then receive p ptr n 8 t else err
  else if op == 32 then reply p h ptr n 1 t
  else if op == 34 then
    if p <= 6 && live h t then Guest.load64 (proc (h &&& 255)+16) t else err
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
      let slot := if ptr == 0 then freeSlot 7 t else ptr &&& 255
      if slot < 7 || slot >= 12 || (ptr != 0 && ptr != identity slot t) || (Guest.load64 (proc slot) t > 0 && Guest.load64 (proc slot) t < 5) then err else
        let r := release h
        let result := start slot (releaseCode h) (Guest.load64 (r+8) t) (Guest.load64 (r+16) t) (Guest.load64 (r+24) t) 0 t
        if result == err then err else
          let t := Guest.store64 (proc slot+96) (Guest.load64 (release h+40) result) result
          let t := if Guest.load64 (proc slot+96) t == 2 then zero (arena slot) 262144 t else t
          let t := tables slot t
          let t := Guest.store64 (proc slot+112) (h+1) t
          identity slot t
  else if op == 51 then
    if p == 1 && live h t && (h &&& 255) >= 4 then teardown (h &&& 255) 0 t else err
  else if op == 52 then
    if p != 1 || h >= 16 || !valid ptr 64 64 || usedRelease h 4 t then err else
      let src := physical p ptr
      let size := Guest.load64 src t
      let rights := Guest.load64 (src+8) t
      let entry := Guest.load64 (src+16) t
      if size == 0 || size > 262144 || (size &&& 3) != 0 || rights > 8191 || (entry != 0x200000 && entry != 0x400000) || (entry == 0x400000 && size > 65536) then err else
        let t := zero (release h) 32 t
        let t := Guest.store64 (release h+8) size t
        let t := Guest.store64 (release h+16) rights t
        let t := Guest.store64 (release h+24) entry t
        let t := copy (src+32) (release h+64) 32 t
        let profile := Guest.load64 (src+24) t
        let t := Guest.store64 (release h+40) (if profile == 2 then 2 else 1) t
        zero (releaseCode h) 32768 t
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
      let t := zero (releaseCode h) 32768 t
      zero (release h) 32 t
    else err
  else if op == 56 then
    let slot := h &&& 255
    if p != 1 || (slot != 2 && slot != 3 && slot != 6) || identity slot t != h || ptr > 1 then err else
      if ptr == 1 && (Guest.load64 (proc slot+8) t &&& 0xffffff) == 0xffffff then err else
      let t := teardown slot 0 t
      let t := if slot == 6 then Devices.streamInit t else t
      if ptr == 0 then t else
        let descriptor := 0x80200000+slot*32
        if Guest.load64 (descriptor+16) t != 2 || Guest.load64 (descriptor+24) t != codeLimit slot slot then err else
        let result := start slot (serviceSource slot) (Guest.load64 descriptor t) (Guest.load64 (descriptor+8) t) 0x200000 slot t
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
  else if op == 64 then
    if p == 3 && (h == 1 || h == 2) then Devices.capacityPurpose h t else err
  else if op == 65 || op == 66 then
    if p != 3 || (v != 1 && v != 2) || n == 0 || n > 4096 || n%512 != 0 || !valid ptr n 4096 then err else
    let t := if op == 66 then copy (physical p ptr) Devices.blockBuffer n t else t
    let result := Devices.blockPurpose v (if op == 65 then 0 else 1) h Devices.blockBuffer n t
    if result != 0 then err else
    if op == 65 then copy Devices.blockBuffer (physical p ptr) n result else result
  else if op == 67 then
    if p == 3 && (h == 1 || h == 2) then Devices.blockPurpose h 4 0 Devices.blockBuffer 0 t else err
  else if op == 80 then
    if p < 5 || (Guest.load64 (proc p+16) t &&& 256) == 0 || Guest.load64 (proc p+96) t != 2 then err else
      let t := if Guest.load64 (proc p+160) t == 0 then zero (0x87200000+(p-5)*0x100000) 112640 t else t
      let t := Guest.store64 (proc p+208) 0 t
      let t := Guest.store64 (proc p+216) 352 t
      let t := Guest.store64 (proc p+160) 1 t
      let t := Guest.store64 (proc p+168) 1 t
      let t := Guest.store64 (proc p+200) 0 t
      identity p t
  else if op == 81 then
    if p < 5 || h != identity p t || Guest.load64 (proc p+160) t != 1 || Guest.load64 (proc p+168) t == err || !validFor p ptr n 1024 t || n%4 != 0 || v > 901120 || n > 901120-v then err else
      let t := copy (physical p ptr) (0x87200000+(p-5)*0x100000+v) n t
      let first := v/2560
      let lastRow := (v+n+2559)/2560
      let t := Guest.store64 (proc p+208) (if first < Guest.load64 (proc p+208) t then first else Guest.load64 (proc p+208) t) t
      let t := Guest.store64 (proc p+216) (if lastRow > Guest.load64 (proc p+216) t then lastRow else Guest.load64 (proc p+216) t) t
      Guest.store64 (proc p+168) (Guest.load64 (proc p+168) t+1) t
  else if op == 82 then
    if p != 4 || !live h t || (h &&& 255) < 5 || Guest.load64 (proc (h &&& 255)+160) t != 1 then err else
      let q := proc (h &&& 255)
      let epoch := Guest.load64 (q+168) t
      if epoch == Guest.load64 (q+200) t then 0 else epoch
  else if op == 83 then
    if p != 4 || !live h t || (h &&& 255) < 5 || Guest.load64 (proc (h &&& 255)+160) t != 1 || ptr >= 352 || n == 0 || n > 8 || n > 352-ptr then err else
      let t := copy (0x87200000+((h &&& 255)-5)*0x100000+ptr*2560) (0x80f00000+(ptr+48)*2560) (n*2560) t
      let q := proc (h &&& 255)
      if ptr+n >= Guest.load64 (q+216) t && Guest.load64 (q+168) t == v then
        let t := Guest.store64 (q+208) 352 t
        let t := Guest.store64 (q+216) 0 t
        Guest.store64 (q+200) v t else t
  else if op == 84 then
    if p != 4 then err else
      let event := Guest.GraphicsDevice.input t
      if event >>> 48 == 1 && (event &&& 0xffffffff) == 1 &&
        (((event >>> 32) &&& 65535) == 28 || ((event >>> 32) &&& 65535) == 272) then
        let t := Guest.store64 (state+136) (Guest.load64 (state+136) event+1) event
        let t := Guest.store64 (state+144) (Guest.load64 (state+16) t) t
        event+t
      else event
  else if op == 85 then
    if p != 4 || (h != 0 && (!live h t || (h &&& 255) < 5 || Guest.load64 (proc (h &&& 255)+160) t != 1)) then err else
      let old := Guest.load64 (state+128) t
      let t := if old != 0 && live old t then
        let q := proc (old &&& 255)
        let t := Guest.store64 (q+176) (Guest.load64 (q+184) t) t
        Guest.store64 (q+192) 1 t else t
      let t := if h != 0 then
        let q := proc (h &&& 255)
        let t := Guest.store64 (q+176) (Guest.load64 (q+184) t) t
        Guest.store64 (q+192) 1 t else t
      Guest.store64 (state+128) h t
  else if op == 86 then
    if p != 4 || !validFor p ptr n 1024 t || n%4 != 0 || v > 1024000 || n > 1024000-v then err else
      copy (physical p ptr) (0x80f00000+v) n t
  else if op == 87 then
    if p != 4 then err else Guest.GraphicsDevice.presentBegin 0 h 640 ptr t
  else if op == 88 then
    if p == 4 then Guest.GraphicsDevice.presentPoll t else err
  else if op == 89 then
    if p != 4 || h == 0 || n == 0 || n > 0xffffffff then err else
      let focus := Guest.load64 (state+128) t
      if focus == 0 || !live focus t then 0 else
        let q := proc (focus &&& 255)
        let head := Guest.load64 (q+176) t
        let tail := Guest.load64 (q+184) t
        if tail-head >= 64 then
          let t := Guest.store64 (q+176) tail t
          Guest.store64 (q+192) 1 t
        else
          let t := Guest.store64 (0x80d10000+(focus &&& 255)*1024+(tail%64)*8) h t
          let t := Guest.store64 (q+184) (tail+1) t
          if Guest.load64 q t == 4 then Guest.store64 q 1 (Guest.store64 (frame (focus &&& 255)+80) 0 t) else t
  else if op == 90 then
    if p < 5 || h != identity p t || (Guest.load64 (proc p+16) t &&& 512) == 0 then err else
      let q := proc p
      if Guest.load64 (q+192) t == 1 then
        let t := Guest.store64 (q+192) 0 t
        0xffff000000000000+t
      else
        let head := Guest.load64 (q+176) t
        let tail := Guest.load64 (q+184) t
        if head == tail then 0 else
          let event := Guest.load64 (0x80d10000+p*1024+(head%64)*8) t
          let t := Guest.store64 (q+176) (head+1) t
          event+t
  else if op == 92 then
    if p != 4 || !live h t || (h &&& 255) < 6 then err else
      (Guest.load64 (proc (h &&& 255)+208) t <<< 32) ||| Guest.load64 (proc (h &&& 255)+216) t
  else if op == 93 then
    -- Trusted compositor cursor readback: a single bounded pixel row only.
    if p != 4 || n == 0 || n > 28 || n%4 != 0 || h%4 != 0 || h > 1024000 || n > 1024000-h || h%2560+n > 2560 || !validFor p ptr n 28 t then err else
      copy (0x80f00000+h) (physical p ptr) n t
  else if op == 111 then
    -- Fresh fork namespaces are minted by Objects; no application is granted
    -- raw entropy/device access or a reusable local capability as an identity.
    if p != 2 || n != 32 || !(valid ptr 32 32 || (ptr >= 0x600000 && ptr <= 0xdfffe0)) then err else
      let r := Devices.random 0x80e0a000 32 t
      let destination := if ptr >= 0x600000 then 0x84000000+ptr-0x600000 else physical p ptr
      if r == 0 then copy 0x80e0a000 destination 32 r else err
  else if op == 100 then
    if p != 5 || n != 32 || !validFor p ptr 32 32 t then err else copy 0x80200400 (physical p ptr) 32 t
  else if op == 101 then
    if p == 6 && Guest.load64 (proc p+24) t == 6 then Devices.streamStatus t else err
  else if op == 102 then
    if p != 6 || Guest.load64 (proc p+24) t != 6 || !validFor p ptr n 1024 t then err else
    Devices.streamRead (physical p ptr) n t
  else if op == 103 then
    if p != 6 || Guest.load64 (proc p+24) t != 6 || !validFor p ptr n 1024 t then err else
    Devices.streamWrite (physical p ptr) n t
  else if op == 104 then
    if p != 6 || Guest.load64 (proc p+24) t != 6 || n == 0 || n > 256 || !validFor p ptr n 256 t then err else
    let result := Devices.random Devices.randomBuffer n t
    if result != 0 then err else n+copy Devices.randomBuffer (physical p ptr) n result
  else if op == 105 then
    if p == 6 && Guest.load64 (proc p+24) t == 6 then
      let result := Devices.streamInit t
      if result == err then err else Devices.streamStatus result
    else err
  else if op == 116 then Guest.load64 (state+16) t
  else if op == 117 then
    let now := Guest.load64 (state+16) t
    let q := proc p
    if Guest.load64 (q+224) t != 0 then Guest.store64 (q+224) 0 t else
    if h <= now || Guest.load64 (queue p+16) t != 0 || Guest.load64 (q+176) t != Guest.load64 (q+184) t then 0 else
    let t := Guest.store64 (q+48) 0 t
    let t := Guest.store64 (q+56) 0 t
    let t := Guest.store64 (q+120) (if h-now > 100 then now+100 else h) t
    Guest.store64 q 4 t
  else if op == 126 then
    -- Coalesced readiness only; no IPC payload, capability or data disclosure.
    if (p != 2 && p != 3 && p != 5 && p != 6) || Guest.load64 (proc p+24) t != p || !live h t then err else
    let target := h &&& 255
    let t := Guest.store64 (proc target+224) 1 t
    if Guest.load64 (proc target) t != 4 then t else
      let t := Guest.store64 (frame target+80) 0 t
      Guest.store64 (proc target) 1 t
  else if op == 118 then
    if p != 1 || (h != 0 && (!live h t || (h &&& 255) < 7)) then err else Guest.store64 (state+216) h t
  else if op == 119 then
    let broker := Guest.load64 (state+216) t
    if broker != 0 && live broker t then broker else err
  else if op == 125 then
    if identity p t != Guest.load64 (state+216) t || !live h t || !validFor p ptr n 32 t || n != 32 then err else
    let slot := Guest.load64 (proc (h &&& 255)+112) t
    if slot == 0 || slot > 16 then err else 32+copy (release (slot-1)+64) (physical p ptr) 32 t
  else if op == 124 then
    if identity p t != Guest.load64 (state+216) t || !validFor p ptr n 384 t || n != 384 then err else 384+inspectProcesses 0 (physical p ptr) t
  else if op == 120 then
    if (Guest.load64 (proc p+16) t &&& 4096) == 0 then err else Guest.AudioDevice.acquire (identity p t) t
  else if op == 121 then
    if (Guest.load64 (proc p+16) t &&& 4096) == 0 || !validFor p ptr n 1024 t then err else
    Guest.AudioDevice.write (identity p t) h (physical p ptr) n t
  else if op == 122 then
    if (Guest.load64 (proc p+16) t &&& 4096) == 0 then err else Guest.AudioDevice.close (identity p t) h t
  else if op == 123 then
    if (Guest.load64 (proc p+16) t &&& 4096) == 0 || !Guest.AudioDevice.valid (identity p t) h t then err else
    (Guest.load64 (Guest.AudioDevice.state+24) t <<< 1) ||| (if Guest.AudioDevice.ready t then 1 else 0)
  else if op == 110 then
    if p == 6 then Guest.load64 (state+16) t else err
  else if op == 109 then
    if p != 6 then err else
    let t := Guest.store64 (proc p+120) (Guest.load64 (state+16) t+1) t
    Guest.store64 (proc p) 4 t
  else if op == 98 then
    if p != 1 || h == 0 || h != Guest.load64 (state+136) t || h == Guest.load64 (state+152) t || Guest.load64 (state+16) t-Guest.load64 (state+144) t > 1000 then err else
      Guest.store64 (state+152) h t
  else if op == 99 then
    if p == 4 then Guest.load64 (state+136) t else err
  else if op == 97 then
    if h > 0 && h <= 6 && live (identity h t) t then identity h t else err
  else if op == 91 then
    if p != 4 || !valid ptr 384 384 then err else 384+inspectProcesses 0 (physical p ptr) t
  else if op == 112 then
    if p != 1 || (h != 0 && (!live h t || (h &&& 255) < 7)) then err else
      Guest.store64 (state+200) h t
  else if op == 113 then
    let registry := Guest.load64 (state+200) t
    if (p == 1 || (Guest.load64 (proc p+16) t &&& 1024) != 0) && registry != 0 && live registry t then registry else err
  else if op == 114 then
    if p != 1 || (h != 0 && (!live h t || (h &&& 255) < 7)) then err else
      let old := Guest.load64 (state+208) t
      let slot := old &&& 255
      let t := if old != h && old != 0 && live old t && Guest.load64 (proc slot) t == 2 && (Guest.load64 (proc slot+32) t &&& 255) == 5 then
        let t := Guest.store64 (proc slot+40) 0 t
        let t := Guest.store64 (frame slot+80) err t
        Guest.store64 (proc slot) 1 t
      else t
      Guest.store64 (state+208) h t
  else if op == 115 then if p == 1 then Guest.load64 (state+208) t else err
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
  if p == 7 then t else
    let descriptor := 0x80200000+p*32
    let t := clearPrivate p t
    let result := if Guest.load64 (descriptor+16) t != 2 || Guest.load64 (descriptor+24) t != codeLimit p p then err else
      start p (serviceSource p) (Guest.load64 descriptor t) (Guest.load64 (descriptor+8) t) 0x200000 p t
    if result == err then Guest.finish 1 else bootServices (p+1) result

def kernelMain (initial : UInt64) : UInt64 :=
  let t := zero state 16384 initial
  let t := zero 0x80100000 24576 t
  let t := zero 0x80b10000 512 t
  let t := zero 0x80c00000 24576 t
  let t := zero rx 2048 t
  let t := Guest.store8 0x10000002 7 t
  let t := Devices.init t
  let t := Guest.GraphicsDevice.init t
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
