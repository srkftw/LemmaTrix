import Guest.LiveSDK
namespace Guest.Transport
open Guest.LiveSDK
-- LT-Transport-v2: an opaque four-channel socket adapter over LT-Stream-v1.
-- Header: magic32, opcode8, channel8, length16, epoch32, value32. Host events
-- never convey authority: Noise and newly issued scoped grants remain required.
def st : UInt64 := 0x640000
def input : UInt64 := 0x640100
def output : UInt64 := 0x640600
def channel (i : UInt64) : UInt64 := 0x641000+i*2048
def enabled (t : UInt64) : Bool := load64 st t == 1
def selected (t : UInt64) : UInt64 := load64 (st+8) t
def choose (i t : UInt64) : UInt64 := store64 (st+8) i t
def magic : UInt64 := 0x324d544c
def putHeader (op slot epoch value n t : UInt64) : UInt64 :=
  let t := store64 output (magic ||| (op <<< 32) ||| (slot <<< 40) ||| (n <<< 48)) t
  store64 (output+8) (epoch ||| (value <<< 32)) t
-- Exactly one output adapter frame is held immutable until the raw device
-- accepts it. This is bounded backpressure, never a partial remote receipt.
def flush (t : UInt64) : UInt64 :=
  let n := load64 (st+16) t
  let pos := load64 (st+24) t
  if n == 0 then t else
    let r := syscall 103 0 (output+pos) (n-pos) 0 t
    if r == error then store64 (st+40) 1 r else
    let t := if r == 0 then r else store64 (st+56) (load64 (st+56) r+1) r
    let next := pos+r
    if next == n then store64 (st+16) 0 (store64 (st+24) 0 t)
    else store64 (st+24) next t

def queue (op slot epoch value source n t : UInt64) : UInt64 :=
  if slot >= 4 || n > 1008 || load64 (st+16) t != 0 then error else
    let t := putHeader op slot epoch value n t
    let t := copy source (output+16) n t
    let t := store64 (st+24) 0 t
    store64 (st+16) (16+n) t

def connect (slot role endpoint n t : UInt64) : UInt64 :=
  if slot >= 4 || n == 0 || n > 96 || (role != 1 && role != 2) || load64 (st+16) t != 0 then error else
    let t := store64 st 1 t
    let p := channel slot
    let t := zero p 256 t
    let t := store64 (p+24) 1 t
    -- The value requests byte-credit flow control. Legacy guests request zero.
    queue role slot 0 1008 endpoint n t

def close (slot t : UInt64) : UInt64 :=
  let p := channel slot
  let t := store64 (p+8) 0 t
  let t := zero (p+32) 252 t
  -- A busy immutable adapter frame must finish before its CLOSE control.
  -- Pending close is retained privately and sent at the next output quantum.
  store64 (p+48) 1 t

partial def pendingClose (i t : UInt64) : UInt64 :=
  if i == 4 || load64 (st+16) t != 0 then t else
  let p := channel i
  if load64 (p+48) t == 0 then pendingClose (i+1) t else
  let r := queue 3 i (load64 p t) 0 input 0 t
  if r == error then t else store64 (p+48) 0 r

-- Return receive capacity only after the broker has consumed opaque bytes.
-- A stalled channel therefore cannot fill the shared adapter event stream.
partial def pendingCredit (i t : UInt64) : UInt64 :=
  if i == 4 || load64 (st+16) t != 0 then t else
  let slot := (load64 (st+48) t+i)%4
  let p := channel slot
  let count := load64 (p+56) t
  if count == 0 || load64 (p+8) t != 1 then pendingCredit (i+1) t else
  let r := queue 10 slot (load64 p t) count input 0 t
  if r == error then t else store64 (st+48) ((slot+1)%4) (store64 (p+56) 0 r)

def status (t : UInt64) : UInt64 :=
  let p := channel (selected t)
  if load64 (st+40) t != 0 then error else
  (load64 p t <<< 32) ||| (if load64 (p+8) t == 1 then 3 else 0)

def read (target n t : UInt64) : UInt64 :=
  let p := channel (selected t)
  if load64 (p+8) t != 1 then error else
  let count := load64 (p+32) t
  let pos := load64 (p+40) t
  let amount := if count-pos < n then count-pos else n
  let t := copy (p+64+pos) target amount t
  let t := if pos+amount == count then store64 (p+32) 0 (store64 (p+40) 0 t) else store64 (p+40) (pos+amount) t
  amount+store64 (p+56) (load64 (p+56) t+amount) t

def write (source n t : UInt64) : UInt64 :=
  let slot := selected t
  let p := channel slot
  if load64 (p+8) t != 1 then error else
  if load64 (st+16) t != 0 || n > load64 (p+1080) t then 0 else
  let r := queue 7 slot (load64 p t) 0 source n t
  if r == error then error else n+store64 (p+1080) (load64 (p+1080) r-n) r

def event (t : UInt64) : UInt64 :=
  let header := load64 input t
  let slot := (header >>> 40) &&& 255
  let op := (header >>> 32) &&& 255
  let n := header >>> 48
  let epoch := load64 (input+8) t &&& 0xffffffff
  if (header &&& 0xffffffff) != magic || slot >= 4 || n > 1008 then store64 (st+40) 1 t else
  let p := channel slot
  if op == 4 || op == 8 then
    if epoch == 0 || epoch <= load64 p t then t else
    let t := zero (p+32) 252 t
    let t := store64 p epoch t
    let t := store64 (p+1080) (load64 (input+8) t >>> 32) t
    store64 (p+8) 1 t
  else if op == 5 || op == 6 then
    if epoch < load64 p t then t else
    let t := zero (p+32) 252 t
    let t := store64 p epoch t
    let t := store64 (p+16) (load64 (input+8) t >>> 32) t
    store64 (p+8) 0 t
  else if op == 9 then store64 (p+24) 2 t else
  if op == 10 && epoch == load64 p t && load64 (p+8) t == 1 then
    let credit := load64 (input+8) t >>> 32
    let held := load64 (p+1080) t
    if credit > 65536 || held > 65536-credit then close slot t else store64 (p+1080) (held+credit) t
  else if op == 7 && epoch == load64 p t && load64 (p+8) t == 1 then
    let count := load64 (p+32) t
    let pos := load64 (p+40) t
    -- Compact at most1008 opaque bytes; validate arithmetic before copying.
    -- A nonconforming adapter closes only this channel instead of holding a
    -- shared incoming frame forever and starving unrelated peer controls.
    if pos > count || count > 1008 || n > 1008-(count-pos) then close slot t else
    let remaining := count-pos
    let t := copy (p+64+pos) (p+64) remaining t
    let t := copy (input+16) (p+64+remaining) n t
    store64 (p+40) 0 (store64 (p+32) (remaining+n) t)
  else t

-- Drain only already-ready opaque device bytes. Header/body/event handling no
-- longer requires three separate timer sleeps. Twelve small steps bound this
-- quantum to at most six control events or four data events; zero read stops.
partial def pumpInput (remaining t : UInt64) : UInt64 :=
  if remaining == 0 || load64 (st+40) t != 0 then t else
  let pos := load64 (st+32) t
  let length : UInt64 := if pos < 16 then 16 else (16 : UInt64)+(load64 input t >>> 48)
  if length > 1024 || pos > length then store64 (st+40) 1 t else
  if pos == length then
    let r := event t
    if r == error then t else pumpInput (remaining-1) (store64 (st+32) 0 r)
  else
    let r := syscall 102 0 (input+pos) (length-pos) 0 t
    if r == error then store64 (st+40) 1 r else
    if r == 0 then r else
    let t := store64 (st+56) (load64 (st+56) r+1) r
    pumpInput (remaining-1) (store64 (st+32) (pos+r) t)
def pump (t : UInt64) : UInt64 :=
  if !enabled t then t else
  let t := pendingCredit 0 (pendingClose 0 (flush t))
  pumpInput 12 (flush t)

end Guest.Transport
