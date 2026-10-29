import Guest.Primitives

/- Freestanding constructor heap and the bounded native application SDK.
   Runtime storage is private RW/NX: 256 fixed 128-byte slots, 0x418000–0x420000.
   Header words: reference count, constructor tag, reference-field count, payload size.
   Object pointers are aligned; immediate constructor values are (tag * 2 + 1).
   A constructor owns its reference fields. Optimized IR inc/dec/reset/reuse preserve
   ownership. No closure, tracing collector, upstream runtime, or implicit host heap. -/
namespace Guest.Structured.Runtime

def base : UInt64 := 0x418000
def limit : UInt64 := 0x420000

@[never_extract, extern "lt_effect_value"] opaque retain : UInt64 → UInt64 → UInt64

def panic (code : UInt64) : UInt64 := Guest.syscall 10 code 0 0 0 0

def valid (p : UInt64) : Bool := p >= base && p < limit && (p-base)%128 == 0

def checked (p t : UInt64) : UInt64 :=
  if valid p && Guest.load64 p t != 0 then p else panic 0x525401

partial def clear (p n t : UInt64) : UInt64 :=
  if n == 0 then t else clear (p+8) (n-1) (Guest.store64 p 0 t)

partial def find (p : UInt64) : UInt64 :=
  if p >= limit then panic 0x525402
  else if Guest.load64 p 0 == 0 then p else find (p+128)

@[noinline] def initSlot (p tag refs bytes : UInt64) : UInt64 :=
  if refs > 8 || bytes > 96 || refs*8 > bytes then panic 0x525403 else
  let t := clear (p+32) 12 0
  let t := Guest.store64 (p+8) tag t
  let t := Guest.store64 (p+16) refs t
  let t := Guest.store64 (p+24) bytes t
  let t := Guest.store64 p 1 t
  retain p t

@[noinline] def alloc (tag refs bytes : UInt64) : UInt64 :=
  initSlot (find base) tag refs bytes

@[noinline] def inc (p n : UInt64) : UInt64 :=
  if p%2 == 1 then 0 else
  let p := checked p 0
  let count := Guest.load64 p 0
  if n > 0xffffffff || count > 0xffffffff-n then panic 0x525404
  else Guest.store64 p (count+n) count

mutual
  partial def releaseFields (p i n depth t : UInt64) : UInt64 :=
    if i == n then t else
      let child := Guest.load64 (p+32+i*8) t
      let t := decDepth child 1 depth
      let t := Guest.store64 (p+32+i*8) 1 t
      releaseFields p (i+1) n depth t
  partial def decDepth (p n depth : UInt64) : UInt64 :=
    if p%2 == 1 then 0 else
    if depth == 0 then panic 0x525405 else
    let p := checked p 0
    let count := Guest.load64 p 0
    if n > count || n == 0 then panic 0x525406 else
    if count > n then Guest.store64 p (count-n) count else
      let refs := Guest.load64 (p+16) count
      let t := releaseFields p 0 refs (depth-1) count
      Guest.store64 p 0 t
end

@[noinline] def dec (p n : UInt64) : UInt64 := decDepth p n 16

@[noinline] def tag (p : UInt64) : UInt64 :=
  if p%2 == 1 then p/2 else Guest.load64 (checked p 0 + 8) 0

@[noinline] def shared (p : UInt64) : UInt64 :=
  if p%2 == 1 then 0 else if Guest.load64 (checked p 0) 0 > 1 then 1 else 0

@[noinline] def reset (p n : UInt64) : UInt64 :=
  if p%2 == 1 then 1 else
  let p := checked p 0
  if Guest.load64 p 0 > 1 then retain 1 (dec p 1) else
    let refs := Guest.load64 (p+16) 0
    if n > refs then panic 0x525407 else
      let t := releaseFields p 0 n 15 0
      retain p t

@[noinline] def reuse (p tag refs bytes : UInt64) : UInt64 :=
  if p%2 == 1 then alloc tag refs bytes else
    let p := checked p 0
    if refs > 8 || bytes > 96 || refs*8 > bytes || Guest.load64 p 0 != 1 then panic 0x525409 else
    let t := Guest.store64 (p+8) tag 0
    let t := Guest.store64 (p+16) refs t
    let t := Guest.store64 (p+24) bytes t
    retain p t

@[noinline] def delete (p : UInt64) : UInt64 :=
  let p := checked p 0
  if Guest.load64 p 0 != 1 then panic 0x525408 else Guest.store64 p 0 0

end Guest.Structured.Runtime

namespace Guest.Structured

/-- Operational handles contain an issuer epoch; stable graph identity is separate. -/
structure ObjectHandle where
  value : UInt64
  incarnation : UInt64
structure ProjectHandle where
  value : UInt64
  generation : UInt64
structure SurfaceHandle where
  value : UInt64
  incarnation : UInt64

/-- Coordinates are unsigned device coordinates; kind 0 denotes no event,
    1 EV_KEY (including buttons), 2 EV_REL, 3 EV_ABS, 65535 overflow. -/
structure InputEvent where
  kind : UInt64
  code : UInt64
  x : UInt64
  y : UInt64
  modifiers : UInt64
  sequence : UInt64

inductive Checked where
  | ok (value : UInt64)
  | error (code : UInt64)

/-- A checked borrowed byte slice. The owner must keep its private storage alive.
    The SDK accepts only mapped private app data, never MMIO/global display memory.
    profile 1: 0x410000–0x418000; profile 2 additionally: 0x600000–0x800000. -/
structure Bytes where
  address : UInt64
  length : UInt64
  capacity : UInt64

@[noinline] def bytes (address length capacity : UInt64) : Bytes :=
  ⟨address,length,capacity⟩

def Bytes.valid (b : Bytes) : Bool :=
  b.length <= b.capacity && b.capacity <= 0x200000 &&
    ((b.address >= 0x410000 && b.address <= 0x418000 && b.capacity <= 0x418000-b.address) ||
     (b.address >= 0x600000 && b.address <= 0x800000 && b.capacity <= 0x800000-b.address))

@[noinline] def Bytes.read (b : Bytes) (index t : UInt64) : Checked :=
  if b.valid && index < b.length then .ok (Guest.load8 (b.address+index) t)
  else .error 1

@[noinline] def Bytes.write (b : Bytes) (index value t : UInt64) : Checked :=
  if b.valid && index < b.capacity && value < 256 then
    let t := Guest.store8 (b.address+index) value t
    .ok (Guest.load8 (b.address+index) t)
  else .error 1

@[noinline] def Bytes.withLength (b : Bytes) (length : UInt64) : Bytes :=
  if b.valid && length <= b.capacity then {b with length} else b

/-- UTF-8 byte boundaries are checked before slicing/erasing; invalid sequences
    are not interpreted. The editor can retain unsupported glyphs byte-for-byte. -/
def continuation (b : UInt64) : Bool := b >= 128 && b < 192

def Bytes.boundary (b : Bytes) (index t : UInt64) : Bool :=
  b.valid && index <= b.length &&
    (index == 0 || index == b.length || !continuation (Guest.load8 (b.address+index) t))

@[noinline] def event (kind code x y modifiers sequence : UInt64) : InputEvent :=
  ⟨kind,code,x,y,modifiers,sequence⟩

@[noinline] def eventCode (ev : InputEvent) : Checked :=
  if ev.kind == 1 then .ok ev.code else .error ev.kind

end Guest.Structured
