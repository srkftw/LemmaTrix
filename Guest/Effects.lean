import Guest.Primitives
namespace Guest.Effects
-- Single-field wrappers are erased/unboxed by upstream Lean IR. Effects are inlined
-- StateM programs; escaping closures and heap results remain explicit compiler errors.
structure Handle where
  raw : UInt64
structure Buffer where
  address : UInt64
structure ByteCount where
  value : UInt64
structure Result where
  word : UInt64
abbrev Effect := StateM UInt64
@[never_extract, extern "lt_effect_value"] opaque effectValue : UInt64 → UInt64 → UInt64
@[inline] def Result.failed (r : Result) : Bool := r.word == 0xffffffffffffffff
@[inline] def read8 (p : Buffer) : Effect UInt64 := fun t =>
  let v := Guest.load8 p.address t
  (v,v)
@[inline] def read64 (p : Buffer) : Effect UInt64 := fun t =>
  let v := Guest.load64 p.address t
  (v,v)
@[inline] def write8 (p : Buffer) (v : UInt64) : Effect Unit := fun t =>
  ((),Guest.store8 p.address v t)
@[inline] def write64 (p : Buffer) (v : UInt64) : Effect Unit := fun t =>
  ((),Guest.store64 p.address v t)
@[inline] def call (operation : UInt64) (handle : Handle) (buffer : Buffer)
    (length : ByteCount) (value : UInt64 := 0) : Effect Result := fun t =>
  let v := Guest.syscall operation handle.raw buffer.address length.value value t
  (⟨v⟩,v)
@[inline] def run (program : Effect UInt64) (initial : UInt64) : UInt64 :=
  let (result,t) := program initial
  effectValue result t
@[inline] def runResult (program : Effect Result) (initial : UInt64) : Result :=
  let (result,t) := program initial
  ⟨effectValue result.word t⟩
end Guest.Effects
