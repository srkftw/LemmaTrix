import Lean

/- Host-only RV64IM backend. The guest contains no upstream Lean runtime. -/
open Lean
namespace LemmaTrix.Compiler
open IR

set_option maxRecDepth 8192
set_option maxHeartbeats 0

def symbol (n : Name) : String :=
  "lt_" ++ String.ofList (n.toString.toList.map fun c => if c.isAlphanum || c == '_' then c else '_')

def scalar : IRType → Bool
  | .uint8 | .uint16 | .uint32 | .uint64 | .usize => true
  | _ => false

def builtin (n : Name) : Bool :=
  let p := n.getPrefix.toString
  let s := n.getString!
  ((["UInt8", "UInt16", "UInt32", "UInt64", "USize"].contains p) &&
    ["add", "sub", "mul", "div", "mod", "land", "lor", "xor", "shiftLeft", "shiftRight",
      "decEq", "decLt", "decLe", "complement", "neg", "toUInt8", "toUInt16", "toUInt32", "toUInt64", "toUSize"].contains s) ||
  (["Bool.toUInt8", "Bool.toUInt16", "Bool.toUInt32", "Bool.toUInt64", "Bool.toUSize", "Bool.not"].contains n.toString)

partial def refs (b : FnBody) : Array Name :=
  match b with
  | .vdecl _ _ (.fap f _) b => (refs b).push f
  | .vdecl _ _ _ b => refs b
  | .jdecl _ _ v b => refs v ++ refs b
  | .case _ _ _ alts => alts.foldl (fun out a => out ++ refs a.body) #[]
  | .set _ _ _ b | .uset _ _ _ b | .sset _ _ _ _ _ b | .setTag _ _ b |
    .inc _ _ _ _ b | .dec _ _ _ _ b | .del _ b => refs b
  | _ => #[]

partial def maxVar (b : FnBody) : Nat :=
  match b with
  | .vdecl x _ _ b => max x.idx (maxVar b)
  | .jdecl _ xs v b => max (xs.foldl (fun n p => max n p.x.idx) 0) (max (maxVar v) (maxVar b))
  | .case _ x _ alts => alts.foldl (fun n a => max n (maxVar a.body)) x.idx
  | .set _ _ _ b | .uset _ _ _ b | .sset _ _ _ _ _ b | .setTag _ _ b |
    .inc _ _ _ _ b | .dec _ _ _ _ b | .del _ b => maxVar b
  | .ret (.var x) => x.idx
  | _ => 0

structure EmitState where
  lines : Array String := #[]
  next : Nat := 0
  scope : String := ""
abbrev EmitM := StateT EmitState (Except String)

def emit (s : String) : EmitM Unit := modify fun st => {st with lines := st.lines.push s}
def fail (s : String) : EmitM α := throw s

def fresh (stem : String) : EmitM String := do
  let st ← get
  set {st with next := st.next + 1}
  return s!".L{st.scope}_{stem}_{st.next}"

def loadOffset (reg : String) (off : Nat) : EmitM Unit := do
  if off < 2048 then emit s!"  ld {reg}, {off}(sp)"
  else
    emit s!"  li t6, {off}"
    emit "  add t6, sp, t6"
    emit s!"  ld {reg}, 0(t6)"

def storeOffset (reg : String) (off : Nat) : EmitM Unit := do
  if off < 2048 then emit s!"  sd {reg}, {off}(sp)"
  else
    emit s!"  li t6, {off}"
    emit "  add t6, sp, t6"
    emit s!"  sd {reg}, 0(t6)"

def load (reg : String) (x : VarId) : EmitM Unit := loadOffset reg (x.idx * 8)
def store (reg : String) (x : VarId) : EmitM Unit := storeOffset reg (x.idx * 8)

def arg (reg : String) : Arg → EmitM Unit
  | .var x => load reg x
  | .erased => fail "erased runtime argument: polymorphic/heap values are outside the scalar ABI"

def narrow (reg : String) : IRType → EmitM Unit
  | .uint8 => emit s!"  andi {reg}, {reg}, 255"
  | .uint16 => do emit s!"  slli {reg}, {reg}, 48"; emit s!"  srli {reg}, {reg}, 48"
  | .uint32 => do emit s!"  slli {reg}, {reg}, 32"; emit s!"  srli {reg}, {reg}, 32"
  | .uint64 | .usize => pure ()
  | t => fail s!"unsupported runtime type {repr t}; use fixed-width scalars and bounded explicit buffers"

def emitBuiltin (n : Name) (ys : Array Arg) : EmitM Unit := do
  let op := n.getString!
  if ys.isEmpty || ys.size > 2 then fail s!"builtin {n}: expected one or two scalar arguments"
  arg "t0" ys[0]!
  if ys.size > 1 then arg "t1" ys[1]!
  match op with
  | "add" => emit "  add t0, t0, t1"
  | "sub" => emit "  sub t0, t0, t1"
  | "mul" => emit "  mul t0, t0, t1"
  | "div" => do
    let z ← fresh "divzero"
    let e ← fresh "divend"
    emit s!"  beqz t1, {z}"
    emit "  divu t0, t0, t1"
    emit s!"  j {e}"
    emit s!"{z}:"
    emit "  li t0, 0"
    emit s!"{e}:"
  | "mod" => emit "  remu t0, t0, t1"
  | "land" => emit "  and t0, t0, t1"
  | "lor" => emit "  or t0, t0, t1"
  | "xor" => emit "  xor t0, t0, t1"
  | "shiftLeft" | "shiftRight" => do
    let width := match n.getPrefix.toString with
      | "UInt8" => 8 | "UInt16" => 16 | "UInt32" => 32 | _ => 64
    emit s!"  andi t1, t1, {width-1}"
    emit (if op == "shiftLeft" then "  sll t0, t0, t1" else "  srl t0, t0, t1")
  | "decEq" => do emit "  xor t0, t0, t1"; emit "  seqz t0, t0"
  | "decLt" => emit "  sltu t0, t0, t1"
  | "decLe" => do emit "  sltu t0, t1, t0"; emit "  xori t0, t0, 1"
  | "complement" => emit "  not t0, t0"
  | "neg" => emit "  neg t0, t0"
  | "not" => emit "  xori t0, t0, 1"
  | "toUInt8" | "toUInt16" | "toUInt32" | "toUInt64" | "toUSize" => pure ()
  | _ => fail s!"unsupported builtin {n}"

structure FnContext where
  fn : Name
  params : Array Param
  frame : Nat
  scratch : Nat
  joins : Array (JoinPointId × Array Param) := #[]

partial def getJoins (b : FnBody) : Array (JoinPointId × Array Param) :=
  match b with
  | .jdecl j xs v b => #[(j, xs)] ++ getJoins v ++ getJoins b
  | .vdecl _ _ _ b => getJoins b
  | .case _ _ _ as => as.foldl (fun a c => a ++ getJoins c.body) #[]
  | _ => #[]

def joinLabel (c : FnContext) (j : JoinPointId) : String := s!".L{symbol c.fn}_jp_{j.idx}"
def bodyLabel (c : FnContext) : String := s!".L{symbol c.fn}_body"

def epilogue (c : FnContext) : EmitM Unit := do
  loadOffset "ra" (c.frame - 8)
  emit s!"  li t6, {c.frame}"
  emit "  add sp, sp, t6"
  emit "  ret"

def externSymbol (env : Environment) (f : Name) : Except String String := do
  let some (.standard _ s) := (getExternAttrData? env f).bind (getExternEntryFor · `all)
    | throw s!"extern {f} has no explicit freestanding symbol"
  let permitted := ["lt_load8", "lt_load32", "lt_load64", "lt_store8", "lt_store32", "lt_store64", "lt_idle_pc", "lt_device_fence", "lt_effect_value", "lt_syscall", "lt_finish", "lt_enter_user", "lt_putc", "lt_read_csr", "lt_write_csr", "lt_barrier", "lt_kernel_addr", "lt_app_addr"]
  if permitted.contains s then
    if !hasNeverExtractAttribute env f then
      throw s!"extern {f} must be marked @[never_extract] to preserve primitive effects through upstream optimization"
    return s
  throw s!"extern {f} requests unsupported primitive '{s}'; add an explicit ABI implementation and allowlist entry"

def callSymbol (env : Environment) (f : Name) : Except String String := do
  match IR.findEnvDecl env f with
  | some (.extern ..) => externSymbol env f
  | some (.fdecl ..) => return symbol f
  | none => throw s!"missing Lean IR for {f}; compile its module .olean first and keep declarations within supported ABI"

def emitExpr (env : Environment) (e : IR.Expr) : EmitM Unit := do
  match e with
  | .lit (.num n) =>
    if n >= 2^64 then fail "integer literal outside UInt64 range"
    emit s!"  li t0, {n}"
  | .fap f ys =>
    if builtin f then emitBuiltin f ys
    else
      if ys.size > 8 then fail s!"{f}: {ys.size} arguments exceeds eight-register scalar ABI"
      for i in [:ys.size] do arg s!"a{i}" ys[i]!
      let s ← match callSymbol env f with | .ok s => pure s | .error e => fail e
      emit s!"  call {s}"
      emit "  mv t0, a0"
  | .ctor info ys =>
    if info.isRef || !ys.isEmpty then fail s!"heap constructor {info.name} is unsupported; use explicit bounded buffer records"
    emit s!"  li t0, {info.cidx}"
  | _ => fail s!"unsupported Lean IR expression: {toString (format e)}; closures, heap objects, strings and allocation require a freestanding runtime"

partial def emitBody (env : Environment) (c : FnContext) (b : FnBody) : EmitM Unit := do
  match b with
  | .vdecl x ty (.fap f ys) (.ret (.var y)) =>
    if f == c.fn && x == y then
      if ys.size != c.params.size then fail s!"{f}: tail-call arity mismatch"
      for i in [:ys.size] do arg s!"a{i}" ys[i]!
      for i in [:c.params.size] do store s!"a{i}" c.params[i]!.x
      emit s!"  j {bodyLabel c}"
    else
      emitExpr env (.fap f ys)
      narrow "t0" ty
      store "t0" x
      arg "a0" (.var y)
      epilogue c
  | .vdecl x ty e b =>
    emitExpr env e
    narrow "t0" ty
    store "t0" x
    emitBody env c b
  | .jdecl j _ v b =>
    emitBody env c b
    emit s!"{joinLabel c j}:"
    emitBody env c v
  | .case _ x ty alts =>
    if !(scalar ty) then fail s!"non-scalar case on {repr ty} is unsupported"
    load "t0" x
    let mut labels := #[]
    let mut fallback := none
    for a in alts do
      let l ← fresh (symbol c.fn ++ "_case")
      labels := labels.push (a, l)
      match a with
      | .ctor info _ =>
        if info.isRef then fail s!"non-scalar case constructor {info.name} is unsupported"
        emit s!"  li t1, {info.cidx}"
        emit s!"  beq t0, t1, {l}"
      | .default _ => fallback := some l
    match fallback with
    | some l => emit s!"  j {l}"
    | none => emit "  unimp"
    for (a, l) in labels do
      emit s!"{l}:"
      emitBody env c a.body
  | .ret a => arg "a0" a; epilogue c
  | .jmp j ys =>
    let some (_, ps) := c.joins.find? (fun p => p.1 == j) | fail s!"unknown join point {j.idx}"
    if ps.size != ys.size then fail "join-point parameter mismatch"
    for i in [:ys.size] do
      arg "t0" ys[i]!
      storeOffset "t0" (c.scratch + i*8)
    for i in [:ps.size] do
      if !(scalar ps[i]!.ty) then fail "non-scalar join point is unsupported"
      loadOffset "t0" (c.scratch + i*8)
      store "t0" ps[i]!.x
    emit s!"  j {joinLabel c j}"
  | .unreachable => emit "  unimp"
  | _ => fail s!"unsupported heap/reference-count instruction in {c.fn}"

def emitDecl (env : Environment) (d : Decl) : Except String (Array String) := do
  let .fdecl fn ps ty b info := d | throw "internal: expected definition"
  if info.sorryDep?.isSome then throw s!"{fn} depends on a sorry axiom"
  if ps.size > 8 then throw s!"{fn}: more than eight parameters are unsupported"
  if !(scalar ty) then throw s!"{fn}: return type {repr ty} is outside the fixed-width scalar ABI"
  for p in ps do
    if !(scalar p.ty) then throw s!"{fn}: parameter {p.x.idx} has unsupported type {repr p.ty}"
  let top := max (maxVar b) (ps.foldl (fun n p => max n p.x.idx) 0)
  let scratch := (top+1)*8
  let joins := getJoins b
  let joinSlots := joins.foldl (fun count jp => max count jp.2.size) 0
  let frame := ((scratch + joinSlots*8 + 8 + 15)/16)*16
  let ctx := {fn, params := ps, frame, scratch, joins}
  let action : EmitM Unit := do
    emit s!".section .text.{symbol fn},\"ax\",@progbits"
    emit ".balign 4"
    emit s!".global {symbol fn}"
    emit s!".type {symbol fn}, @function"
    emit s!"{symbol fn}:"
    emit s!"  li t6, {frame}"
    emit "  sub sp, sp, t6"
    storeOffset "ra" (frame-8)
    for i in [:ps.size] do store s!"a{i}" ps[i]!.x
    emit s!"{bodyLabel ctx}:"
    emitBody env ctx b
    emit s!".size {symbol fn}, .-{symbol fn}"
  match action.run {scope := symbol fn} with
  | .ok (_, st) => return st.lines
  | .error e => throw s!"{fn}: {e}"

partial def closure (env : Environment) (pending : List Name) (seen : Array Name := #[]) (out : Array Decl := #[]) : Except String (Array Decl) := do
  match pending with
  | [] => return out
  | f :: rest =>
    if seen.contains f || builtin f then return ← closure env rest seen out
    let some d := IR.findEnvDecl env f | throw s!"missing compiled Lean IR for {f}"
    match d with
    | .extern .. =>
      let _ ← externSymbol env f
      closure env rest (seen.push f) out
    | .fdecl _ _ _ b _ => closure env ((refs b).toList ++ rest) (seen.push f) (out.push d)

partial def effectful (env : Environment) (f : Name) (seen : Array Name := #[]) : Bool :=
  if seen.contains f || builtin f then false
  else match IR.findEnvDecl env f with
    | some (.extern ..) => true
    | some (.fdecl _ _ _ b _) => (refs b).any (fun g => effectful env g (seen.push f))
    | none => false

unsafe def run (args : List String) : IO Unit := do
  let moduleName :: output :: roots := args | throw (IO.userError "usage: lean --run Compiler/Main.lean MODULE OUTPUT.S ROOT [ROOT ...]")
  if roots.isEmpty then throw (IO.userError "at least one entry declaration is required")
  initSearchPath (← findSysroot)
  enableInitializersExecution
  let env ← importModules #[{module := moduleName.toName}] {} (loadExts := true)
  let declarations ← match closure env (roots.map String.toName) with
    | .ok ds => pure ds
    | .error e => throw (IO.userError s!"freestanding compiler: {e}")
  let mut emitted : Array String := #[]
  for d in declarations do
    if emitted.contains (symbol d.name) then
      throw (IO.userError s!"freestanding compiler: symbol collision at {d.name}; rename the conflicting declaration")
    emitted := emitted.push (symbol d.name)
    if d.name.getString!.startsWith "_closed" && d.params.isEmpty && effectful env d.name then
      throw (IO.userError s!"freestanding compiler: effectful closed constant {d.name}; rebuild all guest modules with -Dcompiler.extract_closed=false and mark primitives @[never_extract]")
  let mut lines := #["# Generated from optimized upstream Lean IR by the Lean-authored LemmaTrix backend.", ".option norvc", ".option norelax", ".attribute arch, \"rv64im\""]
  for d in declarations do
    match emitDecl env d with
    | .ok ls => lines := lines ++ ls
    | .error e => throw (IO.userError s!"freestanding compiler: {e}")
  IO.FS.writeFile output (String.intercalate "\n" lines.toList ++ "\n")
  IO.println s!"Lean IR → RV64IM: {declarations.size} definitions → {output}"

end LemmaTrix.Compiler
unsafe def main (args : List String) : IO Unit := LemmaTrix.Compiler.run args
