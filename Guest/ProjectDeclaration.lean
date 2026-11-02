import Guest.ReleaseClaims
namespace Guest.ProjectDeclaration
open Guest.LiveSDK
-- Project files are editable, unordered, whitespace-bearing JSON. Normalize
-- whitespace only; never rewrite text inside strings or accept escaped keys.
partial def normalize (p end_ out count quoted escaped t : UInt64) : UInt64 :=
  if p == end_ then if quoted == 0 then Guest.Effects.effectValue count t else error else
  let c := load8 p t
  if quoted == 0 && (c == 32 || c == 9 || c == 10 || c == 13) then normalize (p+1) end_ out count 0 0 t else
  let nextQuoted := if escaped != 0 then quoted else if c == 34 then 1-quoted else quoted
  let nextEscape := if quoted == 1 && escaped == 0 && c == 92 then 1 else 0
  normalize (p+1) end_ out (count+1) nextQuoted nextEscape (store8 (out+count) c t)
mutual
  partial def valueEnd (p end_ depth t : UInt64) : UInt64 :=
    if depth == 0 || p >= end_ then 0 else
    if load8 p t == 123 then objectRest (p+1) end_ (depth-1) t else
    if load8 p t == 91 then arrayRest (p+1) end_ (depth-1) t else Guest.ReleaseClaims.valueEnd p end_ depth t
  partial def objectRest (p end_ depth t : UInt64) : UInt64 :=
    if p >= end_ then 0 else if load8 p t == 125 then p+1 else
    let k := Guest.ReleaseClaims.stringEnd p end_ t
    if k == 0 || k >= end_ || !Guest.ReleaseClaims.asciiKey (p+1) (k-p-2) t || load8 k t != 58 then 0 else
    let next := valueEnd (k+1) end_ depth t
    if next == 0 || next >= end_ then 0 else if load8 next t == 125 then next+1 else
    if load8 next t != 44 || next+1 >= end_ || load8 (next+1) t != 34 then 0 else objectRest (next+1) end_ depth t
  partial def arrayRest (p end_ depth t : UInt64) : UInt64 :=
    if p >= end_ then 0 else if load8 p t == 93 then p+1 else
    let next := valueEnd p end_ depth t
    if next == 0 || next >= end_ then 0 else if load8 next t == 93 then next+1 else
    if load8 next t != 44 || next+1 >= end_ || load8 (next+1) t == 93 then 0 else arrayRest (next+1) end_ depth t
end
partial def findField (p end_ tag found t : UInt64) : UInt64 :=
  if p >= end_ then 0 else if load8 p t == 125 then found else
  let k := Guest.ReleaseClaims.stringEnd p end_ t
  if k == 0 || k >= end_ || load8 k t != 58 then 0 else
  let matching := Guest.ReleaseClaims.keyTag (p+1) (k-p-2) t == tag
  if matching && found != 0 then 0 else
  let next := valueEnd (k+1) end_ 32 t
  let selected := if matching then k+1 else found
  if next == 0 || next >= end_ then 0 else if load8 next t == 125 then selected else
  if load8 next t != 44 then 0 else findField (next+1) end_ tag selected t
def field (p end_ tag t : UInt64) : UInt64 :=
  if p >= end_ || load8 p t != 123 then 0 else findField (p+1) end_ tag 0 t
def consistent (h manifest bytes project projectBytes t : UInt64) : Bool :=
  let pe := project+projectBytes
  let me := manifest+bytes
  if projectBytes == 0 || valueEnd project pe 32 t != pe || load8 project t != 123 then false else
  let native := load64 (h+384) t == 1
  let provenance := Guest.ReleaseClaims.field manifest me 28 t
  let recipe := Guest.ReleaseClaims.field manifest me 18 t
  Guest.ReleaseClaims.numberEquals (field project pe 14 t) pe 1 t &&
    Guest.ReleaseClaims.valueEquals (field project pe 22 t) pe (Guest.ReleaseClaims.field manifest me 4 t) me t &&
    Guest.ReleaseClaims.valueEquals (field project pe 3 t) pe (Guest.ReleaseClaims.field manifest me 3 t) me t &&
    Guest.ReleaseClaims.valueEquals (field project pe 24 t) pe (Guest.ReleaseClaims.field manifest me 24 t) me t &&
    Guest.ReleaseClaims.valueEquals (field project pe 35 t) pe (Guest.ReleaseClaims.field provenance me 34 t) me t &&
    (if native then Guest.ReleaseClaims.numberEquals (field project pe 1 t) pe (load64 (h+64) t) t &&
      Guest.ReleaseClaims.numberEquals (field project pe 27 t) pe (load64 (h+400) t) t &&
      Guest.ReleaseClaims.valueEquals (field project pe 15 t) pe (Guest.ReleaseClaims.field manifest me 15 t) me t &&
      Guest.ReleaseClaims.valueEquals (field project pe 20 t) pe (Guest.ReleaseClaims.field recipe me 20 t) me t &&
      Guest.ReleaseClaims.valueEquals (field project pe 19 t) pe (Guest.ReleaseClaims.field recipe me 19 t) me t
     else (field project pe 1 t == 0 || Guest.ReleaseClaims.numberEquals (field project pe 1 t) pe 0 t))
end Guest.ProjectDeclaration
