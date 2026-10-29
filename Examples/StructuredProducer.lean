import Guest.Structured
namespace Examples.StructuredProducer
open Guest.Structured

structure Cursor where
  line : UInt64
  column : UInt64
  revision : UInt64

structure Packed where
  kind : UInt8
  flags : UInt16
  count : UInt32
  stamp : UInt64

@[noinline] def packed (n : UInt64) : Packed := ⟨7,513,0xfedcba98,n⟩
@[noinline] def packedValue (p : Packed) : UInt64 :=
  p.kind.toUInt64+p.flags.toUInt64+p.count.toUInt64+p.stamp
@[noinline] def optional (n : UInt64) : Option UInt64 := if n == 0 then none else some n
@[noinline] def optionValue (v : Option UInt64) : UInt64 := match v with | none => 17 | some n => n

inductive Selection where
  | empty
  | active (anchor : Cursor) (caret : Cursor)
  | rejected (reason : UInt64)

@[noinline] def cursor (line column revision : UInt64) : Cursor := ⟨line,column,revision⟩
@[noinline] def advance (c : Cursor) : Cursor := {c with column := c.column+1}
@[noinline] def select (c : Cursor) : Selection := .active c (advance c)
@[noinline] def selectedWidth (s : Selection) : UInt64 :=
  match s with
  | .empty => 0
  | .rejected reason => reason
  | .active a b => b.column-a.column+a.line+b.revision
end Examples.StructuredProducer
