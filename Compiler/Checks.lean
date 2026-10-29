import Guest.SHA256
import Guest.Effects
namespace CompilerChecks
@[noinline] def arithmetic (x y : UInt64) : UInt64 :=
  ((x*0xfffffffffffffff1 + 71) / y) ^^^ ((x+9) % y)
@[noinline] def narrow (x : UInt64) : UInt64 :=
  let a := x.toUInt8
  let b := (a+250).toUInt64
  let c := (x.toUInt32 * 0xfffffffb).toUInt64
  b ^^^ c
partial def sum (n acc : UInt64) : UInt64 :=
  if n == 0 then acc else sum (n-1) (acc+n)
@[noinline] def branch (x : UInt64) : UInt64 :=
  let y := if x < 20 && x != 0 then x+31 else x-9
  if y <= 48 || y == 90 then y*7 else y*11
-- Includes variable shifts modulo width, unsigned division/modulo by zero,
-- carry/wraparound, scalar conversions, branch joins, and 100000 self-tail calls.
def checkScalar (x : UInt64) : UInt64 :=
  sum 100000 x ^^^ arithmetic x 0 ^^^ arithmetic (x+5) 7 ^^^
  narrow (x+0xffffffff) ^^^ branch x ^^^ ((x <<< (x+48)) >>> 5)
def checkEffects (base : Guest.Effects.Buffer) (initial : UInt64) : UInt64 :=
  Guest.Effects.run (do
    Guest.Effects.write64 base 17
    let value ← Guest.Effects.read64 base
    Guest.Effects.write64 ⟨base.address+8⟩ (value+5)
    Guest.Effects.read64 ⟨base.address+8⟩) initial
end CompilerChecks
