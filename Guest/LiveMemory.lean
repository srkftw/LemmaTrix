import Guest.Primitives
namespace Guest.LiveMemory
def err : UInt64 := 0xffffffffffffffff
def buf : UInt64 := 0x410000
partial def zero (p n t : UInt64) : UInt64 :=
  if n == 0 then t else zero (p+8) (n-1) (Guest.store64 p 0 t)
partial def copy (src dst n t : UInt64) : UInt64 :=
  if n == 0 then t else
  if n >= 8 && src%8 == 0 && dst%8 == 0 then copy (src+8) (dst+8) (n-8) (Guest.store64 dst (Guest.load64 src t) t)
  else copy (src+1) (dst+1) (n-1) (Guest.store8 dst (Guest.load8 src t) t)
partial def equal (a b n t : UInt64) : Bool :=
  if n == 0 then true else Guest.load8 a t == Guest.load8 b t && equal (a+1) (b+1) (n-1) t
end Guest.LiveMemory
