import Guest.SDK
namespace Guest
partial def busy (n t : UInt64) : UInt64 :=
  if n == 0 then t else busy (n-1) (t+1)
partial def awaitRead (t : UInt64) : UInt64 :=
  let n := objectRead 257 256 t
  if n <= 256 then n else awaitRead (yield n)
partial def awaitRevoked (t : UInt64) : UInt64 :=
  let n := objectRead 257 256 t
  if n == 0xffffffffffffffff then n else awaitRevoked (yield n)
def appMain (initial : UInt64) : UInt64 :=
  let denied := objectRead 65535 256 initial
  let len := awaitRead denied
  let t := if len <= 256 then consoleWrite len len else len
  let t := syscall 12 257 0 0 0 t
  let t := yield t
  let t := awaitRevoked t
  let t := syscall 3 257 buffer 1 0 t
  let t := busy 200000 t
  -- A real user-mode load from the supervisor's kernel mapping must fault.
  load64 0x80000000 t
end Guest
