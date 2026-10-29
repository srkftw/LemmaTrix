import Guest.Primitives
namespace Guest
-- ABI 1 handles are process-local, generation-tagged UInt64 values.
-- User buffers are confined to [0x410000,0x411000); messages are at most 256 bytes.
def buffer : UInt64 := 0x410000
def objectRead (handle capacity token : UInt64) : UInt64 := syscall 2 handle buffer capacity 0 token
def objectRevise (parent length token : UInt64) : UInt64 := syscall 3 parent buffer length 0 token
def objectShareRead (handle target token : UInt64) : UInt64 := syscall 4 handle 0 1 target token
def objectRevoke (handle token : UInt64) : UInt64 := syscall 5 handle 0 0 0 token
def consoleWrite (length token : UInt64) : UInt64 := syscall 1 0 buffer length 0 token
def yield (token : UInt64) : UInt64 := syscall 9 0 0 0 0 token
partial def upper (p n token : UInt64) : UInt64 :=
  if n == 0 then token else
    let c := load8 p token
    let c := if c >= 97 && c <= 122 then c-32 else c
    upper (p+1) (n-1) (store8 p c token)
end Guest
