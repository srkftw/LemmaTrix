import Guest.LiveSDK
namespace Guest.ServerSDK
open Guest.LiveSDK
def call (length t : UInt64) : UInt64 := syscall 30 3 wire length 1024 t
def begin (grant bytes digest t : UInt64) : UInt64 :=
  call 96 (copy digest (wire+64) 32 (header 232 grant bytes 0 0 0 0 t))
def append (grant offset source bytes t : UInt64) : UInt64 :=
  if bytes == 0 || bytes > 512 then error else
    call (64+bytes) (copy source (wire+64) bytes (header 233 grant offset 0 0 0 0 t))
def commit (grant t : UInt64) : UInt64 := call 64 (header 234 grant 0 0 0 0 0 t)
def cancel (grant t : UInt64) : UInt64 := call 64 (header 235 grant 0 0 0 0 0 t)
def describe (grant t : UInt64) : UInt64 := call 64 (header 236 grant 0 0 0 0 0 t)
def read (grant offset bytes t : UInt64) : UInt64 := call 64 (header 237 grant offset bytes 0 0 0 t)
def progress (grant t : UInt64) : UInt64 := call 64 (header 238 grant 0 0 0 0 0 t)
end Guest.ServerSDK
