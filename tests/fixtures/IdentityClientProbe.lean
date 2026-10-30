import Guest.IdentitySDK
import Guest.IdentityPolicy
namespace Guest.IdentityClientProbe
open Guest.LiveSDK
def dispatch (length t : UInt64) : UInt64 :=
  let op := load64 command t
  if op == 500 && length >= 128 && length <= 384 then
    let requested := load64 (command+64) t
    let t := copy (command+64) wire (length-64) t
    let r := Guest.IdentitySDK.invoke requested (length-64) t
    if r == error then 64+header 90 0 0 0 0 0 0 r else r
  else if op == 501 || op == 502 then
    let r := if op == 501 then syscall 130 0 0x660000 32 0 t else syscall 104 0 0x660000 32 0 t
    64+header 0 r 0 0 0 0 0 r
  else if op == 503 && length >= 136 then
    let target := load64 (command+64) t
    let t := copy (command+72) wire (length-72) t
    let r := syscall 30 target wire (length-72) 1024 t
    if r == error then 64+header 90 0 0 0 0 0 0 r else r
  else 64+header 2 0 0 0 0 0 0 t
partial def serve (t : UInt64) : UInt64 :=
  let n := receive (self t) t
  if n == error then serve n else
  let token := load64 (incoming+8) n
  let r := if n >= 96 && load64 (incoming+24) n == 2 &&
    Guest.IdentityPolicy.administrative (load64 (incoming+16) n) then dispatch (n-32) n
    else 64+header 1 0 0 0 0 0 0 n
  serve (reply token r r)
def main (t : UInt64) : UInt64 := serve t
end Guest.IdentityClientProbe
