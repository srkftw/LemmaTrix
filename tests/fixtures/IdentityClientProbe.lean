import Guest.IdentitySDK
import Guest.IdentityPolicy
namespace Guest.IdentityClientProbe
open Guest.LiveSDK
def st : UInt64 := 0x660000
def staged : UInt64 := 0x661000
def completed : UInt64 := 0x662000
def runPending (t : UInt64) : UInt64 :=
  if load64 st t != 1 then t else
  let length := load64 (st+8) t
  let t := copy staged wire length t
  let r := Guest.IdentitySDK.invoke (load64 staged t) length t
  let r := if r == error then 64+header 90 0 0 0 0 0 0 r else r
  let t := copy wire completed r r
  store64 st 2 (store64 (st+16) r t)
def dispatch (length t : UInt64) : UInt64 :=
  let op := load64 command t
  if op == 500 && length >= 128 && length <= 384 then
    if load64 st t != 0 then 64+header 4 0 0 0 0 0 0 t else
    let job := load64 (st+24) t+1
    let t := copy (command+64) staged (length-64) t
    let t := store64 (st+8) (length-64) t
    let t := store64 (st+24) job t
    64+header 0 job 0 0 0 0 0 (store64 st 1 t)
  else if op == 504 then
    if load64 (command+8) t != load64 (st+24) t || load64 st t == 0 then
      64+header 3 0 0 0 0 0 0 t else
    if load64 st t != 2 then 64+header 6 0 0 0 0 0 0 t else
    let n := load64 (st+16) t
    n+copy completed wire n (store64 st 0 t)
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
  serve (runPending (reply token r r))
def main (t : UInt64) : UInt64 := serve (zero st 512 t)
end Guest.IdentityClientProbe
