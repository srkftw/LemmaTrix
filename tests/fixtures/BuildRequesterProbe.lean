import Guest.ProjectSDK
namespace Guest.BuildRequesterProbe
open Guest.LiveSDK
def fail (t : UInt64) : UInt64 := 64+store64 wire error (zero wire 8 t)
def target : UInt64 := 0x415000
def enqueue (root t : UInt64) : UInt64 :=
  let service := syscall 97 5 0 0 0 t
  let r := Guest.ProjectSDK.delegate root service 73 service
  if r != 160 || status r != 0 then fail r else
    let grant := result r
    let t := store64 target root (store64 (target+8) grant r)
    let t := header 1 grant 0 0 0 0 0 t
    let r := syscall 30 service wire 64 1024 t
    if r == error then
      let t := Guest.ProjectSDK.revoke root grant r
      fail t
    else r
def cancel (id t : UInt64) : UInt64 :=
  let service := syscall 97 5 0 0 0 t
  let r := syscall 30 service wire 64 1024 (header 5 id 0 0 0 0 0 service)
  if r == error then fail r else
    let t := copy wire 0x416000 r r
    let t := Guest.ProjectSDK.revoke (load64 target t) (load64 (target+8) t) t
    r+copy 0x416000 wire r t
def dispatch (t : UInt64) : UInt64 :=
  let op := load64 command t
  let h := load64 (command+8) t
  if op == 1 then enqueue h t else
  if op == 5 then cancel h t else
  if op == 4 || op == 2 then
    let service := syscall 97 5 0 0 0 t
    let r := syscall 30 service wire 64 1024 (header op h 0 0 0 0 0 service)
    if r == error then fail r else r
  else if op == 6 then
    let r := syscall 30 6 wire 64 1024 (header 2 0 0 0 0 0 0 t)
    if r == error then fail r else r
  else fail t
partial def serve (t : UInt64) : UInt64 :=
  let n := receive (self t) t
  if n != 96 then serve n else
    let token := load64 (incoming+8) n
    let r := if (load64 (incoming+16) n &&& 0x100000000) != 0 then dispatch n else fail n
    serve (reply token r r)
def main (initial : UInt64) : UInt64 := serve (zero target 2 initial)
end Guest.BuildRequesterProbe
