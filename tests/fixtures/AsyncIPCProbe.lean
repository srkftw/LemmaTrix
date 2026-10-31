import Guest.LiveSDK
import Guest.WaitSDK
namespace tests.fixtures.AsyncIPCProbe
open Guest Guest.LiveSDK
def st : UInt64 := 0x650000
partial def ownerLoop (t : UInt64) : UInt64 :=
  let n := receive (self t) t
  let token := load64 (incoming+8) n
  let deadline := Guest.WaitSDK.now n+100
  let t := Guest.WaitSDK.deadline deadline deadline
  let valid := syscall 131 token 0 0 0 t
  let t := header 0 valid 0 0 0 0 0 t
  ownerLoop (reply token 64 t)
def owner (t : UInt64) : UInt64 := ownerLoop t
partial def clientLoop (t : UInt64) : UInt64 :=
  let n := receive (self t) t
  let token := load64 (incoming+8) n
  let op := load64 command n
  let r := if op == 900 then
    let target := syscall 128 2 420 0 0 n
    let r := syscall 133 target wire 64 1024 (header 420 0 0 0 0 0 0 target)
    let t := store64 st r r
    64+header 0 r 0 0 0 0 0 t
  else if op == 901 then
    let r := syscall 134 (load64 st n) wire 1024 0 n
    if r == 0 || r == error then 64+header 0 r 0 0 0 0 0 r else
    64+header 0 r (load64 (wire+8) r) 0 0 0 0 r
  else if op == 902 then
    let r := syscall 135 (load64 st n) 0 0 0 n
    64+header 0 r 0 0 0 0 0 r
  else 64+header 7 0 0 0 0 0 0 n
  clientLoop (reply token r r)
def client (t : UInt64) : UInt64 := clientLoop t
end tests.fixtures.AsyncIPCProbe
