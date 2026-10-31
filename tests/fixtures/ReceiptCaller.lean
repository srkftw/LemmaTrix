import Guest.IdentitySDK
import Guest.WaitSDK
namespace Tests.ReceiptCaller
open Guest Guest.LiveSDK
def state : UInt64 := 0x650000
def dispatch (n t : UInt64) : UInt64 :=
  let op := load64 command t
  if op == 440 && n == 256 && load64 state t == 0 then
    let target := Guest.IdentitySDK.endpoint 409 t
    let t := copy command wire 256 target
    let t := store64 wire 409 t
    let token := syscall 133 target wire 256 1024 t
    let t := store64 state (if token == error then 0 else token) token
    64+header (if token == error then 1 else 0) token 0 0 0 0 0 t
  else if op == 441 && n == 64 then
    let r := syscall 134 (load64 state t) wire 1024 0 t
    if r == 0 then 64+header 6 0 0 0 0 0 0 r else
    if r == error then 64+header 3 0 0 0 0 0 0 (store64 state 0 r) else
    r+store64 state 0 r
  else 64+header 2 0 0 0 0 0 0 t
partial def loop (t : UInt64) : UInt64 :=
  let n := syscall 36 (self t) incoming 1024 0 t
  let t := if n >= 96 then
    let token := load64 (incoming+8) n
    let size := dispatch (n-32) n
    reply token size size else n
  loop (Guest.WaitSDK.deadline (Guest.WaitSDK.now t+1) t)
def main (t : UInt64) : UInt64 := loop (store64 state 0 t)
end Tests.ReceiptCaller
