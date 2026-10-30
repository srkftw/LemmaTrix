import Guest.Library
namespace Guest.LibrarySaveFailureProbe
open Guest.LiveSDK
def state : UInt64 := 0x600000
def grants : UInt64 := 0x620000
def payload : UInt64 := 0x630000
def failure (t : UInt64) : UInt64 := 64+header 2 0 0 0 0 0 0 t
-- These writes initialize only this fixture's ordinary private arena. The
-- tested function is the real Library function, imported without a copy.
def prepareSave (length t : UInt64) : UInt64 :=
  if length != 191 && length != 192 then failure t else
  let old := load64 (Guest.Library.row 0+96) t
  let t := if old == 0 then t else releaseReference old t
  let t := zero payload 24 t
  let r := stage length 2 0 t
  if r != 64 || status r != 0 then failure r else
  let h := result r
  let r := append h 0 payload length r
  if r != 64 || status r != 0 then failure r else
  let r := stageDigest h r
  if r != 96 || status r != 0 then failure r else
  let r := commit h (wire+64) r
  if r != 96 || status r != 0 then failure r else
  let t := zero Guest.Library.st 128 (zero (Guest.Library.row 0) 256 r)
  let t := store64 (Guest.Library.st+16) 1 t
  let t := store64 (Guest.Library.st+184) 10000 t
  let t := store64 (Guest.Library.row 0) 1 t
  let t := store64 (Guest.Library.row 0+96) h t
  let t := store64 state length t
  64+header 0 length h 0 0 0 0 t
partial def undo (h i count t : UInt64) : UInt64 :=
  if i == count then t else
  let r := revoke h (load64 (grants+i*8) t) t
  if r != 64 || status r != 0 then error else undo h (i+1) count r
partial def capacityLoop (h shell i t : UInt64) : UInt64 :=
  let r := share h shell 25 t
  if r == 64 && status r == 4 then
    let t := undo h 0 i r
    if t == error then failure t else 64+header 0 i 4 0 0 0 0 t
  else if r != 64 || status r != 0 || i == 32 then
    let t := if r == 64 && status r == 0 then revoke h (result r) r else r
    let t := undo h 0 i t
    failure t
  else capacityLoop h shell (i+1) (store64 (grants+i*8) (result r) r)
def capacity (t : UInt64) : UInt64 :=
  let h := load64 (Guest.Library.row 0+96) t
  let shell := syscall 97 4 0 0 0 t
  if h == 0 || shell == error then failure shell else capacityLoop h shell 0 shell
partial def repeatRetain (left expected good t : UInt64) : UInt64 :=
  if left == 0 then
    64+header 0 good (load64 (Guest.Library.st+176) t) (load64 (Guest.Library.st+400) t) (load64 (Guest.Library.st+184) t) 0 0 t
  else
    let t := Guest.Library.retainGameSave t
    let ok := load64 (Guest.Library.st+176) t == expected && load64 (Guest.Library.st+400) t == 0
    repeatRetain (left-1) expected (good+(if ok then 1 else 0)) t
def dispatch (length t : UInt64) : UInt64 :=
  let op := load64 command t
  let value := load64 (command+8) t
  if length != 64 then failure t else
  if op == 920 then prepareSave value t
  else if op == 921 then capacity t
  else if op == 922 && value == 40 then repeatRetain value (if load64 state t == 191 then 42 else 21) 0 t
  else if op == 923 && value != 0 then Guest.Library.portal 14 1 value 0 0 t
  else if op == 924 then Guest.Library.portal 4 0 value 0 0 t
  else failure t
partial def serve (t : UInt64) : UInt64 :=
  let n := receive (self t) t
  if n < 96 || n > 1024 then serve n else
  let token := load64 (incoming+8) n
  let r := if load64 incoming n &&& 255 == 1 then dispatch (n-32) n else failure n
  serve (reply token r r)
def main (t : UInt64) : UInt64 :=
  serve (zero state 64 (zero (Guest.Library.row 0) 256 (zero Guest.Library.st 128 t)))
end Guest.LibrarySaveFailureProbe
