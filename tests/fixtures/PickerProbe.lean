import Guest.LiveSDK
namespace Guest.PickerProbe
open Guest.LiveSDK
-- A signed ordinary test caller forwards only the public picker interface.
-- Its IPC recipient sees this incarnation's actual rights, never Launcher's.
def failure (t : UInt64) : UInt64 := 64+store64 wire 2 (zero wire 8 t)
def dispatch (length t : UInt64) : UInt64 :=
  let target := load64 (command+8) t
  let op := load64 (command+16) t
  let requested := load64 (command+24) t
  let nonce := load64 (command+32) t
  let version := load64 (command+40) t
  if length != 64 || load64 command t != 900 || target &&& 255 != 4 ||
    (op != 3 && op != 4 && op != 14) then failure t else
  let t := header op requested nonce 0 0 0 0 t
  let t := store64 (wire+56) version t
  let r := syscall 30 target wire 64 1024 t
  if r != 64 then failure r else r
partial def serve (t : UInt64) : UInt64 :=
  let n := receive (self t) t
  if n < 96 || n > 1024 then serve n else
  let token := load64 (incoming+8) n
  let r := if load64 incoming n &&& 255 == 1 then dispatch (n-32) n else failure n
  serve (reply token r r)
def main (t : UInt64) : UInt64 := serve t
end Guest.PickerProbe
