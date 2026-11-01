import Guest.LiveSDK
namespace Guest.ObjectQuotaProbe
open Guest.LiveSDK
-- The installed test application has ordinary rights799. Objects observes this
-- process incarnation and those rights, rather than the controller's authority.
def failure (t : UInt64) : UInt64 := 64+store64 wire 2 (zero wire 8 t)
def dispatch (length t : UInt64) : UInt64 :=
  let op := load64 command t
  let h := load64 (command+8) t
  if op == 1 && length == 64 then stage (load64 (command+16) t) (load64 (command+24) t) h t else
  if op == 2 && length >= 64 && length <= 576 then append h (load64 (command+16) t) (command+64) (length-64) t else
  if op == 3 && length == 96 then commit h (command+64) t else
  if op == 4 && length == 64 then read h (load64 (command+16) t) (load64 (command+24) t) t else
  if op == 5 && length == 64 then metadata h t else
  if op == 8 && length == 64 then drop h t else
  if op == 13 && length == 64 then abortStage h t else failure t
partial def serve (t : UInt64) : UInt64 :=
  let n := receive (self t) t
  if n < 96 || n > 1024 then serve n else
  let token := load64 (incoming+8) n
  let r := if (load64 incoming n &&& 255) == 1 then dispatch (n-32) n else failure n
  serve (reply token r r)
def main (t : UInt64) : UInt64 := serve t
end Guest.ObjectQuotaProbe
