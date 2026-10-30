import Guest.LiveSDK
namespace Guest.ObjectReferenceProbe
open Guest.LiveSDK
-- An ordinary caller exercises only public Objects read/reference APIs.
-- Objects receives this process's actual rights and full incarnation.
def failure (t : UInt64) : UInt64 := 64+store64 wire 2 (zero wire 8 t)
def dispatch (length t : UInt64) : UInt64 :=
  let op := load64 (command+8) t
  let h := load64 (command+16) t
  if length != 64 || load64 command t != 910 ||
    (op != 4 && op != 5 && op != 8 && op != 47) then failure t else
  let r := if op == 47 then releaseReference h t else
    if op == 5 then metadata h t else
    if op == 8 then drop h t else
    read h (load64 (command+24) t) (load64 (command+32) t) t
  if r < 64 || r > 576 then failure r else r
partial def serve (t : UInt64) : UInt64 :=
  let n := receive (self t) t
  if n < 96 || n > 1024 then serve n else
  let token := load64 (incoming+8) n
  let r := if load64 incoming n &&& 255 == 1 then dispatch (n-32) n else failure n
  serve (reply token r r)
def main (t : UInt64) : UInt64 := serve t
end Guest.ObjectReferenceProbe
