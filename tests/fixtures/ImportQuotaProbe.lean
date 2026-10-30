import Guest.ProjectSDK
namespace Guest.ImportQuotaProbe
open Guest.LiveSDK
-- Explicit test setup reaches services as this ordinary signed application's
-- incarnation and rights, never as its administrative RPC caller.
def failure (t : UInt64) : UInt64 := 64+store64 wire 1 (zero wire 8 t)
def dispatch (length t : UInt64) : UInt64 :=
  let op := load64 command t
  let target := if (op >= 35 && op <= 40) || op == 10 || op == 23 || op == 28 || op == 29 then 2 else
    if op >= 232 && op <= 238 then 3 else 0
  if target != 0 then
    let r := syscall 30 target wire length 1024 (copy command wire length t)
    if r == error then failure r else r
  else failure t
partial def serve (t : UInt64) : UInt64 :=
  let n := receive (self t) t
  if n < 96 || n > 1024 then serve n else
    let token := load64 (incoming+8) n
    let r := if (load64 incoming n &&& 255) == 1 then dispatch (n-32) n else failure n
    serve (reply token r r)
def main (initial : UInt64) : UInt64 := serve initial
end Guest.ImportQuotaProbe
