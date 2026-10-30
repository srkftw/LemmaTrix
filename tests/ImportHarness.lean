import Guest.LiveSDK
namespace Tests.ImportHarness
open Guest Guest.LiveSDK
-- A separately admitted ordinary test caller. It only forwards opaque Objects
-- messages under its own incarnation and its declared127 Objects rights.
partial def serve (endpoint t : UInt64) : UInt64 :=
  let n := receive endpoint t
  let token := load64 (incoming+8) n
  let size := load64 (command+8) n
  let r := if load64 command n != 900 || n != 96+size || size < 64 || size > 928 then error else
    call size (copy (command+64) wire size n)
  let r := if r == error then 64+header 7 0 0 0 0 0 0 r else r
  serve endpoint (reply token r r)
def main (t : UInt64) : UInt64 := serve (self t) t
end Tests.ImportHarness
