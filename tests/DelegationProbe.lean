import Guest.ContentSDK
namespace Tests.DelegationProbe
open Guest Guest.LiveSDK
-- A separately approved test caller with read/share/server.store rights only.
-- It cannot create objects, read backing, inspect keys or mint another issuer.
partial def serve (endpoint t : UInt64) : UInt64 :=
  let n := receive endpoint t
  let token := load64 (incoming+8) n
  let op := load64 command n
  let h := load64 (command+8) n
  let a := load64 (command+16) n
  let b := load64 (command+24) n
  let c := load64 (command+32) n
  let r := if op == 850 then Guest.ContentSDK.share h a n else
    if op == 851 then share h a 1 n else
    if op == 852 then syscall 30 3 wire 64 1024 (header 251 h a b c 0 0 n) else
    if op == 853 then checkDelegation h a n else
    if op == 854 then read h 0 a n else
    if op == 855 then syscall 30 3 wire 64 1024 (header 252 h 0 0 0 0 0 n) else
    if op == 856 then Guest.ContentSDK.release h n else error
  let t := if r == error then reply token 64 (header 7 0 0 0 0 0 0 r) else reply token r r
  serve endpoint t
def main (t : UInt64) : UInt64 := serve (self t) t
end Tests.DelegationProbe
