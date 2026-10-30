import Guest.LibraryFetchSDK
import Guest.ProjectSDK
namespace Tests.LibraryFetchHarness
open Guest Guest.LiveSDK
-- Test-only selected Library incarnation. It forwards frozen signed metadata
-- and delegates the completed root for byte evidence, never imports payloads.
partial def serve (endpoint t : UInt64) : UInt64 :=
  let n := receive endpoint t
  let token := load64 (incoming+8) n
  let op := load64 command n
  let h := load64 (command+8) n
  let a := load64 (command+16) n
  let b := load64 (command+24) n
  let c := load64 (command+32) n
  let r := if op == 720 then Guest.LibraryFetchSDK.begin h a b c (command+64) n else
    if op == 721 then Guest.LibraryFetchSDK.inspect h a n else
    if op == 722 then Guest.LibraryFetchSDK.cancel h a n else
    if op == 723 then Guest.ProjectSDK.delegate h a 1 n else error
  let r := if r == error then 64+header 7 0 0 0 0 0 0 r else r
  serve endpoint (reply token r r)
def main (t : UInt64) : UInt64 := serve (self t) t
end Tests.LibraryFetchHarness
