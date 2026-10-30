import Guest.AudioSDK
namespace Tests.AudioProbe
open Guest Guest.LiveSDK
partial def pattern (i t : UInt64) : UInt64 :=
  if i == 128 then t else pattern (i+1) (store64 (0x600000+i*8) 0x3344112233441122 t)
partial def loop (t : UInt64) : UInt64 :=
  let n := receive (self t) t
  let token := load64 (incoming+8) n
  let op := load64 command n
  let epoch := load64 (command+8) n
  let count := load64 (command+16) n
  let value := if op == 810 then Guest.AudioSDK.acquire n else
    if op == 811 then Guest.AudioSDK.write epoch 0x600000 count n else
    if op == 812 then Guest.AudioSDK.stop epoch n else
    if op == 813 then Guest.AudioSDK.inspect epoch n else
    if op == 814 then Guest.AudioSDK.write epoch 0x80000000 count n else error
  let t := reply token 64 (header 0 value 0 0 0 0 0 value)
  if op == 815 then syscall 10 0 0 0 0 t else loop t
 def main (t : UInt64) : UInt64 := loop (pattern 0 t)
end Tests.AudioProbe
