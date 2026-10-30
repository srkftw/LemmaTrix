import Guest.Library
namespace Guest.LibraryCollectionConsentProbe
open Guest.LiveSDK
def state : UInt64 := 0x600000
def binding : UInt64 := 0x610000
def proof : UInt64 := 0x611000
def samplePrefix : UInt64 := 0x612000
def failure (t : UInt64) : UInt64 := 64+header 2 0 0 0 0 0 0 t
def report (t : UInt64) : UInt64 :=
  let t := header 0 (load64 (Guest.Library.st+8) t) (load64 (Guest.Library.st+88) t)
    (load64 (Guest.Library.st+96) t) (load64 (Guest.Library.st+128) t)
    (load64 (Guest.Library.st+104) t) (load64 (Guest.Library.st+120) t) t
  let t := store64 (wire+56) (load64 (Guest.Library.st+216) t) t
  let t := copy (Guest.Library.st+288) (wire+64) 32 t
  let t := store64 (wire+96) (load64 (Guest.Library.st+208) t) t
  let t := copy (Guest.Library.job 0) (wire+104) 128 t
  let t := copy (Guest.Library.job 1) (wire+232) 128 t
  let t := copy (Guest.Library.job 2) (wire+360) 128 t
  616+copy (Guest.Library.job 3) (wire+488) 128 t
partial def appendMetadata (h row offset t : UInt64) : UInt64 :=
  if offset == 1536 then t else
  let r := append h offset (Guest.Library.row row+256+offset) 512 t
  if r != 64 || status r != 0 then error else appendMetadata h row (offset+512) r
partial def commitRows (i t : UInt64) : UInt64 :=
  if i == 3 then report (store64 (Guest.Library.st+16) 3 t) else
  if load64 (state+i*8) t != 1536 then failure t else
  let r := stage 1536 2 0 t
  if r != 64 || status r != 0 then failure r else
  let h := result r
  let r := appendMetadata h i 0 r
  if r == error then failure r else
  let r := stageDigest h r
  if r != 96 || status r != 0 then failure r else
  let r := commit h (wire+64) r
  if r != 96 || status r != 0 then failure r else
  commitRows (i+1) (store64 (Guest.Library.row i+8) h (store64 (Guest.Library.row i) 1 r))
def pauseActual (length t : UInt64) : UInt64 :=
  if length != 512 || load64 (Guest.Library.job 0) t != 1 then failure t else
  let t := copy (command+64) binding 352 t
  let t := copy (command+416) proof 32 t
  let t := copy (command+448) samplePrefix 64 t
  let r := Guest.ContentSDK.reserve binding (load64 (Guest.Library.job 0+80) t) (load64 (Guest.Library.job 0+72) t) 3 0 t
  if r != 64 || status r != 0 then failure r else
  let h := result r
  let r := Guest.ContentSDK.beginChunk h 0 proof 32 r
  if r != 64 || status r != 0 then failure r else
  let j := result r
  let r := Guest.ContentSDK.append j 0 samplePrefix 64 r
  if r != 64 || status r != 0 then failure r else
  let t := store64 (state+32) h (store64 (state+40) j r)
  let t := store64 (Guest.Library.job 0+24) h t
  let t := store64 (Guest.Library.job 0+48) j t
  let t := store64 (Guest.Library.job 0) 5 t
  report (Guest.Library.pause t)
def dispatch (length t : UInt64) : UInt64 :=
  let op := load64 command t
  let h := load64 (command+8) t
  let a := load64 (command+16) t
  let b := load64 (command+24) t
  if op == 940 && h < 3 && a == load64 (state+h*8) t && b > 0 && b <= 512 && a <= 1536 && b <= 1536-a && length == 64+b then
    64+header 0 (a+b) 0 0 0 0 0 (store64 (state+h*8) (a+b) (copy (command+64) (Guest.Library.row h+256+a) b t))
  else if op == 941 && length == 64 then commitRows 0 t
  else if op == 942 && length == 64 && h < 256 then
    report (Guest.Library.input (((1 : UInt64) <<< 48) ||| (h <<< 32) ||| 1) t)
  else if op == 943 then pauseActual length t
  else if op == 944 && length == 64 then Guest.ContentSDK.inspectJob (load64 (state+40) t) t
  else if op == 945 && length == 64 && h < 4 && a <= 2048 && b <= 512 && b <= 2048-a then
    64+b+copy (Guest.Library.job h+a) (wire+64) b (header 0 0 0 0 0 0 0 t)
  else if op == 946 && length == 64 then report t
  else if op == 947 && length == 64 then Guest.ContentSDK.beginChunk (load64 (state+32) t) 0 proof 32 t
  else if op == 948 && length == 64 then report (Guest.Library.monitorDecision t)
  else failure t
partial def serve (t : UInt64) : UInt64 :=
  let n := receive (self t) t
  if n < 96 || n > 1024 then serve n else
  let token := load64 (incoming+8) n
  let r := if load64 incoming n &&& 255 == 1 then dispatch (n-32) n else failure n
  serve (reply token r r)
def main (t : UInt64) : UInt64 :=
  let t := zero Guest.Library.st 128 (zero (Guest.Library.row 0) 768 (zero (Guest.Library.job 0) 2048 (zero state 64 t)))
  let t := store64 (Guest.Library.st+136) 1 t
  let t := store64 (Guest.Library.st+112) 6029312 t
  serve (store64 (Guest.Library.st+184) 70000 t)
end Guest.LibraryCollectionConsentProbe
