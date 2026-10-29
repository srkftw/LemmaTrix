import Guest.SDK
namespace Guest
partial def awaitShare (t : UInt64) : UInt64 :=
  let ready := syscall 13 0 0 0 0 t
  if ready == 1 then ready else
    let alive := syscall 14 0 0 0 0 ready
    if alive == 0 then alive else awaitShare (yield alive)
partial def rotate (p n t : UInt64) : UInt64 :=
  if n == 0 then t else
    let c := load8 p t
    let c := if c >= 97 && c <= 122 then (c-97+13)%26+97 else c
    rotate (p+1) (n-1) (store8 p c t)
partial def awaitFault (t : UInt64) : UInt64 :=
  let alive := syscall 14 0 0 0 0 t
  if alive == 0 then alive else awaitFault (yield alive)
def runWorkbench (version initial : UInt64) : UInt64 :=
  let release := syscall 15 0 0 0 0 initial
  let metadataLength := objectRead release 256 release
  let len := objectRead 256 256 metadataLength
  let t := consoleWrite len len
  let t := if version == 1 then upper buffer len t else rotate buffer len t
  let revision := objectRevise 256 len t
  let t := consoleWrite len revision
  let t := objectShareRead revision 2 t
  let t := yield t
  let t := awaitShare t
  let t := objectRevoke revision t
  let t := yield t
  let t := syscall 7 0 0 0 0 t
  let t := syscall 8 0 0 0 0 t
  -- The second yield lets the independent client demonstrate stale-handle denial.
  let t := yield t
  let t := awaitFault t
  let t := consoleWrite len t
  store8 buffer 10 t
def appMain (initial : UInt64) : UInt64 := runWorkbench 1 initial
def appV2 (initial : UInt64) : UInt64 := runWorkbench 2 initial
end Guest
