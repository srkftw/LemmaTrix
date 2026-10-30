import Guest.Library
import Guest.GameSaveFormat
namespace Guest.LibraryBindingProbe
open Guest.LiveSDK
def state : UInt64 := 0x600000
def saved : UInt64 := 0x610000
def failure (t : UInt64) : UInt64 := 64+header 2 0 0 0 0 0 0 t
def report (t : UInt64) : UInt64 :=
  let t := header 0 (load64 (Guest.Library.st+176) t) (load64 (Guest.Library.st+16) t)
    (load64 (Guest.Library.row 0+8) t) (load64 (Guest.Library.row 0+96) t)
    (load64 (Guest.Library.row 0+256+48) t) (load64 (Guest.Library.st+528) t) t
  let t := store64 (wire+56) (load64 (Guest.Library.st+536) t) t
  let t := Guest.Library.hash (Guest.Library.row 0+1024) 768 Guest.Library.hashOut t
  96+copy Guest.Library.hashOut (wire+64) 32 t
-- These inputs initialize only this ordinary fixture's own private arena.
-- Admission, signature verification and row mutation are the actual Library.
def prepareSave (length t : UInt64) : UInt64 :=
  if length != 256 || load64 (Guest.Library.st+16) t != 1 then failure t else
  let t := copy (command+64) saved 192 t
  if !Guest.GameSaveFormat.valid saved t then failure t else
  let t := Guest.Library.add t
  if load64 (Guest.Library.row 0+8) t == 0 then failure t else
  let r := stage 192 2 0 t
  if r != 64 || status r != 0 then failure r else
  let h := result r
  let r := append h 0 saved 192 r
  if r != 64 || status r != 0 then failure r else
  let r := stageDigest h r
  if r != 96 || status r != 0 then failure r else
  let r := commit h (wire+64) r
  if r != 96 || status r != 0 then failure r else
  report (store64 (Guest.Library.row 0+96) h r)
def dispatch (length t : UInt64) : UInt64 :=
  let op := load64 command t
  let h := load64 (command+8) t
  let a := load64 (command+16) t
  let b := load64 (command+24) t
  if op == 950 && a <= 1536 && b > 0 && b <= 512 && b <= 1536-a && length == 64+b &&
      (a == 0 || a == load64 state t) then
    64+header 0 (a+b) 0 0 0 0 0 (store64 state (a+b) (copy (command+64) (Guest.Library.metadata+a) b t))
  else if op == 951 && length == 64 && load64 state t == 1536 then
    report (Guest.Library.acceptMetadata t)
  else if op == 952 then prepareSave length t
  else if op == 953 && length == 64 then read (load64 (Guest.Library.row 0+96) t) 0 192 t
  else if op == 954 && length == 64 && a <= 2048 && b <= 512 && b <= 2048-a then
    64+b+copy (Guest.Library.row 0+a) (wire+64) b (header 0 0 0 0 0 0 0 t)
  else if op == 955 && length == 64 then
    report (store64 (Guest.Library.st+528) h (store64 (Guest.Library.st+536) a t))
  else if op == 956 && length == 64 then report (Guest.Library.bindProcess 2 t)
  else failure t
partial def serve (t : UInt64) : UInt64 :=
  let n := receive (self t) t
  if n < 96 || n > 1024 then serve n else
  let token := load64 (incoming+8) n
  let r := if load64 incoming n &&& 255 == 1 then dispatch (n-32) n else failure n
  serve (reply token r r)
def main (t : UInt64) : UInt64 :=
  serve (zero state 64 (zero (Guest.Library.row 0) 256 (zero Guest.Library.st 640 t)))
end Guest.LibraryBindingProbe
