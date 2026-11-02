import Lemma.UI
import Lemma.Objects
namespace Notes.Schema
open Lemma.UI Lemma.Objects
-- Notes schema1 is an immutable4096-byte object. It binds category, revision,
-- bounded UTF-8 title/body, selected projectID32 and preceding revisionID32.
def magic : UInt64 := 0x315345544f4e544c
def capacity : UInt64 := 3904
def fold (c enabled : UInt64) : UInt64 := if enabled == 1 && c >= 65 && c <= 90 then c+32 else c
partial def equalAt (text query bytes offset index folded t : UInt64) : Bool :=
  if index == bytes then true else
  fold (load8 (text+offset+index) t) folded == fold (load8 (query+index) t) folded &&
    equalAt text query bytes offset (index+1) folded t
partial def contains (text length query bytes offset folded t : UInt64) : Bool :=
  if bytes == 0 then true else
  if offset > length || bytes > length-offset then false else
  equalAt text query bytes offset 0 folded t || contains text length query bytes (offset+1) folded t
partial def utf8 (p n i remaining lower upper t : UInt64) : Bool :=
  if i == n then remaining == 0 else
  let c := load8 (p+i) t
  if remaining != 0 then c >= lower && c <= upper && utf8 p n (i+1) (remaining-1) 128 191 t else
  if c == 10 || c == 9 || (c >= 32 && c <= 126) then utf8 p n (i+1) 0 0 0 t else
  if c >= 194 && c <= 223 then utf8 p n (i+1) 1 128 191 t else
  if c == 224 then utf8 p n (i+1) 2 160 191 t else
  if c >= 225 && c <= 236 then utf8 p n (i+1) 2 128 191 t else
  if c == 237 then utf8 p n (i+1) 2 128 159 t else
  if c >= 238 && c <= 239 then utf8 p n (i+1) 2 128 191 t else
  if c == 240 then utf8 p n (i+1) 3 144 191 t else
  if c >= 241 && c <= 243 then utf8 p n (i+1) 3 128 191 t else
  c == 244 && utf8 p n (i+1) 3 128 143 t
partial def previous (p i t : UInt64) : UInt64 :=
  if i == 0 then 0 else
  if load8 (p+i-1) t >= 128 && load8 (p+i-1) t < 192 then previous p (i-1) t else i-1
def valid (p t : UInt64) : Bool :=
  load64 p t == magic && load64 (p+8) t == 1 && load64 (p+16) t <= 2 &&
  load64 (p+24) t != 0 && load64 (p+32) t <= 63 && load64 (p+40) t <= capacity &&
  utf8 (p+128) (load64 (p+32) t) 0 0 0 0 t && utf8 (p+192) (load64 (p+40) t) 0 0 0 0 t
-- App and forks consume this shared selection rule; category0 means all.
def selectedBy (p query bytes category folded t : UInt64) : Bool :=
  (category == 0 || load64 (p+16) t+1 == category) &&
  (contains (p+128) (load64 (p+32) t) query bytes 0 folded t ||
   contains (p+192) (load64 (p+40) t) query bytes 0 folded t)
end Notes.Schema
