import Guest.ContentSDK
namespace Guest.Wave
open Guest.LiveSDK
def info : UInt64 := 0x6e1000
def bytes : UInt64 := 0x6e2000
-- Preserve would-block separately from malformed/denied/integrity failures.
-- Callers can retain a scoped partial reader without accepting unverified bytes.
def unavailable (code t : UInt64) : UInt64 := error+store64 (info+56) code t
def u16 (p t : UInt64) : UInt64 := load8 p t ||| (load8 (p+1) t <<< 8)
def u32 (p t : UInt64) : UInt64 := u16 p t ||| (u16 (p+2) t <<< 16)
-- Exact small reads split at the authenticated content chunk boundary. No
-- payload-sized allocation or unverified provider index is accepted here.
def range (h offset count destination t : UInt64) : UInt64 :=
  if count == 0 || count > 512 then unavailable 2 t else
  let t := store64 (info+56) 0 t
  let first := if count > 4096-offset%4096 then 4096-offset%4096 else count
  let r := ContentSDK.read h offset first t
  if r != first+64 || status r != 0 then unavailable (if r >= 64 && r != error then status r else 7) r else
  let t := copy (wire+64) destination first r
  if first == count then t else
  let r := ContentSDK.read h (offset+first) (count-first) t
  if r != count-first+64 || status r != 0 then unavailable (if r >= 64 && r != error then status r else 7) r else copy (wire+64) (destination+first) (count-first) r
def format (h offset n t : UInt64) : UInt64 :=
  if n < 16 || load64 (info+32) t != 0 then error else
  let r := range h offset 16 bytes t
  if r == error then error else
  let channels := u16 (bytes+2) r
  let align := channels*2
  if u16 bytes r != 1 || (channels != 1 && channels != 2) || u32 (bytes+4) r != 48000 ||
    u32 (bytes+8) r != 48000*align || u16 (bytes+12) r != align || u16 (bytes+14) r != 16 then error else
  let t := store64 (info+24) channels r
  store64 (info+32) 1 t
partial def scan (h offset total fuel t : UInt64) : UInt64 :=
  if offset == total then
    let align := load64 (info+24) t*2
    if load64 (info+32) t != 1 || load64 (info+40) t != 1 || align == 0 || load64 (info+16) t%align != 0 then error else
      store64 (info+48) (load64 (info+16) t/align) t
  else if fuel == 0 || offset > total || total-offset < 8 then error else
  let r := range h offset 8 bytes t
  if r == error then error else
  let kind := u32 bytes r
  let n := u32 (bytes+4) r
  let body := offset+8
  let padding := n%2
  if n > total-body || padding > total-body-n then error else
  let t := if kind == 0x20746d66 then format h body n r else
    if kind == 0x61746164 then
      if load64 (info+40) r != 0 || n == 0 then error else
      store64 (info+40) 1 (store64 (info+16) n (store64 (info+8) body r))
    else r
  if t == error then error else scan h (body+n+padding) total (fuel-1) t
def parse (h t : UInt64) : UInt64 :=
  let t := zero info 16 t
  let r := ContentSDK.describe h t
  if r != 320 || status r != 0 then error else
  if load64 (wire+104) r != 1 then error else
  let total := load64 (wire+88) r
  if total < 44 || total > 67108864 then error else
  let r := range h 0 12 bytes r
  if r == error || u32 bytes r != 0x46464952 || u32 (bytes+8) r != 0x45564157 || u32 (bytes+4) r != total-8 then error else
    scan h 12 total 128 (store64 info h r)
end Guest.Wave
