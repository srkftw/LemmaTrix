import Guest.LiveSDK
namespace Guest.ConsumerFormat
open Guest.LiveSDK
-- ConsumerRelease-v1: canonical512 metadata and publisher RSA2048 signature256.
-- This validates bounded declared metadata. Decoded audio measurements and
-- executable technical admission are checked by their separate consumers.
def magic : UInt64 := 0x31534e4f434c544c
partial def allZero (p n t : UInt64) : Bool :=
  if n == 0 then true else load8 p t == 0 && allZero (p+1) (n-1) t
partial def title (p n i t : UInt64) : Bool :=
  if i == n then true else
    let c := load8 (p+i) t
    c >= 32 && c <= 126 && title p n (i+1) t

def valid (p t : UInt64) : Bool :=
  let facet := load64 (p+16) t
  let format := load64 (p+24) t
  let n := load64 (p+336) t
  load64 p t == magic && load64 (p+8) t == 1 &&
  (facet == 1 || facet == 2) &&
  !allZero (p+32) 32 t && !allZero (p+64) 32 t &&
  !allZero (p+96) 32 t && !allZero (p+128) 32 t && !allZero (p+160) 32 t &&
  !allZero (p+192) 32 t && !allZero (p+224) 32 t &&
  load64 (p+288) t > 0 && load64 (p+288) t <= 0xffffffff &&
  load64 (p+296) t > 0 && load64 (p+296) t <= 0xffffffff &&
  n > 0 && n <= 64 && title (p+344) n 0 t && allZero (p+344+n) (64-n) t &&
  load64 (p+408) t > 0 && load64 (p+408) t <= 6291456 &&
  (load64 (p+448) t == 1 || load64 (p+448) t == 2) &&
  load64 (p+456) t == 1 && load64 (p+464) t <= 15 &&
  load64 (p+472) t == 3 && allZero (p+488) 24 t &&
  (if facet == 1 then
    format == 1 && allZero (p+256) 32 t &&
    load64 (p+416) t > 0 && load64 (p+416) t <= 3145728 &&
    (load64 (p+424) t == 1 || load64 (p+424) t == 2) &&
    load64 (p+432) t == 48000 && load64 (p+440) t == 16 && load64 (p+480) t == 0
   else
    format == 2 && !allZero (p+256) 32 t &&
    allZero (p+416) 32 t && load64 (p+480) t == 1)
end Guest.ConsumerFormat
