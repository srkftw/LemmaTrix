import Guest.Primitives
namespace Guest.AES
-- FIPS197 (2023 update), SP800-38A CTR. Caller-owned 576-byte context.
-- Lookup-table implementation: no constant-time or cache-isolation claim.
-- Context: expanded key0..239, rounds240, counter248, stream264, used280,
-- block288, temporary304, immutable S-box320..575. Buffers must not overlap.
def err : UInt64 := 0xffffffffffffffff
partial def zero (p n t : UInt64) : UInt64 :=
  if n == 0 then t else zero (p+1) (n-1) (store8 p 0 t)
partial def copy (a b n t : UInt64) : UInt64 :=
  if n == 0 then t else copy (a+1) (b+1) (n-1) (store8 b (load8 a t) t)
def xtime (v : UInt64) : UInt64 := ((v <<< 1) ^^^ (((0 : UInt64)-(v >>> 7)) &&& 27)) &&& 255
def sb (c v t : UInt64) : UInt64 := load8 (c+320+(v &&& 255)) t
def table (c t : UInt64) : UInt64 :=
  let t := store64 (c+320) 0xc56f6bf27b777c63 t
  let t := store64 (c+328) 0x76abd7fe2b670130 t
  let t := store64 (c+336) 0xf04759fa7dc982ca t
  let t := store64 (c+344) 0xc072a49cafa2d4ad t
  let t := store64 (c+352) 0xccf73f362693fdb7 t
  let t := store64 (c+360) 0x1531d871f1e5a534 t
  let t := store64 (c+368) 0x9a059618c323c704 t
  let t := store64 (c+376) 0x75b227ebe2801207 t
  let t := store64 (c+384) 0xa05a6e1b1a2c8309 t
  let t := store64 (c+392) 0x842fe329b3d63b52 t
  let t := store64 (c+400) 0x5bb1fc20ed00d153 t
  let t := store64 (c+408) 0xcf584c4a39becb6a t
  let t := store64 (c+416) 0x85334d43fbaaefd0 t
  let t := store64 (c+424) 0xa89f3c507f02f945 t
  let t := store64 (c+432) 0xf5389d928f40a351 t
  let t := store64 (c+440) 0xd2f3ff1021dab6bc t
  let t := store64 (c+448) 0x1744975fec130ccd t
  let t := store64 (c+456) 0x73195d643d7ea7c4 t
  let t := store64 (c+464) 0x88902a22dc4f8160 t
  let t := store64 (c+472) 0xdb0b5ede14b8ee46 t
  let t := store64 (c+480) 0x5c2406490a3a32e0 t
  let t := store64 (c+488) 0x79e4959162acd3c2 t
  let t := store64 (c+496) 0xa94ed58d6d37c8e7 t
  let t := store64 (c+504) 0x08ae7a65eaf4566c t
  let t := store64 (c+512) 0xc6b4a61c2e2578ba t
  let t := store64 (c+520) 0x8a8bbd4b1f74dde8 t
  let t := store64 (c+528) 0x0ef6034866b53e70 t
  let t := store64 (c+536) 0x9e1dc186b9573561 t
  let t := store64 (c+544) 0x948ed9691198f8e1 t
  let t := store64 (c+552) 0xdf2855cee9871e9b t
  let t := store64 (c+560) 0x6842e6bf0d89a18c t
  let t := store64 (c+568) 0x16bb54b00f2d9941 t
  t
partial def keyWords (c nk words i rc t : UInt64) : UInt64 :=
  if i == words then t else
    let p := c+(i-1)*4
    let a := load8 p t
    let b := load8 (p+1) t
    let d := load8 (p+2) t
    let e := load8 (p+3) t
    let rotated := i%nk == 0
    let substitute := rotated || (nk == 8 && i%nk == 4)
    let aa := if rotated then sb c b t ^^^ rc else if substitute then sb c a t else a
    let bb := if rotated then sb c d t else if substitute then sb c b t else b
    let dd := if rotated then sb c e t else if substitute then sb c d t else d
    let ee := if rotated then sb c a t else if substitute then sb c e t else e
    let q := c+(i-nk)*4
    let o := c+i*4
    let t := store8 o (load8 q t ^^^ aa) t
    let t := store8 (o+1) (load8 (q+1) t ^^^ bb) t
    let t := store8 (o+2) (load8 (q+2) t ^^^ dd) t
    let t := store8 (o+3) (load8 (q+3) t ^^^ ee) t
    keyWords c nk words (i+1) (if rotated then xtime rc else rc) t
/-- Initialize AES128/AES256 with zero CTR IV; caller may set counter248..263. -/
def init (c key keyBytes t : UInt64) : UInt64 :=
  if keyBytes != 16 && keyBytes != 32 then err else
    let t := zero c 576 t
    let t := table c t
    let t := copy key c keyBytes t
    let rounds := if keyBytes == 16 then 10 else 14
    let t := store64 (c+240) rounds t
    let t := store64 (c+280) 16 t
    keyWords c (keyBytes/4) ((rounds+1)*4) (keyBytes/4) 1 t
partial def addKey (c round i t : UInt64) : UInt64 :=
  if i == 16 then t else
    addKey c round (i+1) (store8 (c+288+i) (load8 (c+288+i) t ^^^ load8 (c+round*16+i) t) t)
partial def subShift (c i t : UInt64) : UInt64 :=
  if i == 16 then copy (c+304) (c+288) 16 t else
    let row := i%4
    let col := i/4
    let v := load8 (c+288+((col+row)%4)*4+row) t
    subShift c (i+1) (store8 (c+304+i) (sb c v t) t)
partial def mix (c col t : UInt64) : UInt64 :=
  if col == 4 then t else
    let p := c+288+col*4
    let a := load8 p t
    let b := load8 (p+1) t
    let d := load8 (p+2) t
    let e := load8 (p+3) t
    let sum := a ^^^ b ^^^ d ^^^ e
    let t := store8 p (a ^^^ sum ^^^ xtime (a ^^^ b)) t
    let t := store8 (p+1) (b ^^^ sum ^^^ xtime (b ^^^ d)) t
    let t := store8 (p+2) (d ^^^ sum ^^^ xtime (d ^^^ e)) t
    let t := store8 (p+3) (e ^^^ sum ^^^ xtime (e ^^^ a)) t
    mix c (col+1) t
partial def rounds (c r n t : UInt64) : UInt64 :=
  if r > n then t else
    let t := subShift c 0 t
    let t := if r == n then t else mix c 0 t
    rounds c (r+1) n (addKey c r 0 t)
def encryptBlock (c input out t : UInt64) : UInt64 :=
  let t := copy input (c+288) 16 t
  let t := rounds c 1 (load64 (c+240) t) (addKey c 0 0 t)
  copy (c+288) out 16 t
partial def increment (c i t : UInt64) : UInt64 :=
  if i == 0 then t else
    let p := c+248+i-1
    let v := (load8 p t+1) &&& 255
    let t := store8 p v t
    if v == 0 then increment c (i-1) t else t
partial def cryptLoop (c input out n i t : UInt64) : UInt64 :=
  if i == n then t else
    let used := load64 (c+280) t
    let t := if used == 16 then increment c 16 (encryptBlock c (c+248) (c+264) t) else t
    let pos := if used == 16 then 0 else used
    let t := store8 (out+i) (load8 (input+i) t ^^^ load8 (c+264+pos) t) t
    let t := store64 (c+280) (pos+1) t
    cryptLoop c input out n (i+1) t
/-- Serialized incremental CTR. Owner enforces lifetime <2^20 cells (no wrap). -/
def crypt (c input out n t : UInt64) : UInt64 :=
  if n > 4096 || (load64 (c+240) t != 10 && load64 (c+240) t != 14) then err else
    cryptLoop c input out n 0 t
end Guest.AES
