import Guest.ProjectSDK
import Guest.ReleaseFormat
import Guest.ReleaseClaims
namespace Guest.SourceDependencyPolicy
open Guest.LiveSDK Guest.ProjectSDK
-- Private publisher/Registry verification workspace, outside their state,
-- Ed25519 and Noise scratch. Objects never executes cryptography in its arena.
def source : UInt64 := 0x7b0000
def release : UInt64 := 0x7c0000
def state : UInt64 := 0x7d0000
def task (i : UInt64) : UInt64 := 0x720000+i*4096
partial def readAll (handle destination bytes offset t : UInt64) : UInt64 :=
  if offset == bytes then t else
  let n := if bytes-offset > 512 then 512 else bytes-offset
  let r := read handle offset n t
  if r != 64+n || status r != 0 then error else
  readAll handle destination bytes (offset+n) (copy (wire+64) (destination+offset) n r)
def get (root id destination limit t : UInt64) : UInt64 :=
  let r := resolve root id t
  if r != 128 || status r != 0 || load64 (wire+16) r > limit then error else
  let n := load64 (wire+16) r
  let r := readAll (result r) destination n 0 r
  if r == error then error else Guest.Effects.effectValue n r
partial def carrier (root pin pe i count t : UInt64) : Bool :=
  if i == count then false else
  let e := source+32+i*128
  if load64 e t != 10 then carrier root pin pe (i+1) count t else
  let r := resolve root (e+16) t
  if r != 128 || status r != 0 then false else
  let r := metadata (result r) r
  if r != 96 || status r != 0 then false else
  Guest.ReleaseClaims.digestEquals (Guest.ReleaseClaims.field pin pe 30 r) pe (wire+64) r || carrier root pin pe (i+1) count r
partial def find (root pin pe i count t : UInt64) : UInt64 :=
  if i == count then error else
  let e := source+32+i*128
  if load64 e t != 13 then find root pin pe (i+1) count t else
  let n := get root (e+16) release 65536 t
  if n == error then error else
  let c := load64 (release+16) n
  let h := release+32+c*128+64
  if c != 1 || n < 832 || load64 (h+8) n != 4 || load64 (h+384) n != 2 ||
    !Guest.ReleaseClaims.digestEquals (Guest.ReleaseClaims.field pin pe 29 n) pe (h+160) n then find root pin pe (i+1) count n else
  if !Guest.ReleaseFormat.verify h (h+576) n then error else
  Guest.Effects.effectValue h n
partial def enqueue (sourceId p end_ sdk se t : UInt64) : UInt64 :=
  if p >= end_ then error else
  if load8 p t == 93 then t else
  let count := load64 state t
  let pe := Guest.ReleaseClaims.valueEnd p end_ 32 t
  let sdkEnd := Guest.ReleaseClaims.valueEnd sdk se 32 t
  if count == 16 || load8 p t != 123 || pe == 0 || pe-p > 3584 ||
    sdkEnd == 0 || sdkEnd-sdk > 256 then error else
  let q := task count
  let t := copy sourceId q 32 t
  let t := store64 (q+32) (pe-p) t
  let t := store64 (q+40) (sdkEnd-sdk) t
  let t := copy p (q+64) (pe-p) t
  let t := copy sdk (q+3648) (sdkEnd-sdk) t
  let t := store64 state (count+1) t
  if pe < end_ && load8 pe t == 93 then t else
  if pe >= end_ || load8 pe t != 44 then error else enqueue sourceId (pe+1) end_ sdk se t
def one (root pin pe count sdk se t : UInt64) : UInt64 :=
  let h := find root pin pe 0 count t
  if h == error then error else
  let m := h+608
  let me := m+load64 (h-40) h
  if !Guest.ReleaseClaims.digestEquals (Guest.ReleaseClaims.field pin pe 9 h) pe (h+96) h ||
    !Guest.ReleaseClaims.numberEquals (Guest.ReleaseClaims.field pin pe 31 h) pe 0 h ||
    !Guest.ReleaseClaims.valueEquals (Guest.ReleaseClaims.field pin pe 23 h) pe (Guest.ReleaseClaims.field m me 23 h) me h ||
    !Guest.ReleaseClaims.valueEquals (Guest.ReleaseClaims.field pin pe 24 h) pe (Guest.ReleaseClaims.field m me 24 h) me h ||
    !Guest.ReleaseClaims.valueEquals (Guest.ReleaseClaims.field pin pe 28 h) pe (Guest.ReleaseClaims.field m me 28 h) me h ||
    !Guest.ReleaseClaims.valueEquals (Guest.ReleaseClaims.field pin pe 13 h) pe (Guest.ReleaseClaims.field m me 13 h) me h ||
    !Guest.ReleaseClaims.valueEquals sdk se (Guest.ReleaseClaims.field m me 12 h) me h ||
    !carrier root pin pe 0 count h then error else
  let children := Guest.ReleaseClaims.field m me 13 h
  if children == 0 || load8 children h != 91 then error else
  enqueue (release+48) (children+1) me sdk se h
partial def tasks (root cursor t : UInt64) : UInt64 :=
  if cursor == load64 state t then t else
  if cursor >= 16 then error else
  let q := task cursor
  let n := get root q source 8224 t
  let count := load64 (source+16) n
  if n == error || n < 32 || count == 0 || count > 32 || load64 source n != 0x31464e4d544c || n < 32+count*128 then error else
  let r := one root (q+64) (q+64+load64 (q+32) n) count (q+3648) (q+3648+load64 (q+40) n) n
  if r == error then error else tasks root (cursor+1) r
def check (root sourceId manifest bytes t : UInt64) : UInt64 :=
  if bytes == 0 || bytes > 49152 then error else
  let end_ := manifest+bytes
  let dep := Guest.ReleaseClaims.field manifest end_ 13 t
  let sdk := Guest.ReleaseClaims.field manifest end_ 12 t
  if dep == 0 || sdk == 0 || load8 dep t != 91 then error else
  if load8 (dep+1) t == 93 then t else
  let r := enqueue sourceId (dep+1) end_ sdk end_ (store64 state 0 t)
  if r == error then error else tasks root 0 r
end Guest.SourceDependencyPolicy
