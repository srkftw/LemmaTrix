import Guest.ProjectSDK
import Guest.ContentFormat
namespace Guest.LibraryGraphServe
open Guest.LiveSDK
-- Four-KiB private table per approved LibraryPeer scope. Node handles remain
-- local and are never placed in any remote reply. The table is not an index
-- of unrelated Objects and no provider-supplied ordinal is a capability.
def table (scope : UInt64) : UInt64 := 0x620000+scope*4096
def node (scope ordinal : UInt64) : UInt64 := table scope+128+ordinal*160
partial def enumerate (scope root cursor ordinal bytes t : UInt64) : UInt64 :=
  if ordinal > 24 || bytes > 1048576 then error else
  let r := Guest.ProjectSDK.closure root cursor t
  if r < 64 || status r != 0 then error else
  if result r == 0 then
    if ordinal == 0 then error else
    let t := store64 (table scope) ordinal r
    store64 (table scope+8) bytes t
  else if ordinal == 24 || r != 128 || load64 (wire+24) r <= cursor ||
    load64 (wire+16) r > 1048576-bytes then error else
    let p := node scope ordinal
    let handle := result r
    let next := load64 (wire+24) r
    let length := load64 (wire+16) r
    let t := store64 p (load64 (wire+32) r) r
    let t := store64 (p+8) (load64 (wire+40) t) t
    let t := store64 (p+16) length t
    let t := copy (wire+64) (p+32) 64 t
    let t := store64 (p+128) handle t
    let r := metadata handle t
    if r != 96 || status r != 0 || load64 (wire+16) r != length ||
      load64 (wire+32) r != load64 p r then error else
    enumerate scope root next (ordinal+1) (bytes+length) (copy (wire+64) (p+96) 32 r)
def prepare (scope root expected t : UInt64) : UInt64 :=
  if scope >= 16 then error else
  let t := zero (table scope) 512 t
  let r := Guest.ProjectSDK.describeRoot root t
  if r != 160 || status r != 0 || !Guest.ContentFormat.equal (wire+64) expected 32 r then error else
  let length := load64 (wire+16) r
  if length == 0 || length > 63 then error else
  let t := store64 (table scope+16) root r
  let t := store64 (table scope+24) length t
  let t := copy expected (table scope+32) 32 t
  let t := copy (wire+96) (table scope+64) 64 t
  enumerate scope root 0 0 0 t
def current (scope t : UInt64) : Bool :=
  let r := Guest.ProjectSDK.describeRoot (load64 (table scope+16) t) t
  r == 160 && status r == 0 && Guest.ContentFormat.equal (wire+64) (table scope+32) 32 r
-- Returns selected payload bytes in wire+64 and outer total/value in scratch
-- table+3968/+3976. Codes/lengths remain local scalar results, never handles.
def answer (scope op ordinal offset count t : UInt64) : UInt64 :=
  if scope >= 16 then error else
  let s := table scope
  let r := Guest.ProjectSDK.describeRoot (load64 (s+16) t) t
  if r != 160 || status r != 0 || !Guest.ContentFormat.equal (wire+64) (s+32) 32 r then
    Guest.Effects.effectValue error (store64 (s+3984) 3 r) else
  let t := store64 (s+3984) 0 r
  let t := zero (wire+64) 80 t
  if op == 7 then
    let t := store64 (wire+72) (load64 (s+24) t) t
    let t := copy (s+32) (wire+80) 32 t
    let t := copy (s+64) (wire+112) 64 t
    let t := store64 (s+3968) (load64 s t) t
    128+store64 (s+3976) (load64 (s+8) t) t
  else if ordinal >= load64 s t then Guest.Effects.effectValue error (store64 (s+3984) 2 t) else
  let p := node scope ordinal
  if op == 8 then
    let t := copy p (wire+64) 128 t
    let t := store64 (s+3968) (load64 (p+16) t) t
    128+store64 (s+3976) ordinal t
  else if op == 9 then
    let length := load64 (p+16) t
    if count == 0 || count > 512 || offset > length || count > length-offset then error else
    let r := read (load64 (p+128) t) offset count t
    if r != 64+count || status r != 0 || result r != count then error else
    let t := store64 (s+3968) length r
    count+store64 (s+3976) ordinal t
  else error
end Guest.LibraryGraphServe
