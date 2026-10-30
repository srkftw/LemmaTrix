import Guest.ContentFormat
namespace Guest.LibraryCollections
open Guest.LiveSDK
-- Eight private policies; catalog pages and payloads never live in these rows.
-- A job copies its policy before starting and checks only its own generation.
def base : UInt64 := 0x724000
def count : UInt64 := 8
def record (i : UInt64) : UInt64 := base+i*512
partial def find (collection federation i t : UInt64) : UInt64 :=
  if i == count then error else
  let p := record i
  if load64 p t == 1 && ContentFormat.equal (p+160) collection 32 t &&
    ContentFormat.equal (p+192) federation 32 t then i else find collection federation (i+1) t
partial def vacant (i t : UInt64) : UInt64 :=
  if i == count then error else if load64 (record i) t == 0 then i else vacant (i+1) t
@[noinline] def select (collection federation t : UInt64) : UInt64 :=
  let old := find collection federation 0 t
  let i := if old == error then vacant 0 t else old
  if i == error then error else
  let p := record i
  let t := if old != error then t else
    let t := zero p 64 t
    let t := store64 p 1 t
    let t := store64 (p+8) 1 t
    let t := store64 (p+32) 1 t
    let t := store64 (p+40) 6 t
    let t := store64 (p+48) 6029312 t
    let t := store64 (p+64) 6 t
    let t := store64 (p+72) 3 t
    let t := store64 (p+80) 2 t
    let t := store64 (p+104) 3 t
    let t := copy collection (p+160) 32 t
    copy federation (p+192) 32 t
  i+store64 (p+152) 0 t
-- Callers pass a valid index; updates keep already consumed/reserved bytes.
-- Renewing a generation is explicit and affects future operations only.
@[noinline] def approve (i budget providers retention t : UInt64) : UInt64 :=
  let p := record i
  if i >= count || load64 p t != 1 || budget == 0 || budget > ContentFormat.maxBytes ||
    providers == 0 || (providers &&& 6) != providers || retention > 1 || load64 (p+8) t == error then error else
  let t := store64 (p+8) (load64 (p+8) t+1) t
  let t := store64 (p+16) 1 t
  let t := store64 (p+24) 1 t
  let t := store64 (p+48) budget t
  let t := store64 (p+64) providers t
  let t := store64 (p+88) retention t
  store64 (p+96) 0 t
@[noinline] def revoke (i t : UInt64) : UInt64 :=
  if i >= count || load64 (record i) t != 1 then error else
  let p := record i
  let t := store64 (p+8) (load64 (p+8) t+1) t
  store64 (p+24) 0 t
@[noinline] def allowed (i consumer bytes t : UInt64) : Bool :=
  if i >= count then false else
  let p := record i
  load64 p t == 1 && load64 (p+24) t == 1 && load64 (p+96) t == 0 &&
  load64 (p+72) t == 3 && load64 (consumer+24) t == load64 (p+32) t &&
  ((load64 (p+40) t >>> load64 (consumer+448) t) &&& 1) == 1 &&
  bytes <= load64 (p+48) t && load64 (p+56) t <= load64 (p+48) t-bytes
@[noinline] def recovered (i t : UInt64) : UInt64 :=
  -- Recovery never turns saved consent into live acquisition authority. The
  -- user must explicitly renew; completed offline content stays readable.
  let p := record i
  if i >= count || load64 p t != 1 then t else
  let t := store64 (p+24) 0 t
  store64 (p+96) 1 t
end Guest.LibraryCollections
