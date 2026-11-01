import Guest.PrivateRecords
namespace Guest.FeedRecords
open Guest.LiveSDK
-- One explicitly selected account record inside Objects domain3. Its extent
-- follows the separate Messenger domain2; only the unlocked Vault owns keys.
-- No session handle, signing grant or seed belongs in this typed record.
def base : UInt64 := 0x800000
def state : UInt64 := base
def head : UInt64 := base+512
def other : UInt64 := base+1024
def plain : UInt64 := base+4096
def cipher : UInt64 := base+40960
def scratch : UInt64 := base+77824
def hashed : UInt64 := base+79872
def derived : UInt64 := base+79936
def magic : UInt64 := 0x315243455246544c
def accountMagic : UInt64 := 0x315443434146544c
def firstSector : UInt64 := 5396000
def sectorCount : UInt64 := 132
def clear (t : UInt64) : UInt64 := zero base 10240 t
def response (code value generation t : UInt64) : UInt64 :=
  64+header code value generation 3 0 0 0 t
def fail (code t : UInt64) : UInt64 := response code 0 0 t
def eq (a b n t : UInt64) : Bool := Guest.PrivateRecords.equal a b n t
def disk (op sector p bytes t : UInt64) : UInt64 := Guest.PrivateRecords.disk op sector p bytes t
partial def transfer (op sector p bytes t : UInt64) : UInt64 :=
  if bytes == 0 then t else
  let n := if bytes > 4096 then 4096 else bytes
  let r := disk op sector p n t
  if r == error then error else transfer op (sector+n/512) (p+n) (bytes-n) r
def bankSector (generation : UInt64) : UInt64 := firstSector+2+(generation%2)*65
def authorized (caller t : UInt64) : Bool :=
  caller != 0 && syscall 147 0 0 0 3 t == caller && load64 0x620000 t == 1
def backingAllowed (capacity : UInt64) : Bool := capacity != error && capacity >= firstSector+sectorCount
theorem record_banks_fit_extent : (2 : UInt64)+2*65 = sectorCount := by decide
theorem record_extent_follows_domain2 : firstSector = (5394976 : UInt64)+1024 := by decide
def ready (t : UInt64) : UInt64 :=
  let capacity := syscall 64 1 0 0 0 t
  if !backingAllowed capacity then error else
  let r := Guest.PrivateRecords.ready capacity
  if r == error then error else
  let t := copy Guest.PrivateRecords.key scratch 32 r
  let t := store64 (scratch+32) magic t
  Guest.ServiceHash.sha256At (scratch+256) scratch 40 derived t
def validRoot (p t : UInt64) : Bool :=
  load64 p t == magic && load64 (p+8) t == 1 && load64 (p+16) t == 3 &&
  load64 (p+24) t > 0 && load64 (p+32) t >= 256 && load64 (p+32) t <= 32768 &&
  Guest.PrivateRecords.empty (p+52) 12 t && Guest.PrivateRecords.empty (p+96) 416 t
def openRoot (p t : UInt64) : UInt64 :=
  if !validRoot p t then error else
  let n := load64 (p+32) t
  let r := transfer 60 (bankSector (load64 (p+24) t)) cipher ((n+16+511)/512*512) t
  if r == error then error else
  let t := Guest.ServiceHash.sha256At scratch cipher (n+16) hashed r
  if !eq hashed (p+64) 32 t then error else
  let r := Guest.VaultCrypto.decrypt derived (p+40) p 64 cipher n plain t
  if r == error || load64 plain r != accountMagic || load64 (plain+8) r != 1 then error else r
def scan (t : UInt64) : UInt64 :=
  let a := disk 60 firstSector head 512 t
  let b := if a == error then error else disk 60 (firstSector+1) other 512 a
  if b == error then error else
  let high := if load64 (head+24) b >= load64 (other+24) b then head else other
  let low := if high == head then other else head
  let r := openRoot high b
  if r != error then copy high head 512 r else
  let r := openRoot low b
  if r == error then error else copy low head 512 r
def begin (caller length t : UInt64) : UInt64 :=
  let n := load64 (command+16) t
  if length != 96 || n < 256 || n > 32768 then fail 2 t else
  if load64 state t != 0 then fail 7 t else
  -- Do not replace a malformed nonempty root as though it were a new record.
  let old := scan t
  if old == error && (!Guest.PrivateRecords.empty head 512 old || !Guest.PrivateRecords.empty other 512 old) then fail 9 old else
  let generation := if old == error then 1 else load64 (head+24) old+1
  if generation == 0 then fail 4 old else
  let t := zero plain 4096 old
  let t := store64 state caller t
  let t := store64 (state+8) n t
  let t := store64 (state+16) 0 t
  let t := store64 (state+24) generation t
  response 0 n generation (copy (command+64) (state+64) 32 t)
def commit (caller t : UInt64) : UInt64 :=
  let n := load64 (state+8) t
  if load64 state t != caller || load64 (state+16) t != n || n < 256 then fail 3 t else
  let t := Guest.ServiceHash.sha256At scratch plain n hashed t
  if !eq hashed (state+64) 32 t || load64 plain t != accountMagic || load64 (plain+8) t != 1 then fail 9 t else
  let generation := load64 (state+24) t
  let t := zero head 64 t
  let t := store64 head magic t
  let t := store64 (head+8) 1 t
  let t := store64 (head+16) 3 t
  let t := store64 (head+24) generation t
  let t := store64 (head+32) n t
  let r := Guest.PrivateRecords.reserveNonce t
  if r == error then fail 9 r else
  let t := copy (Guest.PrivateRecords.head+40) (head+40) 12 r
  let r := Guest.VaultCrypto.encrypt derived (head+40) head 64 plain n cipher t
  if r == error then fail 9 r else
  let bytes := (n+16+511)/512*512
  let t := Guest.VaultCrypto.clear (cipher+n+16) ((bytes-n-16+7)/8) r
  let t := Guest.ServiceHash.sha256At scratch cipher (n+16) (head+64) t
  let a := transfer 61 (bankSector generation) cipher bytes t
  let a := if a == error then error else syscall 62 0 0 0 0 a
  if a != 0 then fail 8 a else
  let b := disk 61 (firstSector+generation%2) head 512 a
  let b := if b == error then error else syscall 62 0 0 0 0 b
  if b != 0 then fail 8 b else response 0 n generation (clear b)
def dispatch (caller length t : UInt64) : UInt64 :=
  if !authorized caller t then fail 1 t else
  let r := ready t
  if r == error then fail 8 r else
  let op := load64 command r
  let action := load64 (command+8) r
  if op == 277 then
    if action == 0 then begin caller length r else
    if action == 1 then
      let offset := load64 (command+16) r
      let n := length-64
      let total := load64 (state+8) r
      if load64 state r != caller || length <= 64 || length > 576 || offset != load64 (state+16) r ||
        offset > total || n > total-offset then fail 3 r else
      response 0 (offset+n) (load64 (state+24) r)
        (store64 (state+16) (offset+n) (copy (command+64) (plain+offset) n r))
    else if action == 2 && length == 64 then commit caller r else
    if action == 4 && length == 64 then response 0 0 0 (clear (syscall 147 caller 0 0 3 r)) else
    if action == 3 && length == 64 then response 0 0 0 (clear r) else fail 2 r
  else if op == 278 && length == 64 then
    if load64 state r != 0 then fail 7 r else
    if action == 0 then
      let r := scan r
      if r == error then fail 6 (clear r) else
      let n := load64 (head+32) r
      let generation := load64 (head+24) r
      -- Read cache is tied to this exact live owner and cleared on lock.
      response 0 n generation (store64 (state+40) caller (store64 (state+48) n r))
    else if action == 1 then
      let offset := load64 (command+16) r
      let n := load64 (command+24) r
      let total := load64 (state+48) r
      if load64 (state+40) r != caller || n == 0 || n > 512 || offset > total || n > total-offset then fail 3 r else
      64+n+copy (plain+offset) (wire+64) n (header 0 n total 3 0 0 0 r)
    else fail 2 r
  else if op == 279 && length == 64 then
    let t := zero head 64 r
    let a := disk 61 firstSector head 512 t
    let b := if a == error then error else disk 61 (firstSector+1) head 512 a
    let f := if b == error then error else syscall 62 0 0 0 0 b
    response (if f == 0 then 0 else 8) 0 0 (clear (syscall 147 caller 0 0 3 f))
  else fail 2 r
end Guest.FeedRecords
