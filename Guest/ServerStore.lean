import Guest.LiveSDK
import Guest.ServiceHash
import Guest.ProjectGraph
namespace Guest.ServerStore
open Guest.LiveSDK
-- Intentional unencrypted server retention; no personal-vault unlock or key is
-- reused. The block broker selects purpose2 by its explicit device binding.
def st : UInt64 := 0x730000
def rows : UInt64 := 0x731000
def grants : UInt64 := 0x733000
def txn : UInt64 := 0x734000
def page : UInt64 := 0x735000
def indices : UInt64 := 0x737000
def header : UInt64 := 0x739000
def other : UInt64 := 0x739200
def scratch : UInt64 := 0x73a000
def running : UInt64 := 0x73b000
def hashed : UInt64 := 0x73c000
def magic : UInt64 := 0x3152565253544c
def formatMagic : UInt64 := 0x31524f5453544c
def row (i : UInt64) : UInt64 := rows+i*512
def grant (i : UInt64) : UInt64 := grants+i*128
def bankSector (slot generation : UInt64) : UInt64 := 64+slot*4128+(generation%2)*2064
def io (op sector ptr bytes t : UInt64) : UInt64 := syscall op sector ptr bytes 2 t
def disk (op sector ptr bytes t : UInt64) : UInt64 :=
  let t := if op == 66 then copy ptr chunk bytes t else t
  let r := io op sector chunk bytes t
  if r != 0 then error else if op == 65 then copy chunk ptr bytes r else r
def flush (t : UInt64) : UInt64 := syscall 67 2 0 0 0 t
def eq (a b n t : UInt64) : Bool := Guest.ProjectGraph.equal a b n t
def response (code value t : UInt64) : UInt64 :=
  let t := zero wire 8 t
  let t := store64 wire code t
  let t := store64 (wire+8) value t
  let t := store64 (wire+16) (load64 (txn+24) t) t
  let t := store64 (wire+24) (load64 (txn+16) t) t
  let t := store64 (wire+32) (load64 st t) t
  let t := store64 (wire+48) 1 t
  64+store64 (wire+56) (load64 (st+8) t) t
def initialized (t : UInt64) : Bool := load64 st t == 1

def rootValid (p slot t : UInt64) : Bool :=
  if load64 p t != magic || load64 (p+8) t != 1 || load64 (p+16) t != slot ||
     load64 (p+24) t == 0 || load64 (p+32) t == 0 || load64 (p+32) t > 1048576 ||
     load64 (p+40) t == 0 || load64 (p+40) t > 4 ||
     !Guest.ProjectGraph.allZero (p+176) 336 t then false else
    let t := ServiceHash.sha256At scratch p 144 hashed t
    eq hashed (p+144) 32 t
partial def indexIO (op sector p left t : UInt64) : UInt64 :=
  if left == 0 then t else
    let r := disk op sector p 4096 t
    if r == error then error else indexIO op (sector+8) (p+4096) (left-4096) r
def loadIndex (p t : UInt64) : UInt64 :=
  let sector := bankSector (load64 (p+16) t) (load64 (p+24) t)+2048
  let r := indexIO 65 sector indices 8192 t
  if r == error then error else
    let t := ServiceHash.sha256At scratch indices 8192 hashed r
    if eq hashed (p+112) 32 t then t else error
def inspectRoot (p slot t : UInt64) : UInt64 :=
  if !rootValid p slot t then error else loadIndex p t
partial def scan (i t : UInt64) : UInt64 :=
  if i == 8 then t else
    let a := disk 65 (8+i*2) header 512 t
    if a == error then error else
    let b := disk 65 (9+i*2) other 512 a
    if b == error then error else
    let high := if load64 (header+24) b >= load64 (other+24) b then header else other
    let low := if high == header then other else header
    let checked := inspectRoot high i b
    let selected := if checked != error then high else low
    let checked := if checked != error then checked else inspectRoot low i b
    if checked != error then scan (i+1) (copy selected (row i) 512 checked) else
      if Guest.ProjectGraph.allZero header 512 b && Guest.ProjectGraph.allZero other 512 b then scan (i+1) (zero (row i) 64 b) else error
def mount (t : UInt64) : UInt64 :=
  if load64 (txn+8) t != 0 then response 7 0 t else
  let cap := syscall 64 2 0 0 0 t
  if cap < 33088 || cap == error then response 6 0 cap else
  let r := disk 65 0 header 512 cap
  if r == error || load64 header r != formatMagic || load64 (header+8) r != 1 ||
      load64 (header+16) r != 33088 || !Guest.ProjectGraph.allZero (header+24) 488 r then response 6 0 r else
    let r := scan 0 r
    if r == error then response 5 0 r else response 0 8 (store64 st 1 r)

partial def locate (ns i t : UInt64) : UInt64 :=
  if i == 8 then error else
    if load64 (row i) t == magic && eq ns (row i+48) 32 t then i else locate ns (i+1) t
partial def vacant (i t : UInt64) : UInt64 :=
  if i == 8 then error else if load64 (row i) t == 0 && load64 (grant i) t == 0 then i else vacant (i+1) t
def permit (length t : UInt64) : UInt64 :=
  let target := load64 (command+8) t
  let role := load64 (command+16) t
  let quota := load64 (command+24) t
  let actual := syscall 34 target 0 0 0 t
  if length != 96 || actual == error || (actual &&& 0x100000800) == 0 || role == 0 || role > 4 ||
      quota == 0 || quota > 1048576 || Guest.ProjectGraph.allZero (command+64) 32 actual then response 1 0 actual else
    let found := locate (command+64) 0 actual
    let slot := if found == error then vacant 0 actual else found
    if slot == error || (load64 (txn+8) actual != 0 && load64 (txn+32) actual == slot) then response 4 0 actual else
      let g := grant slot
      let generation := load64 (st+8) actual+1
      if generation == 0 || generation > 0xffffff then response 4 0 actual else
      -- Grants are session authority, never durable store identities. Include
      -- this service incarnation so restarting it cannot recycle an old handle
      -- for a still-running caller and a different namespace.
      let serviceInstance := self actual
      let epoch := ((serviceInstance >>> 32)+((serviceInstance >>> 8) &&& 0xffffff)) &&& 0xffffffff
      let handle := (epoch <<< 32) ||| (generation <<< 8) ||| (slot+1)
      let t := zero g 16 serviceInstance
      let t := store64 (st+8) generation t
      let t := store64 g handle t
      let t := store64 (g+8) target t
      let t := store64 (g+16) role t
      let t := store64 (g+24) quota t
      let t := copy (command+64) (g+32) 32 t
      response 0 (load64 g t) t
def authorized (caller h t : UInt64) : UInt64 :=
  let slot := (h &&& 255)-1
  if slot >= 8 || load64 (grant slot) t != h || load64 (grant slot+8) t != caller then error else slot
def abandon (t : UInt64) : UInt64 :=
  let t := zero txn 64 t
  let t := zero page 512 t
  let t := zero indices 1024 t
  zero running 128 t

def begin (caller h total length t : UInt64) : UInt64 :=
  let slot := authorized caller h t
  if slot == error || length != 96 || total == 0 || total > load64 (grant slot+24) t then response 1 0 t else
  if load64 (txn+8) t != 0 then response 7 0 t else
    let generation := load64 (row slot+24) t+1
    if generation == 0 then response 4 0 t else
    let t := abandon t
    let t := store64 txn caller t
    let t := store64 (txn+8) h t
    let t := store64 (txn+16) total t
    let t := store64 (txn+32) slot t
    let t := store64 (txn+40) generation t
    let t := copy (command+64) (txn+64) 32 t
    let t := ServiceHash.initialState running t
    response 0 h t
def feedPage (count t : UInt64) : UInt64 := ServiceHash.blocks running page count count 0 (count/64) t
def writePage (count t : UInt64) : UInt64 :=
  let offset := load64 (txn+24) t-count
  let sector := bankSector (load64 (txn+32) t) (load64 (txn+40) t)+offset/512
  let t := ServiceHash.sha256At scratch page 4096 hashed t
  let t := copy hashed (indices+offset/4096*32) 32 t
  disk 66 sector page 4096 t
def append (caller h offset length t : UInt64) : UInt64 :=
  let total := load64 (txn+16) t
  let count := length-64
  if load64 txn t != caller || load64 (txn+8) t != h || h == 0 ||
      length <= 64 || length > 576 || offset != load64 (txn+24) t || offset > total || count > total-offset ||
      (count != 512 && count != total-offset) then response 2 0 t else
    let t := copy (command+64) (page+offset%4096) count t
    let t := store64 (txn+24) (offset+count) t
    let full := (offset+count)%4096 == 0
    let t := if full then feedPage 4096 t else t
    let r := if full then writePage 4096 t else t
    if r == error then response 6 0 (abandon r) else
      let t := if full then zero page 512 r else r
      response 0 (offset+count) t

partial def bigEndianLength (p n left t : UInt64) : UInt64 :=
  if left == 0 then t else bigEndianLength (p+1) n (left-1) (store8 p ((n >>> ((left-1)*8)) &&& 255) t)
def finishHash (total t : UInt64) : UInt64 :=
  let tail := total%4096
  let whole := tail/64*64
  let t := if whole == 0 then t else ServiceHash.blocks running page tail tail 0 (whole/64) t
  let n := tail%64
  let t := copy (page+whole) hashed n t
  let t := zero page 16 t
  let t := copy hashed page n t
  let t := store8 (page+n) 128 t
  let bytes := if n < 56 then 64 else 128
  let t := bigEndianLength (page+bytes-8) (total*8) 8 t
  let t := ServiceHash.blocks running page bytes bytes 0 (bytes/64) t
  ServiceHash.outputBytes running hashed 0 t
def committed (allBytes flushed : Bool) : Bool := allBytes && flushed
theorem incomplete_never_commits (flushed : Bool) : committed false flushed = false := by cases flushed <;> decide
def commit (caller h t : UInt64) : UInt64 :=
  let total := load64 (txn+16) t
  if load64 txn t != caller || load64 (txn+8) t != h || h == 0 || !committed (total == load64 (txn+24) t) true then response 2 0 t else
    let tail := total%4096
    let r := if tail == 0 then t else writePage tail t
    if r == error then response 6 0 (abandon r) else
    let t := finishHash total r
    if !eq hashed (txn+64) 32 t then response 5 0 (abandon t) else
    let slot := load64 (txn+32) t
    let generation := load64 (txn+40) t
    let t := zero header 64 t
    let t := store64 header magic t
    let t := store64 (header+8) 1 t
    let t := store64 (header+16) slot t
    let t := store64 (header+24) generation t
    let t := store64 (header+32) total t
    let t := store64 (header+40) (load64 (grant slot+16) t) t
    let t := copy (grant slot+32) (header+48) 32 t
    let t := copy hashed (header+80) 32 t
    let t := ServiceHash.sha256At scratch indices 8192 hashed t
    let t := copy hashed (header+112) 32 t
    let t := ServiceHash.sha256At scratch header 144 hashed t
    let t := copy hashed (header+144) 32 t
    let r := indexIO 66 (bankSector slot generation+2048) indices 8192 t
    let r := if r == error then error else flush r
    if r == error then response 6 0 (abandon r) else
    let r := disk 66 (8+slot*2+generation%2) header 512 r
    let r := if r == error then error else flush r
    if r != 0 then response 6 0 (abandon r) else
      let t := copy header (row slot) 512 r
      response 0 generation (abandon t)

def describe (caller h t : UInt64) : UInt64 :=
  let slot := authorized caller h t
  if slot == error then response 1 0 t else
    let t := response 0 h t
    64+512+copy (row slot) (wire+64) 512 t
def read (caller h offset count t : UInt64) : UInt64 :=
  let slot := authorized caller h t
  if slot == error || count == 0 || count > 512 then response 1 0 t else
    let p := row slot
    let total := load64 (p+32) t
    if load64 p t != magic || offset >= total || count > total-offset || offset%4096+count > 4096 then response 2 0 t else
      let r := loadIndex p t
      if r == error then response 5 0 r else
      let sector := bankSector slot (load64 (p+24) r)+(offset/4096)*8
      let r := disk 65 sector page 4096 r
      if r == error then response 6 0 r else
      let t := ServiceHash.sha256At scratch page 4096 hashed r
      if !eq hashed (indices+offset/4096*32) 32 t then response 5 0 t else
        let t := response 0 count t
        64+count+copy (page+offset%4096) (wire+64) count t

def dispatch (caller rights length t : UInt64) : UInt64 :=
  let owner := load64 txn t
  let alive := if owner == 0 then 0 else syscall 34 owner 0 0 0 t
  let t := if owner != 0 && alive == error then abandon alive else alive
  let op := load64 command t
  let h := load64 (command+8) t
  let admin := (rights &&& 0x100000000) != 0
  if length < 64 || load64 (command+56) t != 1 then response 2 0 t else
  if op == 230 && admin && length == 64 then mount t else
  if !initialized t then response 3 0 t else
  if op == 231 && admin then permit length t else
  if op == 239 && admin && length == 64 then
    let slot := (h &&& 255)-1
    if slot >= 8 || load64 (grant slot) t != h then response 1 0 t else
      let t := if load64 (txn+8) t == h then abandon t else t
      response 0 h (zero (grant slot) 16 t)
  else if (rights &&& 2048) == 0 && !admin then response 1 0 t else
  if op == 232 then begin caller h (load64 (command+16) t) length t else
  if op == 233 then append caller h (load64 (command+16) t) length t else
  if op == 234 && length == 64 then commit caller h t else
  if op == 235 && length == 64 then
    if load64 txn t != caller || load64 (txn+8) t != h then response 1 0 t else response 0 h (abandon t)
  else if op == 236 && length == 64 then describe caller h t else
  if op == 237 && length == 64 then read caller h (load64 (command+16) t) (load64 (command+24) t) t else
  if op == 238 && length == 64 then
    if authorized caller h t == error then response 1 0 t else response 0 h t
  else response 2 0 t
end Guest.ServerStore
