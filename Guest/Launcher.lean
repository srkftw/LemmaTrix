import Guest.LiveMemory
import Guest.ServiceSHA256
import Guest.ServiceSignature
namespace Guest.Launcher
open Guest.LiveMemory
@[never_extract, extern "lt_effect_value"] opaque keep : UInt64 → UInt64 → UInt64
def control : UInt64 := 0x630000
def stage : UInt64 := 0x700000
def catalog (i : UInt64) : UInt64 := 0x640000+i*1024
def project (i : UInt64) : UInt64 := 0x660000+i*128
def trust (i : UInt64) : UInt64 := 0x620000+i*384
def hash (src len out t : UInt64) : UInt64 := Guest.ServiceHash.sha256At 0x600200 src len out t


def respond (rid status src len t : UInt64) : UInt64 :=
  let out := 0x416000
  let t := zero out 132 t
  let t := Guest.store64 out (0x0032524c+status*0x100000000) t
  let t := Guest.store64 (out+8) rid t
  let t := Guest.store64 (out+16) len t
  let t := copy src (out+32) len t
  let result := Guest.syscall 41 0 out (len+32) 0 t
  if rid > Guest.load64 (control+528) result && status < 2 then
    let t := zero 0x632000 132 result
    let t := copy out 0x632000 (len+32) t
    let t := Guest.store64 (control+536) (len+32) t
    Guest.store64 (control+528) rid t
  else keep 0 result

def result (value t : UInt64) : UInt64 :=
  let t := zero buf 8 t
  let t := Guest.store64 buf 0 t
  let t := Guest.store64 (buf+8) value t
  keep 64 t
partial def findTrust (projectId publisher i t : UInt64) : UInt64 :=
  if i == 16 then 0 else
    let r := trust i
    if Guest.load64 r t == 1 && equal (r+8) projectId 32 t && equal (r+296) publisher 32 t then i+1 else findTrust projectId publisher (i+1) t
partial def freeTrust (i t : UInt64) : UInt64 :=
  if i == 16 then 0 else if Guest.load64 (trust i) t == 0 then i+1 else freeTrust (i+1) t
partial def nameValid (i n t : UInt64) : Bool :=
  if i == n then true else
    let c := Guest.load8 (stage+432+i) t
    ((c >= 97 && c <= 122) || (c >= 48 && c <= 57) || (i > 0 && (c == 45 || c == 46 || c == 95))) && nameValid (i+1) n t
partial def paddingZero (p n t : UInt64) : Bool :=
  if n == 0 then true else Guest.load8 p t == 0 && paddingZero (p+1) (n-1) t

def validate (t : UInt64) : Bool :=
  let size := Guest.load64 (stage+24) t
  let n := Guest.load64 (stage+424) t
  if Guest.load64 stage t != 0x3253454c544c || Guest.load64 (stage+8) t != 2 || Guest.load64 (stage+16) t != 512 ||
     size == 0 || size > (if Guest.load64 (stage+400) t == 2 then 262144 else 65536) || size%4 != 0 || Guest.load64 (control+256) t != size+768 ||
     Guest.load64 (stage+32) t != (if Guest.load64 (stage+400) t == 2 then 0x200000 else 0x400000) || Guest.load64 (stage+40) t != 2 || Guest.load64 (stage+48) t != 2 || Guest.load64 (stage+56) t != 2 ||
     Guest.load64 (stage+64) t > 4095 || Guest.load64 (stage+72) t > 0xffffffff || Guest.load64 (stage+80) t > 0xffffffff || Guest.load64 (stage+88) t > 0xffffffff ||
     Guest.load64 (stage+384) t != 0 || Guest.load64 (stage+392) t != 0 || (Guest.load64 (stage+400) t != 1 && Guest.load64 (stage+400) t != 2) ||
     Guest.load64 (stage+408) t != 65536+(if Guest.load64 (stage+400) t == 2 then 2097152 else 0) || Guest.load64 (stage+416) t != 16384 || n == 0 || n > 48 || !nameValid 0 n t ||
     !paddingZero (stage+432+n) (48-n) t || Guest.load64 (stage+480) t != 65537 ||
     (Guest.load64 (stage+488) t != 0 && Guest.load64 (stage+488) t != 3) || !paddingZero (stage+496) 16 t then false else
    let key := findTrust (stage+128) (stage+96) 0 t
    if key == 0 then false else
      let t := hash (stage+432) n (control+64) t
      if Guest.load64 (stage+488) t == 0 && !equal (control+64) (stage+128) 32 t then false else
        let t := hash (stage+768) size (control+64) t
        if !equal (control+64) (stage+192) 32 t then false else
          let t := copy (stage+160) (control+96) 32 t
          let t := zero (stage+160) 4 t
          let t := hash stage 512 (control+64) t
          let t := copy (control+96) (stage+160) 32 t
          if !equal (control+64) (stage+160) 32 t then false else
            Guest.ServiceSignature.verify stage 512 (stage+512) (trust (key-1)+40) t

partial def findProject (id i t : UInt64) : UInt64 :=
  if i == 8 then 0 else if Guest.load64 (project i) t == 1 && equal id (project i+8) 32 t then i+1 else findProject id (i+1) t
partial def freeProject (i t : UInt64) : UInt64 :=
  if i == 8 then 0 else if Guest.load64 (project i) t == 0 then i+1 else freeProject (i+1) t
partial def freeRelease (i t : UInt64) : UInt64 :=
  if i == 16 then 0 else if Guest.load64 (catalog i+768) t == 0 then i+1 else freeRelease (i+1) t

def launchable (index t : UInt64) : Bool :=
  if index == 0 || index > 16 then false else
    let r := catalog (index-1)
    Guest.load64 (r+768) t == 1 && Guest.load64 (r+776) t == 0 &&
      findTrust (r+128) (r+96) 0 t != 0

def newer (candidate old t : UInt64) : Bool :=
  let a := Guest.load64 (candidate+72) t
  let b := Guest.load64 (old+72) t
  if a != b then a > b else
    let a := Guest.load64 (candidate+80) t
    let b := Guest.load64 (old+80) t
    if a != b then a > b else Guest.load64 (candidate+88) t > Guest.load64 (old+88) t
partial def uploadCode (slot length offset t : UInt64) : UInt64 :=
  if offset == length then Guest.syscall 54 slot 0 0 0 t else
    let count := if length-offset > 1024 then 1024 else length-offset
    let t := copy (stage+768+offset) 0x410000 count t
    let status := Guest.syscall 53 slot 0x410000 count offset t
    if status == err then err else uploadCode slot length (offset+count) status

def install (t : UInt64) : UInt64 :=
  if Guest.load64 (control+272) t != 1 || Guest.load64 (control+288) t != 1 || !equal (control+128) (stage+160) 32 t || Guest.load64 (control+160) t != Guest.load64 (stage+64) t || !validate t then err else
    let known := findProject (stage+128) 0 t
    let pi := if known == 0 then freeProject 0 t else known
    let free := freeRelease 0 t
    if pi == 0 || free == 0 then err else
      let pr := project (pi-1)
      let active := Guest.load64 (pr+72) t
      if known != 0 && (!equal (pr+40) (stage+96) 32 t || active == 0 || !equal (stage+288) (catalog (active-1)+160) 32 t || !newer stage (catalog (active-1)) t) then err else
        let slot := free-1
        let size := Guest.load64 (stage+24) t
        let t := zero buf 8 t
        let t := Guest.store64 buf size t
        let t := Guest.store64 (buf+8) (Guest.load64 (stage+64) t) t
        let t := Guest.store64 (buf+16) (Guest.load64 (stage+32) t) t
        let t := Guest.store64 (buf+24) (Guest.load64 (stage+400) t) t
        let status := Guest.syscall 52 slot buf 64 0 t
        if status == err then err else
          let status := uploadCode slot size 0 status
          if status == err then err else
            let t := copy stage (catalog slot) 768 status
            let t := Guest.store64 (catalog slot+768) 1 t
            let t := Guest.store64 pr 1 t
            let t := copy (stage+128) (pr+8) 32 t
            let t := copy (stage+96) (pr+40) 32 t
            let t := Guest.store64 (pr+80) active t
            let t := Guest.store64 (pr+72) free t
            let t := Guest.store64 (pr+88) (Guest.load64 (pr+88) t+1) t
            let t := Guest.store64 (control+288) 0 t
            result free t

partial def releaseById (id i t : UInt64) : UInt64 :=
  if i == 16 then 0 else
    if Guest.load64 (catalog i+768) t == 1 && equal id (catalog i+160) 32 t then i+1 else releaseById id (i+1) t
partial def referenced (slot i t : UInt64) : Bool :=
  if i == 8 then false else
    (Guest.load64 (project i) t == 1 && (Guest.load64 (project i+72) t == slot+1 || Guest.load64 (project i+80) t == slot+1)) || referenced slot (i+1) t
partial def collect (i count t : UInt64) : UInt64 :=
  if i == 16 then result count t else
    if Guest.load64 (catalog i+768) t == 1 && !referenced i 0 t then
      let status := Guest.syscall 55 i 0 0 0 t
      if status == 0 then collect (i+1) (count+1) (zero (catalog i) 128 status) else collect (i+1) count status
    else collect (i+1) count t
partial def revokeKey (id i count t : UInt64) : UInt64 :=
  if i == 16 then result count t else
    if Guest.load64 (trust i) t == 1 && equal id (trust i+296) 32 t then
      revokeKey id (i+1) (count+1) (Guest.store64 (trust i) 0 t)
    else revokeKey id (i+1) count t

def forward (endpoint length t : UInt64) : UInt64 := Guest.syscall 30 endpoint buf length 1024 t

def retain (h t : UInt64) : UInt64 :=
  let t := zero buf 8 t
  let t := Guest.store64 buf 5 t
  let t := Guest.store64 (buf+8) h t
  let t := Guest.store64 (buf+56) 1 t
  let metadata := forward 2 64 t
  if metadata != 96 || Guest.load64 buf metadata != 0 || (Guest.load64 (buf+48) metadata &&& 25) != 25 then err else
    let count := Guest.syscall 42 0 0x418000 384 0 metadata
    if count != 384 then err else
      let vault := Guest.load64 (0x418000+96) count
      let t := zero buf 8 count
      let t := Guest.store64 buf 6 t
      let t := Guest.store64 (buf+8) h t
      let t := Guest.store64 (buf+16) vault t
      let t := Guest.store64 (buf+24) 1 t
      let t := Guest.store64 (buf+56) 1 t
      let len := forward 2 64 t
      if len < 64 || len > 1024 || Guest.load64 buf len != 0 then err else
        let handle := Guest.load64 (buf+8) len
        let t := zero buf 8 len
        let t := Guest.store64 buf 203 t
        let t := Guest.store64 (buf+8) handle t
        let t := Guest.store64 (buf+16) 3 t
        let t := Guest.store64 (buf+56) 1 t
        let received := forward 3 64 t
        let t := zero 0x635000 128 received
        let t := if received >= 64 && received <= 1024 then copy buf 0x635000 received t else t
        let t := zero buf 8 t
        let t := Guest.store64 buf 7 t
        let t := Guest.store64 (buf+8) h t
        let t := Guest.store64 (buf+16) handle t
        let t := Guest.store64 (buf+56) 1 t
        let revoked := forward 2 64 t
        if revoked != 64 || Guest.load64 buf revoked != 0 || received < 64 || received > 1024 then
          keep err (zero 0x635000 128 revoked)
        else
          let t := copy 0x635000 buf received revoked
          keep received (zero 0x635000 128 t)

partial def restoreChunks (handle total offset t : UInt64) : UInt64 :=
  if offset == total then
    let t := zero buf 8 t
    let t := Guest.store64 buf 3 t
    let t := Guest.store64 (buf+8) handle t
    let t := Guest.store64 (buf+56) 1 t
    let t := copy (control+192) (buf+64) 32 t
    forward 2 96 t
  else
    let count := if total-offset > 512 then 512 else total-offset
    let t := zero buf 8 t
    let t := Guest.store64 buf 206 t
    let t := Guest.store64 (buf+16) 3 t
    let t := Guest.store64 (buf+24) offset t
    let t := Guest.store64 (buf+32) count t
    let t := Guest.store64 (buf+56) 1 t
    let got := forward 3 64 t
    if got != count+64 || Guest.load64 buf got != 0 then err else
      let t := zero buf 8 got
      let t := Guest.store64 buf 2 t
      let t := Guest.store64 (buf+8) handle t
      let t := Guest.store64 (buf+16) offset t
      let t := Guest.store64 (buf+56) 1 t
      let got := forward 2 (count+64) t
      if got != 64 || Guest.load64 buf got != 0 then err else restoreChunks handle total (offset+count) got

def recover (t : UInt64) : UInt64 :=
  let t := zero buf 8 t
  let t := Guest.store64 buf 204 t
  let t := Guest.store64 (buf+16) 3 t
  let t := Guest.store64 (buf+56) 1 t
  let got := forward 3 64 t
  if got < 96 || Guest.load64 buf got != 0 then err else
    let len := Guest.load64 (buf+16) got
    let kind := Guest.load64 (buf+32) got
    let t := copy (buf+64) (control+192) 32 got
    let t := zero buf 8 t
    let t := Guest.store64 buf 1 t
    let t := Guest.store64 (buf+16) len t
    let t := Guest.store64 (buf+24) kind t
    let t := Guest.store64 (buf+32) 1 t
    let t := Guest.store64 (buf+56) 1 t
    let t := copy (control+192) (buf+64) 32 t
    let got := forward 2 96 t
    if got != 64 || Guest.load64 buf got != 0 then err else restoreChunks (Guest.load64 (buf+8) got) len 0 got

def candidateMaterial (h t : UInt64) : UInt64 :=
  if Guest.load64 (control+272) t != 1 then err else
    let t := zero buf 8 t
    let t := Guest.store64 buf 21 t
    let t := Guest.store64 (buf+8) h t
    let t := Guest.store64 (buf+56) 1 t
    let got := forward 2 64 t
    if got != 128 || Guest.load64 buf got != 0 || Guest.load64 (buf+32) got != 13 then err else
      let t := copy (buf+64) (control+336) 32 got
      let t := zero buf 8 t
      let t := Guest.store64 buf 4 t
      let t := Guest.store64 (buf+8) h t
      let t := Guest.store64 (buf+16) 608 t
      let t := Guest.store64 (buf+24) 512 t
      let t := Guest.store64 (buf+56) 1 t
      let got := forward 2 64 t
      if got != 576 || Guest.load64 buf got != 0 || !equal (buf+64) stage 512 got then err else
        result 1 (Guest.store64 (control+304) 1 got)

-- Native Forge stages the actual checked Release graph and binary closure.
-- A graph grant permits inspection; existing trust/signature validation and a
-- fresh physical approval still govern execution.
def graphHeader (op h a b t : UInt64) : UInt64 :=
  let t := zero buf 8 t
  let t := Guest.store64 buf op t
  let t := Guest.store64 (buf+8) h t
  let t := Guest.store64 (buf+16) a t
  let t := Guest.store64 (buf+24) b t
  Guest.store64 (buf+56) 1 t
partial def graphRead (h destination length offset t : UInt64) : UInt64 :=
  if offset == length then t else
    let n := if length-offset > 512 then 512 else length-offset
    let r := forward 2 64 (graphHeader 4 h offset n t)
    if r != 64+n || Guest.load64 buf r != 0 || Guest.load64 (buf+8) r != n then err else
      graphRead h destination length (offset+n) (copy (buf+64) (destination+offset) n r)
def graphResolve (root id t : UInt64) : UInt64 :=
  let t := graphHeader 25 root 0 0 t
  let r := forward 2 96 (copy id (buf+64) 32 t)
  if r != 128 || Guest.load64 buf r != 0 then err else Guest.load64 (buf+8) r
partial def selectedRelease (i count found t : UInt64) : UInt64 :=
  if i == count then found else
    let e := 0x680020+i*128
    if Guest.load64 e t == 13 then
      if found != err then err else selectedRelease (i+1) count i t
    else selectedRelease (i+1) count found t
partial def materialBinary (root count i used t : UInt64) : UInt64 :=
  if i == count then keep used t else
    let e := 0x682020+i*128
    if Guest.load64 e t != 10 then err else
    let h := graphResolve root (e+16) t
    if h == err then err else
    let n := Guest.load64 (buf+16) h
    if n == 0 || n > 65536 || used > 262144 || n > 262144-used then err else
      let r := graphRead h (stage+768+used) n 0 h
      if r == err then err else materialBinary root count (i+1) (used+n) r
def stageProject (root t : UInt64) : UInt64 :=
  let t := zero (control+256) 8 t
  let r := forward 2 64 (graphHeader 24 root 0 0 t)
  if r != 128 || Guest.load64 buf r != 0 then err else
  let h := Guest.load64 (buf+8) r
  let n := Guest.load64 (buf+16) r
  if n < 32 || n > 65536 then err else
  let r := graphRead h 0x680000 n 0 r
  let count := Guest.load64 0x680010 r
  if r == err || count > 32 || n < 32+count*128 then err else
  let selected := selectedRelease 0 count err r
  if selected == err then err else
  let h := graphResolve root (0x680030+selected*128) selected
  if h == err then err else
  let r := graphRead h 0x681000 544 0 h
  if r == err || Guest.load64 0x681010 r != 4 then err else
  let r := graphRead h (stage-608) 1376 608 r
  if r == err then err else
  let binary := graphResolve root 0x6810b0 r
  if binary == err then err else
  let n := Guest.load64 (buf+16) binary
  if n < 32 || n > 1056 then err else
  let r := graphRead binary 0x682000 n 0 binary
  let count := Guest.load64 0x682010 r
  let detail := Guest.load64 0x682018 r
  if r == err || count == 0 || count > 4 || detail > 512 || n != 32+count*128+detail then err else
  let bytes := materialBinary root count 0 0 r
  if bytes == err || bytes != Guest.load64 (stage+24) bytes then err else
    let t := Guest.store64 (control+256) (bytes+768) bytes
    let t := Guest.store64 (control+264) (bytes+768) t
    if !validate t then err else
      let t := Guest.store64 (control+272) 1 t
      let t := Guest.store64 (control+304) 1 t
      keep 512 (copy stage buf 512 t)

@[noinline] def commandControl (op len t : UInt64) : UInt64 :=
  if op == 1 then result 2 t
  else if op == 2 then Guest.syscall 42 0 buf 384 0 t
  else if op == 3 then
    let t := zero (control+256) 8 t
    result 0 t
  else if op == 10 then
    if len != 288 || (Guest.load8 (buf+32) t &&& 128) == 0 || (Guest.load8 (buf+287) t &&& 1) == 0 then err else
      let t := hash (buf+32) 256 (control+64) t
      let known := findTrust buf (control+64) 0 t
      let slot := if known == 0 then freeTrust 0 t else known
      if slot == 0 then err else
        let r := trust (slot-1)
        let t := Guest.store64 r 1 t
        let t := copy buf (r+8) 32 t
        let t := copy (buf+32) (r+40) 256 t
        let t := copy (control+64) (r+296) 32 t
        let t := copy (control+64) buf 32 t
        keep 32 t
  else if op == 11 then if len == 32 then revokeKey buf 0 0 t else err
  else if op == 12 then
    if Guest.load64 (control+272) t == 1 then keep 512 (copy stage buf 512 t) else err
  else if op == 13 then
    if len != 8 || Guest.load64 buf t >= 16 then err else
      let r := catalog (Guest.load64 buf t)
      if Guest.load64 (r+768) t == 1 then keep 512 (copy r buf 512 t) else err
  else if op == 15 then if len == 8 then candidateMaterial (Guest.load64 buf t) t else err
  else if op == 16 then result (Guest.load64 (control+304) t) t
  else if op == 14 then
    if len != 32 then err else
      let known := findProject buf 0 t
      if known == 0 then err else
        let p := project (known-1)
        let active := Guest.load64 (p+72) t
        let previous := Guest.load64 (p+80) t
        let t := zero buf 16 t
        let t := Guest.store64 (buf+8) previous t
        let t := if active > 0 then copy (catalog (active-1)+160) (buf+64) 32 t else t
        let t := if previous > 0 then copy (catalog (previous-1)+160) (buf+96) 32 t else t
        keep 128 t
  else err

@[noinline] def commandStage (op len t : UInt64) : UInt64 :=
  if op == 20 then
    if len != 8 || Guest.load64 buf t < 772 || Guest.load64 buf t > 262912 then err else
      let size := Guest.load64 buf t
      let t := zero (control+256) 8 t
      let t := Guest.store64 (control+256) size t
      result size t
  else if op == 21 then
    if len <= 8 || len > 520 || Guest.load64 (control+272) t != 0 then err else
      let offset := Guest.load64 buf t
      let received := Guest.load64 (control+264) t
      let total := Guest.load64 (control+256) t
      if offset != received || received > total || len-8 > total-received then err else
        let t := copy (buf+8) (stage+received) (len-8) t
        let t := Guest.store64 (control+264) (received+len-8) t
        result (received+len-8) t
  else if op == 22 then
    if Guest.load64 (control+264) t != Guest.load64 (control+256) t || !validate t then err else
      let t := Guest.store64 (control+272) 1 t
      let t := copy stage buf 512 t
      keep 512 t
  else if op == 23 then
    if len != 40 || Guest.load64 (control+272) t != 1 || !equal buf (stage+160) 32 t || Guest.load64 (buf+32) t != Guest.load64 (stage+64) t then err else
      let t := copy buf (control+128) 32 t
      let t := Guest.store64 (control+160) (Guest.load64 (buf+32) t) t
      let t := Guest.store64 (control+288) 1 t
      result (Guest.load64 (control+160) t) t
  else if op == 24 then install t
  else err

@[noinline] def commandProcess (op len t : UInt64) : UInt64 :=
  if op == 25 then
    if len != 8 then err else
      let index := Guest.load64 buf t
      if !launchable index t then err else
        let identity := Guest.syscall 50 (index-1) 0 0 0 t
        if identity == err then err else result identity identity
  else if op == 26 then
    if len != 8 then err else
      let r := Guest.syscall 51 (Guest.load64 buf t) 0 0 0 t
      if r == err then err else result 0 r
  else if op == 27 then
    if len != 16 then err else
      let old := Guest.load64 buf t
      let slot := Guest.load64 (buf+8) t
      if !launchable slot t || old >>> 8 >= 0x00ffffffffffffff || ((old >>> 8) &&& 0xffffff) == 0xffffff || (old &&& 255) < 4 || (old &&& 255) >= 12 then err else
        let r := Guest.syscall 51 old 0 0 0 t
        if r == err then err else
          let identity := Guest.syscall 50 (slot-1) old 0 0 r
          if identity == err then err else result identity identity
  else if op == 28 then
    if len != 32 then err else
      let found := findProject buf 0 t
      if found == 0 then err else
        let p := project (found-1)
        let old := Guest.load64 (p+80) t
        let active := Guest.load64 (p+72) t
        if !launchable old t then err else
          let t := Guest.store64 (p+72) old t
          let t := Guest.store64 (p+80) active t
          let t := Guest.store64 (p+88) (Guest.load64 (p+88) t+1) t
          result old t
  else if op == 29 then
    if len != 32 then err else
      let found := findProject buf 0 t
      if found == 0 then err else
        let active := Guest.load64 (project (found-1)+72) t
        if active == 0 then err else keep 512 (copy (catalog (active-1)) buf 512 t)
  else if op == 30 then
    if len != 32 then err else
      let found := releaseById buf 0 t
      if found == 0 then err else result found (Guest.store64 (catalog (found-1)+776) 1 t)
  else if op == 31 then collect 0 0 t
  else if op == 32 || op == 33 then
    if len != 8 then err else
      let identity := Guest.load64 buf t
      let changed := Guest.syscall 56 identity (if op == 33 then 1 else 0) 0 0 t
      if changed == err then err else result changed changed
  else err

-- Project retention uses an immutable temporary root. A gesture authorizes the
-- exact stable head displayed by trusted chrome, never whatever is current later.
def projectTxn : UInt64 := 0x636000
def projectReply : UInt64 := 0x637000

def projectHeader (op h a b t : UInt64) : UInt64 :=
  let t := zero buf 8 t
  let t := Guest.store64 buf op t
  let t := Guest.store64 (buf+8) h t
  let t := Guest.store64 (buf+16) a t
  let t := Guest.store64 (buf+24) b t
  Guest.store64 (buf+56) 1 t

partial def projectClosureCount (root cursor count bytes t : UInt64) : UInt64 :=
  if cursor > 64 || count > 64 || bytes > 4194304 then err else
    let got := forward 2 64 (projectHeader 26 root cursor 0 t)
    if got < 64 || Guest.load64 buf got != 0 then err else
      if Guest.load64 (buf+8) got == 0 then
        let t := Guest.store64 (projectTxn+40) count got
        Guest.store64 (projectTxn+48) bytes t
      else
        let next := Guest.load64 (buf+24) got
        if got != 128 || next <= cursor || next > 64 then err else
          projectClosureCount root next (count+1) (bytes+Guest.load64 (buf+16) got) got

def releaseFrozenProject (length t : UInt64) : UInt64 :=
  if length > 1024 then err else
    let t := copy buf projectReply length t
    let root := Guest.load64 (projectTxn+160) t
    let got := forward 2 64 (projectHeader 28 root 0 0 t)
    let t := Guest.store64 (projectTxn+160) 0 got
    if got != 64 || Guest.load64 buf t != 0 then err else
      keep length (copy projectReply buf length t)

def prepareProject (root exact t : UInt64) : UInt64 :=
  let t := Guest.store64 (projectTxn+160) 0 t
  let t := Guest.store64 projectTxn root t
  let got := forward 2 64 (projectHeader 29 root 0 0 t)
  if got != 160 || Guest.load64 buf got != 0 then err else
  if exact == 1 && !equal (buf+64) (projectTxn+8) 32 got then err else
    let t := copy (buf+64) (projectTxn+8) 32 got
    let t := Guest.store64 (projectTxn+56) (Guest.load64 (buf+16) t) t
    let t := Guest.store64 (projectTxn+176) (Guest.load64 (buf+32) t) t
    let t := copy (buf+96) (projectTxn+64) 64 t
    let t := projectHeader 32 root 0 0 t
    let t := copy (projectTxn+8) (buf+64) 32 t
    let got := forward 2 96 t
    if got != 160 || Guest.load64 buf got != 0 then err else
      let frozen := Guest.load64 (buf+8) got
      let t := Guest.store64 (projectTxn+160) frozen got
      let counted := projectClosureCount frozen 0 0 0 t
      if counted == err then
        keep err (releaseFrozenProject 0 counted)
      else counted

def describeProjectRetention (root t : UInt64) : UInt64 :=
  let prepared := prepareProject root 0 t
  if prepared == err then err else
    let t := zero buf 20 prepared
    let t := Guest.store64 (buf+8) root t
    let t := Guest.store64 (buf+16) (Guest.load64 (projectTxn+40) t) t
    let t := Guest.store64 (buf+24) (Guest.load64 (projectTxn+48) t) t
    let t := Guest.store64 (buf+32) (Guest.load64 (projectTxn+56) t) t
    let t := Guest.store64 (buf+40) (Guest.load64 (projectTxn+176) t) t
    let t := Guest.store64 (buf+48) 2 t
    let t := copy (projectTxn+8) (buf+64) 32 t
    let t := copy (projectTxn+64) (buf+96) 64 t
    releaseFrozenProject 160 t

def retainProject (root t : UInt64) : UInt64 :=
  let prepared := prepareProject root 1 t
  if prepared == err then err else
    let count := Guest.syscall 42 0 0x418000 384 0 prepared
    if count != 384 then
      keep err (releaseFrozenProject 0 count)
    else
      let vault := Guest.load64 (0x418000+96) count
      let frozen := Guest.load64 (projectTxn+160) count
      let got := forward 2 64 (projectHeader 27 frozen vault 1 count)
      if got != 160 || Guest.load64 buf got != 0 then
        keep err (releaseFrozenProject 0 got)
      else
        let delegated := Guest.load64 (buf+8) got
        let t := Guest.store64 (projectTxn+168) delegated got
        let t := projectHeader 210 0 3 1 t
        let t := Guest.store64 (buf+64) delegated t
        let received := forward 3 72 t
        if received < 64 || received > 1024 then
          keep err (releaseFrozenProject 0 received)
        else
          let t := copy buf projectReply received received
          let t := projectHeader 31 frozen delegated 0 t
          let revoked := forward 2 64 t
          let t := copy projectReply buf received revoked
          releaseFrozenProject received t

@[noinline] def commandIO (op len t : UInt64) : UInt64 :=
  if op == 70 then Guest.syscall 70 0 0 0 0 t
  else if op == 100 then if len >= 64 && len <= 1024 then forward 2 len t else err
  else if op == 160 then if len >= 64 && len <= 1024 then forward 5 len t else err
  else if op == 170 then
    if len < 64 || len > 1024 then err else
      let provisioning := Guest.load64 buf t == 1
      let received := forward 6 len t
      -- Provisioning secrets are never retained in the management replay cache.
      let t := if provisioning then zero (buf+64) 120 received else received
      keep received t
  else if op == 180 then if len == 8 then stageProject (Guest.load64 buf t) t else err
  else if op == 181 then
    if len != 8 then err else
      let r := Guest.syscall 112 (Guest.load64 buf t) 0 0 0 t
      if r == err then err else 8+Guest.store64 buf (Guest.load64 buf r) r
  else if op == 182 then
    if len != 8 then err else
      let r := Guest.syscall 114 (Guest.load64 buf t) 0 0 0 t
      if r == err then err else 8+Guest.store64 buf (Guest.load64 buf r) r
  else if op == 183 then
    if len != 0 then err else
      let r := Guest.syscall 115 0 0 0 0 t
      8+Guest.store64 buf r r
  else if op == 150 then
    if len < 72 || len > 1032 then err else
      let target := Guest.load64 buf t
      let t := copy (buf+8) buf (len-8) t
      forward target (len-8) t
  else if op == 203 then if len == 8 then retain (Guest.load64 buf t) t else err
  else if op == 207 then recover t
  else if op == 221 then if len == 8 then describeProjectRetention (Guest.load64 buf t) t else err
  else if op == 220 then
    if len != 40 then err else
      let root := Guest.load64 buf t
      let t := copy (buf+8) (projectTxn+8) 32 t
      retainProject root t
  else if (op >= 230 && op <= 239) then
    if len < 64 || len > 1024 || Guest.load64 buf t != op then err else forward 3 len t
  else if (op >= 200 && op <= 206) || (op >= 210 && op <= 217) then
    if len < 64 || len > 1024 || Guest.load64 buf t != op then err else
      let received := forward 3 len t
      if op == 200 then keep received (zero (buf+64) 4 received) else received
  else err

def command (op len t : UInt64) : UInt64 :=
  if op < 20 then commandControl op len t
  else if op < 25 then commandStage op len t
  else if op < 34 then commandProcess op len t
  else commandIO op len t

def pollGUI (t : UInt64) : UInt64 :=
  let n := Guest.syscall 36 1 0x410800 1056 0 t
  if n < 40 || n > 1056 || (Guest.load64 0x410800 n &&& 255) != 4 then n else
    let token := Guest.load64 0x410808 n
    let op := Guest.load64 0x410820 n
    let length := n-40
    let t := copy 0x410828 buf length n
    let allowed := op == 2 || op == 3 || op == 12 || op == 13 || op == 24 || op == 25 || op == 26 || op == 27 || op == 28 || op == 29 || op == 14 || op == 16 || op == 202 || op == 211 || op == 213 || op == 212 || op == 221 || op == 180
    let response := if (op == 200 && length == 104) || (op == 217 && length == 72) then
        let payload := length-8
        let gesture := Guest.load64 (buf+payload) t
        let checked := Guest.syscall 98 gesture 0 0 0 t
        if checked == err then err else command op payload checked
      else if (op == 23 || op == 220) && length == 48 then
        let gesture := Guest.load64 (buf+40) t
        let checked := Guest.syscall 98 gesture 0 0 0 t
        if checked == err then err else command op 40 checked
      else if op == 25 && length == 40 then
        let slot := Guest.load64 buf t
        if slot == 0 || slot > 16 || !equal (buf+8) (catalog (slot-1)+160) 32 t then err else command op 8 t
      else if op == 27 && length == 48 then
        let slot := Guest.load64 (buf+8) t
        if slot == 0 || slot > 16 || !equal (buf+16) (catalog (slot-1)+160) 32 t then err else command op 16 t
      else if op == 28 && length == 96 then
        let known := findProject buf 0 t
        if known == 0 then err else
          let p := project (known-1)
          let active := Guest.load64 (p+72) t
          let previous := Guest.load64 (p+80) t
          if active == 0 || previous == 0 || !equal (buf+32) (catalog (active-1)+160) 32 t || !equal (buf+64) (catalog (previous-1)+160) 32 t then err
          else command op 32 t
      else if allowed && op != 25 && op != 27 && op != 28 then command op length t else err
    let t := if response == err || response > 1024 then zero buf 8 response else response
    let size := if response == err || response > 1024 then 8 else response
    let t := if size == 8 then Guest.store64 buf err t else t
    let t := Guest.syscall 32 token buf size 0 t
    zero 0x410800 132 t

def readByte (t : UInt64) : UInt64 :=
  let index := Guest.load64 (control+520) t
  let count := Guest.load64 (control+512) t
  if index < count && count <= 256 then
    let t := Guest.store64 (control+520) (index+1) t
    let value := Guest.load8 (0x414000+index) t
    keep value (Guest.store8 (0x414000+index) 0 t)
  else
    let n := Guest.syscall 40 0 0x414000 256 0 t
    if n == 0 || n > 256 then
      let t := pollGUI n
      let t := Guest.store64 (control+512) 0 t
      keep err (Guest.store64 (control+520) 0 t)
    else
      let t := Guest.store64 (control+512) n n
      let t := Guest.store64 (control+520) 1 t
      let value := Guest.load8 0x414000 t
      keep value (Guest.store8 0x414000 0 t)
partial def readBytes (dst n i t : UInt64) : UInt64 :=
  if i == n then t else
    let c := readByte t
    -- A native GUI RPC can wake the UART reader. Preserve a partially received
    -- management frame while servicing it; the next read blocks in the kernel.
    if c == err then readBytes dst n i c else
      let t := Guest.store8 (dst+i) c t
      let t := Guest.store64 (control+544) (i+1) t
      readBytes dst n (i+1) t
partial def findMagic (matched t : UInt64) : UInt64 :=
  let c := readByte t
  if c == err then findMagic matched c
  else if matched == 0 && c == 76 then findMagic 1 t
  else if matched == 1 && c == 84 then findMagic 2 t
  else if matched == 2 && c == 50 then findMagic 3 t
  else if matched == 3 && c == 0 then t
  else findMagic (if c == 76 then 1 else 0) t

partial def loop (t : UInt64) : UInt64 :=
  let t := pollGUI t
  let t := findMagic 0 t
  let t := zero 0x413000 4 t
  let t := Guest.store64 0x413000 0x0032544c t
  let t := Guest.store64 (control+544) 0 t
  let received := readBytes 0x413004 28 0 t
  if received == err then
    let rid := if Guest.load64 (control+544) received >= 12 then Guest.load64 0x413008 received else 0
    let t := zero buf 128 received
    if rid == 0 then loop t else loop (respond rid 2 buf 0 t)
  else
    let len := Guest.load64 0x413000 received >>> 32
    let rid := Guest.load64 0x413008 received
    let op := Guest.load64 0x413010 received
    let reserved := Guest.load64 0x413018 received
    if len > 1024 || reserved != 0 || rid == 0 then loop (respond rid 2 buf 0 received) else
      let t := zero buf 128 received
      let t := Guest.store64 (control+544) 0 t
      -- GUI dispatch uses buf. Keep an interrupted UART body in private staging
      -- until the complete management request is available.
      let received := readBytes 0x638000 len 0 t
      if received == err then loop (respond rid 2 buf 0 (zero buf 128 received)) else
        let t := copy 0x638000 buf len received
        let t := zero 0x638000 128 t
        let t := copy 0x413000 0x634000 32 t
        let t := copy buf 0x634020 len t
        let t := hash 0x634000 (len+32) (control+448) t
        let t := zero 0x634000 132 t
        let last := Guest.load64 (control+528) t
        if rid == last then
          if equal (control+400) (control+448) 32 t then
            let size := Guest.load64 (control+536) t
            let t := copy 0x632000 0x416000 size t
            let t := Guest.syscall 41 0 0x416000 size 0 t
            loop t
          else loop (respond rid 4 buf 0 t)
        else if rid < last then loop (respond rid 3 buf 0 t) else
          let t := copy (control+448) (control+400) 32 t
          let size := command op len t
          if size == err || size > 1024 then loop (zero buf 128 (respond rid 1 buf 0 size))
          else loop (zero buf 128 (respond rid 0 buf size size))

def main (initial : UInt64) : UInt64 :=
  let t := zero control 128 initial
  let t := zero 0x632000 512 t
  let t := respond 0 0 buf 0 t
  loop t
end Guest.Launcher
