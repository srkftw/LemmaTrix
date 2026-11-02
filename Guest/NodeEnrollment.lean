import Guest.LiveSDK
import Guest.Ed25519
import Guest.Identity
import Guest.NodeEnrollmentPolicy
namespace Guest.NodeEnrollment
open Guest.LiveSDK
-- Native broker-owned transport/onion keys. Only public material crosses IPC.
-- The node's separately scoped Identity role3 certifies the public body.
-- Scratch is disjoint from four Network banks and Transport, including clears.
def base : UInt64 := 0x690000
def peer (i : UInt64) : UInt64 := base+i*1024
def candidate : UInt64 := base+8192
def scratch : UInt64 := base+12288
def hashed : UInt64 := base+14336
def keys : UInt64 := base+16384
def localNode : UInt64 := base+16640
def response (code value t : UInt64) : UInt64 := 64+header code value 0 0 0 0 0 t
def eq (a b n t : UInt64) : Bool := Guest.Ed25519.difference a b n 0 t == 0
def hash (p n out t : UInt64) : UInt64 := Guest.ServiceHash.sha256At scratch p n out t
def bodyValid (p t : UInt64) : Bool :=
  let n := load64 (p+176) t
  load64 p t == Guest.Identity.nodeMagic && load64 (p+8) t == 2 &&
  (load64 (p+16) t == 7 || load64 (p+16) t == 8 || load64 (p+16) t == 16) &&
  load64 (p+24) t == 1 && load64 (p+32) t == 1 &&
  load64 (p+40) t > 0 && load64 (p+40) t <= 1073741824 &&
  load64 (p+48) t > 0 && load64 (p+48) t <= 1000000000 &&
  load64 (p+56) t == 1 && !Guest.Identity.zeros (p+64) 32 t &&
  !Guest.Identity.zeros (p+96) 32 t && !Guest.Identity.zeros (p+128) 32 t &&
  load64 (p+160) t > 0 && load64 (p+168) t <= 1 && n > 0 && n <= 64 &&
  Guest.Identity.ipv4 (p+184) n 0 0 t && Guest.Identity.zeros (p+184+n) (64-n) t &&
  Guest.Identity.zeros (p+248) 8 t
def certificateValid (p t : UInt64) : Bool :=
  load64 p t == Guest.Identity.signingMagic && load64 (p+8) t == 1 &&
  load64 (p+16) t == 3 && load64 (p+24) t == 2 && load64 (p+32) t > 0 &&
  load64 (p+40) t == 256 && !Guest.Identity.zeros (p+48) 32 t &&
  !Guest.Identity.zeros (p+80) 32 t && Guest.Identity.zeros (p+144) 16 t &&
  bodyValid (p+160) t && Guest.Ed25519.verify (p+112) p 416 (p+416) t

def generate (t : UInt64) : UInt64 :=
  -- An installed localNode declaration must be explicitly removed before rotation.
  if load64 localNode t != 0 then response 3 0 t else
  let t := zero keys 32 t
  let r := syscall 104 0 keys 64 0 t
  if r != 64 then response 6 0 (zero keys 32 r) else
  let t := zero (keys+128) 4 r
  let t := store8 (keys+128) 9 t
  let t := Guest.Noise25519.x25519 keys (keys+128) (keys+64) t
  let t := Guest.Noise25519.x25519 (keys+32) (keys+128) (keys+96) t
  let t := store64 (keys+160) 1 t
  let t := header 0 1 0 0 0 0 0 t
  128+copy (keys+64) (wire+64) 64 t

def installLocal (length t : UInt64) : UInt64 :=
  if length != 544 || load64 (keys+160) t != 1 || !certificateValid (command+64) t ||
    !eq (command+288) (keys+64) 64 t || load64 (command+392) t != 0 then response 2 0 t else
  let t := copy (command+64) (localNode+32) 480 t
  let t := hash (localNode+32) 480 (localNode+512) t
  let t := store64 localNode 1 t
  let t := header 0 1 0 0 0 0 0 t
  96+copy (localNode+512) (wire+64) 32 t

def stage (slot length t : UInt64) : UInt64 :=
  if slot >= 8 || length != 544 || !certificateValid (command+64) t then response 2 0 t else
  let t := copy (command+64) (candidate+32) 480 t
  let t := hash (candidate+32) 480 (candidate+512) t
  let t := store64 candidate (slot+1) t
  let t := header 0 slot (load64 (candidate+352) t) 0 0 0 0 t
  576+copy (candidate+32) (wire+64) 512 t

def approve (slot length t : UInt64) : UInt64 :=
  if slot >= 8 || length != 96 || load64 candidate t != slot+1 ||
    !eq (command+64) (candidate+512) 32 t then response 2 0 t else
  let old := peer slot
  -- A pin may rotate only its same identity/federation/scope, monotonically.
  -- Changing identity requires explicit revoke then separate user approval.
  if !Guest.NodeEnrollmentPolicy.pinAccept (load64 old t)
    (eq (old+144) (candidate+144) 32 t) (eq (old+80) (candidate+80) 96 t)
    (load64 (candidate+352) t > load64 (old+352) t) then response 3 0 t else
  let t := copy candidate old 544 t
  let t := store64 old (if load64 (candidate+360) t == 1 then 2 else 1) t
  response 0 slot (zero candidate 68 t)

def dispatch (op slot length t : UInt64) : UInt64 :=
  if op == 20 && length == 64 then generate t else
  if op == 21 then installLocal length t else
  if op == 22 then stage slot length t else
  if op == 23 then approve slot length t else
  if op == 24 && slot < 8 && length == 64 then response 0 slot (store64 (peer slot) 2 t) else
  if op == 26 && length == 64 then
    let p := if slot == 8 then localNode else peer slot
    if slot > 8 || load64 p t == 0 then response 3 0 t else
    let t := header 0 slot (load64 p t) 0 0 0 0 t
    576+copy (p+32) (wire+64) 512 t
  else
  -- Legacy operation25 keeps its local sentinel4. Operation26 explicitly
  -- addresses all eight peer slots and local sentinel8 without ambiguity.
  if op == 25 && length == 64 then
    let p := if slot == 4 then localNode else peer slot
    if slot > 4 || load64 p t == 0 then response 3 0 t else
    let t := header 0 slot (load64 p t) 0 0 0 0 t
    576+copy (p+32) (wire+64) 512 t
  else response 2 0 t
end Guest.NodeEnrollment
