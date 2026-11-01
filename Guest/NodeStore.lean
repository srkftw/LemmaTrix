import Guest.NodeEnrollment
import Guest.VaultCrypto
namespace Guest.NodeStore
open Guest.LiveSDK
-- Explicit protected operator retention: static DH keys, the already signed
-- public certificate and an optional opaque Identity-owned sealed seed blob.
-- Network cannot unwrap that blob. Live Noise/ntor/circuit state never survives.
-- Two three-sector records in purpose2's dedicated credential extent1..6.
def st : UInt64 := 0x720000
def key : UInt64 := st+32
def record : UInt64 := st+512
def second : UInt64 := st+2560
def plain : UInt64 := st+8192
def scratch : UInt64 := st+10240
def magic : UInt64 := 0x3154534e544c
def response (code generation t : UInt64) : UInt64 := 64+header code generation 0 0 0 0 0 t
def disk (op sector p n t : UInt64) : UInt64 := syscall op sector p n 2 t
def flush (t : UInt64) : UInt64 := disk 143 0 0 0 t
def clear (t : UInt64) : UInt64 := zero st 2048 t
def derive (credential t : UInt64) : UInt64 :=
  let t := copy credential scratch 32 t
  let t := store64 (scratch+32) 0x617265704f2d544c t
  let t := store64 (scratch+40) 0x31762d726f74 t
  Guest.ServiceHash.sha256At (scratch+512) scratch 46 key t

def headerValid (p t : UInt64) : Bool :=
  load64 p t == magic && (load64 (p+8) t == 2 || load64 (p+8) t == 3) && load64 (p+16) t > 0 &&
  load64 (p+16) t <= 65535 && load64 (p+24) t == 768 &&
  Guest.Identity.zeros (p+44) 468 t && Guest.Identity.zeros (p+1296) 240 t

def openRecord (p t : UInt64) : UInt64 :=
  if !headerValid p t then error else
  let r := Guest.VaultCrypto.decrypt key (p+32) p 64 (p+512) 768 plain t
  if r == error then error else
  if load64 plain r != magic || load64 (plain+8) r != 1 ||
      !Guest.NodeEnrollment.certificateValid (plain+96) r ||
      (load64 (p+8) r == 2 && !Guest.Identity.zeros (plain+576) 192 r) ||
      (load64 (p+8) r == 3 && !Guest.Identity.zeros (plain+576) 192 r &&
       (load64 (plain+576) r != Guest.ReceiptSDK.sealMagic || load64 (plain+584) r != 1 ||
        !Guest.Identity.zeros (plain+604) 4 r)) then error else
  -- The authenticated public keys must actually belong to these retained
  -- private scalars; signatures alone are never possession evidence.
  let t := zero scratch 4 r
  let t := store8 scratch 9 t
  let t := Guest.Noise25519.x25519 (plain+32) scratch (scratch+32) t
  let t := Guest.Noise25519.x25519 (plain+64) scratch (scratch+64) t
  if !Guest.NodeEnrollment.eq (scratch+32) (plain+320) 64 t then error else t

def restore (t : UInt64) : UInt64 :=
  let t := copy (plain+32) Guest.NodeEnrollment.keys 64 t
  let t := copy (plain+320) (Guest.NodeEnrollment.keys+64) 64 t
  let t := store64 (Guest.NodeEnrollment.keys+160) 1 t
  let t := copy (plain+96) (Guest.NodeEnrollment.localNode+32) 480 t
  let t := Guest.NodeEnrollment.hash (plain+96) 480 (Guest.NodeEnrollment.localNode+512) t
  store64 Guest.NodeEnrollment.localNode 1 t

def recover (credential t : UInt64) : UInt64 :=
  let t := derive credential t
  let a := disk 141 0 record 1536 t
  let b := if a == error then error else disk 141 3 second 1536 a
  if b == error then response 6 0 (clear b) else
  let first := if headerValid record b && (!headerValid second b || load64 (record+16) b >= load64 (second+16) b) then record else second
  let other := if first == record then second else record
  let attempt := openRecord first b
  let selected := if attempt == error then other else first
  let r := if attempt == error then openRecord other attempt else attempt
  if r == error then response 9 0 (clear r) else
  let generation := load64 (selected+16) r
  let t := restore r
  let t := header 0 generation 192 (if Guest.Identity.zeros (plain+576) 192 t then 0 else 1) 0 0 0 t
  256+clear (copy (plain+576) (wire+64) 192 t)

def retain (credential sealed t : UInt64) : UInt64 :=
  if load64 Guest.NodeEnrollment.localNode t != 1 || load64 (Guest.NodeEnrollment.keys+160) t != 1 then response 3 0 t else
  let t := derive credential t
  let a := disk 141 0 record 1536 t
  let b := if a == error then error else disk 141 3 second 1536 a
  if b == error then response 6 0 (clear b) else
  -- Retaining into a nonempty credential store requires its existing key.
  let av := openRecord record b != error
  let bv := openRecord second b != error
  if (!av && !Guest.Identity.zeros record 1536 b) || (!bv && !Guest.Identity.zeros second 1536 b) then response 9 0 (clear b) else
  let old := if av && (!bv || load64 (record+16) b >= load64 (second+16) b) then load64 (record+16) b else if bv then load64 (second+16) b else 0
  if old >= 65535 then response 4 0 (clear b) else
  let t := zero plain 128 b
  let t := store64 plain magic t
  let t := store64 (plain+8) 1 t
  let t := copy Guest.NodeEnrollment.keys (plain+32) 64 t
  let t := copy (Guest.NodeEnrollment.localNode+32) (plain+96) 480 t
  let t := if sealed == 0 then t else copy sealed (plain+576) 192 t
  if !Guest.Identity.zeros (plain+576) 192 t &&
      (load64 (plain+576) t != Guest.ReceiptSDK.sealMagic || load64 (plain+584) t != 1 ||
       !Guest.Identity.zeros (plain+604) 4 t) then response 2 0 (clear t) else
  let t := zero record 256 t
  let t := store64 record magic t
  let t := store64 (record+8) 3 t
  let t := store64 (record+16) (old+1) t
  let t := store64 (record+24) 768 t
  let r := syscall 104 0 scratch 32 0 t
  if r != 32 then response 6 0 (clear r) else
  let t := copy scratch (record+32) 12 r
  let t := Guest.VaultCrypto.encrypt key (record+32) record 64 plain 768 (record+512) t
  let r := disk 142 (((old+1)%2)*3) record 1536 t
  let r := if r == error then error else flush r
  if r == error then response 6 0 (clear r) else response 0 (old+1) (clear r)
end Guest.NodeStore
