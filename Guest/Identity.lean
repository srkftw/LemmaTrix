import Guest.IdentitySDK
import Guest.IdentityPolicy
import Guest.Ed25519
import Guest.ServiceHash
import Guest.LiveMemory
namespace Guest.Identity
open Guest.LiveSDK
-- Installed profile2, rights EXACTLY zero. Kernel role1 grants narrow entropy;
-- no sockets, Network broker, block device, Objects, console or UI authority.
def st : UInt64 := 0x650000
def keyAt (i : UInt64) : UInt64 := 0x651000+i*256
def grantAt (i : UInt64) : UInt64 := 0x652000+i*128
def canonical : UInt64 := 0x653000
def hashed : UInt64 := 0x653800
def publicDescriptor : UInt64 := 0x654000
def signature : UInt64 := 0x654400
def scratch : UInt64 := 0x655000
def identityMagic : UInt64 := 0x314449544c
def signingMagic : UInt64 := 0x31474953544c
def contactMagic : UInt64 := 0x315443544c
def nodeMagic : UInt64 := 0x31444e544c
def eq (a b n t : UInt64) : Bool := Guest.LiveMemory.equal a b n t
partial def zeros (p n t : UInt64) : Bool :=
  if n == 0 then true else load8 p t == 0 && zeros (p+1) (n-1) t
def hash (p n out t : UInt64) : UInt64 := Guest.ServiceHash.sha256At scratch p n out t
def clearScratch (t : UInt64) : UInt64 :=
  let t := Guest.Ed25519.clear t
  let t := zero canonical 256 t
  let t := zero publicDescriptor 256 t
  zero hashed 4 (zero scratch 128 t)
def response (code value a b t : UInt64) : UInt64 := 64+header code value a b 0 0 0 t
def fail (code t : UInt64) : UInt64 := response code 0 0 0 (clearScratch t)
def serial (t : UInt64) : UInt64 :=
  let next := load64 st t+1
  if next > 0xffffffff then error else
  ((self t &&& 0xffffffff) <<< 32) ||| next
def takeSerial (t : UInt64) : UInt64 := store64 st (load64 st t+1) t
partial def freeKey (i t : UInt64) : UInt64 :=
  if i == 8 then error else if load64 (keyAt i) t == 0 then i else freeKey (i+1) t
partial def findKey (handle i t : UInt64) : UInt64 :=
  if i == 8 then error else
  if load64 (keyAt i) t == 1 && load64 (keyAt i+8) t == handle then keyAt i else findKey handle (i+1) t
partial def freeGrant (i t : UInt64) : UInt64 :=
  if i == 16 then error else if load64 (grantAt i) t == 0 then i else freeGrant (i+1) t
partial def findGrant (handle caller i t : UInt64) : UInt64 :=
  if i == 16 then error else
  let g := grantAt i
  if load64 g t == 1 && load64 (g+8) t == handle && load64 (g+24) t == caller then g
  else findGrant handle caller (i+1) t
partial def revokeGrants (key i t : UInt64) : UInt64 :=
  if i == 16 then t else
  let g := grantAt i
  let t := if key == 0 || load64 (g+16) t == key then zero g 16 t else t
  revokeGrants key (i+1) t
def current (token t : UInt64) : Bool := syscall 131 token 0 0 0 t == 0

def descriptor (k t : UInt64) : UInt64 :=
  let t := zero publicDescriptor 32 t
  let t := store64 publicDescriptor identityMagic t
  let t := store64 (publicDescriptor+8) 1 t
  let t := store64 (publicDescriptor+16) (load64 (k+16) t) t
  let t := store64 (publicDescriptor+24) (load64 (k+24) t) t
  let t := copy (k+32) (publicDescriptor+32) 64 t
  let t := copy (k+128) (publicDescriptor+96) 32 t
  let t := store64 (publicDescriptor+128) 1 t -- RFC8032 pure Ed25519
  let t := store64 (publicDescriptor+136) 1 t -- explicit revocation; no uptime expiry
  Guest.Ed25519.sign (k+96) (k+128) publicDescriptor 192 (publicDescriptor+192) t
def exportKey (k token t : UInt64) : UInt64 :=
  let t := descriptor k t
  if t == error || !current token t then fail 3 t else
  let t := hash publicDescriptor 192 hashed t
  let t := header 0 (load64 (k+8) t) (load64 (k+16) t) (load64 (k+24) t) 0 0 0 t
  let t := copy publicDescriptor (wire+64) 256 t
  let t := copy hashed (wire+320) 32 t
  352+clearScratch t
def create (token t : UInt64) : UInt64 :=
  let role := load64 (command+16) t
  let slot := freeKey 0 t
  let handle := serial t
  if role == 0 || role > 4 || zeros (command+64) 32 t || zeros (command+96) 32 t then fail 2 t else
  if slot == error || handle == error then fail 4 t else
  let k := keyAt slot
  let t := zero k 32 (takeSerial t)
  let entropy := syscall 130 0 (k+96) 32 0 t
  if entropy != 0 || !current token entropy then fail 6 (zero k 32 entropy) else
  let t := Guest.Ed25519.publicKey (k+96) (k+128) entropy
  if t == error || !current token t then fail 3 (zero k 32 t) else
  let t := store64 k 1 t
  let t := store64 (k+8) handle t
  let t := store64 (k+16) role t
  let t := store64 (k+24) 1 t
  let t := copy (command+64) (k+32) 64 t
  let r := exportKey k token t
  if load64 wire r != 0 then 64+zero k 32 r else r

-- Exact canonical typed bodies. Contact approval certifies declared key
-- material, not a person's identity. New messaging sessions remain unavailable.
-- A node declaration has no measured-attestation or network-enrollment meaning.
partial def decimal (p n i digits value limit t : UInt64) : UInt64 :=
  let c := if i < n then load8 (p+i) t else 0
  if c < 48 || c > 57 then
    if digits == 0 || value > limit then error else (i <<< 32) ||| value
  else if digits >= 5 || (digits == 1 && value == 0) then error else
    let value := value*10+c-48
    if value > limit then error else decimal p n (i+1) (digits+1) value limit t
partial def ipv4 (p n i part t : UInt64) : Bool :=
  let parsed := decimal p n i 0 0 255 t
  let next := parsed >>> 32
  if parsed == error || next >= n then false else
  if part < 3 then load8 (p+next) t == 46 && ipv4 p n (next+1) (part+1) t else
  let port := decimal p n (next+1) 0 0 65535 t
  load8 (p+next) t == 58 && port != error && (port &&& 0xffffffff) > 0 && port >>> 32 == n
def validBody (role purpose p n t : UInt64) : Bool :=
  if !Guest.IdentityPolicy.purposeAllowed role purpose then false else
  if purpose == 1 then
    n == 128 && load64 p t == contactMagic && load64 (p+8) t == 1 &&
    load64 (p+16) t > 0 && load64 (p+24) t <= 7 &&
    !zeros (p+32) 32 t && !zeros (p+64) 32 t && !zeros (p+96) 32 t
  else
    let endpointLength := load64 (p+176) t
    n == 256 && load64 p t == nodeMagic && load64 (p+8) t == 1 &&
    load64 (p+16) t >= 1 && load64 (p+16) t <= 6 &&
    load64 (p+24) t == 3 && load64 (p+32) t == 1 &&
    load64 (p+40) t > 0 && load64 (p+40) t <= 1073741824 &&
    load64 (p+48) t > 0 && load64 (p+48) t <= 1000000000 &&
    load64 (p+56) t == 1 && !zeros (p+64) 32 t && !zeros (p+96) 32 t &&
    !zeros (p+128) 32 t && load64 (p+160) t > 0 && load64 (p+168) t == 0 &&
    endpointLength > 0 && endpointLength <= 64 && ipv4 (p+184) endpointLength 0 0 t &&
    zeros (p+184+endpointLength) (64-endpointLength) t && zeros (p+248) 8 t
def authorize (token t : UInt64) : UInt64 :=
  let k := findKey (load64 (command+8) t) 0 t
  let recipient := load64 (command+16) t
  let purpose := load64 (command+24) t
  let length := load64 (command+32) t
  let slot := freeGrant 0 t
  let handle := serial t
  let bindingGeneration := syscall 132 recipient 402 0 0 t
  if k == error then fail 3 t else
  if recipient == 0 || !Guest.IdentityPolicy.purposeAllowed (load64 (k+16) t) purpose ||
    length != (if purpose == 1 then 128 else 256) || zeros (command+64) 32 t then fail 2 t else
  if bindingGeneration == error || bindingGeneration == 0 then fail 3 t else
  if slot == error || handle == error then fail 4 t else
  let g := grantAt slot
  let t := zero g 16 (takeSerial t)
  let t := store64 g 1 t
  let t := store64 (g+8) handle t
  let t := store64 (g+16) (load64 (k+8) t) t
  let t := store64 (g+24) recipient t
  let t := store64 (g+32) purpose t
  let t := store64 (g+40) length t
  let t := store64 (g+48) (load64 (k+24) t) t
  let t := store64 (g+56) 1 t
  let t := copy (command+64) (g+64) 32 t
  let t := store64 (g+96) bindingGeneration t
  if !current token t then fail 3 (zero g 16 t) else response 0 handle purpose length t
def certify (caller token length t : UInt64) : UInt64 :=
  let g := findGrant (load64 (command+8) t) caller 0 t
  if g == error then fail 3 t else
  let k := findKey (load64 (g+16) t) 0 t
  if k == error then fail 3 (zero g 16 t) else
  let bodyLength := length-64
  let purpose := load64 (g+32) t
  let bindingGeneration := syscall 132 caller 402 0 0 t
  if bindingGeneration == error || !Guest.IdentityPolicy.bindingCurrent (load64 (g+96) t) bindingGeneration then
    fail 3 (zero g 16 t) else
  let t := hash (command+64) bodyLength hashed t
  let exactBody := bodyLength == load64 (g+40) t && eq hashed (g+64) 32 t
  if !Guest.IdentityPolicy.permits (load64 g t) (load64 (g+24) t) caller
      (load64 (g+48) t) (load64 (k+24) t) (load64 (g+56) t) exactBody ||
      !validBody (load64 (k+16) t) purpose (command+64) bodyLength t then fail 1 t else
  let t := zero canonical 64 t
  let t := store64 canonical signingMagic t
  let t := store64 (canonical+8) 1 t
  let t := store64 (canonical+16) (load64 (k+16) t) t
  let t := store64 (canonical+24) purpose t
  let t := store64 (canonical+32) (load64 (k+24) t) t
  let t := store64 (canonical+40) bodyLength t
  let t := copy (k+32) (canonical+48) 64 t
  let t := copy (k+128) (canonical+112) 32 t
  let t := copy (command+64) (canonical+160) bodyLength t
  -- Consume before secret work. Cancellation can burn an approval but cannot
  -- produce two differently authorized results or return an old live grant.
  let t := zero g 16 t
  if !current token t then fail 3 t else
  let t := Guest.Ed25519.sign (k+96) (k+128) canonical (160+bodyLength) signature t
  if t == error || !current token t then fail 3 t else
  let t := header 0 (load64 (k+8) t) purpose (160+bodyLength) 1 0 0 t
  let t := copy canonical (wire+64) (160+bodyLength) t
  let t := copy signature (wire+224+bodyLength) 64 t
  (288+bodyLength)+clearScratch t
def revokeKey (t : UInt64) : UInt64 :=
  let handle := load64 (command+8) t
  let k := findKey handle 0 t
  if k == error then fail 3 t else response 0 handle 0 0 (zero k 32 (revokeGrants handle 0 t))
def lock (t : UInt64) : UInt64 :=
  let t := zero 0x651000 256 t
  let t := revokeGrants 0 0 t
  response 0 0 0 0 (clearScratch t)
partial def countKeys (i count t : UInt64) : UInt64 :=
  if i == 8 then count else countKeys (i+1) (count+(if load64 (keyAt i) t == 1 then 1 else 0)) t
partial def countGrants (i count t : UInt64) : UInt64 :=
  if i == 16 then count else countGrants (i+1) (count+(if load64 (grantAt i) t == 1 then 1 else 0)) t
partial def cancelApproval (handle caller admin i t : UInt64) : UInt64 :=
  if i == 16 then fail 3 t else
  let g := grantAt i
  if load64 g t == 1 && load64 (g+8) t == handle && (admin == 1 || load64 (g+24) t == caller) then
    response 0 handle 0 0 (zero g 16 t)
  else cancelApproval handle caller admin (i+1) t
def dispatch (caller rights token length t : UInt64) : UInt64 :=
  let op := load64 command t
  let admin := Guest.IdentityPolicy.administrative rights
  if length < 64 || length > 320 || load64 (command+56) t != 1 ||
    load64 (command+40) t != 0 || load64 (command+48) t != 0 || !current token t then fail 2 t else
  if op == 400 then if admin && length == 128 then create token t else fail 1 t
  else if op == 401 then
    let k := findKey (load64 (command+8) t) 0 t
    if !admin then fail 1 t else if length != 64 then fail 2 t else if k == error then fail 3 t else exportKey k token t
  else if op == 402 then certify caller token length t
  else if op == 403 then if admin && length == 64 then revokeKey t else fail 1 t
  else if op == 404 then if admin && length == 64 then lock t else fail 1 t
  else if op == 405 then if admin && length == 96 then authorize token t else fail 1 t
  else if op == 406 then if length == 64 then
    64+header 0 1 8 16 (countKeys 0 0 t) (countGrants 0 0 t) 0 t else fail 2 t
  else if op == 407 then if length == 64 then
    cancelApproval (load64 (command+8) t) caller (if admin then 1 else 0) 0 t else fail 2 t
  else fail 7 t
partial def serve (t : UInt64) : UInt64 :=
  let n := receive (self t) t
  if n == error then serve (clearScratch n) else
  let token := load64 (incoming+8) n
  let result := if n >= 96 && load64 (incoming+24) n == 2 then
    dispatch (load64 incoming n) (load64 (incoming+16) n) token (n-32) n else fail 2 n
  let t := reply token result result
  -- Command and response windows retain no private seeds; erase public request
  -- data as well so cancelled callers leave no stale certificate body behind.
  serve (zero incoming 128 (zero wire 128 (clearScratch t)))
def main (t : UInt64) : UInt64 := serve (zero st 1 (lock t))
end Guest.Identity
