import Guest.IdentitySDK
import Guest.IdentityPolicy
import Guest.Ed25519
import Guest.ServiceHash
import Guest.LiveMemory
import Guest.VaultCrypto
import Guest.ReceiptSDK
import Guest.WaitSDK
import Guest.ReleaseFormat
import Guest.FederationDecisionFormat
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
  -- Include the full incarnation, including the randomized high boot epoch.
  -- A low32-only token deterministically aliases a new boot's same-slot key.
  -- Handles remain finite ephemeral names, not a rollback/freshness anchor.
  let value := (self t) ^^^ ((next <<< 32) ||| next)
  if value == 0 || value == error then error else value
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
  if role == 0 || role > 7 || zeros (command+64) 32 t || zeros (command+96) 32 t then fail 2 t else
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
-- material, not a person's identity. It is distinct from X3DH messaging keys.
-- Public node declarations support explicit enrollment, not measured attestation.
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
  if purpose == 6 then n == 512 && load64 (p+8) t == 4 && Guest.ReleaseFormat.validHeader p t else
  if purpose == 1 then
    n == 128 && load64 p t == contactMagic && load64 (p+8) t == 1 &&
    load64 (p+16) t > 0 && load64 (p+24) t <= 7 &&
    !zeros (p+32) 32 t && !zeros (p+64) 32 t && !zeros (p+96) 32 t
  else if purpose == 3 then n == 128 && Guest.ReceiptSDK.declarationBody p t else
  if purpose == 4 || purpose == 5 then
    let kind := load64 (p+16) t
    n == 256 && load64 p t == 0x3144564546544c && load64 (p+8) t == 1 &&
    load64 (p+24) t > 0 && load64 (p+96) t <= 16384 && load64 (p+248) t == 0 &&
    !zeros (p+64) 32 t && !zeros (p+112) 32 t &&
    (if purpose == 4 then kind >= 1 && kind <= 9 && kind != 8 else
      kind == 8 && !zeros (p+208) 32 t && load64 (p+240) t > 0 && load64 (p+240) t <= 3)
  else
    let endpointLength := load64 (p+176) t
    let legacy := load64 (p+8) t == 1 && load64 (p+16) t >= 1 &&
      load64 (p+16) t <= 6 && load64 (p+24) t == 3
    let publicNode := load64 (p+8) t == 2 &&
      (load64 (p+16) t == 7 || load64 (p+16) t == 8 || load64 (p+16) t == 16) && load64 (p+24) t == 1
    n == 256 && load64 p t == nodeMagic && (legacy || publicNode) && load64 (p+32) t == 1 &&
    load64 (p+40) t > 0 && load64 (p+40) t <= 1073741824 &&
    load64 (p+48) t > 0 && load64 (p+48) t <= 1000000000 &&
    load64 (p+56) t == 1 && !zeros (p+64) 32 t && !zeros (p+96) 32 t &&
    !zeros (p+128) 32 t && load64 (p+160) t > 0 && (load64 (p+168) t == 0 || (publicNode && load64 (p+168) t == 1)) &&
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
    length != (if purpose == 1 || purpose == 3 then 128 else if purpose == 6 then 512 else 256) || zeros (command+64) 32 t then fail 2 t else
  -- Release approval is reserved to the trusted native coordinator, never an
  -- installed app or a caller merely presenting a project key handle.
  if purpose == 6 && (recipient%256 != 1 || load64 (k+160) t != recipient || load64 (k+168) t != 0) then fail 1 t else
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
def signProject (k token t : UInt64) : UInt64 :=
  let p := command+64
  let t := hash (k+128) 32 hashed t
  if !eq hashed (p+96) 32 t || load64 (p+392) t != load64 (k+24) t || load64 (k+168) t != 0 then fail 1 t else
  let t := copy (p+160) publicDescriptor 32 t
  let t := hash p 512 hashed (zero (p+160) 4 t)
  let t := copy publicDescriptor (p+160) 32 t
  if !eq hashed (p+160) 32 t || !current token t then fail 1 t else
  let t := Guest.ReleaseFormat.signedMessage p canonical t
  let t := Guest.Ed25519.sign (k+96) (k+128) canonical Guest.ReleaseFormat.messageLength signature t
  if t == error || !current token t then fail 3 t else
  let t := header 0 (load64 (k+8) t) 6 512 1 0 0 t
  let t := copy signature (wire+64) 64 t
  let t := copy (k+128) (wire+128) 32 t
  168+clearScratch (store64 (wire+160) (load64 (k+24) t) t)
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
      !validBody (load64 (k+16) t) purpose (command+64) bodyLength t ||
      ((purpose == 4 || purpose == 5) && (!eq (command+176) (k+32) 32 t ||
        load64 (k+160) t != caller || syscall 146 (load64 (k+16) t) 0 0 0 t != caller)) ||
      (purpose == 6 && (caller%256 != 1 || load64 (k+160) t != caller)) then fail 1 t else
  if purpose == 6 then signProject k token (zero g 16 t) else
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
  if i == 16 then count else countGrants (i+1) (count+(if load64 (grantAt i) t != 0 then 1 else 0)) t
partial def cancelApproval (handle caller admin i t : UInt64) : UInt64 :=
  if i == 16 then fail 3 t else
  let g := grantAt i
  if load64 g t != 0 && load64 (g+8) t == handle && (admin == 1 || load64 (g+24) t == caller) then
    response 0 handle 0 0 (zero g 16 t)
  else cancelApproval handle caller admin (i+1) t
-- Sealed operator retention never exports an unwrapped seed. This private
-- workspace is disjoint from key/grant tables and relocatedEd25519 scratch.
def receiptWork : UInt64 := 0x660000
def clearReceipt (t : UInt64) : UInt64 := zero receiptWork 512 t
def receiptFail (code t : UInt64) : UInt64 := fail code (clearReceipt t)
def retentionKey (credential t : UInt64) : UInt64 :=
  let t := copy credential (receiptWork+512) 32 t
  let t := store64 (receiptWork+544) 0x746e6564492d544c t
  let t := store64 (receiptWork+552) 0x336c616553797469 t
  hash (receiptWork+512) 48 (receiptWork+768) t
def sealKeys (token t : UInt64) : UInt64 :=
  let node := findKey (load64 (command+16) t) 0 t
  let receipt := findKey (load64 (command+24) t) 0 t
  if node == error || receipt == error || load64 (node+16) t != 3 ||
    load64 (receipt+16) t != 4 || !eq (node+32) (receipt+32) 64 t then receiptFail 2 t else
  let p := receiptWork
  let b := receiptWork+256
  let t := zero p 18 t
  let t := copy (node+96) p 32 t
  let t := copy (receipt+96) (p+32) 32 t
  let t := copy (node+32) (p+64) 64 t
  let t := store64 (p+128) (load64 (node+24) t) t
  let t := store64 (p+136) (load64 (receipt+24) t) t
  let t := retentionKey (command+64) t
  let r := syscall 130 0 (receiptWork+1024) 32 0 t
  if r != 0 || !current token r then receiptFail 6 r else
  let t := zero b 24 r
  let t := store64 b Guest.ReceiptSDK.sealMagic t
  let t := store64 (b+8) 1 t
  let t := copy (receiptWork+1024) (b+16) 12 t
  let t := Guest.VaultCrypto.encrypt (receiptWork+768) (b+16) b 32 p 144 (b+32) t
  if t == error || !current token t then receiptFail 3 t else
  let t := header 0 (load64 (node+8) t) (load64 (receipt+8) t) 192 0 0 0 t
  256+clearReceipt (copy b (wire+64) 192 t)
partial def freeOtherKey (excluded i t : UInt64) : UInt64 :=
  if i == 8 then error else
  if i != excluded && load64 (keyAt i) t == 0 then i else freeOtherKey excluded (i+1) t
def recoveredKey (slot role seed generation scope t : UInt64) : UInt64 :=
  let p := keyAt slot
  let handle := serial t
  if handle == error then error else
  let t := zero p 32 (takeSerial t)
  let t := copy seed (p+96) 32 t
  let t := copy scope (p+32) 64 t
  let t := Guest.Ed25519.publicKey (p+96) (p+128) t
  let t := store64 (p+8) handle t
  let t := store64 (p+16) role t
  let t := store64 (p+24) generation t
  store64 p 1 t
def recoverKeys (token t : UInt64) : UInt64 :=
  let b := command+128
  let first := freeKey 0 t
  let second := freeOtherKey first 0 t
  if first == error || second == error || load64 b t != Guest.ReceiptSDK.sealMagic ||
    load64 (b+8) t != 1 || !zeros (b+28) 4 t || zeros (command+96) 32 t then receiptFail 2 t else
  let t := retentionKey (command+64) t
  let r := Guest.VaultCrypto.decrypt (receiptWork+768) (b+16) b 32 (b+32) 144 receiptWork t
  if r == error || zeros (receiptWork+64) 32 r || zeros (receiptWork+96) 32 r ||
    load64 (receiptWork+128) r == 0 || load64 (receiptWork+136) r == 0 then receiptFail 9 r else
  let t := Guest.Ed25519.publicKey receiptWork (receiptWork+1024) r
  if !eq (receiptWork+1024) (command+96) 32 t || !current token t then receiptFail 8 t else
  let t := recoveredKey first 3 receiptWork (load64 (receiptWork+128) t) (receiptWork+64) t
  if t == error then receiptFail 4 t else
  let t := recoveredKey second 4 (receiptWork+32) (load64 (receiptWork+136) t) (receiptWork+64) t
  if t == error || !current token t then receiptFail 3 (zero (keyAt first) 32 (zero (keyAt second) 32 t)) else
  let t := header 0 (load64 (keyAt first+8) t) (load64 (keyAt second+8) t) 1 0 0 0 t
  64+clearReceipt t
def authorizeReceipt (token t : UInt64) : UInt64 :=
  let k := findKey (load64 (command+16) t) 0 t
  let recipient := load64 (command+24) t
  let limit := load64 (command+32) t
  let slot := freeGrant 0 t
  let handle := serial t
  let generation := syscall 132 recipient 409 3 0 t
  if k == error || load64 (k+16) t != 4 || recipient == 0 || limit == 0 || limit > 65536 ||
    zeros (command+64) 32 t || zeros (command+96) 32 t then receiptFail 2 t else
  if generation == error || generation == 0 then receiptFail 3 t else
  if slot == error || handle == error then receiptFail 4 t else
  let g := grantAt slot
  let t := zero g 16 (takeSerial t)
  let t := store64 g 2 t
  let t := store64 (g+8) handle t
  let t := store64 (g+16) (load64 (k+8) t) t
  let t := store64 (g+24) recipient t
  let t := store64 (g+48) (load64 (k+24) t) t
  let t := store64 (g+56) limit t
  let t := hash (command+64) 64 (g+64) t
  let t := store64 (g+96) generation t
  if !current token t then receiptFail 3 (zero g 16 t) else
  response 0 handle limit generation (clearReceipt t)
partial def findReceipt (handle caller i t : UInt64) : UInt64 :=
  if i == 16 then error else
  let g := grantAt i
  if load64 g t == 2 && load64 (g+8) t == handle && load64 (g+24) t == caller then g else findReceipt handle caller (i+1) t
def signReceipt (caller token t : UInt64) : UInt64 :=
  let g := findReceipt (load64 (command+8) t) caller 0 t
  if g == error then receiptFail 3 t else
  let k := findKey (load64 (g+16) t) 0 t
  let generation := syscall 132 caller 409 3 0 t
  if k == error || generation == error then receiptFail 3 t else
  if !Guest.ReceiptSDK.bodyValid (command+64) caller t then receiptFail 2 t else
  let t := hash (command+160) 64 hashed t
  let context := eq hashed (g+64) 32 t
  if !Guest.IdentityPolicy.receiptPermits (load64 (g+56) t) (load64 (g+48) t)
      (load64 (k+24) t) (load64 (g+96) t) generation context then receiptFail (if context then 3 else 1) t else
  let t := store64 (g+56) (load64 (g+56) t-1) t
  if !current token t then receiptFail 3 t else
  let t := Guest.Ed25519.sign (k+96) (k+128) (command+64) 192 signature t
  if t == error || !current token t then receiptFail 3 t else
  let t := header 0 (load64 (g+8) t) (load64 (g+56) t) (load64 (k+24) t) 1 0 0 t
  128+clearReceipt (clearScratch (copy signature (wire+64) 64 t))
-- Typed Feed lifecycle: current exact consumer bindings determine key role.
-- It cannot select another purpose, enumerate another owner's keys, or sign
-- arbitrary bytes. The installed account owner mediates the publication gesture.
def feedRole (caller t : UInt64) : UInt64 :=
  if syscall 146 5 0 0 0 t == caller then 5 else
  if syscall 146 6 0 0 0 t == caller then 6 else 0
def feedSealMagic : UInt64 := 0x314c414553464c
partial def lockFeedOwner (caller i t : UInt64) : UInt64 :=
  if i == 8 then t else
  let k := keyAt i
  let t := if load64 k t == 1 && load64 (k+160) t == caller then
    zero k 32 (revokeGrants (load64 (k+8) t) 0 t) else t
  lockFeedOwner caller (i+1) t
def feedRetentionKey (credential t : UInt64) : UInt64 :=
  let t := copy credential (receiptWork+512) 32 t
  let t := store64 (receiptWork+544) feedSealMagic t
  let t := store64 (receiptWork+552) 3 t
  hash (receiptWork+512) 48 (receiptWork+768) t
def feedSeal (caller key token t : UInt64) : UInt64 :=
  let k := findKey key 0 t
  if k == error || load64 (k+160) t != caller || zeros (command+64) 32 t then receiptFail 1 t else
  let p := receiptWork
  let b := receiptWork+256
  let t := zero p 18 t
  let t := copy (k+96) p 32 t
  let t := copy (k+32) (p+32) 64 t
  let t := store64 (p+96) (load64 (k+24) t) t
  let t := store64 (p+104) (load64 (k+16) t) t
  let t := feedRetentionKey (command+64) t
  let r := syscall 130 0 (receiptWork+1024) 32 0 t
  if r != 0 || !current token r then receiptFail 6 r else
  let t := zero b 24 r
  let t := store64 b feedSealMagic t
  let t := store64 (b+8) 1 t
  let t := copy (receiptWork+1024) (b+16) 12 t
  let t := Guest.VaultCrypto.encrypt (receiptWork+768) (b+16) b 32 p 144 (b+32) t
  if t == error || !current token t then receiptFail 3 t else
  256+clearReceipt (copy b (wire+64) 192 (header 0 key 192 3 0 0 0 t))
def feedRecover (caller role token t : UInt64) : UInt64 :=
  let slot := freeKey 0 t
  let b := command+128
  if slot == error || load64 b t != feedSealMagic || load64 (b+8) t != 1 ||
    !zeros (b+28) 4 t || zeros (command+64) 32 t || zeros (command+96) 32 t then receiptFail 2 t else
  let t := feedRetentionKey (command+64) t
  let r := Guest.VaultCrypto.decrypt (receiptWork+768) (b+16) b 32 (b+32) 144 receiptWork t
  if r == error || zeros (receiptWork+32) 32 r || zeros (receiptWork+64) 32 r ||
    load64 (receiptWork+104) r != role || load64 (receiptWork+96) r == 0 ||
    load64 (receiptWork+96) r >= 0xffffffff then receiptFail 9 r else
  let t := Guest.Ed25519.publicKey receiptWork (receiptWork+1024) r
  if !eq (receiptWork+1024) (command+96) 32 t || !current token t then receiptFail 8 t else
  -- Fresh key generation; old approvals are never restored. Reconciliation of
  -- supported backups remains the account owner's required pre-publication step.
  let t := recoveredKey slot role receiptWork (load64 (receiptWork+96) t+1) (receiptWork+32) t
  if t == error || !current token t then receiptFail 3 (zero (keyAt slot) 32 t) else
  exportKey (keyAt slot) token (clearReceipt (store64 (keyAt slot+160) caller t))
-- Project authority uses its own typed seal inside the existing Objects
-- domain3 store. This ciphertext is not a generic fourth vault domain.
def projectSealMagic : UInt64 := 0x314c414553504c
def projectRetentionKey (credential t : UInt64) : UInt64 :=
  let t := copy credential (receiptWork+512) 32 t
  let t := store64 (receiptWork+544) projectSealMagic t
  let t := store64 (receiptWork+552) 3 t
  hash (receiptWork+512) 48 (receiptWork+768) t
def projectSeal (caller key token t : UInt64) : UInt64 :=
  let k := findKey key 0 t
  if k == error || load64 (k+16) t != 1 || load64 (k+160) t != caller ||
    zeros (command+64) 32 t then receiptFail 1 t else
  let p := receiptWork
  let b := receiptWork+256
  let t := zero p 18 t
  let t := copy (k+96) p 32 t
  let t := copy (k+32) (p+32) 64 t
  let t := store64 (p+96) (load64 (k+24) t) t
  let t := store64 (p+104) 1 t
  let t := projectRetentionKey (command+64) t
  let r := syscall 130 0 (receiptWork+1024) 32 0 t
  if r != 0 || !current token r then receiptFail 6 r else
  let t := zero b 24 r
  let t := store64 b projectSealMagic t
  let t := store64 (b+8) 1 t
  let t := copy (receiptWork+1024) (b+16) 12 t
  let t := Guest.VaultCrypto.encrypt (receiptWork+768) (b+16) b 32 p 144 (b+32) t
  if t == error || !current token t then receiptFail 3 t else
  256+clearReceipt (copy b (wire+64) 192 (header 0 key 192 3 0 0 0 t))
def projectRecover (caller token t : UInt64) : UInt64 :=
  let slot := freeKey 0 t
  let b := command+128
  if slot == error || load64 b t != projectSealMagic || load64 (b+8) t != 1 ||
    !zeros (b+28) 4 t || zeros (command+64) 32 t || zeros (command+96) 32 t then receiptFail 2 t else
  let t := projectRetentionKey (command+64) t
  let r := Guest.VaultCrypto.decrypt (receiptWork+768) (b+16) b 32 (b+32) 144 receiptWork t
  if r == error || zeros (receiptWork+32) 32 r || zeros (receiptWork+64) 32 r ||
    load64 (receiptWork+104) r != 1 || load64 (receiptWork+96) r == 0 ||
    load64 (receiptWork+96) r >= 0xffffffff then receiptFail 9 r else
  let t := Guest.Ed25519.publicKey receiptWork (receiptWork+1024) r
  if !eq (receiptWork+1024) (command+96) 32 t || !current token t then receiptFail 8 t else
  let t := recoveredKey slot 1 receiptWork (load64 (receiptWork+96) t+1) (receiptWork+32) t
  if t == error || !current token t then receiptFail 3 (zero (keyAt slot) 32 t) else
  -- A sealed old backup is not an external freshness anchor. Recovery restores
  -- inspection only; it cannot silently authorize a conflicting successor.
  let t := store64 (keyAt slot+160) caller t
  exportKey (keyAt slot) token (clearReceipt (store64 (keyAt slot+168) 1 t))
def decisionCache (k : UInt64) : UInt64 := 0x657000+(k-0x651000)/256*128
def decisionReply (k token t : UInt64) : UInt64 :=
  if !current token t then fail 3 t else
  let t := header 0 (load64 (k+8) t) 7 512 1 0 0 t
  let t := copy (decisionCache k+32) (wire+64) 64 t
  let t := copy (k+128) (wire+128) 32 t
  168+clearScratch (store64 (wire+160) (load64 (k+24) t) t)
def registrySealMagic : UInt64 := 0x314c414553524c
def registryRetentionKey (credential t : UInt64) : UInt64 :=
  let t := copy credential (receiptWork+512) 32 t
  let t := store64 (receiptWork+544) registrySealMagic t
  let t := store64 (receiptWork+552) 3 t
  hash (receiptWork+512) 48 (receiptWork+768) t
def registrySeal (registry key token t : UInt64) : UInt64 :=
  let k := findKey key 0 t
  if k == error || load64 (k+16) t != 7 || load64 (k+160) t != registry ||
    zeros (command+64) 32 t then receiptFail 1 t else
  let p := receiptWork
  let b := receiptWork+256
  let t := zero p 18 t
  let t := copy (k+96) p 32 t
  let t := copy (k+32) (p+32) 64 t
  let t := store64 (p+96) (load64 (k+24) t) t
  let t := store64 (p+104) 7 t
  let t := store64 (p+112) (load64 (k+184) t) t
  let t := store64 (p+120) (load64 (k+176) t) t
  let t := registryRetentionKey (command+64) t
  let r := syscall 130 0 (receiptWork+1024) 32 0 t
  if r != 0 || !current token r then receiptFail 6 r else
  let t := zero b 24 r
  let t := store64 b registrySealMagic t
  let t := store64 (b+8) 1 t
  let t := copy (receiptWork+1024) (b+16) 12 t
  let t := Guest.VaultCrypto.encrypt (receiptWork+768) (b+16) b 32 p 144 (b+32) t
  if t == error || !current token t then receiptFail 3 t else
  256+clearReceipt (copy b (wire+64) 192 (header 0 key 192 3 0 0 0 t))
def registryRecover (registry token t : UInt64) : UInt64 :=
  let slot := freeKey 0 t
  let b := command+128
  let generation := syscall 132 registry 411 0 0 t
  if slot == error || generation == error || generation == 0 || load64 b t != registrySealMagic || load64 (b+8) t != 1 ||
    !zeros (b+28) 4 t || zeros (command+64) 32 t || zeros (command+96) 32 t then receiptFail 2 t else
  let t := registryRetentionKey (command+64) t
  let r := Guest.VaultCrypto.decrypt (receiptWork+768) (b+16) b 32 (b+32) 144 receiptWork t
  if r == error || zeros (receiptWork+32) 32 r || zeros (receiptWork+64) 32 r ||
    load64 (receiptWork+104) r != 7 || load64 (receiptWork+96) r == 0 ||
    load64 (receiptWork+96) r >= 0xffffffff || load64 (receiptWork+120) r > 65536 then receiptFail 9 r else
  let t := Guest.Ed25519.publicKey receiptWork (receiptWork+1024) r
  if !eq (receiptWork+1024) (command+96) 32 t || !current token t then receiptFail 8 t else
  let t := recoveredKey slot 7 receiptWork (load64 (receiptWork+96) t+1) (receiptWork+32) t
  if t == error || !current token t then receiptFail 3 (zero (keyAt slot) 32 t) else
  let k := keyAt slot
  let t := store64 (k+160) registry t
  let t := store64 (k+176) (load64 (receiptWork+120) t) t
  let t := store64 (k+184) (load64 (receiptWork+112) t) t
  let t := store64 (k+192) generation (zero (decisionCache k) 16 t)
  exportKey k token (clearReceipt t)
def decisionLifecycle (caller admin token length t : UInt64) : UInt64 :=
  let action := load64 (command+8) t
  let selected := load64 (command+16) t
  let registry := syscall 113 0 0 0 0 t
  if action == 0 && admin == 1 && caller%256 == 1 && length == 128 then
    let limit := load64 (command+24) t
    let generation := syscall 132 selected 411 0 0 t
    if registry == error || registry != selected || generation == error || generation == 0 ||
      limit == 0 || limit > 65536 then fail 1 t else
    let r := create token (store64 (command+16) 7 t)
    let k := findKey (load64 (wire+8) r) 0 r
    if load64 wire r != 0 || k == error then r else
    let t := zero (decisionCache k) 16 r
    let t := store64 (k+160) selected t
    let t := store64 (k+176) limit t
    352+store64 (k+192) generation t
  else if action == 2 && admin == 1 && caller%256 == 1 && length == 96 && registry != error then
    registrySeal registry selected token t
  else if action == 3 && admin == 1 && caller%256 == 1 && length == 320 && selected == registry && registry != error then
    registryRecover registry token t
  else if action == 1 && length == 576 && caller == registry && registry != error then
    let k := findKey selected 0 t
    let generation := syscall 132 caller 411 0 0 t
    let p := command+64
    if k == error || load64 (k+16) t != 7 || load64 (k+160) t != caller ||
      generation == error || !Guest.IdentityPolicy.bindingCurrent (load64 (k+192) t) generation ||
      !Guest.FederationDecisionFormat.validHeader p t || !eq (k+32) (p+256) 32 t ||
      load64 (p+392) t != load64 (k+24) t then fail 1 t else
    let t := hash (k+128) 32 hashed t
    if !eq hashed (p+288) 32 t then fail 1 t else
    let t := hash p 512 hashed t
    let sequence := load64 (p+48) t
    if sequence == load64 (k+184) t && eq hashed (decisionCache k) 32 t then decisionReply k token t else
    if sequence <= load64 (k+184) t || load64 (k+176) t == 0 then fail 3 t else
    let t := store64 (k+176) (load64 (k+176) t-1) t
    let t := store64 (k+184) sequence t
    let t := zero (decisionCache k) 16 t
    let t := Guest.FederationDecisionFormat.signedMessage p canonical t
    let t := Guest.Ed25519.sign (k+96) (k+128) canonical Guest.FederationDecisionFormat.messageLength signature t
    if t == error || !current token t then fail 3 t else
    let t := copy hashed (decisionCache k) 32 t
    decisionReply k token (copy signature (decisionCache k+32) 64 t)
  else fail 1 t
def feedLifecycle (caller token length t : UInt64) : UInt64 :=
  let role := feedRole caller t
  let action := load64 (command+8) t
  let key := load64 (command+16) t
  let k := findKey key 0 t
  if role == 0 then receiptFail 1 t else
  if action == 0 && length == 128 then
    let t := store64 (command+16) role t
    let r := create token t
    if load64 wire r != 0 then r else
    let created := findKey (load64 (wire+8) r) 0 r
    if created == error then receiptFail 3 r else 352+store64 (created+160) caller r
  else if action == 1 && length == 96 then
    if k == error || load64 (k+160) t != caller || load64 (k+16) t != role then receiptFail 1 t else
    let t := store64 (command+8) key t
    let t := store64 (command+16) caller t
    let t := store64 (command+24) (if role == 5 then 4 else 5) t
    authorize token (store64 (command+32) 256 t)
  else if action == 2 && length == 64 then
    if k == error || load64 (k+160) t != caller then receiptFail 1 t else
    response 0 key 0 0 (zero k 32 (revokeGrants key 0 t))
  else if action == 3 && length == 96 then feedSeal caller key token t
  else if action == 4 && length == 320 then feedRecover caller role token t
  else if action == 5 && length == 64 then response 0 0 0 0 (clearReceipt (lockFeedOwner caller 0 t))
  else receiptFail 2 t
-- A replaced or dead consumer must not leave accessible keys or consume the
-- finite table forever. Native current-role queries authenticate incarnation;
-- no durable record recreates these IPC grants during reclamation.
partial def reapFeedOwners (i t : UInt64) : UInt64 :=
  if i == 8 then t else
  let k := keyAt i
  let owner := load64 (k+160) t
  let role := load64 (k+16) t
  let stale := ((role == 5 || role == 6) && syscall 146 role 0 0 0 t != owner) ||
    (role == 7 && syscall 113 0 0 0 0 t != owner)
  let t := if load64 k t == 1 && owner != 0 && stale then
      zero k 32 (revokeGrants (load64 (k+8) t) 0 t) else t
  reapFeedOwners (i+1) t
def dispatch (caller rights token length t : UInt64) : UInt64 :=
  let op := load64 command t
  let admin := Guest.IdentityPolicy.administrative rights
  if length < 64 || length > 576 || load64 (command+56) t != 1 ||
    load64 (command+40) t != 0 || load64 (command+48) t != 0 || !current token t then fail 2 t else
  if op == 410 then feedLifecycle caller token length t
  else if op == 411 then decisionLifecycle caller (if admin then 1 else 0) token length t
  else if op == 400 then
    if admin && length == 128 && load64 (command+16) t <= 4 then
      if load64 (command+16) t != 1 then create token t else
      if caller%256 != 1 then fail 1 t else
      let r := create token t
      let k := findKey (load64 (wire+8) r) 0 r
      if load64 wire r != 0 || k == error then r else 352+store64 (k+160) caller r
    else fail 1 t
  else if op == 401 then
    let k := findKey (load64 (command+8) t) 0 t
    if !admin then fail 1 t else if length != 64 then fail 2 t else if k == error then fail 3 t else exportKey k token t
  else if op == 402 then certify caller token length t
  else if op == 403 then if admin && length == 64 then revokeKey t else fail 1 t
  else if op == 404 then if admin && length == 64 then lock t else fail 1 t
  else if op == 405 then
    if admin && length == 96 && (load64 (command+24) t <= 3 ||
      (load64 (command+24) t == 6 && caller%256 == 1)) then authorize token t else fail 1 t
  else if op == 406 then if admin && length == 64 then
    64+header 0 1 8 16 (countKeys 0 0 t) (countGrants 0 0 t) 0 t else fail 2 t
  else if op == 407 then if length == 64 then
    cancelApproval (load64 (command+8) t) caller (if admin then 1 else 0) 0 t else fail 2 t
  else if op == 408 && admin then
    if load64 (command+8) t == 0 && length == 96 then sealKeys token t else
    if load64 (command+8) t == 1 && length == 320 then recoverKeys token t else
    if caller%256 == 1 && load64 (command+8) t == 2 && length == 96 then projectSeal caller (load64 (command+16) t) token t else
    if caller%256 == 1 && load64 (command+8) t == 3 && length == 320 then projectRecover caller token t else receiptFail 2 t
  else if op == 409 then
    if admin && load64 (command+8) t == 0 && length == 128 then authorizeReceipt token t else
    if !admin && length == 256 then signReceipt caller token t else receiptFail 2 t
  else fail 7 t
partial def serve (t : UInt64) : UInt64 :=
  let t := reapFeedOwners 0 t
  let n := syscall 36 (self t) incoming 1024 0 t
  if n == 0 then serve (Guest.WaitSDK.deadline (Guest.WaitSDK.now n+100) (clearScratch n)) else
  if n == error then serve (clearScratch n) else
  let n := reapFeedOwners 0 n
  let token := load64 (incoming+8) n
  let result := if n >= 96 && load64 (incoming+24) n == 2 then
    dispatch (load64 incoming n) (load64 (incoming+16) n) token (n-32) n else fail 2 n
  let t := reply token result result
  -- Command and response windows retain no private seeds; erase public request
  -- data as well so cancelled callers leave no stale certificate body behind.
  serve (zero incoming 128 (zero wire 128 (clearReceipt (clearScratch t))))
def main (t : UInt64) : UInt64 := serve (zero st 1 (lock t))
end Guest.Identity
