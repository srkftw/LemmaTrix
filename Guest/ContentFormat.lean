import Guest.LiveSDK
import Guest.ServiceHash
namespace Guest.ContentFormat
open Guest.LiveSDK
-- ContentManifest-v1 is a fixed, canonical 256-byte record. Its SHA-256 is
-- committed by the separately signed consumer release; this module does not
-- turn a bare hash into read authority or publisher admission.
def magic : UInt64 := 0x31544e434d544c
def leafDomain : UInt64 := 0x314641454c544c
def branchDomain : UInt64 := 0x3148434e42544c
def chunkBytes : UInt64 := 4096
def legacyMaxChunks : UInt64 := 1472
def maxChunks : UInt64 := 16384
def maxBytes : UInt64 := maxChunks*chunkBytes
def legacyMaxBytes : UInt64 := legacyMaxChunks*chunkBytes
def wavePCM48 : UInt64 := 1
def genericArtifact : UInt64 := 2
partial def equal (a b n t : UInt64) : Bool :=
  if n == 0 then true else load8 a t == load8 b t && equal (a+1) (b+1) (n-1) t
partial def allZero (p n t : UInt64) : Bool :=
  if n == 0 then true else load8 p t == 0 && allZero (p+1) (n-1) t
partial def treeDepth (count width depth : UInt64) : UInt64 :=
  if width >= count then depth else treeDepth count (width*2) (depth+1)
def depth (count : UInt64) : UInt64 := treeDepth count 1 0
def chunkLength (total index : UInt64) : UInt64 :=
  if index >= (total+4095)/4096 then 0 else if total-index*4096 < 4096 then total-index*4096 else 4096
def valid (p t : UInt64) : Bool :=
  let total := load64 (p+24) t
  let count := load64 (p+32) t
  load64 p t == magic && (load64 (p+8) t == 1 || load64 (p+8) t == 2) && load64 (p+16) t == chunkBytes &&
  total > 0 && total <= (if load64 (p+8) t == 1 then legacyMaxChunks*chunkBytes else maxBytes) && count == (total+4095)/4096 &&
  (load64 (p+40) t == wavePCM48 || (load64 (p+8) t == 2 && load64 (p+40) t == genericArtifact)) && load64 (p+48) t == depth count &&
  load64 (p+56) t == 0 && !allZero (p+64) 32 t &&
  !allZero (p+96) 32 t && allZero (p+160) 96 t
-- Leaf bytes: domain8,index8,exact-length8,SHA256(raw bytes)32. Branch
-- bytes: domain8,left32,right32. The tree pads to the next power of two
-- with canonical zero-length leaves, never by duplicating a payload leaf.
def leaf (input scratch out index length rawHash t : UInt64) : UInt64 :=
  let t := store64 input leafDomain t
  let t := store64 (input+8) index t
  let t := store64 (input+16) length t
  let t := copy rawHash (input+24) 32 t
  ServiceHash.sha256At scratch input 56 out t
def branch (input scratch out left right t : UInt64) : UInt64 :=
  let t := store64 input branchDomain t
  let t := copy left (input+8) 32 t
  let t := copy right (input+40) 32 t
  ServiceHash.sha256At scratch input 72 out t
def publicationAllowed (complete authority live quota : Bool) : Bool := complete && authority && live && quota
theorem incomplete_is_private (authority live quota : Bool) : publicationAllowed false authority live quota = false := by
  cases authority <;> cases live <;> cases quota <;> decide
theorem revoked_never_publishes (complete live quota : Bool) : publicationAllowed complete false live quota = false := by
  cases complete <;> cases live <;> cases quota <;> decide
end Guest.ContentFormat
