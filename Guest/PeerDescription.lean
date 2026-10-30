import Guest.LiveSDK
import Guest.ServiceSignature
import Guest.ProjectGraph
namespace Guest.PeerDescription
open Guest.LiveSDK
-- Public, independently verifiable service material. The pairwise PSK remains
-- separate. Only explicit management provisioning can select this public pin.
def publicKey : UInt64 := 0x634000
def description : UInt64 := 0x634100
def signature : UInt64 := 0x634300
def hashes : UInt64 := 0x634500
def st : UInt64 := 0x634600
def magic : UInt64 := 0x315653444e544c
def equal (a b n t : UInt64) : Bool := Guest.ProjectGraph.equal a b n t
def response (code t : UInt64) : UInt64 := 64+store64 wire code (zero wire 8 t)
def verified (t : UInt64) : Bool := load64 st t == 2
def selected (t : UInt64) : Bool := load64 st t != 0
partial def endpointText (i n t : UInt64) : Bool :=
  if i == n then true else
    let c := load8 (description+168+i) t
    c >= 33 && c <= 126 && endpointText (i+1) n t
-- maxGrant/maxRate are the bounded broker profile; not a promise of available
-- bandwidth. Endpoint text is a declared numeric endpoint, never guest DNS.
def valid (t : UInt64) : Bool :=
  let kind := load64 (description+16) t
  let n := load64 (description+160) t
  let version := load64 (description+8) t
  let profile := (version == (if kind <= 4 then 1 else 2) && load64 (description+48) t == 16777216) ||
    (kind >= 5 && version == 3 && load64 (description+48) t == 134217728)
  load64 description t == magic && profile && kind >= 1 && kind <= 6 &&
  load64 (description+24) t == 3 && load64 (description+32) t == (if kind <= 2 then 2 else if kind <= 4 then 6 else 4) &&
  load64 (description+40) t == 720 && load64 (description+56) t == 65536 &&
  !Guest.ProjectGraph.allZero (description+64) 32 t && !Guest.ProjectGraph.allZero (description+96) 32 t &&
  !equal (description+64) (description+96) 32 t && equal hashes (description+96) 32 t &&
  n > 0 && n <= 96 && endpointText 0 n t && Guest.ProjectGraph.allZero (description+168+n) (96-n) t &&
  Guest.ProjectGraph.allZero (description+264) 248 t

def stage (length t : UInt64) : UInt64 :=
  let t := store64 st 3 (zero st 8 t)
  if length != 832 || (load8 (command+64) t &&& 128) == 0 || (load8 (command+319) t &&& 1) == 0 then response 2 t else
    let t := copy (command+64) publicKey 256 t
    let t := copy (command+320) description 512 t
    let t := Guest.ServiceHash.sha256At 0x600200 publicKey 256 hashes t
    if !valid t then response 2 t else response 0 (store64 st 1 t)
def confirm (length t : UInt64) : UInt64 :=
  if length != 320 || load64 st t != 1 then response 3 t else
    let t := copy (command+64) signature 256 t
    if !Guest.ServiceSignature.verify description 512 signature publicKey t then response 5 (store64 st 3 t) else
      let t := Guest.ServiceHash.sha256At 0x600200 description 512 (hashes+32) t
      response 0 (store64 st 2 t)
def matchesPins (material t : UInt64) : Bool :=
  verified t && equal material (description+64) 64 t && equal (material+64) (hashes+32) 32 t
def permits (operation t : UInt64) : Bool :=
  !verified t || (operation < 64 && (load64 (description+32) t &&& (1 <<< operation)) != 0)
end Guest.PeerDescription
