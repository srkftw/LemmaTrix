import Guest.LiveSDK
import Guest.LiveMemory
import Guest.ServiceHash
namespace Guest.IntentConsent
open Guest.LiveSDK
def state : UInt64 := 0x6f0000
def snapshot : UInt64 := 0x6f0100
def proposalHash : UInt64 := 0x6f0200
def answer (code bytes t : UInt64) : UInt64 :=
  let t := header code 0 0 0 0 0 0 t
  let t := if bytes == 160 then copy snapshot (wire+64) 128 t else t
  let t := if bytes == 160 then copy proposalHash (wire+192) 32 t else t
  let n := 64+bytes
  n+copy wire 0x410000 n t
def prepare (length t : UInt64) : UInt64 :=
  if length != 16 then answer 2 0 t else
  let app := load64 0x410000 t
  let role := load64 0x410008 t
  let r := syscall 160 app role wire 128 t
  if r != 128 then answer 3 0 r else
  let t := copy wire snapshot 128 r
  let t := Guest.ServiceHash.sha256At 0x600200 snapshot 128 proposalHash t
  answer 0 160 (store64 state 1 t)
def approve (length t : UInt64) : UInt64 :=
  if length != 32 || load64 state t != 1 || !Guest.LiveMemory.equal 0x410000 proposalHash 32 t then answer 3 0 t else
  let t := store64 state 0 t
  let r := syscall 160 (load64 snapshot t) (load64 (snapshot+16) t) wire 128 t
  if r != 128 || !Guest.LiveMemory.equal wire snapshot 128 r then answer 3 0 r else
  -- This is precisely the existing exact release/incarnation/generation grant
  -- operation. Consent grants only482 or436, never an owner protocol.
  let t := zero wire 16 r
  let t := store64 wire 1 t
  let t := store64 (wire+8) (load64 (snapshot+16) t) t
  let t := store64 (wire+16) (load64 (snapshot+8) t) t
  let t := store64 (wire+24) (load64 snapshot t) t
  let t := store64 (wire+32) (load64 (snapshot+24) t) t
  let t := store64 (wire+40) (load64 (snapshot+32) t) t
  let t := copy (snapshot+64) (wire+48) 64 t
  let r := syscall 127 0 wire 128 0 t
  answer (if r == error then 3 else 0) 0 r
def dispatch (op length t : UInt64) : UInt64 :=
  if op == 194 then prepare length t else if op == 195 then approve length t else answer 2 0 t
end Guest.IntentConsent
