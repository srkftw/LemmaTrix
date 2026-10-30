import Guest.Primitives
import Guest.Effects
namespace Guest.LiveSDK
-- ABI2: kernel prepends caller instance, reply token, actual rights and ABI.
def incoming : UInt64 := 0x410000
def command : UInt64 := incoming+32
def wire : UInt64 := 0x411000
def chunk : UInt64 := 0x412000
def digest : UInt64 := 0x413000
def error : UInt64 := 0xffffffffffffffff
partial def copy (src dst n t : UInt64) : UInt64 :=
  if n == 0 then t else
  if n >= 8 && src%8 == 0 && dst%8 == 0 then copy (src+8) (dst+8) (n-8) (store64 dst (load64 src t) t)
  else copy (src+1) (dst+1) (n-1) (store8 dst (load8 src t) t)
partial def zero (p n t : UInt64) : UInt64 :=
  if n == 0 then t else zero (p+8) (n-1) (store64 p 0 t)
def header (op h a b c d e t : UInt64) : UInt64 :=
  let t := store64 wire op t
  let t := store64 (wire+8) h t
  let t := store64 (wire+16) a t
  let t := store64 (wire+24) b t
  let t := store64 (wire+32) c t
  let t := store64 (wire+40) d t
  let t := store64 (wire+48) e t
  store64 (wire+56) 1 t
def call (length t : UInt64) : UInt64 :=
  Effects.run (do
    let answer ← Effects.call 30 ⟨2⟩ ⟨wire⟩ ⟨length⟩ 1024
    return answer.word) t
def status (t : UInt64) : UInt64 := load64 wire t
def result (t : UInt64) : UInt64 := load64 (wire+8) t
def begin (length kind parent hash t : UInt64) : UInt64 :=
  let t := header 1 parent length kind 1 0 0 t
  let t := copy hash (wire+64) 32 t
  call 96 t
def stage (length kind parent t : UInt64) : UInt64 := call 64 (header 1 parent length kind 1 1 0 t)
def append (h offset source length t : UInt64) : UInt64 :=
  if length > 512 then error else
    let t := header 2 h offset 0 0 0 0 t
    let t := copy source (wire+64) length t
    call (64+length) t
def commit (h hash t : UInt64) : UInt64 :=
  let t := header 3 h 0 0 0 0 0 t
  let t := copy hash (wire+64) 32 t
  call 96 t
def read (h offset length t : UInt64) : UInt64 := call 64 (header 4 h offset length 0 0 0 t)
def exportChunk (h offset length t : UInt64) : UInt64 := call 64 (header 14 h offset length 0 0 0 t)
def metadata (h t : UInt64) : UInt64 := call 64 (header 5 h 0 0 0 0 0 t)
-- Brokers receiving a delegated handle verify its actual issuing incarnation;
-- a guessed handle owned by the broker is not another caller's authority.
def checkDelegation (h issuer t : UInt64) : UInt64 := call 64 (header 15 h issuer 0 0 0 0 t)
def share (h recipient rights t : UInt64) : UInt64 := call 64 (header 6 h recipient rights 0 0 0 t)
def revoke (h recipientHandle t : UInt64) : UInt64 := call 64 (header 7 h recipientHandle 0 0 0 0 t)
def drop (h t : UInt64) : UInt64 := call 64 (header 8 h 0 0 0 0 0 t)
-- Release only this caller's reference; other readers and graph pins survive.
def releaseReference (h t : UInt64) : UInt64 := call 64 (header 47 h 0 0 0 0 0 t)
def list (cursor t : UInt64) : UInt64 := call 64 (header 9 0 cursor 0 0 0 0 t)
def abortStage (h t : UInt64) : UInt64 := call 64 (header 13 h 0 0 0 0 0 t)
def stageDigest (h t : UInt64) : UInt64 := call 64 (header 12 h 0 0 0 0 0 t)
def self (t : UInt64) : UInt64 := syscall 35 0 0 0 0 t
def receive (endpoint t : UInt64) : UInt64 :=
  Effects.run (do
    let answer ← Effects.call 31 ⟨endpoint⟩ ⟨incoming⟩ ⟨1024⟩
    return answer.word) t
def reply (token length t : UInt64) : UInt64 :=
  Effects.run (do
    let answer ← Effects.call 32 ⟨token⟩ ⟨wire⟩ ⟨length⟩
    return answer.word) t
def console (p n t : UInt64) : UInt64 := syscall 1 0 p n 0 t
end Guest.LiveSDK
