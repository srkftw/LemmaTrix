import Guest.LiveSDK
namespace Guest.ContentSDK
open Guest.LiveSDK
-- Endpoint5, Content-v1. Grants/jobs are local incarnation-bound handles and
-- must never be serialized as remote protocol request identities.
def callContent (length t : UInt64) : UInt64 := syscall 30 5 wire length 1024 t
-- binding=manifest256, manifestSHA25632, providerID32, federationID32.
-- operation is a caller-chosen idempotency word; mode is the positive enum3.
-- All personal content here is volatile. Durable=true is rejected until the
-- selected authenticated chunk-vault transaction is available.
def reserve (binding operation budget mode durable t : UInt64) : UInt64 :=
  let t := header 300 0 operation budget mode durable 0 t
  callContent 416 (copy binding (wire+64) 352 t)
-- proof=rawSHA25632 followed by exactly depth*32 sibling bytes.
def beginChunk (content index proof proofBytes t : UInt64) : UInt64 :=
  if proofBytes > 384 then error else
    let t := header 301 content index 0 0 0 0 t
    callContent (64+proofBytes) (copy proof (wire+64) proofBytes t)
def append (job offset source length t : UInt64) : UInt64 :=
  if length == 0 || length > 512 then error else
    let t := header 302 job offset 0 0 0 0 t
    callContent (64+length) (copy source (wire+64) length t)
def validate (job t : UInt64) : UInt64 := callContent 64 (header 303 job 0 0 0 0 0 t)
def inspectJob (job t : UInt64) : UInt64 := callContent 64 (header 304 job 0 0 0 0 0 t)
-- action1 pause,2 resume/retry,3 cancel. Completion stays queryable until
-- action4 forget; timeout alone never undoes a committed chunk/root.
def control (job action t : UInt64) : UInt64 := callContent 64 (header 305 job action 0 0 0 0 t)
def describe (content t : UInt64) : UInt64 := callContent 64 (header 306 content 0 0 0 0 0 t)
def read (content offset count t : UInt64) : UInt64 := callContent 64 (header 307 content offset count 0 0 0 t)
def share (content recipient t : UInt64) : UInt64 := callContent 64 (header 308 content recipient 0 0 0 0 t)
def release (content t : UInt64) : UInt64 := callContent 64 (header 309 content 0 0 0 0 0 t)
def publish (content t : UInt64) : UInt64 := callContent 64 (header 310 content 0 0 0 0 0 t)
def revokeAcquisition (content t : UInt64) : UInt64 := callContent 64 (header 311 content 0 0 0 0 0 t)
def collect (t : UInt64) : UInt64 := callContent 64 (header 312 0 0 0 0 0 0 t)
-- Selected, validated chunk only (root may be private/partial). Returns rawSHA25632 followed by exactly
-- manifest.depth sibling hashes, suitable for a fresh authorized peer stream.
def proof (content index t : UInt64) : UInt64 := callContent 64 (header 313 content index 0 0 0 0 t)
def reauthorize (content providerFederationManifest t : UInt64) : UInt64 :=
  let t := header 314 content 0 0 0 0 0 t
  callContent 160 (copy providerFederationManifest (wire+64) 96 t)
def adopt (checkpoint operation budget binding t : UInt64) : UInt64 :=
  let t := header 315 checkpoint operation budget 3 0 0 t
  callContent 160 (copy binding (wire+64) 96 t)
def checkDelegation (content issuer t : UInt64) : UInt64 := callContent 64 (header 316 content issuer 0 0 0 0 t)
end Guest.ContentSDK
