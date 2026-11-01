import Guest.LiveSDK
namespace Guest.FeedRetentionSDK
open Guest.LiveSDK
-- Only the explicitly selected Feed owner can reach these Objects-domain3
-- records. The Vault must already be unlocked by its separate Objects policy.
def invoke (op action a b length t : UInt64) : UInt64 :=
  syscall 30 3 wire length 1024 (header op action a b 0 0 0 t)
def begin (bytes hash t : UInt64) : UInt64 :=
  let t := copy hash (wire+64) 32 t
  invoke 277 0 bytes 0 96 t
def append (offset source bytes t : UInt64) : UInt64 :=
  if bytes == 0 || bytes > 512 then error else
  invoke 277 1 offset 0 (64+bytes) (copy source (wire+64) bytes t)
def commit (t : UInt64) : UInt64 := invoke 277 2 0 0 64 t
def cancel (t : UInt64) : UInt64 := invoke 277 3 0 0 64 t
def recover (t : UInt64) : UInt64 := invoke 278 0 0 0 64 t
def read (offset bytes t : UInt64) : UInt64 := invoke 278 1 offset bytes 64 t
def lock (t : UInt64) : UInt64 := invoke 277 4 0 0 64 t
def forget (t : UInt64) : UInt64 := invoke 279 0 0 0 64 t
end Guest.FeedRetentionSDK
