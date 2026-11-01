import Guest.LiveSDK
namespace Guest.FeedAccountSDK
open Guest.LiveSDK
-- Account-v1: scoped public event requests; the graphical caller never sees a
-- Feed seed, a signer permit, a Network capability or an unrestricted vault.
def invoke (action h a b c payload bytes t : UInt64) : UInt64 :=
  let target := syscall 128 5 480 0 0 t
  if target == error || bytes > 896 then error else
  let t := header 480 action h a b c 0 target
  syscall 30 target wire (64+bytes) 1024 (copy payload (wire+64) bytes t)
def submit (action h a b c payload bytes t : UInt64) : UInt64 :=
  let target := syscall 128 5 480 0 0 t
  if target == error || bytes > 896 then error else
  let t := header 480 action h a b c 0 target
  syscall 133 target wire (64+bytes) 1024 (copy payload (wire+64) bytes t)
def collect (token t : UInt64) : UInt64 := syscall 134 token wire 1024 0 t
def cancel (token t : UInt64) : UInt64 := syscall 135 token 0 0 0 t
def inspect (t : UInt64) : UInt64 := invoke 0 0 0 0 0 0 0 t
def create (scope t : UInt64) : UInt64 := invoke 1 0 0 0 0 scope 64 t
def beginDraft (kind bytes references t : UInt64) : UInt64 := invoke 2 kind bytes 0 0 references 96 t
def appendDraft (offset source bytes t : UInt64) : UInt64 := invoke 3 offset 0 0 0 source bytes t
def publish (t : UInt64) : UInt64 := invoke 4 0 0 0 0 0 0 t
def timeline (cursor t : UInt64) : UInt64 := invoke 5 cursor 0 0 0 0 0 t
def read (event offset t : UInt64) : UInt64 := invoke 6 offset 512 0 0 event 32 t
def preference (kind enabled author t : UInt64) : UInt64 := invoke 7 kind enabled 0 0 author 32 t
def lock (t : UInt64) : UInt64 := invoke 9 0 0 0 0 0 0 t
def retry (t : UInt64) : UInt64 := invoke 10 0 0 0 0 0 0 t
def exportPortable (includePreferences t : UInt64) : UInt64 := invoke 12 includePreferences 0 0 0 0 0 t
def importPortable (object t : UInt64) : UInt64 := invoke 13 object 0 0 0 0 0 t
def retention (mode credential t : UInt64) : UInt64 := invoke 14 mode 0 0 0 credential 32 t
def outcome (t : UInt64) : UInt64 := invoke 16 0 0 0 0 0 0 t
def cancelWork (t : UInt64) : UInt64 := invoke 17 0 0 0 0 0 0 t
end Guest.FeedAccountSDK
