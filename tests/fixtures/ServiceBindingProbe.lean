import Guest.LiveSDK
import Guest.ServiceSHA256
namespace Guest.ServiceBindingProbe
open Guest.LiveSDK
def report (a b c d e f g t : UInt64) : UInt64 := 64+header a b c d e f g t
-- The test never returns the entropy seed; only a public digest and syscall status.
def inspectSeed (token t : UInt64) : UInt64 :=
  let authorized := syscall 131 token 0 0 0 t
  let badToken := syscall 131 (token+1) 0 0 0 authorized
  let rng := syscall 130 0 0x600000 32 0 badToken
  let invalidSize := syscall 130 0 0x600000 31 0 rng
  let invalidRegion := syscall 130 0 wire 32 0 invalidSize
  let net := syscall 101 0 0 0 0 invalidRegion
  let vault := syscall 63 0 wire 32 0 net
  let t := Guest.ServiceHash.sha256At 0x601000 0x600000 32 0x600040 vault
  let t := zero 0x600000 4 t
  -- Controlled nonsecret markers verify full domain teardown on slot reuse.
  let t := store64 0x41f000 0x1122334455667788 t
  let t := store64 0x600100 0x1122334455667788 t
  let t := store64 0x7ffff8 0x1122334455667788 t
  let t := store64 0x430000 0x1122334455667788 t
  let t := header authorized badToken rng invalidSize invalidRegion net vault t
  let t := copy 0x600040 (wire+64) 32 t
  96+zero 0x601000 80 (zero 0x600040 4 t)
partial def serviceLoop (t : UInt64) : UInt64 :=
  let n := receive (self t) t
  if n != 96 then serviceLoop n else
  let token := load64 (incoming+8) n
  let op := load64 command n
  let r := if op == 400 then inspectSeed token n
    else if op == 401 then report 0 (load64 0x41f000 n) (load64 0x600100 n)
      (load64 0x7ffff8 n) (load64 0x430000 n) 0 0 n
    else report 0 op (syscall 131 token 0 0 0 n) 0 0 0 0 n
  serviceLoop (reply token r r)
def serviceMain (t : UInt64) : UInt64 := serviceLoop (zero 0x600000 16 t)
partial def clientLoop (t : UInt64) : UInt64 :=
  let n := receive (self t) t
  if n != 96 then clientLoop n else
  let token := load64 (incoming+8) n
  let op := load64 command n
  let service := syscall 128 1 400 0 0 n
  let r := if op == 900 && service != error then
      syscall 30 service wire 64 1024 (header 400 0 0 0 0 0 0 service)
    else report service (syscall 130 0 0x600000 32 0 n) 0 0 0 0 0 n
  clientLoop (reply token (if r == error then 64 else r) r)
def clientMain (t : UInt64) : UInt64 := clientLoop t
end Guest.ServiceBindingProbe
