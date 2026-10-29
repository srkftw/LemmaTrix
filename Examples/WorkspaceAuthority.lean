import Guest.LiveSDK
namespace Examples.WorkspaceAuthority
open Guest Guest.LiveSDK
def state : UInt64 := 0x600000
-- A test-only ordinary installed compartment. It has display/input but neither
-- Launcher authority nor access to another app's pixels or physical events.
def denied (value bit t : UInt64) : UInt64 :=
  store64 (state+8) ((load64 (state+8) t) ||| (if value == error then bit else 0)) t
def check (stale t : UInt64) : UInt64 :=
  let own := load64 state t
  let t := store64 (state+8) 0 t
  let r := syscall 85 own 0 0 0 t
  let t := denied r 1 r
  let r := syscall 86 0 0x410800 4 0 t
  let t := denied r 2 r
  let r := syscall 93 0 0x410800 4 0 t
  let t := denied r 4 r
  let r := syscall 81 (own+1) 0x410800 4 0 t
  let t := denied r 8 r
  let r := syscall 81 own 0x410800 4 901120 t
  let t := denied r 16 r
  let r := syscall 81 own 0x80f00000 4 0 t
  let t := denied r 32 r
  let r := syscall 90 (own+1) 0 0 0 t
  let t := denied r 64 r
  let r := syscall 89 0x1001c00000001 0 1 0 t
  let t := denied r 128 r
  let r := syscall 98 1 0 0 0 t
  let t := denied r 256 r
  let t := header 23 0 0 0 0 0 0 t
  let r := syscall 30 1 wire 64 1024 t
  let t := denied r 512 r
  let shell := syscall 97 4 0 0 0 t
  let t := header 23 0 0 0 0 0 0 t
  let r := syscall 30 shell wire 64 1024 t
  let t := store64 (state+8) ((load64 (state+8) r) ||| (if r == error || status r != 0 then 1024 else 0)) r
  let r := syscall 81 stale 0x410800 4 0 t
  let t := denied r 2048 r
  let mask := load64 (state+8) t
  let t := zero wire 8 t
  let t := store64 (wire+8) mask t
  let t := store64 (wire+16) own t
  Guest.Effects.effectValue 64 t
partial def serve (endpoint t : UInt64) : UInt64 :=
  let n := receive endpoint t
  if n == error then serve endpoint n else
    let token := load64 (incoming+8) n
    let r := check (load64 (command+8) n) n
    serve endpoint (reply token r r)
def main (initial : UInt64) : UInt64 :=
  let surface := syscall 80 0 0 0 0 initial
  if surface == error then syscall 10 1 0 0 0 surface else
    let t := store64 state surface surface
    serve (self t) t
end Examples.WorkspaceAuthority
