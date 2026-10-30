import Guest.Launcher
import Guest.LiveSDK
namespace Guest.LauncherRecoveryProbe
open Guest.LiveSDK
def captured : UInt64 := 0x639000
def failure (t : UInt64) : UInt64 := 64+header 2 0 0 0 0 0 0 t
def cycle (t : UInt64) : UInt64 :=
  let got := stage 192 2 0 t
  if got != 64 || status got != 0 then failure got else
  let handle := result got
  let r := call 64 (header 10 0 0 0 0 0 0 got)
  if r != 64 || status r != 0 then failure r else
  let t := copy (wire+8) captured 24 r
  -- This ordinary caller has Objects127 and no Vault/Launcher authority.
  -- The real Vault206 call is denied by the kernel after the stage exists.
  let failed := Guest.Launcher.restoreChunks handle 192 0 t
  let discarded := Guest.Launcher.discardRecoveredSave handle failed
  let pending := load64 (Guest.Launcher.control+560) discarded
  let r := metadata handle discarded
  let stale := status r
  let r := call 64 (header 10 0 0 0 0 0 0 r)
  if r != 64 || status r != 0 then failure r else
  let count := load64 (wire+8) r
  let bytes := load64 (wire+16) r
  let grants := load64 (wire+24) r
  let t := header 0 handle failed pending count bytes grants r
  let t := copy captured (wire+64) 24 t
  let t := store64 (wire+88) stale t
  128+zero (wire+96) 4 t
partial def serve (t : UInt64) : UInt64 :=
  let n := syscall 31 (self t) 0x410800 1024 0 t
  if n < 96 || n > 1024 then serve n else
  let token := load64 0x410808 n
  let r := if load64 0x410800 n &&& 255 == 1 && n == 96 && load64 0x410820 n == 930 && load64 0x410858 n == 1 then cycle n else failure n
  serve (reply token r r)
def main (t : UInt64) : UInt64 := serve (zero Guest.Launcher.control 128 t)
end Guest.LauncherRecoveryProbe
