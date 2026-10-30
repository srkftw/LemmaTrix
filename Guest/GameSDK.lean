import Guest.LiveSDK
namespace Guest.GameSDK
open Guest.LiveSDK
-- Game-v1: the endpoint is the selected full game process incarnation. The
-- kernel grants no arbitrary application endpoint access from these wrappers.
-- Pack/save handles must already be explicitly shared to that incarnation.
def request (endpoint operation handle t : UInt64) : UInt64 :=
  let t := header operation handle 0 0 0 0 0 t
  Guest.syscall 30 endpoint wire 64 1024 t
-- inspect returns160: generation, selected level, moves, completed mask,
-- won, undo depth and schema1; gameID32, packSHA25632, boxes/player/save handle.
def inspect (endpoint t : UInt64) : UInt64 := request endpoint 500 0 t
def loadLevelPack (endpoint scopedReadHandle t : UInt64) : UInt64 := request endpoint 501 scopedReadHandle t
-- Returns an exact caller-bound immutable save grant with rights restricted to
-- caller's read/share/revoke profile. It is ephemeral until separately retained.
def exportSave (endpoint t : UInt64) : UInt64 := request endpoint 502 0 t
def loadSave (endpoint scopedReadHandle t : UInt64) : UInt64 := request endpoint 503 scopedReadHandle t
end Guest.GameSDK
