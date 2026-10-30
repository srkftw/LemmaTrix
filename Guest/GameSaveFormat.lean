import Guest.LiveSDK
import Guest.CrateModel
namespace Guest.GameSaveFormat
open Guest.LiveSDK
-- Structural schema1 boundary shared by trusted selected-save retention and
-- recovery. The game additionally checks the exact selected pack/level walls,
-- goals and crate count before loading; a retained save is not an executable.
partial def allZero (p n t : UInt64) : Bool :=
  if n == 0 then true else load8 p t == 0 && allZero (p+1) (n-1) t
def valid (p t : UInt64) : Bool :=
  let boxes := load64 (p+104) t
  let player := load64 (p+112) t
  load64 p t == 0x3156415343544c && load64 (p+8) t == 1 &&
  !allZero (p+16) 32 t && !allZero (p+48) 32 t &&
  (load64 (p+80) t == 1 || load64 (p+80) t == 2) &&
  load64 (p+88) t < 8 && load64 (p+96) t <= 0xffffffff &&
  player < 64 && !CrateModel.occupied boxes player &&
  CrateModel.count boxes 0 0 > 0 && CrateModel.count boxes 0 0 <= 8 &&
  load64 (p+120) t < 256 && allZero (p+128) 64 t
end Guest.GameSaveFormat
