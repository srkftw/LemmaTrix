import Guest.Devices
namespace Guest
partial def purposeFill (offset t : UInt64) : UInt64 :=
  if offset == 512 then t else purposeFill (offset+1) (store8 (Devices.blockBuffer+offset) ((offset*173+47) &&& 255) t)
partial def purposeCheck (offset t : UInt64) : Bool :=
  if offset == 512 then true else load8 (Devices.blockBuffer+offset) t == 0 && purposeCheck (offset+1) t

def storagePurposeMain (initial : UInt64) : UInt64 :=
  let t := Devices.init initial
  if Devices.capacityPurpose 1 t != 512 || Devices.capacityPurpose 2 t != 1024 then finish 1 else
  let t := purposeFill 0 t
  let base := load64 (Devices.state+80) t
  let t := store32 (base+0x14) 0 t
  let readonly := load32 (base+0x10) t &&& 32 != 0
  let written := Devices.blockPurpose 2 1 3 Devices.blockBuffer 512 t
  if readonly then
    if written != Devices.error then finish 1 else finish (store8 0x10000000 68 t)
  else if written != 0 then finish 1 else
  if Devices.blockPurpose 2 4 0 Devices.blockBuffer 0 t != 0 then finish 1 else
  if Devices.blockPurpose 1 0 3 Devices.blockBuffer 512 t != 0 then finish 1 else
  if !purposeCheck 0 t then finish 1 else
  let t := store8 0x10000000 83 t
  finish t
end Guest
