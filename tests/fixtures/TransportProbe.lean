import Guest.Devices
namespace Guest
partial def probeDrain (fuel t : UInt64) : UInt64 :=
  if fuel == 0 then finish 1 else
  let base := load64 (Devices.state+32) t
  let t := store32 (base+0x50) 5 t
  let t := deviceFence t
  if Devices.read16 (Devices.streamTX+4098) t == load64 (Devices.state+72) t then t
  else probeDrain (fuel-1) t
partial def probeWrite (p n fuel t : UInt64) : UInt64 :=
  if fuel == 0 then finish 1 else
  let sent := Devices.streamWrite p n t
  if sent == Devices.error then finish 1 else
  if sent == 0 then probeWrite p n (fuel-1) t else sent
partial def probeLoop (remaining fuel t : UInt64) : UInt64 :=
  if remaining == 0 then
    -- The last accepted TX must complete before terminating the machine.
    let t := probeDrain 100000 t
    let t := store8 0x10000000 78 (store8 0x10000000 79 t)
    finish t
  else if fuel == 0 then finish 1 else
  let count := Devices.streamRead 0x80e26000 (if remaining < 113 then remaining else 113) t
  if count == Devices.error then finish 1 else
  if count == 0 then probeLoop remaining (fuel-1) t else
  let sent := probeWrite 0x80e26000 count 100000 t
  if sent != count then finish 1 else probeLoop (remaining-count) fuel t

def transportMain (initial : UInt64) : UInt64 :=
  let t := Devices.init initial
  if Devices.streamStatus t == Devices.error || Devices.streamStatus t == 0 then finish 1 else
  let epoch := Devices.streamStatus t >>> 32
  let t := Devices.streamInit t
  if Devices.streamStatus t >>> 32 != epoch+1 then finish 1 else
  let t := store8 0x10000000 82 t
  probeLoop 4097 1000000 t
end Guest
