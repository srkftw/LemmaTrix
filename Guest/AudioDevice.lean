import Guest.Devices
namespace Guest.AudioDevice
-- PCM1 uses the explicitly bound modern virtio-console at MMIO slot7.
-- It is independent of the network console. Payload is decoded stereo S16LE
-- at48000Hz. One descriptor, at most1024 bytes, may be in flight.
def base : UInt64 := 0x10008000
def state : UInt64 := 0x80e26000
def queue : UInt64 := 0x80e28000
def buffer : UInt64 := 0x80e2a000
def error : UInt64 := 0xffffffffffffffff
def available (t : UInt64) : Bool :=
  Guest.load32 base t == 0x74726976 && Guest.load32 (base+4) t == 2 && Guest.load32 (base+8) t == 3
def reset (t : UInt64) : UInt64 :=
  if !available t then error else
  let t := Guest.store32 (base+0x70) 0 t
  if Guest.Devices.awaitReset base 10000 t == error then error else
  let epoch := Guest.load64 (state+8) t+1
  let t := Guest.Devices.clear state 16 t
  let t := Guest.store64 (state+8) epoch t
  let t := Guest.Devices.clear buffer 128 t
  let t := Guest.store32 (base+0x70) 3 t
  let t := Guest.store32 (base+0x14) 1 t
  if Guest.load32 (base+0x10) t &&& 1 == 0 then error else
  let t := Guest.store32 (base+0x24) 0 t
  let t := Guest.store32 (base+0x20) 0 t
  let t := Guest.store32 (base+0x24) 1 t
  let t := Guest.store32 (base+0x20) 1 t
  let t := Guest.store32 (base+0x70) 11 t
  if Guest.load32 (base+0x70) t &&& 8 == 0 then error else
  let t := Guest.Devices.streamQueue base 1 queue t
  if t == error then error else Guest.store32 (base+0x70) 15 t
def acquire (owner t : UInt64) : UInt64 :=
  if Guest.load64 state t != 0 then error else
  let t := reset t
  if t == error then error else
  let t := Guest.store64 state owner t
  Guest.load64 (state+8) t
def valid (owner epoch t : UInt64) : Bool :=
  owner != 0 && Guest.load64 state t == owner && Guest.load64 (state+8) t == epoch &&
  available t && Guest.load32 (base+0x70) t == 15
def ready (t : UInt64) : Bool :=
  Guest.Devices.read16 (queue+4098) t == Guest.load64 (state+16) t
def write (owner epoch source n t : UInt64) : UInt64 :=
  if !valid owner epoch t || n == 0 || n > 1024 || n%4 != 0 then error else
  let t := Guest.store32 (base+0x50) 1 t
  let t := Guest.deviceFence t
  if !ready t then 0 else
  let count := Guest.load64 (state+16) t
  let t := Guest.Devices.bytesCopy source buffer n t
  let t := Guest.Devices.descriptor queue buffer n 0 0 t
  let t := Guest.Devices.write16 (queue+132+(count%8)*2) 0 t
  let next := (count+1)%65536
  let t := Guest.deviceFence t
  let t := Guest.Devices.write16 (queue+130) next t
  let t := Guest.store64 (state+16) next t
  let t := Guest.store64 (state+24) (Guest.load64 (state+24) t+n/4) t
  let t := Guest.deviceFence t
  n+Guest.store32 (base+0x50) 1 t
def close (owner epoch t : UInt64) : UInt64 :=
  if !valid owner epoch t then error else reset t
def died (owner t : UInt64) : UInt64 :=
  if Guest.load64 state t == owner then reset t else t
end Guest.AudioDevice
