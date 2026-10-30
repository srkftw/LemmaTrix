import Guest.Devices
namespace Guest.AudioDevice
-- PCM2 uses the explicitly bound non-console virtio-serial port1 at MMIO slot7.
-- It is independent of the network console. Payload is decoded stereo S16LE
-- at48000Hz. One descriptor, at most1024 bytes, may be in flight.
def base : UInt64 := 0x10008000
def state : UInt64 := 0x80e26000
def queue : UInt64 := 0x80e28000
def buffer : UInt64 := 0x80e2a000
def controlRX : UInt64 := 0x80e2c000
def controlTX : UInt64 := 0x80e2e000
def controlIn : UInt64 := 0x80e30000
def controlOut : UInt64 := 0x80e30400
def control : UInt64 := state+32
def error : UInt64 := 0xffffffffffffffff
def available (t : UInt64) : Bool :=
  Guest.load32 base t == 0x74726976 && Guest.load32 (base+4) t == 2 && Guest.load32 (base+8) t == 3

def reset (t : UInt64) : UInt64 :=
  if !available t then error else
  let t := Guest.store32 (base+0x70) 0 t
  if Guest.Devices.awaitReset base 10000 t == error then error else
  let epoch := Guest.load64 (state+8) t+1
  let t := Guest.Devices.clear state 32 t
  let t := Guest.store64 (state+8) epoch t
  let t := Guest.Devices.clear buffer 128 t
  let t := Guest.Devices.clear controlIn 128 t
  let t := Guest.Devices.clear controlOut 1 t
  let t := Guest.Devices.portConfigure control base controlRX controlTX controlIn controlOut 0x00316d63702d746c t
  let t := Guest.store32 (base+0x70) 3 t
  let t := Guest.store32 (base+0x14) 0 t
  if Guest.load32 (base+0x10) t &&& 2 == 0 || Guest.load32 (base+0x104) t < 2 then error else
  let t := Guest.store32 (base+0x14) 1 t
  if Guest.load32 (base+0x10) t &&& 1 == 0 then error else
  let t := Guest.store32 (base+0x24) 0 t
  let t := Guest.store32 (base+0x20) 2 t
  let t := Guest.store32 (base+0x24) 1 t
  let t := Guest.store32 (base+0x20) 1 t
  let t := Guest.store32 (base+0x70) 11 t
  if Guest.load32 (base+0x70) t &&& 8 == 0 then error else
  let t := Guest.Devices.streamQueue base 5 queue t
  if t == error then error else
  let t := Guest.Devices.streamQueue base 2 controlRX t
  if t == error then error else
  let t := Guest.Devices.streamQueue base 3 controlTX t
  if t == error then error else
  let t := Guest.Devices.portPost control 0 t
  let t := Guest.deviceFence t
  let t := Guest.store32 (base+0x70) 15 t
  let t := Guest.Devices.portSend control 0 0 1 t
  if t == error then error else
  let t := Guest.Devices.portPump control 8 t
  if t == error || Guest.load64 (control+64) t != 7 then error else
  Guest.Devices.portSend control 1 6 1 t
def acquire (owner t : UInt64) : UInt64 :=
  if Guest.load64 state t != 0 then error else
  let t := reset t
  if t == error then error else
  let t := Guest.store64 state owner t
  Guest.load64 (state+8) t
def valid (owner epoch t : UInt64) : Bool :=
  if owner == 0 || Guest.load64 state t != owner || Guest.load64 (state+8) t != epoch ||
    !available t || Guest.load32 (base+0x70) t != 15 then false else
  let t := Guest.Devices.portPump control 8 t
  t != error && Guest.load64 (control+64) t == 7
def ready (t : UInt64) : Bool :=
  -- Interpreters retry a throttled descriptor on notification; QEMU also
  -- resumes it through the chardev writable event. Neither consumes a short
  -- write as a complete descriptor.
  let t := Guest.store32 (base+0x50) 5 t
  let t := Guest.deviceFence t
  Guest.Devices.read16 (queue+4098) t == Guest.load64 (state+16) t
def write (owner epoch source n t : UInt64) : UInt64 :=
  if !valid owner epoch t || n == 0 || n > 1024 || n%4 != 0 then error else
  let t := Guest.store32 (base+0x50) 5 t
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
  n+Guest.store32 (base+0x50) 5 t
def close (owner epoch t : UInt64) : UInt64 :=
  -- A disconnected host or failed device must not strand the current owner.
  -- Exact ownership still authorizes cancellation; reset acknowledgement is
  -- required before any private DMA storage is cleared or reused.
  if owner == 0 || Guest.load64 state t != owner || Guest.load64 (state+8) t != epoch ||
    !available t then error else reset t
def died (owner t : UInt64) : UInt64 :=
  if Guest.load64 state t == owner then reset t else t
end Guest.AudioDevice
