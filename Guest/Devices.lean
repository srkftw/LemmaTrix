import Guest.Primitives
import Guest.DevicePrimitives
namespace Guest.Devices
-- Reserved supervisor-only DMA region. Applications never supply DMA addresses.
def state : UInt64 := 0x80e05000
def blockQueue : UInt64 := 0x80e00000
def randomQueue : UInt64 := 0x80e02000
def blockBuffer : UInt64 := 0x80e08000
def randomBuffer : UInt64 := 0x80e0a000
def request : UInt64 := 0x80e04000
def statusByte : UInt64 := 0x80e04020
def error : UInt64 := 0xffffffffffffffff

def read16 (p token : UInt64) : UInt64 := load8 p token + (load8 (p+1) token)*256
def write16 (p value token : UInt64) : UInt64 :=
  store8 (p+1) ((value >>> 8) &&& 255) (store8 p (value &&& 255) token)
partial def clear (p words token : UInt64) : UInt64 :=
  if words == 0 then token else clear (p+8) (words-1) (store64 p 0 token)
partial def discover (index token : UInt64) : UInt64 :=
  if index == 8 then token else
    let base := 0x10001000+index*4096
    let version := load32 (base+4) token
    let valid := load32 base token == 0x74726976 && (version == 1 || version == 2)
    let id := if valid then load32 (base+8) token else 0
    let token := if id == 2 then
      let count := load64 (state+96) token
      if count >= 8 then token else
      let token := store64 (state+128+count*8) base token
      store64 (state+96) (count+1) token
      else token
    let token := if id == 3 && base != 0x10008000 && version == 2 && load64 (state+32) token == 0 then store64 (state+32) base token else token
    let token := if id == 4 then store64 (state+8) base token else token
    discover (index+1) token

partial def awaitReset (base remaining token : UInt64) : UInt64 :=
  if load32 (base+0x70) token == 0 then 0 else
    if remaining == 0 then error else awaitReset base (remaining-1) token

def setup (base queue token : UInt64) : UInt64 :=
  if base == 0 then token else
    let token := store32 (base+0x70) 0 token
    let reset := awaitReset base 1000000 token
    if reset == error then
      let token := store32 (base+0x70) ((load32 (base+0x70) reset) ||| 128) reset
      error+token
    else
    -- Reset acknowledgment precedes touching the previous DMA ring or bounce
    -- descriptors. A timed-out old request cannot overlap reinitialization.
    let token := clear queue 1024 reset
    let token := store32 (base+0x70) 1 token
    let token := store32 (base+0x70) 3 token
    let token := store32 (base+0x14) 0 token
    let features := load32 (base+0x10) token &&& 0x220
    let token := store32 (base+0x24) 0 token
    let token := store32 (base+0x20) features token
    let modern := load32 (base+4) token == 2
    let token := if modern then
      let token := store32 (base+0x14) 1 token
      let supported := load32 (base+0x10) token
      if supported &&& 1 == 0 then store32 (base+0x70) 128 token else
      let token := store32 (base+0x24) 1 token
      let token := store32 (base+0x20) 1 token
      store32 (base+0x70) 11 token
      else store32 (base+0x28) 4096 token
    let token := store32 (base+0x30) 0 token
    if load32 (base+0x34) token < 8 || (modern && (load32 (base+0x70) token &&& 8) == 0) then
      store32 (base+0x70) 128 token
    else
    let token := store32 (base+0x38) 8 token
    let token := if modern then
      let token := store32 (base+0x80) queue token
      let token := store32 (base+0x84) 0 token
      let token := store32 (base+0x90) (queue+128) token
      let token := store32 (base+0x94) 0 token
      let token := store32 (base+0xa0) (queue+4096) token
      let token := store32 (base+0xa4) 0 token
      store32 (base+0x44) 1 token
      else
      let token := store32 (base+0x3c) 4096 token
      store32 (base+0x40) (queue >>> 12) token
    let token := store32 (base+0x70) 15 token
    store64 (queue+128) 1 token

def descriptor (p address length flags next token : UInt64) : UInt64 :=
  let token := store64 p address token
  store64 (p+8) (length + flags*0x100000000 + next*0x1000000000000) token

partial def wait (base used expected remaining token : UInt64) : UInt64 :=
  if remaining == 0 then error else
  if (load32 (base+0x70) token &&& 192) != 0 then error else
  if read16 (used+2) token == expected then 0 else wait base used expected (remaining-1) token

def submit (base queue counter token : UInt64) : UInt64 :=
  -- A timed-out request may still own its DMA buffers. Refuse further work
  -- until init explicitly resets the transport and queue together.
  if base == 0 || (load32 (base+0x70) token &&& 192) != 0 then error else
  let index := load64 counter token
  let expected := (index+1) &&& 65535
  let token := write16 (queue+132+(index &&& 7)*2) 0 token
  let token := deviceFence token
  let token := write16 (queue+130) expected token
  let token := store64 counter expected token
  let token := deviceFence token
  let token := store32 (base+0x50) 0 token
  let result := wait base (queue+4096) expected 1000000 token
  let token := deviceFence result
  if result == error then
    let token := store32 (base+0x70) ((load32 (base+0x70) token) ||| 128) token
    error+token
  else
    let token := store32 (base+0x64) 1 token
    result+token

def capacityPurpose (purpose token : UInt64) : UInt64 :=
  let base := load64 (if purpose == 1 then state else state+80) token
  if base == 0 then 0 else load32 (base+0x100) token + (load32 (base+0x104) token)*0x100000000

def blockPurpose (purpose operation sector buffer bytes token : UInt64) : UInt64 :=
  let base := load64 (if purpose == 1 then state else state+80) token
  let queue := if purpose == 1 then blockQueue else 0x80e0c000
  let counter := if purpose == 1 then state+16 else state+88
  let supported := operation == 0 || operation == 1 || operation == 4
  let bounded := buffer >= blockBuffer && buffer <= blockBuffer+4096 && bytes <= 4096 && bytes <= blockBuffer+4096-buffer
  let count := bytes / 512
  let total := capacityPurpose purpose token
  let valid := (purpose == 1 || purpose == 2) && supported && base != 0 && bounded &&
    (if operation == 4 then bytes == 0 else bytes > 0 && bytes % 512 == 0 && sector < total && count <= total-sector)
  if !valid then error else
    let token := store32 (base+0x14) 0 token
    let readonly := (load32 (base+0x10) token &&& 32) != 0
    if operation == 1 && readonly then error else
    let token := store64 request operation token
    let token := store64 (request+8) sector token
    let token := store8 statusByte 255 token
    let token := descriptor queue request 16 1 1 token
    let token :=
      if operation == 4 then descriptor (queue+16) statusByte 1 2 0 token
      else
        let token := descriptor (queue+16) buffer bytes (if operation == 0 then 3 else 1) 2 token
        descriptor (queue+32) statusByte 1 2 0 token
    let completed := submit base queue counter token
    if completed == 0 && load8 statusByte completed == 0 then 0 else error

def capacity (token : UInt64) : UInt64 := capacityPurpose 1 token

def block (operation sector buffer bytes token : UInt64) : UInt64 := blockPurpose 1 operation sector buffer bytes token

def random (buffer length token : UInt64) : UInt64 :=
  let base := load64 (state+8) token
  let valid := base != 0 && length > 0 && length <= 256 && buffer >= randomBuffer &&
    buffer <= randomBuffer+256 && length <= randomBuffer+256-buffer
  if !valid then error else
    let index := load64 (state+24) token
    let token := descriptor randomQueue buffer length 2 0 token
    let completed := submit base randomQueue (state+24) token
    let actual := load32 (randomQueue+4104+(index &&& 7)*8) completed
    if completed == 0 && actual == length then 0 else error
-- Device-purpose binding is out-of-band operator configuration, not disk order.
-- GET_ID serial must exactly equal one of these twenty-byte padded profile IDs.
def identifyBlock (base token : UInt64) : UInt64 :=
  let token := setup base blockQueue token
  let token := clear 0x80e0b000 4 token
  let token := store64 (state+112) 0 token
  let token := store64 request 8 token
  let token := store64 (request+8) 0 token
  let token := store8 statusByte 255 token
  let token := descriptor blockQueue request 16 1 1 token
  let token := descriptor (blockQueue+16) 0x80e0b000 20 3 2 token
  let token := descriptor (blockQueue+32) statusByte 1 2 0 token
  let result := submit base blockQueue (state+112) token
  if result != 0 || load8 statusByte result != 0 then 0 else
  if load64 0x80e0b000 token == 7162247753407231084 && load64 0x80e0b008 token == 212436087668 && load32 0x80e0b010 token == 0 then 1 else
  if load64 0x80e0b000 token == 7311156825132201068 && load64 0x80e0b008 token == 829828466 && load32 0x80e0b010 token == 0 then 2 else 0

partial def bindBlocks (index token : UInt64) : UInt64 :=
  if index == load64 (state+96) token then token else
  let base := load64 (state+128+index*8) token
  let purpose := identifyBlock base token
  let target := if purpose == 1 then state else state+80
  let duplicate := if purpose == 1 then 1 else 2
  let token := if purpose == 0 then store32 (base+0x70) 0 token else
    if load64 target token != 0 || load64 (state+104) token &&& duplicate != 0 then
      let old := load64 target token
      let token := if old != 0 then store32 (old+0x70) 0 token else token
      let token := store32 (base+0x70) 0 token
      let token := store64 target 0 token
      store64 (state+104) (load64 (state+104) token ||| duplicate) token
    else store64 target base token
  bindBlocks (index+1) token

def storageInit (token : UInt64) : UInt64 :=
  let token := clear state 32 token
  let token := discover 0 token
  let token := bindBlocks 0 token
  let token := store64 (state+16) 0 token
  let token := store64 (state+88) 0 token
  let token := setup (load64 state token) blockQueue token
  let token := setup (load64 (state+80) token) 0x80e0c000 token
  setup (load64 (state+8) token) randomQueue token

-- LT-Stream-v1: modern virtio-console singleport, direct split queues only.
-- At most one descriptor per direction is outstanding. All DMA is kernel-owned.
def streamRX : UInt64 := 0x80e20000
def streamTX : UInt64 := 0x80e22000
def streamIn : UInt64 := 0x80e24000
def streamOut : UInt64 := 0x80e24400
def streamControl : UInt64 := 0x80e31000
def streamControlRX : UInt64 := 0x80e32000
def streamControlTX : UInt64 := 0x80e34000
def streamControlIn : UInt64 := 0x80e36000
def streamControlOut : UInt64 := 0x80e36400

def streamQueue (base index queue token : UInt64) : UInt64 :=
  let token := store32 (base+0x30) index token
  if load32 (base+0x34) token < 8 then error else
  let token := clear queue 1024 token
  let token := store32 (base+0x38) 8 token
  let token := store32 (base+0x80) queue token
  let token := store32 (base+0x84) 0 token
  let token := store32 (base+0x90) (queue+128) token
  let token := store32 (base+0x94) 0 token
  let token := store32 (base+0xa0) (queue+4096) token
  let token := store32 (base+0xa4) 0 token
  store32 (base+0x44) 1 token

-- Reliable selected non-console port control, shared by audio and opaque
-- networking. The configuration is supervisor-owned; all queues, buffers and
-- counters are bounded, and no application supplies these physical addresses.
def portConfigure (context base rx tx input output name t : UInt64) : UInt64 :=
  let t := clear context 10 t
  let t := store64 context base t
  let t := store64 (context+8) rx t
  let t := store64 (context+16) tx t
  let t := store64 (context+24) input t
  let t := store64 (context+32) output t
  store64 (context+72) name t
def portSend (context id event value t : UInt64) : UInt64 :=
  let base := load64 context t
  let controlTX := load64 (context+16) t
  let controlOut := load64 (context+32) t
  let count := Guest.load64 (context+56) t
  if Guest.Devices.read16 (controlTX+4098) t != count then error else
  let t := Guest.store64 controlOut (id ||| (event <<< 32) ||| (value <<< 48)) t
  let t := Guest.Devices.descriptor controlTX controlOut 8 0 0 t
  let t := Guest.Devices.write16 (controlTX+132+(count%8)*2) 0 t
  let next := (count+1)%65536
  let t := Guest.deviceFence t
  let t := Guest.Devices.write16 (controlTX+130) next t
  let t := Guest.store64 (context+56) next t
  let t := Guest.deviceFence t
  let t := Guest.store32 (base+0x50) 3 t
  Guest.Devices.wait base (controlTX+4096) next 10000 t

partial def portPost (context index t : UInt64) : UInt64 :=
  let controlRX := load64 (context+8) t
  let controlIn := load64 (context+24) t
  if index == 8 then
    let t := Guest.Devices.write16 (controlRX+130) 8 t
    Guest.store64 (context+48) 8 t
  else
    let t := Guest.Devices.descriptor (controlRX+index*16) (controlIn+index*64) 64 2 0 t
    let t := Guest.Devices.write16 (controlRX+132+index*2) index t
    portPost context (index+1) t

partial def portPump (context remaining t : UInt64) : UInt64 :=
  let base := load64 context t
  let controlRX := load64 (context+8) t
  let controlIn := load64 (context+24) t
  let t := Guest.store32 (base+0x50) 2 t
  let t := Guest.deviceFence t
  let consumed := Guest.load64 (context+40) t
  let used := Guest.Devices.read16 (controlRX+4098) t
  let pending := (used+65536-consumed)%65536
  if pending > 8 then error else
  if pending == 0 || remaining == 0 then t else
  let item := controlRX+4100+(consumed%8)*8
  let head := Guest.load32 item t
  let length := Guest.load32 (item+4) t
  if head != consumed%8 || length < 8 || length > 64 then error else
  let p := controlIn+head*64
  let id := Guest.load32 p t
  let event := Guest.Devices.read16 (p+4) t
  let value := Guest.Devices.read16 (p+6) t
  let flags := Guest.load64 (context+64) t
  if id != 1 then error else
  let t := if event == 1 && value == 1 && length == 8 then
    if flags &&& 1 != 0 then t else
    let t := Guest.store64 (context+64) (flags ||| 1) t
    portSend context 1 3 1 t
  else if event == 7 && value == 1 && (length == 15 || length == 16) &&
      Guest.load64 (p+8) t &&& 0x00ffffffffffffff == Guest.load64 (context+72) t &&
      (length == 15 || Guest.load8 (p+15) t == 0) then
    Guest.store64 (context+64) (flags ||| 2) t
  else if event == 6 && length == 8 && value <= 1 then
    Guest.store64 (context+64) ((flags &&& 0xfffffffffffffffb) ||| (value*4)) t
  else error
  if t == error then error else
  let posted := Guest.load64 (context+48) t
  let t := Guest.Devices.clear p 8 t
  let t := Guest.Devices.write16 (controlRX+132+(posted%8)*2) head t
  let t := Guest.store64 (context+40) ((consumed+1)%65536) t
  let t := Guest.store64 (context+48) ((posted+1)%65536) t
  let t := Guest.deviceFence t
  let t := Guest.Devices.write16 (controlRX+130) ((posted+1)%65536) t
  let t := Guest.deviceFence t
  portPump context (remaining-1) t


def streamPost (base token : UInt64) : UInt64 :=
  let token := descriptor streamRX streamIn 1024 2 0 token
  let index := (load64 (state+48) token+1) &&& 65535
  let token := write16 (streamRX+132+((index-1) &&& 7)*2) 0 token
  let token := deviceFence token
  let token := write16 (streamRX+130) index token
  let token := store64 (state+48) index token
  let token := deviceFence token
  store32 (base+0x50) 4 token

def streamInit (token : UInt64) : UInt64 :=
  let base := load64 (state+32) token
  if base == 0 then 0 else
  let token := store32 (base+0x70) 0 token
  if awaitReset base 10000 token == error then error else
  let epoch := load64 (state+40) token+1
  let token := clear (state+40) 5 token
  let token := store64 (state+200) 0 token
  let token := store64 (state+40) epoch token
  let token := clear streamIn 256 token
  let token := clear streamControlIn 128 token
  let token := clear streamControlOut 1 token
  let token := portConfigure streamControl base streamControlRX streamControlTX streamControlIn streamControlOut 0x003174656e2d746c token
  let token := store32 (base+0x70) 3 token
  let token := store32 (base+0x14) 0 token
  if load32 (base+0x10) token &&& 2 == 0 || load32 (base+0x104) token < 2 then error else
  let token := store32 (base+0x14) 1 token
  if load32 (base+0x10) token &&& 1 == 0 then error else
  let token := store32 (base+0x24) 0 token
  let token := store32 (base+0x20) 2 token
  let token := store32 (base+0x24) 1 token
  let token := store32 (base+0x20) 1 token
  let token := store32 (base+0x70) 11 token
  if load32 (base+0x70) token &&& 8 == 0 then error else
  let token := streamQueue base 4 streamRX token
  if token == error then error else
  let token := streamQueue base 5 streamTX token
  if token == error then error else
  let token := streamQueue base 2 streamControlRX token
  if token == error then error else
  let token := streamQueue base 3 streamControlTX token
  if token == error then error else
  let token := portPost streamControl 0 token
  let token := deviceFence token
  let token := store32 (base+0x70) 15 token
  let token := portSend streamControl 0 0 1 token
  if token == error then error else
  let token := portPump streamControl 8 token
  if token == error || load64 (streamControl+64) token != 7 then error else
  let token := portSend streamControl 1 6 1 token
  if token == error then error else streamPost base token

def init (token : UInt64) : UInt64 :=
  let token := storageInit token
  let result := streamInit token
  if result == error then
    let base := load64 (state+32) token
    if base == 0 then token else store32 (base+0x70) 128 token
  else token

def streamStatus (token : UInt64) : UInt64 :=
  let base := load64 (state+32) token
  if base == 0 then 0 else
  let status := load32 (base+0x70) token
  if status &&& 192 != 0 || status &&& 15 != 15 then error else
  let token := portPump streamControl 8 token
  if token == error || load64 (streamControl+64) token != 7 then error else
  (load64 (state+40) token <<< 32) ||| 3

def streamFail (base token : UInt64) : UInt64 :=
  let token := store32 (base+0x70) 128 token
  error+token

partial def bytesCopy (source target length token : UInt64) : UInt64 :=
  if length == 0 then token else bytesCopy (source+1) (target+1) (length-1) (store8 target (load8 source token) token)

def streamRead (target length token : UInt64) : UInt64 :=
  let base := load64 (state+32) token
  if base == 0 || streamStatus token == error || length == 0 || length > 1024 then error else
  let token := store32 (base+0x50) 4 token
  let token := deviceFence token
  let used := read16 (streamRX+4098) token
  let posted := load64 (state+48) token
  if used != posted && used != ((posted-1) &&& 65535) then streamFail base token else
  let remaining := load64 (state+64) token
  let expected := load64 (state+48) token
  let token := if remaining == 0 && read16 (streamRX+4098) token == expected then
    let head := load32 (streamRX+4100+((expected-1) &&& 7)*8) token
    let actual := load32 (streamRX+4104+((expected-1) &&& 7)*8) token
    if head != 0 || actual == 0 || actual > 1024 then streamFail base token else
    let token := store64 (state+56) 0 token
    store64 (state+64) actual token
    else token
  if token == error then error else
  let remaining := load64 (state+64) token
  if remaining == 0 then 0 else
  let count := if remaining < length then remaining else length
  let offset := load64 (state+56) token
  let token := bytesCopy (streamIn+offset) target count token
  let token := store64 (state+56) (offset+count) token
  let token := store64 (state+64) (remaining-count) token
  let token := store32 (base+0x64) 1 token
  let token := if remaining == count then streamPost base token else token
  count+token

def streamWrite (source length token : UInt64) : UInt64 :=
  let base := load64 (state+32) token
  if base == 0 || streamStatus token == error || length == 0 || length > 1024 then error else
  let submitted := load64 (state+72) token
  let token := store32 (base+0x50) 5 token
  let token := deviceFence token
  let completed := read16 (streamTX+4098) token
  if completed != submitted && completed != ((submitted-1) &&& 65535) then streamFail base token else
  if completed != submitted then 0 else
  let token := if submitted != 0 then
    let head := load32 (streamTX+4100+((submitted-1) &&& 7)*8) token
    let actual := load32 (streamTX+4104+((submitted-1) &&& 7)*8) token
    if head != 0 || actual > load64 (state+200) token then streamFail base token else token
    else token
  if token == error then error else
  let token := bytesCopy source streamOut length token
  let token := descriptor streamTX streamOut length 0 0 token
  let next := (submitted+1) &&& 65535
  let token := write16 (streamTX+132+(submitted &&& 7)*2) 0 token
  let token := deviceFence token
  let token := write16 (streamTX+130) next token
  let token := store64 (state+72) next token
  let token := store64 (state+200) length token
  let token := deviceFence token
  let token := store32 (base+0x50) 5 token
  length+token
end Guest.Devices
