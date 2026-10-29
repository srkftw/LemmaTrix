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
    let token := if id == 2 then store64 state base token else token
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

def init (token : UInt64) : UInt64 :=
  let token := clear state 16 token
  let token := discover 0 token
  let token := setup (load64 state token) blockQueue token
  setup (load64 (state+8) token) randomQueue token

def descriptor (p address length flags next token : UInt64) : UInt64 :=
  let token := store64 p address token
  store64 (p+8) (length + flags*0x100000000 + next*0x1000000000000) token

partial def wait (base used expected remaining token : UInt64) : UInt64 :=
  if remaining == 0 then error else
  if (load32 (base+0x70) token &&& 128) != 0 then error else
  if read16 (used+2) token == expected then 0 else wait base used expected (remaining-1) token

def submit (base queue counter token : UInt64) : UInt64 :=
  -- A timed-out request may still own its DMA buffers. Refuse further work
  -- until init explicitly resets the transport and queue together.
  if base == 0 || (load32 (base+0x70) token &&& 128) != 0 then error else
  let index := load64 counter token
  let expected := (index+1) &&& 65535
  let token := write16 (queue+132+(index &&& 7)*2) 0 token
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

def capacity (token : UInt64) : UInt64 :=
  let base := load64 state token
  if base == 0 then 0 else load32 (base+0x100) token + (load32 (base+0x104) token)*0x100000000

def block (operation sector buffer bytes token : UInt64) : UInt64 :=
  let base := load64 state token
  let supported := operation == 0 || operation == 1 || operation == 4
  let bounded := buffer >= blockBuffer && buffer <= blockBuffer+4096 && bytes <= 4096 && bytes <= blockBuffer+4096-buffer
  let count := bytes / 512
  let total := capacity token
  let valid := supported && base != 0 && bounded &&
    (if operation == 4 then bytes == 0 else bytes > 0 && bytes % 512 == 0 && sector < total && count <= total-sector)
  if !valid then error else
    let token := store32 (base+0x14) 0 token
    let readonly := (load32 (base+0x10) token &&& 32) != 0
    if operation == 1 && readonly then error else
    let token := store64 request operation token
    let token := store64 (request+8) sector token
    let token := store8 statusByte 255 token
    let token := descriptor blockQueue request 16 1 1 token
    let token :=
      if operation == 4 then descriptor (blockQueue+16) statusByte 1 2 0 token
      else
        let token := descriptor (blockQueue+16) buffer bytes (if operation == 0 then 3 else 1) 2 token
        descriptor (blockQueue+32) statusByte 1 2 0 token
    let completed := submit base blockQueue (state+16) token
    if completed == 0 && load8 statusByte completed == 0 then 0 else error

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
end Guest.Devices
