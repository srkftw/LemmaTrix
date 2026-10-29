import Guest.Devices
import Guest.Effects
namespace Guest.GraphicsDevice
-- LT-Dev graphics profile: one 640x400 BGRX scanout and two evdev sources.
-- All queue, control and backing addresses belong to the supervisor driver.
def width : UInt64 := 640
def height : UInt64 := 400
def framebuffer : UInt64 := 0x80f00000
def framebufferBytes : UInt64 := 1024000
def queue : UInt64 := 0x80e10000
def command : UInt64 := 0x80e12000
def response : UInt64 := 0x80e12400
def keyQueue : UInt64 := 0x80e14000
def pointerQueue : UInt64 := 0x80e16000
def eventBuffers : UInt64 := 0x80e18000
def state : UInt64 := 0x80e1a000
def error : UInt64 := 0xffffffffffffffff
def consumedReport : UInt64 := 0xfffffffffffffffe
def inputPending : UInt64 := 0xfffe000000000000

partial def discover (index token : UInt64) : UInt64 :=
  if index == 8 then token else
    let base := 0x10001000+index*4096
    let valid := load32 base token == 0x74726976 && load32 (base+4) token == 2
    let id := if valid then load32 (base+8) token else 0
    let token := if id == 16 then store64 state base token else token
    let token := if id == 18 then
      if load64 (state+8) token == 0 then store64 (state+8) base token
      else store64 (state+16) base token
      else token
    discover (index+1) token

def negotiate (base token : UInt64) : UInt64 :=
  if base == 0 then error else
    let token := store32 (base+0x70) 0 token
    let reset := Devices.awaitReset base 100000 token
    if reset == error then error else
    let token := store32 (base+0x70) 1 reset
    let token := store32 (base+0x70) 3 token
    let token := store32 (base+0x14) 1 token
    if load32 (base+0x10) token &&& 1 == 0 then error else
    let token := store32 (base+0x24) 0 token
    let token := store32 (base+0x20) 0 token
    let token := store32 (base+0x24) 1 token
    let token := store32 (base+0x20) 1 token
    let token := store32 (base+0x70) 11 token
    if load32 (base+0x70) token &&& 8 == 0 then error else token

def configureQueue (base ring token : UInt64) : UInt64 :=
  let token := store32 (base+0x30) 0 token
  if load32 (base+0x44) token != 0 || load32 (base+0x34) token < 8 then error else
  let token := Devices.clear ring 1024 token
  let token := store32 (base+0x38) 8 token
  let token := store32 (base+0x80) ring token
  let token := store32 (base+0x84) 0 token
  let token := store32 (base+0x90) (ring+128) token
  let token := store32 (base+0x94) 0 token
  let token := store32 (base+0xa0) (ring+4096) token
  let token := store32 (base+0xa4) 0 token
  store32 (base+0x44) 1 token

-- A GPU request owns its fixed command and response until the used ring advances.
def submit (bytes token : UInt64) : UInt64 :=
  let base := load64 state token
  let index := load64 (state+24) token
  let token := Devices.clear response 8 token
  let token := Devices.descriptor queue command bytes 1 1 token
  let token := Devices.descriptor (queue+16) response 64 2 0 token
  let token := Devices.write16 (queue+132+(index &&& 7)*2) 0 token
  let token := deviceFence token
  let token := Devices.write16 (queue+130) ((index+1) &&& 65535) token
  let token := store64 (state+24) ((index+1) &&& 65535) token
  let token := deviceFence token
  store32 (base+0x50) 0 token

def complete (token : UInt64) : UInt64 :=
  let base := load64 state token
  if base == 0 || load32 (base+0x70) token &&& 128 != 0 then error else
  if Devices.read16 (queue+4098) token != load64 (state+24) token then 1 else
    let token := deviceFence token
    let token := store32 (base+0x64) (load32 (base+0x60) token &&& 3) token
    let entry := queue+4100+((load64 (state+24) token-1) &&& 7)*8
    if load32 entry token != 0 || load32 (entry+4) token != 24 then error else
    if load32 response token == 0x1100 then 0 else error

partial def awaitBoot (remaining token : UInt64) : UInt64 :=
  let status := complete token
  if status != 1 then status else
  if remaining == 0 then error else awaitBoot (remaining-1) status

def header (kind token : UInt64) : UInt64 :=
  let token := Devices.clear command 16 token
  store32 command kind token

def bootCommand (bytes token : UInt64) : UInt64 :=
  awaitBoot 100000 (submit bytes token)

partial def inputDescriptors (ring buffers index token : UInt64) : UInt64 :=
  if index == 8 then Devices.write16 (ring+130) 8 (deviceFence token) else
    let token := Devices.descriptor (ring+index*16) (buffers+index*8) 8 2 0 token
    let token := Devices.write16 (ring+132+index*2) index token
    inputDescriptors ring buffers (index+1) token

def initInput (base ring buffers token : UInt64) : UInt64 :=
  if base == 0 then token else
  let token := negotiate base token
  if token == error then token else
  let token := configureQueue base ring token
  if token == error then token else
  let token := inputDescriptors ring buffers 0 token
  let token := deviceFence token
  let token := store32 (base+0x70) 15 token
  store32 (base+0x50) 0 (deviceFence token)

def init (token : UInt64) : UInt64 :=
  let token := Devices.clear state 32 token
  let token := discover 0 token
  let base := load64 state token
  if base == 0 then error else
  let token := negotiate base token
  if token == error then error else
  let token := configureQueue base queue token
  if token == error then error else
  let token := store32 (base+0x70) 15 token
  let token := header 0x101 token
  let token := store32 (command+24) 1 token
  let token := store32 (command+28) 2 token
  let token := store32 (command+32) width token
  let token := store32 (command+36) height token
  let token := bootCommand 40 token
  if token == error then error else
  let token := header 0x106 token
  let token := store32 (command+24) 1 token
  let token := store32 (command+28) 1 token
  let token := store64 (command+32) framebuffer token
  let token := store32 (command+40) framebufferBytes token
  let token := bootCommand 48 token
  if token == error then error else
  let token := header 0x103 token
  let token := store32 (command+32) width token
  let token := store32 (command+36) height token
  let token := store32 (command+44) 1 token
  let token := bootCommand 48 token
  if token == error then error else
  let token := initInput (load64 (state+8) token) keyQueue eventBuffers token
  initInput (load64 (state+16) token) pointerQueue (eventBuffers+64) token

def rectangle (x y w h token : UInt64) : UInt64 :=
  let token := store32 (command+24) x token
  let token := store32 (command+28) y token
  let token := store32 (command+32) w token
  store32 (command+36) h token

-- Begin/poll are nonblocking. The compositor must not alter the backing while
-- presentation is in progress. A reset is the only reuse after device failure.
def presentBegin (x y w h token : UInt64) : UInt64 :=
  if load64 state token == 0 || load64 (state+32) token != 0 then error else
  if w == 0 || h == 0 || x >= width || y >= height || w > width-x || h > height-y then error else
  let token := header 0x105 token
  let token := rectangle x y w h token
  let token := store64 (command+40) ((y*width+x)*4) token
  let token := store32 (command+48) 1 token
  let token := store64 (state+32) 1 token
  let token := submit 56 token
  0+token

def presentPoll (token : UInt64) : UInt64 :=
  let stage := load64 (state+32) token
  if stage == 0 then 0 else
  let status := complete token
  if status != 0 then status else
  if stage == 1 then
    -- Rectangle stays in place while the command header changes to FLUSH.
    let token := store32 command 0x104 token
    let token := store32 (command+40) 1 token
    let token := store32 (command+44) 0 token
    let token := store32 (command+48) 0 token
    let token := store64 (state+32) 2 token
    let token := submit 48 token
    1+token
  else
    let token := store64 (state+32) 0 token
    0+token

def pollInput (base ring buffers counter token : UInt64) : UInt64 :=
  if base == 0 then 0 else
  let token := store32 (base+0x50) 0 token
  if load32 (base+0x70) token &&& 128 != 0 then error else
  let consumed := load64 counter token
  let used := Devices.read16 (ring+4098) token
  if used == consumed then 0 else
  if ((used-consumed) &&& 65535) > 8 then error else
  let token := deviceFence token
  let entry := ring+4100+(consumed &&& 7)*8
  let id := load32 entry token
  if id >= 8 || load32 (entry+4) token != 8 then error else
  let p := buffers+id*8
  let event := (Devices.read16 p token <<< 48) ||| (Devices.read16 (p+2) token <<< 32) ||| load32 (p+4) token
  let available := Devices.read16 (ring+130) token
  let token := Devices.write16 (ring+132+(available &&& 7)*2) id token
  let token := deviceFence token
  let token := Devices.write16 (ring+130) ((available+1) &&& 65535) token
  let token := store64 counter ((consumed+1) &&& 65535) token
  let token := store32 (base+0x64) (load32 (base+0x60) token &&& 3) token
  let token := deviceFence token
  Effects.effectValue (if event == 0 then consumedReport else event) token

partial def inputFuel (remaining token : UInt64) : UInt64 :=
  if remaining == 0 then inputPending else
  -- Alternate the first source, so pointer traffic cannot starve the keyboard.
  let turn := load64 (state+56) token &&& 1
  let token := store64 (state+56) (1-turn) token
  let first := if turn == 0 then pollInput (load64 (state+8) token) keyQueue eventBuffers (state+40) token
    else pollInput (load64 (state+16) token) pointerQueue (eventBuffers+64) (state+48) token
  if first == consumedReport then inputFuel (remaining-1) first else
  if first != 0 then first else
  let second := if turn == 0 then pollInput (load64 (state+16) first) pointerQueue (eventBuffers+64) (state+48) first
    else pollInput (load64 (state+8) first) keyQueue eventBuffers (state+40) first
  if second == consumedReport then inputFuel (remaining-1) second else second

-- Zero means both event sources were actually idle. All-zero SYN_REPORT records
-- are consumed internally; a nonzero work marker preserves that guarantee when
-- the bounded report-drain budget is exhausted. Trusted prompts may arm only
-- after an idle result and completed presentation, never after a queued report.
def input (token : UInt64) : UInt64 := inputFuel 32 token

def resetOne (base token : UInt64) : UInt64 :=
  if base == 0 then token else
  let token := store32 (base+0x70) 0 token
  Devices.awaitReset base 100000 token

def reset (token : UInt64) : UInt64 :=
  let token := resetOne (load64 state token) token
  if token == error then error else
  let token := resetOne (load64 (state+8) token) token
  if token == error then error else
  let token := resetOne (load64 (state+16) token) token
  if token == error then error else
  Devices.clear state 32 token
end Guest.GraphicsDevice
