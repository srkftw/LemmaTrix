import Guest.Raster
import Guest.Keyboard
import Guest.Wave
import Guest.AudioSDK
import Guest.WaitSDK
import Guest.VaultCrypto
namespace Guest.Player
open Guest.LiveSDK Guest.Raster

def st : UInt64 := 0x6e0000
def samples : UInt64 := 0x6e3000
def bg : UInt64 := 0x142432
def fg : UInt64 := 0xd8e6ed
def label (id x y t : UInt64) : UInt64 :=
  if id == 0 then
    let t := store64 (0x414000+0) 5498930609861248332 t
    let t := store64 (0x414000+8) 1380276545 t
    text 0x414000 12 x y fg bg t
  else if id == 1 then
    let t := store64 (0x414000+0) 7813780835340996691 t
    let t := store64 (0x414000+8) 8458164858710423905 t
    let t := store64 (0x414000+16) 8295721911059506547 t
    let t := store64 (0x414000+24) 4993401409202319220 t
    let t := store64 (0x414000+32) 6073182477746132038 t
    let t := store64 (0x414000+40) 8301577133762114336 t
    text 0x414000 48 x y fg bg t
  else if id == 2 then
    let t := store64 (0x414000+0) 7234316346692756819 t
    let t := store64 (0x414000+8) 7307484473462191648 t
    let t := store64 (0x414000+16) 7954892334483841124 t
    let t := store64 (0x414000+24) 2322583539455828084 t
    let t := store64 (0x414000+32) 8032016439426707310 t
    let t := store64 (0x414000+40) 7022836344793623410 t
    let t := store64 (0x414000+48) 34169982962396277 t
    text 0x414000 55 x y fg bg t
  else if id == 3 then
    let t := store64 (0x414000+0) 4995703988996296526 t
    let t := store64 (0x414000+8) 21582 t
    text 0x414000 10 x y fg bg t
  else if id == 4 then
    let t := store64 (0x414000+0) 383397217618 t
    text 0x414000 5 x y fg bg t
  else if id == 5 then
    let t := store64 (0x414000+0) 20070800283487312 t
    text 0x414000 7 x y fg bg t
  else if id == 6 then
    let t := store64 (0x414000+0) 75064541528400 t
    text 0x414000 6 x y fg bg t
  else if id == 7 then
    let t := store64 (0x414000+0) 5641130465743492418 t
    let t := store64 (0x414000+8) 7596553831441047623 t
    let t := store64 (0x414000+16) 7021710384594968932 t
    let t := store64 (0x414000+24) 8530220618550175598 t
    let t := store64 (0x414000+32) 28548142444865889 t
    text 0x414000 39 x y fg bg t
  else if id == 8 then
    let t := store64 (0x414000+0) 293219880517 t
    text 0x414000 5 x y fg bg t
  else if id == 9 then
    let t := store64 (0x414000+0) 5931047540229361237 t
    let t := store64 (0x414000+8) 5557532439972431188 t
    let t := store64 (0x414000+16) 4919423183884799041 t
    let t := store64 (0x414000+24) 297799866144 t
    text 0x414000 29 x y fg bg t
  else if id == 10 then
    let t := store64 (0x414000+0) 4991149811937072449 t
    let t := store64 (0x414000+8) 4705792257738099030 t
    let t := store64 (0x414000+16) 4993438935067214166 t
    let t := store64 (0x414000+24) 4994025034156756768 t
    let t := store64 (0x414000+32) 68 t
    text 0x414000 33 x y fg bg t
  else if id == 11 then
    let t := store64 (0x414000+0) 126879463993958 t
    text 0x414000 6 x y fg bg t
  else if id == 12 then
    let t := store64 (0x414000+0) 8317134136819148899 t
    text 0x414000 8 x y fg bg t
  else if id == 13 then
    let t := store64 (0x414000+0) 5491631028718879568 t
    let t := store64 (0x414000+8) 5201710553272426565 t
    let t := store64 (0x414000+16) 122 t
    text 0x414000 17 x y fg bg t
  else if id == 14 then
    let t := store64 (0x414000+0) 8223700967325201743 t
    let t := store64 (0x414000+8) 6998720764907057253 t
    let t := store64 (0x414000+16) 2334102057661064035 t
    let t := store64 (0x414000+24) 2322576912303616614 t
    let t := store64 (0x414000+32) 7957688057479457139 t
    let t := store64 (0x414000+40) 8458077255291073140 t
    let t := store64 (0x414000+48) 7021147439052777828 t
    let t := store64 (0x414000+56) 25955 t
    text 0x414000 58 x y fg bg t
  else t
def mark (state t : UInt64) : UInt64 := store64 (st+8) state (store64 (st+48) 1 t)
def stopOutput (t : UInt64) : UInt64 :=
  let epoch := load64 (st+32) t
  let t := if epoch == 0 then t else Guest.AudioSDK.stop epoch t
  let t := zero samples 128 t
  let t := zero Guest.Wave.bytes 64 t
  store64 (st+64) 0 (store64 (st+32) 0 t)
def invalidInput (h t : UInt64) : UInt64 :=
  let t := stopOutput t
  let t := if h == 0 then t else Guest.ContentSDK.release h t
  mark 6 (store64 st 0 (store64 (st+104) 0 t))
def parsedMatches (t : UInt64) : Bool :=
  (load64 (st+88) t == 0 || load64 (st+88) t == load64 (Guest.Wave.info+24) t) &&
  (load64 (st+96) t == 0 || load64 (st+96) t == load64 (Guest.Wave.info+48) t)
def attach (h channels frames t : UInt64) : UInt64 :=
  let t := stopOutput t
  let previous := load64 st t
  let t := if previous == 0 || previous == h then t else Guest.ContentSDK.release previous t
  let t := store64 st h t
  let t := store64 (st+88) channels t
  let t := store64 (st+96) frames t
  let t := store64 (st+104) 0 t
  let t := store64 (st+112) 0 t
  let t := store64 (st+16) 0 t
  let r := Guest.Wave.parse h t
  if r == error then
    if load64 (Guest.Wave.info+56) r == 6 then mark 4 (store64 (st+104) 1 r) else invalidInput h r
  else if !parsedMatches r then invalidInput h r else mark 1 r

partial def mono (i frames t : UInt64) : UInt64 :=
  if i == frames then t else
    let v := Guest.Wave.u16 (Guest.Wave.bytes+i*2) t
    let t := Guest.VaultCrypto.putLE (samples+i*4) v 2 t
    let t := Guest.VaultCrypto.putLE (samples+i*4+2) v 2 t
    mono (i+1) frames t
def play (t : UInt64) : UInt64 :=
  if load64 st t == 0 || load64 (st+8) t == 6 then t else
  if load64 (st+104) t != 0 then
    let wanted := if load64 (st+112) t == 0 then 1 else 0
    mark (if wanted == 1 then 4 else 3) (store64 (st+112) wanted t)
  else if load64 (st+8) t == 2 || load64 (st+8) t == 4 then mark 3 t else
  let epoch := if load64 (st+32) t == 0 then Guest.AudioSDK.acquire t else load64 (st+32) t
  if epoch == error then mark 7 epoch else
    let t := store64 (st+32) epoch epoch
    let t := if load64 (st+16) t >= load64 (Guest.Wave.info+48) t then store64 (st+16) 0 t else t
    mark 2 t
def seek (forward t : UInt64) : UInt64 :=
  if load64 (st+104) t != 0 then t else
  let was := load64 (st+8) t
  let t := stopOutput t
  let pos := load64 (st+16) t
  let total := load64 (Guest.Wave.info+48) t
  let next := if forward == 1 then if total-pos < 240000 then total else pos+240000 else if pos < 240000 then 0 else pos-240000
  let t := mark 3 (store64 (st+16) next t)
  if was == 2 || was == 4 then play t else t
def prepare (t : UInt64) : UInt64 :=
  let pos := load64 (st+16) t
  let total := load64 (Guest.Wave.info+48) t
  if pos >= total then
    let ready := Guest.AudioSDK.inspect (load64 (st+32) t) t
    if ready == error then mark 7 (stopOutput ready) else
    if ready &&& 1 == 0 then store64 (st+80) 1 ready else
      mark 5 (stopOutput ready)
  else
  let channels := load64 (Guest.Wave.info+24) t
  let align := channels*2
  let count := if total-pos > 512/align then 512/align else total-pos
  let offset := load64 (Guest.Wave.info+8) t+pos*align
  let r := Guest.Wave.range (load64 st t) offset (count*align) Guest.Wave.bytes t
  if r == error then
    if load64 (Guest.Wave.info+56) r == 6 then mark 4 r else invalidInput (load64 st r) r
  else
    let t := if channels == 1 then mono 0 count r else copy Guest.Wave.bytes samples (count*4) r
    let t := store64 (st+64) (count*4) t
    if load64 (st+8) t == 4 then mark 2 t else store64 (st+8) 2 t
-- A missing verified header is distinct from an unsupported decoder format.
-- Collection metadata is an expectation until the actual WAVE parser agrees.
def headerPump (t : UInt64) : UInt64 :=
  if load64 (st+104) t == 0 then t else
  let h := load64 st t
  let r := Guest.Wave.parse h t
  if r == error then
    if load64 (Guest.Wave.info+56) r == 6 then r else invalidInput h r
  else if !parsedMatches r then invalidInput h r else
    let t := store64 (st+104) 0 r
    let t := mark 1 t
    if load64 (st+112) t == 1 then play t else t

def pump (t : UInt64) : UInt64 :=
  let t := headerPump t
  if load64 (st+104) t != 0 || (load64 (st+8) t != 2 && load64 (st+8) t != 4) then t else
  let t := if load64 (st+64) t == 0 then prepare t else t
  let count := load64 (st+64) t
  if count == 0 then t else
  let r := Guest.AudioSDK.write (load64 (st+32) t) samples count t
  if r == error then mark 7 (stopOutput r) else
  if r == 0 then store64 (st+80) 1 r else
    let r := store64 (st+80) 0 r
    let t := store64 (st+16) (load64 (st+16) r+count/4) r
    store64 (st+64) 0 t
def draw (surface t : UInt64) : UInt64 :=
  let t := fill 0 0 640 352 bg t
  let t := fill 0 0 640 35 0x223e50 t
  let t := label 0 16 12 t
  let t := label 1 16 51 t
  let t := label 2 16 75 t
  let t := label (load64 (st+8) t+3) 16 112 t
  let t := label 13 16 145 t
  let t := label 11 16 180 t
  let t := hex (load64 (st+16) t) 12 80 180 fg bg t
  let t := char 160 180 47 fg bg t
  let t := hex (load64 (Guest.Wave.info+48) t) 12 180 180 fg bg t
  let t := label 12 16 208 t
  let t := hex (load64 (Guest.Wave.info+24) t) 2 80 208 fg bg t
  let t := label 14 16 315 t
  let t := store64 (st+48) 0 t
  upload surface 0 901120 0 t
-- Playback changes only these twelve position digits. Upload their nine
-- bounded rows instead of repainting/copying the entire application surface
-- between audio blocks. State changes still redraw the complete interface.
partial def positionRows (surface row t : UInt64) : UInt64 :=
  if row == 9 then t else
    let r := upload surface ((180+row)*2560+80*4) (12*6*4) 0 t
    if r == error then error else positionRows surface (row+1) r
def drawPosition (surface t : UInt64) : UInt64 :=
  positionRows surface 0 (hex (load64 (st+16) t) 12 80 180 fg bg t)
def request (n t : UInt64) : UInt64 :=
  let token := load64 (incoming+8) t
  let caller := load64 incoming t
  let op := load64 command t
  let length := n-32
  let checked := if length == 64 && op == 600 then Guest.ContentSDK.checkDelegation (load64 (command+8) t) caller t else t
  let scopeOK := op != 600 || (checked == 64 && status checked == 0)
  let t := if length == 64 && op == 600 && scopeOK then attach (load64 (command+8) checked) (load64 (command+16) checked) (load64 (command+24) checked) checked else checked
  let t := header (if length != 64 || (op != 600 && op != 601) then 2 else if !scopeOK then 1 else 0) (load64 st t) (load64 (st+8) t) (load64 (st+16) t) (load64 (Guest.Wave.info+48) t) (load64 (Guest.Wave.info+24) t) (load64 (st+32) t) t
  reply token 64 t
def input (_surface ev t : UInt64) : UInt64 :=
  let code := (ev >>> 32) &&& 65535
  if ev >>> 48 != 1 || (ev &&& 0xffffffff) != 1 then t else
  if code == 57 then play t else
  if code == 31 then mark 1 (store64 (st+112) 0 (store64 (st+16) 0 (stopOutput t))) else
  if code == 106 && load64 st t != 0 then seek 1 t else
  if code == 105 && load64 st t != 0 then seek 0 t else t
partial def loop (surface initial : UInt64) : UInt64 :=
  let n := syscall 36 (self initial) incoming 1024 0 initial
  let t := if n >= 96 && n <= 1024 then request n n else n
  let ev := syscall 90 surface 0 0 0 t
  let t := input surface ev ev
  let t := pump t
  let now := Guest.WaitSDK.now t
  let t := if load64 (st+48) now != 0 then
    let drawn := draw surface now
    store64 (st+72) (Guest.WaitSDK.now drawn+20) drawn
    else if load64 (st+8) now == 2 && now >= load64 (st+72) now then
      let drawn := drawPosition surface now
      store64 (st+72) (Guest.WaitSDK.now drawn+20) drawn
    else now
  -- Verified-range publication wakes this reader through its exact scoped
  -- grant. The bounded fallback also supports older Content services.
  let deadline := Guest.WaitSDK.now t+(if load64 (st+8) t == 2 then 1 else 100)
  -- Each successful block already performs a scoped range IPC, and timer
  -- preemption bounds CPU use. Do not add an entire scheduling round per
  -- 128 frames; wait only when output reports backpressure or playback rests.
  let next := if load64 (st+8) t == 2 && load64 (st+80) t == 0 then t else Guest.WaitSDK.deadline deadline t
  loop surface next
def main (initial : UInt64) : UInt64 :=
  let t := zero st 32 initial
  let t := zero Guest.Wave.info 16 t
  let surface := syscall 80 0 0 0 0 t
  if surface == error then error else loop surface (draw surface surface)
end Guest.Player
