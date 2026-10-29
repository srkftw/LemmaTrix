import Guest.Keyboard
import Guest.Raster
import Guest.LiveSDK
import Guest.Structured
import Guest.LiveApps
namespace Guest.TextTools
open Guest.LiveSDK Guest.Raster
open Guest.Structured

def st : UInt64 := 0x6e0000
def input : UInt64 := 0x700000
def fg : UInt64 := 0xd8e6ed
def bg : UInt64 := 0x112330

-- Private labels are guest-authored glyph input, never host-rendered widgets.
def label (id x y t : UInt64) : UInt64 :=
  if id == 0 then
    let t := store64 (0x414000+0) 5714878949987206484 t
    let t := store64 (0x414000+8) 4921951845340959564 t
    let t := store64 (0x414000+16) 6074869107042635845 t
    let t := store64 (0x414000+24) 2325359655552896544 t
    let t := store64 (0x414000+32) 6071207754764144705 t
    let t := store64 (0x414000+40) 5132105 t
    text 0x414000 43 x y fg bg t
  else
  if id == 1 then
    let t := store64 (0x414000+0) 6360582546309273940 t
    let t := store64 (0x414000+8) 5499550742252298324 t
    let t := store64 (0x414000+16) 5928232790458914093 t
    let t := store64 (0x414000+24) 4836917815444455747 t
    let t := store64 (0x414000+32) 5495271481871716948 t
    let t := store64 (0x414000+40) 6000237465318867269 t
    let t := store64 (0x414000+48) 4993741377957404739 t
    text 0x414000 56 x y fg bg t
  else
  if id == 2 then
    let t := store64 (0x414000+0) 64129302941527 t
    text 0x414000 6 x y fg bg t
  else
  if id == 3 then
    let t := store64 (0x414000+0) 64129319852354 t
    text 0x414000 6 x y fg bg t
  else
  if id == 4 then
    let t := store64 (0x414000+0) 3819084 t
    text 0x414000 3 x y fg bg t
  else
  if id == 5 then
    let t := store64 (0x414000+0) 2325357422203982416 t
    let t := store64 (0x414000+8) 2327885233746298195 t
    let t := store64 (0x414000+16) 3395804576522589506 t
    let t := store64 (0x414000+24) 6072349971385896480 t
    let t := store64 (0x414000+32) 293220534593 t
    text 0x414000 37 x y fg bg t
  else
  if id == 6 then
    let t := store64 (0x414000+0) 6505821637182772545 t
    let t := store64 (0x414000+8) 4847362222590018629 t
    let t := store64 (0x414000+16) 6001420618012237908 t
    let t := store64 (0x414000+24) 5269263379905857876 t
    let t := store64 (0x414000+32) 5068029662296625230 t
    let t := store64 (0x414000+40) 6000292582634177862 t
    let t := store64 (0x414000+48) 293221061189 t
    text 0x414000 53 x y fg bg t
  else
  if id == 7 then
    let t := store64 (0x414000+0) 16418196551254607 t
    text 0x414000 7 x y fg bg t
  else
  if id == 8 then
    let t := store64 (0x414000+0) 5931879664086762834 t
    let t := store64 (0x414000+8) 6076834878691758671 t
    let t := store64 (0x414000+16) 5701655346793303880 t
    let t := store64 (0x414000+24) 6071772907867938898 t
    let t := store64 (0x414000+32) 5496996658901046560 t
    let t := store64 (0x414000+40) 1162625601 t
    text 0x414000 44 x y fg bg t
  else
  if id == 9 then
    let t := store64 (0x414000+0) 4919433006539624270 t
    let t := store64 (0x414000+8) 6071772908086251552 t
    let t := store64 (0x414000+16) 5495048297973436192 t
    let t := store64 (0x414000+24) 6143226904431842121 t
    let t := store64 (0x414000+32) 2330986956031215700 t
    let t := store64 (0x414000+40) 2329286007278554697 t
    let t := store64 (0x414000+48) 5263425 t
    text 0x414000 51 x y fg bg t
  else
    t

structure Statistics where
  words : UInt64
  bytes : UInt64
  lines : UInt64

@[noinline] def statistics (b : Bytes) (t : UInt64) : Statistics :=
  if !b.valid then ⟨0,0,0⟩ else
    let counts := Guest.LiveApps.countBytes b.address b.length 0 t
    ⟨counts &&& 0xffffff,b.length,(counts >>> 24) &&& 0xffffff⟩

@[noinline] def drawStatistics (s : Statistics) (t : UInt64) : UInt64 :=
  let t := label 2 8 46 t
  let t := hex s.words 8 56 46 fg bg t
  let t := label 3 170 46 t
  let t := hex s.bytes 8 218 46 fg bg t
  let t := label 4 332 46 t
  hex s.lines 8 356 46 fg bg t

partial def renderInput (offset length caret col row t : UInt64) : UInt64 :=
  if row >= 27 then t else
    let t := if offset == caret then fill (8+col*6) (68+row*9) 6 9 0x507486 t else t
    if offset >= length then t else
      let c := load8 (input+offset) t
      if c == 10 then renderInput (offset+1) length caret 0 (row+1) t else
        let t := char (8+col*6) (68+row*9) c fg (if offset == caret then 0x507486 else bg) t
        renderInput (offset+1) length caret (if col == 102 then 0 else col+1) (if col == 102 then row+1 else row) t

def draw (surface t : UInt64) : UInt64 :=
  let t := fill 0 0 640 352 bg t
  let t := label 0 8 7 t
  let t := label 1 8 24 t
  let t := if load64 (st+40) t == 1 then
      let t := drawStatistics ⟨load64 (st+56) t,load64 (st+64) t,load64 (st+72) t⟩ t
      let t := label 6 8 74 t
      let t := label 7 8 96 t
      let t := hex (load64 (st+48) t) 16 62 96 fg bg t
      let t := if load64 (st+80) t != 0 then label 8 8 118 t else
          let t := hex (load64 (st+256) t) 16 8 118 fg bg t
          let t := hex (load64 (st+264) t) 16 110 118 fg bg t
          let t := hex (load64 (st+272) t) 16 212 118 fg bg t
          hex (load64 (st+280) t) 16 314 118 fg bg t
      label 9 8 148 t
    else
      let n := load64 st t
      let t := drawStatistics (statistics (bytes input n 4096) t) t
      let t := renderInput (load64 (st+96) t) n (load64 (st+8) t) 0 0 t
      label 5 8 326 t
  upload surface 0 901120 0 t

partial def visibleRow (offset target col row t : UInt64) : UInt64 :=
  if offset >= target || row >= 26 then row else
    let c := load8 (input+offset) t
    if c == 10 || col == 102 then visibleRow (offset+1) target 0 (row+1) t
    else visibleRow (offset+1) target (col+1) row t

-- Only the changing statistics strip and occupied text rows are uploaded.
-- The title/footer stay in the backing surface after its initial full paint.
def redrawInput (surface t : UInt64) : UInt64 :=
  if load64 (st+112) t == 1 || load64 (st+40) t == 1 then
    draw surface (store64 (st+112) 0 (store64 (st+104) 0 t))
  else
    let n := load64 st t
    let last := visibleRow (load64 (st+96) t) n 0 0 t
    let old := load64 (st+104) t
    let rows := (if old > last then old else last)+1
    let t := fill 0 42 640 18 bg t
    let t := drawStatistics (statistics (bytes input n 4096) t) t
    let t := fill 0 68 640 (rows*9) bg t
    let t := renderInput (load64 (st+96) t) n (load64 (st+8) t) 0 0 t
    let t := upload surface (42*2560) (18*2560) 0 t
    let t := upload surface (68*2560) (rows*9*2560) 0 t
    store64 (st+104) 0 t

partial def moveRight (p n t : UInt64) : UInt64 :=
  if n == 0 then t else moveRight p (n-1) (store8 (p+n) (load8 (p+n-1) t) t)

def insert (c t : UInt64) : UInt64 :=
  let n := load64 st t
  let cursor := load64 (st+8) t
  if n >= 4096 then t else
    let t := moveRight (input+cursor) (n-cursor) t
    let t := store8 (input+cursor) c t
    let t := store64 st (n+1) t
    store64 (st+8) (cursor+1) t

def erase (forward t : UInt64) : UInt64 :=
  let n := load64 st t
  let cursor := load64 (st+8) t
  if n == 0 || (forward == 0 && cursor == 0) || (forward == 1 && cursor == n) then t else
    let position := if forward == 1 then cursor else cursor-1
    let t := copy (input+position+1) (input+position) (n-position-1) t
    let t := store64 st (n-1) t
    store64 (st+8) position t

partial def uppercase (p n t : UInt64) : UInt64 :=
  if n == 0 then t else
    let c := load8 p t
    uppercase (p+1) (n-1) (store8 p (if c >= 97 && c <= 122 then c-32 else c) t)

def key (code down t : UInt64) : UInt64 :=
  if code == 42 || code == 54 then store64 (st+16) (if down == 0 then 0 else 1) t
  else if code == 29 || code == 97 then store64 (st+24) (if down == 0 then 0 else 1) t
  else if down == 0 then t else
    let shift := load64 (st+16) t
    let ctrl := load64 (st+24) t
    let c := Guest.Keyboard.scanCode code shift
    if code == 1 then store64 (st+40) 0 t
    else if ctrl == 1 && code == 22 then uppercase input (load64 st t) (store64 (st+40) 0 t)
    else if ctrl == 1 && code == 38 then store64 (st+96) 0 (store64 (st+8) 0 (store64 st 0 (store64 (st+40) 0 t)))
    else if code == 105 then store64 (st+8) (if load64 (st+8) t == 0 then 0 else load64 (st+8) t-1) t
    else if code == 106 then store64 (st+8) (if load64 (st+8) t == load64 st t then load64 st t else load64 (st+8) t+1) t
    else if code == 102 then store64 (st+96) 0 (store64 (st+8) 0 t)
    else if code == 107 then store64 (st+8) (load64 st t) t
    else if code == 104 then store64 (st+96) (if load64 (st+96) t < 1024 then 0 else load64 (st+96) t-1024) t
    else if code == 109 then store64 (st+96) (if load64 (st+96) t+1024 > load64 st t then load64 st t else load64 (st+96) t+1024) t
    else if code == 14 then erase 0 (store64 (st+40) 0 t)
    else if code == 111 then erase 1 (store64 (st+40) 0 t)
    else if c != 0 && ctrl == 0 then insert c (store64 (st+40) 0 t)
    else t

def ipc (endpoint surface t : UInt64) : UInt64 :=
  let length := Guest.syscall 36 endpoint incoming 1024 0 t
  if length == 0 || length == error then t else
    let token := load64 (incoming+8) length
    let rights := load64 (incoming+16) length
    let abi := load64 (incoming+24) length
    let h := load64 (command+8) length
    let result := if length >= 96 && abi == 2 && (rights &&& 0x100000000) != 0 &&
        load64 command length == 21 && load64 (command+56) length == 1 then Guest.LiveApps.countObject h length
      else Guest.LiveApps.fail 1 length
    let t := store64 (st+48) h result
    let t := store64 (st+80) (load64 wire result) t
    let t := store64 (st+56) (load64 (wire+8) t) t
    let t := store64 (st+64) (load64 (wire+16) t) t
    let t := store64 (st+72) (load64 (wire+24) t) t
    let t := copy (wire+64) (st+256) 32 t
    let t := store64 (st+40) 1 t
    let t := reply token result t
    draw surface t

partial def loop (endpoint surface t : UInt64) : UInt64 :=
  let t := ipc endpoint surface t
  let packed := Guest.syscall 90 surface 0 0 0 t
  if packed == 0 || packed == error then
    let t := if load64 (st+88) t == 1 then redrawInput surface (store64 (st+88) 0 t) else t
    loop endpoint surface (Guest.syscall 9 0 0 0 0 t)
  else
    let oldLength := load64 st t
    let oldMode := load64 (st+40) t
    let oldScroll := load64 (st+96) t
    let oldRow := visibleRow oldScroll oldLength 0 0 t
    let t := Guest.Effects.effectValue t oldRow
    let ev := Guest.Structured.event (packed >>> 48) ((packed >>> 32) &&& 65535) 0 0 0 (packed &&& 0xffffffff)
    let t := match eventCode ev with
      | .ok code => key code ev.sequence t
      | .error _ => if ev.kind == 65535 || packed == 0x300000000 then store64 (st+16) 0 (store64 (st+24) 0 t) else t
    let t := if packed >>> 48 == 1 && (packed &&& 0xffffffff) != 0 then
        let last := load64 (st+104) t
        let t := store64 (st+104) (if oldRow > last then oldRow else last) t
        let t := if oldMode != load64 (st+40) t || oldScroll != load64 (st+96) t then store64 (st+112) 1 t else t
        store64 (st+88) 1 t
      else t
    loop endpoint surface t

def main (initial : UInt64) : UInt64 :=
  let surface := Guest.syscall 80 0 0 0 0 initial
  if surface == error then Guest.syscall 10 1 0 0 0 initial else
    let t := zero st 64 surface
    let t := draw surface t
    loop (self t) surface t
end Guest.TextTools
