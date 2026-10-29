import Lean
import Util
import Guest.Raster
import Guest.Keyboard
import Guest.Structured
namespace Main
open Guest Guest.LiveSDK Guest.Raster Guest.Structured

-- Elaboration itself is executable build input and runs inside the OS sandbox.
-- Only explicitly exported immutable resources are visible at /input.
elab "creator_resources" : command => do
  let text ← IO.FS.readFile "/input/accent.txt"
  let some value := text.trimAscii.toString.toNat? | throwError "accent.txt must contain a decimal integer"
  if value > 255 then throwError "accent.txt is limited to 0..255"
  Lean.Elab.Command.elabCommand (← `(def $(Lean.mkIdent `accent) : UInt64 := $(Lean.quote value)))
  let a ← IO.FS.readBinFile "/input/assets/a.txt"
  let b ← IO.FS.readBinFile "/input/assets/b.txt"
  let c ← IO.FS.readBinFile "/input/assets/c.txt"
  let total := a.size+b.size+c.size
  Lean.Elab.Command.elabCommand (← `(def $(Lean.mkIdent `resourceBytes) : UInt64 := $(Lean.quote total)))

creator_resources

def state : UInt64 := 0x6e0000
def buffer : UInt64 := 0x700000
def fg : UInt64 := 0xe1eff7
def bg : UInt64 := 0x142b35

def label (id x y t : UInt64) : UInt64 :=
  if id == 0 then
    let t := store64 (0x414000+0) 4919430837382497623 t
    let t := store64 (0x414000+8) 2319107879749375008 t
    let t := store64 (0x414000+16) 2325059535804650051 t
    let t := store64 (0x414000+24) 5557513547166995014 t
    let t := store64 (0x414000+32) 5497001980500134997 t
    let t := store64 (0x414000+40) 4847362278478061637 t
    let t := store64 (0x414000+48) 84 t
    text 0x414000 49 x y fg bg t
  else
  if id == 1 then
    let t := store64 (0x414000+0) 4778953761451170132 t
    let t := store64 (0x414000+8) 4692849021538161737 t
    let t := store64 (0x414000+16) 4764860221472981843 t
    let t := store64 (0x414000+24) 4990904625307272001 t
    let t := store64 (0x414000+32) 3264074351793680160 t
    let t := store64 (0x414000+40) 23152713978290252 t
    text 0x414000 47 x y fg bg t
  else
  if id == 2 then
    let t := store64 (0x414000+0) 64069408080723 t
    text 0x414000 6 x y fg bg t
  else
  if id == 3 then
    let t := store64 (0x414000+0) 16417135695187798 t
    text 0x414000 7 x y fg bg t
  else
  if id == 4 then
    let t := store64 (0x414000+0) 5638874311051595587 t
    let t := store64 (0x414000+8) 3822420 t
    text 0x414000 11 x y fg bg t
  else
  if id == 5 then
    let t := store64 (0x414000+0) 64129319852354 t
    text 0x414000 6 x y fg bg t
  else
  if id == 6 then
    let t := store64 (0x414000+0) 16418218059580759 t
    text 0x414000 7 x y fg bg t
  else
  if id == 7 then
    let t := store64 (0x414000+0) 16418243795436353 t
    text 0x414000 7 x y fg bg t
  else
  if id == 8 then
    let t := store64 (0x414000+0) 4919433066655535169 t
    let t := store64 (0x414000+8) 4851033547819274784 t
    let t := store64 (0x414000+16) 4202779105843880005 t
    text 0x414000 24 x y fg bg t
  else
  if id == 9 then
    let t := store64 (0x414000+0) 4919422045735702339 t
    let t := store64 (0x414000+8) 5712907731477615392 t
    let t := store64 (0x414000+16) 6147499567340265556 t
    let t := store64 (0x414000+24) 2329303569403158612 t
    let t := store64 (0x414000+32) 2329286007278554697 t
    let t := store64 (0x414000+40) 5263425 t
    text 0x414000 43 x y fg bg t
  else
    t

@[noinline] def report (s : Util.Summary) (t : UInt64) : UInt64 :=
  let t := label 2 8 56 t
  let t := hex s.score 8 50 56 0xb8e5a2 bg t
  let t := label 3 150 56 t
  let t := hex s.vowels 8 204 56 fg bg t
  let t := label 4 310 56 t
  let t := hex s.consonants 8 388 56 fg bg t
  let t := label 5 8 76 t
  hex s.bytes 8 50 76 fg bg t

def draw (surface t : UInt64) : UInt64 :=
  let n := load64 state t
  let t := fill 0 0 640 352 bg t
  let t := label 0 8 8 t
  let t := label 1 8 26 t
  let t := report (Util.analyze (bytes buffer n 1024) accent t) t
  let t := label 6 150 76 t
  let t := hex Util.Weight 4 204 76 fg bg t
  let t := label 7 310 76 t
  let t := hex accent 4 364 76 fg bg t
  let t := label 8 8 96 t
  let t := hex resourceBytes 8 164 96 fg bg t
  let t := text buffer (if n > 103 then 103 else n) 8 130 fg bg t
  let t := if n > 103 then text (buffer+103) (if n-103 > 103 then 103 else n-103) 8 144 fg bg t else t
  let t := if n > 206 then text (buffer+206) (if n-206 > 103 then 103 else n-206) 8 158 fg bg t else t
  let t := label 9 8 322 t
  upload surface 0 901120 0 t

def key (code down t : UInt64) : UInt64 :=
  if code == 42 || code == 54 then store64 (state+8) (if down == 0 then 0 else 1) t
  else if code == 29 || code == 97 then store64 (state+16) (if down == 0 then 0 else 1) t
  else if down == 0 then t else
    let n := load64 state t
    if load64 (state+16) t == 1 && code == 38 then store64 state 0 t
    else if code == 14 then store64 state (if n == 0 then 0 else n-1) t
    else
      let c := Guest.Keyboard.scanCode code (load64 (state+8) t)
      if c >= 32 && c <= 126 && n < 1024 && load64 (state+16) t == 0 then
        store64 state (n+1) (store8 (buffer+n) c t)
      else t

partial def loop (surface t : UInt64) : UInt64 :=
  let packed := syscall 90 surface 0 0 0 t
  if packed == 0 || packed == error then loop surface (syscall 9 0 0 0 0 t) else
    let ev := event (packed >>> 48) ((packed >>> 32) &&& 65535) 0 0 0 (packed &&& 0xffffffff)
    let t := match eventCode ev with
      | .ok code => key code ev.sequence t
      | .error _ => if ev.kind == 65535 || packed == 0x300000000 then store64 (state+8) 0 (store64 (state+16) 0 t) else t
    let t := if packed >>> 48 == 1 && (packed &&& 0xffffffff) != 0 then draw surface t else t
    loop surface t

def main (initial : UInt64) : UInt64 :=
  let surface := syscall 80 0 0 0 0 initial
  if surface == error then syscall 10 1 0 0 0 initial else
    let t := zero state 8 surface
    loop surface (draw surface t)
end Main
