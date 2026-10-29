import Guest.Labels
import Guest.Keyboard
import Guest.ProjectSDK
import Guest.ProjectGraph
import Guest.Compositor
import Guest.Structured
namespace Guest.Desktop
open Guest.LiveSDK
open Guest.Raster
open Guest.ProjectSDK
def st : UInt64 := 0x6e0000
def file (i : UInt64) : UInt64 := 0x6e2000+i*256
def dataAt (i : UInt64) : UInt64 := 0x700000+i*32768
def row : UInt64 := file (load64 (st+8) 0)
def fg : UInt64 := 0xd8e6ed
def bg : UInt64 := 0x101b25
def selected (t : UInt64) : UInt64 := file (load64 (st+8) t)
def message (id t : UInt64) : UInt64 := store64 (st+56) id t
partial def loadChunks (h dst total off t : UInt64) : UInt64 :=
  if off == total then t else
    let n := if total-off > 512 then 512 else total-off
    let r := read h off n t
    if r == error || status r != 0 || result r != n then error else
      loadChunks h dst total (off+n) (copy (wire+64) (dst+off) n r)
partial def appendChunks (h src total off t : UInt64) : UInt64 :=
  if off == total then t else
    let n := if total-off > 512 then 512 else total-off
    let r := append h off (src+off) n t
    if r == error || status r != 0 then error else appendChunks h src total (off+n) r

def saveBytes (src n kind parent t : UInt64) : UInt64 :=
  let r := stage n kind parent t
  if r == error || status r != 0 then error else
    let h := result r
    let r := appendChunks h src n 0 r
    if r == error then abortStage h r else
      let r := stageDigest h r
      if r == error || status r != 0 then error else
        let t := copy (wire+64) digest 32 r
        let r := commit h digest t
        if r == error || status r != 0 then error else h

partial def initFiles (i t : UInt64) : UInt64 :=
  if i == 8 then t else
    let t := zero (file i) 32 t
    initFiles (i+1) (store64 (file i+48) (dataAt i) t)

def newProject (t : UInt64) : UInt64 :=
  let t := zero st 32 t
  let t := store64 (st+312) 0 t
  let t := store64 (st+352) 0 t
  let t := store64 (st+320) 0 t
  let t := store64 (st+296) 0 t
  let t := store64 (st+304) 0 t
  let t := zero 0x6e1000 24 t
  let t := initFiles 0 t
  let t := store64 st 2 t
  let t := store64 (file 0+40) 9 t
  let t := store64 (file 0+128) 0x61656c2e6e69614d t
  let t := store8 (file 0+136) 110 t
  let t := store64 (file 1+40) 9 t
  let t := store64 (file 1+128) 0x61656c2e6c697455 t
  let t := store8 (file 1+136) 110 t
  let t := store64 (st+72) 1 t
  let t := store64 (st+80) 0 t
  message 15 t

partial def sourceLines (src total i line col scroll caret t : UInt64) : UInt64 :=
  if i == total then
    if line >= scroll && line < scroll+25 && col < 78 then char (164+col*6) (48+(line-scroll)*11) 95 fg bg t else t
  else if line >= scroll+25 then t else
    let c := load8 (src+i) t
    if Guest.Structured.continuation c then sourceLines src total (i+1) line col scroll caret t else
    let t := if line >= scroll && col < 78 then
        char (164+col*6) (48+(line-scroll)*11) (if c >= 128 then 63 else if c == 9 then 32 else if c == 10 then 32 else c)
          fg (if i == caret then 0x506780 else if load64 (st+88) t == 1 then 0x34485b else
            if load64 (st+88) t == 2 && i >= (if load64 (st+224) t < caret then load64 (st+224) t else caret) &&
              i < (if load64 (st+224) t > caret then load64 (st+224) t else caret) then 0x34485b else bg) t else t
    if c == 10 then sourceLines src total (i+1) (line+1) 0 scroll caret t
    else sourceLines src total (i+1) line (col+1) scroll caret t
partial def fileList (i t : UInt64) : UInt64 :=
  if i == load64 st t then t else
    let f := file i
    let t := text (f+128) (load64 (f+40) t) 8 (52+i*16) fg (if i == load64 (st+8) t then 0x364c61 else bg) t
    let t := if load64 (f+16) t != 0 then char 142 (52+i*16) 42 0xe9bc75 bg t else t
    fileList (i+1) t

def checkpointDraw (t : UInt64) : UInt64 :=
  if load64 (st+352) t == 0 then Guest.Labels.say 96 8 309 0xaac9aa bg t else
    let t := fill 0 180 640 137 0x203447 t
    let t := Guest.Labels.say (if load64 (st+352) t == 1 then 97 else 99) 8 185 fg 0x203447 t
    let t := Guest.Labels.say (if load64 (st+352) t == 1 then 98 else 100) 8 201 fg 0x203447 t
    let t := Guest.Labels.say 102 8 219 fg 0x203447 t
    let t := text 0x6e1040 (load64 (st+48) t) 164 219 fg 0x203447 t
    let t := Guest.Raster.hex (load64 st t) 2 564 219 fg 0x203447 t
    let t := if load64 (st+352) t != 2 then t else
      let t := Guest.Raster.hex (load64 (st+360) t) 4 340 235 fg 0x203447 t
      Guest.Raster.hex (load64 (st+368) t) 4 390 235 fg 0x203447 t
    let t := Guest.Labels.say 103 8 251 fg 0x203447 t
    let t := Guest.Raster.hex (load64 (0x6ef000+160) t) 16 8 269 fg 0x203447 t
    Guest.Raster.hex (load64 (0x6ef000+192) t) 16 8 285 fg 0x203447 t

def draw (surface t : UInt64) : UInt64 :=
  let t := fill 0 0 640 352 bg t
  let t := Guest.Labels.say 9 8 3 fg bg t
  let t := Guest.Labels.say 10 8 15 fg bg t
  let t := Guest.Labels.say 11 8 27 0x9fc6a5 bg t
  let t := fill 0 42 640 2 0x506780 t
  let t := fileList 0 t
  let f := selected t
  let t := sourceLines (load64 (f+48) t) (load64 f t) 0 0 0 (load64 (f+32) t) (load64 (f+8) t) t
  let t := Guest.Labels.say (load64 (st+56) t) 8 322 0xe9bc75 bg t
  let t := if load64 (st+56) t == 40 then text 0x6e5000 (load64 (st+160) t) 164 305 0xf1988c bg t else t
  let t := if load64 (st+72) t != 0 then text 0x6e4000 (load64 (st+80) t) 8 336 fg bg t else
    Guest.Labels.say (if load64 (f+16) t != 0 then 13 else 12) 8 338 fg bg t
  let t := checkpointDraw t
  upload surface 0 901120 0 t

partial def saveFiles (i t : UInt64) : UInt64 :=
  if i == load64 st t then t else
    let f := file i
    let h := if load64 (f+24) t != 0 && load64 (f+16) t != 1 then load64 (f+24) t else
      saveBytes (load64 (f+48) t) (load64 f t) 10 (load64 (f+24) t) t
    if h == error then error else
      let r := nodeMetadata h t
      if r == error || status r != 0 then error else
        let t := copy (wire+64) (f+64) 64 r
        let t := store64 (f+24) h t
        let t := store64 (f+16) (if load64 (f+16) t != 0 then 2 else 0) t
        saveFiles (i+1) t
partial def commitFlags (i t : UInt64) : UInt64 :=
  if i == load64 st t then t else commitFlags (i+1) (store64 (file i+16) 0 t)
partial def manifestEntries (i t : UInt64) : UInt64 :=
  if i == load64 st t then t else
    let e := 0x6f0020+i*128
    let f := file i
    let t := store64 e 10 t
    let t := store64 (e+8) (load64 (f+40) t) t
    let t := copy (f+64) (e+16) 32 t
    let t := copy (f+128) (e+48) (load64 (f+40) t) t
    manifestEntries (i+1) t
partial def artifactEntries (i t : UInt64) : UInt64 :=
  if i == load64 (st+296) t then t else
    let t := copy (0x6eb000+i*128) (0x6f0020+(load64 st t+i)*128) 128 t
    artifactEntries (i+1) t

partial def sortManifestEntries (count i j t : UInt64) : UInt64 :=
  if i >= count then t else
  if j >= count then sortManifestEntries count (i+1) (i+2) t else
    let a := 0x6f0020+i*128
    let b := 0x6f0020+j*128
    let t := if Guest.ProjectGraph.lessName (b+48) (load64 (b+8) t) (a+48) (load64 (a+8) t) 0 t then
      let t := copy a 0x6e9000 128 t
      let t := copy b a 128 t
      copy 0x6e9000 b 128 t else t
    sortManifestEntries count i (j+1) t

partial def sortFiles (i j t : UInt64) : UInt64 :=
  if i >= load64 st t then t else
  if j >= load64 st t then sortFiles (i+1) (i+2) t else
    let a := file i
    let b := file j
    let t := if Guest.ProjectGraph.lessName (b+128) (load64 (b+40) t) (a+128) (load64 (a+40) t) 0 t then
      let t := copy a 0x6e9000 256 t
      let t := copy b a 256 t
      copy 0x6e9000 b 256 t else t
    sortFiles i (j+1) t

def commitProject (t : UInt64) : UInt64 :=
  let t := sortFiles 0 1 t
  let t := saveFiles 0 t
  if t == error then message 24 t else
    let t := zero 0x6f0000 520 t
    let t := store64 0x6f0000 0x31464e4d544c t
    let t := store64 0x6f0008 1 t
    let total := load64 st t+load64 (st+296) t
    let detail := load64 (st+304) t
    let t := store64 0x6f0010 total t
    let t := store64 0x6f0018 detail t
    let t := manifestEntries 0 t
    let t := artifactEntries 0 t
    let t := sortManifestEntries total 0 1 t
    let t := copy 0x6ec000 (0x6f0020+total*128) detail t
    let bytes := 32+total*128+detail
    let previous := load64 (st+32) t
    let r := if previous == 0 then error else Guest.LiveSDK.metadata previous t
    let sameLength := r == 96 && status r == 0 && load64 (wire+16) r == bytes
    let checked := if sameLength then loadChunks previous 0x6f4000 bytes 0 r else r
    -- Saving unchanged canonical bytes must preserve the exact selected revision.
    -- Compare the complete bounded Manifest, including names, removed entries,
    -- attached lineage/releases and details, rather than relying on dirty flags.
    if sameLength && checked != error && Guest.ProjectGraph.equal 0x6f0000 0x6f4000 bytes checked then
      message 25 (commitFlags 0 checked)
    else
      let h := saveBytes 0x6f0000 bytes 11 (load64 (st+32) checked) checked
      if h == error then message 24 t else
        let r := publish h (load64 (st+24) t) 0x6e1000 0x6e1040 (load64 (st+48) t) t
        if r == error || status r != 0 then message 24 r else
          let root := result r
          let t := store64 (st+24) root r
          let t := store64 (st+32) h t
          let t := copy (wire+64) 0x6e1000 32 t
          let launcher := Guest.syscall 97 1 0 0 0 t
          let t := delegate root launcher 127 t
          let shell := Guest.syscall 97 4 0 0 0 t
          let t := delegate root shell 127 t
          message 25 (commitFlags 0 t)

partial def openFiles (root manifest count i sources artifacts t : UInt64) : UInt64 :=
  if i == count then
    if sources == 0 then error else store64 (st+296) artifacts (store64 st sources t)
  else
    let e := 0x6f0020+i*128
    let kind := load64 e t
    let r := resolve root (e+16) t
    if r == error || status r != 0 || load64 (wire+32) r != kind then error else
      if kind != 10 then
        if artifacts >= 24 || (kind != 12 && kind != 13 && kind != 14 && kind != 15) then error else
          let t := copy e (0x6eb000+artifacts*128) 128 r
          openFiles root manifest count (i+1) sources (artifacts+1) t
      else if sources >= 8 || load64 (wire+16) r > 32768 then error else
        let h := result r
        let n := load64 (wire+16) r
        let f := file sources
        let t := store64 f n r
        let t := store64 (f+24) h t
        let t := store64 (f+40) (load64 (e+8) t) t
        let t := copy (e+48) (f+128) (load64 (e+8) t) t
        let r := loadChunks h (load64 (f+48) t) n 0 t
        if r == error then error else openFiles root manifest count (i+1) (sources+1) artifacts r

def openRootReply (r : UInt64) : UInt64 :=
  let root := result r
  let next := load64 (wire+24) r
  let n := load64 (wire+16) r
  let t := copy (wire+64) 0x6e1000 32 r
  let t := copy (wire+96) 0x6e1040 n t
  let t := store64 (st+48) n t
  let r := openHead root t
  if r == error || status r != 0 || load64 (wire+16) r > 8224 then message 24 r else
    let h := result r
    let total := load64 (wire+16) r
    let t := loadChunks h 0x6f0000 total 0 r
    let count := load64 0x6f0010 t
    let detail := load64 0x6f0018 t
    if t == error || count > 32 || detail > 4096 || total != 32+count*128+detail then message 24 t else
      let t := copy (0x6f0020+count*128) 0x6ec000 detail t
      let t := store64 (st+304) detail t
      let t := initFiles 0 t
      let t := store64 st count t
      let t := store64 (st+8) 0 t
      let t := store64 (st+24) root t
      let t := store64 (st+32) h t
      let t := store64 (st+40) next t
      let t := openFiles root h count 0 0 0 t
      message (if t == error then 24 else 28) t

-- A portal request freezes the set already granted to this incarnation. Hashes
-- alone never select or authorize content; new handles come only from Objects.
partial def rememberRoots (cursor fuel t : UInt64) : UInt64 :=
  if fuel == 0 then t else
    let r := roots cursor t
    if r == error || status r != 0 || result r == 0 then r else
      let h := result r
      if (h &&& 255) >= 64 then error else
        let t := store64 (0x6ea000+(h &&& 255)*8) h r
        rememberRoots (load64 (wire+24) t) (fuel-1) t

def requestProjectPortal (t : UInt64) : UInt64 :=
  let t := zero 0x6ea000 64 t
  let t := rememberRoots 0 64 t
  let nonce := load64 (st+240) t+1
  let t := store64 (st+240) nonce t
  let t := store64 (st+232) 1 t
  let t := store64 (st+248) 0 t
  let shell := syscall 97 4 0 0 0 t
  let t := header 3 0 nonce 0 0 0 0 t
  let r := syscall 30 shell wire 64 1024 t
  if r != 64 || status r != 0 || result r != nonce then
    message 18 (store64 (st+232) 0 r)
  else r

def openProject (t : UInt64) : UInt64 :=
  if load64 (st+64) t == 1 then requestProjectPortal t else
    let r := roots (load64 (st+40) t) t
    if r == error || status r != 0 then message 18 r else
      if result r != 0 then openRootReply r else
        let t := store64 (st+40) 0 r
        let r := roots 0 t
        if r == error || status r != 0 then message 18 r else
          if result r == 0 then requestProjectPortal r else openRootReply r

partial def findFreshRoot (cursor fuel t : UInt64) : UInt64 :=
  if fuel == 0 then 0 else
    let r := roots cursor t
    if r == error || status r != 0 || result r == 0 then 0 else
      let h := result r
      if (h &&& 255) < 64 && load64 (0x6ea000+(h &&& 255)*8) r != h then r else
        findFreshRoot (load64 (wire+24) r) (fuel-1) r

def pollProjectPortal (t : UInt64) : UInt64 :=
  if load64 (st+232) t == 0 then t else
    let round := load64 (st+248) t+1
    let t := store64 (st+248) round t
    let r := findFreshRoot 0 64 t
    if r != 0 then
      let t := openRootReply r
      store64 (st+176) 2 (store64 (st+232) 0 t)
    else
      let shell := syscall 97 4 0 0 0 t
      let t := header 4 0 (load64 (st+240) t) 0 0 0 0 t
      let r := syscall 30 shell wire 64 1024 t
      if r != 64 || status r != 0 || load64 (wire+16) r == 3 || round > 4096 then store64 (st+232) 0 r else
        if load64 (wire+16) r != 2 || result r == 0 then r else
          let h := result r
          let r := describeRoot h r
          if r != 160 || status r != 0 then store64 (st+232) 0 r else
            let t := openRootReply r
            store64 (st+176) 2 (store64 (st+232) 0 t)

partial def previous (p i t : UInt64) : UInt64 :=
  if i == 0 then 0 else if Guest.Structured.continuation (load8 (p+i-1) t) then previous p (i-1) t else i-1
partial def following (p n i t : UInt64) : UInt64 :=
  if i >= n then n else if Guest.Structured.continuation (load8 (p+i) t) then following p n (i+1) t else i
partial def shiftRight (p beginIndex count t : UInt64) : UInt64 :=
  if count <= beginIndex then t else shiftRight p beginIndex (count-1) (store8 (p+count) (load8 (p+count-1) t) t)

def remember (f t : UInt64) : UInt64 :=
  let t := copy (load64 (f+48) t) 0x750000 (load64 f t) t
  let t := store64 (st+96) (load64 f t) t
  let t := store64 (st+104) (load64 (f+8) t) t
  let t := store64 (st+112) (load64 (st+8) t+1) t
  store64 (st+120) 0 t

def undo (redo t : UInt64) : UInt64 :=
  let f := selected t
  let expected := load64 (st+(if redo == 1 then 120 else 112)) t
  if expected != load64 (st+8) t+1 then t else
    let src := if redo == 1 then 0x760000 else 0x750000
    let dst := if redo == 1 then 0x750000 else 0x760000
    let t := copy (load64 (f+48) t) dst (load64 f t) t
    let oldLen := load64 f t
    let oldCaret := load64 (f+8) t
    let t := copy src (load64 (f+48) t) (load64 (st+96) t) t
    let t := store64 f (load64 (st+96) t) t
    let t := store64 (f+8) (load64 (st+104) t) t
    let t := store64 (st+96) oldLen t
    let t := store64 (st+104) oldCaret t
    let t := store64 (st+(if redo == 1 then 120 else 112)) 0 t
    let t := store64 (st+(if redo == 1 then 112 else 120)) expected t
    store64 (f+16) 1 t

def insert (c t : UInt64) : UInt64 :=
  let f := selected t
  let n := load64 f t
  let p := load64 (f+48) t
  if n >= 32768 then message 24 t else
    let t := remember f t
    let selection := load64 (st+88) t
    let anchor := load64 (st+224) t
    let caret := load64 (f+8) t
    let left := if selection == 1 then 0 else if selection == 2 && anchor < caret then anchor else caret
    let right := if selection == 1 then load64 f t else if selection == 2 && anchor > caret then anchor else caret
    let t := if selection != 0 then
      let t := copy (p+right) (p+left) (load64 f t-right) t
      let t := store64 f (load64 f t-right+left) t
      store64 (f+8) left t else t
    let n := load64 f t
    let caretIndex := load64 (f+8) t
    let t := shiftRight p caretIndex n t
    let t := store8 (p+caretIndex) c t
    let t := store64 f (n+1) t
    let t := store64 (f+8) (caretIndex+1) t
    let t := store64 (st+88) 0 t
    store64 (f+16) 1 t

def erase (forward t : UInt64) : UInt64 :=
  let f := selected t
  let p := load64 (f+48) t
  let n := load64 f t
  let caretIndex := load64 (f+8) t
  let left := if load64 (st+88) t == 1 then 0 else if load64 (st+88) t == 2 then
    if load64 (st+224) t < caretIndex then load64 (st+224) t else caretIndex
    else if forward == 1 then caretIndex else previous p caretIndex t
  let right := if load64 (st+88) t == 1 then n else if load64 (st+88) t == 2 then
    if load64 (st+224) t > caretIndex then load64 (st+224) t else caretIndex
    else if forward == 1 then following p n (caretIndex+1) t else caretIndex
  if left >= right || right > n then t else
    let t := remember f t
    let t := copy (p+right) (p+left) (n-right) t
    let t := store64 f (n-right+left) t
    let t := store64 (f+8) left t
    let t := store64 (st+88) 0 t
    store64 (f+16) 1 t

def scanCode (code shift : UInt64) : UInt64 := Guest.Keyboard.scanCode code shift

def hexNibble (c : UInt64) : UInt64 :=
  if c >= 48 && c <= 57 then c-48 else if c >= 97 && c <= 102 then c-87 else error
partial def forkPublisherBytes (i t : UInt64) : UInt64 :=
  if i == 32 then t else
    let high := hexNibble (load8 (0x6e4000+i*2) t)
    let low := hexNibble (load8 (0x6e4001+i*2) t)
    if high == error || low == error then error else
      forkPublisherBytes (i+1) (store8 (0x6ef380+i) (high*16+low) t)
def finishFork (t : UInt64) : UInt64 :=
  if load64 (st+80) t != 64 then message 107 t else
    let decoded := forkPublisherBytes 0 t
    if decoded == error then message 107 decoded else
      let r := forkProject (load64 (st+24) decoded) 0x6e1000 0x6ef380 0x6ef300 (load64 (st+376) decoded) decoded
      if r != 256 || status r != 0 then message 107 (store64 (st+72) 0 r) else
        let root := result r
        let t := store64 (st+72) 0 r
        let t := openRootReply t
        let launcher := syscall 97 1 0 0 0 t
        let t := delegate root launcher 127 launcher
        let shell := syscall 97 4 0 0 0 t
        let t := delegate root shell 127 shell
        message 106 t

def acceptPrompt (t : UInt64) : UInt64 :=
  let mode := load64 (st+72) t
  let n := load64 (st+80) t
  if mode == 5 then finishFork t else
  if n == 0 || !Guest.ProjectGraph.validName 0x6e4000 n 63 t then message 24 t else
  if mode == 4 then
    let t := zero 0x6ef300 8 t
    let t := copy 0x6e4000 0x6ef300 n t
    let t := store64 (st+376) n t
    let t := store64 (st+72) 5 t
    message 105 (store64 (st+80) 0 t)
  else if mode == 1 then
    let t := copy 0x6e4000 0x6e1040 n t
    let t := store64 (st+48) n t
    let t := store64 (st+72) 0 t
    message 27 t
  else
    let count := load64 st t
    if mode == 2 && count >= 8 then message 24 t else
      let f := if mode == 2 then file count else selected t
      let t := if mode == 2 then
          let p := load64 (f+48) t
          let t := zero f 32 t
          let t := store64 (f+48) p t
          let t := store64 st (count+1) t
          store64 (st+8) count t
        else t
      let t := zero (f+128) 10 t
      let t := copy 0x6e4000 (f+128) n t
      let t := store64 (f+40) n t
      let t := store64 (f+16) 1 t
      store64 (st+72) 0 t

def removeFile (t : UInt64) : UInt64 :=
  let count := load64 st t
  let i := load64 (st+8) t
  if count <= 1 then message 24 t else
    let t := copy (file i) 0x6e9000 256 t
    let t := copy (file (i+1)) (file i) ((count-i-1)*256) t
    let t := copy 0x6e9000 (file (count-1)) 256 t
    let t := store64 st (count-1) t
    let t := store64 (st+8) 0 t
    message 26 t

def buildProject (t : UInt64) : UInt64 :=
  let t := commitProject t
  if load64 (st+56) t == 24 || load64 (st+24) t == 0 then message 24 t else
    let broker := syscall 97 5 0 0 0 t
    let r := delegate (load64 (st+24) t) broker 73 t
    if r == error || status r != 0 then message 22 r else
      let root := result r
      let t := header 1 root 0 0 0 0 0 r
      let r := syscall 30 broker wire 64 1024 t
      if r == error || status r != 0 then message 22 r else
        let t := store64 (st+144) (result r) r
        let t := store64 (st+152) broker t
        message 23 t

def requestRetention (t : UInt64) : UInt64 :=
  if load64 (st+24) t == 0 then message 24 t else
    let shell := syscall 97 4 0 0 0 t
    let r := delegate (load64 (st+24) t) shell 127 t
    if r == error || status r != 0 then message 36 r else
      let root := result r
      let t := header 2 root 0 0 0 0 0 r
      let t := copy 0x6e1000 (wire+64) 32 t
      let r := syscall 30 shell wire 96 1024 t
      message (if r == error || status r != 0 then 36 else 4) r

def pollBuild (t : UInt64) : UInt64 :=
  if load64 (st+144) t == 0 then t else
    let t := header 4 (load64 (st+144) t) 0 0 0 0 0 t
    let r := syscall 30 (load64 (st+152) t) wire 64 1024 t
    if r == error || status r != 0 || load64 (wire+16) r == 1 then t else
      let t := if load64 (wire+48) r != 0 then store64 (st+216) (load64 (wire+48) r) r else r
      let t := store64 (st+144) 0 t
      let t := copy (wire+128) 0x6e5000 (if r > 128 then r-128 else 0) t
      let t := store64 (st+160) (if r > 128 then r-128 else 0) t
      store64 (st+176) 2 (message (if load64 (wire+16) t == 2 then 46 else 40) t)

partial def lineColumn (p length offset i line col t : UInt64) : UInt64 :=
  if i >= offset || i >= length then (line <<< 32) ||| col else
    let c := load8 (p+i) t
    if c == 10 then lineColumn p length offset (i+1) (line+1) 0 t
    else lineColumn p length offset (i+1) line (col+(if Guest.Structured.continuation c then 0 else 1)) t
partial def position (p length targetLine targetCol i line col t : UInt64) : UInt64 :=
  if i >= length || (line == targetLine && col >= targetCol) then following p length i t else
    let c := load8 (p+i) t
    if line == targetLine && c == 10 then i else
    if c == 10 then position p length targetLine targetCol (i+1) (line+1) 0 t
    else position p length targetLine targetCol (i+1) line (col+(if Guest.Structured.continuation c then 0 else 1)) t

partial def findColon (p i n t : UInt64) : UInt64 :=
  if i == n then n else if load8 (p+i) t == 58 then i else findColon p (i+1) n t
partial def decimal (p n i value t : UInt64) : UInt64 :=
  if i == n then value else
    let c := load8 (p+i) t
    if c < 48 || c > 57 || value > 100000 then value else decimal p n (i+1) (value*10+c-48) t
partial def findFile (name n i t : UInt64) : UInt64 :=
  if i == load64 st t then error else
    let f := file i
    if load64 (f+40) t == n && Guest.ProjectGraph.equal (f+128) name n t then i else findFile name n (i+1) t

def navigateDiagnostic (t : UInt64) : UInt64 :=
  let n := load64 (st+160) t
  let colon := findColon 0x6e5000 0 (if n < 80 then n else 80) t
  let i := findFile 0x6e5000 colon 0 t
  if i == error then t else
    let next := findColon 0x6e5000 (colon+1) n t
    let line := decimal (0x6e5000+colon+1) (next-colon-1) 0 0 t
    let lastColon := findColon 0x6e5000 (next+1) n t
    let col := decimal (0x6e5000+next+1) (lastColon-next-1) 0 0 t
    let f := file i
    let t := store64 (st+8) i t
    let off := position (load64 (f+48) t) (load64 f t) (if line == 0 then 0 else line-1) col 0 0 0 t
    let t := store64 (f+8) off t
    store64 (f+32) (if line > 20 then line-10 else 0) t

def requestFork (t : UInt64) : UInt64 :=
  let t := commitProject t
  if load64 (st+56) t == 24 || load64 (st+24) t == 0 then message 107 t else
    let t := store64 (st+72) 4 t
    message 104 (store64 (st+80) 0 t)

def requestCheckpoint (t : UInt64) : UInt64 :=
  let t := commitProject t
  if load64 (st+56) t == 24 || load64 (st+24) t == 0 then message 101 t else
    let r := projectIdentity (load64 (st+24) t) t
    if r != 192 || status r != 0 then message 101 r else
      let t := copy (wire+160) (0x6ef000+160) 32 r
      let t := copy 0x6e1000 (0x6ef000+192) 32 t
      store64 (st+352) 1 t

def applyCheckpoint (t : UInt64) : UInt64 :=
  let root := load64 (st+24) t
  let r := checkpoint root (0x6ef000+192) t
  if r != 256 || status r != 0 then message 101 (store64 (st+352) 0 r) else
    let t := copy wire 0x6ef000 256 r
    let t := store64 (st+360) (load64 (wire+224) t) t
    let t := store64 (st+368) (load64 (wire+232) t) t
    let r := describeRoot root t
    if r != 160 || status r != 0 then message 101 (store64 (st+352) 0 r) else
      let t := openRootReply r
      store64 (st+352) 2 t

def requestVaultStatus (t : UInt64) : UInt64 :=
  let shell := syscall 97 4 0 0 0 t
  let t := header 5 0 0 0 0 0 0 t
  let r := syscall 30 shell wire 64 1024 t
  if r == 64 && status r == 0 then r else message 36 r

-- This semantic resource has a real consumer: creator's sandboxed elaborator
-- reads accent.txt and embeds its 0..255 value in the native scoring function.
-- Equal parsed values leave the source bytes alone; a changed value edits the
-- working buffer and acquires source lineage only at the ordinary F4 commit.
structure DecimalResource where
  original : UInt64
  proposed : UInt64
  sourceLength : UInt64

partial def parseResource (p n i value digits : UInt64) (failure : Guest.Structured.Checked) (t : UInt64) : Guest.Structured.Checked :=
  if i == n then if digits == 0 then failure else .ok value else
    let c := load8 (p+i) t
    if c == 10 && i+1 == n && digits > 0 then .ok value
    else if c < 48 || c > 57 || digits >= 3 || value*10+c-48 > 255 then failure
    else parseResource p n (i+1) (value*10+c-48) (digits+1) failure t

def openResource (t : UInt64) : UInt64 :=
  let f := selected t
  if load64 (f+40) t != 10 || load64 (f+128) t != 0x742e746e65636361 ||
    load8 (f+136) t != 120 || load8 (f+137) t != 116 then message 76 t else
    match parseResource (load64 (f+48) t) (load64 f t) 0 0 0 (.error 1) t with
    | .error _ => message 77 t
    | .ok value =>
      let resource : DecimalResource := ⟨value,value,load64 f t⟩
      let t := store64 (st+328) resource.original t
      let t := store64 (st+336) resource.proposed t
      let t := store64 (st+344) resource.sourceLength t
      store64 (st+312) 1 t

def applyResource (t : UInt64) : UInt64 :=
  let resource : DecimalResource := ⟨load64 (st+328) t,load64 (st+336) t,load64 (st+344) t⟩
  let t := store64 (st+312) 0 t
  if resource.original == resource.proposed then message 74 t else
    let f := selected t
    let t := remember f t
    let p := load64 (f+48) t
    let v := resource.proposed
    let digits := if v >= 100 then 3 else if v >= 10 then 2 else 1
    let t := if digits == 3 then store8 p (48+v/100) t else t
    let t := if digits >= 2 then store8 (p+digits-2) (48+(v/10)%10) t else t
    let t := store8 (p+digits-1) (48+v%10) t
    let t := store8 (p+digits) 10 t
    let t := store64 f (digits+1) t
    let t := store64 (f+8) digits t
    message 80 (store64 (f+16) 1 t)

def key (code down surface t : UInt64) : UInt64 :=
  if code == 42 || code == 54 then store64 (st+64) (if down == 0 then 0 else 1) t
  else if code == 29 || code == 97 then store64 (st+136) (if down == 0 then 0 else 1) t
  else if down == 0 then t else
    let shift := load64 (st+64) t &&& 1
    let ctrl := load64 (st+136) t &&& 1
    let c := scanCode code shift
    if load64 (st+352) t != 0 then
      if code == 1 then store64 (st+352) 0 t else
      if code == 28 then
        if load64 (st+352) t == 1 then applyCheckpoint t else store64 (st+352) 0 t
      else t
    else if load64 (st+312) t == 1 then
      if code == 1 then store64 (st+312) 0 t
      else if code == 28 then applyResource t
      else if code == 103 then store64 (st+336) (if load64 (st+336) t == 255 then 255 else load64 (st+336) t+1) t
      else if code == 108 then store64 (st+336) (if load64 (st+336) t == 0 then 0 else load64 (st+336) t-1) t
      else t
    else if load64 (st+72) t != 0 then
      if code == 1 then store64 (st+72) 0 t
      else if code == 28 then acceptPrompt t
      else if code == 14 then store64 (st+80) (if load64 (st+80) t == 0 then 0 else load64 (st+80) t-1) t
      else if c >= 33 && c <= 126 && load64 (st+80) t < (if load64 (st+72) t == 5 then 64 else 63) then
        let n := load64 (st+80) t
        store64 (st+80) (n+1) (store8 (0x6e4000+n) c t)
      else t
    else if code == 59 then newProject t
    else if code == 60 then openProject t
    else if code == 61 then store64 (st+8) ((load64 (st+8) t+1)%load64 st t) t
    else if code == 62 then commitProject t
    else if code == 63 then
      if shift == 1 && load64 (st+144) t != 0 then
        let t := header 5 (load64 (st+144) t) 0 0 0 0 0 t
        let t := syscall 30 (load64 (st+152) t) wire 64 1024 t
        store64 (st+144) 0 t
      else buildProject t
    else if code == 64 then
      if load64 (st+56) t == 40 then navigateDiagnostic t else
        store64 (st+320) 0 (store64 (st+128) (1-load64 (st+128) t) t)
    else if code == 15 && load64 (st+128) t == 1 then
      store64 (st+320) ((load64 (st+320) t+1)%(3+load64 (st+296) t)) t
    else if code == 65 || code == 66 then
      let t := store64 (st+72) (if code == 65 then 2 else 3) t
      let t := store64 (st+80) 0 t
      message 16 t
    else if code == 67 then removeFile t
    else if code == 68 then requestRetention t
    else if code == 87 then requestVaultStatus t
    else if ctrl == 1 && code == 33 then requestFork t
    else if ctrl == 1 && code == 37 then requestCheckpoint t
    else if ctrl == 1 && code == 18 then openResource t
    else if ctrl == 1 && code == 44 then undo 0 t
    else if ctrl == 1 && code == 21 then undo 1 t
    else if ctrl == 1 && code == 30 then store64 (st+88) 1 t
    else if code == 14 then erase 0 t
    else if code == 111 then erase 1 t
    else if code == 105 then
      let f := selected t
      let t := if shift == 1 && load64 (st+88) t == 0 then store64 (st+224) (load64 (f+8) t) t else t
      let t := store64 (st+88) (if shift == 1 then 2 else 0) t
      store64 (f+8) (previous (load64 (f+48) t) (load64 (f+8) t) t) t
    else if code == 106 then
      let f := selected t
      let t := if shift == 1 && load64 (st+88) t == 0 then store64 (st+224) (load64 (f+8) t) t else t
      let t := store64 (st+88) (if shift == 1 then 2 else 0) t
      store64 (f+8) (following (load64 (f+48) t) (load64 f t) (load64 (f+8) t+1) t) t
    else if code == 103 || code == 108 then
      let f := selected t
      let here := lineColumn (load64 (f+48) t) (load64 f t) (load64 (f+8) t) 0 0 0 t
      let line := here >>> 32
      let target := if code == 103 then (if line == 0 then 0 else line-1) else line+1
      store64 (f+8) (position (load64 (f+48) t) (load64 f t) target (here &&& 0xffffffff) 0 0 0 t) t
    else if code == 102 then store64 (selected t+8) 0 t
    else if code == 107 then store64 (selected t+8) (load64 (selected t) t) t
    else if code == 104 then
      let f := selected t
      store64 (f+32) (if load64 (f+32) t < 20 then 0 else load64 (f+32) t-20) t
    else if code == 109 then
      let f := selected t
      store64 (f+32) (load64 (f+32) t+20) t
    else if c != 0 && ctrl == 0 then insert c t
    else Guest.syscall 9 surface 0 0 0 t


def pointer (kind code value t : UInt64) : UInt64 :=
  if kind == 3 && code == 0 then store64 (st+184) (if value > 639 then 639 else value) t
  else if kind == 3 && code == 1 then store64 (st+192) (if value > 399 then 399 else value) t
  else if kind == 2 && code == 0 then store64 (st+184) (Guest.Compositor.boundedMotion (load64 (st+184) t) value 639) t
  else if kind == 2 && code == 1 then store64 (st+192) (Guest.Compositor.boundedMotion (load64 (st+192) t) value 399) t
  else if kind == 1 && code == 272 && value == 1 then
    let x := load64 (st+184) t
    let y := load64 (st+192) t
    if y < 96 || y >= 370 then t else
    if x < 156 then
      let i := (y-100)/16
      if i < load64 st t then store64 (st+8) i t else t
    else if x >= 164 then
      let f := selected t
      let target := load64 (f+32) t+(y-96)/11
      let off := position (load64 (f+48) t) (load64 f t) target ((x-164)/6) 0 0 0 t
      store64 (f+8) off t
    else t
  else t

partial def identityBytes (p i x y t : UInt64) : UInt64 :=
  if i == 32 then t else
    identityBytes p (i+1) x y (Guest.Raster.hex (load8 (p+i) t) 2 (x+i*12) y fg bg t)
def identityLine (p x y t : UInt64) : UInt64 := identityBytes p 0 x y t

def inspectedHandle (t : UInt64) : UInt64 :=
  let page := load64 (st+320) t
  if page == 0 then load64 (selected t+24) t
  else if page == 1 then load64 (st+32) t
  else if page == 2 then load64 (st+216) t
  else
    let index := page-3
    if index >= load64 (st+296) t then 0 else
      let r := resolve (load64 (st+24) t) (0x6eb000+index*128+16) t
      if r == error || status r != 0 then 0 else result r

partial def inspectEdges (i count t : UInt64) : UInt64 :=
  if i >= count then t else
    let e := 0x6ed100+i*128
    let y := 244+i*23
    let t := Guest.Raster.hex (load64 e t) 2 8 y fg bg t
    let n := load64 (e+8) t
    let t := text (e+48) (if n > 60 then 60 else n) 32 y fg bg t
    let t := Guest.Raster.hex (load64 (e+16) t) 16 32 (y+10) fg bg t
    inspectEdges (i+1) count t

def inspectDraw (surface t : UInt64) : UInt64 :=
  let r := projectIdentity (load64 (st+24) t) t
  let t := if r == 192 && status r == 0 then copy (wire+160) 0x6ee000 32 r else zero 0x6ee000 4 r
  let h := inspectedHandle t
  let r := if h != 0 then nodeMetadata h t else error
  let valid := r != error && r == 128 && status r == 0
  let t := if valid then copy wire 0x6ed000 128 r else zero 0x6ed000 16 r
  let t := if valid then
    let r := metadata h t
    if r != error && r == 96 && status r == 0 then copy (wire+64) 0x6ed080 32 r else zero 0x6ed080 4 r
    else zero 0x6ed080 4 t
  let kind := load64 (0x6ed000+32) t
  let t := fill 0 0 640 352 bg t
  let t := Guest.Labels.say 58 8 6 fg bg t
  let t := if valid then
    let t := Guest.Labels.say (if kind == 10 then 66 else if kind == 11 then 67 else if kind == 12 then 68 else if kind == 13 then 69 else 70) 8 22 0xaac9aa bg t
    let t := Guest.Labels.say 59 8 40 fg bg t
    let t := Guest.Raster.hex kind 2 8 52 fg bg t
    let t := Guest.Raster.hex 1 2 74 52 fg bg t
    let t := Guest.Raster.hex (load64 (0x6ed000+16) t) 8 142 52 fg bg t
    let t := Guest.Raster.hex (load64 (0x6ed000+48) t) 2 260 52 fg bg t
    let t := Guest.Labels.say 60 8 72 fg bg t
    let t := identityLine (0x6ed000+64) 8 84 t
    let t := Guest.Labels.say 61 8 100 fg bg t
    let t := identityLine (0x6ed000+96) 8 112 t
    let t := Guest.Labels.say 62 8 128 fg bg t
    let t := identityLine 0x6ed080 8 140 t
    let t := Guest.Labels.say 82 8 156 fg bg t
    let t := identityLine 0x6ee000 8 168 t
    let t := Guest.Labels.say 63 8 184 fg bg t
    let t := identityLine 0x6e1000 8 196 t
    let t := Guest.Labels.say 79 8 214 0x9fb6c9 bg t
    if kind == 10 then
      let t := Guest.Labels.say 78 8 236 fg bg t
      let f := selected t
      let t := text (f+128) (load64 (f+40) t) 8 250 fg bg t
      Guest.Labels.say 76 8 280 0x9fb6c9 bg t
    else
      let r := read h 0 32 t
      let count := if r == 96 && status r == 0 then load64 (wire+80) r else 0
      let count := if count > 4 then 4 else count
      let r := if count > 0 then read h 32 (count*128) r else r
      let t := if count > 0 && r == 64+count*128 && status r == 0 then copy (wire+64) 0x6ed100 (count*128) r else r
      let t := Guest.Labels.say 64 8 230 fg bg t
      inspectEdges 0 count t
    else Guest.Labels.say 65 8 52 0xe9bc75 bg t
  upload surface 0 901120 0 t

def resourceDraw (surface t : UInt64) : UInt64 :=
  let resource : DecimalResource := ⟨load64 (st+328) t,load64 (st+336) t,load64 (st+344) t⟩
  let t := fill 0 0 640 352 bg t
  let t := Guest.Labels.say 71 8 12 fg bg t
  let t := Guest.Labels.say 72 8 36 fg bg t
  let t := Guest.Labels.say 73 8 72 fg bg t
  let t := Guest.Raster.hex resource.original 2 8 94 fg bg t
  let t := Guest.Raster.hex resource.proposed 2 110 94 0xaad6a4 bg t
  let t := Guest.Labels.say (if resource.original == resource.proposed then 74 else 75) 8 126 0xe9bc75 bg t
  let t := Guest.Labels.say 60 8 162 fg bg t
  let t := identityLine (selected t+64) 8 180 t
  upload surface 0 901120 0 t

def partialDraw (surface first lastRow t : UInt64) : UInt64 :=
  let f := selected t
  let scroll := load64 (f+32) t
  let a := if first < scroll then scroll else first
  let b := if lastRow >= scroll+25 then scroll+24 else lastRow
  if a > b then t else
    let y := 48+(a-scroll)*11
    let height := (b-a+1)*11
    let t := fill 164 y 476 height bg t
    let t := sourceLines (load64 (f+48) t) (load64 f t) 0 0 0 scroll (load64 (f+8) t) t
    let t := fill 0 322 640 30 bg t
    let t := Guest.Labels.say (load64 (st+56) t) 8 322 0xe9bc75 bg t
    let t := Guest.Labels.say (if load64 (f+16) t != 0 then 13 else 12) 8 338 fg bg t
    let t := char 142 (52+load64 (st+8) t*16) (if load64 (f+16) t != 0 then 42 else 32) 0xe9bc75 bg t
    let t := upload surface (y*2560) (height*2560) 0 t
    let t := upload surface (322*2560) (30*2560) 0 t
    upload surface ((52+load64 (st+8) t*16)*2560) (10*2560) 0 t

partial def loop (surface t : UInt64) : UInt64 :=
  let count := load64 (st+168) t+1
  let t := store64 (st+168) count t
  let t := if count%256 == 0 then pollBuild t else t
  let t := if count%512 == 0 then pollProjectPortal t else t
  let packed := Guest.syscall 90 surface 0 0 0 t
  if packed == 0 || packed == error then
    let t := if load64 (st+176) t != 0 then
      let dirty := load64 (st+176) t
      let t := store64 (st+176) 0 t
      let t := if load64 (st+312) t == 1 then resourceDraw surface t else if load64 (st+128) t == 1 then inspectDraw surface t else
        if dirty == 1 then partialDraw surface (load64 (st+256) t) (load64 (st+264) t) t else draw surface t
      let t := store64 (st+256) 0xffffffff t
      store64 (st+264) 0 t else t
    loop surface (Guest.syscall 9 0 0 0 0 t)
  else
    let ev := Guest.Structured.event (packed >>> 48) ((packed >>> 32) &&& 65535) 0 0 0 (packed &&& 0xffffffff)
    let beforeFile := selected t
    let oldLine := (lineColumn (load64 (beforeFile+48) t) (load64 beforeFile t) (load64 (beforeFile+8) t) 0 0 0 t) >>> 32
    let oldMode := load64 (st+72) t
    let oldLength := load64 beforeFile t
    let t := pointer ev.kind ev.code ev.sequence t
    let t := match Guest.Structured.eventCode ev with
      | .ok code => if ev.kind == 1 then key code ev.sequence surface t else t
      | .error _ => if packed >>> 48 == 65535 || packed == 0x300000000 then store64 (st+64) 0 (store64 (st+136) 0 t) else t
    let afterFile := selected t
    let newLine := (lineColumn (load64 (afterFile+48) t) (load64 afterFile t) (load64 (afterFile+8) t) 0 0 0 t) >>> 32
    let scroll := load64 (afterFile+32) t
    let nextScroll := if newLine < scroll then newLine else if newLine >= scroll+25 then newLine-24 else scroll
    let t := if nextScroll != scroll then store64 (afterFile+32) nextScroll t else t
    let partialKey := ev.kind == 1 && ev.sequence != 0 && oldMode == 0 && beforeFile == afterFile &&
      load64 (st+72) t == 0 && nextScroll == scroll && ((ev.code >= 2 && ev.code <= 57 && ev.code != 28 && ev.code != 29 && ev.code != 42 && ev.code != 54) || ev.code == 105 || ev.code == 106) &&
      load64 (st+136) t == 0 && oldLength <= load64 afterFile t+1
    let redraw := ev.kind == 1 && ev.sequence != 0 && ev.code != 42 && ev.code != 54 && ev.code != 29 && ev.code != 97
    let first := if oldLine < newLine then oldLine else newLine
    let lastRow := if oldLine > newLine then oldLine else newLine
    let t := if redraw then
      let dirty := if partialKey && load64 (st+176) t != 2 then 1 else 2
      let t := store64 (st+176) dirty t
      let t := store64 (st+256) (if first < load64 (st+256) t then first else load64 (st+256) t) t
      store64 (st+264) (if lastRow > load64 (st+264) t then lastRow else load64 (st+264) t) t else t
    loop surface t

def main (initial : UInt64) : UInt64 :=
  let surface := Guest.syscall 80 0 0 0 0 initial
  if surface == error then Guest.syscall 10 1 0 0 0 initial else
    let t := newProject surface
    let t := store64 (st+184) 320 t
    let t := store64 (st+192) 200 t
    let t := draw surface t
    let t := store64 (st+256) 0xffffffff t
    loop surface t
end Guest.Desktop
