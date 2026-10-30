import Guest.Keyboard
import Guest.Raster
import Guest.CrateModel
namespace Guest.CrateGame
open Guest.LiveSDK Guest.Raster Guest.CrateModel

def st : UInt64 := 0x6e0000
def pack : UInt64 := 0x700000
def staging : UInt64 := 0x701000
def saveBytes : UInt64 := 0x702000
def undoBytes : UInt64 := 0x704000
def fg : UInt64 := 0xd8e6ed
def bg : UInt64 := 0x112330

def label (id x y t : UInt64) : UInt64 :=
  if id == 0 then
    let t := store64 (0x414000+0) 5717073734108533315 t
    let t := store64 (0x414000+8) 88301446056786 t
    text 0x414000 14 x y fg bg t
  else if id == 1 then
    let t := store64 (0x414000+0) 7809644627822735951 t
    let t := store64 (0x414000+8) 2334402177157656096 t
    let t := store64 (0x414000+16) 3395825635623073136 t
    let t := store64 (0x414000+24) 8386109761109976864 t
    let t := store64 (0x414000+32) 7237481 t
    text 0x414000 35 x y fg bg t
  else if id == 2 then
    let t := store64 (0x414000+0) 3395805753495409217 t
    let t := store64 (0x414000+8) 2314885686295090976 t
    let t := store64 (0x414000+16) 1702260589 t
    text 0x414000 20 x y fg bg t
  else if id == 3 then
    let t := store64 (0x414000+0) 2314972685609017429 t
    let t := store64 (0x414000+8) 8387236760591028768 t
    let t := store64 (0x414000+16) 7791289122099830816 t
    let t := store64 (0x414000+24) 1818588773 t
    text 0x414000 28 x y fg bg t
  else if id == 4 then
    let t := store64 (0x414000+0) 7526482966033408080 t
    let t := store64 (0x414000+8) 8007484937838031983 t
    let t := store64 (0x414000+16) 2336349433541126514 t
    let t := store64 (0x414000+24) 1801675120 t
    text 0x414000 28 x y fg bg t
  else if id == 5 then
    let t := store64 (0x414000+0) 2338328219397546323 t
    let t := store64 (0x414000+8) 7021786289551208549 t
    let t := store64 (0x414000+16) 2336358255488737388 t
    let t := store64 (0x414000+24) 2340027244252129612 t
    let t := store64 (0x414000+32) 8028075828261971314 t
    let t := store64 (0x414000+40) 8534165646137696366 t
    let t := store64 (0x414000+48) 3042401 t
    text 0x414000 51 x y fg bg t
  else if id == 6 then
    let t := store64 (0x414000+0) 327580796236 t
    text 0x414000 5 x y fg bg t
  else if id == 7 then
    let t := store64 (0x414000+0) 357645569869 t
    text 0x414000 5 x y fg bg t
  else if id == 8 then
    let t := store64 (0x414000+0) 4995694080727797571 t
    let t := store64 (0x414000+8) 68 t
    text 0x414000 9 x y fg bg t
  else if id == 9 then
    let t := store64 (0x414000+0) 1329876565 t
    text 0x414000 4 x y fg bg t
  else if id == 10 then
    let t := store64 (0x414000+0) 7311142234948334928 t
    let t := store64 (0x414000+8) 7310575239046396274 t
    let t := store64 (0x414000+16) 2333181745021480736 t
    let t := store64 (0x414000+24) 8241996475537321831 t
    let t := store64 (0x414000+32) 779380071 t
    text 0x414000 36 x y fg bg t
  else if id == 11 then
    let t := store64 (0x414000+0) 3251673995552771923 t
    let t := store64 (0x414000+8) 2334398904309146400 t
    let t := store64 (0x414000+16) 2338042655863172705 t
    let t := store64 (0x414000+24) 465558725996 t
    text 0x414000 29 x y fg bg t
  else if id == 12 then
    let t := store64 (0x414000+0) 4706900758732755013 t
    let t := store64 (0x414000+8) 8511925814507151436 t
    let t := store64 (0x414000+16) 7161674624469333345 t
    let t := store64 (0x414000+24) 7566181 t
    text 0x414000 27 x y fg bg t
  else if id == 13 then
    let t := store64 (0x414000+0) 5494759097004282447 t
    let t := store64 (0x414000+8) 323250901024 t
    text 0x414000 13 x y fg bg t
  else if id == 14 then
    let t := store64 (0x414000+0) 5701632192741851987 t
    let t := store64 (0x414000+8) 5714259048480983618 t
    let t := store64 (0x414000+16) 68 t
    text 0x414000 17 x y fg bg t
  else if id == 15 then
    let t := store64 (0x414000+0) 383397217618 t
    text 0x414000 5 x y fg bg t
  else if id == 16 then
    let t := store64 (0x414000+0) 2329010957441581399 t
    let t := store64 (0x414000+8) 5494989977483825731 t
    let t := store64 (0x414000+16) 293220336463 t
    text 0x414000 21 x y fg bg t
  else if id == 17 then
    let t := store64 (0x414000+0) 5786357101312101973 t
    let t := store64 (0x414000+8) 22868 t
    text 0x414000 10 x y fg bg t
  else if id == 18 then
    let t := store64 (0x414000+0) 5569066115872869973 t
    let t := store64 (0x414000+8) 6000292376690578505 t
    let t := store64 (0x414000+16) 5643890295912289349 t
    let t := store64 (0x414000+24) 92699492569153 t
    text 0x414000 30 x y fg bg t
  else if id == 19 then
    let t := store64 (0x414000+0) 4706063837210820944 t
    let t := store64 (0x414000+8) 5931276087433905476 t
    let t := store64 (0x414000+16) 5917821527475242831 t
    let t := store64 (0x414000+24) 1413829445 t
    text 0x414000 28 x y fg bg t
  else if id == 20 then
    let t := store64 (0x414000+0) 2325063899492535881 t
    let t := store64 (0x414000+8) 4706297122555053388 t
    let t := store64 (0x414000+16) 5784111897995397955 t
    let t := store64 (0x414000+24) 5640004621922672724 t
    let t := store64 (0x414000+32) 84 t
    text 0x414000 33 x y fg bg t
  else if id == 21 then
    let t := store64 (0x414000+0) 6000292377096765779 t
    let t := store64 (0x414000+8) 2318544860758560596 t
    let t := store64 (0x414000+16) 3539901107243860819 t
    text 0x414000 24 x y fg bg t
  else if id == 22 then
    let t := store64 (0x414000+0) 6071222065644654153 t
    let t := store64 (0x414000+8) 6215340358814679625 t
    let t := store64 (0x414000+16) 6075432086287491141 t
    let t := store64 (0x414000+24) 6074869167240332064 t
    text 0x414000 32 x y fg bg t
  else if id == 23 then
    let t := store64 (0x414000+0) 6075153945012031059 t
    let t := store64 (0x414000+8) 2329560872135053088 t
    let t := store64 (0x414000+16) 2318544950934979922 t
    let t := store64 (0x414000+24) 4707463729541041998 t
    let t := store64 (0x414000+32) 1145392713 t
    text 0x414000 36 x y fg bg t
  else if id == 24 then
    let t := store64 (0x414000+0) 5845764964228940367 t
    let t := store64 (0x414000+8) 5989839319984262997 t
    let t := store64 (0x414000+16) 5053114937205215813 t
    let t := store64 (0x414000+24) 76219920697665 t
    text 0x414000 30 x y fg bg t
  else if id == 25 then
    let t := store64 (0x414000+0) 357761634119 t
    text 0x414000 5 x y fg bg t
  else if id == 26 then
    let t := store64 (0x414000+0) 6998657807898527047 t
    let t := store64 (0x414000+8) 7021783760033374829 t
    let t := store64 (0x414000+16) 7166106818856576372 t
    let t := store64 (0x414000+24) 7142763024152880488 t
    let t := store64 (0x414000+32) 7809920652385742191 t
    let t := store64 (0x414000+40) 101 t
    text 0x414000 41 x y fg bg t
  else if id == 27 then
    let t := store64 (0x414000+0) 7310595043397758549 t
    let t := store64 (0x414000+8) 7575172647817846884 t
    let t := store64 (0x414000+16) 7306085946160717939 t
    let t := store64 (0x414000+24) 2322557185317675108 t
    let t := store64 (0x414000+32) 8458716092899028846 t
    let t := store64 (0x414000+40) 7451612542078511476 t
    let t := store64 (0x414000+48) 779318376 t
    text 0x414000 52 x y fg bg t
  else if id == 28 then
    let t := store64 (0x414000+0) 7070777195125369936 t
    let t := store64 (0x414000+8) 8242467129797211500 t
    let t := store64 (0x414000+16) 7305521809471140961 t
    let t := store64 (0x414000+24) 7454127484635652210 t
    let t := store64 (0x414000+32) 28266723398415461 t
    text 0x414000 39 x y fg bg t
  else if id == 29 then
    let t := store64 (0x414000+0) 8530225752446296396 t
    let t := store64 (0x414000+8) 8386658438686384229 t
    text 0x414000 16 x y fg bg t
  else if id == 30 then
    let t := store64 (0x414000+0) 4704101208955240784 t
    let t := store64 (0x414000+8) 3552562 t
    text 0x414000 11 x y fg bg t
  else t

def originalPack (t : UInt64) : UInt64 :=
  let t := store64 (pack+0) 3554542234077643596 t
  let t := store64 (pack+8) 1 t
  let t := store64 (pack+16) 13875182636130925255 t
  let t := store64 (pack+24) 10874089236606470167 t
  let t := store64 (pack+32) 420219251408519285 t
  let t := store64 (pack+40) 18417994242848302605 t
  let t := store64 (pack+48) 4 t
  let t := store64 (pack+56) 0 t
  let t := store64 (pack+64) 1 t
  let t := store64 (pack+72) 18411139144890810879 t
  let t := store64 (pack+80) 536870912 t
  let t := store64 (pack+88) 134217728 t
  let t := store64 (pack+96) 26 t
  let t := store64 (pack+104) 0 t
  let t := store64 (pack+112) 1 t
  let t := store64 (pack+120) 18411139144890810879 t
  let t := store64 (pack+128) 524288 t
  let t := store64 (pack+136) 134217728 t
  let t := store64 (pack+144) 35 t
  let t := store64 (pack+152) 0 t
  let t := store64 (pack+160) 1 t
  let t := store64 (pack+168) 18411139144890810879 t
  let t := store64 (pack+176) 1310720 t
  let t := store64 (pack+184) 335544320 t
  let t := store64 (pack+192) 35 t
  let t := store64 (pack+200) 0 t
  let t := store64 (pack+208) 1 t
  let t := store64 (pack+216) 18411165533169877503 t
  let t := store64 (pack+224) 2359296 t
  let t := store64 (pack+232) 603979776 t
  let t := store64 (pack+240) 35 t
  let t := store64 (pack+248) 0 t
  let t := store64 (st+112) 15547823508511247991 t
  let t := store64 (st+120) 10711489680023861667 t
  let t := store64 (st+128) 13475777254429773653 t
  let t := store64 (st+136) 12810564433673329127 t
  let t := store64 (st+104) 4 t
  store64 (st+144) 0 t

@[noinline] def levelAt (p index t : UInt64) : Level :=
  let r := p+64+index*48
  ⟨load64 (r+8) t,load64 (r+16) t,load64 (r+24) t,load64 (r+32) t⟩
def level (t : UInt64) : Level := levelAt pack (load64 (st+8) t) t
def board (t : UInt64) : Board := ⟨load64 (st+24) t,load64 (st+32) t⟩
def sameGame (p t : UInt64) : Bool :=
  load64 p t == 13875182636130925255 && load64 (p+8) t == 10874089236606470167 &&
  load64 (p+16) t == 420219251408519285 && load64 (p+24) t == 18417994242848302605
partial def reservedZero (p n t : UInt64) : Bool :=
  if n == 0 then true else load64 p t == 0 && reservedZero (p+8) (n-1) t
partial def validLevels (p index count t : UInt64) : Bool :=
  if index == count then true else
    load64 (p+64+index*48) t == 1 && load64 (p+104+index*48) t == 0 &&
    valid (levelAt p index t) && validLevels p (index+1) count t
@[noinline] def validPack (p length t : UInt64) : Bool :=
  let count := load64 (p+48) t
  length >= 112 && length <= 448 && load64 p t == 0x315445544152434c &&
  load64 (p+8) t == 1 && sameGame (p+16) t && count > 0 && count <= 8 &&
  length == 64+count*48 && load64 (p+56) t == 0 && validLevels p 0 count t

def resetLevel (index t : UInt64) : UInt64 :=
  let l := levelAt pack index t
  let t := store64 (st+8) index t
  let t := store64 (st+16) 0 t
  let t := store64 (st+24) l.boxes t
  let t := store64 (st+32) l.player t
  let t := store64 (st+48) 0 t
  let t := store64 (st+56) (load64 (st+56) t+1) t
  let t := store64 (st+88) 15 t
  store64 (st+96) 1 t

def changed (notice t : UInt64) : UInt64 := store64 (st+96) 1 (store64 (st+88) notice t)

def move (direction t : UInt64) : UInt64 :=
  let old := board t
  let next := step (level t).walls old direction
  if next == old then changed 16 t else
  let count := load64 (st+48) t
  if count == 128 then changed 18 t else
    let target := undoBytes+count*24
    let t := store64 target old.boxes t
    let t := store64 (target+8) old.player t
    let t := store64 (target+16) (load64 (st+16) t) t
    let t := store64 (st+48) (count+1) t
    let t := store64 (st+24) next.boxes t
    let t := store64 (st+32) next.player t
    let t := store64 (st+16) (load64 (st+16) t+1) t
    let t := store64 (st+56) (load64 (st+56) t+1) t
    let t := if won (level t).goals next then
        store64 (st+40) (load64 (st+40) t ||| bit (load64 (st+8) t)) t
      else t
    changed 15 t

def undo (t : UInt64) : UInt64 :=
  let count := load64 (st+48) t
  if count == 0 then changed 17 t else
    let source := undoBytes+(count-1)*24
    let t := store64 (st+24) (load64 source t) t
    let t := store64 (st+32) (load64 (source+8) t) t
    let t := store64 (st+16) (load64 (source+16) t) t
    let t := store64 (st+48) (count-1) t
    changed 15 (store64 (st+56) (load64 (st+56) t+1) t)

partial def cells (i t : UInt64) : UInt64 :=
  if i == 64 then t else
    let l := level t
    let b := board t
    let x := 20+(i%8)*30
    let y := 64+(i/8)*30
    let wall := occupied l.walls i
    let t := fill x y 28 28 (if wall then 0x496274 else 0x203748) t
    let t := if occupied l.goals i then fill (x+8) (y+8) 12 12 0xcda83e t else t
    let t := if occupied b.boxes i then
        let t := fill (x+4) (y+4) 20 20 (if load64 st t == 2 then 0xecae63 else 0xbe9058) t
        let t := fill (x+6) (y+6) 16 2 0x69523a t
        fill (x+6) (y+20) 16 2 0x69523a t
      else t
    let t := if b.player == i then
        let t := fill (x+7) (y+4) 14 20 0x59b9e5 t
        fill (x+10) (y+8) 8 4 0xe1f5ff t
      else t
    cells (i+1) t

def draw (surface t : UInt64) : UInt64 :=
  let t := fill 0 0 640 352 bg t
  let t := label 0 8 8 t
  let t := label 1 8 24 t
  let t := hex (load64 st t) 1 218 24 fg bg t
  let t := label (if load64 (st+144) t == 0 then 13 else 14) 8 44 t
  let t := cells 0 t
  let t := label 6 280 64 t
  let t := hex (load64 (st+8) t+1) 1 346 64 fg bg t
  let t := char 358 64 47 fg bg t
  let t := hex (load64 (st+104) t) 1 370 64 fg bg t
  let t := label 7 280 82 t
  let t := hex (load64 (st+16) t) 4 346 82 fg bg t
  let t := label 8 280 100 t
  let t := hex (load64 (st+40) t) 2 346 100 fg bg t
  let t := label 9 280 118 t
  let t := hex (load64 (st+48) t) 2 346 118 fg bg t
  let t := label 2 280 148 t
  let t := label 3 280 166 t
  let t := label 4 280 184 t
  let t := label 10 280 214 t
  let t := if won (level t).goals (board t) then label 11 280 232 t else t
  let t := if load64 st t == 2 then label 26 280 252 t else label 28 280 252 t
  let t := label 29 280 272 t
  let t := hex (load64 (st+72) t) 16 280 286 fg bg t
  let t := label (load64 (st+88) t) 8 312 t
  let t := label 5 8 334 t
  let t := store64 (st+96) 0 t
  upload surface 0 901120 0 t

def fail (reason t : UInt64) : UInt64 :=
  let t := zero wire 8 t
  64+store64 wire reason t

def loadPack (handle t : UInt64) : UInt64 :=
  let got := metadata handle t
  if got != 96 || status got != 0 || (load64 (wire+32) got != 2 && load64 (wire+32) got != 10) then fail 1 (changed 20 got) else
    let length := load64 (wire+16) got
    if length < 112 || length > 448 then fail 2 (changed 20 got) else
      let t := copy (wire+64) (st+160) 32 got
      let got := read handle 0 length t
      if got != 64+length || status got != 0 || load64 (wire+8) got != length then fail 3 (changed 20 got) else
        let t := copy (wire+64) staging length got
        if !validPack staging length t then fail 2 (changed 20 t) else
          let t := copy staging pack length t
          let t := copy (st+160) (st+112) 32 t
          let t := store64 (st+104) (load64 (pack+48) t) t
          let t := store64 (st+144) 1 t
          let t := store64 (st+40) 0 t
          fail 0 (changed 19 (resetLevel 0 t))

@[noinline] def validSave (p t : UInt64) : Bool :=
  let index := load64 (p+88) t
  load64 p t == 0x3156415343544c && load64 (p+8) t == 1 && sameGame (p+16) t &&
  load64 (p+48) t == load64 (st+112) t && load64 (p+56) t == load64 (st+120) t &&
  load64 (p+64) t == load64 (st+128) t && load64 (p+72) t == load64 (st+136) t &&
  (load64 (p+80) t == 1 || load64 (p+80) t == 2) && index < load64 (st+104) t &&
  load64 (p+96) t <= 0xffffffff && load64 (p+120) t < bit (load64 (st+104) t) &&
  reservedZero (p+128) 8 t &&
  validBoard (levelAt pack index t) ⟨load64 (p+104) t,load64 (p+112) t⟩

def loadSave (handle t : UInt64) : UInt64 :=
  let got := metadata handle t
  if got != 96 || status got != 0 || load64 (wire+16) got != 192 || load64 (wire+32) got != 2 then fail 2 (changed 22 got) else
    let got := read handle 0 192 got
    if got != 256 || status got != 0 || load64 (wire+8) got != 192 then fail 3 (changed 22 got) else
      let t := copy (wire+64) staging 192 got
      if !validSave staging t then fail 2 (changed 22 t) else
        let t := store64 (st+8) (load64 (staging+88) t) t
        let t := store64 (st+16) (load64 (staging+96) t) t
        let t := store64 (st+24) (load64 (staging+104) t) t
        let t := store64 (st+32) (load64 (staging+112) t) t
        let t := store64 (st+40) (load64 (staging+120) t) t
        let t := store64 (st+48) 0 t
        let t := store64 (st+56) (load64 (st+56) t+1) t
        fail 0 (changed 21 t)

def encodeSave (t : UInt64) : UInt64 :=
  let t := zero saveBytes 24 t
  let t := store64 saveBytes 0x3156415343544c t
  let t := store64 (saveBytes+8) 1 t
  let t := copy (pack+16) (saveBytes+16) 32 t
  let t := copy (st+112) (saveBytes+48) 32 t
  let t := store64 (saveBytes+80) (load64 st t) t
  let t := store64 (saveBytes+88) (load64 (st+8) t) t
  let t := store64 (saveBytes+96) (load64 (st+16) t) t
  let t := store64 (saveBytes+104) (load64 (st+24) t) t
  let t := store64 (saveBytes+112) (load64 (st+32) t) t
  store64 (saveBytes+120) (load64 (st+40) t) t

-- One old cached owner reference can await an idempotent release reply.
-- A lost reply does not permit another allocation to accumulate behind it.
def retireSnapshot (t : UInt64) : UInt64 :=
  let previous := load64 (st+192) t
  if previous == 0 then t else
    let r := releaseReference previous t
    if r == 64 && (status r == 0 || status r == 3) then store64 (st+192) 0 r else r

def snapshot (initial : UInt64) : UInt64 :=
  let t := retireSnapshot initial
  if load64 (st+192) t != 0 then fail 4 (changed 24 t) else
  if load64 (st+72) t != 0 && load64 (st+64) t == load64 (st+56) t then fail 0 (changed 23 t) else
    let t := encodeSave t
    let got := stage 192 2 0 t
    if got != 64 || status got != 0 then fail 4 (changed 24 got) else
      let handle := result got
      let got := append handle 0 saveBytes 192 got
      if got != 64 || status got != 0 then fail 4 (changed 24 (abortStage handle got)) else
        let got := stageDigest handle got
        if got != 96 || status got != 0 then fail 4 (changed 24 (abortStage handle got)) else
          let t := copy (wire+64) digest 32 got
          let got := commit handle digest t
          if got != 96 || status got != 0 then fail 4 (changed 24 (abortStage handle got)) else
            let previous := load64 (st+72) got
            let t := store64 (st+72) handle got
            let t := store64 (st+64) (load64 (st+56) t) t
            let t := store64 (st+80) (load64 (st+80) t+1) t
            -- Retire only this cached reference after publication. Previously
            -- exported readers keep their immutable save and its own grant.
            let t := store64 (st+192) (if previous == handle then 0 else previous) t
            let t := retireSnapshot t
            if load64 (st+192) t != 0 then fail 4 (changed 24 t) else fail 0 (changed 23 t)

def inspect (t : UInt64) : UInt64 :=
  let t := zero wire 8 t
  let t := store64 (wire+8) (load64 st t) t
  let t := store64 (wire+16) (load64 (st+8) t) t
  let t := store64 (wire+24) (load64 (st+16) t) t
  let t := store64 (wire+32) (load64 (st+40) t) t
  let t := store64 (wire+40) (if won (level t).goals (board t) then 1 else 0) t
  let t := store64 (wire+48) (load64 (st+48) t) t
  let t := store64 (wire+56) 1 t
  let t := copy (pack+16) (wire+64) 32 t
  let t := copy (st+112) (wire+96) 32 t
  let t := store64 (wire+128) (load64 (st+24) t) t
  let t := store64 (wire+136) (load64 (st+32) t) t
  let t := store64 (wire+144) (load64 (st+72) t) t
  let t := store64 (wire+152) (load64 (st+88) t) t
  160+store64 (wire+160) 0 t

def dispatch (caller rights length t : UInt64) : UInt64 :=
  if length != 64 || load64 (command+56) t != 1 then fail 2 t else
    let op := load64 command t
    let handle := load64 (command+8) t
    if op == 500 then inspect t
    else if op == 501 || op == 503 then
      -- An IPC caller must have issued this exact delegated read scope. A
      -- guessed handle belonging to this game is not that caller's authority.
      let checked := Guest.LiveSDK.checkDelegation handle caller t
      if checked != 64 || status checked != 0 then fail 1 checked else
        if op == 501 then loadPack handle checked else loadSave handle checked
    else if op == 502 then
      let got := snapshot t
      if status got != 0 then got else
        let allowed := rights &&& 25
        if allowed == 0 || (allowed &&& 1) == 0 then fail 1 got else
          share (load64 (st+72) got) caller allowed got
    else fail 2 t

def ipc (endpoint t : UInt64) : UInt64 :=
  let length := Guest.syscall 36 endpoint incoming 1024 0 t
  if length == 0 || length == error then t else
    let caller := load64 incoming length
    let replyToken := load64 (incoming+8) length
    let rights := load64 (incoming+16) length
    let abi := load64 (incoming+24) length
    let result := if length >= 96 && abi == 2 then dispatch caller rights (length-32) length else fail 1 length
    reply replyToken result result

def key (code down t : UInt64) : UInt64 :=
  if down == 0 then t else
  if code == 105 || code == 30 then move 0 t else
  if code == 106 || code == 32 then move 1 t else
  if code == 103 || code == 17 then move 2 t else
  if code == 108 || code == 31 then move 3 t else
  if code == 22 || code == 14 then undo t else
  if code == 19 then resetLevel (load64 (st+8) t) t else
  if code >= 2 && code <= 9 && code-2 < load64 (st+104) t then resetLevel (code-2) t else
  if code == 25 then snapshot t else
  if code == 50 && load64 (st+144) t != 0 then
    let t := originalPack t
    let t := store64 (st+40) 0 t
    changed 19 (resetLevel 0 t)
  else t

partial def loop (endpoint surface t : UInt64) : UInt64 :=
  let t := ipc endpoint t
  let packed := Guest.syscall 90 surface 0 0 0 t
  let t := if packed != error && packed >>> 48 == 1 then key ((packed >>> 32) &&& 65535) (packed &&& 0xffffffff) t else t
  let t := if load64 (st+96) t != 0 then draw surface t else t
  if packed != 0 && packed != error then loop endpoint surface t else
    let now := Guest.syscall 116 0 0 0 0 t
    loop endpoint surface (Guest.syscall 117 (now+100) 0 0 0 now)

def start (generation initial : UInt64) : UInt64 :=
  let surface := Guest.syscall 80 0 0 0 0 initial
  if surface == error then Guest.syscall 10 1 0 0 0 initial else
    let t := zero st 32 surface
    let t := store64 st generation t
    let t := originalPack t
    let t := resetLevel 0 t
    let t := draw surface t
    loop (self t) surface t

def main (initial : UInt64) : UInt64 := start 1 initial
def secondMain (initial : UInt64) : UInt64 := start 2 initial
end Guest.CrateGame
