import Lean
import Lemma.UI
import Lemma.Objects
import Lemma.Forge
import Lemma.Social
import Lemma.Messenger
import Notes.Schema
namespace Main
open Lemma.UI Lemma.Objects
-- A structured resource consumed by the compiled application. Schema1 has a
-- version line and default category0..2. The native editor can change its bytes.
elab "notes_resources" : command => do
  let raw ← IO.FS.readFile "/input/templates.txt"
  let parts := raw.trimAscii.toString.splitOn "\n"
  if parts.length != 2 || parts[0]! != "1" then throwError "templates.txt: schema1 needs version and default category lines"
  let some category := parts[1]!.toNat? | throwError "templates.txt: category must be0..2"
  if category > 2 then throwError "templates.txt: category must be0..2"
  Lean.Elab.Command.elabCommand (← `(def $(Lean.mkIdent `defaultCategory) : UInt64 := $(Lean.quote category)))
notes_resources
-- A fork may change this useful behavior independently of the semantic resource.
def foldSearch : UInt64 := 1
def st : UInt64 := 0x700000
def note (i : UInt64) : UInt64 := 0x710000+i*4096
def row (i : UInt64) : UInt64 := 0x701000+i*256
def query : UInt64 := 0x702000
def manifest : UInt64 := 0x703000
def selected (t : UInt64) : UInt64 := note (load64 (st+8) t)
def selectedRow (t : UInt64) : UInt64 := row (load64 (st+8) t)
def err : UInt64 := Lemma.Objects.error
def bg : UInt64 := 0x14232c
def fg : UInt64 := 0xdce9ec
def accent : UInt64 := 0xa6d7b1
def notice (n t : UInt64) : UInt64 := store64 (st+48) n (store64 st 1 t)
-- Ordinary local typing needs only its affected rows. Full view changes keep
-- the stronger dirty state when several physical events arrive together.
def editing (n t : UInt64) : UInt64 :=
  store64 (st+48) n (store64 st (if load64 st t == 1 then 1 else 2) t)
def label (id x y t : UInt64) : UInt64 :=
  if id == 0 then
    let t := store64 (0x414000+0) 2338603393740665424 t
    let t := store64 (0x414000+8) 2319108013114552142 t
    let t := store64 (0x414000+16) 5989899063652540782 t
    let t := store64 (0x414000+24) 211228314436 t
    text 0x414000 29 x y fg bg t
  else if id == 1 then
    let t := store64 (0x414000+0) 2314981485454570054 t
    let t := store64 (0x414000+8) 7307775882123293510 t
    let t := store64 (0x414000+16) 5701614604042400867 t
    let t := store64 (0x414000+24) 7310590613910349168 t
    let t := store64 (0x414000+32) 5629607704375861363 t
    let t := store64 (0x414000+40) 7632997 t
    text 0x414000 43 x y fg bg t
  else if id == 2 then
    let t := store64 (0x414000+0) 5989878950370899011 t
    let t := store64 (0x414000+8) 7599372962078488161 t
    let t := store64 (0x414000+16) 8377575055503092083 t
    let t := store64 (0x414000+24) 7018106992408095858 t
    let t := store64 (0x414000+32) 2321682711706100594 t
    let t := store64 (0x414000+40) 8319678385385468496 t
    text 0x414000 48 x y fg bg t
  else if id == 3 then
    let t := store64 (0x414000+0) 7593478425241729350 t
    let t := store64 (0x414000+8) 8386658447326912622 t
    let t := store64 (0x414000+16) 8315180308947297381 t
    let t := store64 (0x414000+24) 8532478930838368032 t
    let t := store64 (0x414000+32) 8603398620390236261 t
    let t := store64 (0x414000+40) 7300933337278193696 t
    let t := store64 (0x414000+48) 491328532323 t
    text 0x414000 53 x y fg bg t
  else if id == 4 then
    let t := store64 (0x414000+0) 2334101992527377990 t
    let t := store64 (0x414000+8) 2338617743141730405 t
    let t := store64 (0x414000+16) 8319104318610818592 t
    let t := store64 (0x414000+24) 8675375932898766437 t
    let t := store64 (0x414000+32) 2319108017593935203 t
    let t := store64 (0x414000+40) 7954880248345224562 t
    let t := store64 (0x414000+48) 12660 t
    text 0x414000 50 x y fg bg t
  else if id == 5 then
    let t := store64 (0x414000+0) 2319107953102448980 t
    let t := store64 (0x414000+8) 7234224052141059653 t
    let t := store64 (0x414000+16) 8747238843502261353 t
    text 0x414000 24 x y fg bg t
  else if id == 6 then
    let t := store64 (0x414000+0) 3395828895367390547 t
    let t := store64 (0x414000+8) 7359007571194037536 t
    let t := store64 (0x414000+16) 8675461342853099113 t
    let t := store64 (0x414000+24) 2333835772637945972 t
    let t := store64 (0x414000+32) 8026013166174037093 t
    let t := store64 (0x414000+40) 31076 t
    text 0x414000 42 x y fg bg t
  else if id == 7 then
    let t := store64 (0x414000+0) 7883868238259839315 t
    let t := store64 (0x414000+8) 2334391151659087213 t
    let t := store64 (0x414000+16) 7957695010998478194 t
    text 0x414000 24 x y fg bg t
  else if id == 8 then
    let t := store64 (0x414000+0) 2334102066000260693 t
    let t := store64 (0x414000+8) 7234224026303033196 t
    let t := store64 (0x414000+16) 7566441 t
    text 0x414000 19 x y fg bg t
  else if id == 9 then
    let t := store64 (0x414000+0) 7521983764430352206 t
    let t := store64 (0x414000+8) 7310590613909892713 t
    text 0x414000 16 x y fg bg t
  else if id == 10 then
    let t := store64 (0x414000+0) 2318355878441017935 t
    let t := store64 (0x414000+8) 7598543892949132656 t
    let t := store64 (0x414000+16) 7017488320236121711 t
    let t := store64 (0x414000+24) 7286957737976750448 t
    let t := store64 (0x414000+32) 1919906418 t
    text 0x414000 36 x y fg bg t
  else if id == 11 then
    let t := store64 (0x414000+0) 2334956330984499283 t
    let t := store64 (0x414000+8) 8315178084276987250 t
    let t := store64 (0x414000+16) 7162249965381640480 t
    let t := store64 (0x414000+24) 7305815396255556980 t
    let t := store64 (0x414000+32) 8367811756012367986 t
    let t := store64 (0x414000+40) 5067769077468050799 t
    let t := store64 (0x414000+48) 8315180351695632429 t
    text 0x414000 56 x y fg bg t
  else if id == 12 then
    let t := store64 (0x414000+0) 8295761791061222738 t
    let t := store64 (0x414000+8) 7575168297150341480 t
    let t := store64 (0x414000+16) 8007510524118311022 t
    let t := store64 (0x414000+24) 7954891256277835890 t
    let t := store64 (0x414000+32) 7526756837609334119 t
    let t := store64 (0x414000+40) 5056262989857444640 t
    let t := store64 (0x414000+48) 12593 t
    text 0x414000 50 x y fg bg t
  else if id == 13 then
    let t := store64 (0x414000+0) 7022364301937960262 t
    let t := store64 (0x414000+8) 7299525957817431412 t
    let t := store64 (0x414000+16) 2338042651466888051 t
    let t := store64 (0x414000+24) 126948300911731 t
    text 0x414000 30 x y fg bg t
  else if id == 14 then
    let t := store64 (0x414000+0) 8389754676633104196 t
    let t := store64 (0x414000+8) 474315584609 t
    text 0x414000 13 x y fg bg t
  else if id == 15 then
    let t := store64 (0x414000+0) 2334398844012094802 t
    let t := store64 (0x414000+8) 499933868644 t
    text 0x414000 13 x y fg bg t
  else if id == 16 then
    let t := store64 (0x414000+0) 7598805623994478145 t
    let t := store64 (0x414000+8) 28271 t
    text 0x414000 10 x y fg bg t
  else if id == 17 then
    let t := store64 (0x414000+0) 6998705367398967363 t
    let t := store64 (0x414000+8) 8386658438904705056 t
    let t := store64 (0x414000+16) 2334386829831072032 t
    let t := store64 (0x414000+24) 8079569290752450926 t
    let t := store64 (0x414000+32) 491327808361 t
    text 0x414000 37 x y fg bg t
  else if id == 18 then
    let t := store64 (0x414000+0) 7162249965381644110 t
    let t := store64 (0x414000+8) 7669474516340598132 t
    let t := store64 (0x414000+16) 8098914891675755365 t
    let t := store64 (0x414000+24) 2336349450654279016 t
    let t := store64 (0x414000+32) 8458154160836082018 t
    let t := store64 (0x414000+40) 29804 t
    text 0x414000 42 x y fg bg t
  else if id == 19 then
    let t := store64 (0x414000+0) 6133996337470010435 t
    let t := store64 (0x414000+8) 8295741995656374638 t
    let t := store64 (0x414000+16) 2319108008751948131 t
    let t := store64 (0x414000+24) 7955925892427181637 t
    let t := store64 (0x414000+32) 2319108013366076787 t
    let t := store64 (0x414000+40) 7164771135566082885 t
    let t := store64 (0x414000+48) 7564389 t
    text 0x414000 51 x y fg bg t
  else if id == 20 then
    let t := store64 (0x414000+0) 8675454745549240660 t
    let t := store64 (0x414000+8) 7809643528243733601 t
    let t := store64 (0x414000+16) 7306086968263071008 t
    let t := store64 (0x414000+24) 4283593313701032736 t
    let t := store64 (0x414000+32) 7575180353307821344 t
    let t := store64 (0x414000+40) 126943972651886 t
    text 0x414000 46 x y fg bg t
  else if id == 21 then
    let t := store64 (0x414000+0) 8007521536350381394 t
    let t := store64 (0x414000+8) 8317981811732474990 t
    let t := store64 (0x414000+16) 8315180308947299941 t
    let t := store64 (0x414000+24) 2338042655863152699 t
    let t := store64 (0x414000+32) 2334399943808742000 t
    let t := store64 (0x414000+40) 7309940765292065907 t
    let t := store64 (0x414000+48) 8098915185041432941 t
    let t := store64 (0x414000+56) 30506441440585064 t
    text 0x414000 63 x y fg bg t
  else if id == 22 then
    let t := store64 (0x414000+0) 7450489119641187654 t
    let t := store64 (0x414000+8) 7517387589791871599 t
    let t := store64 (0x414000+16) 6998653495938410089 t
    let t := store64 (0x414000+24) 8387507252816274542 t
    let t := store64 (0x414000+32) 8102941552360769067 t
    let t := store64 (0x414000+40) 7166482027199619941 t
    let t := store64 (0x414000+48) 6647151 t
    text 0x414000 51 x y fg bg t
  else if id == 23 then
    let t := store64 (0x414000+0) 7954874742130894148 t
    let t := store64 (0x414000+8) 7021223364206950755 t
    let t := store64 (0x414000+16) 8295764020082008434 t
    let t := store64 (0x414000+24) 8020383601963984745 t
    let t := store64 (0x414000+32) 7307199604321379700 t
    let t := store64 (0x414000+40) 7521982384705659245 t
    let t := store64 (0x414000+48) 828468581 t
    text 0x414000 52 x y fg bg t
  else if id == 24 then
    let t := store64 (0x414000+0) 8532478930838384462 t
    let t := store64 (0x414000+8) 2338615471322374245 t
    let t := store64 (0x414000+16) 7599387201283060335 t
    let t := store64 (0x414000+24) 8530134849273488739 t
    let t := store64 (0x414000+32) 28548142444865889 t
    text 0x414000 39 x y fg bg t
  else if id == 25 then
    let t := store64 (0x414000+0) 7234316411285302601 t
    let t := store64 (0x414000+8) 8391447924489678880 t
    let t := store64 (0x414000+16) 8315180308947297381 t
    text 0x414000 24 x y fg bg t
  else if id == 26 then
    let t := store64 (0x414000+0) 8223684397374992211 t
    let t := store64 (0x414000+8) 2336927755350406757 t
    let t := store64 (0x414000+16) 8386658447326912559 t
    let t := store64 (0x414000+24) 7307775882660176997 t
    let t := store64 (0x414000+32) 29795 t
    text 0x414000 34 x y fg bg t
  else if id == 27 then
    let t := store64 (0x414000+0) 7286952167337649491 t
    let t := store64 (0x414000+8) 2322296584167318392 t
    let t := store64 (0x414000+16) 8295702168375292995 t
    let t := store64 (0x414000+24) 7070778358692670565 t
    let t := store64 (0x414000+32) 8377575118619632751 t
    let t := store64 (0x414000+40) 7308325285683489906 t
    let t := store64 (0x414000+48) 7565921 t
    text 0x414000 51 x y fg bg t
  else if id == 28 then
    let t := store64 (0x414000+0) 2334398844012094802 t
    let t := store64 (0x414000+8) 495623368558 t
    text 0x414000 13 x y fg bg t
  else if id == 29 then
    let t := store64 (0x414000+0) 2338603393740665424 t
    let t := store64 (0x414000+8) 8389754676633104228 t
    let t := store64 (0x414000+16) 474315584609 t
    text 0x414000 21 x y fg bg t
  else if id == 30 then
    let t := store64 (0x414000+0) 2338603393740665424 t
    let t := store64 (0x414000+8) 7598805623994478177 t
    let t := store64 (0x414000+16) 28271 t
    text 0x414000 18 x y fg bg t
  else t
partial def renderText (p n i line column t : UInt64) : UInt64 :=
  if i == n || line == 16 then t else
  let c := load8 (p+i) t
  if c >= 128 && c < 192 then renderText p n (i+1) line column t else
  if c == 10 || column == 98 then renderText p n (if c == 10 then i+1 else i) (line+1) 0 t else
  renderText p n (i+1) line (column+1) (char (18+column*6) (122+line*11) (if c >= 128 then 63 else c) fg bg t)
partial def noteList (i t : UInt64) : UInt64 :=
  if i == load64 (st+24) t then t else
  let p := note i
  let t := text (p+128) (load64 (p+32) t) (16+i*152) 86 (if i == load64 (st+8) t then accent else fg) bg t
  noteList (i+1) t
def draw (surface t : UInt64) : UInt64 :=
  let p := selected t
  let t := fill 0 0 640 352 bg t
  let t := label 0 14 8 t
  let t := label 1 14 24 t
  let t := label 2 14 38 t
  let t := label 4 14 52 t
  let t := label 22 14 66 t
  let t := noteList 0 t
  let mode := load64 (st+16) t
  let t := label (if mode == 1 then 5 else if mode == 3 then 6 else if mode == 6 then 20 else 14+load64 (p+16) t) 14 104 t
  let t := if mode == 3 then text query (load64 (st+56) t) 14 122 accent bg t else
    if mode == 6 then hex (load64 (st+224) t) 6 14 122 accent bg t else
    renderText (p+192+load64 (st+184) t) (load64 (p+40) t-load64 (st+184) t) 0 0 0 t
  let t := label (load64 (st+48) t) 14 306 t
  let t := label 13 14 322 t
  let t := hex (load64 (st+88) t) 2 220 322 accent bg t
  let t := hex (load64 (st+96) t) 2 260 322 accent bg t
  let t := hex (load64 (p+24) t) 4 320 322 accent bg t
  let t := hex (load64 (p+64) t) 16 368 322 accent bg t
  let t := label 19 14 338 t
  upload surface 0 901120 (store64 st 0 t)
partial def endLine (p n i line column t : UInt64) : UInt64 :=
  if i == n then line else
  let c := load8 (p+i) t
  if c >= 128 && c < 192 then endLine p n (i+1) line column t else
  if c == 10 || column == 98 then endLine p n (if c == 10 then i+1 else i) (line+1) 0 t else
  endLine p n (i+1) line (column+1) t
partial def renderRange (p n i line column first last t : UInt64) : UInt64 :=
  if i == n || line > last then t else
  let c := load8 (p+i) t
  if c >= 128 && c < 192 then renderRange p n (i+1) line column first last t else
  if c == 10 || column == 98 then renderRange p n (if c == 10 then i+1 else i) (line+1) 0 first last t else
  let t := if line < first then t else char (18+column*6) (122+line*11) (if c >= 128 then 63 else c) fg bg t
  renderRange p n (i+1) line (column+1) first last t
@[noinline] def drawEditing (surface t : UInt64) : UInt64 :=
  let p := selected t
  let mode := load64 (st+16) t
  let t := fill 0 104 640 12 bg t
  let t := label (if mode == 1 then 5 else if mode == 3 then 6 else if mode == 6 then 20 else 14+load64 (p+16) t) 14 104 t
  let t := upload surface (104*2560) (12*2560) t
  let t := if mode == 1 then
      let t := fill 0 80 640 20 bg t
      upload surface (80*2560) (20*2560) (noteList 0 t)
    else if mode == 3 || mode == 6 then
      let t := fill 0 120 640 14 bg t
      let t := if mode == 3 then text query (load64 (st+56) t) 14 122 accent bg t else hex (load64 (st+224) t) 6 14 122 accent bg t
      upload surface (120*2560) (14*2560) t
    else
      let off := load64 (st+184) t
      let n := load64 (p+40) t-off
      let line := endLine (p+192+off) n 0 0 0 t
      let first := if line >= 16 then 14 else if line == 0 then 0 else line-1
      let y := 122+first*11
      let t := fill 0 y 640 22 bg t
      let t := renderRange (p+192+off) n 0 0 0 first (first+1) t
      upload surface (y*2560) (22*2560) t
  let t := fill 0 304 640 32 bg t
  let t := label (load64 (st+48) t) 14 306 t
  let t := label 13 14 322 t
  let t := hex (load64 (st+88) t) 2 220 322 accent bg t
  let t := hex (load64 (st+96) t) 2 260 322 accent bg t
  let t := hex (load64 (p+24) t) 4 320 322 accent bg t
  let t := hex (load64 (p+64) t) 16 368 322 accent bg t
  upload surface (304*2560) (32*2560) (store64 st 0 t)

def newNote (t : UInt64) : UInt64 :=
  let count := load64 (st+24) t
  if count >= 4 then notice 10 t else
  let p := note count
  let t := zero p 512 (zero (row count) 32 t)
  let t := store64 p Notes.Schema.magic (store64 (p+8) 1 (store64 (p+16) defaultCategory (store64 (p+24) 1 t)))
  notice 5 (store64 (st+192) 0 (store64 (st+24) (count+1) (store64 (st+8) count (store64 (st+16) 1 t))))
partial def appendBytes (handle p offset t : UInt64) : UInt64 :=
  if offset == 4096 then t else
  let r := append handle offset (p+offset) 512 t
  if r != 64 || status r != 0 then err else appendBytes handle p (offset+512) r
def saveNote (index t : UInt64) : UInt64 :=
  let p := note index
  let f := row index
  if load64 (f+16) t == 0 && load64 f t != 0 then t else
  if !Notes.Schema.valid p t || load64 (p+32) t == 0 then err else
  let old := load64 f t
  let t := copy (f+64) (p+96) 32 (store64 (p+24) (load64 (f+24) t+1) t)
  let r := stage 4096 10 old t
  if r != 64 || status r != 0 then err else
  let h := result r
  let r := appendBytes h p 0 r
  if r == err then err else
  let r := stageDigest h r
  if r != 96 || status r != 0 then err else
  let r := commit h (wire+64) r
  if r != 96 || status r != 0 then err else
  let r := Lemma.Forge.nodeMetadata h r
  if r != 128 || status r != 0 then err else
  let t := copy (wire+64) (f+64) 32 r
  store64 f h (store64 (f+8) old (store64 (f+16) 0 (store64 (f+24) (load64 (p+24) t) t)))
partial def saveAll (i t : UInt64) : UInt64 :=
  if i == load64 (st+24) t then t else
  let r := saveNote i t
  if r == err then err else saveAll (i+1) r
partial def writeSized (handle p size offset t : UInt64) : UInt64 :=
  if offset == size then t else
  let n := if size-offset > 512 then 512 else size-offset
  let r := append handle offset (p+offset) n t
  if r != 64 || status r != 0 then err else writeSized handle p size (offset+n) r
partial def readSized (h p size offset t : UInt64) : UInt64 :=
  if offset == size then t else
  let n := if size-offset > 512 then 512 else size-offset
  let r := read h offset n t
  if r != 64+n || status r != 0 then err else readSized h p size (offset+n) (copy (wire+64) (p+offset) n r)
partial def readBytes (h p offset t : UInt64) : UInt64 :=
  if offset == 4096 then t else
  let r := read h offset 512 t
  if r != 576 || status r != 0 then err else readBytes h p (offset+512) (copy (wire+64) (p+offset) 512 r)
def previousRevision (t : UInt64) : UInt64 :=
  let f := selectedRow t
  let h := load64 (f+8) t
  if h == 0 then notice 10 t else
  let r := readBytes h manifest 0 t
  if r == err || !Notes.Schema.valid manifest r then notice 10 r else
  let t := copy (selected r) 0x724000 4096 r
  let t := copy manifest (selected t) 4096 t
  notice 7 (store64 (st+16) 7 t)
partial def search (start remaining t : UInt64) : UInt64 :=
  if remaining == 0 then notice 9 t else
  let count := load64 (st+24) t
  let i := start%count
  if Notes.Schema.selectedBy (note i) query (load64 (st+56) t) 0 foldSearch t then
    notice 6 (store64 (st+8) i (store64 (st+184) 0 t)) else search (start+1) (remaining-1) t
def chooseProject (mode t : UInt64) : UInt64 :=
  let nonce := load64 (st+160) t+1
  let r := Lemma.UI.requestProject nonce t
  if r != 64 || status r != 0 then notice 10 r else notice 17 (store64 (st+160) nonce (store64 (st+168) mode r))
partial def importNotes (root count i t : UInt64) : UInt64 :=
  if i == count then
    let t := copy 0x720000 0x710000 (count*4096) (copy 0x705000 0x701000 (count*256) t)
    notice 25 (store64 (st+24) count (store64 (st+8) 0 t)) else
  let e := manifest+32+i*128
  if load64 e t != 10 then notice 10 t else
  let r := Lemma.Forge.resolve root (e+16) t
  if r < 64 || status r != 0 then notice 10 r else
  let h := result r
  let p := 0x720000+i*4096
  let f := 0x705000+i*256
  let r := readBytes h p 0 r
  if r == err || !Notes.Schema.valid p r then notice 10 r else
  let t := copy (e+16) (f+64) 32 (zero f 32 r)
  let t := store64 f h (store64 (f+24) (load64 (p+24) r) t)
  importNotes root count (i+1) t
def pollProject (t : UInt64) : UInt64 :=
  if load64 (st+168) t == 0 then t else
  let r := Lemma.UI.pollProject (load64 (st+160) t) t
  if r != 64 || status r != 0 then notice 10 (store64 (st+168) 0 r) else
  let state := load64 (wire+16) r
  if state == 1 then r else
  let mode := load64 (st+168) r
  let t := store64 (st+168) 0 r
  if state != 2 || result r == 0 then notice 10 t else
  let root := result r
  if mode == 1 then
    let r := Lemma.Forge.projectIdentity root t
    if r != 192 || status r != 0 then notice 10 r else
    notice 8 (copy (wire+160) (selected r+64) 32 (store64 (selectedRow r+16) 1 r))
  else
    let r := Lemma.Forge.openHead root t
    if r != 128 || status r != 0 then notice 10 r else
    let h := result r
    let size := load64 (wire+16) r
    if size < 160 || size > 544 then notice 10 r else
    let r := readSized h manifest size 0 r
    if r == err || load64 manifest r != 0x31464e4d544c || (load64 (manifest+16) r == 0 || load64 (manifest+16) r > 4) then notice 10 r else
    let count := load64 (manifest+16) r
    let t := r
    importNotes root count 0 t
partial def manifestEntries (i t : UInt64) : UInt64 :=
  if i == load64 (st+24) t then t else
  let e := manifest+32+i*128
  let t := store64 e 10 (store64 (e+8) 13 t)
  let t := copy (row i+64) (e+16) 32 t
  let t := store64 (e+48) 0x6c2e312d65746f6e t
  let t := store8 (e+53) (i+49) (store64 (e+56) 0x65746f6e74 t)
  manifestEntries (i+1) t
def retainNotes (t : UInt64) : UInt64 :=
  let r := saveAll 0 t
  if r == err then notice 10 r else
  let count : UInt64 := 1
  let size := 32+count*128
  let t := zero manifest 512 r
  let t := store64 manifest 0x31464e4d544c (store64 (manifest+8) 1 (store64 (manifest+16) count t))
  let e := manifest+32
  let t := store64 e 10 (store64 (e+8) 13 t)
  let t := copy (selectedRow t+64) (e+16) 32 t
  let t := store64 (e+48) 0x6c2e312d65746f6e (store64 (e+56) 0x65746f6e74 t)
  let r := stage size 11 (load64 (st+112) t) t
  if r != 64 || status r != 0 then notice 10 r else
  let h := result r
  let r := writeSized h manifest size 0 r
  if r == err then notice 10 r else
  let r := stageDigest h r
  if r != 96 || status r != 0 then notice 10 r else
  let r := commit h (wire+64) r
  if r != 96 || status r != 0 then notice 10 r else
  let t := store64 0x704000 0x2d7463656a6f7270 (store64 0x704008 0x7365746f6e r)
  let r := Lemma.Forge.publish h (load64 (st+104) t) (st+128) 0x704000 13 t
  if r != 160 || status r != 0 then notice 10 r else
  let root := result r
  let t := copy (wire+64) (st+128) 32 (store64 (st+104) root (store64 (st+112) h r))
  let r := Lemma.UI.retainProject root (st+128) t
  notice (if r == 64 && status r == 0 then 21 else 10) r
partial def lineStart (p i t : UInt64) : UInt64 :=
  if i == 0 then 0 else if load8 (p+i-1) t == 10 then i else lineStart p (i-1) t
-- The64-bit local operation name is stable across recovered note objects.
-- Owners additionally bind the full SHA-256 payload, exact release and destination;
-- a name collision is refused, never interpreted as authorization for new bytes.
partial def operationName (p bytes i value t : UInt64) : UInt64 :=
  if i == bytes then (if value == 0 then 1 else value) else
  operationName p bytes (i+1) ((value ^^^ load8 (p+i) t)*1099511628211) t
def shareExcerpt (destination t : UInt64) : UInt64 :=
  let p := selected t
  let n := load64 (p+40) t
  let offset := if load64 (st+192) t == 1 then 0 else lineStart (p+192) n t
  let bytes := n-offset
  if bytes == 0 || bytes > 512 then notice 11 t else
  let r := saveNote (load64 (st+8) t) t
  if r == err then notice 10 r else
  let scope := load64 (selectedRow r+64) r ^^^ destination ^^^ ((if destination == 2 then load64 (st+200) r else 0)*256)
  let operation := operationName (p+192+offset) bytes 0 scope r
  let t := store64 (st+64) operation r
  let r := if destination == 5 then Lemma.Social.requestFeed (p+192+offset) bytes 0 operation t
    else Lemma.Messenger.requestMessage (p+192+offset) bytes (load64 (st+200) t) operation t
  if r != 64 || status r != 0 then notice 24 r else
  notice 12 (store64 (st+(if destination == 5 then 72 else 80)) (result r)
    (store64 (st+(if destination == 5 then 88 else 96)) (load64 (wire+16) r) r))
def inspectSharing (destination t : UInt64) : UInt64 :=
  let h := load64 (st+(if destination == 5 then 72 else 80)) t
  if h == 0 then notice 24 t else
  let r := if destination == 5 then Lemma.Social.inspect h t else Lemma.Messenger.inspect h t
  if r != 64 || status r != 0 then notice 24 r else
  notice 13 (store64 (st+(if destination == 5 then 88 else 96)) (load64 (wire+16) r) r)
def cancelSharing (destination t : UInt64) : UInt64 :=
  let h := load64 (st+(if destination == 5 then 72 else 80)) t
  if h == 0 then notice 24 t else
  let r := if destination == 5 then Lemma.Social.cancel h t else Lemma.Messenger.cancel h t
  if r != 64 || (status r != 0 && status r != 12) then notice 24 r else
  notice 13 (store64 (st+(if destination == 5 then 88 else 96)) (load64 (wire+16) r) r)
def insertByte (c t : UInt64) : UInt64 :=
  let p := selected t
  let mode := load64 (st+16) t
  let length := if mode == 1 then p+32 else if mode == 3 then st+56 else p+40
  let target := if mode == 1 then p+128 else if mode == 3 then query else p+192
  let bound : UInt64 := if mode == 1 || mode == 3 then 63 else Notes.Schema.capacity
  let n := load64 length t
  if n >= bound then notice 10 t else
  let t := store8 (target+n) c (store64 length (n+1) t)
  editing (if mode == 3 then 6 else 8) (if mode == 3 then t else store64 (selectedRow t+16) 1 t)
def unicode (value t : UInt64) : UInt64 :=
  if value < 32 || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff) then notice 10 t else
  let prior := load64 (st+216) t
  let p := selected t
  let n := load64 (if prior == 1 then p+32 else if prior == 3 then st+56 else p+40) t
  let bound : UInt64 := if prior == 1 || prior == 3 then 63 else Notes.Schema.capacity
  let bytes : UInt64 := if value < 128 then 1 else if value < 2048 then 2 else if value < 65536 then 3 else 4
  if n > bound || bytes > bound-n then notice 10 t else
  let t := store64 (st+16) prior (store64 st 1 t)
  if value < 128 then insertByte value t else
  if value < 2048 then insertByte (128+value%64) (insertByte (192+value/64) t) else
  if value < 65536 then insertByte (128+value%64)
    (insertByte (128+(value/64)%64) (insertByte (224+value/4096) t)) else
  insertByte (128+value%64) (insertByte (128+(value/64)%64)
    (insertByte (128+(value/4096)%64) (insertByte (240+value/262144) t)))
def key (code down t : UInt64) : UInt64 :=
  if code == 42 || code == 54 then store64 (st+32) down t else
  if code == 29 || code == 97 then store64 (st+40) down t else
  if down == 0 then t else
  let mode := load64 (st+16) t
  let shift := load64 (st+32) t
  let ctrl := load64 (st+40) t
  if mode == 7 then
    if code == 1 || code == 66 then notice 8 (copy 0x724000 (selected t) 4096 (store64 (st+16) 2 t)) else t
  else if mode == 6 then
    if code == 1 then notice 8 (store64 (st+16) (load64 (st+216) t) t) else
    if code == 28 then unicode (load64 (st+224) t) t else
    let c := scanCode code 0
    let d := if c >= 48 && c <= 57 then c-48 else if c >= 97 && c <= 102 then c-87 else 16
    if d == 16 || load64 (st+232) t == 6 then t else
    editing 20 (store64 (st+224) (load64 (st+224) t*16+d) (store64 (st+232) (load64 (st+232) t+1) t))
  else if code == 1 then notice 8 (store64 (st+16) 2 t) else
  if code == 60 then newNote t else
  if code == 61 then chooseProject 1 t else
  if code == 62 then chooseProject 2 t else
  if code == 63 then notice 8 (store64 (selected t+16) ((load64 (selected t+16) t+1)%3) (store64 (selectedRow t+16) 1 t)) else
  if code == 64 then if ctrl == 1 then cancelSharing 5 t else if shift == 1 then inspectSharing 5 t else shareExcerpt 5 t else
  if code == 65 then if ctrl == 1 then cancelSharing 2 t else if shift == 1 then inspectSharing 2 t else shareExcerpt 2 t else
  if code == 66 then previousRevision t else
  if code == 67 then retainNotes t else
  if code == 68 then chooseProject 2 t else
  if code == 15 then notice 8 (store64 (st+192) 0 (store64 (st+8) ((load64 (st+8) t+1)%load64 (st+24) t) (store64 (st+184) 0 t))) else
  if ctrl == 1 && code == 31 then
    let r := saveNote (load64 (st+8) t) t
    notice (if r == err then 10 else 7) r else
  if ctrl == 1 && code == 33 then notice 6 (store64 (st+16) 3 (store64 (st+56) 0 t)) else
  if ctrl == 1 && code == 30 then notice 27 (store64 (st+192) 1 t) else
  if ctrl == 1 && code == 38 then notice 8 (store64 (st+192) 0 t) else
  if ctrl == 1 && code == 50 then notice 13 (store64 (st+200) (load64 (st+200) t%4+1) t) else
  if ctrl == 1 && code == 22 then notice 20 (store64 (st+216) mode (store64 (st+16) 6 (store64 (st+224) 0 (store64 (st+232) 0 t)))) else
  if ctrl == 1 then t else
  if code == 28 && mode == 1 then notice 8 (store64 (st+16) 2 t) else
  if code == 28 && mode == 3 then search (load64 (st+8) t+1) (load64 (st+24) t) t else
  if code == 14 then
    let p := selected t
    let length := if mode == 1 then p+32 else if mode == 3 then st+56 else p+40
    let target := if mode == 1 then p+128 else if mode == 3 then query else p+192
    let n := Notes.Schema.previous target (load64 length t) t
    editing 8 (store64 length n (if mode == 3 then t else store64 (selectedRow t+16) 1 t))
  else if code == 104 then notice 8 (store64 (st+184) 0 t) else
  if code == 109 then
    let n := load64 (selected t+40) t
    notice 8 (store64 (st+184) (if n > 1200 then n-1200 else 0) t) else
  let c := scanCode code shift
  if c == 0 || (mode == 1 && c == 10) then t else insertByte c t
-- Drain a finite event batch before painting. Rendering one full framebuffer
-- after each key used to overflow the actual native input queue during typing.
partial def drainInput (remaining t : UInt64) : UInt64 :=
  if remaining == 0 then t else
  let ev := Lemma.UI.event t
  if ev == 0 || ev == err then t else
  let t := if ev >>> 48 == 1 then key ((ev >>> 32) &&& 65535) (ev &&& 0xffffffff) t else
    if ev >>> 48 == 65535 then store64 (st+32) 0 (store64 (st+40) 0 t) else t
  drainInput (remaining-1) t
partial def loop (surface t : UInt64) : UInt64 :=
  let t := drainInput 128 (pollProject t)
  let dirty := load64 st t
  let t := if dirty == 1 then draw surface t else if dirty == 2 then drawEditing surface t else t
  loop surface (Lemma.UI.wait (Lemma.UI.now t+1) t)

def main (t : UInt64) : UInt64 :=
  let surface := createSurface t
  if surface == err then Lemma.UI.exit 1 t else
  let t := zero st 64 (zero 0x701000 128 surface)
  let t := newNote (store64 (st+200) 1 t)
  loop surface (draw surface t)
end Main
