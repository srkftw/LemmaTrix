import Guest.Labels
import Guest.ProjectSDK
import Guest.ProjectGraph
namespace Guest.Compositor
open Guest.LiveSDK
open Guest.Raster
-- Only this boot service can address trusted chrome or route raw device input.
def st : UInt64 := 0x700000
def fg : UInt64 := 0xd8e6ed
def bg : UInt64 := 0x17232d
def lifecycleLabel (id x y t : UInt64) : UInt64 :=
  if id == 0 then
    let t := store64 (0x414000+0) 2325059536107688532 t
    let t := store64 (0x414000+8) 5928223938417344844 t
    let t := store64 (0x414000+16) 4707479106208411424 t
    let t := store64 (0x414000+24) 5495889218813381708 t
    let t := store64 (0x414000+32) 5638823750462030149 t
    let t := store64 (0x414000+40) 6000276086503514180 t
    let t := store64 (0x414000+48) 5457235 t
    text 0x414000 51 x y fg bg t
  else
  if id == 1 then
    let t := store64 (0x414000+0) 2327894055355109461 t
    let t := store64 (0x414000+8) 2314942856370603347 t
    let t := store64 (0x414000+16) 6076235859975491141 t
    let t := store64 (0x414000+24) 5989878901849215553 t
    let t := store64 (0x414000+32) 6143841479271927636 t
    let t := store64 (0x414000+40) 5917820208298607955 t
    let t := store64 (0x414000+48) 92712260096837 t
    text 0x414000 54 x y fg bg t
  else
  if id == 2 then
    let t := store64 (0x414000+0) 4848490381803069506 t
    let t := store64 (0x414000+8) 4777277208297231433 t
    let t := store64 (0x414000+16) 3616749079549920065 t
    let t := store64 (0x414000+24) 2325059479971058464 t
    let t := store64 (0x414000+32) 2314926436643000405 t
    let t := store64 (0x414000+40) 6003100679495963461 t
    let t := store64 (0x414000+48) 69 t
    text 0x414000 49 x y fg bg t
  else
  if id == 3 then
    let t := store64 (0x414000+0) 4996261462868566081 t
    let t := store64 (0x414000+8) 4708022066914275104 t
    let t := store64 (0x414000+16) 8944225053789211721 t
    let t := store64 (0x414000+24) 5931276255726687008 t
    let t := store64 (0x414000+32) 4996216382892100175 t
    let t := store64 (0x414000+40) 4992275707649938258 t
    let t := store64 (0x414000+48) 5497002126679744600 t
    let t := store64 (0x414000+56) 5917806070054723653 t
    let t := store64 (0x414000+64) 357896308553 t
    text 0x414000 69 x y fg bg t
  else
  if id == 4 then
    let t := store64 (0x414000+0) 5423250129287925586 t
    let t := store64 (0x414000+8) 2329563079882396704 t
    let t := store64 (0x414000+16) 3818569 t
    text 0x414000 19 x y fg bg t
  else
  if id == 5 then
    let t := store64 (0x414000+0) 2329296989227799120 t
    let t := store64 (0x414000+8) 4990918854551227977 t
    let t := store64 (0x414000+16) 2314885530818453536 t
    let t := store64 (0x414000+24) 2325357422171070496 t
    let t := store64 (0x414000+32) 6004503674201710624 t
    let t := store64 (0x414000+40) 2314885531760412704 t
    let t := store64 (0x414000+48) 5500374289345421344 t
    let t := store64 (0x414000+56) 379119476820 t
    text 0x414000 61 x y fg bg t
  else
  if id == 6 then
    let t := store64 (0x414000+0) 4703249246472654670 t
    let t := store64 (0x414000+8) 4707479106208417107 t
    let t := store64 (0x414000+16) 5269263379654331468 t
    let t := store64 (0x414000+24) 2324174429230157901 t
    let t := store64 (0x414000+32) 4836941064252639571 t
    let t := store64 (0x414000+40) 4995689648203517505 t
    let t := store64 (0x414000+48) 3550560851252041504 t
    let t := store64 (0x414000+56) 50 t
    text 0x414000 57 x y fg bg t
  else
  if id == 7 then
    let t := store64 (0x414000+0) 5713190250128363342 t
    let t := store64 (0x414000+8) 2319107879431905358 t
    let t := store64 (0x414000+16) 4995132200251831622 t
    let t := store64 (0x414000+24) 18515 t
    text 0x414000 26 x y fg bg t
  else
  if id == 8 then
    let t := store64 (0x414000+0) 4836952102235554625 t
    let t := store64 (0x414000+8) 4919430824581942607 t
    let t := store64 (0x414000+16) 5500394077098618656 t
    let t := store64 (0x414000+24) 14932 t
    text 0x414000 26 x y fg bg t
  else
  if id == 9 then
    let t := store64 (0x414000+0) 5917816012804473665 t
    let t := store64 (0x414000+8) 2325059535838202437 t
    let t := store64 (0x414000+16) 5713192458029899823 t
    let t := store64 (0x414000+24) 6217593408393859925 t
    let t := store64 (0x414000+32) 5999152372517052485 t
    let t := store64 (0x414000+40) 4995143036473778245 t
    let t := store64 (0x414000+48) 75064591664467 t
    text 0x414000 54 x y fg bg t
  else
  if id == 10 then
    let t := store64 (0x414000+0) 6074301604541908301 t
    let t := store64 (0x414000+8) 3753504 t
    text 0x414000 11 x y fg bg t
  else
  if id == 11 then
    let t := store64 (0x414000+0) 5284487432599785294 t
    let t := store64 (0x414000+8) 4993442305879004495 t
    let t := store64 (0x414000+16) 5278595075969209153 t
    let t := store64 (0x414000+24) 297632153932 t
    text 0x414000 29 x y fg bg t
  else
    t

-- The visible cursor is rendered by this Lean user service. Kernel93 only
-- validates a <=28-byte framebuffer row read into compositor-private storage.
def cursorBackup : UInt64 := 0x71a000
def cursorRow : UInt64 := 0x71a400

def cursorDirty (y h t : UInt64) : UInt64 :=
  let t := store64 (st+360) (if y < load64 (st+360) t then y else load64 (st+360) t) t
  let t := store64 (st+368) (if y+h > load64 (st+368) t then y+h else load64 (st+368) t) t
  store64 (st+352) 1 t

partial def cursorRestoreRows (x y w h row t : UInt64) : UInt64 :=
  if row == h then t else
    let t := syscall 86 0 (cursorBackup+row*32) (w*4) ((y+row)*2560+x*4) t
    if t == error then t else cursorRestoreRows x y w h (row+1) t

def cursorErase (t : UInt64) : UInt64 :=
  if load64 (st+312) t != 1 then t else
    let x := load64 (st+320) t
    let y := load64 (st+328) t
    let w := load64 (st+336) t
    let h := load64 (st+344) t
    let t := cursorRestoreRows x y w h 0 t
    if t == error then t else
      cursorDirty y h (store64 (st+312) 0 t)

partial def cursorPixels (column row w t : UInt64) : UInt64 :=
  if column == w then t else
    let covered := (row < 6 && column <= row) || (row == 6 && (column == 2 || column == 3))
    let white := column == 0 || column == row || row >= 5
    let c : UInt64 := if white then 0xffffff else 0x101010
    let p := cursorRow+column*4
    let t := if covered then
        let t := store8 p (c &&& 255) t
        let t := store8 (p+1) ((c >>> 8) &&& 255) t
        store8 (p+2) ((c >>> 16) &&& 255) t
      else t
    cursorPixels (column+1) row w t

partial def cursorDrawRows (x y w h row t : UInt64) : UInt64 :=
  if row == h then t else
    let t := syscall 93 ((y+row)*2560+x*4) (cursorBackup+row*32) (w*4) 0 t
    if t == error then t else
    let t := copy (cursorBackup+row*32) cursorRow (w*4) t
    let t := cursorPixels 0 row w t
    let t := syscall 86 0 cursorRow (w*4) ((y+row)*2560+x*4) t
    if t == error then t else cursorDrawRows x y w h (row+1) t

def cursorDraw (t : UInt64) : UInt64 :=
  let t := cursorErase t
  if t == error then t else
  let x := load64 (st+16) t
  let y := load64 (st+24) t
  let w := if x > 633 then 640-x else 7
  let h := if y > 393 then 400-y else 7
  let t := cursorDrawRows x y w h 0 t
  if t == error then t else
  let t := store64 (st+312) 1 t
  let t := store64 (st+320) x t
  let t := store64 (st+328) y t
  let t := store64 (st+336) w t
  let t := store64 (st+344) h t
  cursorDirty y h t

def presentWithCursor (y h t : UInt64) : UInt64 :=
  let t := cursorDraw t
  if t == error then t else
  let t := store64 (st+352) 0 t
  let t := store64 (st+360) 400 t
  let t := store64 (st+368) 0 t
  Guest.syscall 87 y h 0 0 t

def presentCursorMove (t : UInt64) : UInt64 :=
  let t := cursorDraw t
  if t == error then t else
  let first := load64 (st+360) t
  let lastRow := load64 (st+368) t
  let t := store64 (st+352) 0 t
  let t := store64 (st+360) 400 t
  let t := store64 (st+368) 0 t
  if lastRow > first then Guest.syscall 87 first (lastRow-first) 0 0 t else t

-- Global backing remains unchanged until both transfer and flush complete.
-- Waiting here yields the user service; trap dispatch never waits for pixels.
partial def frameReady (t : UInt64) : UInt64 :=
  let busy := Guest.syscall 88 0 0 0 0 t
  if busy == error then busy else if busy == 0 then cursorErase busy else
    frameReady (Guest.syscall 9 0 0 0 0 busy)
def chrome (t : UInt64) : UInt64 :=
  let t := frameReady t
  if t == error then t else
  let t := fill 0 0 640 48 bg t
  let t := Guest.Labels.say 0 8 5 fg bg t
  let t := Guest.Labels.say 4 8 20 0x9fc6a5 bg t
  let t := lifecycleLabel 10 8 34 t
  let t := hex (load64 st t) 16 520 34 fg bg t
  upload 0 0 122880 1 t
partial def chooseFocus (slot after t : UInt64) : UInt64 :=
  if slot == 12 then 0 else
    let row := 0x415000+slot*32
    let who := load64 row t
    if slot > after && load64 (row+8) t > 0 && load64 (row+8) t < 5 && Guest.syscall 82 who 0 0 0 t != error then who
    else chooseFocus (slot+1) after t

def focus (who t : UInt64) : UInt64 :=
  let t := Guest.syscall 85 who 0 0 0 t
  let t := if who != 0 then syscall 89 (((3 : UInt64) <<< 48) ||| load64 (st+16) t) 0 1 0 t else t
  let t := if who != 0 then syscall 89 (((3 : UInt64) <<< 48) ||| ((1 : UInt64) <<< 32) ||| load64 (st+24) t) 0 1 0 t else t
  let t := store64 st who t
  let t := store64 (st+8) 1 t
  let t := store64 (st+64) 0 t
  chrome t

def nextFocus (t : UInt64) : UInt64 :=
  let t := Guest.syscall 91 0 0x415000 384 0 t
  let after := load64 st t &&& 255
  let who := chooseFocus 5 after t
  focus (if who == 0 then chooseFocus 5 0 t else who) t

def boundedMotion (old delta limit : UInt64) : UInt64 :=
  if delta >= 0x80000000 then
    let amount := 0x100000000-delta
    if amount > old then 0 else old-amount
  else if delta > limit-old then limit else old+delta

def management (op length t : UInt64) : UInt64 :=
  let t := copy wire 0x414008 length t
  let t := store64 0x414000 op t
  let r := syscall 30 1 0x414000 (length+8) 1024 t
  if r > 1024 then r else r+copy 0x414000 wire r r

def permission (nameWord length mask x t : UInt64) : UInt64 :=
  if (load64 (0x710000+64) t &&& mask) == 0 then t else
    let t := store64 0x414000 nameWord t
    text 0x414000 length x 134 fg bg t

def materialLabel (t : UInt64) : UInt64 :=
  let t := store64 (0x414000+0) 3395790274483801939 t
  let t := store64 (0x414000+8) 3395789213475881504 t
  let t := store64 (0x414000+16) 4849890008315086112 t
  let t := store64 (0x414000+24) 4991201436754714693 t
  let t := store64 (0x414000+32) 5640005665550245946 t
  let t := store64 (0x414000+40) 5207041071913181268 t
  let t := store64 (0x414000+48) 293220336453 t
  text 0x414000 53 16 184 fg bg t

def approvalDraw (t : UInt64) : UInt64 :=
  let t := frameReady t
  if t == error then t else
  let t := fill 0 0 640 400 bg t
  let t := Guest.Labels.say 5 16 12 fg bg t
  let t := Guest.Labels.say 34 16 40 fg bg t
  let t := text (0x710000+432) (load64 (0x710000+424) t) 80 40 fg bg t
  let t := Guest.Labels.say 33 16 64 fg bg t
  let t := hex (load64 (0x710000+160) t) 16 16 82 fg bg t
  let t := hex (load64 (0x710000+168) t) 16 116 82 fg bg t
  let t := hex (load64 (0x710000+176) t) 16 216 82 fg bg t
  let t := hex (load64 (0x710000+184) t) 16 316 82 fg bg t
  let t := Guest.Labels.say 32 16 110 fg bg t
  let t := hex (load64 (0x710000+64) t) 4 136 110 fg bg t
  let t := permission 0x64616572 4 1 16 t
  let t := permission 0x657461657263 6 2 52 t
  let t := permission 0x657369766572 6 4 100 t
  let t := permission 0x6572616873 5 8 148 t
  let t := permission 0x656b6f766572 6 16 190 t
  let t := permission 0x7473696c 4 32 238 t
  let t := permission 0x74726f707865 6 64 274 t
  let t := permission 0x656c6f736e6f63 7 128 322 t
  let t := permission 0x79616c70736964 7 256 376 t
  let t := permission 0x7475706e69 5 512 430 t
  let t := if (load64 (0x710000+64) t &&& 768) != 0 then Guest.Labels.say 50 16 148 fg bg t else t
  let t := if load64 (st+416) t == 1 then materialLabel t else Guest.Labels.say 57 16 184 fg bg t
  let t := Guest.Labels.say 6 16 166 0x9fc6a5 bg t
  let t := Guest.Labels.say 7 16 210 fg bg t
  let t := Guest.Labels.say 8 16 230 fg bg t
  let t := Guest.Labels.say 56 16 266 fg bg t
  let t := hex (load64 (0x710000+96) t) 16 16 284 fg bg t
  let t := hex (load64 (0x710000+104) t) 16 116 284 fg bg t
  let t := hex (load64 (0x710000+112) t) 16 216 284 fg bg t
  let t := hex (load64 (0x710000+120) t) 16 316 284 fg bg t
  let t := upload 0 0 1024000 1 t
  store64 (st+32) 1 t

def candidate (t : UInt64) : UInt64 :=
  let r := management 12 0 t
  if r != 512 then t else
    let t := copy wire 0x710000 512 r
    let r := management 16 0 t
    let t := store64 (st+416) (if r == 64 then result r else 0) r
    let t := store64 (st+48) (load64 st t) t
    let t := syscall 85 0 0 0 0 t
    let t := store64 (st+40) 1 t
    let t := store64 (st+120) 0 t
    let t := store64 (st+64) 0 t
    approvalDraw t

def dismiss (t : UInt64) : UInt64 :=
  let t := store64 (st+120) 0 t
  let t := store64 (st+40) 0 t
  let t := focus (load64 (st+48) t) t
  store64 (st+32) 1 t

def approve (t : UInt64) : UInt64 :=
  let gesture := syscall 99 0 0 0 0 t
  let t := copy (0x710000+160) wire 32 t
  let t := store64 (wire+32) (load64 (0x710000+64) t) t
  let t := store64 (wire+40) gesture t
  let r := management 23 48 t
  if r != 64 || status r != 0 then t else
    let r := management 24 0 r
    if r != 64 || status r != 0 then t else
      let slot := result r
      let t := store64 wire slot r
      let t := copy (0x710000+160) (wire+8) 32 t
      let r := management 25 40 t
      let t := if r == 64 && status r == 0 then store64 (st+424) (result r) r else r
      dismiss t

def retentionDraw (t : UInt64) : UInt64 :=
  let t := frameReady t
  let t := fill 0 0 640 400 bg t
  let t := Guest.Labels.say 51 16 12 fg bg t
  let t := text (0x710400+96) (load64 (0x710400+32) t) 16 40 fg bg t
  let t := Guest.Labels.say 20 16 64 fg bg t
  let t := hex (load64 (0x710400+64) t) 16 64 64 fg bg t
  let t := hex (load64 (0x710400+72) t) 16 164 64 fg bg t
  let t := hex (load64 (0x710400+80) t) 16 264 64 fg bg t
  let t := hex (load64 (0x710400+88) t) 16 364 64 fg bg t
  let t := Guest.Labels.say 53 16 92 fg bg t
  let t := hex (load64 (0x710400+16) t) 8 64 92 fg bg t
  let t := Guest.Labels.say 54 16 108 fg bg t
  let t := hex (load64 (0x710400+24) t) 8 64 108 fg bg t
  let t := Guest.Labels.say 14 16 140 fg bg t
  let t := hex (load64 (st+112) t) 16 16 172 fg bg t
  let t := Guest.Labels.say 52 16 210 fg bg t
  let t := upload 0 0 1024000 1 t
  store64 (st+32) 1 t

def retentionRequest (root expected caller t : UInt64) : UInt64 :=
  let r := call 64 (header 29 root 0 0 0 0 0 t)
  if r != 160 || status r != 0 || load64 (wire+48) r != caller || !Guest.ProjectGraph.equal expected (wire+64) 32 r then error else
    let launcher := syscall 97 1 0 0 0 r
    let r := Guest.ProjectSDK.delegate root launcher 127 r
    if r == error || status r != 0 then error else
      let h := result r
      let t := store64 wire h r
      let r := management 221 8 t
      if r != 160 || status r != 0 then error else
        let t := copy wire 0x710400 160 r
        let t := store64 (st+96) h t
        let t := store64 (st+112) caller t
        let t := store64 (st+48) (load64 st t) t
        let t := syscall 85 0 0 0 0 t
        let t := store64 (st+40) 2 t
        let t := store64 (st+120) 0 t
        retentionDraw t

def retainApproved (t : UInt64) : UInt64 :=
  let gesture := syscall 99 0 0 0 0 t
  let t := store64 wire (load64 (st+96) t) t
  let t := copy (0x710400+64) (wire+8) 32 t
  let t := store64 (wire+40) gesture t
  let r := management 220 48 t
  let ok := r >= 64 && r <= 1024 && status r == 0
  let t := dismiss r
  let t := Guest.Labels.say (if ok then 55 else 36) 8 20 fg bg t
  let t := upload 0 (20*2560) (12*2560) 1 t
  store64 (st+32) 1 t

-- Trusted project-open portal. Rows retain exact displayed heads, and all
-- delegation uses the kernel-supplied requesting incarnation.
def pickerRow (i : UInt64) : UInt64 := 0x711000+i*128

partial def pickerRows (cursor count fuel t : UInt64) : UInt64 :=
  if fuel == 0 || count == 16 then store64 (st+144) count t else
    let r := Guest.ProjectSDK.roots cursor t
    if r == error || status r != 0 || result r == 0 then store64 (st+144) count r else
      let row := pickerRow count
      let t := store64 row (result r) r
      let t := store64 (row+8) (load64 (wire+16) t) t
      let t := copy (wire+64) (row+16) 32 t
      let t := copy (wire+96) (row+48) 64 t
      pickerRows (load64 (wire+24) t) (count+1) (fuel-1) t

def pickerLabel (id x y t : UInt64) : UInt64 :=
  if id == 0 then
    let t := store64 (0x414000+0) 2325059536107688532 t
    let t := store64 (0x414000+8) 2329560872135905872 t
    let t := store64 (0x414000+16) 5989839320201384015 t
    let t := store64 (0x414000+24) 2324174428977843269 t
    let t := store64 (0x414000+32) 5931276186839499086 t
    let t := store64 (0x414000+40) 361905867343 t
    text 0x414000 45 x y fg bg t
  else
  if id == 1 then
    let t := store64 (0x414000+0) 5283939820061672786 t
    let t := store64 (0x414000+8) 4990920027006846798 t
    let t := store64 (0x414000+16) 3822419 t
    text 0x414000 19 x y fg bg t
  else
  if id == 2 then
    let t := store64 (0x414000+0) 2322260174972339009 t
    let t := store64 (0x414000+8) 4995128742570444114 t
    let t := store64 (0x414000+16) 5284487431796905025 t
    let t := store64 (0x414000+24) 4995126715595375955 t
    let t := store64 (0x414000+32) 2325347586728612384 t
    let t := store64 (0x414000+40) 6071224230275796549 t
    let t := store64 (0x414000+48) 6076006053773123653 t
    text 0x414000 56 x y fg bg t
  else
  if id == 3 then
    let t := store64 (0x414000+0) 2322260174972339009 t
    let t := store64 (0x414000+8) 5498419195068630354 t
    let t := store64 (0x414000+16) 4981068384837771353 t
    let t := store64 (0x414000+24) 5773705222087264580 t
    let t := store64 (0x414000+32) 4692830334269276757 t
    let t := store64 (0x414000+40) 6436850385285567573 t
    text 0x414000 48 x y fg bg t
  else
  if id == 4 then
    let t := store64 (0x414000+0) 5701648762709103169 t
    let t := store64 (0x414000+8) 5989851560641044562 t
    let t := store64 (0x414000+16) 2319107879397051461 t
    let t := store64 (0x414000+24) 4692814936744939077 t
    let t := store64 (0x414000+32) 4997387354387272789 t
    let t := store64 (0x414000+40) 2322242582783995680 t
    let t := store64 (0x414000+48) 83860365656387 t
    text 0x414000 54 x y fg bg t
  else
  if id == 5 then
    let t := store64 (0x414000+0) 4992890351843823438 t
    let t := store64 (0x414000+8) 5278595075970126915 t
    let t := store64 (0x414000+16) 5716229309044244812 t
    let t := store64 (0x414000+24) 5932402151237637152 t
    let t := store64 (0x414000+32) 5211544671390815061 t
    let t := store64 (0x414000+40) 5000261 t
    text 0x414000 43 x y fg bg t
  else
  if id == 6 then
    let t := store64 (0x414000+0) 2329572966898226499 t
    let t := store64 (0x414000+8) 4919430815874303315 t
    let t := store64 (0x414000+16) 64064827246624 t
    text 0x414000 22 x y fg bg t
  else
  if id == 7 then
    let t := store64 (0x414000+0) 2329560872135905872 t
    let t := store64 (0x414000+8) 5638823750461636942 t
    let t := store64 (0x414000+16) 5640006803665395780 t
    let t := store64 (0x414000+24) 5928461441584668756 t
    let t := store64 (0x414000+32) 4847362222590020943 t
    let t := store64 (0x414000+40) 21332 t
    text 0x414000 42 x y fg bg t
  else
  if id == 8 then
    let t := store64 (0x414000+0) 4203075909492753746 t
    text 0x414000 8 x y fg bg t
  else
  if id == 9 then
    let t := store64 (0x414000+0) 2329560872135905872 t
    let t := store64 (0x414000+8) 2325059480187914307 t
    let t := store64 (0x414000+16) 6288513089571790895 t
    let t := store64 (0x414000+24) 4922527989805634592 t
    let t := store64 (0x414000+32) 4703244689279898689 t
    let t := store64 (0x414000+40) 68 t
    text 0x414000 41 x y fg bg t
  else
    t

partial def drawPickerNames (i count selected t : UInt64) : UInt64 :=
  if i == count then t else
    let row := pickerRow i
    let shade := if i == selected then 0x35546a else bg
    let t := fill 12 (106+i*12) 616 12 shade t
    let t := char 16 (107+i*12) (if i == selected then 62 else 32) fg shade t
    let n := load64 (row+8) t
    let t := text (row+48) (if n > 63 then 63 else n) 32 (107+i*12) fg shade t
    drawPickerNames (i+1) count selected t

def pickerDraw (t : UInt64) : UInt64 :=
  let t := store64 (st+120) 0 t
  let t := frameReady t
  let t := fill 0 0 640 400 bg t
  let t := pickerLabel 0 12 10 t
  let t := pickerLabel 1 12 30 t
  let t := hex (load64 (st+128) t) 16 152 30 fg bg t
  let t := pickerLabel 8 380 30 t
  let t := hex (load64 (st+160) t) 8 438 30 fg bg t
  let t := pickerLabel (if load64 (st+136) t == 127 then 2 else 3) 12 50 t
  let t := pickerLabel 4 12 70 t
  let t := pickerLabel 7 12 88 t
  let count := load64 (st+144) t
  let selected := load64 (st+152) t
  let t := if count == 0 then pickerLabel 5 12 120 t else drawPickerNames 0 count selected t
  let t := pickerLabel 6 12 318 t
  let row := pickerRow selected
  let t := if count == 0 then t else
      let t := hex (load64 (row+16) t) 16 12 338 fg bg t
      let t := hex (load64 (row+24) t) 16 114 338 fg bg t
      let t := hex (load64 (row+32) t) 16 216 338 fg bg t
      hex (load64 (row+40) t) 16 318 338 fg bg t
  let t := upload 0 0 1024000 1 t
  store64 (st+32) 1 t

def pickerRequest (caller nonce t : UInt64) : UInt64 :=
  let actual := syscall 34 caller 0 0 0 t
  let rights := if (actual &&& 127) == 127 then 127 else if (actual &&& 1) == 1 then 1 else 0
  if actual == error || rights == 0 || nonce == 0 then error else
    let t := store64 (st+128) caller actual
    let t := store64 (st+136) rights t
    let t := store64 (st+152) 0 t
    let t := store64 (st+160) nonce t
    let t := store64 (st+192) caller t
    let t := store64 (st+200) nonce t
    let t := store64 (st+208) 0 t
    let t := store64 (st+216) 1 t
    let t := pickerRows 0 0 64 t
    let t := store64 (st+48) (load64 st t) t
    let t := syscall 85 0 0 0 0 t
    let t := store64 (st+40) 3 t
    let t := store64 (st+64) 0 t
    let t := store64 (st+120) 0 t
    pickerDraw t

def pickerApprove (t : UInt64) : UInt64 :=
  let caller := load64 (st+128) t
  let rights := load64 (st+136) t
  let actual := syscall 34 caller 0 0 0 t
  if actual == error || (actual &&& rights) != rights || load64 (st+144) t == 0 then t else
    let row := pickerRow (load64 (st+152) t)
    let root := load64 row t
    let r := Guest.ProjectSDK.describeRoot root t
    if r != 160 || status r != 0 then t else
      if !Guest.ProjectGraph.equal (row+16) (wire+64) 32 r then
        let t := pickerRows 0 0 64 r
        let t := store64 (st+152) 0 t
        let t := store64 (st+120) 0 t
        pickerDraw t
      else
        let r := Guest.ProjectSDK.delegate root caller rights r
        if r != 160 || status r != 0 then t else
          let t := store64 (st+208) (result r) r
          let t := store64 (st+216) 2 t
          dismiss t

def pickerCancel (t : UInt64) : UInt64 := dismiss (store64 (st+216) 3 t)

def pickerSelect (back t : UInt64) : UInt64 :=
  let count := load64 (st+144) t
  if count == 0 then t else
    let old := load64 (st+152) t
    let next := if back == 1 then (old+count-1)%count else (old+1)%count
    let t := store64 (st+152) next t
    pickerDraw t

-- Read-only vault status never grants a project or approves future retention.
def vaultStatusLabel (id x y t : UInt64) : UInt64 :=
  if id == 0 then
    let t := store64 (0x414000+0) 2325059536107688532 t
    let t := store64 (0x414000+8) 2329298080182714959 t
    let t := store64 (0x414000+16) 6076235868682928470 t
    let t := store64 (0x414000+24) 1398101057 t
    text 0x414000 28 x y fg bg t
  else
  if id == 1 then
    let t := store64 (0x414000+0) 5283939820061672786 t
    let t := store64 (0x414000+8) 4990920027006846798 t
    let t := store64 (0x414000+16) 3822419 t
    text 0x414000 19 x y fg bg t
  else
  if id == 2 then
    let t := store64 (0x414000+0) 2329298080182714959 t
    let t := store64 (0x414000+8) 2327885233746298195 t
    let t := store64 (0x414000+16) 4919420920437427797 t
    let t := store64 (0x414000+24) 58 t
    text 0x414000 25 x y fg bg t
  else
  if id == 3 then
    let t := store64 (0x414000+0) 5283934322285630785 t
    let t := store64 (0x414000+8) 5931276186839957827 t
    let t := store64 (0x414000+16) 4705452731949992527 t
    let t := store64 (0x414000+24) 5485477062758517070 t
    let t := store64 (0x414000+32) 64064894288207 t
    text 0x414000 38 x y fg bg t
  else
  if id == 4 then
    let t := store64 (0x414000+0) 4919424244507755858 t
    let t := store64 (0x414000+8) 6071772908086251552 t
    let t := store64 (0x414000+16) 16417170222174752 t
    text 0x414000 23 x y fg bg t
  else
  if id == 5 then
    let t := store64 (0x414000+0) 4919424244507755858 t
    let t := store64 (0x414000+8) 5629579043743614752 t
    let t := store64 (0x414000+16) 250505151567 t
    text 0x414000 21 x y fg bg t
  else
  if id == 6 then
    let t := store64 (0x414000+0) 4919424244507755858 t
    let t := store64 (0x414000+8) 4764887915288479520 t
    let t := store64 (0x414000+16) 250505155673 t
    text 0x414000 21 x y fg bg t
  else
  if id == 7 then
    let t := store64 (0x414000+0) 5125189049753882435 t
    let t := store64 (0x414000+8) 5713190241826065989 t
    let t := store64 (0x414000+16) 14926 t
    text 0x414000 18 x y fg bg t
  else
  if id == 8 then
    let t := store64 (0x414000+0) 2327885233746298195 t
    let t := store64 (0x414000+8) 2319107815056294211 t
    let t := store64 (0x414000+16) 4993453258965012302 t
    let t := store64 (0x414000+24) 5053115001730257709 t
    let t := store64 (0x414000+32) 6004218930738185554 t
    let t := store64 (0x414000+40) 84977023468320 t
    text 0x414000 46 x y fg bg t
  else
  if id == 9 then
    let t := store64 (0x414000+0) 5629577935776530771 t
    let t := store64 (0x414000+8) 5989859111494501701 t
    let t := store64 (0x414000+16) 2325357422136348741 t
    let t := store64 (0x414000+24) 5931276255524640837 t
    let t := store64 (0x414000+32) 5782938942798383695 t
    let t := store64 (0x414000+40) 83843504624208 t
    text 0x414000 46 x y fg bg t
  else
  if id == 10 then
    let t := store64 (0x414000+0) 4981071687668945733 t
    let t := store64 (0x414000+8) 5495271405182604366 t
    let t := store64 (0x414000+16) 4543311 t
    text 0x414000 19 x y fg bg t
  else
  if id == 11 then
    let t := store64 (0x414000+0) 6133994318429508691 t
    let t := store64 (0x414000+8) 4774180957501931854 t
    let t := store64 (0x414000+16) 6143286062939653452 t
    let t := store64 (0x414000+24) 5284501670466704460 t
    let t := store64 (0x414000+32) 5629574615679386947 t
    let t := store64 (0x414000+40) 5715159484328858703 t
    let t := store64 (0x414000+48) 17486 t
    text 0x414000 50 x y fg bg t
  else
    t

def vaultStatusDraw (t : UInt64) : UInt64 :=
  let t := frameReady t
  let t := fill 0 0 640 400 bg t
  let t := vaultStatusLabel 0 12 12 t
  let t := vaultStatusLabel 1 12 38 t
  let t := hex (load64 (st+400) t) 16 152 38 fg bg t
  let t := if load64 0x719000 t != 0 || load64 0x719080 t != 0 then
      vaultStatusLabel 11 12 76 t
    else
      let t := vaultStatusLabel 2 12 76 t
      let t := hex (load64 (0x719000+40) t) 1 258 76 fg bg t
      let t := vaultStatusLabel 3 12 100 t
      let t := hex (load64 (0x719080+40) t) 1 258 100 fg bg t
      let t := vaultStatusLabel 4 12 132 t
      let t := hex (load64 (0x719080+24) t) 8 258 132 fg bg t
      let t := vaultStatusLabel 5 12 156 t
      let t := hex (load64 (0x719080+16) t) 8 258 156 fg bg t
      let t := vaultStatusLabel 6 12 180 t
      let t := hex (load64 (0x719080+32) t) 16 258 180 fg bg t
      let t := vaultStatusLabel 7 12 204 t
      hex (load64 (0x719080+56) t) 16 258 204 fg bg t
  let t := vaultStatusLabel 8 12 250 t
  let t := vaultStatusLabel 9 12 274 t
  let t := vaultStatusLabel 10 12 322 t
  let t := upload 0 0 1024000 1 t
  store64 (st+32) 1 t

def vaultStatusRequest (caller t : UInt64) : UInt64 :=
  let actual := syscall 34 caller 0 0 0 t
  if actual == error then error else
    let t := store64 (st+400) caller actual
    let t := header 202 0 3 0 0 0 0 t
    let r := management 202 64 t
    let t := if r >= 64 && r <= 1024 then copy wire 0x719000 64 r else store64 0x719000 1 r
    let t := header 212 0 3 0 0 0 0 t
    let r := management 212 64 t
    let t := if r == 64 then copy wire 0x719080 64 r else store64 0x719080 1 r
    let t := if load64 0x719000 t == 0 && load64 (0x719000+40) t == 0 && load64 0x719080 t == 3 then zero 0x719080 8 t else t
    let t := store64 (st+48) (load64 st t) t
    let t := syscall 85 0 0 0 0 t
    let t := store64 (st+40) 5 t
    let t := store64 (st+64) 0 t
    let t := store64 (st+120) 0 t
    vaultStatusDraw t

def pollApps (t : UInt64) : UInt64 :=
  let n := syscall 36 4 0x416000 1056 0 t
  if n < 96 || n > 1056 then t else
    let token := load64 0x416008 n
    let caller := load64 0x416000 n
    let op := load64 0x416020 n
    let root := load64 0x416028 n
    let nonce := load64 0x416030 n
    let abi := load64 0x416018 n
    if op == 4 && n == 96 && abi == 2 then
      let valid := caller == load64 (st+192) n && nonce == load64 (st+200) n
      let t := zero wire 8 n
      let t := store64 wire (if valid then 0 else 1) t
      let t := if !valid then t else
          let t := store64 (wire+8) (load64 (st+208) t) t
          store64 (wire+16) (load64 (st+216) t) t
      syscall 32 token wire 64 0 t
    else
      let r := if load64 (st+40) n != 0 || abi != 2 then error else
        if n == 128 && op == 2 then retentionRequest root 0x416060 caller n
        else if n == 96 && op == 3 && load64 0x416058 n == 1 then pickerRequest caller nonce n
        else if n == 96 && op == 5 && load64 0x416058 n == 1 then vaultStatusRequest caller n else error
      let t := zero wire 8 r
      let t := store64 wire (if r == error then 1 else 0) t
      let t := store64 (wire+8) nonce t
      syscall 32 token wire 64 0 t

-- Installed generations are inert catalog records until an explicit start.
-- This modal uses the existing Launcher authority path and never grants that
-- authority to an application. The selected record includes the actual slot.
def lifecycleRow (i : UInt64) : UInt64 := 0x712000+i*1024

partial def lifecycleCatalog (index count t : UInt64) : UInt64 :=
  if index == 16 then store64 (st+256) count t else
    let t := store64 wire index t
    let r := management 13 8 t
    if r != 512 then lifecycleCatalog (index+1) count r else
      let row := lifecycleRow count
      let t := copy wire row 512 r
      let t := store64 (row+520) (index+1) t
      let t := copy (row+128) wire 32 t
      let active := management 29 32 t
      let isActive := active == 512 && Guest.ProjectGraph.equal (row+160) (wire+160) 32 active
      let t := store64 (row+512) (if isActive then 1 else 0) active
      let t := copy (row+128) wire 32 t
      let relation := management 14 32 t
      let t := if relation == 128 && status relation == 0 then
          let t := copy (wire+64) (row+528) 64 relation
          store64 (row+592) (result relation) t
        else zero (row+528) 9 relation
      lifecycleCatalog (index+1) (count+1) t

def lifecycleRefresh (t : UInt64) : UInt64 :=
  let t := lifecycleCatalog 0 0 t
  let t := if load64 (st+264) t >= load64 (st+256) t then store64 (st+264) 0 t else t
  let r := management 2 0 t
  if r == 384 then copy wire 0x718000 384 r else zero 0x718000 48 r

partial def lifecycleRows (i t : UInt64) : UInt64 :=
  if i == load64 (st+256) t then t else
    let row := lifecycleRow i
    let y := 72+i*11
    let shade := if i == load64 (st+264) t then 0x35546a else bg
    let t := fill 4 y 632 11 shade t
    let t := char 4 (y+1) (if load64 (row+512) t == 1 then 65 else 45) fg shade t
    let t := hex (load64 (row+520) t) 2 16 (y+1) fg shade t
    let n := load64 (row+424) t
    let t := text (row+432) (if n > 30 then 30 else n) 40 (y+1) fg shade t
    let t := hex (load64 (row+72) t) 8 226 (y+1) fg shade t
    let t := char 274 (y+1) 46 fg shade t
    let t := hex (load64 (row+80) t) 8 280 (y+1) fg shade t
    let t := char 328 (y+1) 46 fg shade t
    let t := hex (load64 (row+88) t) 8 334 (y+1) fg shade t
    let t := hex (load64 (row+400) t) 1 390 (y+1) fg shade t
    let t := hex (load64 (row+24) t) 8 408 (y+1) fg shade t
    let t := hex (load64 (row+64) t) 4 468 (y+1) fg shade t
    lifecycleRows (i+1) t

partial def lifecycleProcesses (i t : UInt64) : UInt64 :=
  if i == 12 then t else
    let row := 0x718000+i*32
    let y := 278+(i-1)*9
    let who := load64 row t
    let t := char 4 y (if who == load64 (st+48) t && who != 0 then 62 else 32) fg bg t
    let t := hex who 16 20 y fg bg t
    let t := hex (load64 (row+8) t) 2 166 y fg bg t
    let t := hex (load64 (row+16) t) 16 210 y fg bg t
    let t := hex (load64 (row+24) t) 16 360 y fg bg t
    lifecycleProcesses (i+1) t

def lifecycleDraw (t : UInt64) : UInt64 :=
  let t := frameReady t
  if t == error then t else
  let t := fill 0 0 640 400 bg t
  let t := lifecycleLabel 0 8 8 t
  let t := lifecycleLabel 1 8 24 t
  let t := lifecycleLabel 2 8 36 t
  let t := lifecycleLabel 3 8 56 t
  let t := if load64 (st+256) t == 0 then lifecycleLabel 6 8 76 t else lifecycleRows 0 t
  let t := if load64 (st+256) t == 0 then t else
    let row := lifecycleRow (load64 (st+264) t)
    if load64 (row+592) t == 0 then lifecycleLabel 11 8 252 t else
      let t := lifecycleLabel 4 8 252 t
      let t := hex (load64 (row+560) t) 16 128 252 fg bg t
      let t := hex (load64 (row+568) t) 16 232 252 fg bg t
      let t := hex (load64 (row+576) t) 16 336 252 fg bg t
      hex (load64 (row+584) t) 16 440 252 fg bg t
  let t := lifecycleLabel 5 8 266 t
  let t := lifecycleProcesses 1 t
  let outcome := load64 (st+272) t
  let t := lifecycleLabel (if outcome == 0 then 7 else if outcome == 1 then 8 else 9) 8 384 t
  let t := if outcome == 1 then hex (load64 (st+280) t) 16 182 384 fg bg t else t
  let t := upload 0 0 1024000 1 t
  let t := store64 (st+120) 0 t
  store64 (st+32) 1 t

def lifecycleOpen (t : UInt64) : UInt64 :=
  let t := store64 (st+48) (load64 st t) t
  let t := syscall 85 0 0 0 0 t
  let t := store64 (st+56) 0 t
  let t := store64 (st+40) 4 t
  let t := store64 (st+120) 0 t
  let t := store64 (st+64) 0 t
  let t := store64 (st+264) 0 t
  let t := store64 (st+272) 0 t
  lifecycleDraw (lifecycleRefresh t)

def lifecycleAction (op t : UInt64) : UInt64 :=
  let count := load64 (st+256) t
  let selected := load64 (st+264) t
  if op != 26 && (count == 0 || selected >= count) then lifecycleDraw (store64 (st+272) 2 t) else
    let row := lifecycleRow selected
    let t := if op == 25 then
        let t := store64 wire (load64 (row+520) t) t
        copy (row+160) (wire+8) 32 t
      else if op == 26 then store64 wire (load64 (st+48) t) t
      else if op == 27 then
        let t := store64 wire (load64 (st+48) t) t
        let t := store64 (wire+8) (load64 (row+520) t) t
        copy (row+160) (wire+16) 32 t
      else
        let t := copy (row+128) wire 32 t
        copy (row+528) (wire+32) 64 t
    let r := management op (if op == 25 then 40 else if op == 27 then 48 else if op == 28 then 96 else 8) t
    let ok := r == 64 && status r == 0
    let value := if ok then result r else error
    let t := store64 (st+272) (if ok then 1 else 2) r
    let t := store64 (st+280) value t
    let t := if ok && (op == 25 || op == 27) then store64 (st+48) value t
      else if ok && op == 26 then store64 (st+48) 0 t else t
    lifecycleDraw (lifecycleRefresh t)

def lifecycleRoute (code value t : UInt64) : UInt64 :=
  if value != 1 then t else
  if code == 1 then dismiss t
  else if code == 88 then candidate (dismiss t)
  else if code == 63 then lifecycleDraw (lifecycleRefresh t)
  else if code == 103 || code == 108 || code == 15 then
    let count := load64 (st+256) t
    if count == 0 then t else
      let old := load64 (st+264) t
      let next := if code == 103 then (if old == 0 then count-1 else old-1) else (old+1)%count
      lifecycleDraw (store64 (st+264) next t)
  else if load64 (st+120) t != 1 then t
  else if code == 28 then lifecycleAction 25 t
  else if code == 31 then lifecycleAction 26 t
  else if code == 19 then lifecycleAction 27 t
  else if code == 48 then lifecycleAction 28 t
  else t

def route (ev t : UInt64) : UInt64 :=
  let kind := ev >>> 48
  let code := (ev >>> 32) &&& 65535
  let value := ev &&& 0xffffffff
  -- Full-screen trusted modals consume pointer input, but physical motion must
  -- still advance the shell's coordinates before ordinary focus resumes.
  let t := if kind == 2 && code == 0 then
      let t := store64 (st+16) (boundedMotion (load64 (st+16) t) value 639) t
      store64 (st+352) 1 t
    else if kind == 2 && code == 1 then
      let t := store64 (st+24) (boundedMotion (load64 (st+24) t) value 399) t
      store64 (st+352) 1 t
    else t
  if kind == 65534 then t
  else if kind == 0 && code == 3 then
    let t := store64 (st+56) 0 t
    Guest.syscall 89 ev 0 1 0 t
  else if load64 (st+40) t == 5 then
    if kind == 1 && value == 1 && (code == 1 || (code == 28 && load64 (st+120) t == 1)) then dismiss t else t
  else if load64 (st+40) t == 4 then
    if kind == 1 then lifecycleRoute code value t else t
  else if load64 (st+40) t != 0 then
    if kind == 1 && code == 28 && value == 1 && load64 (st+120) t == 1 then
      if load64 (st+40) t == 2 then retainApproved t
      else if load64 (st+40) t == 3 then pickerApprove t else approve t
    else if kind == 1 && code == 1 && value == 1 then
      if load64 (st+40) t == 3 then pickerCancel t else dismiss t
    else if kind == 1 && value == 1 && load64 (st+40) t == 3 && (code == 15 || code == 105 || code == 106 || code == 103 || code == 108) then
      pickerSelect (if code == 105 || code == 103 then 1 else 0) t
    else t
  else if kind == 1 && code == 67 && value == 1 && load64 (st+56) t == 1 then lifecycleOpen t
  else if kind == 1 && code == 88 && value == 1 then candidate t
  else if kind == 2 then
    Guest.syscall 89 ev 0 1 0 t
  else if kind == 1 && code == 56 then store64 (st+56) value t
  else if kind == 1 && code == 15 && value == 1 && load64 (st+56) t == 1 then nextFocus t
  else if kind == 1 && code == 272 && value == 1 && load64 (st+24) t < 48 then
    if load64 (st+24) t >= 32 && load64 (st+16) t < 160 then lifecycleOpen t
    else if load64 (st+16) t > 300 then candidate t else nextFocus t
  else Guest.syscall 89 ev 0 1 0 t

-- At most eight rows (20 KiB) enter one trap. A concurrent upload advances the
-- kernel epoch, so acknowledging an older composite never clears newer work.
def composite (who epoch t : UInt64) : UInt64 :=
  let copying := load64 (st+64) t
  let t := if copying == 0 then
      let t := cursorErase t
      let range := Guest.syscall 92 who 0 0 0 t
      let forced := load64 (st+8) range == 1
      let first : UInt64 := if forced || range == error then 0 else range >>> 32
      let lastRow : UInt64 := if forced || range == error then 352 else range &&& 0xffffffff
      let t := store64 (st+64) who range
      let t := store64 (st+72) epoch t
      let t := store64 (st+80) first t
      store64 (st+88) lastRow t else t
  let row := load64 (st+80) t
  let lastRow := load64 (st+88) t
  let rows := if lastRow > row+8 then 8 else if lastRow > row then lastRow-row else 0
  let expected := load64 (st+72) t
  let t := if rows == 0 then error else Guest.syscall 83 who row rows expected t
  if t == error then store64 (st+64) 0 t else
  if row+rows == lastRow then
    let t := store64 (st+64) 0 t
    let t := store64 (st+8) 0 t
    let t := store64 (st+32) 0 t
    presentWithCursor 0 400 t
  else store64 (st+80) (row+rows) t

partial def loop (t : UInt64) : UInt64 :=
  let t := Guest.syscall 88 0 0 0 0 t
  let t := pollApps t
  let pending := load64 (st+424) t
  let t := if pending != 0 && syscall 82 pending 0 0 0 t != error then focus pending (store64 (st+424) 0 t) else t
  let ev := Guest.syscall 84 0 0 0 0 t
  let t := if ev != 0 && ev != error then route ev ev else t
  let who := load64 st t
  let t := if who == 0 && load64 (st+40) t == 0 then nextFocus t else t
  let who := load64 st t
  let dirty := if who == 0 then 0 else Guest.syscall 82 who 0 0 0 t
  let busy := Guest.syscall 88 0 0 0 0 t
  let t := if busy == 0 && ev == 0 && load64 (st+32) t == 0 && load64 (st+40) t != 0 then store64 (st+120) 1 t else t
  let t := if busy == 0 && load64 (st+40) t == 0 && who != 0 && dirty != error && (dirty != 0 || load64 (st+8) t == 1 || load64 (st+64) t != 0) then
      composite who dirty t
    else if busy == 0 && load64 (st+32) t == 1 then
      let t := store64 (st+32) 0 t
      presentWithCursor 0 400 t
    else if busy == 0 && load64 (st+352) t == 1 && load64 (st+64) t == 0 then presentCursorMove t
    else if dirty == error && who != 0 then focus 0 t else t
  loop (Guest.syscall 9 0 0 0 0 t)

def main (initial : UInt64) : UInt64 :=
  let t := zero st 64 initial
  let t := store64 (st+16) 320 t
  let t := store64 (st+24) 200 t
  let t := store64 (st+360) 400 t
  let t := chrome t
  let t := store64 (st+32) 1 t
  loop t
end Guest.Compositor
