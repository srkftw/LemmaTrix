import Guest.LiveSDK
namespace Guest.Raster
open Guest.LiveSDK
def pixels : UInt64 := 0x600000
def color (c : UInt64) : UInt64 := c ||| (c <<< 32)
def glyph (raw : UInt64) : UInt64 :=
  let c := raw
  if c == 97 then 16692328448 else
  if c == 98 then 32801348112 else
  if c == 99 then 15620126720 else
  if c == 100 then 16695014433 else
  if c == 101 then 15602333696 else
  if c == 102 then 8867684646 else
  if c == 103 then 15082243552 else
  if c == 104 then 18842704400 else
  if c == 105 then 15170940932 else
  if c == 106 then 13491050498 else
  if c == 107 then 20024281616 else
  if c == 108 then 15170932876 else
  if c == 109 then 23275956224 else
  if c == 110 then 18842703872 else
  if c == 111 then 15621208064 else
  if c == 112 then 17748772800 else
  if c == 113 then 1123599840 else
  if c == 114 then 17734359040 else
  if c == 115 then 32261028864 else
  if c == 116 then 6753120520 else
  if c == 117 then 14614578176 else
  if c == 118 then 4648911872 else
  if c == 119 then 11464655872 else
  if c == 120 then 18593694720 else
  if c == 121 then 15082243616 else
  if c == 122 then 33558723584 else
  if c == 65 then 18842895918 else
  if c == 66 then 32801506878 else
  if c == 67 then 16660316687 else
  if c == 68 then 32801080894 else
  if c == 69 then 33840644639 else
  if c == 70 then 17734517279 else
  if c == 71 then 16695149071 else
  if c == 72 then 18842895921 else
  if c == 73 then 33424543903 else
  if c == 74 then 13507823687 else
  if c == 75 then 18879369809 else
  if c == 76 then 33840185872 else
  if c == 77 then 18842572657 else
  if c == 78 then 18842507057 else
  if c == 79 then 15621211694 else
  if c == 80 then 17734518334 else
  if c == 81 then 14585218606 else
  if c == 82 then 18879563326 else
  if c == 83 then 32247333391 else
  if c == 84 then 4433514655 else
  if c == 85 then 15621211697 else
  if c == 86 then 4648912433 else
  if c == 87 then 11464787505 else
  if c == 88 then 18834663985 else
  if c == 89 then 4433521201 else
  if c == 90 then 33831389247 else
  if c == 48 then 15629733422 else
  if c == 49 then 15170933124 else
  if c == 50 then 33558693422 else
  if c == 51 then 32247317566 else
  if c == 52 then 2247698626 else
  if c == 53 then 32247857695 else
  if c == 54 then 15621636622 else
  if c == 55 then 8866891839 else
  if c == 56 then 15621113390 else
  if c == 57 then 15067498030 else
  if c == 46 then 6643777536 else
  if c == 44 then 4502585344 else
  if c == 58 then 207624384 else
  if c == 59 then 4502591680 else
  if c == 45 then 1015808 else
  if c == 95 then 33285996544 else
  if c == 61 then 32537600 else
  if c == 43 then 139432064 else
  if c == 40 then 2290360450 else
  if c == 41 then 8726317192 else
  if c == 91 then 15309480206 else
  if c == 93 then 15101659214 else
  if c == 123 then 3360428163 else
  if c == 125 then 25908318360 else
  if c == 47 then 17725261857 else
  if c == 92 then 1109533200 else
  if c == 42 then 720353952 else
  if c == 34 then 10570 else
  if c == 39 then 4228 else
  if c == 60 then 2290622594 else
  if c == 62 then 8726284424 else
  if c == 33 then 4299296900 else
  if c == 63 then 4299228718 else
  if c == 124 then 4433514628 else
  if c == 35 then 368389098 else
  if c == 37 then 224662361 else
  if c == 64 then 16667827758 else
  if c == 38 then 14584926796 else
  if c == 36 then 5307322852 else
  if c == 94 then 17732 else
  if c == 126 then 730112 else
  if c == 96 then 136 else
  if c == 32 then 0 else
  14495514670
partial def fillWords (p n c t : UInt64) : UInt64 :=
  if n == 0 then t else fillWords (p+8) (n-1) c (store64 p c t)
partial def fill (x y w h c t : UInt64) : UInt64 :=
  if h == 0 || x >= 640 || y >= 400 || w > 640-x then t else
    let t := fillWords (pixels+y*2560+x*4) (w/2) (color c) t
    fill x (y+1) w (h-1) c t
partial def glyphRow (x y bits col fg bg t : UInt64) : UInt64 :=
  if col == 6 || x+col >= 640 then t else
    let c := if col < 5 && ((bits >>> (4-col)) &&& 1) == 1 then fg else bg
    let t := Guest.store8 (pixels+y*2560+(x+col)*4) (c &&& 255) t
    let t := Guest.store8 (pixels+y*2560+(x+col)*4+1) ((c >>> 8) &&& 255) t
    let t := Guest.store8 (pixels+y*2560+(x+col)*4+2) ((c >>> 16) &&& 255) t
    glyphRow x y bits (col+1) fg bg t
partial def glyphRows (x y bits row fg bg t : UInt64) : UInt64 :=
  if row == 9 || y+row >= 400 then t else
    let t := glyphRow x (y+row) (if row < 7 then (bits >>> (row*5)) &&& 31 else 0) 0 fg bg t
    glyphRows x y bits (row+1) fg bg t
def char (x y c fg bg t : UInt64) : UInt64 := glyphRows x y (glyph c) 0 fg bg t
partial def text (p n x y fg bg t : UInt64) : UInt64 :=
  if n == 0 || x >= 634 then t else
    let t := char x y (load8 p t) fg bg t
    text (p+1) (n-1) (x+6) y fg bg t
partial def hex (v digits x y fg bg t : UInt64) : UInt64 :=
  if digits == 0 then t else
    let c := (v >>> ((digits-1)*4)) &&& 15
    let t := char x y (if c < 10 then c+48 else c+87) fg bg t
    hex v (digits-1) (x+6) y fg bg t
partial def upload (handle offset count trusted t : UInt64) : UInt64 :=
  if count == 0 then t else
    let n := if count > 1024 then 1024 else count
    let r := Guest.syscall (if trusted == 1 then 86 else 81) handle (pixels+offset) n offset t
    if r == error then error else upload handle (offset+n) (count-n) trusted r
end Guest.Raster
