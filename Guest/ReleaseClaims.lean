import Guest.LiveSDK
import Guest.LiveMemory
namespace Guest.ReleaseClaims
-- Canonical bounded JSON is parsed structurally. No substring search can select
-- a nested/spoofed claim. Object keys are unique, sorted, unescaped ASCII; values
-- support JSON strings/escapes, numbers, arrays, objects, booleans and null.
-- This is the shipped metadata profile, not a general Unicode-key JSON editor.
def byte (p t : UInt64) : UInt64 := Guest.load8 p t
def equal (a b n t : UInt64) : Bool := Guest.LiveMemory.equal a b n t
def digit (c : UInt64) : Bool := c >= 48 && c <= 57
def hexDigit (c : UInt64) : Bool := digit c || (c >= 97 && c <= 102)
partial def fourHex (p end_ n t : UInt64) : UInt64 :=
  if n == 0 then p else
  if p >= end_ || !hexDigit (byte p t) then 0 else fourHex (p+1) end_ (n-1) t
def continuation (p end_ t : UInt64) : Bool :=
  p < end_ && byte p t >= 128 && byte p t <= 191
def utf8End (p end_ t : UInt64) : UInt64 :=
  let c := byte p t
  if c >= 194 && c <= 223 && continuation (p+1) end_ t then p+2 else
  if p+2 < end_ && continuation (p+2) end_ t &&
    ((c == 224 && byte (p+1) t >= 160 && byte (p+1) t <= 191) ||
     (c >= 225 && c <= 236 && continuation (p+1) end_ t) ||
     (c == 237 && byte (p+1) t >= 128 && byte (p+1) t <= 159) ||
     (c >= 238 && c <= 239 && continuation (p+1) end_ t)) then p+3 else
  if p+3 < end_ && continuation (p+2) end_ t && continuation (p+3) end_ t &&
    ((c == 240 && byte (p+1) t >= 144 && byte (p+1) t <= 191) ||
     (c >= 241 && c <= 243 && continuation (p+1) end_ t) ||
     (c == 244 && byte (p+1) t >= 128 && byte (p+1) t <= 143)) then p+4 else 0
partial def hexValue (p n value t : UInt64) : UInt64 :=
  if n == 0 then value else
  let c := byte p t
  hexValue (p+1) (n-1) (value*16+(if c <= 57 then c-48 else c-87)) t
partial def stringRest (p end_ t : UInt64) : UInt64 :=
  if p >= end_ then 0 else
  let c := byte p t
  if c == 34 then p+1 else
  if c < 32 then 0 else
  if c >= 128 then
    let next := utf8End p end_ t
    if next == 0 then 0 else stringRest next end_ t else
  if c != 92 then stringRest (p+1) end_ t else
  if p+1 >= end_ then 0 else
  let escape := byte (p+1) t
  if escape == 34 || escape == 92 || escape == 98 || escape == 102 || escape == 110 || escape == 114 || escape == 116 then stringRest (p+2) end_ t else
  if escape != 117 then 0 else
  let next := fourHex (p+2) end_ 4 t
  if next == 0 then 0 else
  let scalar := hexValue (p+2) 4 0 t
  if scalar >= 0xdc00 && scalar <= 0xdfff then 0 else
  if scalar < 0xd800 || scalar > 0xdbff then stringRest next end_ t else
  if next+6 > end_ || byte next t != 92 || byte (next+1) t != 117 || fourHex (next+2) end_ 4 t == 0 then 0 else
  let low := hexValue (next+2) 4 0 t
  if low < 0xdc00 || low > 0xdfff then 0 else stringRest (next+6) end_ t
def stringEnd (p end_ t : UInt64) : UInt64 :=
  if p >= end_ || byte p t != 34 then 0 else stringRest (p+1) end_ t
partial def asciiKey (p n t : UInt64) : Bool :=
  if n == 0 then true else
  let c := byte p t
  c >= 32 && c < 127 && c != 92 && c != 34 && asciiKey (p+1) (n-1) t
partial def lessKey (a an b bn t : UInt64) : Bool :=
  if an == 0 then bn != 0 else if bn == 0 then false else
  let x := byte a t
  let y := byte b t
  if x != y then x < y else lessKey (a+1) (an-1) (b+1) (bn-1) t
partial def digitsEnd (p end_ t : UInt64) : UInt64 :=
  if p < end_ && digit (byte p t) then digitsEnd (p+1) end_ t else p
def numberEnd (p end_ t : UInt64) : UInt64 :=
  let p := if p < end_ && byte p t == 45 then p+1 else p
  if p >= end_ || !digit (byte p t) then 0 else
  let q := if byte p t == 48 then p+1 else digitsEnd p end_ t
  let q := if q < end_ && byte q t == 46 then
    let n := digitsEnd (q+1) end_ t
    if n == q+1 then 0 else n else q
  if q == 0 then 0 else
  if q < end_ && byte q t == 101 then
    let r := if q+1 < end_ && (byte (q+1) t == 43 || byte (q+1) t == 45) then q+2 else q+1
    let n := digitsEnd r end_ t
    if n == r then 0 else n else q
def literal (p end_ word count t : UInt64) : UInt64 :=
  if count > end_-p then 0 else
  let mask := if count == 8 then 0xffffffffffffffff else ((1 : UInt64) <<< (count*8))-1
  if (Guest.load64 p t &&& mask) == word then p+count else 0
mutual
  partial def valueEnd (p end_ depth t : UInt64) : UInt64 :=
    if depth == 0 || p >= end_ then 0 else
    let c := byte p t
    if c == 34 then stringEnd p end_ t else
    if c == 123 then objectRest (p+1) end_ (depth-1) 0 0 t else
    if c == 91 then arrayRest (p+1) end_ (depth-1) t else
    if c == 110 then literal p end_ 1819047278 4 t else
    if c == 116 then literal p end_ 1702195828 4 t else
    if c == 102 then literal p end_ 435728179558 5 t else numberEnd p end_ t
  partial def objectRest (p end_ depth previous previousBytes t : UInt64) : UInt64 :=
    if p >= end_ then 0 else
    if byte p t == 125 then p+1 else
    let keyEnd := stringEnd p end_ t
    if keyEnd == 0 || !asciiKey (p+1) (keyEnd-p-2) t ||
      (previous != 0 && !lessKey previous previousBytes (p+1) (keyEnd-p-2) t) || keyEnd >= end_ || byte keyEnd t != 58 then 0 else
    let next := valueEnd (keyEnd+1) end_ depth t
    if next == 0 || next >= end_ then 0 else
    if byte next t == 125 then next+1 else
    if byte next t != 44 || next+1 >= end_ || byte (next+1) t != 34 then 0 else
    objectRest (next+1) end_ depth (p+1) (keyEnd-p-2) t
  partial def arrayRest (p end_ depth t : UInt64) : UInt64 :=
    if p >= end_ then 0 else
    if byte p t == 93 then p+1 else
    let next := valueEnd p end_ depth t
    if next == 0 || next >= end_ then 0 else
    if byte next t == 93 then next+1 else
    if byte next t != 44 || next+1 >= end_ || byte (next+1) t == 93 then 0 else
    arrayRest (next+1) end_ depth t
end

partial def wordBytes (p n word t : UInt64) : Bool :=
  if n == 0 then true else
  if byte p t != word%256 then false else wordBytes (p+1) (n-1) (word/256) t
@[noinline] def keyMatch (p n count a b c t : UInt64) : Bool :=
  if n != count then false else
  let first := if count > 8 then 8 else count
  let second := if count > 16 then 8 else if count > 8 then count-8 else 0
  if !wordBytes p first a t then false else
  if !wordBytes (p+8) second b t then false else
  wordBytes (p+16) (if count > 16 then count-16 else 0) c t
@[noinline] def keyTag (p n t : UInt64) : UInt64 :=
  if keyMatch p n 6 126943805008242 0 0 t then 1 else
  if keyMatch p n 16 7305808869231650162 7308332183992823903 0 t then 2 else
  if keyMatch p n 5 499917218150 0 0 t then 3 else
  if keyMatch p n 7 32760384526971504 0 0 t then 4 else
  if keyMatch p n 7 31084746137298294 0 0 t then 5 else
  if keyMatch p n 20 7307217292035782000 7021786293846105970 1852795252 t then 6 else
  if keyMatch p n 16 8751735924676977769 7453010364987436383 0 t then 7 else
  if keyMatch p n 6 111520527180659 0 0 t then 8 else
  if keyMatch p n 16 7307217292035782000 7235419251344629618 0 t then 9 else
  if keyMatch p n 14 8386093285581682032 110403735416681 0 t then 10 else
  if keyMatch p n 18 6875977810685947756 6878231818130125424 25705 t then 11 else
  if keyMatch p n 3 7038067 0 0 t then 12 else
  if keyMatch p n 12 7954874742130894180 1936025955 0 t then 13 else
  if keyMatch p n 6 107122480669555 0 0 t then 14 else
  if keyMatch p n 7 28550371649741165 0 0 t then 15 else
  if keyMatch p n 7 28549272340166002 0 0 t then 16 else
  if keyMatch p n 6 128017497219440 0 0 t then 17 else
  if keyMatch p n 6 111533478864242 0 0 t then 18 else
  if keyMatch p n 6 111516500389741 0 0 t then 19 else
  if keyMatch p n 5 521611275877 0 0 t then 20 else
  if keyMatch p n 9 7593465222953660276 110 0 t then 21 else
  if keyMatch p n 4 1701667182 0 0 t then 22 else
  if keyMatch p n 7 32497657166461029 0 0 t then 23 else
  if keyMatch p n 7 28555890632386924 0 0 t then 24 else
  if keyMatch p n 7 30243645579093358 0 0 t then 25 else
  if keyMatch p n 11 7310594991874794864 6644590 0 t then 26 else
  if keyMatch p n 7 28548172593721968 0 0 t then 27 else
  if keyMatch p n 10 7953759798970774128 25955 0 t then 28 else
  if keyMatch p n 10 6874027268401554802 25705 0 t then 29 else
  if keyMatch p n 10 6878243912925736803 25705 0 t then 30 else
  if keyMatch p n 12 7596562542729650531 1936025972 0 t then 31 else
  if keyMatch p n 11 7598257976942686054 7235943 0 t then 32 else
  if keyMatch p n 11 8241417320907763571 7630703 0 t then 33 else
  0
partial def findField (p end_ tag t : UInt64) : UInt64 :=
  if p >= end_ || byte p t != 34 then 0 else
  let keyEnd := stringEnd p end_ t
  if keyEnd == 0 || keyEnd >= end_ || byte keyEnd t != 58 then 0 else
  let start := keyEnd+1
  if keyTag (p+1) (keyEnd-p-2) t == tag then start else
  let next := valueEnd start end_ 32 t
  if next == 0 || next >= end_ || byte next t != 44 then 0 else findField (next+1) end_ tag t
def field (obj end_ tag t : UInt64) : UInt64 :=
  if obj == 0 || obj >= end_ || byte obj t != 123 then 0 else findField (obj+1) end_ tag t
partial def uintEquals (p end_ value expected t : UInt64) : Bool :=
  if p == end_ then value == expected else
  if p > end_ || !digit (byte p t) then false else
  let c := byte p t-48
  value <= (0xffffffffffffffff-c)/10 && uintEquals (p+1) end_ (value*10+c) expected t
def numberEquals (p end_ expected t : UInt64) : Bool :=
  p != 0 && p < end_ && digit (byte p t) &&
    let n := numberEnd p end_ t
    n != 0 && uintEquals p n 0 expected t
def valueEquals (a ae b be t : UInt64) : Bool :=
  if a == 0 || b == 0 then false else
  let an := valueEnd a ae 32 t
  let bn := valueEnd b be 32 t
  an != 0 && bn != 0 && an-a == bn-b && equal a b (an-a) t
partial def hexEquals (p digest index t : UInt64) : Bool :=
  if index == 64 then byte p t == 34 else
  let b := byte (digest+index/2) t
  let nibble := if index%2 == 0 then b/16 else b%16
  let c := if nibble < 10 then 48+nibble else 87+nibble
  byte p t == c && hexEquals (p+1) digest (index+1) t
def digestEquals (p end_ digest t : UInt64) : Bool :=
  p != 0 && p+66 <= end_ && byte p t == 34 && hexEquals (p+1) digest 0 t
def stringEquals (p end_ source bytes t : UInt64) : Bool :=
  p != 0 && p+bytes+2 <= end_ && byte p t == 34 && byte (p+bytes+1) t == 34 && equal (p+1) source bytes t
def versionEquals (p end_ h t : UInt64) : Bool :=
  if p == 0 || p >= end_ || byte p t != 34 then false else
  let a := p+1
  let b := digitsEnd a end_ t
  let c := digitsEnd (b+1) end_ t
  let d := digitsEnd (c+1) end_ t
  a < b && b < end_ && byte b t == 46 && b+1 < c && c < end_ && byte c t == 46 && c+1 < d && d < end_ && byte d t == 34 &&
    uintEquals a b 0 (Guest.load64 (h+72) t) t && uintEquals (b+1) c 0 (Guest.load64 (h+80) t) t && uintEquals (c+1) d 0 (Guest.load64 (h+88) t) t &&
    (b-a == 1 || byte a t != 48) && (c-b == 2 || byte (b+1) t != 48) && (d-c == 2 || byte (c+1) t != 48)

@[noinline] def textMatch (p end_ count a b c t : UInt64) : Bool :=
  if p == 0 || p >= end_ || count > end_-p then false else keyMatch p count count a b c t

def nativeFacet (p end_ t : UInt64) : Bool :=
  textMatch p end_ 19 4712302780409269794 7598805550879240304 2256495 t

def sourceFacet (p end_ t : UInt64) : Bool :=
  textMatch p end_ 21 8101813437696656418 7598824096732702061 147981558118 t

def machine (p end_ t : UInt64) : Bool :=
  textMatch p end_ 11 3275917122451295266 2241142 0 t

def structuredRuntime (p end_ t : UInt64) : Bool :=
  textMatch p end_ 18 8462954687813143586 8515572857302250595 8755 t

def scalarRuntime (p end_ t : UInt64) : Bool :=
  textMatch p end_ 19 3257288169956330530 3275089324280276581 2241142 t

def sourceRuntime (p end_ t : UInt64) : Bool :=
  textMatch p end_ 13 3271130047602193186 148066037359 0 t

def check (h manifest bytes lock lockBytes logical t : UInt64) : Bool :=
  if bytes == 0 || bytes > 49152 || lockBytes == 0 || lockBytes > 49152 then false else
  let end_ := manifest+bytes
  let lockEnd := lock+lockBytes-(if byte (lock+lockBytes-1) t == 10 then 1 else 0)
  if valueEnd manifest end_ 32 t != end_ || byte manifest t != 123 || valueEnd lock lockEnd 32 t != lockEnd || byte lock t != 123 then false else
  let native := Guest.load64 (h+384) t == 1
  let mapping := field manifest end_ 7 t
  let recipe := field manifest end_ 18 t
  let parent := field manifest end_ 17 t
  let sdk := field lock lockEnd 12 t
  let dependencies := field lock lockEnd 13 t
  if !(sdk != 0 && byte sdk t == 123 && dependencies != 0 && byte dependencies t == 91) then false else
  if !(numberEquals (field lock lockEnd 14 t) lockEnd 1 t) then false else
  if !(machine (field lock lockEnd 15 t) lockEnd t) then false else
  if !(numberEquals (field lock lockEnd 27 t) lockEnd (Guest.load64 (h+400) t) t) then false else
  if !(valueEquals (field manifest end_ 3 t) end_ (field lock lockEnd 3 t) lockEnd t) then false else
  if !(numberEquals (field manifest end_ 14 t) end_ 4 t) then false else
  if !(numberEquals (field manifest end_ 1 t) end_ (Guest.load64 (h+64) t) t) then false else
  if !(numberEquals (field manifest end_ 2 t) end_ (Guest.load64 (h+400) t) t) then false else
  if !(numberEquals (field manifest end_ 6 t) end_ (Guest.load64 (h+392) t) t) then false else
  if !((if native then nativeFacet (field manifest end_ 3 t) end_ t else sourceFacet (field manifest end_ 3 t) end_ t)) then false else
  if !(stringEquals (field manifest end_ 4 t) end_ (h+432) (Guest.load64 (h+424) t) t) then false else
  if !(versionEquals (field manifest end_ 5 t) end_ h t && machine (field manifest end_ 15 t) end_ t) then false else
  if !((if !native then sourceRuntime (field manifest end_ 16 t) end_ t else if Guest.load64 (h+400) t == 2 then structuredRuntime (field manifest end_ 16 t) end_ t else scalarRuntime (field manifest end_ 16 t) end_ t)) then false else
  if !(numberEquals (field mapping end_ 8 t) end_ 4 t) then false else
  if !(digestEquals (field mapping end_ 9 t) end_ (h+96) t) then false else
  if !(digestEquals (field mapping end_ 10 t) end_ (h+128) t) then false else
  if !(digestEquals (field mapping end_ 11 t) end_ logical t) then false else
  if !((if Guest.load64 (h+288) t == 0 && Guest.load64 (h+296) t == 0 && Guest.load64 (h+304) t == 0 && Guest.load64 (h+312) t == 0 then parent != 0 && literal parent end_ 1819047278 4 t == parent+4 else digestEquals parent end_ (h+288) t)) then false else
  if !(valueEquals (field manifest end_ 12 t) end_ (field lock lockEnd 12 t) lockEnd t) then false else
  if !(valueEquals (field manifest end_ 13 t) end_ (field lock lockEnd 13 t) lockEnd t) then false else
  if !(valueEquals (field recipe end_ 18 t) end_ (field lock lockEnd 18 t) lockEnd t) then false else
  if !(valueEquals (field recipe end_ 19 t) end_ (field lock lockEnd 19 t) lockEnd t) then false else
  if !(valueEquals (field recipe end_ 20 t) end_ (field lock lockEnd 20 t) lockEnd t) then false else
  valueEquals (field recipe end_ 21 t) end_ (field lock lockEnd 21 t) lockEnd t
end Guest.ReleaseClaims
