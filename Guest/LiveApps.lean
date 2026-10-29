import Guest.LiveSDK
namespace Guest.LiveApps
open Guest.LiveSDK

def fail (status t : UInt64) : UInt64 :=
  let t := zero wire 8 t
  64+store64 wire status t

def allowed (rights needed : UInt64) : Bool := (rights &&& needed) == needed
partial def transformBytes (p n mode t : UInt64) : UInt64 :=
  if n == 0 then t else
    let c := load8 p t
    let transformed := if c >= 97 && c <= 122 then
      if mode == 1 then c-32 else (c-97+13)%26+97
      else c
    transformBytes (p+1) (n-1) mode (store8 p transformed t)

partial def transformChunks (source target offset total mode t : UInt64) : UInt64 :=
  if offset == total then t else
    let count := if total-offset > 512 then 512 else total-offset
    let result := read source offset count t
    if result == error || status result != 0 then result else
      let got := load64 (wire+8) result
      if got != count then fail 2 result else
        let t := copy (wire+64) chunk count result
        let t := transformBytes chunk count mode t
        let result := append target offset chunk count t
        if result == error || status result != 0 then result else
          transformChunks source target (offset+count) total mode result

def abortWith (stage reason t : UInt64) : UInt64 := fail reason (Guest.LiveSDK.abortStage stage t)

def finishStage (caller callerRights staged t : UInt64) : UInt64 :=
  let result := stageDigest staged t
  if result == error then abortWith staged 7 result else
  if status result != 0 then abortWith staged (status result) result else
    let t := copy (wire+64) digest 32 result
    let result := commit staged digest t
    if result == error then abortWith staged 7 result else
    if status result != 0 then abortWith staged (status result) result else
      let ownRights := load64 (wire+48) result
      share staged caller (ownRights &&& callerRights &&& 127) result

def transformObject (caller callerRights source mode t : UInt64) : UInt64 :=
  if mode != 1 && mode != 2 then fail 2 t else
    let result := metadata source t
    if result == error then fail 7 result else
    if status result != 0 then result else
      let length := load64 (wire+16) result
      let kind := load64 (wire+32) result
      let sourceRights := load64 (wire+48) result
      if !allowed sourceRights 13 then fail 1 result else
        let result := stage length kind source result
        if result == error then fail 7 result else
        if status result != 0 then result else
          let staged := load64 (wire+8) result
          let result := transformChunks source staged 0 length mode result
          if result == error then abortWith staged 7 result else
          if status result != 0 then abortWith staged (status result) result else
            finishStage caller callerRights staged result

partial def transferRange (source target start count offset t : UInt64) : UInt64 :=
  if count == 0 then t else
    let n := if count > 512 then 512 else count
    let result := read source start n t
    if result == error || status result != 0 then result else
      if load64 (wire+8) result != n then fail 2 result else
        let t := copy (wire+64) chunk n result
        let result := append target offset chunk n t
        if result == error || status result != 0 then result else
          transferRange source target (start+n) (count-n) (offset+n) result

def patchObject (caller callerRights source offset deleted inserted t : UInt64) : UInt64 :=
  let result := metadata source t
  if result == error then fail 7 result else
  if status result != 0 then result else
    let total := load64 (wire+16) result
    let kind := load64 (wire+32) result
    let sourceRights := load64 (wire+48) result
    if !allowed sourceRights 13 then fail 1 result else
    if offset > total || deleted > total-offset || inserted > 512 || total-deleted+inserted > 65536 then fail 2 result else
      let result := stage (total-deleted+inserted) kind source result
      if result == error then fail 7 result else
      if status result != 0 then result else
        let staged := load64 (wire+8) result
        let result := transferRange source staged 0 offset 0 result
        if result == error then abortWith staged 7 result else
        if status result != 0 then abortWith staged (status result) result else
          let result := if inserted == 0 then result else append staged offset (command+64) inserted result
          if result == error then abortWith staged 7 result else
          if status result != 0 then abortWith staged (status result) result else
            let result := transferRange source staged (offset+deleted) (total-offset-deleted) (offset+inserted) result
            if result == error then abortWith staged 7 result else
            if status result != 0 then abortWith staged (status result) result else
              finishStage caller callerRights staged result

-- Counts are computed from streamed bytes, not supplied metadata or fixture text.
-- Packed state: 24-bit word count, 24-bit LF count, bit48 inside a word.
partial def countBytes (p n acc t : UInt64) : UInt64 :=
  if n == 0 then acc else
    let c := load8 p t
    let whitespace := c == 32 || c == 9 || c == 10 || c == 13
    let words := acc &&& 0xffffff
    let lines := (acc >>> 24) &&& 0xffffff
    let inside := (acc >>> 48) &&& 1
    let words := if !whitespace && inside == 0 then words+1 else words
    let lines := if c == 10 then lines+1 else lines
    let next := words ||| (lines <<< 24) ||| ((if whitespace then (0 : UInt64) else 1) <<< 48)
    countBytes (p+1) (n-1) next t

partial def countChunks (h offset total acc t : UInt64) : UInt64 :=
  if offset == total then acc else
    let count := if total-offset > 512 then 512 else total-offset
    let result := read h offset count t
    if result == error || status result != 0 then error else
      if load64 (wire+8) result != count then error else
        let next := countBytes (wire+64) count acc result
        countChunks h (offset+count) total next result

def countObject (h t : UInt64) : UInt64 :=
  let result := metadata h t
  if result == error then fail 7 result else
  if status result != 0 then result else
    let length := load64 (wire+16) result
    let kind := load64 (wire+32) result
    let t := copy (wire+64) digest 32 result
    let counts := countChunks h 0 length 0 t
    if counts == error then fail 3 counts else
      let t := zero wire 8 counts
      let t := store64 (wire+8) (counts &&& 0xffffff) t
      let t := store64 (wire+16) length t
      let t := store64 (wire+24) ((counts >>> 24) &&& 0xffffff) t
      let t := store64 (wire+32) kind t
      96+copy digest (wire+64) 32 t

def dispatch (kind caller callerRights length t : UInt64) : UInt64 :=
  if length < 64 || length > 576 || load64 (command+56) t != 1 then fail 2 t else
    let op := load64 command t
    let h := load64 (command+8) t
    if op == 20 then
      if kind == 1 then transformObject caller callerRights h (load64 (command+16) t) t else fail 1 t
    else if op == 23 then
      if kind == 1 then patchObject caller callerRights h (load64 (command+16) t) (load64 (command+24) t) (length-64) t else fail 1 t
    else if op == 21 then
      if kind == 3 then countObject h t else fail 1 t
    else if op == 22 then
      if kind == 2 then metadata h t else fail 1 t
    else if op >= 1 && op <= 14 then
      let t := copy command wire length t
      let result := call length t
      if result == error then fail 7 result else result
    else fail 7 t

partial def serve (kind endpoint t : UInt64) : UInt64 :=
  let length := receive endpoint t
  if length == error then serve kind endpoint length else
    let caller := load64 incoming length
    let replyToken := load64 (incoming+8) length
    let rights := load64 (incoming+16) length
    let abi := load64 (incoming+24) length
    let result := if length >= 96 && abi == 2 && allowed rights 0x100000000 then
      dispatch kind caller rights (length-32) length else fail 1 length
    let t := reply replyToken result result
    serve kind endpoint t

def workbenchMain (initial : UInt64) : UInt64 := serve 1 (self initial) initial
def inspectorMain (initial : UInt64) : UInt64 := serve 2 (self initial) initial
def workerMain (initial : UInt64) : UInt64 := serve 3 (self initial) initial
end Guest.LiveApps
