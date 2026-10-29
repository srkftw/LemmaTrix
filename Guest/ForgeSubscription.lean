import Guest.ProjectGraph
namespace Guest.ForgeSubscription
open Guest.LiveSDK
def st : UInt64 := 0x6e1a00
-- logical,publication,federation,peer,desiredRoot; no capabilities or approval.
def ids : UInt64 := 0x6e1800
def enabled (t : UInt64) : Bool := load64 st t == 1
def status (t : UInt64) : UInt64 := load64 (st+32) t
def accepts (old incoming : UInt64) (sameIdentity sameRoot : Bool) : Bool :=
  sameIdentity && (incoming > old || (incoming == old && sameRoot))
theorem other_identity_rejected (old incoming : UInt64) (sameRoot : Bool) : accepts old incoming false sameRoot = false := by simp [accepts]
def disable (t : UInt64) : UInt64 := zero st 8 (zero ids 20 t)
def toggle (descriptor peer clock t : UInt64) : UInt64 :=
  if enabled t then disable t else
    if load64 (descriptor+16) t != 2 || Guest.ProjectGraph.allZero (descriptor+64) 32 t || Guest.ProjectGraph.allZero (descriptor+96) 32 t then error else
      let t := copy (descriptor+64) ids 64 t
      let t := copy (descriptor+288) (ids+64) 32 t
      let t := copy peer (ids+96) 32 t
      let t := copy (descriptor+320) (ids+128) 32 t
      let t := store64 st 1 t
      let t := store64 (st+8) (clock+16000) t
      let t := store64 (st+16) 16000 t
      let t := store64 (st+24) (load64 (descriptor+48) t) t
      store64 (st+32) 1 t
def due (clock t : UInt64) : Bool := enabled t && clock >= load64 (st+8) t
def queried (clock t : UInt64) : UInt64 :=
  let delay := load64 (st+16) t
  let t := store64 (st+8) (clock+delay) t
  let t := store64 (st+16) (if delay < 128000 then delay*2 else 128000) t
  store64 (st+40) (load64 (st+40) t+1) t
-- Called only after the separate Registry compartment verifies the signature.
def observe (descriptor peer clock t : UInt64) : UInt64 :=
  if !enabled t then t else
    let identity := Guest.ProjectGraph.equal (descriptor+64) ids 64 t &&
      Guest.ProjectGraph.equal (descriptor+288) (ids+64) 32 t && Guest.ProjectGraph.equal peer (ids+96) 32 t
    let sameRoot := Guest.ProjectGraph.equal (descriptor+320) (ids+128) 32 t
    let sequence := load64 (descriptor+48) t
    if !accepts (load64 (st+24) t) sequence identity sameRoot then store64 (st+32) 3 t else
    if sequence == load64 (st+24) t then t else
      let t := copy (descriptor+320) (ids+128) 32 t
      let t := store64 (st+24) sequence t
      let t := store64 (st+16) 16000 t
      let t := store64 (st+8) (clock+16000) t
      store64 (st+32) (if load64 (descriptor+16) t == 3 then 4 else if sameRoot then 1 else 2) t
def inspect (t : UInt64) : UInt64 :=
  let t := zero wire 8 t
  let t := copy st (wire+64) 64 t
  288+copy ids (wire+128) 160 t
end Guest.ForgeSubscription
