import Guest.ContentVault
namespace Guest.ServerContent
open Guest.LiveSDK
-- Explicit operator state, separate from personal Objects-domain keys/policy.
-- This frontend alone can select the shared engine's purpose2 backend.
def st : UInt64 := 0x7a0000
def grant (i : UInt64) : UInt64 := 0x7a1000+i*128
def response (code value t : UInt64) : UInt64 :=
  let t := header code value 0 0 0 0 0 t
  64+t
partial def freeGrant (i t : UInt64) : UInt64 :=
  if i == 4 then error else if load64 (grant i) t == 0 then i else freeGrant (i+1) t
def authorized (caller h t : UInt64) : UInt64 :=
  let i := (h &&& 255)-1
  if h == 0 || i >= 4 || load64 (grant i) t != h || load64 (grant i+8) t != caller then error else i
def permit (rights length t : UInt64) : UInt64 :=
  let target := load64 (command+16) t
  let quota := load64 (command+24) t
  let archive := load64 (command+48) t
  let actual := syscall 34 target 0 0 0 t
  if (rights &&& 0x100000000) == 0 || length != 128 || actual == error ||
    ((actual &&& 2048) == 0 && (actual &&& 0x100000000) == 0) ||
    quota == 0 || quota > ContentFormat.maxBytes || archive >= 4 || load64 (command+32) t != 2 ||
    load64 (command+40) t != 3 || ContentFormat.allZero (command+64) 32 actual || ContentFormat.allZero (command+96) 32 actual then response 1 0 actual else
    let capacity := syscall 64 2 0 0 0 actual
    if capacity == error || capacity < 62552+archive*29464 then response 6 0 capacity else
    let mounted := syscall 65 0 chunk 512 2 capacity
    if mounted != 0 || load64 chunk mounted != 0x31524f5453544c || load64 (chunk+8) mounted != 1 ||
      load64 (chunk+16) mounted != 33088 || !ContentFormat.allZero (chunk+24) 488 mounted then response 6 0 mounted else
    let slot := freeGrant 0 mounted
    let generation := load64 (st+8) mounted+1
    if slot == error || generation > 0xffffff || generation == 0 then response 4 0 mounted else
    let service := self mounted
    let epoch := ((service >>> 32)+((service >>> 8) &&& 0xffffff)) &&& 0xffffffff
    let handle := (epoch <<< 32) ||| (generation <<< 8) ||| (slot+1)
    let g := grant slot
    let t := zero g 16 service
    let t := store64 (st+8) generation t
    let t := store64 g handle t
    let t := store64 (g+8) target t
    let t := store64 (g+16) archive t
    let t := store64 (g+24) quota t
    let t := copy (command+64) (g+32) 64 t
    response 0 handle t
def selectBackend (caller h t : UInt64) : UInt64 :=
  let slot := authorized caller h t
  if slot == error || ContentVault.active t then error else
    let g := grant slot
    let b := ContentVault.backend
    let t := zero b 16 t
    let t := store64 b 2 t
    let t := store64 (b+8) h t
    let t := store64 (b+16) caller t
    let t := copy (g+32) (b+24) 64 t
    let t := store64 (b+88) (load64 (g+24) t) t
    let t := store64 (b+104) (load64 (g+16) t) t
    store64 (b+112) g t
def sameOperation (caller h t : UInt64) : Bool :=
  ContentVault.isServer t && load64 (ContentVault.backend+8) t == h && load64 (ContentVault.backend+16) t == caller
def dispatch (caller rights length t : UInt64) : UInt64 :=
  let op := load64 command t
  let h := load64 (command+8) t
  if length < 64 || length > 1024 || load64 (command+56) t != 1 then response 2 0 t else
  if op == 250 then permit rights length t else
  if ((rights &&& 2048) == 0 && (rights &&& 0x100000000) == 0) then response 1 0 t else
  if op == 256 then
    if (rights &&& 0x100000000) == 0 then response 1 0 t else
    let slot := (h &&& 255)-1
    if slot >= 4 || load64 (grant slot) t != h then response 1 0 t else response 0 h (zero (grant slot) 16 t)
  else if authorized caller h t == error then response 1 0 t else
  if length != 64 then response 2 0 t else
  -- A delegated handle belongs to Vault, so verify its exact issuing caller
  -- before this frontend reads or closes it. Handles are never secret proofs.
  let content := load64 (command+16) t
  let checked := if op == 251 then Guest.ContentSDK.checkDelegation content caller t else t
  if op == 251 && (checked == error || status checked != 0) then response 1 0 checked else
  let selectedMetadata := load64 (command+24) checked
  let checked := if op == 251 && selectedMetadata != 0 then LiveSDK.checkDelegation selectedMetadata caller checked else checked
  if op == 251 && selectedMetadata != 0 && (checked == error || status checked != 0) then response 1 0 checked else
  let t := checked
  if op == 252 then
    if !sameOperation caller h t then response 6 0 t else ContentVault.response 0 t
  else if op == 254 then
    if !sameOperation caller h t then response 1 0 t else ContentVault.response 0 (ContentVault.finish 5 0 t)
  else if ContentVault.active t then
    if op == 251 then ContentVault.rejectRetain 7 content t else response 7 0 t
  else
    let selected := selectBackend caller h t
    if selected == error then response 1 0 selected else
    if op == 251 then ContentVault.startRetain caller (load64 (command+16) selected) (load64 (command+32) selected) (load64 (command+24) selected) selected else
    if op == 253 then ContentVault.startRecover caller (load64 (command+16) selected) (load64 (command+24) selected) 0 (ContentVault.backend+56) selected else
    if op == 255 then ContentVault.inventory selected else response 2 0 selected
def clear (t : UInt64) : UInt64 := zero st 1024 t
end Guest.ServerContent
