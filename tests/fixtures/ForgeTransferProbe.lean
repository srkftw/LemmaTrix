import Guest.Forge
namespace Guest.ForgeTransferProbe
open Guest.LiveSDK
open Guest.ProjectSDK
open Guest.Forge

-- A focused SDK consumer for the slow assembly backend checks. It uses the
-- shipped Forge-v1 parser/transfer/import operations, with no editor or drawing
-- loop. Administrative RPCs select explicit capabilities and initiate SDK
-- actions; installation still uses the ordinary trusted Compositor prompt.
def failure (t : UInt64) : UInt64 := 64+store64 wire 1 (zero wire 8 t)
def pendingInstall : UInt64 := 0x6e2000
def metadataLegacy (t : UInt64) : UInt64 :=
  let t := packetHeader 2 0 (load64 (st+40) t) (load64 (st+48) t) (load64 (st+480) t) 0 offeredHead t
  let t := copy offeredName (packet+96) 64 t
  let t := copy logical (packet+160) 32 t
  sendPacket (load64 (st+8) t) 192 t
def advertiseLegacy (t : UInt64) : UInt64 :=
  let t := prepare t
  if load64 (st+136) t != 4 then t else metadataLegacy t
def dispatch (n t : UInt64) : UInt64 :=
  let op := load64 command t
  if op == 1 then configure (n-32) t else
  if op == 2 then 320+copy st (wire+64) 256 (zero wire 8 t) else
  if op == 56 then 192+copy (st+256) (wire+64) 128 (zero wire 8 t) else
  if n != 96 then failure t else
  if op == 3 then
    let root := load64 (command+8) t
    let r := describeRoot root t
    if r != 160 || status r != 0 then failure r else
      64+zero wire 8 (store64 (st+24) root r)
  else if op == 4 then 64+zero wire 8 (advertiseLegacy t)
  else if op == 5 then 64+zero wire 8 (discovery t)
  else if op == 6 then 64+zero wire 8 (requestFetch t)
  else if op == 7 then
    if load64 pendingInstall t != 0 then failure t else
      64+zero wire 8 (store64 pendingInstall 1 t)
  else failure t
def control (t : UInt64) : UInt64 :=
  let n := syscall 36 (self t) incoming 1024 0 t
  if n < 96 || n > 1024 then n else
    let token := load64 (incoming+8) n
    let r := if (load64 incoming n &&& 255) == 1 then dispatch n n else failure n
    reply token r r
def acceptLegacy (length t : UInt64) : UInt64 :=
  if !validFrame length t then message 9 t else
  let kind := load64 (received+16) t
  let transaction := load64 (received+24) t
  let a := load64 (received+32) t
  let b := load64 (received+40) t
  let c := load64 (received+48) t
  if kind == 1 then
    if length != 96 || load64 (st+32) t == 0 || load64 (st+80) t != 0 then message 9 t else metadataLegacy t
  else
  if kind == 2 then store64 (st+448) 0 (accept2 length transaction a b c t) else
  if kind == 3 then
    if a != 0 then message 9 t else accept3 length transaction a b c t
  else
  if kind == 8 then accept8 length transaction a b c t else
  if load64 (st+112) t == 0 || transaction != load64 (st+232) t || !equal (received+64) remoteHead 32 t then message 9 t else
  if kind == 4 then accept4 length transaction a b c t else
  if kind == 5 then accept5 length transaction a b c t else
  if kind == 6 then accept6 length transaction a b c t else
  if kind == 7 then accept7 length transaction a b c t else failImport t
def receiveLegacy (grant t : UInt64) : UInt64 :=
  if grant == 0 then t else
    let r := Guest.NetworkSDK.receive grant t
    if r < 64 || status r != 0 then r else
      let n := load64 (wire+16) r
      if n > 720 || r != n+64 then message 9 r else acceptLegacy n (copy (wire+64) received n r)
partial def loop (count t : UInt64) : UInt64 :=
  let t := control t
  let t := if load64 pendingInstall t == 0 then t else inspectInstall (store64 pendingInstall 0 t)
  let t := if count%32 != 0 || load64 st t == 0 then t else
    let t := store64 (st+400) count t
    let t := pollSend t
    let t := if load64 (st+176) t == 1 && load64 (st+80) t == 0 then requestFetch (store64 (st+176) 0 t) else t
    let t := receiveLegacy (load64 (st+8) t) t
    let t := receiveLegacy (load64 (st+16) t) t
    sender t
  loop (count+1) (syscall 9 0 0 0 0 t)
def main (initial : UInt64) : UInt64 := loop 0 (zero pendingInstall 1 (zero st 128 initial))
end Guest.ForgeTransferProbe
