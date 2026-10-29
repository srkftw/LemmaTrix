import Guest.RemoteBuild
namespace Guest.RemoteIngest
open Guest.LiveSDK
-- SourceUpload-v1 carries no capability, signing authority or execution approval.
-- Client phases1metadata,2upload,3await-ready,4request; provider10fetch,
-- 11importing,12ready-reply,13ready. Phase0 retains the last nonce for replay
-- rejection until explicit relationship reconfiguration or process restart.
def st : UInt64 := 0x752000
def nonce : UInt64 := st+64
def root : UInt64 := st+96
def project : UInt64 := st+128
def compiler : UInt64 := st+160
def phase (t : UInt64) : UInt64 := load64 st t
def init (t : UInt64) : UInt64 := zero st 32 t
def stop (code t : UInt64) : UInt64 := store64 (st+40) code (store64 st 0 t)
def reject (code t : UInt64) : UInt64 := store64 (st+48) (load64 (st+48) t+1) (store64 (st+40) code t)
def roleAccepted (forge remote incoming : UInt64) : Bool :=
  (forge == 3 && remote == 2 && incoming == 2) || (forge == 4 && remote == 3 && incoming == 3)
theorem verifier_request_cannot_enter_builder : roleAccepted 3 2 3 = false := by decide
def bounds (role nodes bytes : UInt64) : Bool :=
  (role == 2 || role == 3) && nodes > 0 && nodes <= 24 && bytes > 0 && bytes <= 1048576
def valid (p length t : UInt64) : Bool :=
  length == 192 && bounds (load64 (p+32) t) (load64 (p+40) t) (load64 (p+48) t) &&
  load64 (p+56) t == 1 && load64 (p+24) t == load64 (p+96) t &&
  !Guest.ProjectGraph.allZero (p+64) 32 t && !Guest.ProjectGraph.allZero (p+96) 32 t &&
  !Guest.ProjectGraph.allZero (p+128) 32 t && !Guest.ProjectGraph.allZero (p+160) 32 t
def equal (a b n t : UInt64) : Bool := Guest.ProjectGraph.equal a b n t
def exact (p t : UInt64) : Bool :=
  load64 (p+32) t == load64 (st+8) t && load64 (p+40) t == load64 (st+24) t &&
  load64 (p+48) t == load64 (st+32) t && equal (p+64) root 32 t &&
  equal (p+96) nonce 32 t && equal (p+128) project 64 t
def client (job role nodes bytes clock t : UInt64) : UInt64 :=
  if phase t != 0 || !bounds role nodes bytes || Guest.ProjectGraph.allZero job 32 t then error else
    let t := init t
    let t := store64 (st+8) role t
    let t := store64 (st+16) (clock+1000000) t
    let t := store64 (st+24) nodes t
    let t := store64 (st+32) bytes t
    let t := copy job nonce 32 t
    let t := copy Guest.RemoteBuild.source root 32 t
    let t := copy Guest.RemoteBuild.project project 32 t
    store64 st 1 (copy Guest.RemoteBuild.compiler compiler 32 t)
def acceptUpload (p length forgeRole metadata logical clock t : UInt64) : UInt64 :=
  let remoteState := Guest.RemoteBuild.state t
  if !valid p length t || !roleAccepted forgeRole (load64 Guest.RemoteBuild.st t) (load64 (p+32) t) ||
     !equal (p+160) Guest.RemoteBuild.compiler 32 t || !equal (p+64) metadata 32 t || !equal (p+128) logical 32 t then reject 1 t else
  if phase t >= 10 && exact p t then
    if phase t == 13 then store64 st 12 t else t
  else if (phase t != 0 && !(phase t == 13 && remoteState >= 3 && remoteState <= 6)) ||
      remoteState == 1 || remoteState == 2 || remoteState == 7 then reject 3 t else
  if equal (p+96) nonce 32 t then reject 4 t else
    let t := init t
    let t := store64 (st+8) (load64 (p+32) t) t
    let t := store64 (st+16) (clock+1000000) t
    let t := store64 (st+24) (load64 (p+40) t) t
    let t := store64 (st+32) (load64 (p+48) t) t
    let t := copy (p+64) root 32 t
    let t := copy (p+96) nonce 32 t
    let t := copy (p+128) project 64 t
    store64 st 10 t
def acceptReady (p length t : UInt64) : UInt64 :=
  if phase t != 3 || !valid p length t || !exact p t then reject 2 t else store64 st 4 t
def expired (clock t : UInt64) : Bool := phase t != 0 && clock >= load64 (st+16) t
def inspect (t : UInt64) : UInt64 := 320+copy st (wire+64) 256 (zero wire 8 t)
end Guest.RemoteIngest
