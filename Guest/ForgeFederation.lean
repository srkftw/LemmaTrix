import Guest.ProjectSDK
import Guest.ProjectGraph
import Guest.RegistrySDK
import Guest.Raster
namespace Guest.ForgeFederation
open Guest.LiveSDK
open Guest.ProjectSDK
-- Private Forge memory; neither signer credentials nor imported authority.
-- state: required,localPhase,slot,sequence,sendPhase,localClass,localReason,
-- remotePhase,remoteClass,remoteReason,remoteSequence,wireSequence,metadataEpoch,
-- reserved,reserved,error; view flag128, expected policy136, federationID160.
def st : UInt64 := 0x6e2000
def localDescriptor : UInt64 := 0x6e2400
def remote : UInt64 := 0x6e2800
def equal (a b n t : UInt64) : Bool := Guest.ProjectGraph.equal a b n t
def enabled (t : UInt64) : Bool := load64 st t == 1
def localPhase (t : UInt64) : UInt64 := load64 (st+8) t
def remotePhase (t : UInt64) : UInt64 := load64 (st+56) t
def sendPhase (t : UInt64) : UInt64 := load64 (st+32) t
def ready (head t : UInt64) : Bool := localPhase t == 2 && equal (localDescriptor+320) head 32 t
def mayFetch (t : UInt64) : Bool := !enabled t || (remotePhase t == 2 && Guest.RegistrySDK.admitted (load64 (st+64) t))
def mayInstall (root t : UInt64) : Bool :=
  !enabled t || (remotePhase t == 2 && Guest.RegistrySDK.admitted (load64 (st+64) t) && equal (remote+320) root 32 t)
def expected (p root t : UInt64) : Bool :=
  load64 p t == 0x314d4441544c && load64 (p+8) t == 1 && load64 (p+48) t > 0 &&
  load64 (p+32) t == load64 (st+136) t && equal (p+288) (st+160) 32 t && equal (p+320) root 32 t
-- An explicitly offered seed root may carry the original verified federation
-- descriptor unchanged. This grants the seed no admission/signing authority.
def reuseRemote (head t : UInt64) : UInt64 :=
  if !enabled t || localPhase t == 1 ||
    !((remotePhase t == 2 || remotePhase t == 3) && load64 (st+72) t <= 6 && expected remote head t) then t else
    let t := copy remote localDescriptor 768 t
    let t := store64 (st+8) 2 t
    let t := store64 (st+24) (load64 (remote+48) t) t
    let t := store64 (st+40) (load64 (remote+16) t) t
    store64 (st+48) (load64 (remote+24) t) t
def configure (required policy identity t : UInt64) : UInt64 :=
  if required > 1 || (required == 1 && (policy < 1 || policy > 2 || Guest.ProjectGraph.allZero identity 32 t)) || localPhase t == 1 then error else
    let t := zero st 32 t
    let t := zero localDescriptor 96 t
    let t := zero remote 96 t
    let t := store64 st required t
    let t := store64 (st+136) policy t
    copy identity (st+160) 32 t

def begin (root head t : UInt64) : UInt64 :=
  if !enabled t || localPhase t == 1 then error else
    let service := Guest.RegistrySDK.endpoint t
    if service == error then error else
      let r := delegate root service 25 service
      if r != 160 || status r != 0 then error else
        let r := Guest.RegistrySDK.admit (result r) r
        if r != 576 || status r != 0 || !expected (wire+64) head r || load64 (wire+16) r >= 16 then error else
          let t := copy (wire+64) localDescriptor 512 r
          let t := store64 (st+8) 1 t
          let t := store64 (st+16) (load64 (wire+16) t) t
          let t := store64 (st+24) (load64 (wire+8) t) t
          let t := store64 (st+40) (load64 (localDescriptor+16) t) t
          store64 (st+48) (load64 (localDescriptor+24) t) t

def poll (head t : UInt64) : UInt64 :=
  if localPhase t == 2 && sendPhase t == 0 then
    let r := Guest.RegistrySDK.query (load64 (st+104) t) t
    if r != 832 || status r != 0 then store64 (st+104) 0 r else
      let t := store64 (st+104) (load64 (wire+24) r) r
      if !expected (wire+64) head t || load64 (wire+112) t <= load64 (st+24) t then t else
        let t := copy (wire+64) localDescriptor 768 t
        let t := store64 (st+24) (load64 (localDescriptor+48) t) t
        let t := store64 (st+40) (load64 (localDescriptor+16) t) t
        let t := store64 (st+48) (load64 (localDescriptor+24) t) t
        store64 (st+32) 1 t
  else if localPhase t != 1 then t else
    let r := Guest.RegistrySDK.inspect (load64 (st+16) t) t
    if r == 576 && status r == 0 && load64 (wire+8) r == 1 then r else
    if r != 832 || status r != 0 || load64 (wire+8) r != 2 ||
       !expected (wire+64) head r || load64 (wire+112) r != load64 (st+24) r then
      store64 (st+8) 3 (store64 (st+120) 1 r)
    else
      let t := copy (wire+64) localDescriptor 768 r
      let t := store64 (st+8) 2 t
      store64 (st+32) 1 t

-- A recovered Registry catalog contains signed metadata, not content caps.
-- Repeated explicit discovery advances the existing bounded SDK cursor; one
-- empty end wraps to the first page without claiming a global latest record.
def catalogName : UInt64 := 0x6e3100
partial def catalogHex (root i t : UInt64) : UInt64 :=
  if i == 16 then t else
    let byte := load8 (root+i/2) t
    let digit := if i%2 == 0 then byte >>> 4 else byte &&& 15
    catalogHex root (i+1) (store8 (catalogName+8+i) (if digit < 10 then digit+48 else digit+87) t)
def catalogEntry (cursor t : UInt64) : UInt64 :=
  let r := Guest.RegistrySDK.query cursor t
  if r != 832 || status r != 0 then error else
  if load64 (wire+24) r > 16 || !expected (wire+64) (wire+384) r ||
    Guest.ProjectGraph.allZero (wire+384) 32 r then error else
    let t := copy (wire+64) localDescriptor 768 r
    let t := store64 (st+368) (load64 (wire+24) t) t
    let t := store64 (st+8) 2 t
    let t := store64 (st+24) (load64 (localDescriptor+48) t) t
    let t := store64 (st+40) (load64 (localDescriptor+16) t) t
    let t := store64 (st+48) (load64 (localDescriptor+24) t) t
    let t := zero catalogName 8 t
    let t := store64 catalogName 3271706165590122851 t
    catalogHex (localDescriptor+320) 0 t
def catalog (t : UInt64) : UInt64 :=
  if !enabled t || localPhase t == 1 then error else
    let cursor := load64 (st+368) t
    let r := catalogEntry cursor t
    if r != error || cursor == 0 then r else catalogEntry 0 r

-- Recheck the public signed decision in the isolated verifier. This applies
-- its current monotonic/revocation knowledge and grants no peer authority.
def verifyRemote (root sequence t : UInt64) : UInt64 :=
  let r := Guest.RegistrySDK.verify remote root t
  if r != 832 || status r != 0 || !expected (wire+64) root r then
    store64 (st+56) 3 (store64 (st+72) 8 r)
  else
    let t := copy (wire+64) remote 768 r
    let t := store64 (st+64) (load64 (wire+8) t) t
    let t := store64 (st+72) (load64 (wire+16) t) t
    let t := store64 (st+80) sequence t
    store64 (st+56) (if Guest.RegistrySDK.admitted (load64 (st+64) t) then 2 else 3) t
def portable (root t : UInt64) : Bool :=
  enabled t && (remotePhase t == 2 || (remotePhase t == 3 && load64 (st+72) t <= 6)) && expected remote root t
-- Signed admission is public portable evidence. Only the exact same immutable
-- root, chosen federation and policy can reuse it after fresh peer enrollment.
-- Other metadata clears assembly; old grants/handles never appear here.
def metadata (root t : UInt64) : UInt64 :=
  let t := store64 (st+96) (load64 (st+96) t+1) t
  if portable root t then verifyRemote root (load64 (remote+48) t) t else
    zero (st+56) 5 (zero remote 96 t)

def decision (p root sequence t : UInt64) : UInt64 :=
  if !enabled t || !expected p root t || sequence != load64 (p+48) t then
    store64 (st+56) 3 (store64 (st+72) 7 t)
  else
    let t := copy p remote 512 t
    let t := store64 (st+88) sequence t
    let t := store64 (st+56) 1 t
    store64 (st+128) 1 t

def signature (p root sequence t : UInt64) : UInt64 :=
  if !enabled t || remotePhase t != 1 || sequence != load64 (st+88) t || !expected remote root t then
    store64 (st+56) 3 (store64 (st+72) 7 t)
  else
    verifyRemote root sequence (copy p (remote+512) 256 t)
def init (t : UInt64) : UInt64 := zero st 512 t

def inspect (t : UInt64) : UInt64 :=
  let t := zero wire 8 t
  let t := copy st (wire+64) 128 t
  960+copy remote (wire+192) 768 t
def inspectLocal (t : UInt64) : UInt64 :=
  let t := zero wire 8 t
  let t := store64 (wire+8) (localPhase t) t
  832+copy localDescriptor (wire+64) 768 t

def fingerprint (p x y t : UInt64) : UInt64 :=
  let t := Guest.Raster.hex (load64 p t) 16 x y 0xd8e6ed 0x101b25 t
  let t := Guest.Raster.hex (load64 (p+8) t) 16 (x+102) y 0xd8e6ed 0x101b25 t
  let t := Guest.Raster.hex (load64 (p+16) t) 16 (x+204) y 0xd8e6ed 0x101b25 t
  Guest.Raster.hex (load64 (p+24) t) 16 (x+306) y 0xd8e6ed 0x101b25 t
def label (id x y t : UInt64) : UInt64 :=
  if id == 0 then
    let t := store64 4276224 5283920084417660230 t
    let t := store64 4276232 6001412933993647695 t
    let t := store64 4276240 5053090597708974419 t
    let t := store64 4276248 5643667103477276721 t
    Guest.Raster.text 0x414000 32 x y 0x9fc6a5 0x101b25 t
  else if id == 1 then
    let t := store64 4276224 4919430815874570309 t
    let t := store64 4276232 6071224230123750944 t
    let t := store64 4276240 75080865304393 t
    Guest.Raster.text 0x414000 22 x y 0x9fc6a5 0x101b25 t
  else if id == 2 then
    let t := store64 4276224 3395812264564772688 t
    let t := store64 4276232 6148611195726811936 t
    let t := store64 4276240 4995689717088404818 t
    let t := store64 4276248 5283939837087330080 t
    let t := store64 4276256 4703255684041426766 t
    let t := store64 4276264 5132115 t
    Guest.Raster.text 0x414000 43 x y 0x9fc6a5 0x101b25 t
  else if id == 3 then
    let t := store64 4276224 4995371957961709637 t
    let t := store64 4276232 5917804974921958732 t
    let t := store64 4276240 5525327 t
    Guest.Raster.text 0x414000 19 x y 0x9fc6a5 0x101b25 t
  else if id == 4 then
    let t := store64 4276224 4992331761217328464 t
    let t := store64 4276232 6496478030268670034 t
    let t := store64 4276240 5638864406001439301 t
    let t := store64 4276248 6291333289803587667 t
    let t := store64 4276256 10574 t
    Guest.Raster.text 0x414000 34 x y 0x9fc6a5 0x101b25 t
  else if id == 5 then
    let t := store64 4276224 5125172531394072403 t
    let t := store64 4276232 5570745070011826514 t
    let t := store64 4276240 23729957600774477 t
    Guest.Raster.text 0x414000 23 x y 0x9fc6a5 0x101b25 t
  else if id == 6 then
    let t := store64 4276224 4990918871462008389 t
    let t := store64 4276232 5572159235322495776 t
    let t := store64 4276240 5525061 t
    Guest.Raster.text 0x414000 19 x y 0x9fc6a5 0x101b25 t
  else if id == 7 then
    let t := store64 4276224 4995709443909961042 t
    let t := store64 4276232 6004503674201710660 t
    let t := store64 4276240 5283934391169462048 t
    let t := store64 4276248 5279994828088689997 t
    let t := store64 4276256 17740 t
    Guest.Raster.text 0x414000 34 x y 0x9fc6a5 0x101b25 t
  else if id == 8 then
    let t := store64 4276224 5495048297971265862 t
    let t := store64 4276232 4993442310173250377 t
    let t := store64 4276240 5714876750694274115 t
    let t := store64 4276248 4991712650168646484 t
    let t := store64 4276256 4735828 t
    Guest.Raster.text 0x414000 35 x y 0x9fc6a5 0x101b25 t
  else if id == 9 then
    let t := store64 4276224 2325913809414474060 t
    let t := store64 4276232 6075160323089059652 t
    let t := store64 4276240 4996268051567493408 t
    let t := store64 4276248 4981065031057624096 t
    let t := store64 4276256 5642809484675073368 t
    Guest.Raster.text 0x414000 40 x y 0x9fc6a5 0x101b25 t
  else if id == 10 then
    let t := store64 4276224 5269287800923242830 t
    let t := store64 4276232 5917813800762102606 t
    let t := store64 4276240 2329281652000641349 t
    let t := store64 4276248 5928223938417344844 t
    let t := store64 4276256 3556896 t
    Guest.Raster.text 0x414000 35 x y 0x9fc6a5 0x101b25 t
  else if id == 11 then
    let t := store64 4276224 5566816515132835152 t
    let t := store64 4276232 6133978912060887877 t
    let t := store64 4276240 4919430884862612558 t
    let t := store64 4276248 362258191392 t
    Guest.Raster.text 0x414000 29 x y 0x9fc6a5 0x101b25 t
  else if id == 12 then
    let t := store64 4276224 6001412933993640262 t
    let t := store64 4276232 3550560795317193043 t
    let t := store64 4276240 6001411826230763569 t
    let t := store64 4276248 4848490377371466568 t
    let t := store64 4276256 3410160882767048537 t
    let t := store64 4276264 5851223 t
    Guest.Raster.text 0x414000 43 x y 0x9fc6a5 0x101b25 t
  else if id == 13 then
    let t := store64 4276224 5932740723593398611 t
    let t := store64 4276232 2325357422171070533 t
    let t := store64 4276240 5641131625435439152 t
    let t := store64 4276248 5640002207544785735 t
    let t := store64 4276256 2319952197020698948 t
    let t := store64 4276264 4919418734198801750 t
    let t := store64 4276272 4992879355923472443 t
    let t := store64 4276280 1145394243 t
    Guest.Raster.text 0x414000 60 x y 0x9fc6a5 0x101b25 t
  else if id == 14 then
    let t := store64 4276224 5927673078914162771 t
    let t := store64 4276232 5989874727140016713 t
    let t := store64 4276240 5931276186839566153 t
    let t := store64 4276248 5788568442332596815 t
    let t := store64 4276256 357645435204 t
    Guest.Raster.text 0x414000 37 x y 0x9fc6a5 0x101b25 t
  else if id == 15 then
    let t := store64 4276224 5999451469895770195 t
    let t := store64 4276232 5053103950560580163 t
    let t := store64 4276240 2326183236755398709 t
    let t := store64 4276248 2322526261014188117 t
    let t := store64 4276256 5715719182706816582 t
    let t := store64 4276264 17750 t
    Guest.Raster.text 0x414000 42 x y 0x9fc6a5 0x101b25 t
  else if id == 16 then
    let t := store64 4276224 5785245645447255379 t
    let t := store64 4276232 6133954508277893460 t
    let t := store64 4276240 6076235804391326800 t
    let t := store64 4276248 977622081 t
    Guest.Raster.text 0x414000 28 x y 0x9fc6a5 0x101b25 t
  else if id == 17 then
    let t := store64 4276224 5283920084417660230 t
    let t := store64 4276232 6001401943222668879 t
    let t := store64 4276240 6147771185369075529 t
    let t := store64 4276248 2329010957306909257 t
    let t := store64 4276256 4919430815874172242 t
    Guest.Raster.text 0x414000 40 x y 0x9fc6a5 0x101b25 t
  else t
def view (surface t : UInt64) : UInt64 :=
  let p := if remotePhase t == 0 && localPhase t > 0 then localDescriptor else remote
  let phase := if p == localDescriptor then localPhase t else remotePhase t
  let t := Guest.Raster.fill 0 0 640 352 0x101b25 t
  let t := label 0 10 8 t
  let t := label 1 10 28 t
  let t := fingerprint (st+160) 10 40 t
  let t := label 2 10 58 t
  let t := Guest.Raster.hex (load64 (st+136) t) 2 10 70 0xe9bc75 0x101b25 t
  let t := Guest.Raster.hex phase 2 70 70 0xe9bc75 0x101b25 t
  let t := Guest.Raster.hex (load64 (p+16) t) 2 130 70 0xe9bc75 0x101b25 t
  let t := Guest.Raster.hex (load64 (p+24) t) 2 190 70 0xe9bc75 0x101b25 t
  let t := label 3 10 88 t
  let t := fingerprint (p+320) 10 100 t
  let t := label 4 10 118 t
  let t := fingerprint (p+352) 10 130 t
  let t := label 5 10 148 t
  let t := fingerprint (p+160) 10 160 t
  let t := label 6 10 178 t
  let t := fingerprint (p+224) 10 190 t
  let t := label 7 10 208 t
  let t := Guest.Raster.hex (load64 (p+40) t) 16 10 220 0xe9bc75 0x101b25 t
  let t := Guest.Raster.hex (load64 (p+56) t) 2 130 220 0xe9bc75 0x101b25 t
  let t := label 13 10 238 t
  let t := label 8 10 260 t
  let t := label 9 10 280 t
  let t := label 10 10 300 t
  let t := label 11 10 320 t
  let t := store64 (0x6e0000+248) 0 t
  Guest.Raster.upload surface 0 901120 0 t
end Guest.ForgeFederation
