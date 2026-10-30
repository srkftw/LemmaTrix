import Guest.ProjectSDK
import Guest.Raster
import Guest.Keyboard
import Guest.RegistrySDK
import Guest.ConsumerFormat
import Guest.ContentSDK
import Guest.ContentFormat
import Guest.LibraryPeerSDK
import Guest.WaitSDK
import Guest.Wave
import Guest.GameSDK
import Guest.LibraryFetchSDK
import Guest.LibraryCollections
import Guest.PrivateRecords
namespace Guest.Library
open Guest.LiveSDK Guest.Raster

def st : UInt64 := 0x6e0000
def row (i : UInt64) : UInt64 := 0x700000+i*2048
def peer (i : UInt64) : UInt64 := 0x710000+i*1024
def job (i : UInt64) : UInt64 := 0x720000+i*4096
def metadata : UInt64 := 0x714000
def work : UInt64 := 0x716000
def hashScratch : UInt64 := 0x6e4000
def hashOut : UInt64 := 0x6e5000
def bg : UInt64 := 0x11212e
def fg : UInt64 := 0xd8e6ed
def eq (a b n t : UInt64) : Bool := Guest.ContentFormat.equal a b n t
def hash (p n out t : UInt64) : UInt64 := Guest.ServiceHash.sha256At hashScratch p n out t
def dirty (t : UInt64) : UInt64 := store64 (st+24) 1 t
def notice (id t : UInt64) : UInt64 := dirty (store64 (st+176) id t)
@[noinline] partial def jobFailure (j r : UInt64) : UInt64 :=
  let code := if r == error then error else status r
  let t := store64 (j+96) code r
  let t := if r != 64 then t else store64 (j+120) (load64 (wire+16) t) t
  notice 42 (store64 j 12 t)
def selected (t : UInt64) : UInt64 := row (load64 (st+8) t)
def consumer (i : UInt64) : UInt64 := row i+1024
@[noinline] partial def label0b (id x y color t : UInt64) : UInt64 :=
  if id == 8 then
    let t := store64 (0x414000+0) 8511930191083104592 t
    let t := store64 (0x414000+8) 4279946221065432175 t
    let t := store64 (0x414000+16) 7310874250626224672 t
    let t := store64 (0x414000+24) 8242553123633329267 t
    let t := store64 (0x414000+32) 7309940760746684537 t
    let t := store64 (0x414000+40) 31084746153813364 t
    text 0x414000 47 x y color bg t
  else if id == 9 then
    let t := store64 (0x414000+0) 2334397779128968001 t
    let t := store64 (0x414000+8) 7813572869537491060 t
    let t := store64 (0x414000+16) 4570713170542552428 t
    let t := store64 (0x414000+24) 6998684278654387488 t
    let t := store64 (0x414000+32) 3395825678387671152 t
    let t := store64 (0x414000+40) 7953747407132640544 t
    let t := store64 (0x414000+48) 7103843 t
    text 0x414000 51 x y color bg t
  else if id == 10 then
    let t := store64 (0x414000+0) 7234318597473988673 t
    let t := store64 (0x414000+8) 6998720695968822048 t
    let t := store64 (0x414000+16) 8243105079639434350 t
    let t := store64 (0x414000+24) 7286889542587085921 t
    let t := store64 (0x414000+32) 7234316402863268718 t
    let t := store64 (0x414000+40) 8029109356424684064 t
    let t := store64 (0x414000+48) 3368292 t
    text 0x414000 51 x y color bg t
  else if id == 11 then
    let t := store64 (0x414000+0) 8820707168001226049 t
    let t := store64 (0x414000+8) 4049946916415366245 t
    let t := store64 (0x414000+16) 8026947690928742459 t
    let t := store64 (0x414000+24) 8029968104952963131 t
    let t := store64 (0x414000+32) 8392847272196663660 t
    let t := store64 (0x414000+40) 32767015939481701 t
    text 0x414000 47 x y color bg t
  else if id == 12 then
    let t := store64 (0x414000+0) 7308332243887091542 t
    let t := store64 (0x414000+8) 8223692119759287584 t
    let t := store64 (0x414000+16) 4279657070797616229 t
    let t := store64 (0x414000+24) 7234298802019983904 t
    let t := store64 (0x414000+32) 8315168227309482528 t
    let t := store64 (0x414000+40) 7021788157845594400 t
    let t := store64 (0x414000+48) 7566446 t
    text 0x414000 51 x y color bg t
  else if id == 13 then
    let t := store64 (0x414000+0) 7597131870759712070 t
    let t := store64 (0x414000+8) 7147063527858990703 t
    let t := store64 (0x414000+16) 8439871481763296620 t
    let t := store64 (0x414000+24) 7089066488320385390 t
    let t := store64 (0x414000+32) 25964 t
    text 0x414000 34 x y color bg t
  else if id == 14 then
    let t := store64 (0x414000+0) 4707459271918634317 t
    let t := store64 (0x414000+8) 383532289824 t
    text 0x414000 13 x y color bg t
  else if id == 15 then
    let t := store64 (0x414000+0) 5497841028315627856 t
    let t := store64 (0x414000+8) 4705216255664136281 t
    let t := store64 (0x414000+16) 4541506 t
    text 0x414000 19 x y color bg t
  else t
partial def label0 (id x y color t : UInt64) : UInt64 :=
  if id == 0 then
    let t := store64 (0x414000+0) 5281631927840621900 t
    let t := store64 (0x414000+8) 383632101954 t
    text 0x414000 13 x y color bg t
  else if id == 1 then
    let t := store64 (0x414000+0) 7809651189923983686 t
    let t := store64 (0x414000+8) 7300370396264556399 t
    let t := store64 (0x414000+16) 5341325534346572389 t
    let t := store64 (0x414000+24) 5125153851744412271 t
    let t := store64 (0x414000+32) 2320838288168283489 t
    let t := store64 (0x414000+40) 8315168162700881744 t
    let t := store64 (0x414000+48) 7022349122379597344 t
    let t := store64 (0x414000+56) 1684369001 t
    text 0x414000 60 x y color bg t
  else if id == 2 then
    let t := store64 (0x414000+0) 7142819395816352083 t
    let t := store64 (0x414000+8) 8079523098445570412 t
    let t := store64 (0x414000+16) 7521891478339674476 t
    let t := store64 (0x414000+24) 8386653723097260901 t
    let t := store64 (0x414000+32) 21747584627138933 t
    text 0x414000 39 x y color bg t
  else if id == 3 then
    let t := store64 (0x414000+0) 2329241047831486529 t
    let t := store64 (0x414000+8) 2338053702334443341 t
    let t := store64 (0x414000+16) 8746950815728541767 t
    let t := store64 (0x414000+24) 5269339542357296160 t
    let t := store64 (0x414000+32) 5495873826357596192 t
    let t := store64 (0x414000+40) 28559193596580384 t
    text 0x414000 47 x y color bg t
  else if id == 4 then
    let t := store64 (0x414000+0) 8315178071121600593 t
    let t := store64 (0x414000+8) 8746391042724995176 t
    let t := store64 (0x414000+16) 4990904625304466021 t
    let t := store64 (0x414000+24) 2328959663001587744 t
    let t := store64 (0x414000+32) 6134024091364255058 t
    let t := store64 (0x414000+40) 8243124913752592928 t
    text 0x414000 48 x y color bg t
  else if id == 5 then
    let t := store64 (0x414000+0) 7308892947869626190 t
    let t := store64 (0x414000+8) 7887337240561655908 t
    let t := store64 (0x414000+16) 8245918730096243301 t
    let t := store64 (0x414000+24) 8462580707610227556 t
    let t := store64 (0x414000+32) 7310222300147184229 t
    let t := store64 (0x414000+40) 8223683306485671276 t
    let t := store64 (0x414000+48) 3348833642404734821 t
    text 0x414000 56 x y color bg t
  else if id == 6 then
    let t := store64 (0x414000+0) 8751185064972739922 t
    let t := store64 (0x414000+8) 7234299921576173616 t
    let t := store64 (0x414000+16) 7594230310270415219 t
    let t := store64 (0x414000+24) 7236832841296995698 t
    let t := store64 (0x414000+32) 8511930239636041584 t
    let t := store64 (0x414000+40) 111516181951337 t
    text 0x414000 46 x y color bg t
  else if id == 7 then
    let t := store64 (0x414000+0) 7301214825104944945 t
    let t := store64 (0x414000+8) 8030604370248951148 t
    let t := store64 (0x414000+16) 4981016863571208566 t
    let t := store64 (0x414000+24) 7957652872685245518 t
    let t := store64 (0x414000+32) 2330648130927945070 t
    let t := store64 (0x414000+40) 7286935756435449170 t
    let t := store64 (0x414000+48) 7954884629262987886 t
    let t := store64 (0x414000+56) 116 t
    text 0x414000 57 x y color bg t
  else label0b id x y color t
partial def label1 (id x y color t : UInt64) : UInt64 :=
  if id == 16 then
    let t := store64 (0x414000+0) 5713977594995623250 t
    let t := store64 (0x414000+8) 383532155203 t
    text 0x414000 13 x y color bg t
  else if id == 17 then
    let t := store64 (0x414000+0) 4919424244507755858 t
    text 0x414000 8 x y color bg t
  else if id == 18 then
    let t := store64 (0x414000+0) 75064541528400 t
    text 0x414000 6 x y color bg t
  else if id == 19 then
    let t := store64 (0x414000+0) 3395789183460655430 t
    let t := store64 (0x414000+8) 4994009628745813792 t
    text 0x414000 16 x y color bg t
  else if id == 20 then
    let t := store64 (0x414000+0) 4993449947212693827 t
    let t := store64 (0x414000+8) 68 t
    text 0x414000 9 x y color bg t
  else if id == 21 then
    let t := store64 (0x414000+0) 2325913809413816663 t
    let t := store64 (0x414000+8) 5931328949892304710 t
    let t := store64 (0x414000+16) 5845724132091713103 t
    let t := store64 (0x414000+24) 1096044373 t
    text 0x414000 28 x y color bg t
  else if id == 22 then
    let t := store64 (0x414000+0) 431197807681 t
    text 0x414000 5 x y color bg t
  else if id == 25 then
    let t := store64 (0x414000+0) 495623371106 t
    text 0x414000 5 x y color bg t
  else if id == 26 then
    let t := store64 (0x414000+0) 8243105097092919920 t
    text 0x414000 8 x y color bg t
  else if id == 27 then
    let t := store64 (0x414000+0) 2336927755367179365 t
    let t := store64 (0x414000+8) 121424956188018 t
    text 0x414000 14 x y color bg t
  else if id == 28 then
    let t := store64 (0x414000+0) 2340029477534397777 t
    let t := store64 (0x414000+8) 7234314139196417380 t
    let t := store64 (0x414000+16) 7306086968195293243 t
    let t := store64 (0x414000+24) 8316850424063926386 t
    let t := store64 (0x414000+32) 2336349463790182688 t
    let t := store64 (0x414000+40) 495623371106 t
    text 0x414000 45 x y color bg t
  else if id == 29 then
    let t := store64 (0x414000+0) 7234316346692625778 t
    let t := store64 (0x414000+8) 8386104319403237434 t
    let t := store64 (0x414000+16) 7310308001891052591 t
    let t := store64 (0x414000+24) 435476720943 t
    text 0x414000 29 x y color bg t
  else if id == 30 then
    let t := store64 (0x414000+0) 7234316346692625778 t
    let t := store64 (0x414000+8) 7142820559936692282 t
    let t := store64 (0x414000+16) 113723912776037 t
    text 0x414000 22 x y color bg t
  else if id == 31 then
    let t := store64 (0x414000+0) 7234316346692625778 t
    let t := store64 (0x414000+8) 8243107278869241914 t
    let t := store64 (0x414000+16) 8243122730785072498 t
    let t := store64 (0x414000+24) 7598814351195139941 t
    let t := store64 (0x414000+32) 8243107283108654703 t
    let t := store64 (0x414000+40) 25701 t
    text 0x414000 42 x y color bg t
  else t
partial def label2 (id x y color t : UInt64) : UInt64 :=
  if id == 32 then
    let t := store64 (0x414000+0) 7234316346692625778 t
    let t := store64 (0x414000+8) 7307218417350680634 t
    let t := store64 (0x414000+16) 7162249995383677042 t
    let t := store64 (0x414000+24) 1852795252 t
    text 0x414000 28 x y color bg t
  else if id == 34 then
    let t := store64 (0x414000+0) 7307199746975080527 t
    let t := store64 (0x414000+8) 8387186985527156850 t
    let t := store64 (0x414000+16) 7022364637025757283 t
    let t := store64 (0x414000+24) 2973054484276079724 t
    let t := store64 (0x414000+32) 2334392246434023968 t
    let t := store64 (0x414000+40) 5413453627300585549 t
    let t := store64 (0x414000+48) 2327270727593579296 t
    let t := store64 (0x414000+56) 1684107084 t
    text 0x414000 60 x y color bg t
  else if id == 35 then
    let t := store64 (0x414000+0) 8028074750291829825 t
    let t := store64 (0x414000+8) 8243107283012427886 t
    let t := store64 (0x414000+16) 7286944522513555571 t
    let t := store64 (0x414000+24) 7957695015493526904 t
    let t := store64 (0x414000+32) 7022923206234235168 t
    let t := store64 (0x414000+40) 108 t
    text 0x414000 41 x y color bg t
  else if id == 36 then
    let t := store64 (0x414000+0) 7234318597473988673 t
    let t := store64 (0x414000+8) 4285565824861696032 t
    let t := store64 (0x414000+16) 7958740646438595104 t
    let t := store64 (0x414000+24) 8367816129496969313 t
    let t := store64 (0x414000+32) 7954877705875973480 t
    let t := store64 (0x414000+40) 31084746152964709 t
    text 0x414000 47 x y color bg t
  else if id == 37 then
    let t := store64 (0x414000+0) 8243105097092919888 t
    let t := store64 (0x414000+8) 7308895159564267296 t
    let t := store64 (0x414000+16) 8386658447326912570 t
    let t := store64 (0x414000+24) 7954879164785504049 t
    let t := store64 (0x414000+32) 8751185004989535264 t
    text 0x414000 40 x y color bg t
  else if id == 38 then
    let t := store64 (0x414000+0) 7308332243887091542 t
    let t := store64 (0x414000+8) 8391735975095138080 t
    let t := store64 (0x414000+16) 8246214480173621536 t
    let t := store64 (0x414000+24) 7164775246990767727 t
    let t := store64 (0x414000+32) 8511913682638240114 t
    let t := store64 (0x414000+40) 1953264993 t
    text 0x414000 44 x y color bg t
  else if id == 39 then
    let t := store64 (0x414000+0) 6061921335340450126 t
    let t := store64 (0x414000+8) 4692825876278236498 t
    let t := store64 (0x414000+16) 2327306946397491280 t
    let t := store64 (0x414000+24) 4919428642889614674 t
    text 0x414000 32 x y color bg t
  else if id == 40 then
    let t := store64 (0x414000+0) 7526470944280309582 t
    let t := store64 (0x414000+8) 2334102031740531488 t
    let t := store64 (0x414000+16) 2334956331019233644 t
    let t := store64 (0x414000+24) 2338328528881218657 t
    let t := store64 (0x414000+32) 125823003817315 t
    text 0x414000 38 x y color bg t
  else if id == 41 then
    let t := store64 (0x414000+0) 8028075781016806739 t
    let t := store64 (0x414000+8) 8029390865575714926 t
    let t := store64 (0x414000+16) 8749487341609905184 t
    let t := store64 (0x414000+24) 7089066488320385312 t
    let t := store64 (0x414000+32) 7310589519812650348 t
    let t := store64 (0x414000+40) 29806 t
    text 0x414000 42 x y color bg t
  else if id == 42 then
    let t := store64 (0x414000+0) 8388361569363586633 t
    let t := store64 (0x414000+8) 7020393216920792185 t
    let t := store64 (0x414000+16) 5567381664649126004 t
    let t := store64 (0x414000+24) 7166460029768920352 t
    let t := store64 (0x414000+32) 104 t
    text 0x414000 33 x y color bg t
  else if id == 43 then
    let t := store64 (0x414000+0) 7598258067103182669 t
    let t := store64 (0x414000+8) 4285575741986334574 t
    let t := store64 (0x414000+16) 8462654443613023776 t
    let t := store64 (0x414000+24) 2336927755367183209 t
    let t := store64 (0x414000+32) 500068086375 t
    text 0x414000 37 x y color bg t
  else if id == 44 then
    let t := store64 (0x414000+0) 2334102057476973892 t
    let t := store64 (0x414000+8) 7309940795038199660 t
    let t := store64 (0x414000+16) 4279936346685072742 t
    let t := store64 (0x414000+24) 7142834788879331104 t
    let t := store64 (0x414000+32) 8241904473059455087 t
    let t := store64 (0x414000+40) 7306640014106239077 t
    let t := store64 (0x414000+48) 1684370531 t
    text 0x414000 52 x y color bg t
  else if id == 45 then
    let t := store64 (0x414000+0) 7310595043397758549 t
    let t := store64 (0x414000+8) 7017841271895826532 t
    let t := store64 (0x414000+16) 3826036 t
    text 0x414000 19 x y color bg t
  else t
partial def label3 (id x y color t : UInt64) : UInt64 :=
  if id == 49 then
    let t := store64 (0x414000+0) 16440324979254611 t
    text 0x414000 7 x y color bg t
  else if id == 50 then
    let t := store64 (0x414000+0) 5498704166163337038 t
    let t := store64 (0x414000+8) 362090417484 t
    text 0x414000 13 x y color bg t
  else if id == 51 then
    let t := store64 (0x414000+0) 5283934322285630785 t
    let t := store64 (0x414000+8) 293220925763 t
    text 0x414000 13 x y color bg t
  else if id == 52 then
    let t := store64 (0x414000+0) 2325350859325982287 t
    let t := store64 (0x414000+8) 4847366672178421807 t
    let t := store64 (0x414000+16) 1196312916 t
    text 0x414000 20 x y color bg t
  else if id == 54 then
    let t := store64 (0x414000+0) 7598807758542761795 t
    let t := store64 (0x414000+8) 7741536462551674479 t
    let t := store64 (0x414000+16) 7599372962075665509 t
    let t := store64 (0x414000+24) 8079584675319805797 t
    let t := store64 (0x414000+32) 521358896239 t
    text 0x414000 37 x y color bg t
  else if id == 58 then
    let t := store64 (0x414000+0) 8103230749690118992 t
    let t := store64 (0x414000+8) 7019813714331202677 t
    let t := store64 (0x414000+16) 2338621054691337575 t
    let t := store64 (0x414000+24) 7597131072125560162 t
    let t := store64 (0x414000+32) 8295740938855147374 t
    let t := store64 (0x414000+40) 28259048229268581 t
    text 0x414000 47 x y color bg t
  else if id == 61 then
    let t := store64 (0x414000+0) 8387235364514193747 t
    let t := store64 (0x414000+8) 7935463968216477285 t
    let t := store64 (0x414000+16) 8099006088107812197 t
    let t := store64 (0x414000+24) 8097789225105191521 t
    let t := store64 (0x414000+32) 119165854642800 t
    text 0x414000 38 x y color bg t
  else t
partial def label4 (id x y color t : UInt64) : UInt64 :=
  if id == 66 then
    let t := store64 (0x414000+0) 2334957443097059651 t
    let t := store64 (0x414000+8) 8243124913753516388 t
    let t := store64 (0x414000+16) 8030604370148663417 t
    let t := store64 (0x414000+24) 495857267303 t
    text 0x414000 29 x y color bg t
  else if id == 69 then
    let t := store64 (0x414000+0) 8079569209299136339 t
    let t := store64 (0x414000+8) 7521891508369845359 t
    let t := store64 (0x414000+16) 8223637122450943585 t
    let t := store64 (0x414000+24) 2333181779129235045 t
    let t := store64 (0x414000+32) 8026013118912361062 t
    let t := store64 (0x414000+40) 8243593258494881397 t
    let t := store64 (0x414000+48) 7630433 t
    text 0x414000 51 x y color bg t
  else if id == 70 then
    let t := store64 (0x414000+0) 4707459271363940173 t
    let t := store64 (0x414000+8) 8606172383467085882 t
    let t := store64 (0x414000+16) 8386658447326912622 t
    let t := store64 (0x414000+24) 2338042707299344428 t
    let t := store64 (0x414000+32) 8306080462789504876 t
    let t := store64 (0x414000+40) 7810758454475432035 t
    text 0x414000 48 x y color bg t
  else if id == 71 then
    let t := store64 (0x414000+0) 5641130483175736129 t
    let t := store64 (0x414000+8) 71 t
    text 0x414000 9 x y color bg t
  else if id == 72 then
    let t := store64 (0x414000+0) 5283920024355750230 t
    let t := store64 (0x414000+8) 18254 t
    text 0x414000 10 x y color bg t
  else if id == 74 then
    let t := store64 (0x414000+0) 7955997369270673474 t
    let t := store64 (0x414000+8) 5629535154363003680 t
    let t := store64 (0x414000+16) 8243124913752592928 t
    let t := store64 (0x414000+24) 5773650342438859552 t
    let t := store64 (0x414000+32) 7310838769399055151 t
    let t := store64 (0x414000+40) 8247338242305713525 t
    let t := store64 (0x414000+48) 7564399 t
    text 0x414000 51 x y color bg t
  else t
def label (id x y color t : UInt64) : UInt64 :=
  if id < 16 then label0 id x y color t else
  if id < 32 then label1 id x y color t else
  if id < 48 then label2 id x y color t else
  if id < 64 then label3 id x y color t else
  label4 id x y color t

@[noinline] def current (descriptor expected t : UInt64) : UInt64 :=
  let r := Guest.RegistrySDK.current descriptor expected t
  if r == 64 && status r == 2 then Guest.RegistrySDK.verify descriptor expected r else r
def nextId (t : UInt64) : UInt64 := store64 (st+184) (load64 (st+184) t+1) t
-- Retry only the already configured endpoint while an approved caller needs
-- it. A connected Noise handshake is never reset. Ten seconds exceeds the
-- opaque adapter's five-second connect deadline; this is a bounded retry,
-- not provider selection or renewal of collection/service terms.
def availablePeer (slot t : UInt64) : UInt64 :=
  let p := peer slot
  let r := Guest.NetworkSDK.inspectPeer slot t
  if r != 64 || status r != 0 then r else
  if result r == 3 then 64+store64 (p+104) 0 r else
  if result r != 0 || (load64 (wire+24) r &&& 3) == 3 then r else
  let now := Guest.WaitSDK.now r
  if load64 (p+104) now == 0 then store64 (p+104) (now+1000) now else
  if now < load64 (p+104) now then now else
    let t := store64 (p+104) (now+1000) now
    Guest.NetworkSDK.inspectPeer slot (Guest.NetworkSDK.openPeer slot t)
-- A grant is made only for a separately verified selected enrollment and the
-- immutable federation/manifest root. No local capability is sent to the peer.
def ensureGrant (slot root t : UInt64) : UInt64 :=
  let p := peer slot
  if load64 p t != 0 && eq (p+768) root 32 t then t else
  let r := availablePeer slot t
  if r != 64 || status r != 0 || result r != 3 then notice 37 (store64 p 0 r) else
  let r := Guest.NetworkSDK.callPeer slot 64 (header 15 0 0 0 0 0 0 r)
  if r != 576 || status r != 0 then notice 37 r else
  let t := copy (wire+64) (p+128) 512 r
  let kind := load64 (p+144) t
  if kind != (if slot == 0 then 5 else 6) then notice 29 t else
  let t := copy (p+224) work 32 t
  let t := hash (p+128) 512 (work+32) t
  let t := copy root (work+64) 32 t
  let t := if load64 p t == 0 then t else Guest.NetworkSDK.callPeer slot 64 (header 8 (load64 p t) 0 0 0 0 0 t)
  let budget := if slot == 0 then 16777216 else load64 (root-632) t
  let wanted := if budget <= 8388608 then 16777216 else budget+budget/2+65536
  let limit := load64 (p+176) t
  if slot != 0 && limit < budget then notice 21 (store64 p 0 t) else
  let r := Guest.LibraryPeerSDK.grant slot work (if slot == 0 then 1 else load64 root t ||| 1) (if wanted < limit then wanted else limit) 100000 t
  let t := store64 (st+544) r r
  let t := store64 (st+552) (if r == error then error else status r) t
  let t := store64 (st+560) slot t
  if r != 64 || status r != 0 then notice 37 t else
    dirty (copy root (p+768) 32 (store64 p (result r) t))
def issue (slot ji operation h a b initial : UInt64) : UInt64 :=
  let p := peer slot
  if load64 (p+16) initial != 0 then initial else
  let root := if slot == 0 then st+256 else job ji+512+192
  let t := ensureGrant slot root initial
  if load64 p t == 0 then t else
  let t := nextId t
  let id := load64 (st+184) t
  let r := Guest.LibraryPeerSDK.request slot (load64 p t) id operation h a b t
  let t := store64 (st+544) r r
  let t := store64 (st+552) (if r == error then error else status r) t
  let t := store64 (st+560) operation t
  if r != 64 || status r != 0 then
    if r == 64 && status r == 4 then t else
    let t := Guest.NetworkSDK.revokePeer slot (load64 p t) t
    notice 37 (store64 p 0 t)
  else
  let t := store64 (p+8) id t
  let t := store64 (p+16) operation t
  let t := store64 (p+24) (Guest.WaitSDK.now t+2000) t
  let t := store64 (p+32) (ji+1) t
  let t := if slot == 0 then t else store64 (p+80) (load64 (job ji+80) t) t
  store64 (p+40) (result r) t
partial def findEdition (id i t : UInt64) : UInt64 :=
  if i == load64 (st+16) t then error else
  if eq (consumer i+160) id 32 t then i else findEdition id (i+1) t
@[noinline] def metadataAdmission (t : UInt64) : UInt64 :=
  let r := Guest.RegistrySDK.current metadata (metadata+320) t
  if (r == 64 && (status r == 6 || status r == 2)) ||
    (r == 832 && status r == 3 && load64 (metadata+48) r > load64 (wire+112) r) then
    Guest.RegistrySDK.verify metadata (metadata+320) r
  else r
def acceptMetadata (t : UInt64) : UInt64 :=
  let classification := load64 (metadata+16) t
  if !Guest.RegistrySDK.consumerAdmitted classification || !Guest.ConsumerFormat.valid (metadata+768) t then notice 29 t else
  let t := hash (metadata+768) 768 hashOut t
  if !eq hashOut (metadata+400) 32 t then notice 29 t else
  let r := metadataAdmission t
  if r != 832 || status r != 0 || !Guest.RegistrySDK.consumerAdmitted (result r) then notice 29 r else
  let old := findEdition (metadata+768+160) 0 r
  let i := if old == error then load64 (st+16) r else old
  if i >= 16 then notice 21 r else
  -- A signed edition identifier is publisher-supplied, not a global mutable
  -- name. Admission refreshes may replace only the descriptor for the exact
  -- same signed consumer; private references remain bound to those bytes.
  if old != error && !eq (consumer old) (metadata+768) 768 r then notice 29 r else
  if old != error && load64 (row i+256+48) r >= load64 (metadata+48) r then r else
  let t := if old == error then zero (row i) 256 r else r
  let t := copy metadata (row i+256) 1536 t
  let t := store64 (row i) 1 t
  let t := if old == error then store64 (st+16) (i+1) t else t
  notice 14 t
@[noinline] def collectionFor (i t : UInt64) : UInt64 :=
  Guest.LibraryCollections.find (consumer i+96) (row i+256+288) 0 t
@[noinline] def jobPolicy (j t : UInt64) : UInt64 :=
  let i := load64 (j+400) t-1
  if i >= Guest.LibraryCollections.count then 0 else Guest.LibraryCollections.record i
@[noinline] def policyLive (j t : UInt64) : Bool :=
  let p := jobPolicy j t
  p != 0 && load64 (p+24) t == 1 && load64 (p+96) t == 0 &&
    load64 (p+8) t == load64 (j+64) t
partial def freeJob (i t : UInt64) : UInt64 :=
  if i == 4 then error else if load64 (job i) t == 0 || load64 (job i) t == 10 || load64 (job i) t >= 12 then i else freeJob (i+1) t
@[noinline] def initializeAcquisition (ji i ci t : UInt64) : UInt64 :=
  let m := consumer i
  let policyRecord := Guest.LibraryCollections.record ci
  let j := job ji
  let oldHandle := load64 (j+48) t
  let t := if oldHandle == 0 then t else Guest.ContentSDK.control oldHandle 3 t
  let t := if oldHandle == 0 then t else Guest.ContentSDK.control oldHandle 4 t
  let oldRow := load64 (j+8) t
  let t := if load64 j t == 0 || oldRow >= 16 || load64 (row oldRow+64) t != ji+1 then t else store64 (row oldRow+64) 0 t
  let t := zero j 512 t
  let t := copy m (j+512) 768 t
  let t := copy (row i+256) (j+1280) 768 t
  let t := store64 j 1 t
  let t := store64 (j+8) i t
  let requestedProvider := load64 (st+136) t
  let providers := load64 (policyRecord+64) t
  let chosenProvider := if ((providers >>> requestedProvider) &&& 1) != 0 then requestedProvider else if (providers &&& 2) != 0 then 1 else 2
  let t := store64 (j+16) chosenProvider t
  let durableResume := load64 (row i+48) t == 2 && load64 (policyRecord+128) t != 0 && load64 (row i+120) t != 0
  let t := if load64 (row i+48) t != 2 || durableResume then t else store64 (j+24) (load64 (row i+16) t) t
  let t := store64 (j+64) (load64 (policyRecord+8) t) t
  let t := store64 (j+72) (load64 (m+408) t) t
  let t := store64 (j+400) (ci+1) t
  let t := copy policyRecord (j+2048) 512 t
  let t := store64 (j+408) (load64 (policyRecord+128) t) t
  let t := nextId t
  let t := store64 (j+80) (if durableResume then load64 (row i+120) t else load64 (st+184) t) t
  let t := store64 (j+104) 3 t
  let t := store64 (j+112) (load64 (policyRecord+64) t) t
  let t := store64 (row i+64) (ji+1) t
  let t := if durableResume then t else store64 (policyRecord+56) (load64 (policyRecord+56) t+load64 (m+408) t) t
  let t := copy (m+160) (policyRecord+224) 32 t
  let t := store64 (policyRecord+256) (load64 (policyRecord+256) t+1) t
  notice 36 t

@[noinline] def queue (i t : UInt64) : UInt64 :=
  if i >= load64 (st+16) t then t else
  let m := consumer i
  let existing := load64 (row i+64) t
  if existing > 0 && existing <= 4 && load64 (job (existing-1)) t != 13 && load64 (job (existing-1)) t != 14 then notice 18 t else
  let fresh := current (row i+256) (row i+256+320) t
  if fresh != 832 || status fresh != 0 || !Guest.RegistrySDK.consumerAdmitted (result fresh) then notice 54 fresh else
  if load64 (m+16) t != 1 then notice 34 t else
  let ci := collectionFor i t
  if ci == error then notice 21 (store64 (st+208) 1 (store64 (st+216) (i+1) t)) else
  if load64 (Guest.LibraryCollections.record ci+88) t == 1 && load64 (Guest.LibraryCollections.record ci+128) t == 0 then notice 21 t else
  let resume := load64 (row i+48) t == 2 && load64 (row i+120) t != 0 && load64 (Guest.LibraryCollections.record ci+128) t != 0
  if load64 (m+408) t > load64 (Guest.LibraryCollections.record ci+48) t ||
    !Guest.LibraryCollections.allowed ci m (if resume then 0 else load64 (m+408) t) t then notice 21 t else
  let ji := freeJob 0 t
  if ji == error then notice 21 ji else
  initializeAcquisition ji i ci t
-- Rules use stable collection/item identities. Claims remain unmeasured until
-- the completed local WAV parser checks actual rate/channels/frame count.
def eligible (i t : UInt64) : Bool :=
  let ci := collectionFor i t
  ci != error && load64 (consumer i+16) t == 1 &&
    load64 (Guest.LibraryCollections.record ci+16) t == 1 &&
    load64 (consumer i+408) t <= load64 (Guest.LibraryCollections.record ci+48) t
partial def offeredBetter (candidate i t : UInt64) : Bool :=
  if i == load64 (st+16) t then false else
  let a := consumer candidate
  let b := consumer i
  let better := load64 (b+424) t > load64 (a+424) t ||
    (load64 (b+424) t == load64 (a+424) t && load64 (b+296) t > load64 (a+296) t)
  (i != candidate && eligible i t && eq (a+128) (b+128) 32 t && better) || offeredBetter candidate (i+1) t
partial def acquiredEdition (candidate i t : UInt64) : Bool :=
  if i == load64 (st+16) t then false else
  let a := consumer candidate
  let b := consumer i
  let covers := load64 (b+424) t > load64 (a+424) t ||
    (load64 (b+424) t == load64 (a+424) t && load64 (b+296) t >= load64 (a+296) t)
  let ji := load64 (row i+64) t
  let pending := ji > 0 && ji <= 4 && load64 (job (ji-1)) t != 13 && load64 (job (ji-1)) t != 14
  ((pending || load64 (row i+24) t >= 2) && eq (a+128) (b+128) 32 t && covers) || acquiredEdition candidate (i+1) t
partial def best (i chosen t : UInt64) : UInt64 :=
  if i == load64 (st+16) t then chosen else
  let preferable := chosen == error || load64 (consumer i+424) t > load64 (consumer chosen+424) t ||
    (load64 (consumer i+424) t == load64 (consumer chosen+424) t && load64 (consumer i+296) t > load64 (consumer chosen+296) t)
  best (i+1) (if eligible i t && !offeredBetter i 0 t && !acquiredEdition i 0 t && preferable then i else chosen) t
partial def reasons (i chosen t : UInt64) : UInt64 :=
  if i == load64 (st+16) t then t else
  let code := if !eq (consumer i+96) (st+288) 32 t then 32 else
    if load64 (consumer i+408) t > load64 (st+112) t then 30 else
    if load64 (consumer i+16) t != 1 then 29 else
    if chosen != error && eq (consumer i+128) (consumer chosen+128) 32 t && load64 (consumer i+424) t < load64 (consumer chosen+424) t then 31 else 28
  reasons (i+1) chosen (store64 (row i+40) code t)
partial def monitorEach (i t : UInt64) : UInt64 :=
  if i == load64 (st+16) t then t else
  let ci := collectionFor i t
  let t := if !eligible i t || offeredBetter i 0 t || acquiredEdition i 0 t then t else
    if ci == error || !Guest.LibraryCollections.allowed ci (consumer i) (load64 (consumer i+408) t) t then t else queue i t
  monitorEach (i+1) t
def monitorDecision (t : UInt64) : UInt64 := dirty (monitorEach 0 t)

def metadataReply (operation code t : UInt64) : UInt64 :=
  if code != 0 then
    let t := store64 (st+40) 0 t
    let t := store64 (st+192) (Guest.WaitSDK.now t+100) t
    monitorDecision (notice 40 t)
  else if operation == 1 then
    let t := store64 (st+48) (Guest.LibraryPeerSDK.resultId t) t
    let t := store64 (st+32) (Guest.LibraryPeerSDK.next t) t
    dirty (store64 (st+40) 2 (store64 (st+56) 0 t))
  else
    let offset := load64 (st+56) t
    let n := load64 (wire+16) t-64
    if n == 0 || n > 640 || offset > 1536 || n > 1536-offset then notice 29 (store64 (st+40) 0 t) else
    let t := copy Guest.LibraryPeerSDK.data (metadata+offset) n t
    let t := store64 (st+56) (offset+n) t
    if offset+n != 1536 then t else
      let t := acceptMetadata t
      store64 (st+40) 1 t

@[noinline] def manifestReply (ji t : UInt64) : UInt64 :=
  let j := job ji
  let n := load64 (wire+16) t-64
  if n != 256 || !Guest.ContentFormat.valid Guest.LibraryPeerSDK.data t then notice 42 (store64 j 12 t) else
  let t := copy Guest.LibraryPeerSDK.data (j+128) 256 t
  let t := hash (j+128) 256 hashOut t
  if !eq hashOut (j+512+192) 32 t || load64 (j+152) t != load64 (j+512+408) t then notice 42 (store64 j 12 t) else
  if load64 (j+24) t != 0 then
    let t := copy (peer (load64 (j+16) t)+224) work 32 t
    let t := copy (j+1280+288) (work+32) 32 t
    let t := copy (j+512+192) (work+64) 32 t
    let recovered := load64 (row (load64 (j+8) t)+48) t == 2
    let r := if recovered then Guest.ContentSDK.adopt (load64 (j+24) t) (load64 (j+80) t) (load64 (j+72) t) work t
      else Guest.ContentSDK.reauthorize (load64 (j+24) t) work t
    if r != 64 || status r != 0 then notice 21 (store64 j 14 r) else
    let t := if !recovered then r else
      let old := load64 (j+24) r
      let fresh := result r
      let t := Guest.ContentSDK.release old r
      let t := store64 (j+24) fresh t
      store64 (row (load64 (j+8) t)+16) fresh (store64 (row (load64 (j+8) t)+48) 0 t)
    store64 j 3 t
  else
  let t := copy (j+128) work 256 t
  let t := copy hashOut (work+256) 32 t
  let t := copy (peer (load64 (j+16) t)+224) (work+288) 32 t
  let t := copy (j+1280+288) (work+320) 32 t
  let r := Guest.ContentSDK.reserve work (load64 (j+80) t) (load64 (j+72) t) 3 (load64 (j+408) t) t
  if r != 64 || status r != 0 then notice 21 (store64 j 14 r) else
    let t := store64 (j+24) (result r) r
    let t := store64 (row (load64 (j+8) t)+16) (result t) t
    dirty (store64 j 3 t)

@[noinline] def proofReply (ji t : UInt64) : UInt64 :=
  let j := job ji
  let n := load64 (wire+16) t-64
  let depth := load64 (j+176) t
  if depth > 14 || n != 32+depth*32 then notice 42 (store64 j 12 t) else
  let t := copy Guest.LibraryPeerSDK.data work n t
  let r := Guest.ContentSDK.beginChunk (load64 (j+24) t) (load64 (j+32) t) work n t
  if r != 64 || status r != 0 then jobFailure j r else
  if result r == 0 && load64 (wire+16) r == 4 then
    store64 (j+32) (load64 (j+32) r+1) (store64 j 3 r)
  else store64 (j+48) (result r) (store64 (j+40) 0 (store64 j 5 r))

@[noinline] def dataReply (ji operation t : UInt64) : UInt64 :=
  let j := job ji
  let n := load64 (wire+16) t-64
  let total := Guest.ContentFormat.chunkLength (load64 (j+512+408) t) (load64 (j+32) t)
  let offset := load64 (j+40) t
  if n == 0 || n > (if operation == 10 then 640 else 512) || offset > total || n > total-offset ||
    (operation == 10 && Guest.LibraryPeerSDK.resultId t != load64 (j+32) t*4096+offset) then notice 42 (store64 j 12 t) else
  let t := copy Guest.LibraryPeerSDK.data work n t
  let r := Guest.ContentSDK.append (load64 (j+48) t) offset work n t
  if r != 64 || status r != 0 then jobFailure j r else
  let t := store64 (j+40) (offset+n) r
  let t := store64 (j+56) (load64 (j+32) t*4096+offset+n) t
  if offset+n < total then store64 j 5 t else
    let r := Guest.ContentSDK.validate (load64 (j+48) t) t
    if r != 64 || status r != 0 then jobFailure j r else store64 j 7 r

@[noinline] def seedReply (ji operation code t : UInt64) : UInt64 :=
  if ji >= 4 then t else
  let j := job ji
  if load64 j t == 11 || load64 j t >= 12 then t else
  if code != 0 then notice 37 (store64 j 12 (store64 (j+96) code t)) else
  if operation == 3 then manifestReply ji t else
  if operation == 4 then proofReply ji t else
  if operation == 5 || operation == 10 then dataReply ji operation t else t

partial def receivePeers (slot t : UInt64) : UInt64 :=
  if slot == 3 then t else
  let p := peer slot
  let op := load64 (p+16) t
  if op == 0 || load64 p t == 0 then receivePeers (slot+1) t else
  let r := Guest.LibraryPeerSDK.receive slot (load64 p t) t
  let id := load64 (p+8) r
  let t := if Guest.LibraryPeerSDK.valid op id r then
    let code := Guest.LibraryPeerSDK.remoteStatus r
    let r := store64 (st+640) 1 r
    let t := if op == 10 && code == 0 && Guest.LibraryPeerSDK.next r != 0 then r else store64 (p+16) 0 r
    if slot == 0 then metadataReply op code t else
      let ji := load64 (p+32) t-1
      if ji >= 4 || load64 (p+80) t != load64 (job ji+80) t || load64 (job ji+16) t != slot then t else seedReply ji op code t
  else if Guest.WaitSDK.now r >= load64 (p+24) r then
    let t := Guest.NetworkSDK.revokePeer slot (load64 p r) r
    let t := store64 (p+16) 0 t
    let t := store64 p 0 t
    if slot == 0 then notice 37 (store64 (st+40) 0 t) else notice 37 (store64 (job (load64 (p+32) t-1)) 12 t)
  else r
  receivePeers (slot+1) t

@[noinline] partial def monitored (i t : UInt64) : Bool :=
  if i == Guest.LibraryCollections.count then false else
  (load64 (Guest.LibraryCollections.record i) t == 1 && load64 (Guest.LibraryCollections.record i+16) t == 1) || monitored (i+1) t
def catalogPump (t : UInt64) : UInt64 :=
  if load64 (st+224) t == 0 || load64 (peer 0+16) t != 0 then t else
  let phase := load64 (st+40) t
  if phase == 1 then issue 0 0 1 (load64 (st+32) t) 0 0 t else
  if phase == 2 then
    let off := load64 (st+56) t
    issue 0 0 2 (load64 (st+48) t) off (if 1536-off > 640 then 640 else 1536-off) t
  else if monitored 0 t && Guest.WaitSDK.now t >= load64 (st+192) t then
    store64 (st+40) 1 (store64 (st+32) 0 t) else t

-- Small native collection references are immutable Objects only after Add.
-- They contain selected signed metadata, never session keys or transport grants.
partial def appendSmall (h source length off t : UInt64) : UInt64 :=
  if off == length then t else
  let n := if length-off > 512 then 512 else length-off
  let r := Guest.LiveSDK.append h off (source+off) n t
  if r != 64 || status r != 0 then error else appendSmall h source length (off+n) r
@[noinline] def add (t : UInt64) : UInt64 :=
  let r := selected t
  if load64 r t == 0 || load64 (r+8) t != 0 then t else
  let answer := stage 1536 2 0 t
  if answer != 64 || status answer != 0 then notice 21 answer else
  let h := result answer
  let answer := appendSmall h (r+256) 1536 0 answer
  if answer == error then notice 21 (abortStage h answer) else
  let answer := stageDigest h answer
  if answer < 96 || status answer != 0 then notice 21 answer else
  let t := copy (wire+64) digest 32 answer
  let answer := commit h digest t
  if answer != 96 || status answer != 0 then notice 21 answer else
  notice 22 (store64 (r+8) h answer)
@[noinline] def bindRetention (ji t : UInt64) : UInt64 :=
  let j := job ji
  if load64 (j+408) t == 0 || load64 (j+416) t == 1 then t else
  let ri := load64 (j+8) t
  let chosen := load64 (st+8) t
  let t := store64 (st+8) ri t
  let t := add t
  let t := store64 (st+8) chosen t
  if load64 (row ri+8) t == 0 then jobFailure j error else
  let vault := syscall 97 3 0 0 0 t
  let r := Guest.LiveSDK.share (load64 (row ri+8) vault) vault 1 vault
  if r != 64 || status r != 0 then jobFailure j r else
  let r := syscall 30 3 wire 64 1024 (header 264 (load64 (j+408) r) (result r) 0 0 0 0 r)
  if r != 64 || status r != 0 then jobFailure j r else store64 (j+416) 1 r

@[noinline] def validationCompletion (ji phase t : UInt64) : UInt64 :=
  let j := job ji
  let r := Guest.ContentSDK.inspectJob (load64 (j+48) t) t
  if r != 64 || status r != 0 then jobFailure j r else
  let state := load64 (wire+16) r
  if state >= 5 then notice 42 (store64 (j+96) (load64 (wire+40) r) (store64 (j+120) state (store64 j 12 r))) else
  if state != 4 then r else
  let t := Guest.ContentSDK.control (load64 (j+48) r) 4 r
  let t := store64 (j+48) 0 t
  if phase == 7 then store64 (j+32) (load64 (j+32) t+1) (store64 j 3 t) else
    let r := Guest.Wave.parse (load64 (j+24) t) t
    if r == error || load64 (Guest.Wave.info+24) r != load64 (j+512+424) r ||
      load64 (Guest.Wave.info+48) r != load64 (j+512+416) r then notice 42 (store64 j 12 r) else
    let t := store64 (row (load64 (j+8) r)+24) 2 r
    notice 16 (store64 j 10 t)

@[noinline] def jobPump (ji t : UInt64) : UInt64 :=
  let j := job ji
  let phase := load64 j t
  let slot := load64 (j+16) t
  if phase == 0 || phase >= 10 then t else
  let checked := if phase == 3 || phase == 8 then current (j+1280) (j+1280+320) t else t
  let revoked := (phase == 3 || phase == 8) && (checked != 832 || status checked != 0 || !Guest.RegistrySDK.consumerAdmitted (result checked))
  if !policyLive j checked || revoked then
    let h := load64 (j+48) checked
    let t := if h == 0 then checked else Guest.ContentSDK.control h 3 checked
    let t := if h == 0 then t else Guest.ContentSDK.control h 4 t
    let content := load64 (j+24) t
    let t := if content == 0 then t else Guest.ContentSDK.revokeAcquisition content t
    notice 54 (store64 j 14 (store64 (j+48) 0 t))
  else
  if phase == 1 then
    let t := bindRetention ji t
    if load64 j t != 1 then t else issue slot ji 3 0 0 0 t
  else
  if phase == 3 then
    if load64 (j+32) t >= load64 (j+160) t then store64 j 8 t else
    let r := Guest.ContentSDK.inspectChunk (load64 (j+24) t) (load64 (j+32) t) t
    if r != 64 || status r != 0 then jobFailure j r else
    if result r == 1 then dirty (store64 (st+640) 1 (store64 (j+32) (load64 (j+32) r+1) r))
    else issue slot ji 4 (load64 (j+32) r) 0 0 r
  else if phase == 5 then
    let remaining := Guest.ContentFormat.chunkLength (load64 (j+512+408) t) (load64 (j+32) t)-load64 (j+40) t
    issue slot ji (if load64 (peer slot+136) t >= 3 then 10 else 5) (load64 (j+32) t*4096+load64 (j+40) t)
      (if load64 (peer slot+136) t >= 3 then remaining else if remaining > 512 then 512 else remaining) 0 t
  else if phase == 7 || phase == 9 then
    validationCompletion ji phase t
  else if phase == 8 then
    let r := Guest.ContentSDK.publish (load64 (j+24) t) t
    if r != 64 || status r != 0 then jobFailure j r else
    store64 (j+48) (result r) (store64 j 9 r)
  else t
partial def jobsPump (i t : UInt64) : UInt64 :=
  if i == 4 then t else jobsPump (i+1) (jobPump i t)
def policy (t : UInt64) : UInt64 :=
  if load64 (selected t) t == 0 then t else
  let t := store64 (st+216) (load64 (st+8) t+1) t
  notice 9 (store64 (st+208) 1 t)
-- Revocation is scoped to this collection. Other rows keep their frozen jobs.
partial def retirePolicy (ci i t : UInt64) : UInt64 :=
  if i == 4 then t else
  let j := job i
  let phase := load64 j t
  let t := if load64 (j+400) t != ci+1 || phase == 0 || phase == 10 || phase == 13 || phase == 14 then t else
    let h := load64 (j+48) t
    let t := if h == 0 then t else Guest.ContentSDK.control h 3 t
    let t := if h == 0 then t else Guest.ContentSDK.control h 4 t
    let content := load64 (j+24) t
    let t := if content == 0 then t else Guest.ContentSDK.revokeAcquisition content t
    store64 j 14 (store64 (j+48) 0 t)
  retirePolicy ci (i+1) t
def approvePolicy (t : UInt64) : UInt64 :=
  let chosen := load64 (st+216) t-1
  if chosen >= load64 (st+16) t then notice 21 (store64 (st+208) 0 t) else
  let ci := Guest.LibraryCollections.select (consumer chosen+96) (row chosen+256+288) t
  if ci == error then notice 21 ci else
  let t := retirePolicy ci 0 ci
  let t := Guest.LibraryCollections.approve ci 6029312 6 0 t
  let p := Guest.LibraryCollections.record ci
  let t := copy (p+160) (st+288) 32 t
  let t := store64 (st+208) 0 t
  let t := store64 (st+88) 1 t
  let t := store64 (st+96) 1 t
  let t := store64 (st+128) (load64 (p+8) t) t
  monitorDecision (notice 36 t)
@[noinline] def subscribe (t : UInt64) : UInt64 :=
  let ci := Guest.LibraryCollections.select (selected t+1024+96) (selected t+256+288) t
  if ci == error then notice 21 ci else
  let p := Guest.LibraryCollections.record ci
  let enabled := if load64 (p+16) ci == 0 then 1 else 0
  let t := store64 (p+16) enabled ci
  notice 43 (store64 (st+88) enabled t)
def chosenJob (t : UInt64) : UInt64 :=
  let h := load64 (selected t+64) t
  if h == 0 || h > 4 then error else job (h-1)
@[noinline] partial def pause (t : UInt64) : UInt64 :=
  let j := chosenJob t
  if j == error || load64 j t == 0 || load64 j t >= 10 then t else
  let t := store64 (j+88) (load64 j t) t
  let h := load64 (j+48) t
  let t := if h == 0 then t else Guest.ContentSDK.control h 1 t
  notice 18 (store64 j 11 t)
@[noinline] partial def cancel (t : UInt64) : UInt64 :=
  let j := chosenJob t
  if j == error || load64 j t == 0 then t else
  let h := load64 (j+48) t
  let t := if h == 0 then t else Guest.ContentSDK.control h 3 t
  let t := if h == 0 then t else Guest.ContentSDK.control h 4 t
  let content := load64 (j+24) t
  let t := if content == 0 then t else Guest.ContentSDK.revokeAcquisition content t
  notice 20 (store64 j 13 (store64 (j+48) 0 t))
@[noinline] partial def retry (t : UInt64) : UInt64 :=
  let j := chosenJob t
  if j == error then t else
  if !policyLive j t then notice 69 t else
  if load64 j t == 11 then
    let h := load64 (j+48) t
    let t := if h == 0 then t else Guest.ContentSDK.control h 2 t
    dirty (store64 j (load64 (j+88) t) t)
  else if load64 j t == 12 then
    let h := load64 (j+48) t
    let t := if h == 0 then t else Guest.ContentSDK.control h 3 t
    let t := if h == 0 then t else Guest.ContentSDK.control h 4 t
    let slot := load64 (st+136) t
    if ((load64 (j+112) t >>> slot) &&& 1) == 0 then notice 21 t else
    let inspected := Guest.NetworkSDK.inspectPeer slot t
    let t := if inspected == 64 && status inspected == 0 && result inspected == 3 then inspected else
      let opened := Guest.NetworkSDK.openPeer slot inspected
      store64 (peer slot+64) (if opened == 64 && status opened == 0 then 0 else 1) opened
    let t := store64 (j+16) slot t
    let t := store64 (j+48) 0 t
    dirty (store64 j 1 t)
  else t

def play (t : UInt64) : UInt64 :=
  let r := selected t
  let player := load64 (st+160) t
  let checked := current (r+256) (r+256+320) t
  let currentOK := checked == 832 && status checked == 0 && Guest.RegistrySDK.consumerAdmitted (result checked)
  let unavailable := checked == error || (checked == 64 && status checked == 6)
  if !currentOK && !(load64 (r+48) checked != 0 && unavailable) then notice 54 checked else
  if player == 0 then notice 58 t else
  if (load64 (r+24) t != 1 && load64 (r+24) t != 2 && load64 (r+24) t != 3) || load64 (r+16) t == 0 then notice 41 t else
  let answer := Guest.ContentSDK.share (load64 (r+16) t) player t
  if answer != 64 || status answer != 0 then notice 41 answer else
  let t := header 600 (result answer) (load64 (r+1024+424) answer) (load64 (r+1024+416) answer) 0 0 0 answer
  let answer := syscall 30 player wire 64 1024 t
  if answer != 64 || status answer != 0 || load64 (wire+16) answer == 6 then notice 42 answer else notice 16 answer

@[noinline] def portal (op h nonce data length t : UInt64) : UInt64 :=
  let shell := syscall 97 4 0 0 0 t
  let t := header op h nonce 0 0 0 0 shell
  let t := if length == 0 then t else copy data (wire+64) length t
  syscall 30 shell wire (64+length) 1024 t

-- A level pack is selected as Source data from a granted Project. Parsing and
-- compatibility remain in the game; only a read grant crosses this boundary.
def packs : UInt64 := 0x718000
partial def packSuffix (p n i t : UInt64) : Bool :=
  if i == 9 then true else
  let word : UInt64 := 0x6c6576656c746c2e
  let c := if i == 8 then 115 else (word >>> (i*8)) &&& 255
  load8 (p+n-9+i) t == c && packSuffix p n (i+1) t
@[noinline] partial def modBegin (t : UInt64) : UInt64 :=
  let who := load64 (st+168) t
  let check := syscall 125 who work 32 0 t
  if who == 0 || check != 32 || !eq work (selected check+1024+256) 32 check then notice 42 check else
  let t := copy work (st+488) 32 check
  let t := nextId t
  let nonce := load64 (st+184) t
  let r := portal 14 25 nonce 0 0 t
  if r != 64 || status r != 0 then notice 39 r else
    notice 39 (store64 (st+320) nonce (store64 (st+432) 2 (store64 (st+480) who r)))
def packScan (t : UInt64) : UInt64 :=
  if load64 (st+432) t != 3 then t else
  let i := load64 (st+464) t
  if i == load64 (st+456) t then
    if load64 (st+472) t == 0 then notice 42 (store64 (st+432) 0 t)
    else dirty (store64 (st+432) 4 (store64 (st+464) 0 t))
  else
    let r := Guest.LiveSDK.read (load64 (st+448) t) (32+i*128) 128 t
    if r != 192 || status r != 0 then notice 42 (store64 (st+432) 0 r) else
    let p := wire+64
    let n := load64 (p+8) r
    let t := if load64 p r == 10 && n >= 9 && n <= 80 && packSuffix (p+48) n 0 r then
        let count := load64 (st+472) r
        store64 (st+472) (count+1) (copy p (packs+count*128) 128 r)
      else r
    store64 (st+464) (i+1) t
@[noinline] partial def modApply (t : UInt64) : UInt64 :=
  let who := load64 (st+480) t
  let check := syscall 125 who work 32 0 t
  if check != 32 || !eq work (st+488) 32 check then notice 42 (store64 (st+432) 0 check) else
  let p := packs+load64 (st+464) check*128
  let r := Guest.ProjectSDK.resolve (load64 (st+440) check) (p+16) check
  if r != 128 || status r != 0 then notice 42 (store64 (st+432) 0 r) else
  let resource := result r
  let r := Guest.LiveSDK.share resource who 1 r
  if r != 64 || status r != 0 then notice 42 (store64 (st+432) 0 r) else
  let packScope := result r
  let r := Guest.GameSDK.loadLevelPack who packScope r
  let ok := r == 64 && status r == 0
  let t := Guest.LiveSDK.revoke resource packScope r
  notice (if ok then 16 else 42) (store64 (st+432) 0 t)

def install (t : UInt64) : UInt64 :=
  let r := selected t
  if load64 (r+1024+16) t != 2 then
    notice 8 (store64 (r+32) (if load64 (r+32) t == 0 then 1 else 0) t)
  else if load64 (st+536) t != 0 then notice 18 t
  else if load64 (st+528) t != 0 then
    let t := nextId t
    let operation := load64 (st+184) t
    let answer := Guest.LibraryFetchSDK.begin (load64 (st+528) t) (load64 (st+136) t) operation 1048576 (r+256) t
    if answer != 64 || status answer != 0 then notice 42 answer else
      notice 71 (store64 (st+536) operation (store64 (st+576) (load64 (st+8) answer) answer))
  else
    let t := nextId t
    let nonce := load64 (st+184) t
    let answer := portal 3 0 nonce 0 0 t
    if answer != 64 || status answer != 0 then notice 39 answer else
      notice 39 (store64 (st+320) nonce (store64 (st+328) (load64 (st+8) answer) answer))
@[noinline] partial def nativeInstall (root chosen t : UInt64) : UInt64 :=
  if chosen >= load64 (st+16) t then notice 42 t else
  let answer := Guest.ProjectSDK.describeRoot root t
  if answer != 160 || status answer != 0 || !eq (wire+64) (row chosen+256+320) 32 answer then notice 42 answer else
  let t := copy (wire+64) work 32 answer
  let check := Guest.RegistrySDK.verify (row chosen+256) work t
  if check != 832 || status check != 0 || !Guest.RegistrySDK.executableAdmitted (result check) then notice 29 check else
    let shell := syscall 97 4 0 0 0 check
    let r := Guest.ProjectSDK.delegate root shell 89 shell
    if r != 160 || status r != 0 then notice 42 r else portal 6 (result r) 0 0 0 r
def installPump (t : UInt64) : UInt64 :=
  if load64 (st+320) t == 0 then t else
  let r := portal 4 0 (load64 (st+320) t) 0 0 t
  if r != 64 then r else
  if status r != 0 || load64 (wire+16) r >= 3 then notice 21 (store64 (st+320) 0 (store64 (st+432) 0 r)) else
  if load64 (wire+16) r != 2 then r else
  let root := result r
  let chosen := load64 (st+328) r
  let t := store64 (st+320) 0 r
  if load64 (st+432) t == 2 then
    let t := store64 (st+440) root t
    let r := Guest.ProjectSDK.openHead root t
    if r != 128 || status r != 0 then notice 42 (store64 (st+432) 0 r) else
    let t := store64 (st+448) (result r) r
    let r := Guest.LiveSDK.read (result r) 0 32 t
    if r != 96 || status r != 0 || load64 (wire+64) r != 0x31464e4d544c ||
      load64 (wire+80) r > 32 then notice 42 (store64 (st+432) 0 r) else
      dirty (store64 (st+456) (load64 (wire+80) r) (store64 (st+464) 0 (store64 (st+472) 0 (store64 (st+432) 3 r))))
  else
  nativeInstall root chosen t

def fetchPump (t : UInt64) : UInt64 :=
  let operation := load64 (st+536) t
  if operation == 0 then t else
  let r := Guest.LibraryFetchSDK.inspect (load64 (st+528) t) operation t
  if r != 64 then notice 42 (store64 (st+536) 0 r) else
  let phase := load64 (wire+16) r
  if phase == 1 then r else
  let t := store64 (st+536) 0 r
  if status r != 0 || phase != 2 then notice 42 t else
    nativeInstall (result t) (load64 (st+576) t) t

partial def chooseProcess (i audio t : UInt64) : UInt64 :=
  if i == 12 then error else
  let p := 0x6e6000+i*32
  let rights := load64 (p+16) t
  if load64 (p+8) t == 0 || load64 (p+8) t >= 5 then chooseProcess (i+1) audio t else
  if audio == 2 then
    if rights == 1151 then load64 p t else chooseProcess (i+1) audio t
  else if audio == 1 then
    if (rights &&& 4096) != 0 then load64 p t else chooseProcess (i+1) audio t
  else if rights != 795 then chooseProcess (i+1) audio t else
    let checked := syscall 125 (load64 p t) work 32 0 t
    if checked == 32 && eq work (selected checked+1024+256) 32 checked then load64 p checked else chooseProcess (i+1) audio checked

@[noinline] partial def bindProcess (audio t : UInt64) : UInt64 :=
  -- The active operation was submitted to this exact helper incarnation.
  -- Rebinding would send its inspection to another helper and orphan it.
  if audio == 2 && load64 (st+536) t != 0 then notice 18 t else
  let r := syscall 124 0 0x6e6000 384 0 t
  if r == error then notice 58 r else
  let who := chooseProcess 7 audio r
  if who == error then notice 58 who else
  let checked := if audio != 0 then who else syscall 125 who work 32 0 who
  if audio == 0 && (checked != 32 || !eq work (selected checked+1024+256) 32 checked) then notice 42 checked else
  notice 16 (store64 (if audio == 2 then st+528 else if audio == 1 then st+160 else st+168) who checked)
-- Explicit retention enters trusted compositor approval; the application never
-- invokes Vault or obtains keys. A shared read handle is not durable backing.
def retain (t : UInt64) : UInt64 :=
  if load64 (st+376) t != 0 then notice 18 t else
  let r := selected t
  let h := load64 (r+16) t
  if h == 0 || load64 (r+8) t == 0 then notice 41 t else
  let shell := syscall 97 4 0 0 0 t
  let answer := Guest.ContentSDK.share h shell shell
  if answer != 64 || status answer != 0 then notice 41 answer else
  let content := result answer
  let answer := Guest.LiveSDK.share (load64 (r+8) answer) shell 25 answer
  if answer != 64 || status answer != 0 then notice 41 answer else
  let metadataHandle := result answer
  let t := copy (r+1024+192) work 32 answer
  let answer := portal 8 content metadataHandle work 32 t
  if answer != 64 || status answer != 0 then notice 21 answer else dirty (store64 (st+360) (load64 (st+8) answer+1) (store64 (st+368) metadataHandle (store64 (st+376) 1 answer)))

def recoverRetained (t : UInt64) : UInt64 :=
  if load64 (st+376) t != 0 then notice 18 t else
  let t := nextId t
  let nonce := load64 (st+184) t
  let r := portal 10 0 nonce 0 0 t
  if r != 64 || status r != 0 then notice 21 r else
    notice 39 (store64 (st+368) nonce (store64 (st+376) 2 r))
partial def readMetadata (h off t : UInt64) : UInt64 :=
  if off == 1536 then t else
  let r := Guest.LiveSDK.read h off 512 t
  if r != 576 || status r != 0 then error else readMetadata h (off+512) (copy (wire+64) (metadata+off) 512 r)
@[noinline] def installRetained (h content complete t : UInt64) : UInt64 :=
  let r := t
  let old := findEdition (metadata+928) 0 r
  let ri := if old == error then load64 (st+16) r else old
  if ri >= 16 then notice 21 r else
  let previousMetadata := load64 (row ri+8) r
  let previousContent := load64 (row ri+16) r
  let r := if previousMetadata == 0 || previousMetadata == h then r else Guest.LiveSDK.releaseReference previousMetadata r
  let r := if previousContent == 0 || previousContent == content then r else Guest.ContentSDK.release previousContent r
  let t := copy metadata (row ri+256) 1536 r
  let t := store64 (row ri) 1 t
  let t := store64 (row ri+8) h t
  let t := store64 (row ri+16) content t
  let t := store64 (row ri+24) (if complete == 1 then 3 else 1) t
  let t := store64 (row ri+48) (if complete == 1 then 1 else 2) t
  let t := store64 (row ri+104) 1 t
  let t := if old == error then store64 (st+16) (ri+1) t else t
  let t := store64 (st+8) ri t
  notice 17 t

def restoreSelection (h content t : UInt64) : UInt64 :=
  let r := readMetadata h 0 t
  if r == error || !Guest.ConsumerFormat.valid (metadata+768) r then notice 42 r else
  let t := hash (metadata+768) 768 hashOut r
  if !eq hashOut (metadata+400) 32 t then notice 42 t else
  let r := Guest.ContentSDK.describe content t
  if r != 320 || status r != 0 then notice 42 r else
  let complete := load64 (wire+16) r == 2
  if !complete && load64 (wire+16) r != 1 then notice 42 r else
  let t := hash (wire+64) 256 hashOut r
  if !eq hashOut (metadata+768+192) 32 t then notice 42 t else
  let r := if complete then Guest.Wave.parse content t else t
  if complete && (r == error || load64 (Guest.Wave.info+24) r != load64 (metadata+768+424) r ||
    load64 (Guest.Wave.info+48) r != load64 (metadata+768+416) r) then notice 42 r else
  installRetained h content (if complete then 1 else 0) r

def vaultPump (t : UInt64) : UInt64 :=
  let mode := load64 (st+376) t
  if mode == 0 then t else
  let r := portal 9 0 (load64 (st+368) t) 0 0 t
  if r != 80 then r else
  let phase := load64 (wire+16) r
  if phase < 4 then r else
  let content := load64 (wire+64) r
  let metadataHandle := load64 (wire+72) r
  let t := store64 (st+376) 0 r
  if mode == 1 then
    let ri := load64 (st+360) t-1
    let h := if ri >= 16 then 0 else load64 (row ri+8) t
    let t := if h == 0 then t else Guest.LiveSDK.revoke h (load64 (st+368) t) t
    if phase != 4 || ri >= 16 then notice 21 t else
    let r := Guest.ContentSDK.describe (load64 (row ri+16) t) t
    if r != 320 || status r != 0 then notice 21 r else
      notice 17 (store64 (row ri+104) 1 (store64 (row ri+24) (if load64 (wire+16) r == 2 then 3 else 1) r))
  else if phase != 4 || content == 0 || metadataHandle == 0 then notice 21 t else restoreSelection metadataHandle content t

partial def searchAt (title n offset i count t : UInt64) : Bool :=
  if i == count then true else if offset+i >= n then false else
  let a := load8 (title+offset+i) t
  let b := load8 (0x6e0400+i) t
  let a := if a >= 65 && a <= 90 then a+32 else a
  let b := if b >= 65 && b <= 90 then b+32 else b
  a == b && searchAt title n offset (i+1) count t
partial def titleMatches (p n offset count t : UInt64) : Bool :=
  if count == 0 then true else if offset >= n then false else
    searchAt p n offset 0 count t || titleMatches p n (offset+1) count t
partial def catalogRows (i stop line t : UInt64) : UInt64 :=
  if i == stop || line == 10 then t else
  let r := row i
  let m := r+1024
  let visible := (load64 st t != 3 || load64 (m+16) t == 2) && (load64 st t != 5 || load64 (r+104) t == 1 || load64 (r+48) t > 0) && titleMatches (m+344) (load64 (m+336) t) 0 (load64 (st+72) t) t
  if !visible then catalogRows (i+1) stop line t else
  let y := 100+line*17
  let t := if i == load64 (st+8) t then fill 8 (y-2) 624 16 0x29495d t else t
  let t := char 12 y (if load64 (r+8) t == 0 then 45 else 43) fg bg t
  let t := text (m+344) (load64 (m+336) t) 30 y fg bg t
  let t := hex (load64 (m+424) t) 1 430 y fg bg t
  let t := hex (load64 (m+408) t) 8 454 y fg bg t
  let t := label (if load64 (r+24) t == 3 then 17 else if load64 (r+24) t == 2 then 16 else if load64 (r+16) t != 0 then 15 else 14) 516 y 0xa9c6ab t
  catalogRows (i+1) stop (line+1) t
partial def providerRows (i t : UInt64) : UInt64 :=
  if i == 3 then t else
  let p := peer i
  let y := 120+i*54
  let t := if i != load64 (st+336) t then t else fill 8 (y-3) 624 51 0x29495d t
  let t := hex i 1 16 y fg bg t
  let t := label (if load64 (p+56) t == 3 then 51 else if load64 (p+96) t == 0 then 50 else 52) 40 y fg t
  let n := load64 (p+288) t
  let t := if n > 0 && n <= 96 then text (p+296) n 40 (y+15) 0xc2b48c bg t else t
  let t := if load64 (p+96) t == 0 then t else
    let t := hex (load64 (p+224) t) 16 40 (y+30) fg bg t
    let t := hex (load64 (p+232) t) 16 168 (y+30) fg bg t
    let t := hex (load64 (p+240) t) 16 296 (y+30) fg bg t
    hex (load64 (p+248) t) 16 424 (y+30) fg bg t
  providerRows (i+1) t
partial def byteNumber (v digits x y t : UInt64) : UInt64 :=
  if digits == 0 then t else
    byteNumber (v/10) (digits-1) x y (char (x+(digits-1)*8) y (v%10+48) fg bg t)
def queueLabel (phase : UInt64) : UInt64 :=
  if phase == 7 || phase == 8 || phase == 9 then 72 else
  if phase == 10 then 16 else if phase == 11 then 18 else
  if phase == 12 then 19 else if phase == 13 then 20 else
  if phase == 14 then 21 else 71
partial def queueRows (i t : UInt64) : UInt64 :=
  if i == 4 then t else
  let j := job i
  let y := 105+i*45
  let t := if load64 j t == 0 then t else
    let t := text (j+512+344) (load64 (j+512+336) t) 14 y fg bg t
    let t := label (queueLabel (load64 j t)) 14 (y+14) fg t
    let t := byteNumber (load64 (j+56) t) 7 190 (y+14) t
    let t := char 250 (y+14) 47 fg bg t
    let t := byteNumber (load64 (j+512+408) t) 7 262 (y+14) t
    let t := label 26 336 (y+14) fg t
    byteNumber (load64 (j+16) t) 1 408 (y+14) t
  queueRows (i+1) t

partial def packRows (i stop line t : UInt64) : UInt64 :=
  if i == stop || line == 10 then t else
  let p := packs+i*128
  let y := 128+line*16
  let t := if i != load64 (st+464) t then t else fill 10 (y-2) 616 16 0x29495d t
  let t := text (p+48) (load64 (p+8) t) 16 y fg bg t
  packRows (i+1) stop (line+1) t

@[noinline] def collectionLabel (id x y t : UInt64) : UInt64 :=
  if id == 0 then
    let t := store64 (0x414000+0) 5283922227724308291 t
    let t := store64 (0x414000+8) 7236837238369373775 t
    let t := store64 (0x414000+16) 8389754637861089381 t
    let t := store64 (0x414000+24) 7311153582385946912 t
    let t := store64 (0x414000+32) 7594029311123791972 t
    let t := store64 (0x414000+40) 29541 t
    text 0x414000 42 x y fg bg t
  else if id == 1 then
    let t := store64 (0x414000+0) 2336936576420900949 t
    let t := store64 (0x414000+8) 8944276830209992051 t
    let t := store64 (0x414000+16) 2338609986426390304 t
    let t := store64 (0x414000+24) 7597132135905042556 t
    let t := store64 (0x414000+32) 2324737550145711988 t
    let t := store64 (0x414000+40) 111512105936242 t
    text 0x414000 46 x y fg bg t
  else if id == 2 then
    let t := store64 (0x414000+0) 7234318610140980594 t
    let t := store64 (0x414000+8) 7596562555642851104 t
    let t := store64 (0x414000+16) 8315180351695644526 t
    let t := store64 (0x414000+24) 8243116074772495392 t
    let t := store64 (0x414000+32) 2340781565013488737 t
    let t := store64 (0x414000+40) 28554769915274081 t
    text 0x414000 47 x y fg bg t
  else if id == 3 then
    let t := store64 (0x414000+0) 4928996481858627408 t
    let t := store64 (0x414000+8) 2340781375932407918 t
    let t := store64 (0x414000+16) 8247620832851013425 t
    let t := store64 (0x414000+24) 2328959674796434787 t
    let t := store64 (0x414000+32) 8031659162544202102 t
    let t := store64 (0x414000+40) 111516300108140 t
    text 0x414000 46 x y fg bg t
  else if id == 4 then
    let t := store64 (0x414000+0) 8097789280689352261 t
    let t := store64 (0x414000+8) 8367814987270287984 t
    let t := store64 (0x414000+16) 7596569198838638952 t
    let t := store64 (0x414000+24) 7166147437900364131 t
    let t := store64 (0x414000+32) 8317134089574507296 t
    text 0x414000 40 x y fg bg t
  else if id == 5 then
    let t := store64 (0x414000+0) 7310016704525067602 t
    let t := store64 (0x414000+8) 7594029311123791972 t
    let t := store64 (0x414000+16) 8388342946312778597 t
    let t := store64 (0x414000+24) 6998708665766274592 t
    let t := store64 (0x414000+32) 7598814415692329315 t
    let t := store64 (0x414000+40) 8030604713523179119 t
    let t := store64 (0x414000+48) 7102838 t
    text 0x414000 51 x y fg bg t
  else if id == 6 then
    let t := store64 (0x414000+0) 7308335520438826310 t
    let t := store64 (0x414000+8) 8944275778110583907 t
    let t := store64 (0x414000+16) 7022349122379597344 t
    let t := store64 (0x414000+24) 8533873931757907561 t
    let t := store64 (0x414000+32) 133532403134053 t
    text 0x414000 38 x y fg bg t
  else if id == 7 then
    let t := store64 (0x414000+0) 5495890318593705029 t
    let t := store64 (0x414000+8) 5711444230028936005 t
    let t := store64 (0x414000+16) 5642809484373216332 t
    text 0x414000 24 x y fg bg t
  else t
@[noinline] partial def collectionRows (i t : UInt64) : UInt64 :=
  if i == Guest.LibraryCollections.count then t else
  let p := Guest.LibraryCollections.record i
  let y := 120+i*20
  let t := if i == load64 (st+600) t then fill 8 (y-2) 624 18 0x29495d t else t
  let t := if load64 p t == 0 then hex i 1 12 y fg bg t else
    let t := hex i 1 12 y fg bg t
    let t := hex (load64 (p+160) t) 12 30 y fg bg t
    let t := byteNumber (load64 (p+56) t) 8 140 y t
    let t := char 208 y 47 fg bg t
    let t := byteNumber (load64 (p+48) t) 8 220 y t
    let t := hex (load64 (p+8) t) 4 310 y fg bg t
    let t := char 360 y (if load64 (p+16) t == 1 then 77 else 45) fg bg t
    let t := char 380 y (if load64 (p+24) t == 1 then 65 else 45) fg bg t
    let t := hex (load64 (p+64) t) 1 410 y fg bg t
    let t := char 440 y (if load64 (p+88) t == 1 then 86 else 69) fg bg t
    char 470 y (if load64 (p+96) t == 1 then 63 else 32) fg bg t
  collectionRows (i+1) t
@[noinline] def collectionInput (code t : UInt64) : UInt64 :=
  let ci := load64 (st+600) t
  let p := Guest.LibraryCollections.record ci
  if load64 (st+608) t == 1 then
    if code == 1 then dirty (store64 (st+608) 0 t) else
    if code == 104 || code == 109 then
      let old := load64 (st+616) t
      let next := if code == 104 then if old > Guest.ContentFormat.maxBytes-1048576 then Guest.ContentFormat.maxBytes else old+1048576
        else if old <= 1048576 then 1048576 else old-1048576
      dirty (store64 (st+616) next t)
    else if code == 2 || code == 3 then
      let mask := load64 (st+624) t ^^^ ((1 : UInt64) <<< (code-1))
      if mask == 0 then t else dirty (store64 (st+624) mask t)
    else if code == 19 then dirty (store64 (st+632) (if load64 (st+632) t == 0 then 1 else 0) t)
    else if code == 28 then
      let t := retirePolicy ci 0 t
      let t := Guest.LibraryCollections.approve ci (load64 (st+616) t) (load64 (st+624) t) (load64 (st+632) t) t
      notice (if t == error then 21 else 36) (store64 (st+608) 0 t)
    else t
  else if code == 103 || code == 108 then
    dirty (store64 (st+600) (if code == 103 then (ci+7)%8 else (ci+1)%8) t)
  else if load64 p t == 0 then t else
  if code == 34 then
    let t := store64 (st+616) (load64 (p+48) t) t
    let t := store64 (st+624) (load64 (p+64) t) t
    dirty (store64 (st+608) 1 (store64 (st+632) (load64 (p+88) t) t))
  else if code == 31 then dirty (store64 (p+16) (if load64 (p+16) t == 0 then 1 else 0) t)
  else if code == 46 then
    let t := retirePolicy ci 0 t
    notice 54 (Guest.LibraryCollections.revoke ci t)
  else t

def exportLabel (t : UInt64) : UInt64 :=
  let t := store64 work 8390891584591568984 t
  let t := store64 (work+8) 7310309144435826746 t
  text work 16 12 321 fg bg t

def draw (surface t : UInt64) : UInt64 :=
  let t := fill 0 0 640 352 bg t
  let t := fill 0 0 640 32 0x203e50 t
  let t := label 0 12 10 fg t
  let t := label 1 12 39 0xb1cbd8 t
  let t := label 2 12 57 0xc2b48c t
  let t := label 49 12 77 fg t
  let t := text 0x6e0400 (load64 (st+72) t) 68 77 fg bg t
  let tab := load64 st t
  let t := if tab == 4 then
      let t := collectionLabel 0 12 94 t
      let t := collectionRows 0 t
      collectionLabel 1 12 285 t
    else if tab == 1 then
      let t := label 6 12 94 fg t
      let t := providerRows 0 t
      label 7 12 298 fg t
    else if tab == 2 then queueRows 0 t
    else if load64 (st+16) t == 0 then label 5 12 112 fg t
    else catalogRows (load64 (st+8) t/10*10) (load64 (st+16) t) 0 t
  let t := if load64 (st+232) t == 0 || load64 (st+16) t == 0 then t else
    let r := selected t
    let t := fill 8 165 624 132 0x203e50 t
    let t := label 45 16 173 fg t
    let t := text (r+1024+344) (load64 (r+1024+336) t) 16 190 fg bg t
    let t := label (load64 (r+40) t) 16 210 0xe0bd80 t
    let t := label 27 16 232 fg t
    let t := hex (load64 (r+256+48) t) 8 120 232 fg bg t
    let t := hex (load64 (r+1024+160) t) 16 16 251 fg bg t
    label 35 16 275 fg t
  let t := if tab == 4 then collectionLabel 2 12 300 t else label (if tab == 3 then 34 else 3) 12 300 fg t
  let t := if tab == 4 then collectionLabel 5 12 316 t else label (if tab == 3 then 74 else 4) 12 316 fg t
  let t := if tab == 4 || tab == 1 then t else exportLabel t
  let t := label (load64 (st+176) t) 12 337 0xe0bd80 t
  let t := if tab != 4 || load64 (st+608) t == 0 then t else
    let t := fill 4 90 632 204 0x28475b t
    let t := collectionLabel 7 16 103 t
    let t := collectionLabel 3 16 136 t
    let t := byteNumber (load64 (st+616) t) 8 16 172 t
    let t := hex (load64 (st+624) t) 1 130 172 fg bg t
    let t := hex (load64 (st+632) t) 1 170 172 fg bg t
    collectionLabel 4 16 235 t
  let t := if load64 (st+208) t == 0 then t else
    let t := fill 4 90 632 204 0x28475b t
    let t := label 9 16 103 fg t
    let t := label 10 16 132 fg t
    let t := label 11 16 159 fg t
    let t := label 12 16 186 fg t
    let t := label 13 16 213 fg t
    label 8 16 248 fg t
  let t := if load64 (st+432) t != 4 then t else
    let t := fill 4 90 632 204 0x28475b t
    let t := label 70 16 103 fg t
    packRows (load64 (st+464) t/10*10) (load64 (st+472) t) 0 t
  upload surface 0 901120 0 (store64 (st+24) 0 t)

def connectProvider (slot t : UInt64) : UInt64 :=
  let p := peer slot
  let t := store64 (p+64) 1 t
  let r := Guest.NetworkSDK.openPeer slot t
  dirty (store64 (p+64) (if r == 64 && status r == 0 then 0 else 1) r)
partial def providerStatus (slot t : UInt64) : UInt64 :=
  if slot == 3 then t else
  let p := peer slot
  let t := if load64 (p+64) t == 0 then t else connectProvider slot t
  let r := Guest.NetworkSDK.inspectPeer slot t
  let phase := if r == 64 && status r == 0 then result r else 0
  let enrolled := r == 64 && status r == 0 && load64 (wire+56) r == 1 && load64 (wire+16) r != 0
  let changed := phase != load64 (p+56) r || (if enrolled then 1 else 0) != load64 (p+96) r
  let t := store64 (p+96) (if enrolled then 1 else 0) (store64 (p+56) phase r)
  let r := if !enrolled then t else Guest.NetworkSDK.callPeer slot 64 (header 15 0 0 0 0 0 0 t)
  let t := if r == 576 && status r == 0 then copy (wire+64) (p+128) 512 r else r
  providerStatus (slot+1) (if changed then dirty t else t)

def gameCurrent (t : UInt64) : UInt64 :=
  let who := load64 (st+168) t
  let r := syscall 125 who work 32 0 t
  if who == 0 || r != 32 || !eq work (selected r+1024+256) 32 r then error else who
-- One pending release per row bounds cleanup after a lost reply. A new
-- snapshot/recovery cannot overwrite that reference until release is confirmed.
@[noinline] def releaseSavePending (r t : UInt64) : UInt64 :=
  let h := load64 (r+112) t
  if h == 0 then t else
  let answer := Guest.LiveSDK.releaseReference h t
  if answer == 64 && (status answer == 0 || status answer == 3) then store64 (r+112) 0 answer else answer
@[noinline] def replaceGameSave (r h t : UInt64) : UInt64 :=
  let previous := load64 (r+96) t
  let t := store64 (r+96) h t
  let t := if previous == 0 || previous == h then t else releaseSavePending r (store64 (r+112) previous t)
  notice 61 t
@[noinline] partial def gameSave (t : UInt64) : UInt64 :=
  let t := releaseSavePending (selected t) t
  if load64 (st+400) t != 0 || load64 (selected t+112) t != 0 then notice 18 t else
  let who := gameCurrent t
  if who == error then notice 42 who else
  let r := Guest.GameSDK.exportSave who who
  if r != 64 || status r != 0 then notice 42 r else
    replaceGameSave (selected r) (result r) r
@[noinline] partial def gameLoad (t : UInt64) : UInt64 :=
  let who := gameCurrent t
  if who == error then notice 42 who else
  let save := load64 (selected who+96) who
  if save == 0 then notice 42 who else
  let r := Guest.LiveSDK.share save who 1 who
  if r != 64 || status r != 0 then notice 42 r else
  let saveScope := result r
  let r := Guest.GameSDK.loadSave who saveScope r
  let ok := r == 64 && status r == 0
  let t := Guest.LiveSDK.revoke save saveScope r
  notice (if ok then 16 else 42) t
@[noinline] partial def retainGameSave (t : UInt64) : UInt64 :=
  if load64 (st+400) t != 0 then notice 18 t else
  let save := load64 (selected t+96) t
  if save == 0 then notice 42 t else
  let r := Guest.LiveSDK.metadata save t
  if r != 96 || status r != 0 || load64 (wire+16) r != 192 then notice 42 r else
  let t := copy (wire+64) work 32 r
  let shell := syscall 97 4 0 0 0 t
  let r := Guest.LiveSDK.share save shell 25 shell
  if r != 64 || status r != 0 then notice 42 r else
  let saveScope := result r
  let t := nextId r
  let nonce := load64 (st+184) t
  let r := portal 11 saveScope nonce work 32 t
  if r != 64 || status r != 0 then notice 21 (Guest.LiveSDK.revoke save saveScope r) else
    dirty (store64 (st+400) nonce (store64 (st+408) (load64 (st+8) r+1) (store64 (st+416) 1 (store64 (st+424) saveScope r))))
@[noinline] partial def recoverGameSave (t : UInt64) : UInt64 :=
  let t := releaseSavePending (selected t) t
  if load64 (st+400) t != 0 || load64 (selected t+112) t != 0 then notice 18 t else
  let who := gameCurrent t
  if who == error then notice 42 who else
  let r := Guest.GameSDK.inspect who who
  if r != 160 || status r != 0 then notice 42 r else
  let t := copy (wire+64) work 32 r
  let t := nextId t
  let nonce := load64 (st+184) t
  let r := portal 12 0 nonce work 32 t
  if r != 64 || status r != 0 then notice 21 r else
    notice 39 (store64 (st+400) nonce (store64 (st+408) (load64 (st+8) r+1) (store64 (st+416) 2 r)))

def saveRecoveryPump (t : UInt64) : UInt64 :=
  if load64 (st+400) t == 0 then t else
  let r := portal 13 0 (load64 (st+400) t) 0 0 t
  if r != 64 then r else
  let state := load64 (wire+8) r
  if state < 2 then r else
  let recovered := load64 (wire+16) r
  let i := load64 (st+408) r-1
  let mode := load64 (st+416) r
  let t := store64 (st+400) 0 r
  if i >= 16 then notice 42 t else
  let t := if mode == 2 then t else Guest.LiveSDK.revoke (load64 (row i+96) t) (load64 (st+424) t) t
  if state != 2 then notice 21 t else
  if mode == 1 then notice 17 t else
  if recovered == 0 then notice 42 t else replaceGameSave (row i) recovered t

@[noinline] def removeLocal (t : UInt64) : UInt64 :=
  let r := selected t
  let t := releaseSavePending r t
  if load64 (st+400) t != 0 || load64 (st+376) t != 0 || load64 (r+112) t != 0 then notice 18 t else
  let h := load64 (r+16) t
  let t := if h == 0 then t else Guest.ContentSDK.release h t
  if h != 0 && (t != 64 || (status t != 0 && status t != 3)) then notice 18 t else
  let t := replaceGameSave r 0 t
  if load64 (r+112) t != 0 then notice 18 t else
  let h := load64 (r+8) t
  let t := store64 (r+112) h (store64 (r+8) 0 t)
  notice 44 (store64 (r+16) 0 (store64 (r+24) 0 (releaseSavePending r t)))

@[noinline] def exportIntent (t : UInt64) : UInt64 :=
  if ((syscall 34 (self t) 0 0 0 t) &&& 64) == 0 then notice 21 t else
  let content := load64 (selected t+16) t
  let r := Guest.ContentSDK.describe content t
  if r != 320 || status r != 0 || load64 (wire+16) r != 2 then notice 21 r else
  let length := load64 (wire+32) r
  let old := load64 (st+672) r
  let r := if old == 0 then r else Guest.ContentSDK.release old r
  let r := Guest.ContentSDK.share content (self r) r
  if r != 64 || status r != 0 then notice 21 r else
  let t := store64 (st+672) (result r) r
  let t := nextId t
  let t := store64 (st+664) (load64 (st+184) t) t
  let t := store64 (st+720) length t
  notice 22 (store64 (st+656) 1 (store64 (st+680) 0 (zero (st+688) 4 t)))

@[noinline] def regularInput (code t : UInt64) : UInt64 :=
  if code >= 59 && code <= 64 then dirty (store64 st (code-59) (store64 (st+232) 0 t)) else
  if load64 st t == 4 then collectionInput code t else
  if code == 53 then dirty (store64 (st+80) 1 t) else
  if code == 103 then dirty (store64 (st+8) (if load64 (st+8) t == 0 then 0 else load64 (st+8) t-1) t) else
  if code == 108 then dirty (store64 (st+8) (if load64 (st+8) t+1 < load64 (st+16) t then load64 (st+8) t+1 else load64 (st+8) t) t) else
  if code == 28 && load64 st t != 1 then dirty (store64 (st+232) (if load64 (st+232) t == 0 then 1 else 0) t) else
  if code == 16 then notice 66 (store64 (st+40) 1 (store64 (st+32) 0 t)) else
  if load64 st t == 1 then
    if code >= 2 && code <= 4 then dirty (store64 (st+336) (code-2) t) else
    if code == 28 then connectProvider (load64 (st+336) t) t else
    if code == 45 then
      let slot := load64 (st+336) t
      let t := Guest.NetworkSDK.removePeer slot t
      dirty (zero (peer slot) 128 t) else t
  else if code == 30 then add t else
  if code == 45 then exportIntent t else
  if code == 31 && load64 (selected t+8) t != 0 then
    subscribe t
  else if code == 34 then policy t else
  if code == 32 then queue (load64 (st+8) t) t else
  if code == 25 then pause t else
  if code == 46 then cancel t else
  if code == 20 then retry t else
  if code == 23 then install t else
  if code == 19 then retain t else
  if code == 22 then recoverRetained t else
  if code == 35 then bindProcess 1 t else
  if code == 36 then bindProcess 0 t else
  if code == 24 then bindProcess 2 t else
  if code == 37 then gameSave t else
  if code == 38 then gameLoad t else
  if code == 48 then retainGameSave t else
  if code == 49 then recoverGameSave t else
  if code == 50 then modBegin t else
  if code == 57 then play t else
  if code == 2 || code == 3 then dirty (store64 (st+136) (code-1) t) else
  if code == 111 then removeLocal t
  else t


def input (ev t : UInt64) : UInt64 :=
  let code := (ev >>> 32) &&& 65535
  if ev >>> 48 != 1 || (ev &&& 0xffffffff) != 1 then t else
  if load64 (st+432) t == 4 then
    if code == 1 then dirty (store64 (st+432) 0 t) else
    if code == 103 then dirty (store64 (st+464) (if load64 (st+464) t == 0 then 0 else load64 (st+464) t-1) t) else
    if code == 108 then dirty (store64 (st+464) (if load64 (st+464) t+1 < load64 (st+472) t then load64 (st+464) t+1 else load64 (st+464) t) t) else
    if code == 28 then modApply t else t
  else if load64 (st+208) t != 0 then
    if code == 28 then approvePolicy t else if code == 1 then dirty (store64 (st+208) 0 t) else t
  else if load64 (st+80) t != 0 then
    if code == 28 || code == 1 then dirty (store64 (st+80) 0 t) else
    let n := load64 (st+72) t
    if code == 14 then dirty (store64 (st+72) (if n == 0 then 0 else n-1) t) else
    let c := Guest.Keyboard.scanCode code 0
    if c < 32 || c > 126 || n >= 48 then t else dirty (store64 (st+72) (n+1) (store8 (0x6e0400+n) c t))
  else regularInput code t

@[noinline] def requestJobControl (token t : UInt64) : UInt64 :=
  let ji := load64 (command+8) t
  let action := load64 (command+16) t
  let provider := load64 (command+24) t
  let valid := ji < 4 && load64 (job ji) t != 0 && load64 (job ji+8) t < load64 (st+16) t &&
    action >= 1 && action <= 3 && (action != 2 || provider == 1 || provider == 2)
  let chosen := load64 (st+8) t
  let selectedProvider := load64 (st+136) t
  let t := if !valid then t else
    let t := store64 (st+8) (load64 (job ji+8) t) t
    let t := if action != 2 then t else store64 (st+136) provider t
    if action == 1 then pause t else if action == 2 then retry t else cancel t
  let t := store64 (st+8) chosen (store64 (st+136) selectedProvider t)
  reply token 64 (header (if valid then 0 else 2) ji (if valid then load64 (job ji) t else 0) 0 0 0 0 t)

@[noinline] def bindExport (token nonce state t : UInt64) : UInt64 :=
  if state == 2 && !eq (command+64) (st+688) 32 t then reply token 64 (header 2 0 0 0 0 0 0 t) else
  let r := if state == 2 then t else Guest.ContentSDK.share (load64 (st+672) t) (load64 incoming t) t
  if state == 1 && (r != 64 || status r != 0) then reply token 64 (header 1 0 0 0 0 0 0 r) else
  let t := if state == 2 then r else store64 (st+680) (result r) (copy (command+64) (st+688) 32 r)
  let t := store64 (st+656) 2 t
  reply token 64 (header 0 nonce (load64 (st+720) t) (load64 (st+680) t) 2 0 0 t)

@[noinline] def exportRequest (token op n t : UInt64) : UInt64 :=
  let nonce := load64 (command+8) t
  let state := load64 (st+656) t
  if op == 725 && n == 96 && nonce == 0 then
    reply token 64 (header 0 (load64 (st+664) t) (load64 (st+720) t) 0 state 0 0 t)
  else if nonce == 0 || nonce != load64 (st+664) t || state == 0 then reply token 64 (header 3 0 0 0 0 0 0 t)
  else if op == 726 && n == 96 && state == 3 then reply token 64 (header 0 nonce 0 0 3 0 0 t)
  else if op == 726 && n == 96 && state == 2 then
    let r := Guest.ContentSDK.release (load64 (st+672) t) t
    reply token 64 (header 0 nonce 0 0 3 0 0 (dirty (store64 (st+656) 3 (store64 (st+672) 0 r))))
  else if op == 725 && n == 128 && (state == 1 || state == 2) && !Guest.ContentFormat.allZero (command+64) 32 t then
    bindExport token nonce state t
  else reply token 64 (header 2 0 0 0 0 0 0 t)

@[noinline] def policyRequest (token n t : UInt64) : UInt64 :=
  if n != 160 then reply token 64 (header 2 0 0 0 0 0 0 t) else
  let action := load64 (command+8) t
  let mode := load64 (command+32) t
  let requested := load64 (command+48) t
  if mode != 3 || action < 1 || action > 3 || (Guest.ContentFormat.allZero (command+64) 32 t || Guest.ContentFormat.allZero (command+96) 32 t) then
    reply token 64 (header 2 0 0 0 0 0 0 t) else
  let ci := Guest.LibraryCollections.select (command+64) (command+96) t
  if ci == error then reply token 64 (header 4 0 0 0 0 0 0 ci) else
  let p := Guest.LibraryCollections.record ci
  if requested != 0 && requested != load64 (p+8) ci then reply token 64 (header 3 ci 0 0 0 0 0 ci) else
  let t := if action == 2 then store64 (p+16) (if load64 (command+16) ci == 0 then 0 else 1) ci else
    let t := retirePolicy ci 0 ci
    if action == 3 then Guest.LibraryCollections.revoke ci t else
      Guest.LibraryCollections.approve ci (load64 (command+16) t) (load64 (command+24) t) (load64 (command+40) t) t
  if t == error then reply token 64 (header 2 ci 0 0 0 0 0 t) else
    reply token 64 (header 0 ci (load64 (p+8) t) (load64 (p+16) t) (load64 (p+24) t) (load64 (p+56) t) 0 (dirty t))

@[noinline] def collectionRequest (token op n t : UInt64) : UInt64 :=
  if op == 724 && n == 96 then
    let t := restoreSelection (load64 (command+8) t) (load64 (command+16) t) t
    let t := if load64 (st+176) t != 17 then t else store64 (selected t+120) (load64 (command+24) t) t
    reply token 64 (header (if load64 (st+176) t == 17 then 0 else 5) (load64 (st+8) t) 0 0 0 0 0 t)
  else if op == 723 && n == 608 then
    let ci := load64 (command+8) t
    if ci >= Guest.LibraryCollections.count || !Guest.PrivateRecords.validPolicy (command+64) t then reply token 64 (header 2 0 0 0 0 0 0 t) else
    let t := retirePolicy ci 0 t
    let t := copy (command+64) (Guest.LibraryCollections.record ci) 512 t
    let t := Guest.LibraryCollections.recovered ci t
    reply token 64 (header 0 ci 0 0 0 0 0 (dirty t))
  else if op == 722 && n == 96 then
    let ci := load64 (command+8) t
    if ci >= Guest.LibraryCollections.count || load64 (Guest.LibraryCollections.record ci) t != 1 then reply token 64 (header 2 0 0 0 0 0 0 t) else
    let t := store64 (Guest.LibraryCollections.record ci+128) (load64 (command+16) t) t
    reply token 64 (header 0 ci 0 0 0 0 0 t)
  else if op == 721 && n == 96 then
    let i := load64 (command+8) t
    let valid := i < Guest.LibraryCollections.count
    let t := header (if valid then 0 else 2) i 0 0 0 0 0 t
    reply token (if valid then 576 else 64) (if valid then
      let t := copy (Guest.LibraryCollections.record i) (wire+64) 512 t
      let t := store64 (wire+64+128) 0 t
      store64 (wire+64+152) 0 t
    else t)
  else if op == 720 then policyRequest token n t
  else reply token 64 (header 2 0 0 0 0 0 0 t)

@[noinline] def configureRequest (caller op n t : UInt64) : UInt64 :=
  let t := if (caller &&& 255) == 1 && n == 128 && op == 700 then
      let t := copy (command+64) (st+256) 32 t
      store64 (st+224) 1 t
    else if (caller &&& 255) == 1 && n == 160 && op == 706 && load64 (command+16) t > 0 && load64 (command+16) t <= Guest.ContentFormat.maxBytes then
      let t := copy (command+64) (st+256) 64 t
      let ci := Guest.LibraryCollections.select (command+96) (command+64) t
      let t := if ci == error then ci else Guest.LibraryCollections.approve ci (load64 (command+16) ci) 2 0 ci
      let t := store64 (st+112) (load64 (command+16) t) t
      let t := store64 (st+224) 1 t
      let t := store64 (st+88) 1 t
      let t := store64 (st+96) 1 t
      let t := store64 (st+104) 2 t
      let t := store64 (st+128) (load64 (st+128) t+1) t
      store64 (st+40) 1 t
    else if (caller &&& 255) == 1 && n == 96 && op == 702 then
      store64 (st+160) (load64 (command+8) t) (store64 (st+168) (load64 (command+16) t) t)
    else t
  t

def request (n t : UInt64) : UInt64 :=
  let token := load64 (incoming+8) t
  let op := load64 command t
  let caller := load64 incoming t
  let t := configureRequest caller op n t
  let admin := (caller &&& 255) == 1
  if admin && (op == 725 || op == 726) then exportRequest token op n t
  else if admin && (op >= 720 && op <= 724) then collectionRequest token op n t
  else if admin && n == 96 && op == 708 then
    let ji := load64 (command+8) t
    let handle := if ji < 4 then load64 (job ji+48) t else 0
    let r := if handle == 0 then error else Guest.ContentSDK.inspectJob handle t
    if r != 64 then reply token 64 (header 1 0 0 0 0 0 0 r) else
      let t := copy wire work 64 r
      let t := header 0 ji 0 0 0 0 0 t
      reply token 128 (copy work (wire+64) 64 t)
  else if admin && n == 96 && op == 707 then
    requestJobControl token t
  else if admin && n == 96 && (op == 703 || op == 704) then
    let i := load64 (command+8) t
    let off := load64 (command+16) t
    let count := load64 (command+24) t
    let valid := i < (if op == 703 then load64 (st+16) t else 4) && off <= 2048 && count <= 640 && count <= 2048-off
    let t := header (if valid then 0 else 2) i off count 0 0 0 t
    let t := if valid then copy ((if op == 703 then row i else job i)+off) (wire+64) count t else t
    reply token (if valid then 64+count else 64) t
  else if admin && n == 96 && op == 705 then
    let i := load64 (command+8) t
    let r := if i >= load64 (st+16) t then error else Guest.ContentSDK.share (load64 (row i+16) t) caller t
    reply token 64 (if r == 64 then r else header 1 0 0 0 0 0 0 r)
  else
    let t := header (if op == 700 || op == 701 || op == 702 || op == 706 then 0 else 2) (load64 (st+16) t) (load64 (st+8) t) (load64 (st+88) t) (load64 (st+96) t) (load64 (st+120) t) (load64 (st+176) t) t
    let t := copy st (wire+64) 640 t
    reply token 704 t

partial def transferActive (i t : UInt64) : Bool :=
  if i == 4 then false else
  (load64 (job i) t > 0 && load64 (job i) t < 10) || transferActive (i+1) t
partial def loop (surface initial : UInt64) : UInt64 :=
  let n := syscall 36 (self initial) incoming 1024 0 initial
  let t := if n >= 96 && n <= 1024 then request n n else n
  let ev := syscall 90 surface 0 0 0 t
  let t := input ev ev
  let t := receivePeers 0 (store64 (st+640) 0 t)
  let t := catalogPump t
  let t := jobsPump 0 t
  let t := installPump t
  let t := fetchPump t
  let t := packScan t
  let t := vaultPump t
  let t := saveRecoveryPump t
  let now := Guest.WaitSDK.now t
  let t := if now >= load64 (st+344) now then providerStatus 0 (store64 (st+344) (now+100) now) else now
  let t := if now >= load64 (st+352) t && (load64 (st+40) t != 0 || load64 (st+376) t != 0) then dirty (store64 (st+352) (now+20) t) else t
  let t := if load64 (st+24) t == 0 then t else draw surface t
  let active := load64 (st+40) t != 0 || transferActive 0 t || load64 (st+376) t != 0 || load64 (st+400) t != 0 || load64 (st+536) t != 0
  let ready := load64 (st+640) t == 1 && load64 (st+648) t < 4
  let t := store64 (st+648) (if ready then load64 (st+648) t+1 else 0) t
  let next := Guest.WaitSDK.now t+(if ready then 0 else if active then 1 else 100)
  loop surface (Guest.WaitSDK.deadline next t)
def main (initial : UInt64) : UInt64 :=
  let t := zero st 1024 initial
  let t := zero 0x700000 20480 t
  let t := zero Guest.LibraryCollections.base 512 t
  let t := store64 (st+136) 1 t
  let t := store64 (st+112) 6029312 t
  let t := store64 (st+176) 38 t
  let t := store64 (st+184) (self t <<< 24) t
  let surface := syscall 80 0 0 0 0 t
  if surface == error then error else loop surface (draw surface surface)
-- Operator-selected headless acquisition uses exactly the same catalog,
-- policy, chunk validator and provider protocol as the graphical application.
-- No input/display authority and no host source/payload are needed to acquire.
partial def headlessLoop (initial : UInt64) : UInt64 :=
  let n := syscall 36 (self initial) incoming 1024 0 initial
  let t := if n >= 96 && n <= 1024 then request n n else n
  let t := receivePeers 0 (store64 (st+640) 0 t)
  let t := catalogPump t
  let t := jobsPump 0 t
  let now := Guest.WaitSDK.now t
  let t := if now >= load64 (st+344) now then providerStatus 0 (store64 (st+344) (now+100) now) else now
  let active := load64 (st+40) t != 0 || transferActive 0 t
  let ready := load64 (st+640) t == 1 && load64 (st+648) t < 4
  let t := store64 (st+648) (if ready then load64 (st+648) t+1 else 0) t
  headlessLoop (Guest.WaitSDK.deadline (Guest.WaitSDK.now t+(if ready then 0 else if active then 1 else 100)) t)
def headlessMain (initial : UInt64) : UInt64 :=
  let t := zero st 1024 initial
  let t := zero 0x700000 20480 t
  let t := zero Guest.LibraryCollections.base 512 t
  let t := store64 (st+136) 1 t
  let t := store64 (st+184) (self t <<< 24) t
  headlessLoop t
end Guest.Library
