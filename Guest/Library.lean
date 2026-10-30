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
partial def label0 (id x y color t : UInt64) : UInt64 :=
  if id == 0 then
    let t := store64 (0x414000+0) 5281631927840621900 t
    let t := store64 (0x414000+8) 383632101954 t
    text 0x414000 13 x y color bg t
  else if id == 1 then
    let t := store64 (0x414000+0) 7809651189923983686 t
    let t := store64 (0x414000+8) 5773669999057069935 t
    let t := store64 (0x414000+16) 8318822943647231858 t
    let t := store64 (0x414000+24) 7310838768846905376 t
    let t := store64 (0x414000+32) 5125153851738973557 t
    let t := store64 (0x414000+40) 2319107656866164065 t
    let t := store64 (0x414000+48) 114776330036563 t
    text 0x414000 54 x y color bg t
  else if id == 2 then
    let t := store64 (0x414000+0) 8388363463661282640 t
    let t := store64 (0x414000+8) 2334111870320076140 t
    let t := store64 (0x414000+16) 2340029477534397809 t
    let t := store64 (0x414000+24) 7955443209958945377 t
    let t := store64 (0x414000+32) 7883939740836193381 t
    let t := store64 (0x414000+40) 7095809806264449907 t
    let t := store64 (0x414000+48) 8314037906472395617 t
    let t := store64 (0x414000+56) 5567381664665268853 t
    text 0x414000 64 x y color bg t
  else if id == 3 then
    let t := store64 (0x414000+0) 5989823119953567809 t
    let t := store64 (0x414000+8) 8245937438911843616 t
    let t := store64 (0x414000+16) 8031172958083293216 t
    let t := store64 (0x414000+24) 2340010785837641760 t
    let t := store64 (0x414000+32) 7599104617365914656 t
    let t := store64 (0x414000+40) 7588600870562981234 t
    let t := store64 (0x414000+48) 5917813770744242286 t
    let t := store64 (0x414000+56) 435778710885 t
    text 0x414000 61 x y color bg t
  else if id == 4 then
    let t := store64 (0x414000+0) 8315178071121600593 t
    let t := store64 (0x414000+8) 7020074018743001192 t
    let t := store64 (0x414000+16) 4706353008050595193 t
    let t := store64 (0x414000+24) 2340008599224337731 t
    let t := store64 (0x414000+32) 7593478425241735712 t
    let t := store64 (0x414000+40) 7162221081223241838 t
    let t := store64 (0x414000+48) 3409260241649759855 t
    let t := store64 (0x414000+56) 5517123 t
    text 0x414000 59 x y color bg t
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
    let t := store64 (0x414000+0) 8243105097092919888 t
    let t := store64 (0x414000+8) 2322295501785690912 t
    let t := store64 (0x414000+16) 8751185064972739954 t
    let t := store64 (0x414000+24) 7234299921575981088 t
    let t := store64 (0x414000+32) 2334111870315733107 t
    let t := store64 (0x414000+40) 7162256579379608370 t
    let t := store64 (0x414000+48) 7597414673048477812 t
    let t := store64 (0x414000+56) 7598532952375653486 t
    let t := store64 (0x414000+64) 6646882 t
    text 0x414000 67 x y color bg t
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
  else if id == 8 then
    let t := store64 (0x414000+0) 7885649520038539086 t
    let t := store64 (0x414000+8) 8387235364479792225 t
    let t := store64 (0x414000+16) 2318912282932047461 t
    let t := store64 (0x414000+24) 7953753191868164432 t
    let t := store64 (0x414000+32) 7163386859017692519 t
    let t := store64 (0x414000+40) 7310028429769795956 t
    let t := store64 (0x414000+48) 2334381307661018470 t
    let t := store64 (0x414000+56) 199605644911 t
    text 0x414000 61 x y color bg t
  else if id == 9 then
    let t := store64 (0x414000+0) 2334402202894889025 t
    let t := store64 (0x414000+8) 2334101988909084514 t
    let t := store64 (0x414000+16) 7598805593930102113 t
    let t := store64 (0x414000+24) 8316307316775395427 t
    let t := store64 (0x414000+32) 4981050931419903081 t
    let t := store64 (0x414000+40) 8102082521086645326 t
    let t := store64 (0x414000+48) 4981046554681306994 t
    let t := store64 (0x414000+56) 7305804385079018323 t
    let t := store64 (0x414000+64) 29548 t
    text 0x414000 66 x y color bg t
  else if id == 10 then
    let t := store64 (0x414000+0) 2338324109331885907 t
    let t := store64 (0x414000+8) 3615037497570321779 t
    let t := store64 (0x414000+16) 8386658447326912571 t
    let t := store64 (0x414000+24) 8243105079639434341 t
    let t := store64 (0x414000+32) 7286889542587085921 t
    let t := store64 (0x414000+40) 7234316402863268718 t
    let t := store64 (0x414000+48) 8029109356424684064 t
    let t := store64 (0x414000+56) 3368292 t
    text 0x414000 59 x y color bg t
  else if id == 11 then
    let t := store64 (0x414000+0) 8820707168001226049 t
    let t := store64 (0x414000+8) 5773667787737097317 t
    let t := store64 (0x414000+16) 8246126356433489219 t
    let t := store64 (0x414000+24) 7310594678324553317 t
    let t := store64 (0x414000+32) 7594585336717469042 t
    let t := store64 (0x414000+40) 3616450013580650860 t
    let t := store64 (0x414000+48) 8392847271002190649 t
    let t := store64 (0x414000+56) 29541 t
    text 0x414000 58 x y color bg t
  else if id == 12 then
    let t := store64 (0x414000+0) 4706900758732755013 t
    let t := store64 (0x414000+8) 7022640558675868492 t
    let t := store64 (0x414000+16) 4285582364663488620 t
    let t := store64 (0x414000+24) 7742373268247899680 t
    let t := store64 (0x414000+32) 7453010347690386208 t
    let t := store64 (0x414000+40) 7309377664828913201 t
    let t := store64 (0x414000+48) 7431065164980428914 t
    let t := store64 (0x414000+56) 1953390962 t
    text 0x414000 60 x y color bg t
  else if id == 13 then
    let t := store64 (0x414000+0) 7020677651101545798 t
    let t := store64 (0x414000+8) 7308324465885667702 t
    let t := store64 (0x414000+16) 3201618883719929902 t
    let t := store64 (0x414000+24) 7236828443317988640 t
    let t := store64 (0x414000+32) 7310575256332300320 t
    let t := store64 (0x414000+40) 8243122732211659552 t
    let t := store64 (0x414000+48) 7811882189719500064 t
    let t := store64 (0x414000+56) 199270097505 t
    text 0x414000 61 x y color bg t
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
    let t := store64 (0x414000+0) 7234316402526741345 t
    let t := store64 (0x414000+8) 7310012263327687712 t
    let t := store64 (0x414000+16) 8388354946792235108 t
    let t := store64 (0x414000+24) 7237112413330357113 t
    let t := store64 (0x414000+32) 7236270204636914789 t
    let t := store64 (0x414000+40) 7308044107532935283 t
    let t := store64 (0x414000+48) 2338042707166961764 t
    let t := store64 (0x414000+56) 8388362677733385057 t
    let t := store64 (0x414000+64) 7237481 t
    text 0x414000 67 x y color bg t
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
    let t := store64 (0x414000+0) 8247626254411852115 t
    let t := store64 (0x414000+8) 8319108855239880549 t
    let t := store64 (0x414000+16) 8295757408969322345 t
    let t := store64 (0x414000+24) 2334399943741108325 t
    let t := store64 (0x414000+32) 7165064418700522086 t
    let t := store64 (0x414000+40) 8458716092899028065 t
    let t := store64 (0x414000+48) 8102082521559165300 t
    let t := store64 (0x414000+56) 465491619698 t
    text 0x414000 61 x y color bg t
  else if id == 36 then
    let t := store64 (0x414000+0) 6998727288811188048 t
    let t := store64 (0x414000+8) 2334102066235076720 t
    let t := store64 (0x414000+16) 8461539573182394214 t
    let t := store64 (0x414000+24) 8101729874644984180 t
    let t := store64 (0x414000+32) 8317708060514677349 t
    let t := store64 (0x414000+40) 8386658447326912571 t
    let t := store64 (0x414000+48) 7957404669984010089 t
    let t := store64 (0x414000+56) 8241996772119966831 t
    let t := store64 (0x414000+64) 7882821570751915367 t
    text 0x414000 72 x y color bg t
  else if id == 37 then
    let t := store64 (0x414000+0) 8243105097092919888 t
    let t := store64 (0x414000+8) 7811882189719500064 t
    let t := store64 (0x414000+16) 7521891242115621473 t
    let t := store64 (0x414000+24) 8391720272443699055 t
    let t := store64 (0x414000+32) 2334102083314282344 t
    let t := store64 (0x414000+40) 8386105418748030049 t
    let t := store64 (0x414000+48) 6998648999207335529 t
    let t := store64 (0x414000+56) 8387235364223345774 t
    let t := store64 (0x414000+64) 31090 t
    text 0x414000 66 x y color bg t
  else if id == 38 then
    let t := store64 (0x414000+0) 7598807758542761795 t
    let t := store64 (0x414000+8) 7310575247904763503 t
    let t := store64 (0x414000+16) 7161113873270858016 t
    let t := store64 (0x414000+24) 2334397743343297896 t
    let t := store64 (0x414000+32) 7308332243887091574 t
    let t := store64 (0x414000+40) 7286943397266224416 t
    let t := store64 (0x414000+48) 2338609982203523192 t
    let t := store64 (0x414000+56) 2338340601787474511 t
    let t := store64 (0x414000+64) 7809653449870569569 t
    text 0x414000 72 x y color bg t
  else if id == 39 then
    let t := store64 (0x414000+0) 6061921335340450126 t
    let t := store64 (0x414000+8) 4692825876278236498 t
    let t := store64 (0x414000+16) 2327306946397491280 t
    let t := store64 (0x414000+24) 4919428642889614674 t
    text 0x414000 32 x y color bg t
  else if id == 40 then
    let t := store64 (0x414000+0) 7234316346692756819 t
    let t := store64 (0x414000+8) 8247343714165682720 t
    let t := store64 (0x414000+16) 8029390865575714937 t
    let t := store64 (0x414000+24) 8295745358448977440 t
    let t := store64 (0x414000+32) 7596482287037736809 t
    let t := store64 (0x414000+40) 8027139014440612979 t
    let t := store64 (0x414000+48) 7142835905570807922 t
    let t := store64 (0x414000+56) 491496108661 t
    text 0x414000 61 x y color bg t
  else if id == 41 then
    let t := store64 (0x414000+0) 8028075781016806739 t
    let t := store64 (0x414000+8) 8029390865575714926 t
    let t := store64 (0x414000+16) 8749487341609905184 t
    let t := store64 (0x414000+24) 7089066488320385312 t
    let t := store64 (0x414000+32) 7310589519812650348 t
    let t := store64 (0x414000+40) 29806 t
    text 0x414000 42 x y color bg t
  else if id == 42 then
    let t := store64 (0x414000+0) 7308623593077498189 t
    let t := store64 (0x414000+8) 7954892334483841124 t
    let t := store64 (0x414000+16) 7162240872924258420 t
    let t := store64 (0x414000+24) 4850412414248837484 t
    let t := store64 (0x414000+32) 8247625154749603917 t
    let t := store64 (0x414000+40) 7214893546953076069 t
    let t := store64 (0x414000+48) 491327481449 t
    text 0x414000 53 x y color bg t
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
    let t := store64 (0x414000+8) 7163375908187827823 t
    let t := store64 (0x414000+16) 8531350552824062073 t
    let t := store64 (0x414000+24) 8462580614265400175 t
    let t := store64 (0x414000+32) 8170480940731430245 t
    let t := store64 (0x414000+40) 7957695015293249909 t
    let t := store64 (0x414000+48) 28259044236029984 t
    text 0x414000 55 x y color bg t
  else if id == 58 then
    let t := store64 (0x414000+0) 8103230749690118992 t
    let t := store64 (0x414000+8) 7019813714331202677 t
    let t := store64 (0x414000+16) 2338621054691337575 t
    let t := store64 (0x414000+24) 7597131072125560162 t
    let t := store64 (0x414000+32) 8295740938855147374 t
    let t := store64 (0x414000+40) 28259048229268581 t
    text 0x414000 47 x y color bg t
  else if id == 61 then
    let t := store64 (0x414000+0) 7665811700669899091 t
    let t := store64 (0x414000+8) 8387235364748944229 t
    let t := store64 (0x414000+16) 8749489599638563169 t
    let t := store64 (0x414000+24) 6998719601003880736 t
    let t := store64 (0x414000+32) 8386109743963665184 t
    let t := store64 (0x414000+40) 8386658438684287077 t
    let t := store64 (0x414000+48) 8534165646137696371 t
    let t := store64 (0x414000+56) 27745 t
    text 0x414000 58 x y color bg t
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
    let t := store64 (0x414000+16) 7310309144435826798 t
    let t := store64 (0x414000+24) 7311142561566699040 t
    let t := store64 (0x414000+32) 7310589338300740460 t
    let t := store64 (0x414000+40) 2318338277832925298 t
    let t := store64 (0x414000+48) 7164771135566082885 t
    let t := store64 (0x414000+56) 27749 t
    text 0x414000 58 x y color bg t
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

def current (descriptor expected t : UInt64) : UInt64 :=
  let r := Guest.RegistrySDK.current descriptor expected t
  if r == 64 && status r == 2 then Guest.RegistrySDK.verify descriptor expected r else r
def nextId (t : UInt64) : UInt64 := store64 (st+184) (load64 (st+184) t+1) t
-- A grant is made only for a separately verified selected enrollment and the
-- immutable federation/manifest root. No local capability is sent to the peer.
def ensureGrant (slot root t : UInt64) : UInt64 :=
  let p := peer slot
  if load64 p t != 0 && eq (p+768) root 32 t then t else
  let r := Guest.NetworkSDK.inspectPeer slot t
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
  let r := Guest.LibraryPeerSDK.grant slot work (if slot == 0 then 1 else load64 root t ||| 1) 16777216 100000 t
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
def acceptMetadata (t : UInt64) : UInt64 :=
  let classification := load64 (metadata+16) t
  if !Guest.RegistrySDK.consumerAdmitted classification || !Guest.ConsumerFormat.valid (metadata+768) t then notice 29 t else
  let t := hash (metadata+768) 768 hashOut t
  if !eq hashOut (metadata+400) 32 t then notice 29 t else
  let r := Guest.RegistrySDK.verify metadata (metadata+320) t
  if r != 832 || status r != 0 || !Guest.RegistrySDK.consumerAdmitted (result r) then notice 29 r else
  let old := findEdition (metadata+768+160) 0 r
  let i := if old == error then load64 (st+16) r else old
  if i >= 16 then notice 21 r else
  if old != error && load64 (row i+256+48) r >= load64 (metadata+48) r then r else
  let t := if old == error then zero (row i) 256 r else r
  let t := copy metadata (row i+256) 1536 t
  let t := store64 (row i) 1 t
  let t := if old == error then store64 (st+16) (i+1) t else t
  notice 14 t
partial def freeJob (i t : UInt64) : UInt64 :=
  if i == 4 then error else if load64 (job i) t == 0 || load64 (job i) t == 10 || load64 (job i) t >= 12 then i else freeJob (i+1) t
def queue (i t : UInt64) : UInt64 :=
  if i >= load64 (st+16) t then t else
  let m := consumer i
  let existing := load64 (row i+64) t
  if existing > 0 && existing <= 4 && load64 (job (existing-1)) t != 13 && load64 (job (existing-1)) t != 14 then notice 18 t else
  let fresh := current (row i+256) (row i+256+320) t
  if fresh != 832 || status fresh != 0 || !Guest.RegistrySDK.consumerAdmitted (result fresh) then notice 54 fresh else
  if load64 (m+16) t != 1 then notice 34 t else
  if load64 (st+96) t != 1 then notice 21 (store64 (st+208) 1 t) else
  if !eq (m+96) (st+288) 32 t || load64 (m+408) t > load64 (st+112) t ||
    load64 (st+120) t > load64 (st+112) t-load64 (m+408) t then notice 21 t else
  let ji := freeJob 0 t
  if ji == error then notice 21 ji else
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
  let t := store64 (j+16) (load64 (st+136) t) t
  let t := if load64 (row i+48) t != 2 then t else store64 (j+24) (load64 (row i+16) t) t
  let t := store64 (j+64) (load64 (st+128) t) t
  let t := store64 (j+72) (load64 (st+112) t) t
  let t := nextId t
  let t := store64 (j+80) (load64 (st+184) t) t
  let t := store64 (j+104) 3 t
  let t := store64 (j+112) (load64 (st+104) t) t
  let t := store64 (row i+64) (ji+1) t
  let t := store64 (st+120) (load64 (st+120) t+load64 (m+408) t) t
  notice 36 t
-- Rules use stable collection/item identities. Claims remain unmeasured until
-- the completed local WAV parser checks actual rate/channels/frame count.
def eligible (i t : UInt64) : Bool :=
  load64 (consumer i+16) t == 1 && eq (consumer i+96) (st+288) 32 t &&
  load64 (consumer i+408) t <= load64 (st+112) t
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
def monitorDecision (t : UInt64) : UInt64 :=
  if load64 (st+88) t == 0 then t else
  let chosen := best 0 error t
  let t := reasons 0 chosen t
  if chosen == error || load64 (st+96) t == 0 then dirty t else queue chosen t

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

def seedReply (ji operation code t : UInt64) : UInt64 :=
  if ji >= 4 then t else
  let j := job ji
  if load64 j t == 11 || load64 j t >= 12 then t else
  if code != 0 then notice 37 (store64 j 12 (store64 (j+96) code t)) else
  let n := load64 (wire+16) t-64
  if operation == 3 then
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
    let r := Guest.ContentSDK.reserve work (load64 (j+80) t) (load64 (j+72) t) 3 0 t
    if r != 64 || status r != 0 then notice 21 (store64 j 14 r) else
      let t := store64 (j+24) (result r) r
      let t := store64 (row (load64 (j+8) t)+16) (result t) t
      dirty (store64 j 3 t)
  else if operation == 4 then
    if n < 32 || n > 384 then notice 42 (store64 j 12 t) else
    let t := copy Guest.LibraryPeerSDK.data work n t
    let r := Guest.ContentSDK.beginChunk (load64 (j+24) t) (load64 (j+32) t) work n t
    if r != 64 || status r != 0 then jobFailure j r else
    if result r == 0 && load64 (wire+16) r == 4 then
      store64 (j+32) (load64 (j+32) r+1) (store64 j 3 r)
    else store64 (j+48) (result r) (store64 (j+40) 0 (store64 j 5 r))
  else if operation == 5 then
    let total := Guest.ContentFormat.chunkLength (load64 (j+512+408) t) (load64 (j+32) t)
    let offset := load64 (j+40) t
    if n == 0 || n > 512 || offset > total || n > total-offset then notice 42 (store64 j 12 t) else
    let t := copy Guest.LibraryPeerSDK.data work n t
    let r := Guest.ContentSDK.append (load64 (j+48) t) offset work n t
    if r != 64 || status r != 0 then jobFailure j r else
    let t := store64 (j+40) (offset+n) r
    let t := store64 (j+56) (load64 (j+32) t*4096+offset+n) t
    if offset+n < total then store64 j 5 t else
      let r := Guest.ContentSDK.validate (load64 (j+48) t) t
      if r != 64 || status r != 0 then jobFailure j r else store64 j 7 r
  else t
partial def receivePeers (slot t : UInt64) : UInt64 :=
  if slot == 3 then t else
  let p := peer slot
  let op := load64 (p+16) t
  if op == 0 || load64 p t == 0 then receivePeers (slot+1) t else
  let r := Guest.LibraryPeerSDK.receive slot (load64 p t) t
  let id := load64 (p+8) r
  let t := if Guest.LibraryPeerSDK.valid op id r then
    let code := Guest.LibraryPeerSDK.remoteStatus r
    let t := store64 (p+16) 0 r
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

def catalogPump (t : UInt64) : UInt64 :=
  if load64 (st+224) t == 0 || load64 (peer 0+16) t != 0 then t else
  let phase := load64 (st+40) t
  if phase == 1 then issue 0 0 1 (load64 (st+32) t) 0 0 t else
  if phase == 2 then
    let off := load64 (st+56) t
    issue 0 0 2 (load64 (st+48) t) off (if 1536-off > 640 then 640 else 1536-off) t
  else if load64 (st+88) t != 0 && Guest.WaitSDK.now t >= load64 (st+192) t then
    store64 (st+40) 1 (store64 (st+32) 0 t) else t

def jobPump (ji t : UInt64) : UInt64 :=
  let j := job ji
  let phase := load64 j t
  let slot := load64 (j+16) t
  if phase == 0 || phase >= 10 then t else
  let checked := if phase == 3 || phase == 8 then current (j+1280) (j+1280+320) t else t
  let revoked := (phase == 3 || phase == 8) && (checked != 832 || status checked != 0 || !Guest.RegistrySDK.consumerAdmitted (result checked))
  if load64 (st+96) checked == 0 || load64 (j+64) checked != load64 (st+128) checked || revoked then
    let h := load64 (j+48) checked
    let t := if h == 0 then checked else Guest.ContentSDK.control h 3 checked
    let t := if h == 0 then t else Guest.ContentSDK.control h 4 t
    let content := load64 (j+24) t
    let t := if content == 0 then t else Guest.ContentSDK.revokeAcquisition content t
    notice 54 (store64 j 14 (store64 (j+48) 0 t))
  else
  if phase == 1 then issue slot ji 3 0 0 0 t else
  if phase == 3 then
    if load64 (j+32) t >= load64 (j+160) t then store64 j 8 t else issue slot ji 4 (load64 (j+32) t) 0 0 t
  else if phase == 5 then
    let remaining := Guest.ContentFormat.chunkLength (load64 (j+512+408) t) (load64 (j+32) t)-load64 (j+40) t
    issue slot ji 5 (load64 (j+32) t*4096+load64 (j+40) t) (if remaining > 512 then 512 else remaining) 0 t
  else if phase == 7 || phase == 9 then
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
  else if phase == 8 then
    let r := Guest.ContentSDK.publish (load64 (j+24) t) t
    if r != 64 || status r != 0 then jobFailure j r else
    store64 (j+48) (result r) (store64 j 9 r)
  else t
partial def jobsPump (i t : UInt64) : UInt64 :=
  if i == 4 then t else jobsPump (i+1) (jobPump i t)
-- Small native collection references are immutable Objects only after Add.
-- They contain selected signed metadata, never session keys or transport grants.
partial def appendSmall (h source length off t : UInt64) : UInt64 :=
  if off == length then t else
  let n := if length-off > 512 then 512 else length-off
  let r := Guest.LiveSDK.append h off (source+off) n t
  if r != 64 || status r != 0 then error else appendSmall h source length (off+n) r
def add (t : UInt64) : UInt64 :=
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
def policy (t : UInt64) : UInt64 :=
  if load64 (selected t) t == 0 then t else
  let t := store64 (st+216) (load64 (st+8) t+1) t
  notice 9 (store64 (st+208) 1 t)
-- Replacing the consent generation first revokes every unfinished operation.
-- Paused jobs also own staging state and must not retain the previous grant.
partial def retirePolicy (i t : UInt64) : UInt64 :=
  if i == 4 then t else
  let j := job i
  let phase := load64 j t
  let t := if phase == 0 || phase == 10 || phase == 13 || phase == 14 then t else
    let h := load64 (j+48) t
    let t := if h == 0 then t else Guest.ContentSDK.control h 3 t
    let t := if h == 0 then t else Guest.ContentSDK.control h 4 t
    let content := load64 (j+24) t
    let t := if content == 0 then t else Guest.ContentSDK.revokeAcquisition content t
    store64 j 14 (store64 (j+48) 0 t)
  retirePolicy (i+1) t
def approvePolicy (t : UInt64) : UInt64 :=
  let t := retirePolicy 0 t
  let chosen := load64 (st+216) t-1
  if chosen >= load64 (st+16) t then notice 21 (store64 (st+208) 0 t) else
  let t := copy (consumer chosen+96) (st+288) 32 t
  let t := store64 (st+208) 0 t
  let t := store64 (st+88) 1 t
  let t := store64 (st+96) 1 t
  let t := store64 (st+104) 6 t
  let t := store64 (st+112) 6029312 t
  let t := store64 (st+120) 0 t
  let t := store64 (st+128) (load64 (st+128) t+1) t
  monitorDecision (notice 36 t)
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
  if load64 (j+64) t != load64 (st+128) t || load64 (st+96) t == 0 then notice 69 t else
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
  if !currentOK && !(load64 (r+48) checked == 1 && unavailable) then notice 54 checked else
  if player == 0 then notice 58 t else
  if (load64 (r+24) t != 2 && load64 (r+24) t != 3) || load64 (r+16) t == 0 then notice 41 t else
  let answer := Guest.ContentSDK.share (load64 (r+16) t) player t
  if answer != 64 || status answer != 0 then notice 41 answer else
  let t := header 600 (result answer) (load64 (r+1024+424) answer) (load64 (r+1024+416) answer) 0 0 0 answer
  let answer := syscall 30 player wire 64 1024 t
  if answer != 64 || status answer != 0 || load64 (wire+16) answer == 6 then notice 42 answer else notice 16 answer

def portal (op h nonce data length t : UInt64) : UInt64 :=
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
  let t := copy metadata (row 0+256) 1536 r
  let t := store64 (row 0) 1 t
  let t := store64 (row 0+8) h t
  let t := store64 (row 0+16) content t
  let t := store64 (row 0+24) (if complete then 3 else 1) t
  let t := store64 (row 0+48) (if complete then 1 else 2) t
  let t := store64 (st+16) 1 t
  let t := store64 (st+8) 0 t
  let t := store64 (st+88) 0 t
  let t := store64 (st+96) 0 t
  notice 17 t

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
  let visible := (load64 st t != 3 || load64 (m+16) t == 2) && titleMatches (m+344) (load64 (m+336) t) 0 (load64 (st+72) t) t
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

def draw (surface t : UInt64) : UInt64 :=
  let t := fill 0 0 640 352 bg t
  let t := fill 0 0 640 32 0x203e50 t
  let t := label 0 12 10 fg t
  let t := label 1 12 39 0xb1cbd8 t
  let t := label 2 12 57 0xc2b48c t
  let t := label 49 12 77 fg t
  let t := text 0x6e0400 (load64 (st+72) t) 68 77 fg bg t
  let tab := load64 st t
  let t := if tab == 1 then
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
  let t := label (if tab == 3 then 34 else 3) 12 300 fg t
  let t := label (if tab == 3 then 74 else 4) 12 316 fg t
  let t := label (load64 (st+176) t) 12 337 0xe0bd80 t
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
@[noinline] partial def gameSave (t : UInt64) : UInt64 :=
  let who := gameCurrent t
  if who == error then notice 42 who else
  let r := Guest.GameSDK.exportSave who who
  if r != 64 || status r != 0 then notice 42 r else
    notice 61 (store64 (selected r+96) (result r) r)
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
  let save := load64 (selected t+96) t
  if save == 0 then notice 42 t else
  let shell := syscall 97 4 0 0 0 t
  let r := Guest.LiveSDK.share save shell 25 shell
  if r != 64 || status r != 0 then notice 42 r else
  let saveScope := result r
  let r := Guest.LiveSDK.metadata save r
  if r != 96 || status r != 0 || load64 (wire+16) r != 192 then notice 42 r else
  let t := copy (wire+64) work 32 r
  let t := nextId t
  let nonce := load64 (st+184) t
  let r := portal 11 saveScope nonce work 32 t
  if r != 64 || status r != 0 then notice 21 r else
    dirty (store64 (st+400) nonce (store64 (st+408) (load64 (st+8) r+1) (store64 (st+416) 1 (store64 (st+424) saveScope r))))
@[noinline] partial def recoverGameSave (t : UInt64) : UInt64 :=
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
  if recovered == 0 then notice 42 t else notice 61 (store64 (row i+96) recovered t)

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
  else if code >= 59 && code <= 62 then dirty (store64 st (code-59) (store64 (st+232) 0 t)) else
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
  if code == 31 && load64 (selected t+8) t != 0 then
    let t := copy (selected t+1024+96) (st+288) 32 t
    let enabled := if load64 (st+88) t == 0 then 1 else 0
    notice 43 (store64 (st+88) enabled t)
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
  if code == 111 then
    let r := selected t
    let h := load64 (r+16) t
    let t := if h == 0 then t else Guest.ContentSDK.release h t
    let h := load64 (r+8) t
    let t := if h == 0 then t else drop h t
    notice 44 (store64 (r+8) 0 (store64 (r+16) 0 (store64 (r+24) 0 t)))
  else t

def request (n t : UInt64) : UInt64 :=
  let token := load64 (incoming+8) t
  let op := load64 command t
  let caller := load64 incoming t
  let t := if (caller &&& 255) == 1 && n == 128 && op == 700 then
      let t := copy (command+64) (st+256) 32 t
      store64 (st+224) 1 t
    else if (caller &&& 255) == 1 && n == 160 && op == 706 && load64 (command+16) t > 0 && load64 (command+16) t <= 6029312 then
      let t := copy (command+64) (st+256) 64 t
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
  let admin := (caller &&& 255) == 1
  if admin && n == 96 && op == 708 then
    let ji := load64 (command+8) t
    let handle := if ji < 4 then load64 (job ji+48) t else 0
    let r := if handle == 0 then error else Guest.ContentSDK.inspectJob handle t
    if r != 64 then reply token 64 (header 1 0 0 0 0 0 0 r) else
      let t := copy wire work 64 r
      let t := header 0 ji 0 0 0 0 0 t
      reply token 128 (copy work (wire+64) 64 t)
  else if admin && n == 96 && op == 707 then
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
  let t := receivePeers 0 t
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
  let next := Guest.WaitSDK.now t+(if active then 1 else 100)
  loop surface (Guest.WaitSDK.deadline next t)
def main (initial : UInt64) : UInt64 :=
  let t := zero st 1024 initial
  let t := zero 0x700000 20480 t
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
  let t := receivePeers 0 t
  let t := catalogPump t
  let t := jobsPump 0 t
  let now := Guest.WaitSDK.now t
  let t := if now >= load64 (st+344) now then providerStatus 0 (store64 (st+344) (now+100) now) else now
  let active := load64 (st+40) t != 0 || transferActive 0 t
  headlessLoop (Guest.WaitSDK.deadline (Guest.WaitSDK.now t+(if active then 1 else 100)) t)
def headlessMain (initial : UInt64) : UInt64 :=
  let t := zero st 1024 initial
  let t := zero 0x700000 20480 t
  let t := store64 (st+136) 1 t
  let t := store64 (st+184) (self t <<< 24) t
  headlessLoop t
end Guest.Library
