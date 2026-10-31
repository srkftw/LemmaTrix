import Guest.MessengerSDK
import Guest.Raster
import Guest.Keyboard
import Guest.WaitSDK
import Guest.ServiceHash
import Guest.MessengerProject
namespace Guest.Messenger
open Guest.LiveSDK Guest.Raster
-- The graphical process owns display/input and authorized plaintext only. It
-- never receives identity/prekey/ratchet seeds or an unrestricted vault mount.
def st : UInt64 := 0x700000
def composeBuffer : UInt64 := 0x701000
def inviteBuffer : UInt64 := 0x702000
def fingerprint : UInt64 := 0x703000
def displayText : UInt64 := 0x704000
def publicBundle : UInt64 := 0x705000
def federation : UInt64 := 0x706000
def labelBuffer : UInt64 := 0x707000
def ciphertext : UInt64 := 0x708000
def hashScratch : UInt64 := 0x709000
def commitment : UInt64 := 0x70a000
def contact (i : UInt64) : UInt64 := 0x70b000+i*64
def history (i : UInt64) : UInt64 := 0x70c000+i*1024
def transfer : UInt64 := 0x70e000
def transferId : UInt64 := transfer+160
def reference : UInt64 := 0x70f000
def expectedRoot : UInt64 := 0x70f100
def bg : UInt64 := 0x111b28
def fg : UInt64 := 0xdbe8ee
def accent : UInt64 := 0x83d5c5
def dirty (t : UInt64) : UInt64 := store64 (st+8) 1 t
def notice (id t : UInt64) : UInt64 := dirty (store64 (st+16) id t)
def attachmentLabel (id x y color t : UInt64) : UInt64 :=
  if id == 69 then
    let t := store64 (labelBuffer+0) 2338603393740665424 t
    let t := store64 (labelBuffer+8) 8243107338930713204 t
    let t := store64 (labelBuffer+16) 7956018212682276922 t
    let t := store64 (labelBuffer+24) 8097789280856186983 t
    let t := store64 (labelBuffer+32) 8223683306520015472 t
    let t := store64 (labelBuffer+40) 1702131055 t
    text labelBuffer 44 x y color bg t
  else
  if id == 70 then
    let t := store64 (labelBuffer+0) 7308612546338255937 t
    let t := store64 (labelBuffer+8) 2319970935307400302 t
    let t := store64 (labelBuffer+16) 2338603393841589865 t
    let t := store64 (labelBuffer+24) 8030038433884040801 t
    let t := store64 (labelBuffer+32) 2337214749187535986 t
    let t := store64 (labelBuffer+40) 32497592573780559 t
    text labelBuffer 47 x y color bg t
  else
  if id == 71 then
    let t := store64 (labelBuffer+0) 7308327840451211590 t
    let t := store64 (labelBuffer+8) 7307775882123310179 t
    let t := store64 (labelBuffer+16) 2338333891886085219 t
    let t := store64 (labelBuffer+24) 8223700954423258473 t
    let t := store64 (labelBuffer+32) 2334102066133558117 t
    let t := store64 (labelBuffer+40) 32760384526971504 t
    text labelBuffer 47 x y color bg t
  else
  if id == 72 then
    let t := store64 (labelBuffer+0) 7310591762041630277 t
    let t := store64 (labelBuffer+8) 7162247809296506980 t
    let t := store64 (labelBuffer+16) 7234314199461208180 t
    let t := store64 (labelBuffer+24) 7811882149974991392 t
    let t := store64 (labelBuffer+32) 7892834 t
    text labelBuffer 35 x y color bg t
  else
  if id == 73 then
    let t := store64 (labelBuffer+0) 2338603393740665424 t
    let t := store64 (labelBuffer+8) 8243107338930713204 t
    let t := store64 (labelBuffer+16) 4279657062207677984 t
    let t := store64 (labelBuffer+24) 8007533669950779936 t
    let t := store64 (labelBuffer+32) 7810758454475432050 t
    text labelBuffer 40 x y color bg t
  else
  if id == 74 then
    let t := store64 (labelBuffer+0) 2338603393740665424 t
    let t := store64 (labelBuffer+8) 7234316411285302633 t
    let t := store64 (labelBuffer+16) 7083916401943931168 t
    let t := store64 (labelBuffer+24) 8007465504524690794 t
    let t := store64 (labelBuffer+32) 5053160179704423792 t
    let t := store64 (labelBuffer+40) 1701278319 t
    text labelBuffer 44 x y color bg t
  else
  if id == 75 then
    let t := store64 (labelBuffer+0) 4212100838726791760 t
    let t := store64 (labelBuffer+8) 8390339637992645920 t
    let t := store64 (labelBuffer+16) 7741253900696577125 t
    let t := store64 (labelBuffer+24) 8315178075586457632 t
    let t := store64 (labelBuffer+32) 115 t
    text labelBuffer 33 x y color bg t
  else
  if id == 76 then
    let t := store64 (labelBuffer+0) 6998721791185937747 t
    let t := store64 (labelBuffer+8) 8386658438904705056 t
    let t := store64 (labelBuffer+16) 2334386829831072032 t
    let t := store64 (labelBuffer+24) 2334102057712448116 t
    let t := store64 (labelBuffer+32) 125779918940528 t
    text labelBuffer 38 x y color bg t
  else
  if id == 77 then
    let t := store64 (labelBuffer+0) 8079579113627546182 t
    let t := store64 (labelBuffer+8) 8295758483868512114 t
    let t := store64 (labelBuffer+16) 4279657096467016805 t
    let t := store64 (labelBuffer+24) 7453010313414538016 t
    let t := store64 (labelBuffer+32) 8390339637992645920 t
    let t := store64 (labelBuffer+40) 7379550829144990821 t
    let t := store64 (labelBuffer+48) 7631717 t
    text labelBuffer 51 x y color bg t
  else
  if id == 78 then
    let t := store64 (labelBuffer+0) 2338603393740665424 t
    let t := store64 (labelBuffer+8) 7164775599194924402 t
    let t := store64 (labelBuffer+16) 7955925612728695397 t
    let t := store64 (labelBuffer+24) 7526676561498828915 t
    let t := store64 (labelBuffer+32) 8030516718339452786 t
    let t := store64 (labelBuffer+40) 8245886547675935861 t
    let t := store64 (labelBuffer+48) 25959 t
    text labelBuffer 50 x y color bg t
  else
  if id == 79 then
    let t := store64 (labelBuffer+0) 7308533390191521606 t
    let t := store64 (labelBuffer+8) 8511910448208306548 t
    let t := store64 (labelBuffer+16) 2334102010248917605 t
    let t := store64 (labelBuffer+24) 2335230160870205556 t
    let t := store64 (labelBuffer+32) 7234316346692756851 t
    let t := store64 (labelBuffer+40) 111550860849696 t
    text labelBuffer 46 x y color bg t
  else
  if id == 80 then
    let t := store64 (labelBuffer+0) 7309940765075074886 t
    let t := store64 (labelBuffer+8) 2334381307661018470 t
    let t := store64 (labelBuffer+16) 7020101786482601589 t
    let t := store64 (labelBuffer+24) 8079583553113123938 t
    let t := store64 (labelBuffer+32) 7306000201232772207 t
    let t := store64 (labelBuffer+40) 1684367726 t
    text labelBuffer 44 x y color bg t
  else
  if id == 81 then
    let t := store64 (labelBuffer+0) 7598807758610329161 t
    let t := store64 (labelBuffer+8) 7307775882660177774 t
    let t := store64 (labelBuffer+16) 8462108017802900579 t
    let t := store64 (labelBuffer+24) 7310597216645703783 t
    let t := store64 (labelBuffer+32) 28542713838575716 t
    text labelBuffer 39 x y color bg t
  else
  if id == 83 then
    let t := store64 (labelBuffer+0) 8026294576626364226 t
    let t := store64 (labelBuffer+8) 7235349960603038830 t
    let t := store64 (labelBuffer+16) 133540892405349 t
    text labelBuffer 22 x y color bg t
  else
  if id == 84 then
    let t := store64 (labelBuffer+0) 2334111957543710293 t
    let t := store64 (labelBuffer+8) 7598805623894339177 t
    let t := store64 (labelBuffer+16) 28271 t
    text labelBuffer 18 x y color bg t
  else
  t
def label0 (id x y color t : UInt64) : UInt64 :=
  if id == 0 then
    let t := store64 (labelBuffer+0) 7306930302439613773 t
    let t := store64 (labelBuffer+8) 114 t
    text labelBuffer 9 x y color bg t
  else
  if id == 1 then
    let t := store64 (labelBuffer+0) 2334399943808741968 t
    let t := store64 (labelBuffer+8) 8011181856930492015 t
    let t := store64 (labelBuffer+16) 7307775882660177262 t
    let t := store64 (labelBuffer+24) 32783474433750115 t
    text labelBuffer 31 x y color bg t
  else
  if id == 2 then
    let t := store64 (labelBuffer+0) 7021786289551208517 t
    let t := store64 (labelBuffer+8) 8028074750225096812 t
    let t := store64 (labelBuffer+16) 8391162071561871470 t
    let t := store64 (labelBuffer+24) 7310309130344100449 t
    let t := store64 (labelBuffer+32) 6998720786163507315 t
    let t := store64 (labelBuffer+40) 8031170932064150638 t
    let t := store64 (labelBuffer+48) 31090 t
    text labelBuffer 50 x y color bg t
  else
  if id == 3 then
    let t := store64 (labelBuffer+0) 7234309775326209362 t
    let t := store64 (labelBuffer+8) 7453005979876412704 t
    let t := store64 (labelBuffer+16) 7593470771912012389 t
    let t := store64 (labelBuffer+24) 8245924292133462126 t
    let t := store64 (labelBuffer+32) 1684372073 t
    text labelBuffer 36 x y color bg t
  else
  if id == 4 then
    let t := store64 (labelBuffer+0) 7575166123761824323 t
    let t := store64 (labelBuffer+8) 2340029477669463396 t
    let t := store64 (labelBuffer+16) 3294752 t
    text labelBuffer 19 x y color bg t
  else
  if id == 5 then
    let t := store64 (labelBuffer+0) 7598805623894339145 t
    let t := store64 (labelBuffer+8) 56376279723631 t
    text labelBuffer 14 x y color bg t
  else
  if id == 6 then
    let t := store64 (labelBuffer+0) 7142837043854339401 t
    let t := store64 (labelBuffer+8) 2314978178654039663 t
    let t := store64 (labelBuffer+16) 13382 t
    text labelBuffer 18 x y color bg t
  else
  if id == 7 then
    let t := store64 (labelBuffer+0) 2334402202894889025 t
    let t := store64 (labelBuffer+8) 13638 t
    text labelBuffer 10 x y color bg t
  else
  if id == 8 then
    let t := store64 (labelBuffer+0) 3910848972019690562 t
    text labelBuffer 8 x y color bg t
  else
  if id == 9 then
    let t := store64 (labelBuffer+0) 8389719161264039251 t
    let t := store64 (labelBuffer+8) 29285 t
    text labelBuffer 10 x y color bg t
  else
  if id == 10 then
    let t := store64 (labelBuffer+0) 3982906626439144786 t
    text labelBuffer 8 x y color bg t
  else
  if id == 11 then
    let t := store64 (labelBuffer+0) 15839703750373196 t
    text labelBuffer 7 x y color bg t
  else
  if id == 12 then
    let t := store64 (labelBuffer+0) 5053156856725007957 t
    let t := store64 (labelBuffer+8) 57 t
    text labelBuffer 9 x y color bg t
  else
  if id == 13 then
    let t := store64 (labelBuffer+0) 5053166760785768262 t
    let t := store64 (labelBuffer+8) 12337 t
    text labelBuffer 10 x y color bg t
  else
  if id == 14 then
    let t := store64 (labelBuffer+0) 2338603376728502083 t
    let t := store64 (labelBuffer+8) 8246216697567930726 t
    let t := store64 (labelBuffer+16) 8026294339094474345 t
    let t := store64 (labelBuffer+24) 7526676497325715565 t
    let t := store64 (labelBuffer+32) 8032487043176427378 t
    let t := store64 (labelBuffer+40) 7310309114282799733 t
    let t := store64 (labelBuffer+48) 7308900609911103598 t
    let t := store64 (labelBuffer+56) 108 t
    text labelBuffer 57 x y color bg t
  else
  if id == 15 then
    let t := store64 (labelBuffer+0) 8097789280689352261 t
    let t := store64 (labelBuffer+8) 8367814987270287984 t
    let t := store64 (labelBuffer+16) 7161137258227263848 t
    let t := store64 (labelBuffer+24) 7305798977753194612 t
    let t := store64 (labelBuffer+32) 7306000107009548347 t
    let t := store64 (labelBuffer+40) 126879481293923 t
    text labelBuffer 46 x y color bg t
  else
  if id == 16 then
    let t := store64 (labelBuffer+0) 2334398904326254403 t
    let t := store64 (labelBuffer+8) 1954047348 t
    text labelBuffer 12 x y color bg t
  else
  if id == 17 then
    let t := store64 (labelBuffer+0) 8030604713523179342 t
    let t := store64 (labelBuffer+8) 8389765627373708662 t
    let t := store64 (labelBuffer+16) 7308327840455615329 t
    let t := store64 (labelBuffer+24) 1684370531 t
    text labelBuffer 28 x y color bg t
  else
  if id == 18 then
    let t := store64 (labelBuffer+0) 7791337742275016017 t
    let t := store64 (labelBuffer+8) 3251732437543248751 t
    let t := store64 (labelBuffer+16) 7811882149974339104 t
    let t := store64 (labelBuffer+24) 7305792289332817762 t
    let t := store64 (labelBuffer+32) 7286935674813510768 t
    let t := store64 (labelBuffer+40) 28538298446408054 t
    text labelBuffer 47 x y color bg t
  else
  if id == 19 then
    let t := store64 (labelBuffer+0) 7070761801846060115 t
    let t := store64 (labelBuffer+8) 8026096685789552761 t
    let t := store64 (labelBuffer+16) 120 t
    text labelBuffer 17 x y color bg t
  else
  if id == 20 then
    let t := store64 (labelBuffer+0) 7234318571485226322 t
    let t := store64 (labelBuffer+8) 7162240872689328416 t
    let t := store64 (labelBuffer+16) 110386908002674 t
    text labelBuffer 22 x y color bg t
  else
  if id == 21 then
    let t := store64 (labelBuffer+0) 7959303536564858706 t
    let t := store64 (labelBuffer+8) 7809911822066218593 t
    let t := store64 (labelBuffer+16) 8532476794931847269 t
    let t := store64 (labelBuffer+24) 7306087009988731745 t
    let t := store64 (labelBuffer+32) 8317701428967993888 t
    let t := store64 (labelBuffer+40) 7310021098310300192 t
    let t := store64 (labelBuffer+48) 100 t
    text labelBuffer 49 x y color bg t
  else
  if id == 22 then
    let t := store64 (labelBuffer+0) 8245933071047814741 t
    let t := store64 (labelBuffer+8) 8243118315558692212 t
    let t := store64 (labelBuffer+16) 474315584609 t
    text labelBuffer 21 x y color bg t
  else
  if id == 23 then
    let t := store64 (labelBuffer+0) 3251709317717651276 t
    let t := store64 (labelBuffer+8) 7598258015748579616 t
    let t := store64 (labelBuffer+16) 8026370501748483450 t
    let t := store64 (labelBuffer+24) 8171062582735693174 t
    let t := store64 (labelBuffer+32) 431198726517 t
    text labelBuffer 37 x y color bg t
  else
  if id == 24 then
    let t := store64 (labelBuffer+0) 8388361569363586633 t
    let t := store64 (labelBuffer+8) 8247617492460380281 t
    let t := store64 (labelBuffer+16) 101 t
    text labelBuffer 17 x y color bg t
  else
  if id == 25 then
    let t := store64 (labelBuffer+0) 2338603376728502083 t
    let t := store64 (labelBuffer+8) 8751735924676977769 t
    let t := store64 (labelBuffer+16) 7234302100218864416 t
    let t := store64 (labelBuffer+24) 8030604713523162400 t
    let t := store64 (labelBuffer+32) 8462656715650523510 t
    let t := store64 (labelBuffer+40) 1684370025 t
    text labelBuffer 44 x y color bg t
  else
  if id == 26 then
    let t := store64 (labelBuffer+0) 7811884354617173330 t
    let t := store64 (labelBuffer+8) 8223694344368185705 t
    let t := store64 (labelBuffer+16) 28259039741047141 t
    text labelBuffer 23 x y color bg t
  else
  if id == 27 then
    let t := store64 (labelBuffer+0) 8151626876200053062 t
    let t := store64 (labelBuffer+8) 7527877966898163573 t
    let t := store64 (labelBuffer+16) 110386908198241 t
    text labelBuffer 22 x y color bg t
  else
  if id == 28 then
    let t := store64 (labelBuffer+0) 2334956330868174679 t
    let t := store64 (labelBuffer+8) 8030609103219007533 t
    let t := store64 (labelBuffer+16) 7955997339207999596 t
    let t := store64 (labelBuffer+24) 7020101786482581619 t
    let t := store64 (labelBuffer+32) 6646882 t
    text labelBuffer 35 x y color bg t
  else
  if id == 29 then
    let t := store64 (labelBuffer+0) 7955925836844196176 t
    let t := store64 (labelBuffer+8) 7957695015159097718 t
    let t := store64 (labelBuffer+16) 7307218078216316960 t
    let t := store64 (labelBuffer+24) 4283597746323398766 t
    let t := store64 (labelBuffer+32) 7953747407671608608 t
    let t := store64 (labelBuffer+40) 1936483683 t
    text labelBuffer 44 x y color bg t
  else
  if id == 30 then
    let t := store64 (labelBuffer+0) 7955925866589155148 t
    let t := store64 (labelBuffer+8) 7957695015159097718 t
    let t := store64 (labelBuffer+16) 7163375852442363936 t
    let t := store64 (labelBuffer+24) 45601486958368 t
    text labelBuffer 30 x y color bg t
  else
  if id == 31 then
    let t := store64 (labelBuffer+0) 2336927755351057747 t
    let t := store64 (labelBuffer+8) 7020101786482601589 t
    let t := store64 (labelBuffer+16) 8391085908910500962 t
    let t := store64 (labelBuffer+24) 2334111870320144993 t
    let t := store64 (labelBuffer+32) 8386105066543540578 t
    let t := store64 (labelBuffer+40) 7308910564437489257 t
    let t := store64 (labelBuffer+48) 114 t
    text labelBuffer 49 x y color bg t
  else
  if id == 32 then
    let t := store64 (labelBuffer+0) 2338603376728502083 t
    let t := store64 (labelBuffer+8) 7234318597473988705 t
    text labelBuffer 16 x y color bg t
  else
  if id == 33 then
    let t := store64 (labelBuffer+0) 2338603376728502083 t
    let t := store64 (labelBuffer+8) 28259009575218274 t
    text labelBuffer 15 x y color bg t
  else
  if id == 34 then
    let t := store64 (labelBuffer+0) 7593478425778614094 t
    let t := store64 (labelBuffer+8) 8391166426662331758 t
    let t := store64 (labelBuffer+16) 7526769937260049007 t
    let t := store64 (labelBuffer+24) 110387008205423 t
    text labelBuffer 30 x y color bg t
  else
  t
def label1 (id x y color t : UInt64) : UInt64 :=
  if id == 35 then
    let t := store64 (labelBuffer+0) 7308612546338255937 t
    let t := store64 (labelBuffer+8) 7599104626777945198 t
    let t := store64 (labelBuffer+16) 7813877729219274098 t
    let t := store64 (labelBuffer+24) 7957688057630122857 t
    let t := store64 (labelBuffer+32) 8391720272695027060 t
    let t := store64 (labelBuffer+40) 7598805649663881064 t
    let t := store64 (labelBuffer+48) 28271 t
    text labelBuffer 50 x y color bg t
  else
  if id == 36 then
    let t := store64 (labelBuffer+0) 7142836987885678406 t
    let t := store64 (labelBuffer+8) 7161040562708112748 t
    let t := store64 (labelBuffer+16) 7308324500363502947 t
    let t := store64 (labelBuffer+24) 7719288926848904224 t
    let t := store64 (labelBuffer+32) 8389719160576506213 t
    let t := store64 (labelBuffer+40) 7594879246290416229 t
    let t := store64 (labelBuffer+48) 7564658 t
    text labelBuffer 51 x y color bg t
  else
  if id == 37 then
    let t := store64 (labelBuffer+0) 7311152469766058310 t
    let t := store64 (labelBuffer+8) 8317708060514677618 t
    let t := store64 (labelBuffer+16) 8026294567816142880 t
    let t := store64 (labelBuffer+24) 4981016807972237421 t
    let t := store64 (labelBuffer+32) 7305804385079026547 t
    let t := store64 (labelBuffer+40) 3418326019388481644 t
    let t := store64 (labelBuffer+48) 7957688057527035728 t
    let t := store64 (labelBuffer+56) 1952670068 t
    text labelBuffer 60 x y color bg t
  else
  if id == 38 then
    let t := store64 (labelBuffer+0) 126948300911699 t
    text labelBuffer 6 x y color bg t
  else
  if id == 39 then
    let t := store64 (labelBuffer+0) 7598805615236113734 t
    let t := store64 (labelBuffer+8) 7596848471615762031 t
    let t := store64 (labelBuffer+16) 500068347252 t
    text labelBuffer 21 x y color bg t
  else
  if id == 40 then
    let t := store64 (labelBuffer+0) 28542640894207309 t
    text labelBuffer 7 x y color bg t
  else
  if id == 41 then
    let t := store64 (labelBuffer+0) 7954874719498888526 t
    let t := store64 (labelBuffer+8) 7018141078128978292 t
    let t := store64 (labelBuffer+16) 31076 t
    text labelBuffer 18 x y color bg t
  else
  if id == 42 then
    let t := store64 (labelBuffer+0) 7598805623894339145 t
    let t := store64 (labelBuffer+8) 8245933057956146799 t
    let t := store64 (labelBuffer+16) 7309940523364803956 t
    let t := store64 (labelBuffer+24) 7956002506354813302 t
    let t := store64 (labelBuffer+32) 8389759096071546215 t
    text labelBuffer 40 x y color bg t
  else
  if id == 43 then
    let t := store64 (labelBuffer+0) 8007510524188058948 t
    let t := store64 (labelBuffer+8) 2334391147682799730 t
    let t := store64 (labelBuffer+16) 8388361603773658465 t
    let t := store64 (labelBuffer+24) 121 t
    text labelBuffer 25 x y color bg t
  else
  if id == 44 then
    let t := store64 (labelBuffer+0) 7308335478031147331 t
    let t := store64 (labelBuffer+8) 100 t
    text labelBuffer 9 x y color bg t
  else
  if id == 45 then
    let t := store64 (labelBuffer+0) 2336936577129475669 t
    let t := store64 (labelBuffer+8) 8751168585183552868 t
    let t := store64 (labelBuffer+16) 111550525633312 t
    text labelBuffer 22 x y color bg t
  else
  if id == 46 then
    let t := store64 (labelBuffer+0) 6998721855778483529 t
    let t := store64 (labelBuffer+8) 8386654083790889760 t
    let t := store64 (labelBuffer+16) 8386111977447909664 t
    let t := store64 (labelBuffer+24) 7070773959522676585 t
    let t := store64 (labelBuffer+32) 1852401509 t
    text labelBuffer 36 x y color bg t
  else
  if id == 47 then
    let t := store64 (labelBuffer+0) 7022083123460468558 t
    let t := store64 (labelBuffer+8) 7562599 t
    text labelBuffer 11 x y color bg t
  else
  if id == 48 then
    let t := store64 (labelBuffer+0) 7022364301937698130 t
    let t := store64 (labelBuffer+8) 7022907795970221428 t
    let t := store64 (labelBuffer+16) 111516181425257 t
    text labelBuffer 22 x y color bg t
  else
  if id == 49 then
    let t := store64 (labelBuffer+0) 7234318597473988673 t
    let t := store64 (labelBuffer+8) 28538277256848416 t
    text labelBuffer 15 x y color bg t
  else
  if id == 50 then
    let t := store64 (labelBuffer+0) 8386094384959873347 t
    let t := store64 (labelBuffer+8) 7305798977753194597 t
    text labelBuffer 16 x y color bg t
  else
  if id == 51 then
    let t := store64 (labelBuffer+0) 34184295202646344 t
    text labelBuffer 7 x y color bg t
  else
  if id == 52 then
    let t := store64 (labelBuffer+0) 7162256579379621710 t
    let t := store64 (labelBuffer+8) 7358993273163948148 t
    let t := store64 (labelBuffer+16) 30227092422290529 t
    text labelBuffer 23 x y color bg t
  else
  if id == 53 then
    let t := store64 (labelBuffer+0) 7954880248345224530 t
    let t := store64 (labelBuffer+8) 7956009403787714676 t
    let t := store64 (labelBuffer+16) 8026096685789552741 t
    let t := store64 (labelBuffer+24) 7311146959361024120 t
    let t := store64 (labelBuffer+32) 7599104626777946482 t
    let t := store64 (labelBuffer+40) 7310222221680797042 t
    let t := store64 (labelBuffer+48) 8223683306485671276 t
    let t := store64 (labelBuffer+56) 1702131055 t
    text labelBuffer 60 x y color bg t
  else
  if id == 56 then
    let t := store64 (labelBuffer+0) 7306930302439613773 t
    let t := store64 (labelBuffer+8) 2338613357914234994 t
    let t := store64 (labelBuffer+16) 7598819853035991651 t
    let t := store64 (labelBuffer+24) 7503054386272824417 t
    let t := store64 (labelBuffer+32) 7021781869991589989 t
    let t := store64 (labelBuffer+40) 8367736982006494307 t
    let t := store64 (labelBuffer+48) 7310589338305062248 t
    let t := store64 (labelBuffer+56) 114 t
    text labelBuffer 57 x y color bg t
  else
  if id == 57 then
    let t := store64 (labelBuffer+0) 8511934573253243206 t
    let t := store64 (labelBuffer+8) 3622618274030450017 t
    let t := store64 (labelBuffer+16) 8243124913752601120 t
    let t := store64 (labelBuffer+24) 8316292674424807456 t
    let t := store64 (labelBuffer+32) 8101246892906803060 t
    let t := store64 (labelBuffer+40) 2320556811800048239 t
    let t := store64 (labelBuffer+48) 2340027304416340328 t
    let t := store64 (labelBuffer+56) 32772479305805667 t
    text labelBuffer 63 x y color bg t
  else
  if id == 58 then
    let t := store64 (labelBuffer+0) 7022349259822818638 t
    let t := store64 (labelBuffer+8) 7022364301937962601 t
    let t := store64 (labelBuffer+16) 25972 t
    text labelBuffer 18 x y color bg t
  else
  if id == 59 then
    let t := store64 (labelBuffer+0) 2338042715908040018 t
    let t := store64 (labelBuffer+8) 2338615488502986083 t
    let t := store64 (labelBuffer+16) 7310596091285434211 t
    let t := store64 (labelBuffer+24) 28556934562127972 t
    text labelBuffer 31 x y color bg t
  else
  if id == 60 then
    let t := store64 (labelBuffer+0) 8007528172309474633 t
    let t := store64 (labelBuffer+8) 8316292675483821164 t
    let t := store64 (labelBuffer+16) 8388366762314461044 t
    let t := store64 (labelBuffer+24) 2335243286339788904 t
    let t := store64 (labelBuffer+32) 2334956330750469491 t
    let t := store64 (labelBuffer+40) 8388361603773658465 t
    let t := store64 (labelBuffer+48) 121 t
    text labelBuffer 49 x y color bg t
  else
  if id == 61 then
    let t := store64 (labelBuffer+0) 7022082024104947523 t
    let t := store64 (labelBuffer+8) 8316292675417368948 t
    let t := store64 (labelBuffer+16) 7957688057714601844 t
    let t := store64 (labelBuffer+24) 7311910905446294899 t
    let t := store64 (labelBuffer+32) 115 t
    text labelBuffer 33 x y color bg t
  else
  if id == 62 then
    let t := store64 (labelBuffer+0) 7022082024104947523 t
    let t := store64 (labelBuffer+8) 8316292675417368948 t
    let t := store64 (labelBuffer+16) 7957688057714601844 t
    let t := store64 (labelBuffer+24) 8029390621081757043 t
    text labelBuffer 32 x y color bg t
  else
  if id == 63 then
    let t := store64 (labelBuffer+0) 7020105101879435587 t
    let t := store64 (labelBuffer+8) 7020677651269380468 t
    let t := store64 (labelBuffer+16) 7308324465885667702 t
    let t := store64 (labelBuffer+24) 8390044913288359200 t
    let t := store64 (labelBuffer+32) 8390317583334711397 t
    let t := store64 (labelBuffer+40) 7164792839193456225 t
    let t := store64 (labelBuffer+48) 121398885642853 t
    text labelBuffer 54 x y color bg t
  else
  if id == 64 then
    let t := store64 (labelBuffer+0) 7306930302439613773 t
    let t := store64 (labelBuffer+8) 2338613357914234994 t
    let t := store64 (labelBuffer+16) 8028075772644520047 t
    let t := store64 (labelBuffer+24) 8388356097741889646 t
    let t := store64 (labelBuffer+32) 6579572 t
    text labelBuffer 35 x y color bg t
  else
  if id == 66 then
    let t := store64 (labelBuffer+0) 8675375932899618373 t
    let t := store64 (labelBuffer+8) 3762230244597326689 t
    let t := store64 (labelBuffer+16) 7162241152197158944 t
    let t := store64 (labelBuffer+24) 7018969010165345641 t
    let t := store64 (labelBuffer+32) 32495402391658866 t
    text labelBuffer 39 x y color bg t
  else
  if id == 67 then
    let t := store64 (labelBuffer+0) 7306930302439613773 t
    let t := store64 (labelBuffer+8) 7449361081668149362 t
    let t := store64 (labelBuffer+16) 8388356097741889637 t
    let t := store64 (labelBuffer+24) 28259013969929760 t
    text labelBuffer 31 x y color bg t
  else
  if id == 68 then
    let t := store64 (labelBuffer+0) 2340025105359597125 t
    let t := store64 (labelBuffer+8) 7020101786482601589 t
    let t := store64 (labelBuffer+16) 6646882 t
    text labelBuffer 19 x y color bg t
  else
  t
def label (id x y color t : UInt64) : UInt64 :=
  if id < 35 then label0 id x y color t else
  if id < 69 then label1 id x y color t else attachmentLabel id x y color t

def failed (r t : UInt64) : UInt64 :=
  if r == error then notice 31 t else
  let code := status r
  let r := store64 (st+224) code r
  notice (if code == 1 || code == 3 then 43 else if code == 4 then 27 else
    if code == 5 then 23 else if code == 6 then 68 else if code == 7 then 22 else
    if code == 8 then 25 else if code == 9 then 24 else if code == 12 then 26 else
    if code == 13 then 67 else 45) r
partial def hexBytes (p n x y t : UInt64) : UInt64 :=
  if n == 0 then t else
  let t := hex (load8 p t) 2 x y accent bg t
  hexBytes (p+1) (n-1) (if x >= 600 then 16 else x+12) (if x >= 600 then y+12 else y) t
def exportPage (t : UInt64) : UInt64 :=
  let total := if load64 (st+200) t == 672 then 672 else if load64 (st+200) t == 320 then 320 else 256
  let pages := (total+255)/256
  let page := load64 (st+216) t%pages
  let remaining := total-page*256
  let count := if remaining > 256 then 256 else remaining
  let t := hexBytes (publicBundle+page*256) count 16 124 t
  let t := store64 (labelBuffer+0) 4928996481858627408 t
  let t := store64 (labelBuffer+8) 8388365997536459374 t
  let t := store64 (labelBuffer+16) 7021147477758276705 t
  let t := store64 (labelBuffer+24) 25959 t
  let t := text labelBuffer 26 16 224 fg bg t
  let t := hex (page+1) 1 184 224 accent bg t
  let t := char 192 224 47 fg bg t
  hex pages 1 200 224 accent bg t
partial def wrapped (p n x y t : UInt64) : UInt64 :=
  if n == 0 || y >= 258 then t else
  let c := load8 p t
  let newline := c == 10 || x >= 610
  let t := if c == 10 then t else char x y c fg bg t
  wrapped (p+1) (n-1) (if newline then 16 else x+6) (if newline then y+12 else y) t
partial def masked (n x y t : UInt64) : UInt64 :=
  if n == 0 then t else
  let t := char x y 42 fg bg t
  masked (n-1) (if x >= 610 then 16 else x+6) (if x >= 610 then y+12 else y) t
def drawTransfer (t : UInt64) : UInt64 :=
  let phase := load64 transfer t
  let incomingTransfer := phase >= 20
  if (phase > 0 && phase < 20) || (phase >= 20 && phase < 24) then
    let t := label 75 14 204 accent t
    let sent := load64 (if incomingTransfer then transfer+104 else transfer+136) t*512
    let total := load64 (if incomingTransfer then transfer+64 else transfer+24) t
    let t := hex (if sent > total then total else sent) 6 250 204 accent bg t
    let t := hex total 6 306 204 accent bg t
    t else if load64 (history (load64 (st+24) t)+640) t != 0 then label 78 14 204 accent t else
    if load64 (transfer+56) t != 0 then label 70 14 204 accent t else t
def draw (surface t : UInt64) : UInt64 :=
  let t := fill 0 0 640 352 bg t
  let t := fill 0 0 640 36 0x223448 t
  let t := label 0 14 12 fg t
  let t := label (if load64 (st+80) t == 1 then 3 else 2) 128 12 0x9fb4c4 t
  let t := label 4 14 45 accent t
  let t := label 5 160 45 accent t
  let t := label 6 286 45 accent t
  let t := label 7 470 45 accent t
  let t := label 8 552 45 accent t
  let t := fill 10 64 620 1 0x355064 t
  let t := label (if load64 (st+48) t == 1 then 49 else 50) 14 76 fg t
  let t := hex (load64 (st+24) t) 2 130 76 accent bg t
  let t := hexBytes fingerprint 32 160 76 t
  let t := label 39 14 92 0x9fb4c4 t
  let t := hexBytes federation 32 160 92 t
  let mode := load64 (st+32) t
  let bound := (mode == 3 && load64 (st+200) t == 672) || load64 (contact (load64 (st+24) t)+40) t == 1
  let t := label (if bound then 83 else 84) 470 104 0x9fb4c4 t
  let t := if mode == 1 then
      let t := label 14 14 104 fg t
      let t := hexBytes fingerprint 32 16 124 t
      label 15 14 152 accent t
    else if mode == 2 then
      let t := label 29 14 104 fg t
      let n := load64 (st+56) t
      let offset := if n > 512 then n-512 else 0
      wrapped (inviteBuffer+offset) (n-offset) 16 124 t
    else if mode == 3 then
      let t := label 30 14 104 fg t
      exportPage t
    else if mode == 4 then label 36 14 128 0xffbf80 t
    else if mode == 5 then
      let t := label 56 14 104 fg t
      let t := label 57 14 126 accent t
      let t := label (58+load64 (st+176) t) 14 150 fg t
      let t := label (if load64 (st+184) t == 1 then 61 else 62) 14 174 accent t
      let t := hex (load64 (st+56) t) 2 588 174 accent bg t
      masked (load64 (st+56) t) 16 200 t
    else if mode == 6 then
      let t := label 78 14 104 accent t
      let t := hexBytes reference 32 16 124 t
      let t := hexBytes (reference+32) 32 16 160 t
      let t := hex (load64 (reference+64) t) 2 16 196 accent bg t
      let t := hex (load64 (transfer+192) t) 2 64 196 accent bg t
      let t := hex (load64 (transfer+200) t) 2 112 196 accent bg t
      hex (load64 (transfer+208) t) 8 160 196 accent bg t
    else
      let t := label 51 14 104 accent t
      let t := wrapped displayText (load64 (st+96) t) 16 124 t
      let t := label 16 14 230 accent t
      let n := load64 (st+40) t
      let t := hex n 3 116 230 accent bg t
      let offset := if n > 98 then n-98 else 0
      wrapped (composeBuffer+offset) (n-offset) 16 247 t
  let t := fill 10 276 620 1 0x355064 t
  let t := label (load64 (st+16) t) 14 286 0xf2ca91 t
  let t := label 9 14 309 accent t
  let t := label 10 140 309 accent t
  let t := label 11 248 309 accent t
  let t := label 12 344 309 accent t
  let t := label 13 452 309 accent t
  let t := label 71 14 334 0x9fb4c4 t
  let t := drawTransfer t
  let t := upload surface 0 901120 0 t
  store64 (st+8) 0 t
def backgroundRequest (operation action : UInt64) : Bool :=
  operation == 420 || (operation == 463 && action == 0)
def submitTagged (operation action length t : UInt64) : UInt64 :=
  let pending := load64 (st+144) t
  -- A completed status poll must not consume a user's approval/send gesture.
  -- A rejected gesture cannot replace the action of an admitted request.
  -- A chunk fetch poll is idempotent and cannot acknowledge deletion. Text may
  -- preempt that poll, while crypto staging/commit requests must finish.
  let fetchPoll := operation == 426 && load64 (st+152) t == 463 && load64 (st+256) t == 463
  let t := if pending != 0 && !backgroundRequest operation action &&
      (backgroundRequest (load64 (st+152) t) (load64 (st+256) t) || fetchPoll) then
    let r := Guest.MessengerSDK.cancelRequest pending t
    if r == error then r else store64 (transfer+128) 0 (store64 (st+144) 0 r)
    else t
  if load64 (st+144) t != 0 then notice 28 t else
  let token := Guest.MessengerSDK.submit (if operation >= 460 then 4 else 2) operation length t
  if token == error then
    let t := if operation >= 460 then store64 (st+104) 0 token else token
    let t := if action == 0 then t else store64 (transfer+128) 0 (store64 transfer 9 t)
    notice (if operation >= 460 then 21 else 31) t else
  let t := store64 (transfer+128) action (store64 (st+256) action (store64 (st+152) operation (store64 (st+144) token token)))
  let t := if operation == 426 then store64 (st+264) (load64 (st+24) t) t else t
  if backgroundRequest operation (load64 (st+256) t) || load64 (st+16) t == 28 ||
      (load64 (st+16) t == 69 && (load64 (st+256) t == 463 || load64 (st+256) t == 461)) then t else notice 28 t
def submit (operation length t : UInt64) : UInt64 := submitTagged operation 0 length t
def checkStatus (t : UInt64) : UInt64 := submit 420 64 (header 420 0 0 0 0 0 0 t)
def createIdentity (t : UInt64) : UInt64 :=
  submit 421 96 (copy federation (wire+64) 32 (header 421 0 0 0 0 0 0 t))
def showInvitation (t : UInt64) : UInt64 := submit 434 64 (header 434 0 27 0 0 0 0 (store64 (st+216) 0 (store64 (st+200) 672 t)))
def importBundle (t : UInt64) : UInt64 :=
  let n := if load64 (st+200) t == 672 then 672 else if load64 (st+200) t == 320 then 320 else 256
  submit 423 (64+n) (copy publicBundle (wire+64) n (header 423 0 0 0 0 0 0 t))
def approveContact (t : UInt64) : UInt64 :=
  if load64 (st+32) t != 1 then notice 17 t else
  submit 424 96 (copy fingerprint (wire+64) 32 (header 424 (load64 (st+24) t) 0 0 0 0 0 t))
def blockContact (t : UInt64) : UInt64 := submit 425 64 (header 425 (load64 (st+24) t) 0 0 0 0 0 t)
def send (t : UInt64) : UInt64 :=
  if load64 (st+32) t != 0 then notice 45 t else
  if load64 (st+48) t != 1 then notice 17 t else
  let n := load64 (st+40) t
  if n == 0 then t else
  submit 426 (64+n) (copy composeBuffer (wire+64) n (header 426 (load64 (st+24) t) n 0 0 0 0 (store64 (st+248) (load64 (st+24) t) t)))
def retry (t : UInt64) : UInt64 :=
  let h := load64 (st+64) t
  if h == 0 then notice 45 t else notice 18 (store64 (st+104) 1 (store64 (st+232) 0 t))
def cancel (t : UInt64) : UInt64 :=
  let outstanding := load64 (st+144) t
  let t := if outstanding == 0 then t else Guest.MessengerSDK.cancelRequest outstanding t
  let t := store64 (st+144) 0 t
  let h := load64 (st+64) t
  if h == 0 then notice 44 (store64 (st+32) 0 t) else
  if load64 (st+104) t >= 3 then submit 462 64 (header 462 h 0 0 0 0 0 t) else
  submit 430 64 (header 430 h 0 0 0 0 0 t)
def cancelPending (t : UInt64) : UInt64 :=
  let token := load64 (st+144) t
  let t := if token == 0 then t else Guest.MessengerSDK.cancelRequest token t
  store64 (transfer+128) 0 (store64 (st+144) 0 t)
def lock (t : UInt64) : UInt64 := submit 431 64 (header 431 0 0 0 0 0 0 (cancelPending t))
def forget (t : UInt64) : UInt64 := submit 433 64 (header 433 0 0 0 0 0 0 (cancelPending t))
def unlock (t : UInt64) : UInt64 :=
  notice 56 (store64 (st+32) 5 (store64 (st+56) 0 (store64 (st+176) 1 (store64 (st+184) 0 (zero inviteBuffer 168 t)))))
def clearPlaintext (t : UInt64) : UInt64 :=
  let t := Guest.MessengerProject.clear (zero transfer 32 t)
  let t := zero reference 9 (zero expectedRoot 4 t)
  let t := zero inviteBuffer 168 (zero 0x70c000 640 (zero 0x70b000 40 (zero composeBuffer 64 (zero displayText 64 (zero publicBundle 84 (zero fingerprint 4 t))))))
  store64 (st+64) 0 (store64 (st+248) 0 (store64 (st+104) 0
    (store64 (st+32) 0 (store64 (st+48) 0 (store64 (st+40) 0 (store64 (st+96) 0 t))))))
def nextRestoredContact (t : UInt64) : UInt64 :=
  let old := load64 (st+208) t
  if old >= 4 then
    submitTagged 434 21 64 (header 434 0 21 0 0 0 0 (store64 (transfer+232) 0 (store64 (st+208) 0 t))) else
  let i := old+1
  submit 434 64 (header 434 i 15 0 0 0 0 (store64 (st+208) i t))
def referenceNibble (c : UInt64) : UInt64 :=
  if c >= 48 && c <= 57 then c-48 else if c >= 97 && c <= 102 then c-87 else error
partial def referenceHex (source out i t : UInt64) : UInt64 :=
  if i == 32 then t else
  let a := referenceNibble (load8 (source+i*2) t)
  let b := referenceNibble (load8 (source+i*2+1) t)
  if a == error || b == error then error else referenceHex source out (i+1) (store8 (out+i) (a*16+b) t)
def parseReference (source n contact t : UInt64) : UInt64 :=
  let p := history contact+640
  let t := zero p 10 t
  if n != 143 || load64 source t != 4992890351844676684 || load8 (source+8) t != 67 || load8 (source+9) t != 84 ||
    load8 (source+10) t != 49 || load8 (source+11) t != 32 || load8 (source+76) t != 32 || load8 (source+141) t != 32 ||
    (load8 (source+142) t != 49 && load8 (source+142) t != 50) then t else
  let r := referenceHex (source+12) (p+8) 0 t
  if r == error then zero p 10 r else
  let r := referenceHex (source+77) (p+40) 0 r
  if r == error then zero p 10 r else store64 p (load8 (source+142) r-48) r
def inspectProjectReference (t : UInt64) : UInt64 :=
  let p := history (load64 (st+24) t)+640
  if load64 p t == 0 || (load64 (st+144) t != 0 && !backgroundRequest (load64 (st+152) t) (load64 (st+256) t)) then notice 45 t else
  let t := copy (p+8) reference 64 t
  let t := store64 (reference+64) (load64 p t) t
  let t := header 463 0 3 0 0 0 0 t
  submitTagged 463 303 136 (copy reference (wire+64) 72 (store64 (st+32) 6 (store64 (transfer+248) 0 t)))
def submitTransfer (operation action length t : UInt64) : UInt64 :=
  submitTagged operation action length t
def projectPortal (op h nonce t : UInt64) : UInt64 :=
  let shell := syscall 97 4 0 0 0 t
  syscall 30 shell wire 64 1024 (header op h nonce 0 0 0 0 shell)
def chooseProject (t : UInt64) : UInt64 :=
  if load64 (st+48) t != 1 || (load64 transfer t > 0 && load64 transfer t < 8) then notice 17 t else
  let t := if load64 transfer t == 10 then t else
    store64 (transfer+32) 0 (store64 (transfer+40) 0 (store64 (transfer+48) 0
      (store64 (transfer+136) 0 (store64 (transfer+152) 0 t))))
  let t := store64 (transfer+240) 1 t
  let t := store64 (transfer+224) (if load64 transfer t == 10 then 1+load64 (transfer+152) t*2 else 0) t
  let nonce := load64 (transfer+112) t+1
  let r := projectPortal 14 25 nonce t
  if r != 64 || status r != 0 then notice 73 r else
  notice 76 (store64 transfer 1 (store64 (transfer+112) nonce (store64 (transfer+16) (load64 (st+24) r) r)))
def importProject (t : UInt64) : UInt64 :=
  let h := load64 (transfer+56) t
  if h == 0 || (load64 (st+144) t != 0 && !backgroundRequest (load64 (st+152) t) (load64 (st+256) t)) || (load64 transfer t > 0 && load64 transfer t < 8) then notice 45 t else
  submitTransfer 434 5 64 (header 434 h 5 0 0 0 0 (store64 (transfer+240) 2 (store64 transfer 20 t)))
def nextTransfer (t : UInt64) : UInt64 :=
  if load64 (transfer+232) t == 0 then
    submitTransfer 434 21 64 (header 434 1 21 0 0 0 0 (store64 (transfer+232) 1 t)) else notice 64 t
def attachmentCompleted (action length t : UInt64) : UInt64 :=
  let code := status t
  let t := store64 (transfer+128) 0 t
  if action == 21 then
    if code == 3 then nextTransfer t else
    if code != 0 || length != 128 then notice 73 t else
    if load64 (wire+16) t != 1 then nextTransfer t else
    let t := copy (wire+96) expectedRoot 32 t
    let t := copy (wire+64) transferId 32 t
    let t := store64 (transfer+8) (result t) (store64 (transfer+16) (load64 (wire+24) t) t)
    let staged := load64 (wire+40) t
    let published := load64 (wire+48) t
    let first := if staged > published then published else if published == 0 then 0 else ((published-1)/14)*14
    let t := store64 (transfer+152) (if staged == published && published != 0 then 1 else 0) t
    let t := store64 (transfer+24) (load64 (wire+32) t) (store64 (transfer+32) first (store64 (transfer+40) first t))
    -- Publication is local ciphertext availability, not a persisted remote
    -- receipt. Recovery must replay the final uncertain batch exactly.
    nextTransfer (store64 transfer (if staged == 0 then 0 else 10) t)
  else if action == 304 then notice 44 (store64 (transfer+216) 0 t)
  else if action == 303 then
    if code == 6 then notice 81 (store64 (transfer+216) 2 t) else
    if code != 0 || length != 128 then notice 80 (store64 (transfer+216) 0 t) else
    let state := result t
    let t := store64 (transfer+192) (load64 (wire+24) t) (store64 (transfer+200) (load64 (wire+32) t) (store64 (transfer+208) (load64 (wire+40) t) t))
    if state == 3 then notice 79 (store64 (transfer+216) 0 t) else
    if state == 4 then notice 80 (store64 (transfer+216) 0 t) else notice 81 (store64 (transfer+216) 1 t)
  else if code == 6 && action >= 460 then
    let t := if action == 460 then store64 transfer 6 t else t
    if load64 (st+16) t == 69 then t else notice 69 t else
  if code != 0 then notice 73 (store64 transfer 9 (store64 (transfer+120) code t)) else
  if action == 1 then
    if length != 64 then notice 73 t else
    let t := store64 (st+64) (result t) (store64 (st+232) 1 t)
    let h := load64 (wire+16) t
    let t := store64 (transfer+8) h (store64 transfer 2 t)
    let t := header 434 h 22 0 0 0 0 t
    submitTransfer 434 22 96 (copy Guest.MessengerProject.head (wire+64) 32 t)
  else if action == 22 then notice 77 (store64 (st+248) (load64 (transfer+16) t) (store64 (st+104) 1 (store64 transfer 3 t)))
  else if action == 16 then
    store64 (transfer+32) (load64 (transfer+32) t+1) t
  else if action == 17 then store64 transfer 6 (store64 (transfer+48) (load64 (transfer+40) t) t)
  else if action == 460 then store64 transfer 7 t
  else if action == 461 then
    let state := load64 (wire+16) t
    if state == 5 then store64 transfer 6 (store64 (transfer+48) (load64 (transfer+48) t+1) t) else
    if state != 2 then t else
    let next := load64 (transfer+48) t+1
    let t := dirty (store64 (transfer+224) 0 (store64 (transfer+136) next (store64 (transfer+32) next (store64 (transfer+40) next t))))
    if next*512 >= load64 (transfer+24) t then notice 72 (store64 transfer 8 t) else store64 transfer 4 t
  else if action == 5 then
    if length != 128 || load64 (wire+16) t != 2 then notice 73 t else
    let n := load64 (wire+24) t
    let t := copy (wire+64) transferId 32 (copy (wire+96) expectedRoot 32 t)
    let t := Guest.MessengerProject.receiveBegin n t
    store64 transfer 21 (store64 (transfer+64) n (store64 (transfer+104) 0 t))
  else if action == 463 then
    let n := load64 (wire+16) t
    if n <= 16 || n > 528 || length != 64+n then notice 73 t else
    let t := copy (wire+64) ciphertext n t
    let t := header 434 (load64 (transfer+56) t) 3 (load64 (transfer+104) t) 0 0 0 t
    submitTransfer 434 3 (64+n) (copy ciphertext (wire+64) n t)
  else if action == 3 then
    let n := load64 (wire+16) t
    if n == 0 || n > 512 || length != 64+n then notice 73 t else
    let t := Guest.MessengerProject.feed (wire+64) n t
    let next := load64 (transfer+104) t+1
    let t := store64 (transfer+104) next (store64 transfer 21 t)
    if next%8 == 0 || next*512 >= load64 (transfer+64) t then dirty t else t
  else if action == 203 then notice 74 (store64 transfer 24 t)
  else notice 73 t
def restoredContact (t : UInt64) : UInt64 :=
  let slot := result t
  let state := load64 (wire+16) t
  if slot == 0 || slot > 4 || state == 0 || state > 3 then notice 24 t else
  let t := store64 (contact slot) (if state == 2 then 1 else 0) t
  let t := store64 (contact slot+40) (if load64 (wire+24) t == 1 then 1 else 0) t
  let t := copy (wire+64) (contact slot+8) 32 t
  let retainedMessage := if state == 2 && load64 (wire+40) t == 2 && load64 (wire+48) t > 208 && load64 (wire+48) t <= 720 then load64 (wire+32) t else 0
  let t := store64 (contact slot+48) retainedMessage (store64 (contact slot+56) (if retainedMessage == 0 then 0 else load64 (wire+48) t) t)
  let t := if load64 (st+24) t == 0 || load64 (st+24) t == slot then
    let t := copy (wire+64) fingerprint 32 t
    store64 (st+64) retainedMessage (store64 (st+248) slot
      (store64 (st+24) slot (store64 (st+48) (if state == 2 then 1 else 0) t)))
    else t
  nextRestoredContact t
def completedStatus (t : UInt64) : UInt64 :=
  let t := store64 (st+72) (result t) t
  let retained := load64 (wire+40) t
  let t := if load64 (st+80) t == retained then t else dirty (store64 (st+80) retained t)
  let latest := load64 (wire+32) t
  if latest == 0 || latest == load64 (st+88) t then
    let endpoint := syscall 128 4 463 0 0 t
    if endpoint == error then t else submit 463 64 (header 463 0 0 0 0 0 0 t) else
  submit 429 64 (header 429 latest 0 0 0 0 0 t)
def completedPlain (operation length t : UInt64) : UInt64 :=
  if operation == 434 && load64 (st+208) t != 0 && status t == 3 then nextRestoredContact t else
  if operation == 462 && status t == 14 then notice (if load64 (wire+16) t == 2 then 19 else 63) t else
  if operation == 460 && status t == 4 then notice 18 (store64 (st+104) (if load64 (st+104) t == 6 then 1 else 5) t) else
  if operation >= 460 && status t == 14 then notice 21 (store64 (st+104) 0 t) else
  if operation >= 460 && status t == 6 then notice 28 (store64 (st+104) (if load64 (st+104) t == 6 then 1 else 4) t) else
  if status t != 0 then failed length t else
  if operation == 420 && length == 64 then
    completedStatus t
  else if (operation == 421 || operation == 422) && length == 320 then
    let t := copy (wire+64) publicBundle 256 t
    let t := copy (publicBundle+192) federation 32 t
    notice (if operation == 421 then 41 else 30) (store64 (st+32) (if operation == 421 then 0 else 3) t)
  else if operation == 434 && length == 736 then
    let t := copy (wire+64) publicBundle 672 t
    let t := copy (publicBundle+192) federation 32 t
    notice 30 (store64 (st+200) 672 (store64 (st+32) 3 t))
  else if operation == 434 && length == 384 then
    let t := copy (wire+64) publicBundle 320 t
    let t := copy (publicBundle+192) federation 32 t
    notice 30 (store64 (st+200) 320 (store64 (st+32) 3 t))
  else if operation == 434 && length == 96 && load64 (st+208) t != 0 then
    restoredContact t
  else if operation == 423 && length == 96 then
    let t := store64 (st+24) (result t) t
    let t := copy (wire+64) fingerprint 32 t
    let t := copy fingerprint (contact (load64 (st+24) t)+8) 32 t
    let t := store64 (contact (load64 (st+24) t)+40) (if load64 (wire+24) t == 1 then 1 else 0) t
    notice 42 (store64 (st+48) 0 (store64 (st+32) 1 t))
  else if operation == 424 && length == 64 then
    notice 32 (store64 (contact (load64 (st+24) t)) 1 (store64 (st+48) 1 (store64 (st+32) 0 t)))
  else if operation == 425 && length == 64 then
    notice 33 (store64 (contact (load64 (st+24) t)) 0 (store64 (st+48) 0 t))
  else if operation == 426 && length == 64 then
    let chosen := load64 (st+264) t
    let t := store64 (st+248) chosen (store64 (contact chosen+48) (result t) (store64 (st+64) (result t) t))
    let t := store64 (st+104) 1 t
    let t := store64 (st+232) 1 t
    notice 18 (store64 (st+40) 0 (zero composeBuffer 64 t))
  else if (operation == 427 || operation == 435) && length >= 64 then
    let n := load64 (wire+16) t
    let message := result t
    let chosen := load64 (wire+32) t
    if message == 0 || chosen == 0 || chosen > 4 || n == 0 || n > 896 || length != 64+n || load64 (wire+24) t != 2 then notice 24 t else
    let t := store64 (st+64) message (store64 (contact chosen+48) message (store64 (contact chosen+56) n t))
    let t := store64 (st+240) n (store64 (st+248) (load64 (wire+32) t) t)
    let t := copy (wire+64) ciphertext n t
    let t := Guest.ServiceHash.sha256At hashScratch ciphertext n commitment t
    let t := header 460 (load64 (st+64) t) n 1 (load64 (wire+32) t) (load64 (st+232) t) 0 t
    let t := copy commitment (wire+64) 32 t
    submit 460 (96+n) (copy ciphertext (wire+96) n (store64 (st+104) 3 t))
  else if (operation == 460 || operation == 461) && length == 64 then
    let evidence := load64 (wire+16) t
    notice (if evidence == 2 then 19 else if evidence == 3 then 20 else 18)
      (store64 (st+104) (if evidence == 6 then 7 else if evidence == 2 || evidence == 3 then 0 else if load64 (st+104) t == 6 then 6 else 4) t)
  else if operation == 463 && length == 64 then
    let reason := load64 (wire+24) t
    if reason == 0 then t else notice (if reason == 9 then 24 else if reason == 5 then 23 else if reason == 12 then 26 else 21) t
  else if operation == 430 && length == 64 then notice 44 (store64 (st+104) 0 (store64 (st+32) 0 t))
  else if operation == 462 && length == 64 then
    if result t == 0 then notice 23 (store64 (st+104) 0 t) else
    submit 430 64 (header 430 (load64 (st+64) t) 0 0 0 0 0 t)
  else if (operation == 431 || operation == 433) && length == 64 then
    let t := clearPlaintext t
    let endpoint := syscall 128 4 462 0 0 t
    if endpoint == error then notice 23 endpoint else submit 462 64 (header 462 0 0 0 0 0 0 endpoint)
  else if operation == 432 && length == 64 then
    let t := store64 (st+32) 0 t
    if load64 (st+176) t != 1 then notice 64 t else
    submit 434 64 (header 434 1 15 0 0 0 0 (store64 (st+208) 1 t))
  else if operation == 429 && length >= 64 then
    let n := load64 (wire+16) t
    let source := load64 (wire+24) t
    if n > 512 || length != 64+n || source == 0 || source > 4 then notice 24 t else
    let t := parseReference (wire+64) n source t
    let t := store64 (history source+8) (load64 (wire+40) t) (store64 (history source) n t)
    let t := if source == load64 (st+24) t then store64 (transfer+56) (load64 (wire+40) t) t else t
    let t := copy (wire+64) (history source+64) n t
    let t := store64 (st+88) (result t) t
    let t := if source == load64 (st+24) t then copy (wire+64) displayText n (store64 (st+96) n t) else t
    notice 20 t
  else notice 45 t
def completed (operation action length t : UInt64) : UInt64 :=
  if operation == 434 && load64 (st+200) t == 672 && (status t == 3 || status t == 7) && action == 0 && load64 (st+208) t == 0 then
    submit 434 64 (header 434 0 12 0 0 0 0 (store64 (st+200) 320 t)) else
  if action != 0 then attachmentCompleted action length t else
  completedPlain operation length t
def collect (t : UInt64) : UInt64 :=
  let token := load64 (st+144) t
  if token == 0 then t else
  let r := Guest.MessengerSDK.collect token t
  if r == 0 then r else
  let operation := load64 (st+152) r
  let action := load64 (st+256) r
  let t := store64 (transfer+128) 0 (store64 (st+256) 0 (store64 (st+144) 0 r))
  if r == error || r < 64 || r > 1024 then failed r t else completed operation action r t
def nibble (c : UInt64) : UInt64 :=
  if c >= 48 && c <= 57 then c-48 else if c >= 97 && c <= 102 then c-87 else if c >= 65 && c <= 70 then c-55 else error
partial def parseInvite (i t : UInt64) : UInt64 :=
  if i == load64 (st+200) t then importBundle t else
  let high := nibble (load8 (inviteBuffer+i*2) t)
  let low := nibble (load8 (inviteBuffer+i*2+1) t)
  if high == error || low == error then notice 24 t else
  parseInvite (i+1) (store8 (publicBundle+i) (high*16+low) t)
partial def unlockCredential (i t : UInt64) : UInt64 :=
  if i == 32 then
    let t := header 432 (load64 (st+176) t) (load64 (st+184) t) 0 0 0 0 t
    let t := copy publicBundle (wire+64) 32 t
    let t := submit 432 96 t
    zero publicBundle 84 (zero inviteBuffer 168 (zero wire 128 t))
  else
    let high := nibble (load8 (inviteBuffer+i*2) t)
    let low := nibble (load8 (inviteBuffer+i*2+1) t)
    if high == error || low == error then notice 24 t else
    unlockCredential (i+1) (store8 (publicBundle+i) (high*16+low) t)
def unlockKey (code t : UInt64) : UInt64 :=
  if code == 1 then notice 23 (store64 (st+32) 0 (zero inviteBuffer 168 t)) else
  if code >= 59 && code <= 61 then dirty (store64 (st+176) (code-59) t) else
  if code == 62 then dirty (store64 (st+184) (1-load64 (st+184) t) t) else
  let n := load64 (st+56) t
  if code == 28 then if n == 64 then unlockCredential 0 t else notice 66 t else
  if code == 14 then
    let next := if n == 0 then 0 else n-1
    dirty (store64 (st+56) next (store8 (inviteBuffer+next) 0 t))
  else
  let c := Guest.Keyboard.scanCode code (load64 (st+112) t)
  if nibble c == error || n >= 64 then t else dirty (store64 (st+56) (n+1) (store8 (inviteBuffer+n) c t))
def turnExportPage (forward t : UInt64) : UInt64 :=
  let pages := if load64 (st+200) t == 672 then 3 else if load64 (st+200) t == 320 then 2 else 1
  let old := load64 (st+216) t%pages
  dirty (store64 (st+216) (if forward == 1 then (old+1)%pages else (old+pages-1)%pages) t)
def key (code t : UInt64) : UInt64 :=
  let mode := load64 (st+32) t
  if code == 66 then lock t else
  if mode == 5 then unlockKey code t else
  if code == 1 then
    if mode == 6 && load64 (transfer+216) t == 0 then notice 44 (store64 (st+32) 0 t) else
    if load64 (transfer+216) t != 0 then submitTransfer 462 304 64 (header 462 0 0 0 0 0 0 (store64 (st+32) 0 (cancelPending t))) else
    if load64 transfer t >= 20 then notice 44 (store64 transfer 9 (Guest.MessengerProject.fail 10 (cancelPending t))) else
    if load64 transfer t > 0 && load64 transfer t < 8 then
      submit 462 64 (header 462 (load64 (transfer+8) t) 0 0 0 0 0 (store64 transfer 9 (cancelPending t))) else cancel t else
  if code == 87 then chooseProject t else
  if code == 110 then importProject (store64 (transfer+72) 0 t) else
  if code == 60 then createIdentity t else
  if code == 61 then showInvitation t else
  if code == 62 then notice 29 (store64 (st+32) 2 (store64 (st+56) 0 (zero inviteBuffer 168 t))) else
  if code == 63 then approveContact t else
  if code == 64 then blockContact t else
  if code == 65 then
    if load64 transfer t == 9 && load64 (transfer+240) t == 2 then importProject (store64 (transfer+72) 1 t) else
    if load64 transfer t == 9 && load64 (transfer+8) t != 0 then notice 69 (store64 transfer 6 t) else retry t else
  if code == 67 then unlock t else
  if code == 68 then notice 36 (store64 (st+32) 4 t) else
  if code == 59 && mode == 0 && load64 (history (load64 (st+24) t)+640) t != 0 then inspectProjectReference t else
  if code == 59 || code == 15 then dirty (store64 (st+32) 0 t) else
  if mode == 3 && (code == 104 || code == 109 || code == 105 || code == 106) then
    turnExportPage (if code == 109 || code == 106 then 1 else 0) t else
  if mode == 0 && (code == 104 || code == 109) then
    if load64 (st+104) t != 0 || (load64 (st+144) t != 0 && load64 (st+152) t == 426) then notice 28 t else
    let old := load64 (st+24) t
    let next := if code == 104 then (old+2)%4+1 else old%4+1
    let t := copy (contact next+8) fingerprint 32 t
    let t := store64 (transfer+56) (load64 (history next+8) t) t
    let n := load64 (history next) t
    let t := copy (history next+64) displayText n (store64 (st+96) n t)
    notice (if load64 (contact next) t == 1 then 32 else 17)
      (store64 (st+64) (load64 (contact next+48) t) (store64 (st+248) next
        (store64 (st+24) next (store64 (st+48) (load64 (contact next) t) t))))
  else if code == 28 then
    if mode == 3 || mode == 6 then t else if mode == 1 then approveContact t else if mode == 4 then forget t else
    if mode == 2 then
      let n := load64 (st+56) t
      if n == 512 || n == 640 || n == 1344 then parseInvite 0 (store64 (st+200) (n/2) t) else notice 24 t
    else send t
  else if mode == 1 || mode == 3 || mode == 4 || mode == 6 then t else
  let ptr := if mode == 2 then inviteBuffer else composeBuffer
  let length := if mode == 2 then st+56 else st+40
  let n := load64 length t
  if code == 14 then
    let next := if n == 0 then 0 else n-1
    dirty (store64 length next (store8 (ptr+next) 0 t))
  else
  let c := Guest.Keyboard.scanCode code (load64 (st+112) t)
  if c < 32 || c > 126 || n >= (if mode == 2 then 1344 else 512) then t else dirty (store64 length (n+1) (store8 (ptr+n) c t))
def boundedMotion (old value limit : UInt64) : UInt64 :=
  if (value &&& 0x80000000) != 0 then
    let n := 0x100000000-value
    if n > old then 0 else old-n
  else if value > limit-old then limit else old+value
def click (t : UInt64) : UInt64 :=
  let x := load64 (st+120) t
  let y := load64 (st+128) t
  if load64 (st+32) t == 3 && y >= 260 && y < 292 then turnExportPage (if x >= 120 then 1 else 0) t else
  if y >= 250 && y < 274 && load64 (history (load64 (st+24) t)+640) t != 0 then inspectProjectReference t else
  if y >= 250 && y < 274 && load64 (transfer+56) t != 0 then importProject t else
  if y >= 378 && x < 310 then chooseProject t else
  if y >= 378 then importProject t else
  if y >= 88 && y < 112 then
    if x < 150 then createIdentity t else if x < 280 then showInvitation t else
    if x < 464 then notice 29 (store64 (st+32) 2 (store64 (st+56) 0 t)) else
    if x < 548 then approveContact t else blockContact t
  else if y >= 350 && y < 378 then
    if x < 130 then send t else if x < 240 then retry t else if x < 338 then lock t else
    if x < 446 then unlock t else notice 36 (store64 (st+32) 4 t)
  else if load64 (st+32) t == 1 && y >= 184 && y < 220 then approveContact t
  else dirty (store64 (st+32) 0 t)
def input (event t : UInt64) : UInt64 :=
  let kind := event >>> 48
  let code := (event >>> 32) &&& 65535
  let value := event &&& 0xffffffff
  if kind == 65535 || (kind == 0 && code == 3) then store64 (st+112) 0 t else
  if kind == 2 && code == 0 then store64 (st+120) (boundedMotion (load64 (st+120) t) value 639) t else
  if kind == 2 && code == 1 then store64 (st+128) (boundedMotion (load64 (st+128) t) value 399) t else
  if kind != 1 then t else
  if code == 42 || code == 54 then store64 (st+112) value t else
  if value != 1 then t else if code == 272 then click t else key code t
def routePump (t : UInt64) : UInt64 :=
  if load64 (st+144) t != 0 then t else
  let phase := load64 (st+104) t
  if phase == 1 then
    submit 460 64 (header 460 (load64 (st+64) t) 0 1 (load64 (st+248) t) 0 3 (store64 (st+104) 6 t))
  else if phase == 7 then
    let op := if load64 (st+232) t == 0 then 435 else 427
    submit op 64 (header op (load64 (st+64) t) 0 0 0 0 0 (store64 (st+104) 2 t))
  else if phase == 5 then
    let now := Guest.WaitSDK.now t
    if now < load64 (st+160) now then now else
    let n := load64 (st+240) now
    let t := header 460 (load64 (st+64) now) n 1 (load64 (st+248) now) (load64 (st+232) now) 0 now
    let t := copy commitment (wire+64) 32 t
    submit 460 (96+n) (copy ciphertext (wire+96) n (store64 (st+160) (now+100) t))
  else if phase == 4 || phase == 6 then
    let now := Guest.WaitSDK.now t
    if now < load64 (st+160) now then now else
    submit 461 64 (header 461 (load64 (st+64) now) 0 0 0 0 0 (store64 (st+160) (now+100) now))
  else t
def projectPump (t : UInt64) : UInt64 :=
  let t := if load64 transfer t >= 21 && load64 transfer t <= 23 then Guest.MessengerProject.pump t else t
  let t := if load64 transfer t >= 20 && Guest.MessengerProject.phase t >= 11 && Guest.MessengerProject.phase t <= 14 &&
    !Guest.ProjectGraph.equal expectedRoot (Guest.MessengerProject.index+32) 32 t then Guest.MessengerProject.fail 9 t else t
  if Guest.MessengerProject.phase t == 9 && load64 transfer t >= 20 then notice 73 (store64 transfer 9 t) else
  if load64 (st+144) t != 0 || load64 (st+104) t != 0 then t else
  if load64 (transfer+216) t == 2 then
    let count := load64 (transfer+248) t
    if count >= 64 then notice 80 (store64 (transfer+216) 0 t) else
    let t := header 463 0 3 0 0 0 0 (store64 (transfer+248) (count+1) t)
    submitTransfer 463 303 136 (copy reference (wire+64) 72 t) else
  if load64 (transfer+216) t == 1 then
    submitTransfer 461 303 64 (header 461 0 3 0 0 0 0 t) else
  let phase := load64 transfer t
  if phase == 1 then
    let r := projectPortal 4 0 (load64 (transfer+112) t) t
    if r != 64 || status r != 0 then notice 73 (store64 transfer 9 r) else
    if load64 (wire+16) r == 3 then notice 44 (store64 transfer 0 r) else
    if load64 (wire+16) r != 2 || result r == 0 then r else
    let r := Guest.MessengerProject.prepare (result r) r
    if Guest.MessengerProject.phase r != 1 then notice 73 (store64 transfer 9 r) else
    let bytes := Guest.MessengerProject.total r
    if load64 (transfer+224) r != 0 then
      if bytes != load64 (transfer+24) r || !Guest.ProjectGraph.equal expectedRoot Guest.MessengerProject.head 32 r then notice 73 (store64 transfer 9 r) else
      notice 69 (store64 transfer 4 r) else
    let n := load64 (Guest.MessengerProject.st+24) r
    let t := store64 (transfer+24) bytes (store64 transfer 2 r)
    let t := header 434 (load64 (transfer+16) t) 1 bytes 0 0 0 t
    submitTransfer 434 1 (64+n) (copy Guest.MessengerProject.name (wire+64) n t)
  else if phase == 3 then store64 transfer 4 (store64 (transfer+32) 0 (store64 (transfer+40) 0 t)) else
  if phase == 4 then
    let index := load64 (transfer+32) t
    let first := load64 (transfer+40) t
    if index >= first+14 || index*512 >= load64 (transfer+24) t then
      submitTransfer 434 17 64 (header 434 (load64 (transfer+8) t) 17 0 0 0 0 (store64 transfer 5 t))
    else
    let r := Guest.MessengerProject.slice index t
    if r == error then notice 73 (store64 transfer 9 r) else
    let n := load64 (Guest.MessengerProject.st+32) r
    let t := header 434 (load64 (transfer+8) r) 16 index 0 0 0 r
    submitTransfer 434 16 (64+n) (copy Guest.MessengerProject.page (wire+64) n t)
  else if phase == 6 then
    let t := header 460 (load64 (transfer+8) t) (load64 (transfer+48) t) 1 (load64 (transfer+16) t) (load64 (transfer+24) t) 2 t
    submitTransfer 460 460 72 (store64 (wire+64) (if load64 (transfer+224) t >= 3 then 0 else 1) t)
  else if phase == 7 then
    let now := Guest.WaitSDK.now t
    if now < load64 (st+160) now then now else
    submitTransfer 461 461 64 (header 461 (load64 (transfer+8) now) 0 0 0 0 0 (store64 (st+160) (now+50) now))
  else if phase == 21 then
    if Guest.MessengerProject.phase t == 14 then
      let t := header 463 (load64 (transfer+56) t) 2 0 0 0 0 t
      submitTransfer 463 203 96 (copy transferId (wire+64) 32 (store64 transfer 23 t))
    else if !Guest.MessengerProject.needsChunk t then t else
    let t := header 463 (load64 (transfer+56) t) 1 (load64 (transfer+104) t) (load64 (transfer+72) t) 0 0 t
    submitTransfer 463 463 96 (copy transferId (wire+64) 32 (store64 (transfer+72) 0 t))
  else t
def request (length t : UInt64) : UInt64 :=
  let token := load64 (incoming+8) t
  let op := load64 command t
  let admin := (load64 (incoming+16) t &&& 0x100000000) != 0
  if !admin || length < 96 || load64 (command+56) t != 1 then reply token 64 (header 1 0 0 0 0 0 0 t) else
  if op == 780 && (length == 352 || length == 416 || length == 768) then
    -- Import stages a candidate only. Actual approval remains a device gesture.
    let n := length-96
    let t := store64 (st+200) n (copy (command+64) publicBundle n t)
    let t := submit 423 (64+n) (copy publicBundle (wire+64) n (header 423 0 0 0 0 0 0 t))
    reply token 64 (header 0 (load64 (st+24) t) (load64 (st+32) t) 0 0 0 0 t)
  else if op == 781 && length == 128 then
    let t := copy (command+64) federation 32 t
    reply token 64 (header 0 0 0 0 0 0 0 (dirty t))
  else if op == 782 && length == 96 then
    let t := header 0 (load64 (st+24) t) (load64 (st+32) t) (load64 (st+40) t)
      (load64 (st+16) t) (load64 (st+48) t) (load64 (st+64) t) t
    reply token 96 (copy fingerprint (wire+64) 32 t)
  else if op == 783 && length == 96 then
    reply token 64 (header 0 (load64 (st+56) t) (load64 (st+176) t) (load64 (st+184) t)
      (load64 (st+152) t) (load64 (st+224) t) (if load64 (st+144) t == 0 then 0 else 1) t)
  else if op == 784 && length == 96 then
    let receiving := load64 transfer t >= 20
    reply token 64 (header 0 (load64 transfer t) (load64 (if receiving then transfer+104 else transfer+32) t)
      (load64 (if receiving then transfer+104 else transfer+136) t)
      (load64 (if receiving then transfer+64 else transfer+24) t)
      (Guest.MessengerProject.phase t) (load64 (Guest.MessengerProject.st+88) t) t)
  else if op == 785 && length == 96 then
    let t := header 0 (load64 (st+32) t) (load64 (transfer+192) t) (load64 (transfer+200) t)
      (load64 (transfer+208) t) (load64 (transfer+216) t) (load64 (reference+64) t) t
    reply token 128 (copy reference (wire+64) 64 t)
  else reply token 64 (header 7 0 0 0 0 0 0 t)
partial def inputPump (fuel t : UInt64) : UInt64 :=
  if fuel == 0 then t else
  let event := syscall 90 (self t) 0 0 0 t
  if event == 0 || event == error then event else inputPump (fuel-1) (input event event)
partial def loop (surface t : UInt64) : UInt64 :=
  let n := syscall 36 (self t) incoming 1024 0 t
  let t := if n >= 96 && n <= 1024 then request n n else n
  let t := inputPump 8 t
  let t := collect t
  let t := projectPump (routePump t)
  let now := Guest.WaitSDK.now t
  let t := if now >= load64 (st+136) now && load64 (st+144) now == 0 then checkStatus (store64 (st+136) (now+50) now) else now
  let t := if load64 (st+8) t == 1 then draw surface t else t
  loop surface (Guest.WaitSDK.deadline (Guest.WaitSDK.now t+1) t)
def main (t : UInt64) : UInt64 :=
  let t := Guest.MessengerProject.clear (zero transfer 32 t)
  let t := zero st 32 (zero 0x70c000 640 (zero 0x70b000 40 (zero composeBuffer 64 (zero inviteBuffer 168 (zero fingerprint 4 (zero displayText 64 t))))))
  let t := store64 (st+120) 320 (store64 (st+128) 200 t)
  let t := notice 46 t
  let surface := syscall 80 0 0 0 0 t
  if surface == error then error else loop surface (draw surface surface)
end Guest.Messenger
