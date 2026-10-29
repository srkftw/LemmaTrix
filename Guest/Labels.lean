import Guest.Raster
namespace Guest.Labels
open Guest.LiveSDK
def say0 (id x y fg bg t : UInt64) : UInt64 :=
  if id == 0 then
    let t := store64 (0x414000+0) 5283377952305530188 t
    let t := store64 (0x414000+8) 5494708344262238296 t
    let t := store64 (0x414000+16) 5712288646302015572 t
    let t := store64 (0x414000+24) 3550561073718580547 t
    let t := store64 (0x414000+32) 4704928183514839602 t
    let t := store64 (0x414000+40) 4981016905358787911 t
    let t := store64 (0x414000+48) 5427758134812361555 t
    let t := store64 (0x414000+56) 5263188 t
    Guest.Raster.text 0x414000 59 x y fg bg t
  else
  if id == 1 then
    let t := store64 (0x414000+0) 4836942236695675214 t
    let t := store64 (0x414000+8) 6278108381223929170 t
    let t := store64 (0x414000+16) 4990904625307275855 t
    Guest.Raster.text 0x414000 24 x y fg bg t
  else
  if id == 2 then
    let t := store64 (0x414000+0) 2327318950915034697 t
    let t := store64 (0x414000+8) 5716274384606350913 t
    let t := store64 (0x414000+16) 5485463872982163538 t
    let t := store64 (0x414000+24) 5999152372517052500 t
    let t := store64 (0x414000+32) 5932402086896541765 t
    let t := store64 (0x414000+40) 5715103404726178645 t
    let t := store64 (0x414000+48) 1279349842 t
    Guest.Raster.text 0x414000 52 x y fg bg t
  else
  if id == 3 then
    let t := store64 (0x414000+0) 4692826967166504787 t
    let t := store64 (0x414000+8) 4992890351843820622 t
    let t := store64 (0x414000+16) 4995689717088408643 t
    let t := store64 (0x414000+24) 4995711634075305248 t
    let t := store64 (0x414000+32) 2325339864327670048 t
    let t := store64 (0x414000+40) 6000295842513504340 t
    let t := store64 (0x414000+48) 84 t
    Guest.Raster.text 0x414000 49 x y fg bg t
  else
  if id == 4 then
    let t := store64 (0x414000+0) 4706900758732755013 t
    let t := store64 (0x414000+8) 5713189219406651468 t
    let t := store64 (0x414000+16) 4707463729538474062 t
    let t := store64 (0x414000+24) 2330978181359619657 t
    let t := store64 (0x414000+32) 2326187639265445972 t
    let t := store64 (0x414000+40) 2329298080182714959 t
    let t := store64 (0x414000+48) 362057908566 t
    Guest.Raster.text 0x414000 53 x y fg bg t
  else
  if id == 5 then
    let t := store64 (0x414000+0) 5773689786745702739 t
    let t := store64 (0x414000+8) 4836942172136358721 t
    let t := store64 (0x414000+16) 4995689648203517505 t
    Guest.Raster.text 0x414000 24 x y fg bg t
  else
  if id == 6 then
    let t := store64 (0x414000+0) 5932740723593398611 t
    let t := store64 (0x414000+8) 4993158576714489925 t
    let t := store64 (0x414000+16) 5715947674664968260 t
    let t := store64 (0x414000+24) 3264920808279200341 t
    let t := store64 (0x414000+32) 6134000902296455490 t
    let t := store64 (0x414000+40) 4992598942643738190 t
    let t := store64 (0x414000+48) 68 t
    Guest.Raster.text 0x414000 49 x y fg bg t
  else
  if id == 7 then
    let t := store64 (0x414000+0) 4692814936744939077 t
    let t := store64 (0x414000+8) 4981057424872067152 t
    let t := store64 (0x414000+16) 5495889219081683288 t
    let t := store64 (0x414000+24) 4921943049620373829 t
    let t := store64 (0x414000+32) 6076276554990965280 t
    let t := store64 (0x414000+40) 6073182477745144901 t
    let t := store64 (0x414000+48) 83 t
    Guest.Raster.text 0x414000 49 x y fg bg t
  else
  if id == 8 then
    let t := store64 (0x414000+0) 5638862014140076869 t
    let t := store64 (0x414000+8) 2314986685891102019 t
    let t := store64 (0x414000+16) 5782938908404961100 t
    let t := store64 (0x414000+24) 5269295407528104528 t
    let t := store64 (0x414000+32) 4702637982384791635 t
    let t := store64 (0x414000+40) 4918247758710456660 t
    let t := store64 (0x414000+48) 22042224532605261 t
    Guest.Raster.text 0x414000 55 x y fg bg t
  else
  if id == 9 then
    let t := store64 (0x414000+0) 2314940709138416709 t
    let t := store64 (0x414000+8) 2314946163643527494 t
    let t := store64 (0x414000+16) 2327874268624335430 t
    let t := store64 (0x414000+24) 6077683898986481184 t
    let t := store64 (0x414000+32) 5053074263914399264 t
    let t := store64 (0x414000+40) 6073470566923444276 t
    Guest.Raster.text 0x414000 48 x y fg bg t
  else
  if id == 10 then
    let t := store64 (0x414000+0) 4921389123339564358 t
    let t := store64 (0x414000+8) 6002815756029796384 t
    let t := store64 (0x414000+16) 3982906243680519504 t
    let t := store64 (0x414000+24) 4054963837450076448 t
    let t := store64 (0x414000+32) 2325349725488108064 t
    let t := store64 (0x414000+40) 5714299721233286688 t
    let t := store64 (0x414000+48) 17750 t
    Guest.Raster.text 0x414000 50 x y fg bg t
  else
  if id == 11 then
    let t := store64 (0x414000+0) 6134001787244532803 t
    let t := store64 (0x414000+8) 5932440414413866062 t
    let t := store64 (0x414000+16) 5711766446444978252 t
    let t := store64 (0x414000+24) 4692834728204771360 t
    let t := store64 (0x414000+32) 2329560872168805152 t
    let t := store64 (0x414000+40) 5000257 t
    Guest.Raster.text 0x414000 43 x y fg bg t
  else
  if id == 12 then
    let t := store64 (0x414000+0) 4995371889277157715 t
    let t := store64 (0x414000+8) 4995090457417044819 t
    let t := store64 (0x414000+16) 86102439577942 t
    Guest.Raster.text 0x414000 22 x y fg bg t
  else
  if id == 13 then
    let t := store64 (0x414000+0) 5717073820008991044 t
    let t := store64 (0x414000+8) 6143508332314970962 t
    let t := store64 (0x414000+16) 1380271686 t
    Guest.Raster.text 0x414000 20 x y fg bg t
  else
  if id == 14 then
    let t := store64 (0x414000+0) 2314926363914882899 t
    let t := store64 (0x414000+8) 4992890351843811452 t
    let t := store64 (0x414000+16) 4764844123245007939 t
    let t := store64 (0x414000+24) 2340781229282707797 t
    let t := store64 (0x414000+32) 4995408177572172320 t
    let t := store64 (0x414000+40) 5284487217052131360 t
    let t := store64 (0x414000+48) 297481946436 t
    Guest.Raster.text 0x414000 53 x y fg bg t
  else
  if id == 15 then
    let t := store64 (0x414000+0) 2329560872135905872 t
    let t := store64 (0x414000+8) 250270794062 t
    Guest.Raster.text 0x414000 13 x y fg bg t
  else
    t
def say1 (id x y fg bg t : UInt64) : UInt64 :=
  if id == 16 then
    let t := store64 (0x414000+0) 5566816514915191110 t
    let t := store64 (0x414000+8) 14917 t
    Guest.Raster.text 0x414000 10 x y fg bg t
  else
  if id == 17 then
    let t := store64 (0x414000+0) 4846190211749924421 t
    let t := store64 (0x414000+8) 2319107875388015939 t
    let t := store64 (0x414000+16) 4849885605284500293 t
    let t := store64 (0x414000+24) 5459013 t
    Guest.Raster.text 0x414000 27 x y fg bg t
  else
  if id == 18 then
    let t := store64 (0x414000+0) 5281962940799405902 t
    let t := store64 (0x414000+8) 5715718976601150548 t
    let t := store64 (0x414000+16) 357895980362 t
    Guest.Raster.text 0x414000 21 x y fg bg t
  else
  if id == 19 then
    let t := store64 (0x414000+0) 5716267792019443273 t
    let t := store64 (0x414000+8) 4774189795988283474 t
    let t := store64 (0x414000+16) 2325339890010572108 t
    let t := store64 (0x414000+24) 4990918853677829697 t
    let t := store64 (0x414000+32) 1498567763 t
    Guest.Raster.text 0x414000 36 x y fg bg t
  else
  if id == 20 then
    let t := store64 (0x414000+0) 250253231432 t
    Guest.Raster.text 0x414000 5 x y fg bg t
  else
  if id == 21 then
    let t := store64 (0x414000+0) 16418243796418896 t
    Guest.Raster.text 0x414000 7 x y fg bg t
  else
  if id == 22 then
    let t := store64 (0x414000+0) 5927335537282733378 t
    let t := store64 (0x414000+8) 4705792257738359881 t
    let t := store64 (0x414000+16) 4993438935067214166 t
    let t := store64 (0x414000+24) 2329574104225697568 t
    let t := store64 (0x414000+32) 4995691851606282051 t
    let t := store64 (0x414000+40) 68 t
    Guest.Raster.text 0x414000 41 x y fg bg t
  else
  if id == 23 then
    let t := store64 (0x414000+0) 6147730444047177026 t
    let t := store64 (0x414000+8) 4981030804479366469 t
    let t := store64 (0x414000+16) 5570745070212301144 t
    let t := store64 (0x414000+24) 5989862568961001805 t
    let t := store64 (0x414000+32) 23731070097703246 t
    Guest.Raster.text 0x414000 39 x y fg bg t
  else
  if id == 24 then
    let t := store64 (0x414000+0) 6071777314571439939 t
    let t := store64 (0x414000+8) 6075168229269065504 t
    let t := store64 (0x414000+16) 6216465364745527361 t
    let t := store64 (0x414000+24) 5570745070196707145 t
    let t := store64 (0x414000+32) 6000292582634309965 t
    let t := store64 (0x414000+40) 293221061189 t
    Guest.Raster.text 0x414000 45 x y fg bg t
  else
  if id == 25 then
    let t := store64 (0x414000+0) 2329560872135905872 t
    let t := store64 (0x414000+8) 4995710560466980675 t
    let t := store64 (0x414000+16) 6000293476758528068 t
    let t := store64 (0x414000+24) 5629549150989142355 t
    let t := store64 (0x414000+32) 4774187606158103631 t
    let t := store64 (0x414000+40) 17740 t
    Guest.Raster.text 0x414000 42 x y fg bg t
  else
  if id == 26 then
    let t := store64 (0x414000+0) 5567946812868544838 t
    let t := store64 (0x414000+8) 5715707981484873295 t
    let t := store64 (0x414000+16) 5641122825148768333 t
    let t := store64 (0x414000+24) 76164036304967 t
    Guest.Raster.text 0x414000 30 x y fg bg t
  else
  if id == 27 then
    let t := store64 (0x414000+0) 5354588986060260686 t
    let t := store64 (0x414000+8) 4919373546160145221 t
    let t := store64 (0x414000+16) 6000285956133901385 t
    let t := store64 (0x414000+24) 3766733658883904544 t
    let t := store64 (0x414000+32) 23724494402044704 t
    Guest.Raster.text 0x414000 39 x y fg bg t
  else
  if id == 28 then
    let t := store64 (0x414000+0) 4836941064252510287 t
    let t := store64 (0x414000+8) 4919430888955923791 t
    let t := store64 (0x414000+16) 6071772908086251552 t
    Guest.Raster.text 0x414000 24 x y fg bg t
  else
  if id == 29 then
    let t := store64 (0x414000+0) 4995090414417040706 t
    let t := store64 (0x414000+8) 6076553404338689363 t
    let t := store64 (0x414000+16) 5716229304632230721 t
    let t := store64 (0x414000+24) 6147223414686107936 t
    let t := store64 (0x414000+32) 5782989515451089746 t
    let t := store64 (0x414000+40) 1414482003 t
    Guest.Raster.text 0x414000 44 x y fg bg t
  else
  if id == 30 then
    let t := store64 (0x414000+0) 6278094117454233934 t
    let t := store64 (0x414000+8) 6278082005578764879 t
    let t := store64 (0x414000+16) 4764860221640430159 t
    let t := store64 (0x414000+24) 5485436162019775577 t
    let t := store64 (0x414000+32) 1397050953 t
    Guest.Raster.text 0x414000 36 x y fg bg t
  else
  if id == 31 then
    let t := store64 (0x414000+0) 6004779685926424398 t
    let t := store64 (0x414000+8) 5281684768618988613 t
    let t := store64 (0x414000+16) 86102439641411 t
    Guest.Raster.text 0x414000 22 x y fg bg t
  else
    t
def say2 (id x y fg bg t : UInt64) : UInt64 :=
  if id == 32 then
    let t := store64 (0x414000+0) 4995709443909961042 t
    let t := store64 (0x414000+8) 6004503674201710660 t
    let t := store64 (0x414000+16) 58 t
    Guest.Raster.text 0x414000 17 x y fg bg t
  else
  if id == 33 then
    let t := store64 (0x414000+0) 2325356322407335250 t
    let t := store64 (0x414000+8) 3818569 t
    Guest.Raster.text 0x414000 11 x y fg bg t
  else
  if id == 34 then
    let t := store64 (0x414000+0) 4203058317122032208 t
    Guest.Raster.text 0x414000 8 x y fg bg t
  else
  if id == 35 then
    let t := store64 (0x414000+0) 4707463729538675014 t
    let t := store64 (0x414000+8) 6003370107942751817 t
    let t := store64 (0x414000+16) 3550560743006162760 t
    let t := store64 (0x414000+24) 2329570836309483569 t
    let t := store64 (0x414000+32) 91625950893139 t
    Guest.Raster.text 0x414000 38 x y fg bg t
  else
  if id == 36 then
    let t := store64 (0x414000+0) 5713977573656314198 t
    let t := store64 (0x414000+8) 2329010957306907459 t
    let t := store64 (0x414000+16) 4705216255664148053 t
    let t := store64 (0x414000+24) 4541506 t
    Guest.Raster.text 0x414000 27 x y fg bg t
  else
  if id == 37 then
    let t := store64 (0x414000+0) 2329000185696964432 t
    let t := store64 (0x414000+8) 4780928668396703297 t
    let t := store64 (0x414000+16) 4995126543548301647 t
    let t := store64 (0x414000+24) 5917822626987067168 t
    let t := store64 (0x414000+32) 293220930895 t
    Guest.Raster.text 0x414000 37 x y fg bg t
  else
  if id == 38 then
    let t := store64 (0x414000+0) 2325913809414213442 t
    let t := store64 (0x414000+8) 4702683010837860935 t
    let t := store64 (0x414000+16) 4990913446934749260 t
    Guest.Raster.text 0x414000 24 x y fg bg t
  else
  if id == 39 then
    let t := store64 (0x414000+0) 5713977569511165766 t
    let t := store64 (0x414000+8) 6432630244336751699 t
    let t := store64 (0x414000+16) 5999152372517052499 t
    let t := store64 (0x414000+24) 17477 t
    Guest.Raster.text 0x414000 26 x y fg bg t
  else
  if id == 40 then
    let t := store64 (0x414000+0) 4703482338544801090 t
    let t := store64 (0x414000+8) 5989837121010355273 t
    let t := store64 (0x414000+16) 5640548841236219205 t
    let t := store64 (0x414000+24) 91548458177359 t
    Guest.Raster.text 0x414000 30 x y fg bg t
  else
  if id == 41 then
    let t := store64 (0x414000+0) 5928228362266693443 t
    let t := store64 (0x414000+8) 6003102896253125664 t
    let t := store64 (0x414000+16) 1396918612 t
    Guest.Raster.text 0x414000 20 x y fg bg t
  else
  if id == 42 then
    let t := store64 (0x414000+0) 6074323736522149710 t
    let t := store64 (0x414000+8) 5931276221315883066 t
    let t := store64 (0x414000+16) 4692842433091029583 t
    let t := store64 (0x414000+24) 5567936023907812690 t
    let t := store64 (0x414000+32) 1279349317 t
    Guest.Raster.text 0x414000 36 x y fg bg t
  else
  if id == 43 then
    let t := store64 (0x414000+0) 5639949650602840656 t
    let t := store64 (0x414000+8) 5701644350989157716 t
    let t := store64 (0x414000+16) 4993442310173640016 t
    let t := store64 (0x414000+24) 5715718976601150531 t
    let t := store64 (0x414000+32) 1413694794 t
    Guest.Raster.text 0x414000 36 x y fg bg t
  else
  if id == 44 then
    let t := store64 (0x414000+0) 2327891868612964678 t
    let t := store64 (0x414000+8) 5284202444410274124 t
    let t := store64 (0x414000+16) 17484 t
    Guest.Raster.text 0x414000 18 x y fg bg t
  else
  if id == 45 then
    let t := store64 (0x414000+0) 6071207754764144705 t
    let t := store64 (0x414000+8) 1397641033 t
    Guest.Raster.text 0x414000 12 x y fg bg t
  else
  if id == 46 then
    let t := store64 (0x414000+0) 5711444230145660226 t
    let t := store64 (0x414000+8) 3251675159203696717 t
    let t := store64 (0x414000+16) 5211589785677025312 t
    let t := store64 (0x414000+24) 5282237793204982341 t
    let t := store64 (0x414000+32) 4995371953765238606 t
    let t := store64 (0x414000+40) 76228175479120 t
    Guest.Raster.text 0x414000 46 x y fg bg t
  else
  if id == 47 then
    let t := store64 (0x414000+0) 4990923338413196626 t
    let t := store64 (0x414000+8) 92725396261152 t
    Guest.Raster.text 0x414000 14 x y fg bg t
  else
    t
def say3 (id x y fg bg t : UInt64) : UInt64 :=
  if id == 48 then
    let t := store64 (0x414000+0) 2329296989227799120 t
    let t := store64 (0x414000+8) 5930994780700229958 t
    let t := store64 (0x414000+16) 4919426473830667040 t
    Guest.Raster.text 0x414000 24 x y fg bg t
  else
  if id == 49 then
    let t := store64 (0x414000+0) 2322261205764948559 t
    let t := store64 (0x414000+8) 4995128742570444114 t
    let t := store64 (0x414000+16) 5284487431796905025 t
    let t := store64 (0x414000+24) 4995126715595375955 t
    let t := store64 (0x414000+32) 2325347586728612384 t
    let t := store64 (0x414000+40) 5789453326140787020 t
    let t := store64 (0x414000+48) 5526095 t
    Guest.Raster.text 0x414000 51 x y fg bg t
  else
  if id == 50 then
    let t := store64 (0x414000+0) 4204463523148024132 t
    let t := store64 (0x414000+8) 4995689725513846816 t
    let t := store64 (0x414000+16) 4919426473729475360 t
    let t := store64 (0x414000+24) 4990904582341481248 t
    let t := store64 (0x414000+32) 6076851569370869536 t
    let t := store64 (0x414000+40) 4995430159265177658 t
    let t := store64 (0x414000+48) 98184266195012 t
    Guest.Raster.text 0x414000 54 x y fg bg t
  else
  if id == 51 then
    let t := store64 (0x414000+0) 6061931174976308562 t
    let t := store64 (0x414000+8) 4846251727945681224 t
    let t := store64 (0x414000+16) 4847362278478061652 t
    let t := store64 (0x414000+24) 5211597435214962772 t
    let t := store64 (0x414000+32) 21583 t
    Guest.Raster.text 0x414000 34 x y fg bg t
  else
  if id == 52 then
    let t := store64 (0x414000+0) 5917794035389713989 t
    let t := store64 (0x414000+8) 5639949628959970373 t
    let t := store64 (0x414000+16) 2325059536057619011 t
    let t := store64 (0x414000+24) 4836930060630171695 t
    let t := store64 (0x414000+32) 327579553345 t
    Guest.Raster.text 0x414000 37 x y fg bg t
  else
  if id == 53 then
    let t := store64 (0x414000+0) 64129318801230 t
    Guest.Raster.text 0x414000 6 x y fg bg t
  else
  if id == 54 then
    let t := store64 (0x414000+0) 64129319852354 t
    Guest.Raster.text 0x414000 6 x y fg bg t
  else
  if id == 55 then
    let t := store64 (0x414000+0) 2325348630054196548 t
    let t := store64 (0x414000+8) 6075153945012031059 t
    let t := store64 (0x414000+16) 6076562393587991328 t
    let t := store64 (0x414000+24) 17477 t
    Guest.Raster.text 0x414000 26 x y fg bg t
  else
  if id == 56 then
    let t := store64 (0x414000+0) 4992331761217328464 t
    let t := store64 (0x414000+8) 64155089051730 t
    Guest.Raster.text 0x414000 14 x y fg bg t
  else
  if id == 57 then
    let t := store64 (0x414000+0) 5557518095621640019 t
    let t := store64 (0x414000+8) 4200804335598523457 t
    let t := store64 (0x414000+16) 5572159235322495776 t
    let t := store64 (0x414000+24) 5498419195321536069 t
    let t := store64 (0x414000+32) 6004218922249035865 t
    let t := store64 (0x414000+40) 4919417621985969696 t
    Guest.Raster.text 0x414000 48 x y fg bg t
  else
  if id == 58 then
    let t := store64 (0x414000+0) 5716267792019443273 t
    let t := store64 (0x414000+8) 7935450713589555282 t
    let t := store64 (0x414000+16) 8026370501749536869 t
    let t := store64 (0x414000+24) 2321119761747960946 t
    let t := store64 (0x414000+32) 2314971646344324466 t
    let t := store64 (0x414000+40) 8392569429265958432 t
    let t := store64 (0x414000+48) 435610543648 t
    Guest.Raster.text 0x414000 53 x y fg bg t
  else
  if id == 59 then
    let t := store64 (0x414000+0) 5989839320034199883 t
    let t := store64 (0x414000+8) 2319107797960443971 t
    let t := store64 (0x414000+16) 2319107875136624962 t
    let t := store64 (0x414000+24) 2325059536022491719 t
    let t := store64 (0x414000+32) 91621454989650 t
    Guest.Raster.text 0x414000 38 x y fg bg t
  else
  if id == 60 then
    let t := store64 (0x414000+0) 6061921292272096339 t
    let t := store64 (0x414000+8) 4922238818230554713 t
    let t := store64 (0x414000+16) 1145643077 t
    Guest.Raster.text 0x414000 20 x y fg bg t
  else
  if id == 61 then
    let t := store64 (0x414000+0) 5917806104196240467 t
    let t := store64 (0x414000+8) 2327885233745647173 t
    let t := store64 (0x414000+16) 92695147200848 t
    Guest.Raster.text 0x414000 22 x y fg bg t
  else
  if id == 62 then
    let t := store64 (0x414000+0) 2325055116469158224 t
    let t := store64 (0x414000+8) 59602104305747 t
    Guest.Raster.text 0x414000 14 x y fg bg t
  else
  if id == 63 then
    let t := store64 (0x414000+0) 2329572966898226499 t
    let t := store64 (0x414000+8) 5931276186839499086 t
    let t := store64 (0x414000+16) 4992275733218150991 t
    let t := store64 (0x414000+24) 17473 t
    Guest.Raster.text 0x414000 26 x y fg bg t
  else
    t
def say4 (id x y fg bg t : UInt64) : UInt64 :=
  if id == 64 then
    let t := store64 (0x414000+0) 4995090414300059988 t
    let t := store64 (0x414000+8) 6000276081990583622 t
    let t := store64 (0x414000+16) 2318338333566771258 t
    let t := store64 (0x414000+24) 7810774612209721715 t
    let t := store64 (0x414000+32) 7020584489267590241 t
    let t := store64 (0x414000+40) 7089075326267712877 t
    let t := store64 (0x414000+48) 8246126395372103020 t
    let t := store64 (0x414000+56) 2020173413 t
    Guest.Raster.text 0x414000 60 x y fg bg t
  else
  if id == 65 then
    let t := store64 (0x414000+0) 8245918730096242510 t
    let t := store64 (0x414000+8) 7810775711956410468 t
    let t := store64 (0x414000+16) 2319107948690039653 t
    let t := store64 (0x414000+24) 7305792376618905454 t
    let t := store64 (0x414000+32) 8458358700353418099 t
    let t := store64 (0x414000+40) 7593480606250724457 t
    let t := store64 (0x414000+48) 435610083692 t
    Guest.Raster.text 0x414000 53 x y fg bg t
  else
  if id == 66 then
    let t := store64 (0x414000+0) 111477796466515 t
    Guest.Raster.text 0x414000 6 x y fg bg t
  else
  if id == 67 then
    let t := store64 (0x414000+0) 2338603393740665424 t
    let t := store64 (0x414000+8) 8391162021251277165 t
    Guest.Raster.text 0x414000 16 x y fg bg t
  else
  if id == 68 then
    let t := store64 (0x414000+0) 431315580226 t
    Guest.Raster.text 0x414000 5 x y fg bg t
  else
  if id == 69 then
    let t := store64 (0x414000+0) 4207896288998221138 t
    let t := store64 (0x414000+8) 7142837043686435104 t
    let t := store64 (0x414000+16) 2322578050336976495 t
    let t := store64 (0x414000+24) 8247626254411852147 t
    let t := store64 (0x414000+32) 8097789220709539941 t
    let t := store64 (0x414000+40) 8439864867546952304 t
    let t := store64 (0x414000+48) 8391179665156367731 t
    let t := store64 (0x414000+56) 55187211314277 t
    Guest.Raster.text 0x414000 62 x y fg bg t
  else
  if id == 70 then
    let t := store64 (0x414000+0) 7305804402280461893 t
    Guest.Raster.text 0x414000 8 x y fg bg t
  else
  if id == 71 then
    let t := store64 (0x414000+0) 2327306907641136452 t
    let t := store64 (0x414000+8) 4990923338413196626 t
    let t := store64 (0x414000+16) 2329011180729025824 t
    let t := store64 (0x414000+24) 8245937404401304352 t
    let t := store64 (0x414000+32) 8515590487923712833 t
    let t := store64 (0x414000+40) 7305792289328013361 t
    let t := store64 (0x414000+48) 128060694099054 t
    Guest.Raster.text 0x414000 54 x y fg bg t
  else
  if id == 72 then
    let t := store64 (0x414000+0) 3328195744760619350 t
    let t := store64 (0x414000+8) 2314885531172155950 t
    let t := store64 (0x414000+16) 7959953205044991264 t
    let t := store64 (0x414000+24) 8315166010787783456 t
    let t := store64 (0x414000+32) 2314961763472340512 t
    let t := store64 (0x414000+40) 8243122709926518816 t
    let t := store64 (0x414000+48) 8315168201473286432 t
    let t := store64 (0x414000+56) 7166147436356837408 t
    let t := store64 (0x414000+64) 8317134089574507296 t
    Guest.Raster.text 0x414000 72 x y fg bg t
  else
  if id == 73 then
    let t := store64 (0x414000+0) 5494759097004282447 t
    let t := store64 (0x414000+8) 5715155142083358496 t
    let t := store64 (0x414000+16) 4474195 t
    Guest.Raster.text 0x414000 19 x y fg bg t
  else
  if id == 74 then
    let t := store64 (0x414000+0) 7308323456518811973 t
    let t := store64 (0x414000+8) 7310868735955334254 t
    let t := store64 (0x414000+16) 8462108807998087226 t
    let t := store64 (0x414000+24) 7599372962078483314 t
    let t := store64 (0x414000+32) 2338328219548084595 t
    let t := store64 (0x414000+40) 28259048195715683 t
    Guest.Raster.text 0x414000 47 x y fg bg t
  else
  if id == 75 then
    let t := store64 (0x414000+0) 8028075828261973577 t
    let t := store64 (0x414000+8) 7020378939280089454 t
    let t := store64 (0x414000+16) 7018969010014876782 t
    let t := store64 (0x414000+24) 8102082520686094190 t
    let t := store64 (0x414000+32) 8031924123500312940 t
    let t := store64 (0x414000+40) 8458358678761335666 t
    let t := store64 (0x414000+48) 3766733513611896422 t
    let t := store64 (0x414000+56) 8319390330368516896 t
    Guest.Raster.text 0x414000 64 x y fg bg t
  else
  if id == 76 then
    let t := store64 (0x414000+0) 8007476190270092355 t
    let t := store64 (0x414000+8) 8295737305619916144 t
    let t := store64 (0x414000+16) 2334102057442962533 t
    let t := store64 (0x414000+24) 8371756774824567649 t
    let t := store64 (0x414000+32) 7883941909811459192 t
    let t := store64 (0x414000+40) 8462109104396069985 t
    let t := store64 (0x414000+48) 6644594 t
    Guest.Raster.text 0x414000 51 x y fg bg t
  else
  if id == 77 then
    let t := store64 (0x414000+0) 2334106421097295433 t
    let t := store64 (0x414000+8) 7305808869231650162 t
    let t := store64 (0x414000+16) 8244249722772135994 t
    let t := store64 (0x414000+24) 7020383269764210789 t
    let t := store64 (0x414000+32) 3834025831700635756 t
    let t := store64 (0x414000+40) 8101729887664568096 t
    let t := store64 (0x414000+48) 7359000956843813236 t
    let t := store64 (0x414000+56) 8603403748697534057 t
    let t := store64 (0x414000+64) 1701734764 t
    Guest.Raster.text 0x414000 68 x y fg bg t
  else
  if id == 78 then
    let t := store64 (0x414000+0) 7017568567410188611 t
    let t := store64 (0x414000+8) 7598805589467209836 t
    let t := store64 (0x414000+16) 7165919078633203062 t
    let t := store64 (0x414000+24) 111520460447845 t
    Guest.Raster.text 0x414000 30 x y fg bg t
  else
  if id == 79 then
    let t := store64 (0x414000+0) 2336927755351057747 t
    let t := store64 (0x414000+8) 7020303078580646503 t
    let t := store64 (0x414000+16) 7311153513409571699 t
    let t := store64 (0x414000+24) 8246782936275446048 t
    let t := store64 (0x414000+32) 7526769937259720293 t
    let t := store64 (0x414000+40) 7935391443582546543 t
    let t := store64 (0x414000+48) 8387235364731188837 t
    let t := store64 (0x414000+56) 431198464353 t
    Guest.Raster.text 0x414000 61 x y fg bg t
  else
    t
def say5 (id x y fg bg t : UInt64) : UInt64 :=
  if id == 80 then
    let t := store64 (0x414000+0) 7305808869231650130 t
    let t := store64 (0x414000+8) 7234304290904367392 t
    let t := store64 (0x414000+16) 7742373266839270432 t
    let t := store64 (0x414000+24) 7378714103804030569 t
    let t := store64 (0x414000+32) 7142766484802728549 t
    let t := store64 (0x414000+40) 7575181517059353967 t
    let t := store64 (0x414000+48) 7308324466020674925 t
    let t := store64 (0x414000+56) 8028074707559739936 t
    let t := store64 (0x414000+64) 110 t
    Guest.Raster.text 0x414000 65 x y fg bg t
  else
  if id == 81 then
    let t := store64 (0x414000+0) 7309940760863405378 t
    let t := store64 (0x414000+8) 7810757020275733875 t
    let t := store64 (0x414000+16) 2337214414352510575 t
    let t := store64 (0x414000+24) 8822395977998759017 t
    let t := store64 (0x414000+32) 7165919078633205349 t
    let t := store64 (0x414000+40) 7310030993675533157 t
    let t := store64 (0x414000+48) 2334097595051308142 t
    let t := store64 (0x414000+56) 7935454015552840045 t
    let t := store64 (0x414000+64) 1919252325 t
    Guest.Raster.text 0x414000 68 x y fg bg t
  else
  if id == 82 then
    let t := store64 (0x414000+0) 2327306864691728204 t
    let t := store64 (0x414000+8) 2329560872135905872 t
    let t := store64 (0x414000+16) 2325343128267934028 t
    let t := store64 (0x414000+24) 17481 t
    Guest.Raster.text 0x414000 26 x y fg bg t
  else
    t
def say6 (id x y fg bg t : UInt64) : UInt64 :=
  if id == 96 then
    let t := store64 (0x414000+0) 2322251216327963715 t
    let t := store64 (0x414000+8) 7597414702928717923 t
    let t := store64 (0x414000+16) 7165919078633206894 t
    let t := store64 (0x414000+24) 8245937481777160293 t
    let t := store64 (0x414000+32) 121 t
    Guest.Raster.text 0x414000 33 x y fg bg t
  else
  if id == 97 then
    let t := store64 (0x414000+0) 7597414702928717891 t
    let t := store64 (0x414000+8) 7310030993675547758 t
    let t := store64 (0x414000+16) 7165919078633206894 t
    let t := store64 (0x414000+24) 2323709439362670693 t
    let t := store64 (0x414000+32) 8026294636604845637 t
    let t := store64 (0x414000+40) 2322576946747762286 t
    let t := store64 (0x414000+48) 7164771135566082885 t
    let t := store64 (0x414000+56) 779316325 t
    Guest.Raster.text 0x414000 60 x y fg bg t
  else
  if id == 98 then
    let t := store64 (0x414000+0) 7598257706442777931 t
    let t := store64 (0x414000+8) 7521981564372019559 t
    let t := store64 (0x414000+16) 7885080994131572329 t
    let t := store64 (0x414000+24) 4283895688056370281 t
    let t := store64 (0x414000+32) 8389754698058785568 t
    let t := store64 (0x414000+40) 8295757393064191520 t
    let t := store64 (0x414000+48) 8391403612172542324 t
    let t := store64 (0x414000+56) 8319395793566458721 t
    let t := store64 (0x414000+64) 8367799666768964640 t
    let t := store64 (0x414000+72) 8390047166775912808 t
    let t := store64 (0x414000+80) 46 t
    Guest.Raster.text 0x414000 81 x y fg bg t
  else
  if id == 99 then
    let t := store64 (0x414000+0) 7597414702928717891 t
    let t := store64 (0x414000+8) 7813865678659679342 t
    let t := store64 (0x414000+16) 7309978950672151653 t
    let t := store64 (0x414000+24) 8223624735748355169 t
    let t := store64 (0x414000+32) 7234308675814056805 t
    let t := store64 (0x414000+40) 8314896634767307296 t
    let t := store64 (0x414000+48) 58 t
    Guest.Raster.text 0x414000 49 x y fg bg t
  else
  if id == 100 then
    let t := store64 (0x414000+0) 2334402176956461633 t
    let t := store64 (0x414000+8) 2334097638073917808 t
    let t := store64 (0x414000+16) 8439857173818335597 t
    let t := store64 (0x414000+24) 7089066488320385390 t
    let t := store64 (0x414000+32) 7307218278599779692 t
    let t := store64 (0x414000+40) 2338340653495361650 t
    let t := store64 (0x414000+48) 7236833183485161057 t
    let t := store64 (0x414000+56) 8314330363680222825 t
    let t := store64 (0x414000+64) 2336921123819975200 t
    let t := store64 (0x414000+72) 13058235735894384 t
    Guest.Raster.text 0x414000 79 x y fg bg t
  else
  if id == 101 then
    let t := store64 (0x414000+0) 7597414702928717891 t
    let t := store64 (0x414000+8) 7308332162361619566 t
    let t := store64 (0x414000+16) 7599372963416128100 t
    let t := store64 (0x414000+24) 8390047166775915887 t
    let t := store64 (0x414000+32) 8534995790118154272 t
    let t := store64 (0x414000+40) 3040357 t
    Guest.Raster.text 0x414000 43 x y fg bg t
  else
  if id == 102 then
    let t := store64 (0x414000+0) 7234316346692756819 t
    let t := store64 (0x414000+8) 8386658438904705056 t
    let t := store64 (0x414000+16) 8315171486950240032 t
    let t := store64 (0x414000+24) 58 t
    Guest.Raster.text 0x414000 25 x y fg bg t
  else
  if id == 103 then
    let t := store64 (0x414000+0) 7142830407995191887 t
    let t := store64 (0x414000+8) 7954884663572262255 t
    let t := store64 (0x414000+16) 7521981564116213876 t
    let t := store64 (0x414000+24) 7018130082659399273 t
    let t := store64 (0x414000+32) 14948 t
    Guest.Raster.text 0x414000 34 x y fg bg t
  else
    t
def say7 (id x y fg bg t : UInt64) : UInt64 :=
  if id == 104 then
    let t := store64 (0x414000+0) 7881701908395749190 t
    let t := store64 (0x414000+8) 7575185850760700005 t
    let t := store64 (0x414000+16) 4285584516693517668 t
    let t := store64 (0x414000+24) 7018141438805308704 t
    let t := store64 (0x414000+32) 2338346091007909997 t
    let t := store64 (0x414000+40) 7310575239018079603 t
    let t := store64 (0x414000+48) 14889 t
    Guest.Raster.text 0x414000 50 x y fg bg t
  else
  if id == 105 then
    let t := store64 (0x414000+0) 7809933828255343950 t
    let t := store64 (0x414000+8) 8462299375528866665 t
    let t := store64 (0x414000+16) 8747515638088035426 t
    let t := store64 (0x414000+24) 2320539253970585888 t
    let t := store64 (0x414000+32) 8314035730082393964 t
    let t := store64 (0x414000+40) 16371145723355237 t
    Guest.Raster.text 0x414000 47 x y fg bg t
  else
  if id == 106 then
    let t := store64 (0x414000+0) 7310014136068501318 t
    let t := store64 (0x414000+8) 8606132852387837025 t
    let t := store64 (0x414000+16) 7598819853036232814 t
    let t := store64 (0x414000+24) 7308895020947241332 t
    let t := store64 (0x414000+32) 8439872597044586337 t
    let t := store64 (0x414000+40) 2334102031740531566 t
    let t := store64 (0x414000+48) 8462299349826956917 t
    let t := store64 (0x414000+56) 8028075772393122914 t
    let t := store64 (0x414000+64) 11886 t
    Guest.Raster.text 0x414000 66 x y fg bg t
  else
  if id == 107 then
    let t := store64 (0x414000+0) 7593462736151015238 t
    let t := store64 (0x414000+8) 8318277293049144684 t
    let t := store64 (0x414000+16) 7309940799333298804 t
    let t := store64 (0x414000+24) 8319591566782587245 t
    let t := store64 (0x414000+32) 199270097505 t
    Guest.Raster.text 0x414000 37 x y fg bg t
  else
    t
def say (id x y fg bg t : UInt64) : UInt64 :=
  if id < 16 then say0 id x y fg bg t else
  if id < 32 then say1 id x y fg bg t else
  if id < 48 then say2 id x y fg bg t else
  if id < 64 then say3 id x y fg bg t else
  if id < 80 then say4 id x y fg bg t else
  if id < 96 then say5 id x y fg bg t else
  if id < 104 then say6 id x y fg bg t else
  say7 id x y fg bg t
end Guest.Labels
