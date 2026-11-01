import Guest.FeedAccountSDK
import Guest.Raster
import Guest.Keyboard
import Guest.WaitSDK
import Guest.ProjectSDK
import Guest.LiveMemory
namespace Guest.Feed
open Guest.LiveSDK Guest.Raster
-- Graphic-only process: published/plaintext data and explicit user input.
-- A separate owner speaks mode1 and Identity holds every signing seed.
def st : UInt64 := 0x700000
def labels : UInt64 := 0x701000
def compose : UInt64 := 0x710000
def content : UInt64 := 0x714000
def references : UInt64 := 0x719000
def identity : UInt64 := 0x71a000
def selected : UInt64 := 0x71b000
def eventId : UInt64 := 0x71b200
def accountScope : UInt64 := 0x71c000
def credentialText : UInt64 := 0x71d000
def credential : UInt64 := 0x71d100
def portable : UInt64 := 0x720000
def project : UInt64 := 0x724000
def selectedRoot : UInt64 := 0x725000
def hashOut : UInt64 := 0x726000
def bg : UInt64 := 0x111d2a
def fg : UInt64 := 0xe3ecf4
def accent : UInt64 := 0x8cdec6
def dirty (t : UInt64) : UInt64 := store64 st 1 t
def notice (n t : UInt64) : UInt64 := dirty (store64 (st+32) n t)
-- Separate label tables keep nested raster calls within the ordinary16KiB stack.
@[noinline] def label0 (id x y color t : UInt64) : UInt64 :=
  -- 0: Feed / LemmaNET
  if id == 0 then
    let t := store64 (labels+0) 5485436162307089734 t
    let t := store64 (labels+8) 23720100988022117 t
    text labels 15 x y color bg t
  -- 1: F2 Identity  F3 Compose  F4 Preview  F5 Publish
  else if id == 1 then
    let t := store64 (labels+0) 8389754637235794502 t
    let t := store64 (labels+8) 2320275336823665769 t
    let t := store64 (labels+16) 2334398904326254403 t
    let t := store64 (labels+24) 8531350757586519584 t
    let t := store64 (labels+32) 2320838286776952169 t
    let t := store64 (labels+40) 29400294205060432 t
    text labels 47 x y color bg t
  -- 2: F6 Reply  F7 Follow  F8 Block  F9 Report  F10 Appeal
  else if id == 2 then
    let t := store64 (labels+0) 8749491756545881670 t
    let t := store64 (labels+8) 7813540982691340320 t
    let t := store64 (labels+16) 2321682711707086700 t
    let t := store64 (labels+24) 5053074427511532610 t
    let t := store64 (labels+32) 8390891584271556665 t
    let t := store64 (labels+40) 8088781797091319840 t
    let t := store64 (labels+48) 1818322288 t
    text labels 52 x y color bg t
  -- 3: PgDn Next  PgUp First  Enter Read  Tab Filter
  else if id == 3 then
    let t := store64 (labels+0) 8675426158395025232 t
    let t := store64 (labels+8) 2337462108819562612 t
    let t := store64 (labels+16) 4981016872396941638 t
    let t := store64 (labels+24) 7018105893638468718 t
    let t := store64 (labels+32) 5053146952072437860 t
    let t := store64 (labels+40) 491328400489 t
    text labels 45 x y color bg t
  -- 4: No identity. Select federation, then F2.
  else if id == 4 then
    let t := store64 (labels+0) 8389754637772681038 t
    let t := store64 (labels+8) 7810740526427763817 t
    let t := store64 (labels+16) 7306075984807355237 t
    let t := store64 (labels+24) 2318349332978622834 t
    let t := store64 (labels+32) 3328800179685255284 t
    text labels 40 x y color bg t
  -- 5: Ready / privacy-required mode1
  else if id == 5 then
    let t := store64 (labels+0) 2319108038866330962 t
    let t := store64 (labels+8) 3276759474138346096 t
    let t := store64 (labels+16) 7234314173708068210 t
    let t := store64 (labels+24) 54311546481952 t
    text labels 30 x y color bg t
  -- 6: Working; input remains available
  else if id == 6 then
    let t := store64 (labels+0) 4280511369892228951 t
    let t := store64 (labels+8) 8223700967324805408 t
    let t := store64 (labels+16) 6998720738985340261 t
    let t := store64 (labels+24) 7308324465885667702 t
    text labels 32 x y color bg t
  -- 7: Draft / Enter inserts a new line / Esc closes
  else if id == 7 then
    let t := store64 (labels+0) 2319108017425052228 t
    let t := store64 (labels+8) 7955925892427181637 t
    let t := store64 (labels+16) 2333181762201609587 t
    let t := store64 (labels+24) 7308895158390973806 t
    let t := store64 (labels+32) 7142818355741732640 t
    let t := store64 (labels+40) 495623303020 t
    text labels 45 x y color bg t
  -- 8: Preview exact content and audience; F5 publishes
  else if id == 8 then
    let t := store64 (labels+0) 2339450035074593360 t
    let t := store64 (labels+8) 8026294645159983205 t
    let t := store64 (labels+16) 7953674101353444462 t
    let t := store64 (labels+24) 7954880197006794852 t
    let t := store64 (labels+32) 8079516306807416163 t
    let t := store64 (labels+40) 8315167131908727413 t
    text labels 48 x y color bg t
  -- 9: Pending / signed event staged
  else if id == 9 then
    let t := store64 (labels+0) 2334956330750469456 t
    let t := store64 (labels+8) 7234309766870409263 t
    let t := store64 (labels+16) 8295758531113936160 t
    let t := store64 (labels+24) 431198003572 t
    text labels 29 x y color bg t
  -- 10: Durably accepted by federation
  else if id == 10 then
    let t := store64 (labels+0) 2340020651193169220 t
    let t := store64 (labels+8) 7234316402526741345 t
    let t := store64 (labels+16) 7306075984807682592 t
    let t := store64 (labels+24) 121424789660018 t
    text labels 30 x y color bg t
  -- 11: Replicated under signed audience
  else if id == 11 then
    let t := store64 (labels+0) 8386093285582595410 t
    let t := store64 (labels+8) 8243105118545798245 t
    let t := store64 (labels+16) 2334102031740531488 t
    let t := store64 (labels+24) 7305804402364020065 t
    text labels 32 x y color bg t
  -- 12: Failed / inspect reason; F5 retries exact event
  else if id == 12 then
    let t := store64 (labels+0) 3395824505810673990 t
    let t := store64 (labels+8) 8386658464741353760 t
    let t := store64 (labels+16) 4282482837021880864 t
    let t := store64 (labels+24) 8247328358463260192 t
    let t := store64 (labels+32) 7161137258227262825 t
    let t := store64 (labels+40) 32772479355527284 t
    text labels 47 x y color bg t
  -- 13: Reconciliation required after uncertain response
  else if id == 13 then
    let t := store64 (labels+0) 7811884354617173330 t
    let t := store64 (labels+8) 8223694344368185705 t
    let t := store64 (labels+16) 2334102048954741093 t
    let t := store64 (labels+24) 7959303592147707489 t
    let t := store64 (labels+32) 2336921123938264419 t
    let t := store64 (labels+40) 7310308045059482994 t
    text labels 48 x y color bg t
  -- 14: Unsupported action in current native profile
  else if id == 14 then
    let t := store64 (labels+0) 8245933071047814741 t
    let t := store64 (labels+8) 7598807740087297396 t
    let t := store64 (labels+16) 8458640183714147951 t
    let t := store64 (labels+24) 7020584553557619314 t
    let t := store64 (labels+32) 8030604369998539124 t
    let t := store64 (labels+40) 1701603686 t
    text labels 44 x y color bg t
  -- 15: Reading committed signed content
  else if id == 15 then
    let t := store64 (labels+0) 2334956330749617490 t
    let t := store64 (labels+8) 7310596091285434211 t
    let t := store64 (labels+16) 7234309766870409316 t
    let t := store64 (labels+24) 8389754706581218080 t
    text labels 32 x y color bg t
  else t
@[noinline] def label1 (id x y color t : UInt64) : UInt64 :=
  -- 16: Locally blocked; federation reversal cannot unblock
  if id == 16 then
    let t := store64 (labels+0) 2340020694141857612 t
    let t := store64 (labels+8) 4279657057812966498 t
    let t := store64 (labels+16) 8386109760942204448 t
    let t := store64 (labels+24) 7311142585927364457 t
    let t := store64 (labels+32) 7953747407821435762 t
    let t := store64 (labels+40) 7809926153148591982 t
    let t := store64 (labels+48) 7037807 t
    text labels 51 x y color bg t
  -- 17: Following author locally
  else if id == 17 then
    let t := store64 (labels+0) 7956021537170812742 t
    let t := store64 (labels+8) 8245924292133462119 t
    let t := store64 (labels+16) 8749487341609905184 t
    text labels 24 x y color bg t
  -- 18: Blocked author locally / press F8 to unblock
  else if id == 18 then
    let t := store64 (labels+0) 2334102018788912194 t
    let t := store64 (labels+8) 7791353178170357089 t
    let t := store64 (labels+16) 3395847625619104623 t
    let t := store64 (labels+24) 5053165721370128416 t
    let t := store64 (labels+32) 7092735245324394552 t
    let t := store64 (labels+40) 1801678700 t
    text labels 44 x y color bg t
  -- 19: Report goes only to home federation moderators
  else if id == 19 then
    let t := store64 (labels+0) 7431067420006049106 t
    let t := store64 (labels+8) 8749489599638889839 t
    let t := store64 (labels+16) 7308620263303640096 t
    let t := store64 (labels+24) 8386109760942204448 t
    let t := store64 (labels+32) 7306087009988013929 t
    let t := store64 (labels+40) 126935333364082 t
    text labels 46 x y color bg t
  -- 20: Appeal requests an explicit authorized result
  else if id == 20 then
    let t := store64 (labels+0) 8223692085148020801 t
    let t := store64 (labels+8) 2338340670507676005 t
    let t := store64 (labels+16) 7596570333862194785 t
    let t := store64 (labels+24) 7526769937259719011 t
    let t := store64 (labels+32) 8223683306586731119 t
    let t := store64 (labels+40) 500035842917 t
    text labels 45 x y color bg t
  -- 21: Identity public key / home federation / peer audience
  else if id == 21 then
    let t := store64 (labels+0) 8751735924676977737 t
    let t := store64 (labels+8) 2333824946137296928 t
    let t := store64 (labels+16) 8027701722568287595 t
    let t := store64 (labels+24) 8243105079639434605 t
    let t := store64 (labels+32) 2319107991806768225 t
    let t := store64 (labels+40) 7238798768054035824 t
    let t := store64 (labels+48) 435459876201 t
    text labels 53 x y color bg t
  -- 22: Audience: home federation only
  else if id == 22 then
    let t := store64 (labels+0) 7305804402364020033 t
    let t := store64 (labels+8) 7358993311818326074 t
    let t := store64 (labels+16) 8028075772644516965 t
    let t := store64 (labels+24) 133506616205422 t
    text labels 30 x y color bg t
  -- 23: Audience: home plus selected peer federation
  else if id == 23 then
    let t := store64 (labels+0) 7305804402364020033 t
    let t := store64 (labels+8) 8079569252197605434 t
    let t := store64 (labels+16) 7308327840455554412 t
    let t := store64 (labels+24) 7306369254904132707 t
    let t := store64 (labels+32) 7021786250896351346 t
    let t := store64 (labels+40) 1852795252 t
    text labels 44 x y color bg t
  -- 24: A toggles audience before preview
  else if id == 24 then
    let t := store64 (labels+0) 7308329989264646209 t
    let t := store64 (labels+8) 7954880197006794867 t
    let t := store64 (labels+16) 8245922028362687843 t
    let t := store64 (labels+24) 7307502048469065829 t
    let t := store64 (labels+32) 119 t
    text labels 33 x y color bg t
  -- 25: Selected event / author validity is separate from policy
  else if id == 25 then
    let t := store64 (labels+0) 7234316346692756819 t
    let t := store64 (labels+8) 3395842136534836512 t
    let t := store64 (labels+16) 2338053650979840288 t
    let t := store64 (labels+24) 8751735855874072950 t
    let t := store64 (labels+32) 7021223364210682144 t
    let t := store64 (labels+40) 8030593374882128242 t
    let t := store64 (labels+48) 8746950815730638957 t
    text labels 56 x y color bg t
  -- 26: No events available under selected scope
  else if id == 26 then
    let t := store64 (labels+0) 8389754715014983502 t
    let t := store64 (labels+8) 7020101786482581619 t
    let t := store64 (labels+16) 7306085944835533922 t
    let t := store64 (labels+24) 8386658447326912626 t
    let t := store64 (labels+32) 7309464668146263141 t
    text labels 40 x y color bg t
  -- 27: Local filter: chronological
  else if id == 27 then
    let t := store64 (labels+0) 7594793471469383500 t
    let t := store64 (labels+8) 7521891238038303852 t
    let t := store64 (labels+16) 7595161808100290418 t
    let t := store64 (labels+24) 7102819 t
    text labels 27 x y color bg t
  -- 28: Local filter: followed authors only
  else if id == 28 then
    let t := store64 (labels+0) 7594793471469383500 t
    let t := store64 (labels+8) 8027138821233931372 t
    let t := store64 (labels+16) 6998704207892016236 t
    let t := store64 (labels+24) 8007527072797324405 t
    let t := store64 (labels+32) 7957614 t
    text labels 35 x y color bg t
  -- 29: F11 Project card / F1 Retention / Esc Cancel
  else if id == 29 then
    let t := store64 (labels+0) 7669474378898288966 t
    let t := store64 (labels+8) 7237954629511963493 t
    let t := store64 (labels+16) 7300933341922996000 t
    let t := store64 (labels+24) 2336927755367507316 t
    let t := store64 (labels+32) 7008481056626384943 t
    let t := store64 (labels+40) 1818583918 t
    text labels 44 x y color bg t
  -- 30: Retention: explicit Objects-domain consent required
  else if id == 30 then
    let t := store64 (labels+0) 8028075828261971282 t
    let t := store64 (labels+8) 7596570333862181486 t
    let t := store64 (labels+16) 7307761437348489571 t
    let t := store64 (labels+24) 7020389870190425187 t
    let t := store64 (labels+32) 7310308044835941993 t
    let t := store64 (labels+40) 7599104626777945198 t
    let t := store64 (labels+48) 6579570 t
    text labels 51 x y color bg t
  -- 31: Export approved state via native Objects
  else if id == 31 then
    let t := store64 (labels+0) 6998721855778486341 t
    let t := store64 (labels+8) 2334102066235076720 t
    let t := store64 (labels+16) 7599297041350620275 t
    let t := store64 (labels+24) 7311146993654308961 t
    let t := store64 (labels+32) 8319383698887823136 t
    text labels 40 x y color bg t
  else t
@[noinline] def label2 (id x y color t : UInt64) : UInt64 :=
  -- 32: Private drafts and follow graph are never published
  if id == 32 then
    let t := store64 (labels+0) 2334399943808741968 t
    let t := store64 (labels+8) 6998720764704813668 t
    let t := store64 (labels+16) 8028911461405320302 t
    let t := store64 (labels+24) 2335239970625101943 t
    let t := store64 (labels+32) 7311142568746906209 t
    let t := store64 (labels+40) 8316297357049208946 t
    let t := store64 (labels+48) 6579560 t
    text labels 51 x y color bg t
  -- 33: Project card references original signed release
  else if id == 33 then
    let t := store64 (labels+0) 2338603393740665424 t
    let t := store64 (labels+8) 7378429047966163299 t
    let t := store64 (labels+16) 2338324109263729253 t
    let t := store64 (labels+24) 7809644627822735983 t
    let t := store64 (labels+32) 2334102031740531488 t
    let t := store64 (labels+40) 28555834798400882 t
    text labels 47 x y color bg t
  -- 34: C Continue in Forge / local action needs approval
  else if id == 34 then
    let t := store64 (labels+0) 7956018234388586563 t
    let t := store64 (labels+8) 8018131845161969013 t
    let t := store64 (labels+16) 8028827622473820018 t
    let t := store64 (labels+24) 7598807740087820643 t
    let t := store64 (labels+32) 8314882298346499695 t
    let t := store64 (labels+40) 7022923206234235168 t
    let t := store64 (labels+48) 108 t
    text labels 49 x y color bg t
  -- 35: Shortcuts: E edit own selected event / T tombstone
  else if id == 35 then
    let t := store64 (labels+0) 8391722832462047315 t
    let t := store64 (labels+8) 7594306060926597747 t
    let t := store64 (labels+16) 7310222278974709876 t
    let t := store64 (labels+24) 7286934583992608108 t
    let t := store64 (labels+32) 6061896914879538550 t
    let t := store64 (labels+40) 8031170902088447008 t
    let t := store64 (labels+48) 25966 t
    text labels 50 x y color bg t
  -- 36: Locked; publishing identity has been revoked locally
  else if id == 36 then
    let t := store64 (labels+0) 2322560419595775820 t
    let t := store64 (labels+8) 7595447668187493744 t
    let t := store64 (labels+16) 8389754637772679022 t
    let t := store64 (labels+24) 2338319731384743017 t
    let t := store64 (labels+32) 8531350552739931490 t
    let t := store64 (labels+40) 7165064418548869999 t
    let t := store64 (labels+48) 2037148769 t
    text labels 52 x y color bg t
  -- 37: Compose longer text up to 16384 bytes
  else if id == 37 then
    let t := store64 (labels+0) 2334398904326254403 t
    let t := store64 (labels+8) 8367813887506935660 t
    let t := store64 (labels+16) 8367811756012370021 t
    let t := store64 (labels+24) 2320541500606324847 t
    let t := store64 (labels+32) 495623371106 t
    text labels 37 x y color bg t
  -- 38: Signed event id
  else if id == 38 then
    let t := store64 (labels+0) 7286934583892207955 t
    let t := store64 (labels+8) 28263085784327542 t
    text labels 15 x y color bg t
  -- 39: Body bytes / local receive cursor
  else if id == 39 then
    let t := store64 (labels+0) 8392847272196730690 t
    let t := store64 (labels+8) 7165064417655157605 t
    let t := store64 (labels+16) 7594585633987783777 t
    let t := store64 (labels+24) 8030888409031533942 t
    let t := store64 (labels+32) 114 t
    text labels 33 x y color bg t
  -- 40: Policy event result is in signed federation timeline
  else if id == 40 then
    let t := store64 (labels+0) 7286957664962899792 t
    let t := store64 (labels+8) 8315177770727400822 t
    let t := store64 (labels+16) 7575181468590435445 t
    let t := store64 (labels+24) 7234309766870409326 t
    let t := store64 (labels+32) 8386109760942204448 t
    let t := store64 (labels+40) 7308613717773414249 t
    let t := store64 (labels+48) 1701734764 t
    text labels 52 x y color bg t
  -- 41: Retention: F2 Create F3 Recover F4 Preferences F5 Apply
  else if id == 41 then
    let t := store64 (labels+0) 8028075828261971282 t
    let t := store64 (labels+8) 8233459944060369518 t
    let t := store64 (labels+16) 2320275337980961125 t
    let t := store64 (labels+24) 2338042715908040018 t
    let t := store64 (labels+32) 7306638987100173382 t
    let t := store64 (labels+40) 5053165661206766962 t
    let t := store64 (labels+48) 34177702357442613 t
    text labels 55 x y color bg t
  -- 42: F6 Lock F7 Forget F8 Export public profile F9 Import
  else if id == 42 then
    let t := store64 (labels+0) 2336070161391433286 t
    let t := store64 (labels+8) 7306934742675371846 t
    let t := store64 (labels+16) 8104303534138597492 t
    let t := store64 (labels+24) 7809933828255150703 t
    let t := store64 (labels+32) 7594880358905045865 t
    let t := store64 (labels+40) 7874860853795775852 t
    let t := store64 (labels+48) 1953656688 t
    text labels 52 x y color bg t
  -- 43: Credential: 64 hexadecimal digits; separate unlock key
  else if id == 43 then
    let t := store64 (labels+0) 7598819853035991619 t
    let t := store64 (labels+8) 7503054386272824417 t
    let t := store64 (labels+16) 7883941909815720037 t
    let t := store64 (labels+24) 8388349483303332961 t
    let t := store64 (labels+32) 8241992374090218355 t
    let t := store64 (labels+40) 8028913685028500577 t
    let t := store64 (labels+48) 133476495944547 t
    text labels 54 x y color bg t
  -- 44: Preferences export is explicit / no private key material
  else if id == 44 then
    let t := store64 (labels+0) 7954890096655037008 t
    let t := store64 (labels+8) 8030050511333057891 t
    let t := store64 (labels+16) 8675375937256191090 t
    let t := store64 (labels+24) 3395842115025595504 t
    let t := store64 (labels+32) 8532476794936192544 t
    let t := store64 (labels+40) 2340012992175109217 t
    let t := store64 (labels+48) 7809639168886464877 t
    text labels 56 x y color bg t
  -- 45: Portable state is an ordinary scoped Objects object
  else if id == 45 then
    let t := store64 (labels+0) 7308324466020478800 t
    let t := store64 (labels+8) 7575166123762807584 t
    let t := store64 (labels+16) 7237969736219304051 t
    let t := store64 (labels+24) 7166107138058710633 t
    let t := store64 (labels+32) 7665776516279922799 t
    let t := store64 (labels+40) 7665811700904649573 t
    let t := store64 (labels+48) 7627621 t
    text labels 51 x y color bg t
  -- 46: Recovered history needs current authority to publish
  else if id == 46 then
    let t := store64 (labels+0) 7310016704525067602 t
    let t := store64 (labels+8) 8245937481777160292 t
    let t := store64 (labels+16) 2338323018191609977 t
    let t := store64 (labels+24) 2338615488502986083 t
    let t := store64 (labels+32) 8388361603773658465 t
    let t := store64 (labels+40) 7094700072603230329 t
    let t := store64 (labels+48) 1752394092 t
    text labels 52 x y color bg t
  -- 47: Original release admission is rechecked before Fork
  else if id == 47 then
    let t := store64 (labels+0) 7809644627822735951 t
    let t := store64 (labels+8) 7310293708390625824 t
    let t := store64 (labels+16) 7598543892948214048 t
    let t := store64 (labels+24) 7309940825232797295 t
    let t := store64 (labels+32) 2334102018788255843 t
    let t := store64 (labels+40) 5053150324079355234 t
    let t := store64 (labels+48) 7041647 t
    text labels 51 x y color bg t
  else t
@[noinline] def label3 (id x y color t : UInt64) : UInt64 :=
  -- 48: F11 selects actual signed Registry release; C inspects
  if id == 48 then
    let t := store64 (labels+0) 7308327840451211590 t
    let t := store64 (labels+8) 8463498868543419491 t
    let t := store64 (labels+16) 7308892947869625441 t
    let t := store64 (labels+24) 8391166423523795044 t
    let t := store64 (labels+32) 7018134777289013618 t
    let t := store64 (labels+40) 7955925689402353011 t
    let t := store64 (labels+48) 126943720992883 t
    text labels 54 x y color bg t
  -- 49: Fork requires exact card root in trusted project picker
  else if id == 49 then
    let t := store64 (labels+0) 8171062582500814662 t
    let t := store64 (labels+8) 8675375937194453365 t
    let t := store64 (labels+16) 7237954629511963489 t
    let t := store64 (labels+24) 7955925901184561696 t
    let t := store64 (labels+32) 7234316415681066016 t
    let t := store64 (labels+40) 8386658438904705056 t
    let t := store64 (labels+48) 32199659248775200 t
    text labels 55 x y color bg t
  -- 50: Imported preferences; create a fresh destination identity
  else if id == 50 then
    let t := store64 (labels+0) 7234316411285302601 t
    let t := store64 (labels+8) 7310016635638804512 t
    let t := store64 (labels+16) 8242467182729323374 t
    let t := store64 (labels+24) 7358988582892364133 t
    let t := store64 (labels+32) 8315162377363613042 t
    let t := store64 (labels+40) 7957695015158704500 t
    let t := store64 (labels+48) 8388363798450563360 t
    let t := store64 (labels+56) 121 t
    text labels 57 x y color bg t
  -- 51: Author unblocked locally; federation policy remains
  else if id == 51 then
    let t := store64 (labels+0) 8439871524511708481 t
    let t := store64 (labels+8) 7234306451255878254 t
    let t := store64 (labels+16) 8749487341609905184 t
    let t := store64 (labels+24) 7021786250896351291 t
    let t := store64 (labels+32) 7813587163105159540 t
    let t := store64 (labels+40) 7020378934985974633 t
    let t := store64 (labels+48) 7564905 t
    text labels 51 x y color bg t
  -- 52: New local Fork publisher public ID: 64 hexadecimal digits
  else if id == 52 then
    let t := store64 (labels+0) 7017575154565211470 t
    let t := store64 (labels+8) 8079575870739980396 t
    let t := store64 (labels+16) 8243109537870799477 t
    let t := store64 (labels+24) 2333824946137296928 t
    let t := store64 (labels+32) 7503054386272814153 t
    let t := store64 (labels+40) 7883941909815720037 t
    let t := store64 (labels+48) 8388349483303332961 t
    let t := store64 (labels+56) 115 t
    text labels 57 x y color bg t
  -- 53: Enter confirms chosen publisher and opens trusted picker
  else if id == 53 then
    let t := store64 (labels+0) 8026294636604845637 t
    let t := store64 (labels+8) 7142835922917746286 t
    let t := store64 (labels+16) 8462299358349717352 t
    let t := store64 (labels+24) 2338042655846001762 t
    let t := store64 (labels+32) 7954887939406982753 t
    let t := store64 (labels+40) 7310595043397738611 t
    let t := store64 (labels+48) 8243112767686451300 t
    text labels 56 x y color bg t
  -- 54: Feed state committed in selected Objects domain
  else if id == 54 then
    let t := store64 (labels+0) 7022364301937960262 t
    let t := store64 (labels+8) 7596848471615759732 t
    let t := store64 (labels+16) 2336920844496106612 t
    let t := store64 (labels+24) 7234316346692756851 t
    let t := store64 (labels+32) 8319383698887823136 t
    let t := store64 (labels+40) 31078114606933024 t
    text labels 47 x y color bg t
  -- 55: Federation decision: hide / exact event scope
  else if id == 55 then
    let t := store64 (labels+0) 7598805615236113734 t
    let t := store64 (labels+8) 8316287474039025263 t
    let t := store64 (labels+16) 7235428763975970665 t
    let t := store64 (labels+24) 7161137258222788709 t
    let t := store64 (labels+32) 2338615488569221236 t
    let t := store64 (labels+40) 435678045043 t
    text labels 45 x y color bg t
  -- 56: Appeal result: upheld by authorized moderator
  else if id == 56 then
    let t := store64 (labels+0) 8223692085148020801 t
    let t := store64 (labels+8) 8439809973402563429 t
    let t := store64 (labels+16) 8746589041994328176 t
    let t := store64 (labels+24) 7598258015748579616 t
    let t := store64 (labels+32) 7306087009987356026 t
    let t := store64 (labels+40) 491496169842 t
    text labels 45 x y color bg t
  -- 57: Appeal result: reversed by authorized moderator
  else if id == 57 then
    let t := store64 (labels+0) 8223692085148020801 t
    let t := store64 (labels+8) 8223637191288779621 t
    let t := store64 (labels+16) 2334102053399656037 t
    let t := store64 (labels+24) 8027794383277422946 t
    let t := store64 (labels+32) 8029109326242802034 t
    let t := store64 (labels+40) 32210692986791268 t
    text labels 47 x y color bg t
  -- 58: Policy version / decision generation
  else if id == 58 then
    let t := store64 (labels+0) 8511936763607674704 t
    let t := store64 (labels+8) 3395835543826952805 t
    let t := store64 (labels+16) 8028074707240969248 t
    let t := store64 (labels+24) 7021786293846089838 t
    let t := store64 (labels+32) 1852795252 t
    text labels 36 x y color bg t
  -- 59: Peer sharing: direct encrypted federation replication (mode3); client access stays mode1.
  else if id == 59 then
    let t := store64 (labels+0) 7018986602452313424 t
    let t := store64 (labels+8) 7594230306868980082 t
    let t := store64 (labels+16) 7164775247259067762 t
    let t := store64 (labels+24) 7358992178031393138 t
    let t := store64 (labels+32) 8028075772644516965 t
    let t := store64 (labels+40) 7163375912303599726 t
    let t := store64 (labels+48) 7865572407890244705 t
    let t := store64 (labels+56) 7142774057151587439 t
    let t := store64 (labels+64) 7161040566936234348 t
    let t := store64 (labels+72) 7022364302190536035 t
    let t := store64 (labels+80) 3559361510241235833 t
    let t := store64 (labels+88) 46 t
    text labels 89 x y color bg t
  -- 60: Recipients and external copies may retain this post after tombstone.
  else if id == 60 then
    let t := store64 (labels+0) 7954880248345224530 t
    let t := store64 (labels+8) 7286934622324159348 t
    let t := store64 (labels+16) 2336349433691993208 t
    let t := store64 (labels+24) 7863411828786753379 t
    let t := store64 (labels+32) 7593478425778616673 t
    let t := store64 (labels+40) 8079584628063871086 t
    let t := store64 (labels+48) 7310580662471521135 t
    let t := store64 (labels+56) 8391158752882204786 t
    let t := store64 (labels+64) 778399343 t
    text labels 68 x y color bg t
  -- 61: Author edit / exact target event
  else if id == 61 then
    let t := store64 (labels+0) 7286950019904861505 t
    let t := store64 (labels+8) 8675375643979180388 t
    let t := store64 (labels+16) 7454127484640191329 t
    let t := store64 (labels+24) 8389754715014984805 t
    text labels 32 x y color bg t
  -- 62: Author tombstone / recipients may retain copies
  else if id == 62 then
    let t := store64 (labels+0) 8367813930473780545 t
    let t := store64 (labels+8) 7308901791211613551 t
    let t := store64 (labels+16) 8100114692160106272 t
    let t := store64 (labels+24) 7020303074387191145 t
    let t := store64 (labels+32) 7955997369272770681 t
    let t := store64 (labels+40) 32481125854044960 t
    text labels 47 x y color bg t
  -- 63: Reply / signed causal parent reference
  else if id == 63 then
    let t := store64 (labels+0) 2319108039001531730 t
    let t := store64 (labels+8) 7142819395816352115 t
    let t := store64 (labels+16) 7021147468934116705 t
    let t := store64 (labels+24) 7378429048234337650 t
    let t := store64 (labels+32) 111477728309861 t
    text labels 38 x y color bg t
  -- 64: Feed retention unavailable: unlock Objects and approve this owner.
  else if id == 64 then
    let t := store64 (labels+0) 8387235364496303430 t
    let t := store64 (labels+8) 8439867126481972837 t
    let t := store64 (labels+16) 7089066488320385390 t
    let t := store64 (labels+24) 8028913685025678700 t
    let t := store64 (labels+32) 7162247752869505891 t
    let t := store64 (labels+40) 6998704246172447604 t
    let t := store64 (labels+48) 8367799667004698736 t
    let t := store64 (labels+56) 7308910564438403432 t
    let t := store64 (labels+64) 11890 t
    text labels 66 x y color bg t
  else t
def label (id x y color t : UInt64) : UInt64 :=
  if id < 16 then label0 id x y color t else
  if id < 32 then label1 id x y color t else
  if id < 48 then label2 id x y color t else label3 id x y color t
partial def wrapped (p n x y t : UInt64) : UInt64 :=
  if n == 0 || y > 306 then t else
  let c := load8 p t
  let t := if c == 10 then t else char x y c fg bg t
  let newline := c == 10 || x >= 612
  wrapped (p+1) (n-1) (if newline then 14 else x+6) (if newline then y+12 else y) t
partial def hexBytes (p n x y t : UInt64) : UInt64 :=
  if n == 0 then t else
  hexBytes (p+1) (n-1) (x+12) y (hex (load8 p t) 2 x y accent bg t)
def draw (_surface t : UInt64) : UInt64 :=
  let t := fill 0 0 640 352 bg t
  let t := fill 0 0 640 32 0x254259 t
  let t := label 0 14 12 fg t
  let t := label 1 14 42 accent t
  let t := label 2 14 58 accent t
  let t := label 3 14 74 0xa0b8c9 t
  let t := fill 12 92 616 1 0x355064 t
  let mode := load64 (st+24) t
  let t := label (load64 (st+32) t) 14 102 accent t
  let t := if mode == 1 || mode == 6 || mode == 7 || mode == 9 then
      let t := label (if mode == 9 then 8 else if mode == 6 then 19 else if mode == 7 then 20 else 7) 14 122 fg t
      let t := if mode == 9 then
          if load64 (st+144) t == 5 then label 60 14 134 accent t else
          if load64 (st+208) t == 1 then label 59 14 134 accent t else t
        else t
      let n := load64 (st+40) t
      let offset := if n > 1300 then n-1300 else 0
      let t := wrapped (compose+offset) (n-offset) 14 146 t
      hex n 4 540 316 accent bg t
    else if mode == 3 then
      let t := label 21 14 122 fg t
      let t := hexBytes identity 32 14 146 t
      let t := hexBytes (identity+32) 32 14 170 t
      let t := hexBytes (identity+64) 32 14 194 t
      label 32 14 230 fg t
    else if mode == 10 then
      let t := label 52 14 128 fg t
      let t := hex (load64 (st+240) t) 2 14 156 accent bg t
      label 53 14 180 accent t
    else if mode == 8 then
      let t := label 47 14 128 fg t
      let t := hexBytes (project+320) 32 14 152 t
      let t := label 49 14 180 accent t
      label 34 14 204 fg t
    else if mode == 5 then
      let t := label 30 14 128 fg t
      let t := label 41 14 150 accent t
      let t := label 42 14 168 accent t
      let t := label 43 14 190 fg t
      let t := hex (load64 (st+240) t) 2 14 212 accent bg t
      let t := hex (load64 (st+248) t) 1 62 212 accent bg t
      let t := hex (load64 (st+256) t) 1 82 212 accent bg t
      label 44 14 242 fg t
    else
      let kind := load64 (selected+176) t
      let action := load64 (selected+400) t
      let t := label (if kind == 8 && action > 0 && action <= 3 then 54+action else
        if kind == 4 then 61 else if kind == 5 then 62 else if kind == 2 then 63 else 25) 14 122 fg t
      let t := hexBytes (if kind == 8 || kind == 4 || kind == 5 then selected+368 else if kind == 2 then selected+192 else eventId) 32 14 138 t
      let t := hexBytes (selected+112) 32 14 154 t
      let t := label (if kind == 8 then 58 else 39) 14 172 0xa0b8c9 t
      let t := hex (if kind == 8 then load64 (selected+264) t else load64 (st+176) t) 4 280 172 accent bg t
      let t := hex (if kind == 8 then load64 (selected+184) t else load64 (st+56) t) 4 330 172 accent bg t
      let offset := load64 (st+80) t
      let n := load64 (st+72) t
      if load64 (st+200) t != 0 then t else
      let start := if load64 (selected+176) t == 3 && n >= 1546 && offset == 0 then 1546 else offset
      wrapped (content+start) (if n > start then n-start else 0) 14 192 t
  let t := fill 12 312 616 1 0x355064 t
  let t := label (if load64 (st+208) t == 0 then 22 else 23) 14 324 accent t
  let t := label 24 350 340 0xa0b8c9 t
  let t := label 29 14 340 0xa0b8c9 t
  let t := hex (load64 (st+96) t) 2 600 324 0xffbd83 bg t
  -- The surface transfer is separately pumped; a whole-frame upload must not
  -- leave ordinary keyboard input waiting through880 kernel calls.
  store64 st 0 (store64 (st+368) 1 t)
def paintPump (surface t : UInt64) : UInt64 :=
  let pending := load64 (st+368) t
  if pending == 0 then t else
  let offset := pending-1
  let bytes := if 901120-offset > 16384 then 16384 else 901120-offset
  let r := upload surface offset bytes 0 t
  if r == error then notice 12 (store64 (st+368) 0 r) else
  store64 (st+368) (if offset+bytes == 901120 then 0 else offset+bytes+1) r
 def submit (action h a b c payload bytes t : UInt64) : UInt64 :=
  -- A status read cannot consume an explicit keyboard/pointer gesture.
  let pending := load64 (st+8) t
  let t := if pending != 0 && load64 (st+16) t == 0 && action != 0 then
      let r := Guest.FeedAccountSDK.cancel pending t
      if r == error then r else store64 (st+8) 0 r
    else t
  if load64 (st+8) t != 0 then notice 6 t else
  let token := Guest.FeedAccountSDK.submit action h a b c payload bytes t
  if token == error then notice 14 token else
  let t := store64 (st+352) h (store64 (st+8) token (store64 (st+16) action token))
  if action == 0 then t else notice 6 t
 def inspect (t : UInt64) : UInt64 := submit 0 0 0 0 0 0 0 t
 def timeline (cursor t : UInt64) : UInt64 :=
  submit 5 cursor (load64 (st+160) t) 0 0 0 0 (store64 (st+24) 0 (store64 (st+72) 0 t))
 def createIdentity (t : UInt64) : UInt64 :=
  if load64 (st+168) t != 0 then notice 21 (store64 (st+24) 3 t) else
  submit 1 0 0 0 0 accountScope 64 (store64 (st+24) 3 t)
 def beginCompose (kind t : UInt64) : UInt64 :=
  if load64 (st+168) t == 0 then notice 4 t else
  if load64 (st+192) t == 8 then notice 13 t else
  let t := zero compose 2048 (zero references 12 t)
  let t := if kind == 2 || kind == 4 || kind == 5 then copy eventId references 32 t else t
  let t := if kind == 4 || kind == 5 || kind == 6 || kind == 7 then copy eventId (references+64) 32 t else t
  notice (if kind == 6 then 19 else if kind == 7 then 20 else 7)
    (store64 (st+24) (if kind == 6 then 6 else if kind == 7 then 7 else 1)
      (store64 (st+144) kind (store64 (st+360) 0 (store64 (st+40) 0 t))))
 def sendChunk (t : UInt64) : UInt64 :=
  let offset := load64 (st+48) t
  let n := if load64 (st+40) t-offset > 512 then 512 else load64 (st+40) t-offset
  submit 3 offset 0 0 0 (compose+offset) n t
partial def cardEncode (i t : UInt64) : UInt64 :=
  if i == 768 then t else
  let c := load8 (project+i) t
  let hi := c >>> 4
  let lo := c &&& 15
  cardEncode (i+1) (store8 (content+10+i*2) (if lo < 10 then lo+48 else lo+87)
    (store8 (content+9+i*2) (if hi < 10 then hi+48 else hi+87) t))
def wrapCard (t : UInt64) : UInt64 :=
  if load64 (st+144) t != 3 || load64 (st+360) t == 1 then t else
  let n := load64 (st+40) t
  if n > 14838 then error else
  let t := copy compose (content+1546) n t
  let t := store64 content 0x31445241432d544c (store8 (content+8) 32 (store8 (content+1545) 10 t))
  let t := cardEncode 0 t
  store64 (st+360) 1 (store64 (st+40) (n+1546) (copy content compose (n+1546) t))
 def publish (t : UInt64) : UInt64 :=
  if load64 (st+192) t == 8 then submit 10 0 0 0 0 0 0 t else
  if load64 (st+24) t != 9 || load64 (st+40) t == 0 then notice 8 t else
  let t := wrapCard t
  if t == error then notice 12 t else
  submit 2 (load64 (st+144) t) (load64 (st+40) t) 0 0 references 96 (store64 (st+48) 0 t)
 def preference (kind t : UInt64) : UInt64 :=
  let offset := if kind == 1 then st+224 else st+232
  let enabled := 2
  let projectFollow := kind == 1 && load64 (selected+176) t == 3
  submit 7 (if projectFollow then 4 else kind) enabled 0 0
    (if projectFollow then selected+368 else selected+112) 32 (store64 offset enabled t)
def projectPortal (action h nonce t : UInt64) : UInt64 :=
  let shell := syscall 97 4 0 0 0 t
  syscall 30 shell wire 64 1024 (header action h nonce 0 0 0 0 shell)
def projectSelect (t : UInt64) : UInt64 := submit 19 (load64 (st+288) t) 0 0 0 0 0 (store64 (st+304) 0 t)
def cardDigit (c : UInt64) : UInt64 :=
  if c >= 48 && c <= 57 then c-48 else if c >= 97 && c <= 102 then c-87 else 16
partial def cardDecode (i t : UInt64) : UInt64 :=
  if i == 768 then t else
  let hi := cardDigit (load8 (content+9+i*2) t)
  let lo := cardDigit (load8 (content+10+i*2) t)
  if hi > 15 || lo > 15 then error else cardDecode (i+1) (store8 (project+i) (hi*16+lo) t)
def projectInspect (t : UInt64) : UInt64 :=
  if load64 (selected+176) t != 3 then notice 14 t else
  if load64 (st+72) t >= 1546 && load64 content t == 0x31445241432d544c && load8 (content+8) t == 32 && load8 (content+1545) t == 10 then
    let r := cardDecode 0 t
    if r == error || !Guest.LiveMemory.equal (project+320) (selected+336) 32 r ||
        !Guest.LiveMemory.equal (project+64) (selected+368) 32 r then notice 12 r else
    let t := copy project portable 768 (copy (project+320) (portable+768) 32 r)
    submit 20 0 0 0 0 portable 800 (store64 (st+312) 0 t)
  else submit 19 0 0 0 0 0 0 (store64 (st+304) 1 t)
def projectVerify (t : UInt64) : UInt64 :=
  let t := copy project portable 768 (copy (project+320) (portable+768) 32 t)
  submit 20 0 0 0 0 portable 800 t
partial def forkAlias (serial i t : UInt64) : UInt64 :=
  if i == 8 then t else
  let n := (serial >>> ((7-i)*4)) &&& 15
  forkAlias serial (i+1) (store8 (selectedRoot+8+i) (if n < 10 then n+48 else n+87) t)
def projectFork (t : UInt64) : UInt64 :=
  notice 52 (store64 (st+24) 10 (store64 (st+240) 0 (zero credentialText 8 t)))
def projectPump (t : UInt64) : UInt64 :=
  if load64 (st+320) t == 0 || load64 (st+8) t != 0 then t else
  let r := projectPortal 4 0 (load64 (st+296) t) t
  if r != 64 || status r != 0 then notice 12 (store64 (st+320) 0 r) else
  let phase := load64 (wire+16) r
  if phase == 1 then r else
  if phase != 2 || result r == 0 then notice 5 (store64 (st+320) 0 r) else
  let h := result r
  let r := Guest.ProjectSDK.describeRoot h r
  if r != 160 || status r != 0 || !Guest.LiveMemory.equal (wire+64) (project+320) 32 r then notice 12 (store64 (st+320) 0 r) else
  let t := store64 (st+328) h (store64 (st+320) 0 (store64 (st+312) 2 r))
  projectVerify t
partial def appendPortable (object offset t : UInt64) : UInt64 :=
  if offset == 2048 then
    let r := Guest.LiveSDK.stageDigest object t
    if r != 96 || status r != 0 then error else
    let t := copy (wire+64) hashOut 32 r
    Guest.LiveSDK.commit object hashOut t
  else
    let r := Guest.LiveSDK.append object offset (portable+offset) 512 t
    if r != 64 || status r != 0 then error else appendPortable object (offset+512) r
 def publishPortable (t : UInt64) : UInt64 :=
  let old := load64 (st+280) t
  let t := if old == 0 then t else Guest.LiveSDK.releaseReference old t
  let r := Guest.LiveSDK.stage 2048 6 0 t
  if r != 64 || status r != 0 then notice 12 r else
  let object := result r
  let r := appendPortable object 0 r
  if r != 96 || status r != 0 then notice 12 r else
  notice 45 (store64 (st+280) object r)
partial def readPortable (object offset t : UInt64) : UInt64 :=
  if offset == 2048 then t else
  let r := Guest.LiveSDK.read object offset 512 t
  if r != 576 || status r != 0 then error else readPortable object (offset+512) (copy (wire+64) (portable+offset) 512 r)
 def importPortable (t : UInt64) : UInt64 :=
  let object := load64 (st+272) t
  if object == 0 then notice 14 t else
  let r := Guest.LiveSDK.metadata object t
  if r != 96 || status r != 0 || load64 (wire+16) r != 2048 || load64 (wire+32) r != 6 then notice 12 r else
  let r := readPortable object 0 r
  if r == error then notice 12 r else submit 13 0 0 0 0 portable 512 (store64 (st+264) 0 r)
 def completed (action n t : UInt64) : UInt64 :=
  let code := status t
  let t := store64 (st+8) 0 t
  let t := if action == 0 then t else store64 (st+96) code t
  if code == 15 && action == 16 then
    let t := store64 (st+200) 0 t
    if load64 (wire+24) t == 1 && load64 (wire+16) t != 0 then timeline (load64 (wire+16) t) t else notice 16 t
  else if code != 0 && code != 6 then
    let t := if action == 16 then
        zero content 2048 (zero selected 60 (zero eventId 4 (store64 (st+176) 0 (store64 (st+72) 0 (store64 (st+200) 0 t)))))
      else t
    if action == 14 then notice 64 (store64 (st+344) 0 t) else
    notice (if code == 12 then 13 else if code == 15 then 16 else if code == 7 then 14 else 12) t else
  if action == 0 then
    let phase := load64 (wire+32) t
    let changed := phase != load64 (st+192) t || load64 (wire+40) t != load64 (st+336) t ||
      (if result t == 0 then 0 else 1) != load64 (st+168) t
    let t := store64 (st+336) (load64 (wire+40) t) t
    let t := store64 (st+192) phase (store64 (st+88) phase t)
    let t := if changed then store64 (st+96) (load64 (wire+40) t) t else t
    let t := if n == 160 then copy (wire+64) identity 96 t else t
    let t := store64 (st+168) (if result t == 0 then 0 else 1) t
    if !changed then
      if load64 (st+24) t == 5 && load64 (st+344) t == 1 && load64 (st+32) t == 6 then notice 54 t else t
    else notice (if phase == 7 then 11 else if phase == 6 then 10 else if phase == 8 then 12 else if phase >= 1 && phase <= 5 then 9 else if result t == 0 then 4 else 5) t
  else if action == 1 then inspect t
  else if action == 2 then sendChunk t
  else if action == 3 then
    let offset := result t
    let t := store64 (st+48) offset t
    if offset == load64 (st+40) t then submit 4 0 0 0 0 0 0 t else sendChunk t
  else if action == 4 || action == 10 then notice 9 (store64 (st+24) 0 t)
  else if action == 5 || action == 6 then store64 (st+200) action t
  else if action == 7 then notice (if load64 (wire+8) t == 1 then 17 else if load64 (wire+16) t == 0 then 51 else 18) t
  else if action == 9 then notice 36 (store64 (st+344) 0 (store64 (st+168) 0 t))
  else if action == 14 then
    let t := store64 (st+344) (if load64 (st+352) t == 2 then 0 else 1) t
    inspect (notice 46 (zero credentialText 8 (zero credential 4 (store64 (st+240) 0 t))))
  else if action == 12 then
    let offset := load64 (wire+16) t
    if n != 576 || offset > 1536 then notice 12 t else
    let t := copy (wire+64) (portable+offset) 512 t
    if offset == 1536 then publishPortable t else submit 12 (load64 (st+256) t) (offset+512) 512 0 0 0 t
  else if action == 13 then
    let offset := result t
    if offset == 2048 then notice 50 t else submit 13 offset 0 0 0 (portable+offset) 512 t
  else if action == 19 then
    if n != 832 then notice 12 t else
    let cursor := load64 (wire+24) t
    if load64 (st+304) t == 1 && !Guest.LiveMemory.equal (wire+384) (selected+336) 32 t then
      if cursor == 0 then notice 14 t else submit 19 cursor 0 0 0 0 0 t
    else
      let t := copy (wire+64) project 768 (store64 (st+288) cursor t)
      if load64 (st+304) t == 1 then projectVerify (store64 (st+312) 0 t) else
      let t := beginCompose 3 t
      notice 33 (copy (project+64) (references+64) 32 (copy (project+320) (references+32) 32 t))
  else if action == 20 then
    if n != 832 then notice 12 t else
    let t := copy (wire+64) project 768 t
    if load64 (st+312) t == 0 then notice 47 (store64 (st+24) 8 t) else
    if load64 (st+312) t == 1 then
      let nonce := load64 (st+296) t+1
      let r := projectPortal 14 1 nonce t
      if r != 64 || status r != 0 then notice 12 r else
      notice 49 (store64 (st+320) 1 (store64 (st+296) nonce r))
    else
      let t := zero selectedRoot 8 t
      let t := store64 selectedRoot 0x6b726f6664656566 t
      let t := forkAlias (load64 (st+296) t) 0 t
      let r := Guest.ProjectSDK.forkProject (load64 (st+328) t) (project+320) (selectedRoot+64) selectedRoot 16 t
      notice (if r == 256 && status r == 0 then 5 else 12) (store64 (st+312) 0 r)
  else if action == 16 then
    if code == 6 then t else
    let requested := load64 (st+200) t
    if requested == 5 && n == 576 then
      let t := copy (wire+64) eventId 32 (copy (wire+96) selected 480 t)
      let t := store64 (st+56) (result t) (store64 (st+64) (load64 (wire+16) t) t)
      let t := store64 (st+176) (load64 (wire+32) t) (store64 (st+72) 0 (store64 (st+80) 0 t))
      if load64 (wire+40) t == 0 then notice 40 (store64 (st+200) 0 t) else
      submit 6 0 (if load64 (st+176) t > 512 then 512 else load64 (st+176) t) 0 0 eventId 32 (store64 (st+200) 6 t)
    else if requested == 6 && n > 64 && n <= 576 then
      let off := load64 (st+72) t
      let count := n-64
      if off+count > 16384 then notice 12 t else
      let t := copy (wire+64) (content+off) count t
      let t := store64 (st+72) (off+count) t
      if off+count < load64 (st+176) t then
        let remaining := load64 (st+176) t-off-count
        submit 6 (off+count) (if remaining > 512 then 512 else remaining) 0 0 eventId 32 t else
      notice 15 (store64 (st+200) 0 t)
    else notice 26 (store64 (st+200) 0 t)
  else notice 5 t
 def collect (t : UInt64) : UInt64 :=
  let token := load64 (st+8) t
  if token == 0 then t else
  let r := Guest.FeedAccountSDK.collect token t
  if r == 0 then r else
  if r == error || r < 64 || r > 1024 then notice 12 (store64 (st+8) 0 r) else
  completed (load64 (st+16) r) r r
def digit (c : UInt64) : UInt64 :=
  if c >= 48 && c <= 57 then c-48 else if c >= 97 && c <= 102 then c-87 else
  if c >= 65 && c <= 70 then c-55 else 16
partial def decodeCredential (i t : UInt64) : UInt64 :=
  if i == 32 then t else decodeCredential (i+1)
    (store8 (credential+i) (load8 (credentialText+i*2) t*16+load8 (credentialText+i*2+1) t) t)
def retentionKey (code t : UInt64) : UInt64 :=
  if code == 1 then notice 5 (store64 (st+24) 0 (zero credentialText 8 (zero credential 4 (store64 (st+240) 0 t)))) else
  if code == 60 then dirty (store64 (st+248) 0 t) else
  if code == 61 then dirty (store64 (st+248) 1 t) else
  if code == 62 then dirty (store64 (st+256) (1-load64 (st+256) t) t) else
  if code == 63 then
    if load64 (st+240) t != 64 then notice 43 t else
    let t := decodeCredential 0 t
    submit 14 (load64 (st+248) t) (load64 (st+256) t) 0 0 credential 32 t
  else if code == 64 then submit 9 0 0 0 0 0 0 t
  else if code == 65 then submit 14 2 0 0 0 0 0 t
  else if code == 66 then submit 12 (load64 (st+256) t) 0 512 0 0 0 t
  else if code == 67 then importPortable t
  else if code == 14 then
    let n := load64 (st+240) t
    if n == 0 then t else dirty (store64 (st+240) (n-1) t)
  else
    let c := digit (Guest.Keyboard.scanCode code (load64 (st+104) t))
    let n := load64 (st+240) t
    if c == 16 || n >= 64 then t else dirty (store64 (st+240) (n+1) (store8 (credentialText+n) c t))
def projectKey (code t : UInt64) : UInt64 :=
  if code == 1 then notice 47 (store64 (st+24) 8 (zero credentialText 8 t)) else
  if code == 28 then
    if load64 (st+240) t != 64 then notice 52 t else
    let t := decodeCredential 0 t
    let t := copy credential (selectedRoot+64) 32 (zero credentialText 8 (store64 (st+240) 0 t))
    let t := zero credential 4 t
    projectVerify (store64 (st+312) 1 (store64 (st+24) 8 t))
  else if code == 14 then
    let n := load64 (st+240) t
    if n == 0 then t else dirty (store64 (st+240) (n-1) t)
  else
    let c := digit (Guest.Keyboard.scanCode code (load64 (st+104) t))
    let n := load64 (st+240) t
    if c == 16 || n >= 64 then t else dirty (store64 (st+240) (n+1) (store8 (credentialText+n) c t))
 def key (code t : UInt64) : UInt64 :=
  let mode := load64 (st+24) t
  if mode == 5 then retentionKey code t else
  if mode == 10 then projectKey code t else
  if code == 1 then
    let token := load64 (st+8) t
    let t := if token == 0 then t else Guest.FeedAccountSDK.cancel token t
    let active := load64 (st+200) t != 0 ||
      (load64 (st+192) t >= 1 && load64 (st+192) t <= 5)
    let t := store64 (st+8) 0 (store64 (st+72) 0 (store64 (st+200) 0 (store64 (st+24) 0 t)))
    if active then submit 17 0 0 0 0 0 0 t else notice 5 t
  else if code == 60 then createIdentity t
  else if code == 61 then beginCompose 1 t
  else if code == 62 then notice 8 (store64 (st+24) 9 t)
  else if code == 63 then publish t
  else if code == 64 then beginCompose 2 t
  else if code == 65 then preference 1 t
  else if code == 66 then preference 2 t
  else if code == 67 then beginCompose 6 t
  else if code == 68 then beginCompose 7 t
  else if code == 87 then projectSelect t
  else if code == 59 then notice 30 (store64 (st+24) 5 t)
  else if mode == 1 || mode == 6 || mode == 7 then
    if code == 14 then
      let n := load64 (st+40) t
      if n == 0 then t else dirty (store64 (st+40) (n-1) t)
    else
      let c := Guest.Keyboard.scanCode code (load64 (st+104) t)
      let n := load64 (st+40) t
      if c == 0 || n >= 16384 then t else dirty (store64 (st+40) (n+1) (store8 (compose+n) c t))
  else if code == 30 then
    let selectedAudience := 1-load64 (st+208) t
    let t := store64 (st+208) selectedAudience t
    submit 18 selectedAudience 0 0 0 0 0 (notice (if selectedAudience == 0 then 22 else 23) t)
  else if code == 19 && mode == 0 then submit 11 0 0 0 0 0 0 t
  else if code == 46 then projectInspect t
  else if code == 33 && mode == 8 then projectFork t
  else if code == 18 then beginCompose 4 t
  else if code == 20 then beginCompose 5 t
  else if code == 15 then notice (if load64 (st+160) t == 0 then 28 else 27) (store64 (st+160) (1-load64 (st+160) t) t)
  else if code == 109 then
    if load64 (st+80) t+900 < load64 (st+72) t then dirty (store64 (st+80) (load64 (st+80) t+900) t) else timeline (load64 (st+64) t) t
  else if code == 104 then
    if load64 (st+80) t >= 900 then dirty (store64 (st+80) (load64 (st+80) t-900) t) else timeline 0 t
  else if code == 28 then timeline (load64 (st+56) t) t
  else t
 def motion (old value bound : UInt64) : UInt64 :=
  if value < 0x80000000 then if old+value > bound then bound else old+value else
  let n := 0x100000000-value
  if n > old then 0 else old-n
 def input (event t : UInt64) : UInt64 :=
  let kind := event >>> 48
  let code := (event >>> 32) &&& 65535
  let value := event &&& 0xffffffff
  if kind == 65535 then store64 (st+104) 0 t else
  if kind == 2 && code == 0 then store64 (st+112) (motion (load64 (st+112) t) value 639) t else
  if kind == 2 && code == 1 then store64 (st+120) (motion (load64 (st+120) t) value 399) t else
  if kind != 1 then t else
  if code == 42 || code == 54 then store64 (st+104) value t else
  if value != 1 then t else if code != 272 then key code t else
  let x := load64 (st+112) t
  let y := load64 (st+120) t
  if y >= 38 && y < 56 then key (if x < 110 then 60 else if x < 230 then 61 else if x < 350 then 62 else 63) t else
  if y >= 56 && y < 74 then key (if x < 115 then 64 else if x < 250 then 65 else if x < 370 then 66 else if x < 500 then 67 else 68) t else
  if y >= 334 then key 59 t else
  if y >= 312 && y < 334 then key 30 t else t
partial def inputPump (fuel t : UInt64) : UInt64 :=
  if fuel == 0 then t else
  let event := syscall 90 (self t) 0 0 0 t
  if event == 0 || event == error then event else inputPump (fuel-1) (input event event)
def request (n t : UInt64) : UInt64 :=
  let token := load64 (incoming+8) t
  let admin := (load64 (incoming+16) t &&& 0x100000000) != 0
  let op := load64 command t
  if !admin || load64 (command+56) t != 1 then reply token 64 (header 1 0 0 0 0 0 0 t) else
  if op == 790 && n == 160 then
    reply token 64 (header 0 0 0 0 0 0 0 (notice 4 (copy (command+64) accountScope 64 t)))
  else if op == 792 && n == 96 then
    reply token 64 (header 0 0 0 0 0 0 0 (notice 45 (store64 (st+272) (load64 (command+8) t) t)))
  else if op == 795 && n == 96 then
    let t := copy eventId (wire+64) 32 (header 0 0 0 0 0 0 0 t)
    reply token 576 (copy selected (wire+96) 480 t)
  else if op == 794 && n == 96 && load64 (st+280) t != 0 then
    let r := Guest.LiveSDK.share (load64 (st+280) t) (load64 incoming t) 1 t
    reply token (if r >= 64 && r <= 1024 then r else 64) (if r >= 64 && r <= 1024 then r else header 1 0 0 0 0 0 0 r)
  else if op == 793 && n == 96 then
    reply token 64 (header 0 (load64 (st+280) t) (load64 (st+272) t) (load64 (st+240) t) (load64 (st+248) t) (load64 (st+256) t) (load64 (st+344) t) t)
  else if op == 791 && n == 96 then
    let t := header 0 (load64 (st+168) t) (load64 (st+24) t) (load64 (st+40) t)
      (load64 (st+32) t) (load64 (st+88) t) (load64 (st+96) t) t
    let t := copy identity (wire+64) 96 t
    let t := store64 (wire+160) (load64 (st+16) t) (store64 (wire+168) (if load64 (st+8) t == 0 then 0 else 1) t)
    let t := store64 (wire+176) (load64 (st+48) t) (store64 (wire+184) (load64 (st+144) t) t)
    let t := store64 (wire+192) (load64 (st+200) t) (store64 (wire+200) (load64 (st+360) t) t)
    let t := store64 (wire+208) (load64 (st+344) t) (store64 (wire+216) (load64 (st+336) t) t)
    reply token 224 t
  else reply token 64 (header 7 0 0 0 0 0 0 t)
partial def loop (surface t : UInt64) : UInt64 :=
  let n := syscall 36 (self t) incoming 1024 0 t
  let t := if n >= 96 && n <= 1024 then request n n else n
  let t := projectPump (collect (inputPump 64 t))
  let now := Guest.WaitSDK.now t
  let t := if load64 (st+8) now != 0 || now < load64 (st+128) now then now else
      let t := store64 (st+128) (now+100) now
      if load64 (st+200) t != 0 then submit 16 0 0 0 0 0 0 t else inspect t
  let t := if load64 st t == 1 && load64 (st+368) t == 0 then draw surface t else t
  let t := paintPump surface t
  loop surface (Guest.WaitSDK.deadline (Guest.WaitSDK.now t+1) t)
def main (t : UInt64) : UInt64 :=
  let t := notice 4 (zero st 48 (zero accountScope 8 (zero identity 12 (zero eventId 4 t))))
  let surface := syscall 80 0 0 0 0 t
  if surface == error then error else loop surface (draw surface surface)
end Guest.Feed
