import Guest.NetworkSDK
namespace Guest.ForgeTransport
open Guest.LiveSDK
-- Private per-Forge transport choice. Selection is administrative and immutable
-- while a configured relationship/outbox exists; it never changes a mode1
-- terminal request into a mode3 record. Four explicit bulk peer contexts are
-- already enforced by the native broker and its exact caller-owned grants.
def st : UInt64 := 0x6e3400
def policy : UInt64 := st+64
def enabled (t : UInt64) : Bool := load64 st t == 1
def slot (t : UInt64) : UInt64 := load64 (st+8) t
def init (t : UInt64) : UInt64 := zero st 16 t
def configure (selected peer stream t : UInt64) : UInt64 :=
  if selected > 1 || peer >= 4 || (selected == 1 && stream == 0) then error else
  let t := store64 st selected t
  store64 (st+16) stream (store64 (st+8) peer t)
-- Both profiles share the same bounded record fields. Only v2 adds exact
-- peer context, nonzero request identity and the pinned stream word.
def call (length t : UInt64) : UInt64 :=
  if enabled t then Guest.NetworkSDK.callPeer (slot t) length t else Guest.NetworkSDK.callNetwork length t
def grant (pins direction mode budget rate lifetime operation t : UInt64) : UInt64 :=
  let t := header 2 0 direction mode budget rate lifetime t
  let t := copy pins (wire+64) 96 t
  let t := store64 (wire+160) operation t
  if enabled t then call 176 (store64 (wire+168) (load64 (st+16) t) t) else call 168 t
def send (handle operation source length t : UInt64) : UInt64 :=
  let selected := enabled t
  if length > (if selected then 704 else 720) then error else
  let serial := if selected then load64 (st+24) t+1 else 0
  if selected && serial == 0 then error else
  let t := store64 (st+24) serial t
  let t := header 3 handle operation serial 0 0 0 t
  call (64+length) (copy source (wire+64) length t)
def poll (handle t : UInt64) : UInt64 := call 64 (header 4 handle 0 0 0 0 0 t)
def receive (handle t : UInt64) : UInt64 := call 64 (header 6 handle 0 0 0 0 0 t)
def revoke (handle t : UInt64) : UInt64 := call 64 (header 8 handle 0 0 0 0 0 t)
def nonce (t : UInt64) : UInt64 := call 64 (header 10 0 0 0 0 0 0 t)
def inspect (t : UInt64) : UInt64 :=
  let t := header 0 (load64 st t) (slot t) (load64 (st+16) t) (load64 (st+24) t) 0 0 t
  64+t
end Guest.ForgeTransport
