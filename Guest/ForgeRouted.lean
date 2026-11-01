import Guest.ForgeFederation
namespace Guest.ForgeRouted
open Guest.LiveSDK
-- One explicit mode1 metadata request. Existing Forge federation verification
-- owns signature, chosen federation/policy and current admission judgments.
def st : UInt64 := 0x7e0000
def root : UInt64 := st+128
def descriptor : UInt64 := st+256
def init (t : UInt64) : UInt64 := zero st 512 t
def phase (t : UInt64) : UInt64 := load64 st t
def failure (reason t : UInt64) : UInt64 :=
  let token := load64 (st+8) t
  let t := if token == 0 then t else syscall 135 token 0 0 0 t
  store64 (st+24) reason (store64 st 4 (store64 (st+8) 0 t))
def begin (selected cursor mode t : UInt64) : UInt64 :=
  if mode != 1 || cursor >= 16 || !Guest.ForgeFederation.enabled t ||
    Guest.ProjectGraph.allZero selected 32 t || phase t == 1 || phase t == 2 || phase t == 5 then error else
  let serial := load64 (st+16) t+1
  if serial == 0 then error else
  let t := copy selected root 32 t
  let t := zero descriptor 96 t
  let t := store64 (st+16) serial t
  let t := store64 (st+32) 0 t
  let network := syscall 97 6 0 0 0 t
  if network == error then error else
  let t := store64 (wire+56) 2 (header 39 serial 0 0 0 0 0 network)
  let t := store64 (wire+64) 6 t
  let t := store64 (wire+72) cursor t
  let t := zero (wire+80) 5 t
  let t := store64 (wire+120) 1 t
  let t := copy (Guest.ForgeFederation.st+160) (wire+128) 32 t
  let token := syscall 133 network wire 160 1024 t
  if token == error then failure 1 token else
  store64 st 1 (store64 (st+8) token token)
def collect (t : UInt64) : UInt64 :=
  let network := syscall 97 6 0 0 0 t
  if network == error then failure 2 network else
  let t := store64 (wire+56) 2 (header 40 (load64 (st+16) t) 0 0 0 0 0 network)
  let token := syscall 133 network wire 64 1024 t
  if token == error then failure 3 token else store64 st 5 (store64 (st+8) token token)
def accept (n t : UInt64) : UInt64 :=
  -- Outer broker response64, original Registry reply64, signed descriptor768.
  if n != 896 || status t != 0 || load64 (wire+16) t != 832 ||
    load64 (wire+64) t != 0 || !Guest.ForgeFederation.expected (wire+128) root t then failure 4 t else
  let t := copy (wire+128) descriptor 768 t
  let t := copy descriptor Guest.ForgeFederation.remote 768 t
  let t := Guest.ForgeFederation.verifyRemote root (load64 (descriptor+48) t) t
  if Guest.ForgeFederation.remotePhase t != 2 then failure 5 t else
  store64 st 3 (store64 (st+8) 0 t)
def pump (t : UInt64) : UInt64 :=
  if (phase t == 1 || phase t == 2 || phase t == 5) && load64 (st+32) t >= 8192 then failure 8 t else
  let t := store64 (st+32) (load64 (st+32) t+1) t
  if phase t == 2 then collect t else
  if phase t != 1 && phase t != 5 then t else
  let old := phase t
  let r := syscall 134 (load64 (st+8) t) wire 1024 0 t
  if r == 0 then r else
  if r == error then failure 6 r else
  let t := store64 (st+8) 0 r
  if old == 1 then
    if r != 64 || status t != 0 then failure 7 t else store64 st 2 t
  else if status t == 6 then store64 st 2 t else accept r t
def inspect (t : UInt64) : UInt64 :=
  let t := header 0 (phase t) (load64 (st+24) t) 1 (load64 (st+16) t) 0 0 t
  let t := copy root (wire+64) 32 t
  864+copy descriptor (wire+96) 768 t
end Guest.ForgeRouted
