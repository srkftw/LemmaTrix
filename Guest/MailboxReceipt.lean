import Guest.ReceiptSDK
import Guest.IdentitySDK
namespace Guest.MailboxReceipt
open Guest.LiveSDK
-- Public profile and one admitted signature job. Only Identity holds seeds.
-- Mailbox must durably commit the returned signature with its original body
-- before reporting durable acceptance. This helper owns no backing itself.
def st : UInt64 := 0x740000
def body : UInt64 := st+256
def signature : UInt64 := st+512
def profile : UInt64 := st+1024
def pending (t : UInt64) : Bool := load64 (st+8) t == 1
def completed (t : UInt64) : Bool := load64 (st+8) t == 2
def failed (t : UInt64) : Bool := load64 (st+8) t == 3
def reason (t : UInt64) : UInt64 := load64 (st+24) t
def generation (t : UInt64) : UInt64 := load64 (st+32) t
def configured (t : UInt64) : Bool := load64 st t != 0
def clear (t : UInt64) : UInt64 :=
  let token := load64 (st+16) t
  let t := if token == 0 then t else syscall 135 token 0 0 0 t
  zero st 512 t
def configure (grant certificate terms nodeHash t : UInt64) : UInt64 :=
  if pending t || grant == 0 || !Guest.ReceiptSDK.declarationBody (certificate+160) t ||
    !Guest.ReceiptSDK.eq (certificate+208) nodeHash 32 t ||
    !Guest.ReceiptSDK.nonzero terms 32 t then error else
  let t := clear t
  let t := store64 st grant t
  let t := copy certificate profile 352 t
  let t := copy terms (profile+352) 32 t
  copy nodeHash (profile+384) 32 t
def begin (source t : UInt64) : UInt64 :=
  if !configured t || load64 (st+8) t != 0 || !Guest.ReceiptSDK.bodyValid source (self t) t ||
    !Guest.ReceiptSDK.eq (source+96) (profile+352) 64 t then error else
  let target := Guest.IdentitySDK.endpoint 409 t
  if target == error then error else
  let t := copy source body 192 target
  let t := header 409 (load64 st t) 0 0 0 0 0 t
  let t := copy body (wire+64) 192 t
  let token := syscall 133 target wire 256 1024 t
  if token == error then error else
  store64 (st+8) 1 (store64 (st+16) token token)
def pump (t : UInt64) : UInt64 :=
  if !pending t then t else
  let n := syscall 134 (load64 (st+16) t) wire 1024 0 t
  if n == 0 then n else
  let t := store64 (st+16) 0 n
  if n != 128 || status t != 0 then
    store64 (st+8) 3 (store64 (st+24) (if n == error then 3 else status t) t)
  else
    let t := copy (wire+64) signature 64 t
    store64 (st+8) 2 (store64 (st+32) (load64 (wire+24) t) t)
def take (out t : UInt64) : UInt64 :=
  if !completed t then error else
  let t := copy signature out 64 t
  store64 (st+8) 0 (zero body 24 (zero signature 8 t))
end Guest.MailboxReceipt
