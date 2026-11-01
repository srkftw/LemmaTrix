import Guest.LiveSDK
namespace Guest.FeedSDK
open Guest.LiveSDK
-- Builders own no transport. Consumers submit these typed requests only through
-- their explicitly selected mode1 terminal; there is no direct fallback.
def request (p action handle offset count t : UInt64) : UInt64 :=
  let t := zero p 8 t
  let t := store64 p 491 t
  let t := store64 (p+8) action t
  let t := store64 (p+16) handle t
  let t := store64 (p+24) offset t
  let t := store64 (p+32) count t
  store64 (p+56) 1 t
def begin (p envelope t : UInt64) : UInt64 := copy envelope (p+64) 480 (request p 1 0 0 0 t)
def append (p handle eventID offset source count t : UInt64) : UInt64 :=
  if count == 0 || count > 512 then error else
  let t := request p 2 handle offset count t
  copy source (p+96) count (copy eventID (p+64) 32 t)
def commit (p handle eventID t : UInt64) : UInt64 := copy eventID (p+64) 32 (request p 3 handle 0 0 t)
def poll (p eventID t : UInt64) : UInt64 := copy eventID (p+64) 32 (request p 4 0 0 0 t)
def timeline (p cursor t : UInt64) : UInt64 := request p 5 cursor 0 0 t
def read (p eventID offset count t : UInt64) : UInt64 := copy eventID (p+64) 32 (request p 6 0 offset count t)
def cancel (p handle eventID t : UInt64) : UInt64 := copy eventID (p+64) 32 (request p 7 handle 0 0 t)
def status (p t : UInt64) : UInt64 := request p 8 0 0 0 t
end Guest.FeedSDK
