import Guest.LiveSDK
namespace Guest.LibraryFetchSDK
open Guest.LiveSDK
-- This separate package is explicitly selected by the native Library. It owns
-- its network stream and private Objects import; no host payload path exists.
def callFetch (service length t : UInt64) : UInt64 := syscall 30 service wire length 1024 t
def begin (service slot operation bytes admission t : UInt64) : UInt64 :=
  let t := header 710 slot operation bytes 0 0 0 t
  callFetch service 832 (copy admission (wire+64) 768 t)
def inspect (service operation t : UInt64) : UInt64 :=
  callFetch service 64 (header 711 operation 0 0 0 0 0 t)
def cancel (service operation t : UInt64) : UInt64 :=
  callFetch service 64 (header 712 operation 0 0 0 0 0 t)
end Guest.LibraryFetchSDK
