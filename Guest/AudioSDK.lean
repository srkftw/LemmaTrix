import Guest.LiveSDK
namespace Guest.AudioSDK
open Guest.LiveSDK
def right : UInt64 := 4096
def acquire (t : UInt64) : UInt64 := syscall 120 0 0 0 0 t
def write (epoch samples bytes t : UInt64) : UInt64 := syscall 121 epoch samples bytes 0 t
def stop (epoch t : UInt64) : UInt64 := syscall 122 epoch 0 0 0 t
def inspect (epoch t : UInt64) : UInt64 := syscall 123 epoch 0 0 0 t
end Guest.AudioSDK
