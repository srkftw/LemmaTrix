import Guest.LiveSDK
namespace Guest.WaitSDK
def now (t : UInt64) : UInt64 := Guest.syscall 116 0 0 0 0 t
-- Absolute monotonic timer-tick deadline, bounded to100 ticks per wait.
-- Input and IPC can wake sooner. Callers recheck readiness after waking.
def deadline (deadline t : UInt64) : UInt64 := Guest.syscall 117 deadline 0 0 0 t
end Guest.WaitSDK
