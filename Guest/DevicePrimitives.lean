namespace Guest
@[never_extract, extern "lt_load32"] opaque load32 : UInt64 → UInt64 → UInt64
@[never_extract, extern "lt_store32"] opaque store32 : UInt64 → UInt64 → UInt64 → UInt64
@[never_extract, extern "lt_device_fence"] opaque deviceFence : UInt64 → UInt64
end Guest
