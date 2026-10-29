namespace Guest
@[never_extract, extern "lt_load8"] opaque load8 : UInt64 → UInt64 → UInt64
@[never_extract, extern "lt_load64"] opaque load64 : UInt64 → UInt64 → UInt64
@[never_extract, extern "lt_store8"] opaque store8 : UInt64 → UInt64 → UInt64 → UInt64
@[never_extract, extern "lt_store64"] opaque store64 : UInt64 → UInt64 → UInt64 → UInt64
@[never_extract, extern "lt_syscall"] opaque syscall : UInt64 → UInt64 → UInt64 → UInt64 → UInt64 → UInt64 → UInt64
@[never_extract, extern "lt_finish"] opaque finish : UInt64 → UInt64
@[never_extract, extern "lt_enter_user"] opaque enterUser : UInt64 → UInt64
end Guest
