namespace Guest.VaultPolicy
-- Kernel-issued caller rights and explicit domain, never caller-supplied identity.
def authorized (callerRights domain : UInt64) : Bool :=
  (callerRights &&& 0x100000000) != 0 && domain == 3

theorem wallet_denied (rights : UInt64) : authorized rights 1 = false := by
  unfold authorized
  have h : ((1 : UInt64) == 3) = false := by decide
  rw [h]
  exact Bool.and_false _
theorem messenger_denied (rights : UInt64) : authorized rights 2 = false := by
  unfold authorized
  have h : ((2 : UInt64) == 3) = false := by decide
  rw [h]
  exact Bool.and_false _
theorem unprivileged_denied (domain : UInt64) : authorized 0 domain = false := by
  unfold authorized
  have h : (((0 : UInt64) &&& 0x100000000) != 0) = false := by decide
  rw [h]
  rfl
def committedGeneration (callerRights domain : UInt64) (unlocked : Bool)
    (old candidate : UInt64) : UInt64 :=
  if authorized callerRights domain && unlocked then candidate else old

theorem denied_preserves_generation (rights domain old candidate : UInt64) (unlocked : Bool)
    (denied : authorized rights domain = false) :
    committedGeneration rights domain unlocked old candidate = old := by
  unfold committedGeneration
  rw [denied]
  rfl
end Guest.VaultPolicy
