namespace Guest.MessengerStoragePolicy
-- This region follows every existing personal indexed-content bank. Objects
-- authorization remains unchanged. Explicit management authorizes one current
-- registered rights-zero owner; domain2 is never inferred from attached media.
def firstSector : UInt64 := 5394976
def sectorCount : UInt64 := 1024
def ownerAllowed (role rights caller registered authorized domain : UInt64) : Bool :=
  role == 2 && rights == 0 && caller != 0 && caller == registered &&
  caller == authorized && domain == 2
def extentAllowed (relative bytes capacity : UInt64) : Bool :=
  capacity >= firstSector+sectorCount && relative < sectorCount &&
  bytes > 0 && bytes <= 4096 && bytes % 512 == 0 && bytes/512 <= sectorCount-relative
theorem objects_domain_denied (r w c registered authorized : UInt64) :
    ownerAllowed r w c registered authorized 3 = false := by simp [ownerAllowed]
theorem wallet_domain_denied (r w c registered authorized : UInt64) :
    ownerAllowed r w c registered authorized 1 = false := by simp [ownerAllowed]
theorem non_owner_denied (w c registered authorized d : UInt64) :
    ownerAllowed 3 w c registered authorized d = false := by simp [ownerAllowed]
theorem network_rights_denied (c registered authorized : UInt64) :
    ownerAllowed 2 1024 c registered authorized 2 = false := by
  have zero : ((1024 : UInt64) == 0) = false := by decide
  simp only [ownerAllowed,zero,Bool.and_false,Bool.false_and]
theorem wrong_owner_denied (r w c registered authorized d : UInt64) (h : c ≠ authorized) :
    ownerAllowed r w c registered authorized d = false := by simp [ownerAllowed,h]
theorem indexed_region_is_separate : firstSector = (151000 : UInt64)+72+32*163872 := by decide
theorem small_backing_denied : extentAllowed 0 512 512 = false := by decide
end Guest.MessengerStoragePolicy
