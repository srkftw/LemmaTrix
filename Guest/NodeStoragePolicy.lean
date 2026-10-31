namespace Guest.NodeStoragePolicy
-- Purpose2 operator credentials occupy six reserved sectors1..6 after the
-- format header0. Registry roots start8; ServiceJobs keys remain56..63.
def firstSector : UInt64 := 1
def ownerAllowed (pid service caller authorized purpose : UInt64) : Bool :=
  pid == 6 && service == 6 && caller != 0 && caller == authorized && purpose == 2
def extentAllowed (sector bytes : UInt64) : Bool :=
  sector < 6 && bytes > 0 && bytes <= 1536 && bytes % 512 == 0 && bytes/512 <= 6-sector
theorem ordinary_denied (service caller authorized purpose : UInt64) :
    ownerAllowed 7 service caller authorized purpose = false := by simp [ownerAllowed]
theorem personal_backing_denied (pid service caller authorized : UInt64) :
    ownerAllowed pid service caller authorized 1 = false := by simp [ownerAllowed]
theorem ninth_sector_denied : extentAllowed 8 512 = false := by decide
theorem seventh_sector_denied : extentAllowed 6 512 = false := by decide
theorem bank_bounds : firstSector+6 < (8 : UInt64) := by decide
end Guest.NodeStoragePolicy
