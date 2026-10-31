namespace Guest.IdentityPolicy
-- Pure checks used by the live Identity broker. Kernel-authenticated caller
-- incarnations, never claimed roles in an application payload, supply identity.
def administrative (rights : UInt64) : Bool := (rights &&& 0x100000000) != 0
def purposeAllowed (role purpose : UInt64) : Bool :=
  (role == 2 && purpose == 1) || (role == 3 && purpose == 2)
def bindingCurrent (stored current : UInt64) : Bool := current != 0 && stored == current
def permits (active owner caller storedGeneration currentGeneration remaining : UInt64)
    (bodyMatches : Bool) : Bool :=
  active == 1 && owner == caller && storedGeneration == currentGeneration &&
    remaining == 1 && bodyMatches

theorem revoked_denies (owner caller generation current remaining : UInt64) (exactBody : Bool) :
    permits 0 owner caller generation current remaining exactBody = false := by
  simp [permits]
theorem wrong_caller_denies (active owner caller generation current remaining : UInt64)
    (exactBody : Bool) (wrong : (owner == caller) = false) :
    permits active owner caller generation current remaining exactBody = false := by
  simp [permits, wrong]
theorem stale_generation_denies (active owner caller generation current remaining : UInt64)
    (exactBody : Bool) (stale : (generation == current) = false) :
    permits active owner caller generation current remaining exactBody = false := by
  simp [permits, stale]
theorem changed_body_denies (active owner caller generation current remaining : UInt64) :
    permits active owner caller generation current remaining false = false := by
  simp [permits]
theorem exhausted_denies (active owner caller generation current : UInt64) (exactBody : Bool) :
    permits active owner caller generation current 0 exactBody = false := by
  simp [permits]
theorem project_key_cannot_certify_contact : purposeAllowed 1 1 = false := by decide
theorem receipt_key_cannot_certify_contact : purposeAllowed 4 1 = false := by decide
theorem messenger_key_cannot_declare_node : purposeAllowed 2 2 = false := by decide
theorem missing_binding_denies (stored : UInt64) : bindingCurrent stored 0 = false := by
  simp [bindingCurrent]
theorem replaced_binding_denies (stored current : UInt64) (different : (stored == current) = false) :
    bindingCurrent stored current = false := by
  simp [bindingCurrent, different]
end Guest.IdentityPolicy
