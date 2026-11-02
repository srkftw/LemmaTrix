namespace Guest.IdentityPolicy
-- Pure checks used by the live Identity broker. Kernel-authenticated caller
-- incarnations, never claimed roles in an application payload, supply identity.
def administrative (rights : UInt64) : Bool := (rights &&& 0x100000000) != 0
def purposeAllowed (role purpose : UInt64) : Bool :=
  (role == 1 && purpose == 6) || (role == 2 && purpose == 1) || (role == 3 && (purpose == 2 || purpose == 3)) ||
  (role == 5 && purpose == 4) || (role == 6 && purpose == 5) || (role == 7 && purpose == 7)
def bindingCurrent (stored current : UInt64) : Bool := current != 0 && stored == current
def permits (active owner caller storedGeneration currentGeneration remaining : UInt64)
    (bodyMatches : Bool) : Bool :=
  active == 1 && owner == caller && storedGeneration == currentGeneration &&
    remaining == 1 && bodyMatches
-- Finite automatic receipts use the exact current admitted Mailbox binding;
-- the live signer finds the exact caller before invoking this predicate.
def receiptPermits (remaining storedKey currentKey storedBinding currentBinding : UInt64)
    (contextMatches : Bool) : Bool :=
  remaining > 0 && storedKey == currentKey && bindingCurrent storedBinding currentBinding && contextMatches
theorem receipt_exhausted_denies (storedKey currentKey storedBinding currentBinding : UInt64) (context : Bool) :
    receiptPermits 0 storedKey currentKey storedBinding currentBinding context = false := by simp [receiptPermits]
theorem receipt_changed_context_denies (remaining storedKey currentKey storedBinding currentBinding : UInt64) :
    receiptPermits remaining storedKey currentKey storedBinding currentBinding false = false := by simp [receiptPermits]
theorem receipt_missing_binding_denies (remaining storedKey currentKey storedBinding : UInt64) (context : Bool) :
    receiptPermits remaining storedKey currentKey storedBinding 0 context = false := by simp [receiptPermits,bindingCurrent]

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
theorem project_key_has_typed_release_purpose : purposeAllowed 1 6 = true := by decide
theorem feed_key_cannot_sign_project : purposeAllowed 5 6 = false := by decide
theorem node_key_cannot_sign_project : purposeAllowed 3 6 = false := by decide
theorem registry_key_has_typed_decision_purpose : purposeAllowed 7 7 = true := by decide
theorem publisher_cannot_admit_release : purposeAllowed 1 7 = false := by decide
theorem receipt_key_cannot_certify_contact : purposeAllowed 4 1 = false := by decide
theorem receipt_key_has_no_generic_signing (purpose : UInt64) : purposeAllowed 4 purpose = false := by simp [purposeAllowed]
theorem messenger_key_cannot_declare_node : purposeAllowed 2 2 = false := by decide
theorem missing_binding_denies (stored : UInt64) : bindingCurrent stored 0 = false := by
  simp [bindingCurrent]
theorem replaced_binding_denies (stored current : UInt64) (different : (stored == current) = false) :
    bindingCurrent stored current = false := by
  simp [bindingCurrent, different]
theorem feed_author_cannot_sign_moderation : purposeAllowed 5 5 = false := by decide
theorem feed_moderator_cannot_sign_author_events : purposeAllowed 6 4 = false := by decide
theorem feed_author_has_typed_purpose : purposeAllowed 5 4 = true := by decide
theorem feed_moderator_has_typed_purpose : purposeAllowed 6 5 = true := by decide
theorem messenger_cannot_sign_feed : purposeAllowed 2 4 = false := by decide
end Guest.IdentityPolicy
