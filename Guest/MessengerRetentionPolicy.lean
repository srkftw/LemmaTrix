namespace Guest.MessengerRetentionPolicy
-- The live normal-recovery check requires both the latest reserved counter
-- and its random nonce prefix. Reserving a later counter retires older roots.
def currentNonce (rootCounter reservedCounter : UInt64) (samePrefix : Bool) : Bool :=
  rootCounter == reservedCounter && samePrefix
theorem stale_counter_denied (rootCounter reservedCounter : UInt64)
    (h : rootCounter ≠ reservedCounter) :
    currentNonce rootCounter reservedCounter true = false := by
  simp [currentNonce,h]
theorem changed_prefix_denied (rootCounter reservedCounter : UInt64) :
    currentNonce rootCounter reservedCounter false = false := by
  simp [currentNonce]
theorem matching_reservation_allowed (counter : UInt64) :
    currentNonce counter counter true = true := by
  change (decide (counter = counter) && true) = true
  rw [decide_eq_true (Eq.refl counter)]
  rfl
end Guest.MessengerRetentionPolicy
