namespace Guest.NodeEnrollmentPolicy
-- Live stage/approve already binds the exact newly verified fingerprint. This
-- predicate distinguishes in-place rotation from explicit revoked replacement.
def pinAccept (oldState : UInt64) (sameIdentity sameBinding newer : Bool) : Bool :=
  oldState == 0 ||
  ((oldState == 1 || (oldState == 2 && sameIdentity)) && sameBinding && newer) ||
  (oldState == 2 && !sameIdentity)

theorem active_identity_substitution_denied (newer : Bool) :
    pinAccept 1 false false newer = false := by cases newer <;> decide
theorem revoked_new_identity_allowed : pinAccept 2 false false false = true := by decide
theorem active_stale_generation_denied : pinAccept 1 true true false = false := by decide
theorem revoked_stale_generation_denied : pinAccept 2 true true false = false := by decide
theorem same_identity_scope_substitution_denied : pinAccept 2 true false true = false := by decide
end Guest.NodeEnrollmentPolicy
