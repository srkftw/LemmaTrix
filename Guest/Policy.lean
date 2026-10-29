namespace Guest.Policy
/-- Pure portion of the kernel-owned capability check. Handle generation is never supplied as identity. -/
def permits (storedGeneration handleGeneration active granted requested : UInt64) : Bool :=
  storedGeneration == handleGeneration && active == 1 && (granted &&& requested) == requested

theorem revoked_denies (g h rights requested : UInt64) :
    permits g h 0 rights requested = false := by
  unfold permits
  have zero_ne_one : ((0 : UInt64) == 1) = false := by decide
  rw [zero_ne_one]
  cases (g == h) <;> rfl

theorem stale_denies (g h active rights requested : UInt64) (stale : (g == h) = false) :
    permits g h active rights requested = false := by
  unfold permits
  rw [stale]
  rfl

theorem missing_right_denies (g h active rights requested : UInt64)
    (missing : ((rights &&& requested) == requested) = false) :
    permits g h active rights requested = false := by
  unfold permits
  rw [missing]
  exact Bool.and_false _

/-- A denied publication leaves the externally visible generation unchanged. -/
def nextGeneration (allowed : Bool) (old proposed : UInt64) : UInt64 :=
  if allowed then proposed else old

theorem denied_preserves_generation (old proposed : UInt64) :
    nextGeneration false old proposed = old := by
  rfl
end Guest.Policy
