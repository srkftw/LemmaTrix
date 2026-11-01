import Guest.FeedEvent
namespace Guest.FeedPolicy
open Guest.LiveSDK
-- Transport ownership never supplies durable author identity. An authenticated
-- retry may use a new origin only after its signed event is revalidated.
def stageOwned (caller origin handle expectedCaller expectedOrigin expectedHandle : UInt64) : Bool :=
  caller == expectedCaller && origin == expectedOrigin && handle != 0 && handle == expectedHandle
theorem foreign_origin_denied (caller origin handle ec eo eh : UInt64) (h : origin ≠ eo) :
    stageOwned caller origin handle ec eo eh = false := by simp [stageOwned, h]
theorem zero_stage_denied (caller origin ec eo eh : UInt64) :
    stageOwned caller origin 0 ec eo eh = false := by simp [stageOwned]
-- Signed moderation is separate from author validity and local preference.
-- action1 hide,2 appeal upheld,3 reversal. A decision always binds one exact
-- target event, one federation, configured moderator key and policy version.
def authorizedDecision (event federation moderator policy t : UInt64) : Bool :=
  Guest.FeedEvent.framingValid event t && load64 (event+176) t == 8 &&
  Guest.FeedEvent.eq (event+272) federation 32 t &&
  Guest.FeedEvent.eq (event+112) moderator 32 t && load64 (event+264) t == policy

def visible (blocked : Bool) (decision : UInt64) : Bool := !blocked && decision != 1 && decision != 2
theorem reversal_preserves_local_block : visible true 3 = false := by decide
theorem unblocked_reversal_visible : visible false 3 = true := by decide
end Guest.FeedPolicy
