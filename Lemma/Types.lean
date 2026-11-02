import Guest.Structured
import Guest.LiveSDK
namespace Lemma
/-- SDK 0.1.0. Live values are scoped to the issuing process and service epoch;
    stable content identities must be stored separately. -/
def sdkVersion : UInt64 := 0x00010000
abbrev Bytes := Guest.Structured.Bytes
abbrev ObjectHandle := Guest.Structured.ObjectHandle
abbrev ProjectHandle := Guest.Structured.ProjectHandle
abbrev SurfaceHandle := Guest.Structured.SurfaceHandle
abbrev InputEvent := Guest.Structured.InputEvent
inductive Error where
  | invalidInput | denied | busy | unavailable | expired | cancelled | incompatible | uncertain
inductive Result (α : Type) where
  | ok (value : α)
  | failed (reason : Error)
structure Operation where
  value : UInt64
  serviceGeneration : UInt64
/-- Only evidence reported by the owning service may advance an operation. -/
inductive Completion where
  | pending | reviewRequired | accepted | recipientConfirmed | failed | cancelled | outcomeUncertain
end Lemma
