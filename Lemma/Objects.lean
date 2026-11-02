import Lemma.Types
namespace Lemma.Objects
-- The wire buffer belongs to this process. No process-global object authority
-- or durable retention is created by these calls. Existing broker checks apply.
export Guest.LiveSDK (wire chunk digest error copy zero status result stage append commit read metadata share revoke drop releaseReference abortStage stageDigest)
def maxChunk : UInt64 := 512
def begin (length kind parent hash t : UInt64) : UInt64 := Guest.LiveSDK.begin length kind parent hash t
/-- A borrowed operational handle records the current incarnation. It is never
    a reusable retention credential. -/
def handle (value t : UInt64) : Lemma.ObjectHandle := ⟨value,Guest.LiveSDK.self t⟩
def readScoped (h : Lemma.ObjectHandle) (offset length t : UInt64) : UInt64 :=
  if h.incarnation != Guest.LiveSDK.self t || length > maxChunk then error
  else read h.value offset length t
end Lemma.Objects
