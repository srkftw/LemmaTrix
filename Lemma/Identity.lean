import Lemma.Types
namespace Lemma.Identity
-- Secret lifecycle and release approval belong to trusted native surfaces.
-- A public client cannot request arbitrary signatures or enumerate identities.
def callerIncarnation (t : UInt64) : UInt64 := Guest.LiveSDK.self t
def arbitrarySigningAvailable : Bool := false
def privateKeyExportAvailable : Bool := false
end Lemma.Identity
