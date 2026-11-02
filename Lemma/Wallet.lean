import Lemma.Types
namespace Lemma.Wallet
-- LemmaCoin's protocol is absent. No balance, payment receipt or success value
-- is fabricated by the SDK.
def available : Bool := false
def requestPayment : Lemma.Result UInt64 := .failed .unavailable
end Lemma.Wallet
