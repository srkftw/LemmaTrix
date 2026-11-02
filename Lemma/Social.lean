import Lemma.Types
import Guest.AppIntentSDK
namespace Lemma.Social
-- Frozen request bytes are queued for trusted Feed owner review. The ordinary
-- app receives a caller-scoped operation, never account management authority.
def maxTextBytes : UInt64 := 512
def requestFeed (payload length audience operation t : UInt64) : UInt64 :=
  Guest.AppIntentSDK.requestFeed payload length audience operation t
def inspect (operation t : UInt64) : UInt64 := Guest.AppIntentSDK.inspect 5 operation t
def cancel (operation t : UInt64) : UInt64 := Guest.AppIntentSDK.cancel 5 operation t
end Lemma.Social
