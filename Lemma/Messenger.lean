import Lemma.Types
import Guest.AppIntentSDK
namespace Lemma.Messenger
-- Recipient approval and the session/ratchet remain inside native Messenger.
-- Selection of an excerpt never authorizes another recipient or arbitrary blob.
def maxTextBytes : UInt64 := 512
def requestMessage (payload length recipient operation t : UInt64) : UInt64 :=
  Guest.AppIntentSDK.requestMessage payload length recipient operation t
def inspect (operation t : UInt64) : UInt64 := Guest.AppIntentSDK.inspect 2 operation t
def cancel (operation t : UInt64) : UInt64 := Guest.AppIntentSDK.cancel 2 operation t
end Lemma.Messenger
