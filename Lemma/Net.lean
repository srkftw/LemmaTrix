import Lemma.Types
import Guest.NetworkSDK
namespace Lemma.Net
/-- Only mode 1's approved terminal request is an ordinary app transport here.
    Peer enrollment, provisioning, grants and mode 3 bypass are not public APIs. -/
def interactiveOnion : UInt64 := 1
def maxRequestBytes : UInt64 := 960
def submit (request : Lemma.Operation) (payload : Lemma.Bytes) (t : UInt64) : UInt64 :=
  if !payload.valid || payload.length < 64 || payload.length > maxRequestBytes then Guest.LiveSDK.error
  else Guest.NetworkSDK.terminalSubmit interactiveOnion request.value payload.address payload.length t
def collect (request : Lemma.Operation) (t : UInt64) : UInt64 :=
  Guest.NetworkSDK.terminalCollect interactiveOnion request.value t
def delayedMixAvailable : Bool := false
def privateClusterAvailable : Bool := false
end Lemma.Net
