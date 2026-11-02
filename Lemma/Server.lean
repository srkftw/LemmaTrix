import Lemma.Types
import Guest.ServerSDK
namespace Lemma.Server
structure StoreGrant where
  value : UInt64
  generation : UInt64
-- Only a separately issued exact store grant is accepted by the server broker.
def describe (grant : StoreGrant) (t : UInt64) : UInt64 := Guest.ServerSDK.describe grant.value t
def read (grant : StoreGrant) (offset bytes t : UInt64) : UInt64 := Guest.ServerSDK.read grant.value offset bytes t
def progress (grant : StoreGrant) (t : UInt64) : UInt64 := Guest.ServerSDK.progress grant.value t
def provisionAvailable : Bool := false
end Lemma.Server
