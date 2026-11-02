import Lemma.Types
import Guest.ProjectSDK
namespace Lemma.Forge
-- A selected Objects project grant is required. These operations neither install
-- an executable nor approve signing, publication or an unselected root.
export Guest.ProjectSDK (nodeMetadata openHead resolve closure describeRoot projectIdentity freeze freezeExport publish delegate)
def fork (root expected publisher alias aliasLength t : UInt64) : UInt64 :=
  Guest.ProjectSDK.forkProject root expected publisher alias aliasLength t
end Lemma.Forge
