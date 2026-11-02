import Lemma.Forge
namespace Lemma.Library
-- Inspect only a caller-selected project. Catalog acquisition remains a native
-- Library review action; receiving a Feed card is not install/execute approval.
def inspect (project : Lemma.ProjectHandle) (t : UInt64) : UInt64 :=
  Guest.ProjectSDK.describeRoot project.value t
def resolve (project : Lemma.ProjectHandle) (contentId t : UInt64) : UInt64 :=
  Guest.ProjectSDK.resolve project.value contentId t
def automaticInstallAvailable : Bool := false
end Lemma.Library
