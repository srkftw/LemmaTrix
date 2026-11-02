import Lemma.Types
namespace Lemma.Proof
/-- An evidence commitment is an attribution, not a compiler-correctness proof. -/
structure Evidence where
  contentId : Lemma.Bytes
  sourceId : Lemma.Bytes
  toolchainId : Lemma.Bytes
  independentAdministration : Bool

def compilerCorrectnessProved : Bool := false
end Lemma.Proof
