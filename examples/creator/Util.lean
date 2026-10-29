import Guest.Structured
namespace Util
open Guest.Structured

-- Edit this real algorithm parameter, then build the selected immutable project.
def Weight : UInt64 := 3

structure Summary where
  bytes : UInt64
  vowels : UInt64
  consonants : UInt64
  score : UInt64
  deriving Inhabited

@[noinline] def classify (c : UInt64) : Checked :=
  let lower := if c >= 65 && c <= 90 then c+32 else c
  if lower == 97 || lower == 101 || lower == 105 || lower == 111 || lower == 117 then .ok 0
  else if lower >= 97 && lower <= 122 then .ok 1
  else .error c

partial def scan (b : Bytes) (index vowels consonants score accent t : UInt64) : Summary :=
  if index >= b.length then ⟨b.length,vowels,consonants,score⟩ else
    match b.read index t with
    | .error _ => ⟨0,0,0,0⟩
    | .ok c =>
      match classify c with
      | .ok weight =>
        if weight == 0 then scan b (index+1) (vowels+1) consonants (score+Weight) accent t
        else scan b (index+1) vowels (consonants+1) (score+weight) accent t
      | .error value =>
        let extra := if value >= 48 && value <= 57 then accent else 0
        scan b (index+1) vowels consonants (score+extra) accent t

@[noinline] def analyze (b : Bytes) (accent t : UInt64) : Summary :=
  if b.valid then scan b 0 0 0 0 accent t else ⟨0,0,0,0⟩
end Util
