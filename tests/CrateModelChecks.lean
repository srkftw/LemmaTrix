import Guest.CrateModel
open Guest.CrateModel
private def l1 : Level := ⟨18411139144890810879,536870912,134217728,26⟩
private def l2 : Level := ⟨18411139144890810879,524288,134217728,35⟩
private def l3 : Level := ⟨18411139144890810879,1310720,335544320,35⟩
private def l4 : Level := ⟨18411165533169877503,2359296,603979776,35⟩
private def play (l : Level) (directions : List UInt64) : Board :=
  directions.foldl (fun b d => step l.walls b d) ⟨l.boxes,l.player⟩
def main : IO Unit := do
  let cases := [
    ("original level1", valid l1), ("original level2", valid l2),
    ("original level3", valid l3), ("original level4", valid l4),
    ("solve level1", won l1.goals (play l1 [1,1])),
    ("solve level2", won l2.goals (play l2 [2])),
    ("solve level3", won l3.goals (play l3 [0,2,3,1,1,2])),
    ("solve level4", won l4.goals (play l4 [0,2,3,1,1,1,2])),
    ("boundary up", step l1.walls ⟨l1.boxes,9⟩ 2 == ⟨l1.boxes,9⟩),
    ("boundary left", step l1.walls ⟨l1.boxes,9⟩ 0 == ⟨l1.boxes,9⟩),
    ("no row wrap", neighbour 63 1 == 64),
    ("no underflow", neighbour 0 0 == 64),
    ("invalid player", !valid {l1 with player := 64}),
    ("missing goals", !valid {l1 with goals := 0}),
    ("invalid save boxes", !validBoard l1 ⟨0,26⟩)]
  for (name, ok) in cases do
    unless ok do throw (IO.userError name)
  IO.println "CrateModel: original solutions and malformed/boundary cases passed"
