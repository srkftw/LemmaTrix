import Lemma.UI
import Lemma.Objects
namespace Main
-- Private app memory and ordinary caller surface; no trusted approval surface.
partial def loop (surface t : UInt64) : UInt64 :=
  let e := Lemma.UI.event t
  if e == 1 then Lemma.UI.exit 0 e
  else loop surface (Lemma.UI.wait (Lemma.UI.now e+1) e)
def main (initial : UInt64) : UInt64 :=
  let surface := Lemma.UI.createSurface initial
  if surface == Lemma.UI.error then surface else
  let t := Lemma.UI.fill 0 0 640 352 0x152632 surface
  let t := Lemma.UI.hex 0x1e77a 5 40 40 0xe5eef7 0x152632 t
  let t := Lemma.UI.upload surface 0 901120 t
  loop surface (Lemma.UI.present surface t)
end Main
