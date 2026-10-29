import Examples.StructuredProducer
namespace Examples.StructuredConsumer
open Guest.Structured Examples.StructuredProducer

@[noinline] def readValue (b : Bytes) (index : UInt64) : UInt64 :=
  match b.read index 0 with
  | .ok value => value
  | .error code => 1000+code

@[noinline] def eventValue (e : InputEvent) : UInt64 :=
  match eventCode e with
  | .ok code => code+e.x+e.y+e.sequence
  | .error kind => 100+kind

partial def repeated (remaining sum : UInt64) : UInt64 :=
  if remaining == 0 then sum else
    let c := cursor 2 4 remaining
    let v := selectedWidth (select c)
    repeated (remaining-1) (sum+v)

/-- Native fixture crosses two application modules, reuses/shared records, matches
    all variants, checks byte access, and reclaims far more than the arena capacity. -/
def check (_ : UInt64) : UInt64 :=
  let p := 0x414000
  let t := Guest.store8 p 65 0
  let t := Guest.store8 (p+1) 0xc3 t
  let t := Guest.store8 (p+2) 0xa9 t
  let b := bytes p 3 16
  let good := readValue b 0
  let bad := readValue b 16
  let ev := event 1 7 3 4 0 10
  let e := eventValue ev
  let none := selectedWidth .empty
  let err := selectedWidth (.rejected 19)
  let boundaries := b.boundary 1 t && !b.boundary 2 t && b.boundary 3 t
  let write := match b.write 3 90 t with | .ok v => v | .error _ => 0
  let b := b.withLength 4
  let packed := packedValue (packed 0x8000000000000000)
  let boxed := optionValue (optional 0xffffffffffffffff)
  let absent := optionValue (optional 0)
  let result := repeated 4096 0
  if good == 65 && bad == 1001 && e == 24 && none == 0 && err == 19 &&
      boundaries && packed == 0x80000000fedcbcA0 && boxed == 0xffffffffffffffff && absent == 17 && write == 90 && readValue b 3 == 90 && result == 8402944 then 0 else 1
end Examples.StructuredConsumer
