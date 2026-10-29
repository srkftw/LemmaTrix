import Guest.Primitives
namespace Guest.Keyboard
def scanCode (code shift : UInt64) : UInt64 :=
  if code >= 2 && code <= 11 then
    if shift == 1 then if code == 2 then 33 else if code == 3 then 64 else if code == 4 then 35 else if code == 5 then 36 else if code == 6 then 37 else if code == 7 then 94 else if code == 8 then 38 else if code == 9 then 42 else if code == 10 then 40 else 41
    else if code == 11 then 48 else code+47
  else if code == 28 then 10 else if code == 57 then 32 else if code == 15 then 9
  else if code == 12 then if shift == 1 then 95 else 45
  else if code == 13 then if shift == 1 then 43 else 61
  else if code == 26 then if shift == 1 then 123 else 91
  else if code == 27 then if shift == 1 then 125 else 93
  else if code == 39 then if shift == 1 then 58 else 59
  else if code == 40 then if shift == 1 then 34 else 39
  else if code == 41 then if shift == 1 then 126 else 96
  else if code == 43 then if shift == 1 then 124 else 92
  else if code == 51 then if shift == 1 then 60 else 44
  else if code == 52 then if shift == 1 then 62 else 46
  else if code == 53 then if shift == 1 then 63 else 47
  else
    let c := if code == 16 then 113 else if code == 17 then 119 else if code == 18 then 101 else if code == 19 then 114 else if code == 20 then 116 else if code == 21 then 121 else if code == 22 then 117 else if code == 23 then 105 else if code == 24 then 111 else if code == 25 then 112 else if code == 30 then 97 else if code == 31 then 115 else if code == 32 then 100 else if code == 33 then 102 else if code == 34 then 103 else if code == 35 then 104 else if code == 36 then 106 else if code == 37 then 107 else if code == 38 then 108 else if code == 44 then 122 else if code == 45 then 120 else if code == 46 then 99 else if code == 47 then 118 else if code == 48 then 98 else if code == 49 then 110 else if code == 50 then 109 else 0
    if c != 0 && shift == 1 then c-32 else c
end Guest.Keyboard
