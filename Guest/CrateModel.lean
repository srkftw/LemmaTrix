namespace Guest.CrateModel

-- A bounded original box-pushing game. Bit positions are y*8+x; no pointer,
-- object capability, executable or provider input enters these transitions.
structure Level where
  walls : UInt64
  goals : UInt64
  boxes : UInt64
  player : UInt64
  deriving DecidableEq, Repr

structure Board where
  boxes : UInt64
  player : UInt64
  deriving DecidableEq, Repr

def bit (position : UInt64) : UInt64 := (1 : UInt64) <<< position
def occupied (mask position : UInt64) : Bool := (mask &&& bit position) != 0
partial def count (mask n acc : UInt64) : UInt64 :=
  if n == 64 then acc else count mask (n+1) (acc+((mask >>> n) &&& 1))

def boundary : UInt64 := 0xff818181818181ff
def valid (level : Level) : Bool :=
  level.player < 64 && (level.walls &&& boundary) == boundary &&
  (level.goals &&& level.walls) == 0 && (level.boxes &&& level.walls) == 0 &&
  !occupied level.walls level.player && !occupied level.boxes level.player &&
  count level.boxes 0 0 > 0 && count level.boxes 0 0 <= 8 &&
  count level.boxes 0 0 == count level.goals 0 0

def validBoard (level : Level) (board : Board) : Bool :=
  board.player < 64 && !occupied level.walls board.player &&
  !occupied board.boxes board.player && (board.boxes &&& level.walls) == 0 &&
  count board.boxes 0 0 == count level.boxes 0 0

def neighbour (position direction : UInt64) : UInt64 :=
  if position >= 64 then 64 else
  if direction == 0 then (if position%8 == 0 then 64 else position-1) else
  if direction == 1 then (if position%8 == 7 then 64 else position+1) else
  if direction == 2 then (if position < 8 then 64 else position-8) else
  if direction == 3 then (if position >= 56 then 64 else position+8) else 64

def step (walls : UInt64) (board : Board) (direction : UInt64) : Board :=
  let next := neighbour board.player direction
  if next >= 64 || occupied walls next then board else
  if !occupied board.boxes next then ⟨board.boxes,next⟩ else
    let beyond := neighbour next direction
    if beyond >= 64 || occupied walls beyond || occupied board.boxes beyond then board else
      ⟨(board.boxes &&& (~~~(bit next))) ||| bit beyond,next⟩

def won (goals : UInt64) (board : Board) : Bool := board.boxes == goals

-- Source-level only. This is the exact blocked-move branch consumed by step;
-- assumptions explicitly enumerate the checked wall/bounds decision.
theorem blocked_move_preserves (walls : UInt64) (board : Board) (direction : UInt64)
    (blocked : (neighbour board.player direction >= 64 ||
      occupied walls (neighbour board.player direction)) = true) :
    step walls board direction = board := by
  simp [step, blocked]

end Guest.CrateModel
