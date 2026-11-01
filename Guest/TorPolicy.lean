namespace Guest.TorPolicy
-- The live router calls this exact predicate before reserving a record's bytes
-- and work. These source-level denial lemmas do not establish binary semantics.
def recordAllowed (channel bytes used byteLimit work workLimit : UInt64) : Bool :=
  channel < 4 && bytes > 0 && used <= byteLimit && bytes <= byteLimit-used && work < workLimit

theorem unknown_channel_denied (bytes used byteLimit work workLimit : UInt64) :
    recordAllowed 4 bytes used byteLimit work workLimit = false := by
  simp [recordAllowed]

theorem empty_record_denied (channel used byteLimit work workLimit : UInt64) :
    recordAllowed channel 0 used byteLimit work workLimit = false := by
  simp [recordAllowed]

theorem exhausted_work_denied (channel bytes used byteLimit work : UInt64) :
    recordAllowed channel bytes used byteLimit work work = false := by
  simp [recordAllowed]
end Guest.TorPolicy
namespace Guest.TorPolicy
theorem exhausted_bytes_denied (channel limit work workLimit : UInt64) :
    recordAllowed channel 1 limit limit work workLimit = false := by
  simp [recordAllowed]
end Guest.TorPolicy
