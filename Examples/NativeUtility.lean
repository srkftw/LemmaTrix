import Guest.SDK
namespace Guest
-- A native SDK template: read authorized imported object, uppercase, publish a revision.
-- Run with read/create/revise grants; handles are process-local ABI 1 scalar tokens.
def appMain (initial : UInt64) : UInt64 :=
  let len := objectRead 256 256 initial
  if len > 256 then len else
    let token := upper buffer len len
    let revision := objectRevise 256 len token
    if revision == 0xffffffffffffffff then revision else consoleWrite len revision
end Guest
