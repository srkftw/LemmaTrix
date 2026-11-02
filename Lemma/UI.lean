import Lemma.Types
import Guest.Raster
import Guest.Keyboard
import Guest.WaitSDK
import Guest.ProjectSDK
namespace Lemma.UI
-- Borrowed private memory and raster helpers. The kernel bounds surfaces and
-- input to this caller; trusted review surfaces cannot be created by this API.
export Guest (load8 load64 store8 store64)
export Guest.Raster (pixels color fill char text hex)
export Guest.Keyboard (scanCode)
def error : UInt64 := Guest.LiveSDK.error
def self (t : UInt64) : UInt64 := Guest.LiveSDK.self t
def createSurface (t : UInt64) : UInt64 := Guest.syscall 80 0 0 0 0 t
def upload (surface offset count t : UInt64) : UInt64 :=
  if offset > 901120 || count > 901120-offset || count%4 != 0 then error
  else Guest.Raster.upload surface offset count 0 t
-- Upload marks the caller surface dirty. Yield lets the native compositor
-- present it asynchronously; the app cannot invoke compositor-only operations.
def present (_surface t : UInt64) : UInt64 := Guest.syscall 9 0 0 0 0 t
def event (t : UInt64) : UInt64 := Guest.syscall 90 (self t) 0 0 0 t
def wait (deadline t : UInt64) : UInt64 := Guest.WaitSDK.deadline deadline t
def now (t : UInt64) : UInt64 := Guest.WaitSDK.now t
def exit (code t : UInt64) : UInt64 := Guest.syscall 10 code 0 0 0 t
def console (data length t : UInt64) : UInt64 := Guest.LiveSDK.console data length t
-- Trusted shell owns selected-project and explicit retention reviews. Requests
-- are asynchronous; an app-drawn dialog cannot approve these actions.
def shell (t : UInt64) : UInt64 := Guest.syscall 97 4 0 0 0 t
def requestProject (nonce t : UInt64) : UInt64 :=
  if nonce == 0 then error else
  let target := shell t
  Guest.syscall 30 target Guest.LiveSDK.wire 64 1024 (Guest.LiveSDK.header 3 0 nonce 0 0 0 0 target)
def pollProject (nonce t : UInt64) : UInt64 :=
  let target := shell t
  Guest.syscall 30 target Guest.LiveSDK.wire 64 1024 (Guest.LiveSDK.header 4 0 nonce 0 0 0 0 target)
def retainProject (root expected t : UInt64) : UInt64 :=
  let target := shell t
  let r := Guest.ProjectSDK.delegate root target 127 target
  if r == error || Guest.LiveSDK.status r != 0 then error else
  let t := Guest.LiveSDK.header 2 (Guest.LiveSDK.result r) 0 0 0 0 0 r
  let t := Guest.LiveSDK.copy expected (Guest.LiveSDK.wire+64) 32 t
  Guest.syscall 30 target Guest.LiveSDK.wire 96 1024 t
end Lemma.UI
