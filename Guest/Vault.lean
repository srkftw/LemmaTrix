import Guest.LiveSDK
import Guest.Effects
import Guest.ServiceHash
import Guest.VaultCrypto
import Guest.VaultPolicy
import Guest.ProjectVault
import Guest.ServerStore
import Guest.ContentVault
import Guest.ServerContent
namespace Guest.Vault
open Guest.LiveSDK
-- One explicitly authorized Objects record per vault. Dual authenticated roots select
-- committed banks only. Entire-store rollback remains outside this implementation.
def state : UInt64 := 0x620000
def key : UInt64 := state+128
def digest : UInt64 := state+160
def header : UInt64 := state+512
def rootA : UInt64 := state+1024
def rootB : UInt64 := state+1536
def bank : UInt64 := 0x630000
def plaintext : UInt64 := 0x650000
def ioBuffer : UInt64 := 0x412000
def magic : UInt64 := 0x31544c56544c
def error : UInt64 := 0xffffffffffffffff

partial def equal (a b n t : UInt64) : Bool :=
  if n == 0 then true else load8 a t == load8 b t && equal (a+1) (b+1) (n-1) t
partial def allZero (p n t : UInt64) : Bool :=
  if n == 0 then true else load8 p t == 0 && allZero (p+1) (n-1) t
-- An actual consumer of the typed inline StateM SDK: wrappers and do notation lower
-- to the same fixed-width primitive ABI, without guest closures or heap objects.
def device (op sector ptr bytes t : UInt64) : UInt64 := Effects.run (do
  let result ← Effects.call op ⟨sector⟩ ⟨ptr⟩ ⟨bytes⟩
  return result.word) t
partial def transfer (op sector ptr remaining t : UInt64) : UInt64 :=
  if remaining == 0 then t else
    let n := if remaining < 4096 then remaining else 4096
    let t := if op == 61 then copy ptr ioBuffer n t else t
    let result := device op sector ioBuffer n t
    if result != 0 then error else
      let t := if op == 60 then copy ioBuffer ptr n result else result
      transfer op (sector+n/512) (ptr+n) (remaining-n) t

def describe (status result t : UInt64) : UInt64 :=
  let t := zero wire 128 t
  let t := store64 wire status t
  let t := store64 (wire+8) result t
  let t := store64 (wire+16) (load64 (state+24) t) t
  let t := store64 (wire+24) (load64 (state+40) t) t
  let t := store64 (wire+32) (load64 (state+32) t) t
  let t := store64 (wire+40) (load64 state t) t
  let t := store64 (wire+48) 3 t
  let t := store64 (wire+56) (load64 (state+8) t) t
  64+t

def wipePlain (t : UInt64) : UInt64 :=
  let t := zero plaintext 8192 t
  store64 (state+16) 0 t

def wipeSecrets (t : UInt64) : UInt64 :=
  let t := ContentVault.abandonPersonal t
  let t := ProjectVault.clear t
  let t := zero plaintext 8192 t
  let t := zero 0x600000 16384 t
  let t := zero bank 9216 t
  let t := zero state 256 t
  let t := zero ioBuffer 512 t
  zero incoming 128 t

def lock (t : UInt64) : UInt64 := describe 0 0 (wipeSecrets t)

-- Explicit logical deletion invalidates both durable commit roots before acknowledgment.
-- Ciphertext remains on the medium; this operation does not claim physical secure erasure.
def delete (t : UInt64) : UInt64 :=
  if load64 state t != 1 then describe 3 0 t else
    let t := zero ioBuffer 64 t
    let first := device 61 0 ioBuffer 512 t
    if first != 0 then describe 4 0 (wipeSecrets first) else
      let second := device 61 1 ioBuffer 512 first
      if second != 0 then describe 4 0 (wipeSecrets second) else
        let flushed := device 62 0 ioBuffer 0 second
        if flushed != 0 then describe 4 0 (wipeSecrets flushed)
        else describe 0 0 (wipeSecrets flushed)

def validRoot (r t : UInt64) : Bool :=
  load64 r t == magic && load64 (r+8) t == 1 && load64 (r+16) t == 3 &&
  load64 (r+24) t > 0 && load64 (r+32) t == load64 (r+24) t%2 && load64 (r+40) t <= 65536 &&
  load64 (r+48) t > 0 && load64 (r+48) t <= 9 && allZero (r+116) 12 t && allZero (r+176) 336 t

def tryRoot (r t : UInt64) : UInt64 :=
  if !validRoot r t then error else
    let len := load64 (r+40) t
    let sector := if load64 (r+32) t == 0 then 8 else 152
    let bytes := ((len+144+511)/512)*512
    let result := transfer 60 sector bank bytes t
    if result != 0 || !equal r bank 128 result || !equal (r+128) (bank+128+len) 16 result then error else
      let t := ServiceHash.sha256At 0x600200 (bank+128) len digest result
      if !equal digest (r+144) 32 t then error else
        let result := VaultCrypto.decrypt key (r+104) r 128 (bank+128) len plaintext t
        if result != 0 then error else
          let t := ServiceHash.sha256At 0x600200 plaintext len digest result
          if !equal digest (r+72) 32 t then error else
            let t := copy r header 128 t
            let t := store64 (state+8) (load64 (r+24) t) t
            let t := store64 (state+24) len t
            let t := store64 (state+32) (load64 (r+48) t) t
            let t := store64 (state+40) (load64 (r+56) t) t
            let t := store64 (state+56) (load64 (r+32) t) t
            store64 (state+88) 1 t

def scan (t : UInt64) : UInt64 :=
  let t := wipePlain t
  let a := transfer 60 0 rootA 512 t
  if a != 0 then error else
    let b := transfer 60 1 rootB 512 a
    if b != 0 then error else
      let high := if load64 (rootA+24) b >= load64 (rootB+24) b then rootA else rootB
      let low := if high == rootA then rootB else rootA
      let result := tryRoot high b
      if result == 0 then result else
        let result := tryRoot low b
        if result == 0 then result else
          if allZero rootA 512 b && allZero rootB 512 b then
            let t := store64 (state+8) 0 b
            let t := store64 (state+24) 0 t
            let t := store64 (state+32) 0 t
            let t := store64 (state+40) 0 t
            let t := store64 (state+56) 0 t
            let t := zero header 16 t
            store64 (state+88) 0 t
          else error

def unlock (length t : UInt64) : UInt64 :=
  if length != 96 then describe 2 0 t else
    let t := wipePlain t
    let t := zero key 4 t
    let t := store64 state 0 t
    let t := copy (command+64) key 32 t
    let legacy := scan t
    let result := if legacy == 0 then ProjectVault.scan legacy else legacy
    if result != 0 then
      let t := ProjectVault.clear result
      let t := zero key 4 t
      let t := zero 0x600000 16384 t
      describe 5 0 t
    else
      let t := wipePlain result
      let t := store64 state 1 t
      describe 0 0 t

partial def fetch (h offset len t : UInt64) : UInt64 :=
  if offset == len then t else
    let n := if len-offset < 512 then len-offset else 512
    let result := LiveSDK.read h offset n t
    if result != 64+n || load64 wire result != 0 || load64 (wire+8) result != n then error else
      fetch h (offset+n) len (copy (wire+64) (plaintext+offset) n result)

def retain (h rights domain t : UInt64) : UInt64 :=
  if !VaultPolicy.authorized rights domain then describe 1 0 t else
  if load64 state t != 1 then describe 3 0 t else
    let t := wipePlain t
    let received := metadata h t
    if received != 96 || load64 wire received != 0 || load64 (wire+16) received > 65536 ||
      load64 (wire+32) received == 0 || load64 (wire+32) received > 9 || load64 (wire+40) received != 2 then describe 1 0 received else
      let len := load64 (wire+16) received
      let generation := load64 (state+8) received+1
      if generation == 0 then describe 6 0 received else
        let t := zero header 16 received
        let t := store64 header magic t
        let t := store64 (header+8) 1 t
        let t := store64 (header+16) 3 t
        let t := store64 (header+24) generation t
        let t := store64 (header+32) (generation%2) t
        let t := store64 (header+40) len t
        let t := store64 (header+48) (load64 (wire+32) t) t
        let t := store64 (header+56) (load64 (wire+24) t) t
        let t := store64 (header+64) (load64 (wire+56) t) t
        let t := copy (wire+64) (header+72) 32 t
        let result := fetch h 0 len t
        if result != 0 then describe 1 0 (wipePlain result) else
          let t := ServiceHash.sha256At 0x600200 plaintext len digest result
          if !equal digest (header+72) 32 t then describe 5 0 (wipePlain t) else
            let entropy := device 63 0 ioBuffer 12 t
            if entropy != 0 then describe 4 0 (wipePlain entropy) else
              let t := copy ioBuffer (header+104) 12 entropy
              let t := zero bank 9216 t
              let t := copy header bank 128 t
              let result := VaultCrypto.encrypt key (header+104) header 128 plaintext len (bank+128) t
              if result != 0 then describe 5 0 (wipePlain result) else
                let t := wipePlain result
                let bytes := ((len+144+511)/512)*512
                let sector := if generation%2 == 0 then 8 else 152
                let written := transfer 61 sector bank bytes t
                if written != 0 then describe 4 0 written else
                  let flushed := device 62 0 ioBuffer 0 written
                  if flushed != 0 then describe 4 0 flushed else
                    let t := zero rootA 64 flushed
                    let t := copy header rootA 128 t
                    let t := copy (bank+128+len) (rootA+128) 16 t
                    let t := ServiceHash.sha256At 0x600200 (bank+128) len (rootA+144) t
                    let committed := transfer 61 (generation%2) rootA 512 t
                    if committed != 0 then describe 4 0 committed else
                      let flushed := device 62 0 ioBuffer 0 committed
                      if flushed != 0 then describe 4 0 flushed else
                        let published := VaultPolicy.committedGeneration rights domain (load64 state flushed == 1) (load64 (state+8) flushed) generation
                        let t := store64 (state+8) published flushed
                        let t := store64 (state+24) len t
                        let t := store64 (state+32) (load64 (header+48) t) t
                        let t := store64 (state+40) (load64 (header+56) t) t
                        let t := store64 (state+56) (generation%2) t
                        let t := store64 (state+88) 1 t
                        describe 0 generation t

def recover (t : UInt64) : UInt64 :=
  if load64 state t != 1 then describe 3 0 t else
    let result := scan t
    if result != 0 then describe 5 0 (wipePlain result) else
      if load64 (state+88) result != 1 then describe 6 0 result else
        let t := store64 (state+16) 1 result
        let t := describe 0 (load64 (state+24) t) t
        96+copy (header+72) (wire+64) 32 t

def status (t : UInt64) : UInt64 :=
  if load64 state t == 1 && load64 (state+88) t == 1 then
    let t := describe 0 (load64 (header+64) t) t
    96+copy (header+72) (wire+64) 32 t
  else describe 0 0 t

def recoverChunk (offset count t : UInt64) : UInt64 :=
  let len := load64 (state+24) t
  if load64 state t != 1 || load64 (state+16) t != 1 then describe 3 0 t else
    if count > 512 || offset > len || count > len-offset then describe 2 0 t else
      let t := describe 0 count t
      if count == 0 then t else 64+count+copy (plaintext+offset) (wire+64) count t

def dispatch (caller rights length t : UInt64) : UInt64 :=
  if length < 64 || load64 (command+56) t != 1 then describe 2 0 t else
    let op := load64 command t
    let domain := load64 (command+16) t
    if op >= 230 && op <= 239 then ServerStore.dispatch caller rights length t else
    if op >= 250 && op <= 256 then ServerContent.dispatch caller rights length t else
    if op == 247 then
      let shell := syscall 97 4 0 0 0 t
      let manager := syscall 97 1 0 0 0 shell
      if caller != shell || domain != 3 || length != 64 || ContentVault.isServer manager ||
        load64 (command+8) manager == 0 || load64 (command+8) manager != load64 (ContentVault.st+8) manager ||
        load64 (ContentVault.st+16) manager != manager then ContentVault.response 1 manager else
        ContentVault.response (if load64 state manager == 1 then 0 else 3) manager
    else
    if !VaultPolicy.authorized rights domain then describe 1 0 t else
      if op == 200 then
        if ContentVault.active t && !ContentVault.isServer t then describe 7 0 t else unlock length t
      else if op >= 240 && op <= 249 then
        if load64 state t != 1 then
          if op == 240 then ContentVault.rejectRetain 3 (load64 (command+8) t) t else describe 3 0 t
        else ContentVault.dispatch caller op length t
      else if op >= 210 && op <= 217 then
        if load64 state t != 1 then describe 3 0 t else ProjectVault.dispatch op length t
      else if length != 64 then describe 2 0 t
      else if op == 201 then lock t
      else if op == 202 then status t
      else if op == 203 then retain (load64 (command+8) t) rights domain t
      else if op == 204 then recover t
      else if op == 205 then delete t
      else if op == 206 then recoverChunk (load64 (command+24) t) (load64 (command+32) t) t
      else describe 2 0 t

partial def loop (initial : UInt64) : UInt64 :=
  let t := ContentVault.pump initial
  let received := if ContentVault.active t then syscall 36 3 incoming 1024 0 t else receive 3 t
  if received == 0 then loop (syscall 117 (syscall 116 0 0 0 0 received+1) 0 0 0 received) else
  if received == error then loop received else
  let token := load64 (incoming+8) received
  let caller := load64 incoming received
  let rights := load64 (incoming+16) received
  let length := if received >= 32 then received-32 else 0
  let replyLength := dispatch caller rights length received
  let t := zero incoming 128 replyLength
  let t := LiveSDK.reply token replyLength t
  loop t

def appMain (initial : UInt64) : UInt64 :=
  let t := ProjectVault.clear (ContentVault.clear (ServerContent.clear initial))
  let t := zero state 256 t
  let t := zero 0x600000 16384 t
  let t := wipePlain t
  loop t
end Guest.Vault
