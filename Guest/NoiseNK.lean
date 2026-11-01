import Guest.Noise
import Guest.LiveSDK
namespace Guest.NoiseNK
open Guest.LiveSDK
-- Noise revision34 NK: <- s; -> e,es; <- e,ee.
-- No initiator static identity is sent. Accepted descriptor commitment is the
-- prologue suffix; the responder public key is the specified pre-message.
-- Uses Noise's serialized workspace. Persistent channel state is banked by
-- the owner; no yield/IPC is permitted during a handshake/record quantum.
def init (role staticPrivate acceptedStatic descriptor ephemeral t : UInt64) : UInt64 :=
  let t := Guest.Noise.disconnect t
  let t := copy ephemeral Guest.Noise.privateKey 32 t
  let t := copy acceptedStatic Guest.Noise.remoteKey 32 t
  let t := if role == 2 then copy staticPrivate Guest.Noise.psk 32 t else t
  -- SHA256("Noise_NK_25519_ChaChaPoly_SHA256") (32 bytes, zero-padded).
  let t := zero Guest.Noise.h 4 t
  let t := store64 Guest.Noise.h 0x4b4e5f6573696f4e t
  let t := store64 (Guest.Noise.h+8) 0x435f39313535325f t
  let t := store64 (Guest.Noise.h+16) 0x6c6f506168436168 t
  let t := store64 (Guest.Noise.h+24) 0x3635324148535f79 t
  let t := copy Guest.Noise.h Guest.Noise.ck 32 t
  -- prologue = ASCII LT-OnionChannel-v1 || descriptorSHA256.
  let t := zero Guest.Noise.concat 8 t
  let t := store64 Guest.Noise.concat 0x6e6f696e4f2d544c t
  let t := store64 (Guest.Noise.concat+8) 0x2d6c656e6e616843 t
  let t := store8 (Guest.Noise.concat+16) 118 t
  let t := store8 (Guest.Noise.concat+17) 49 t
  let t := copy descriptor (Guest.Noise.concat+18) 32 t
  -- mixHash aliases concat, so stage the prologue in binding first.
  let t := copy Guest.Noise.concat Guest.Noise.binding 50 t
  let t := Guest.Noise.mixHash Guest.Noise.binding 50 t
  let t := Guest.Noise.mixHash Guest.Noise.remoteKey 32 t
  let t := zero Guest.Noise.publicKey 4 t
  let t := store8 Guest.Noise.publicKey 9 t
  let t := Guest.Noise25519.x25519 Guest.Noise.privateKey Guest.Noise.publicKey Guest.Noise.publicKey t
  let t := zero (Guest.Noise.state+16) 2 t
  let t := store64 Guest.Noise.state role t
  store64 (Guest.Noise.state+8) 1 t

def mixDH (privateKey publicKey t : UInt64) : UInt64 :=
  let t := Guest.Noise25519.x25519 privateKey publicKey Guest.Noise.concat t
  if Guest.Noise.nonzero Guest.Noise.concat 32 0 t == 0 then error
  else Guest.Noise.mixKey Guest.Noise.concat 32 t

def writeFirst (out t : UInt64) : UInt64 :=
  if load64 Guest.Noise.state t != 1 || load64 (Guest.Noise.state+8) t != 1 then error else
  let t := copy Guest.Noise.publicKey out 32 t
  let t := Guest.Noise.mixHash Guest.Noise.publicKey 32 t
  let t := mixDH Guest.Noise.privateKey Guest.Noise.remoteKey t
  if t == error then error else
  store64 (Guest.Noise.state+8) 2 (Guest.Noise.emptySeal (out+32) t)

def readFirst (input t : UInt64) : UInt64 :=
  if load64 Guest.Noise.state t != 2 || load64 (Guest.Noise.state+8) t != 1 then error else
  let t := copy input Guest.Noise.remoteKey 32 t
  let t := Guest.Noise.mixHash input 32 t
  let t := mixDH Guest.Noise.psk Guest.Noise.remoteKey t
  if t == error then error else
  let t := Guest.Noise.emptyOpen (input+32) t
  if t == error then error else store64 (Guest.Noise.state+8) 2 t

def writeSecond (out t : UInt64) : UInt64 :=
  if load64 Guest.Noise.state t != 2 || load64 (Guest.Noise.state+8) t != 2 then error else
  let t := copy Guest.Noise.publicKey out 32 t
  let t := Guest.Noise.mixHash Guest.Noise.publicKey 32 t
  let t := mixDH Guest.Noise.privateKey Guest.Noise.remoteKey t
  if t == error then error else Guest.Noise.split (Guest.Noise.emptySeal (out+32) t)

def readSecond (input t : UInt64) : UInt64 :=
  if load64 Guest.Noise.state t != 1 || load64 (Guest.Noise.state+8) t != 2 then error else
  let t := copy input Guest.Noise.remoteKey 32 t
  let t := Guest.Noise.mixHash input 32 t
  let t := mixDH Guest.Noise.privateKey Guest.Noise.remoteKey t
  if t == error then error else
  let t := Guest.Noise.emptyOpen (input+32) t
  if t == error then error else Guest.Noise.split t
end Guest.NoiseNK
