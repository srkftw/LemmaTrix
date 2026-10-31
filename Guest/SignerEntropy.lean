import Guest.Primitives
namespace Guest.SignerEntropy
-- Supervisor-only seed transfer. Kernel130 checks both the registered signer
-- instance and the exact32-byte,8-byte-aligned destination extent before this call.
-- Four explicit loads avoid generic copy frames retaining seed words. The
-- freestanding compiler erases this namespace's fixed frames and temporary/
-- argument registers on return; a0 is the zero effect token. The caller clears
-- the DMA buffer on both success and failure and never exports seed bytes.
def copy32 (input output t : UInt64) : UInt64 :=
  let t := store64 output (load64 input t) t
  let t := store64 (output+8) (load64 (input+8) t) t
  let t := store64 (output+16) (load64 (input+16) t) t
  store64 (output+24) (load64 (input+24) t) t
end Guest.SignerEntropy
