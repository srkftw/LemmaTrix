"""Compiled native Delivery cache reuse and explicit failed-fetch retry checks.

This fixture supplies opaque terminal-reply bytes to the real native decoder.
It covers coordinator state transitions, not routed delivery or AEAD/session
assurance. No production actor, backing, operational key or mailbox is edited.
"""
import argparse,hashlib,json,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import driver
from structured_runtime import BOOT
B=ROOT/'build/native-messenger-delivery'
SOURCE='''import Guest.MessengerDelivery
namespace build.NativeMessengerDelivery
open Guest Guest.LiveSDK Guest.MessengerDelivery
def idA : UInt64 := 0x7a0000
def idB : UInt64 := 0x7a0040
-- The fixture trap is a rejected/current-token oracle, not the live kernel.
-- It counts foreign calls so a passive scheduling hint cannot hide admission.
def calls : UInt64 := 0x7a0080
def attachmentCommand (h index contact fresh t : UInt64) : UInt64 :=
  let t := zero command 128 t
  store64 command 460 (store64 (command+8) h (store64 (command+16) index
    (store64 (command+24) 1 (store64 (command+32) contact (store64 (command+48) 2
      (store64 (command+56) 1 (store64 (command+64) fresh t)))))))
def reconciliationHintChecks (t : UInt64) : UInt64 :=
  let t := zero st 64 (zero attachment 32 (zero parked 256 (zero calls 4 t)))
  let t := store64 st 77 (store64 (st+152) 1 (store64 (st+24) 7
    (store64 (st+112) 11 (store64 (st+88) 123 (store64 (calls+16) 1 t)))))
  let t := store64 attachment 7 (store64 (attachment+8) 77 (store64 (attachment+16) 55
    (store64 (attachment+24) 1 (store64 (attachment+40) 14 (store64 (attachment+64) 11 t)))))
  let t := store64 ciphertext 0xaabb (store64 commitment 0xccdd (store64 requestId 0xeeff t))
  let r := dispatch 55 799 1012 72 (attachmentCommand 77 13 1 1 t)
  if status r != 6 || !attachmentHintMatches 55 77 13 1 1 r ||
    load64 (st+88) r != 123 || load64 attachment r != 7 || load64 (st+24) r != 7 ||
    load64 calls r != 1 || load64 (calls+8) r != 131 then 76 else
  let r := dispatch 55 799 1013 72 (store64 (attachmentHint+48) 9 r)
  if status r != 6 || load64 (attachmentHint+48) r != 9 then 77 else
  let t := store64 (st+88) 0 (store64 (calls+16) 1 (zero calls 4 r))
  let t := receiveQuantum t
  if load64 calls t != 0 || load64 (st+88) t != 0 || !attachmentWaiting t then 78 else
  let r := dispatch 55 799 1014 72 t
  if status r != 0 || load64 attachmentHint r != 0 || load64 attachment r != 3 ||
    load64 (st+24) r != 2 || load64 (st+224) r != 1 || load64 calls r != 1 ||
    load64 (calls+8) r != 131 || load64 ciphertext r != 0xaabb ||
    load64 commitment r != 0xccdd || load64 requestId r != 0xeeff then 79 else
  let t := store64 attachment 7 (store64 (st+24) 7 (store64 (st+88) 123 r))
  let t := attachmentHintQuantum (store64 (attachmentHint+48) 8191
    (deferAttachment 55 77 13 1 1 t))
  let r := dispatch 55 799 1015 72 t
  if status r != 14 || load64 attachmentHint r != 0 || load64 attachment r != 7 ||
    load64 (st+88) r != 123 || load64 (st+24) r != 7 then 80 else
  let r := dispatch 55 799 1016 72 (attachmentCommand 77 14 1 1 r)
  if status r != 12 || load64 attachmentHint r != 0 then 81 else 0
def reconciliationChecks (t : UInt64) : UInt64 :=
  let t := zero st 64 (zero attachment 32 (zero calls 4 t))
  let t := store64 st 77 (store64 (st+24) 7 (store64 (st+112) 11 (store64 (calls+16) 1 t)))
  let t := store64 attachment 7 (store64 (attachment+8) 77 (store64 (attachment+16) 55
    (store64 (attachment+24) 1 (store64 (attachment+40) 14 (store64 (attachment+64) 11 t)))))
  let t := store64 (st+32) 77 (store64 (st+40) 55 (store64 (st+48) 7520
    (store64 (st+56) 32 (store64 (st+64) 1 (store64 (st+72) 555 t)))))
  let t := store64 ciphertext 0xaabb (store64 commitment 0xccdd (store64 requestId 0xeeff (store64 remote 0x1122 t)))
  let r := dispatch 55 799 1005 72 (attachmentCommand 77 13 1 1 t)
  if status r != 0 || load64 (st+224) r != 1 || load64 attachment r != 3 || load64 (st+24) r != 2 ||
    load64 calls r != 1 || load64 (calls+8) r != 131 then 68 else
  if load64 ciphertext r != 0xaabb || load64 commitment r != 0xccdd || load64 requestId r != 0xeeff ||
    load64 remote r != 0x1122 || load64 (st+32) r != 77 || load64 (st+40) r != 55 ||
    load64 (st+48) r != 7520 || load64 (st+56) r != 32 || load64 (st+64) r != 1 || load64 (st+72) r != 555 then 69 else
  let t := store64 attachment 7 (store64 (attachment+64) 9 (store64 (st+24) 7 r))
  let r := dispatch 55 799 1006 72 t
  if status r != 0 || load64 (st+224) r != 0 then 70 else
  let t := store64 attachment 7 (store64 (attachment+64) 1 (store64 (st+24) 7 (store64 (st+224) 1 r)))
  let r := dispatch 55 799 1007 72 t
  if status r != 0 || load64 (st+224) r != 0 then 71 else
  let t := store64 attachment 7 (store64 (attachment+64) 11 (store64 (st+24) 7 (store64 (st+224) 1 r)))
  let r := dispatch 55 799 1008 72 (attachmentCommand 77 13 1 0 t)
  if status r != 0 || load64 (st+224) r != 0 then 72 else
  let t := store64 attachment 7 (store64 (st+24) 7 r)
  let r := dispatch 55 799 1009 72 (attachmentCommand 77 14 1 1 t)
  if status r != 12 || load64 attachment r != 7 || load64 (st+224) r != 0 then 73 else
  let r := dispatch 56 799 1010 72 (attachmentCommand 77 13 1 1 r)
  if status r != 4 || load64 attachment r != 7 || load64 (st+224) r != 0 then 74 else
  let r := dispatch 55 799 1011 72 (store64 (calls+16) 0 r)
  if status r != 1 || load64 attachment r != 7 || load64 (st+224) r != 0 ||
    load64 ciphertext r != 0xaabb || load64 commitment r != 0xccdd || load64 requestId r != 0xeeff ||
    load64 remote r != 0x1122 || load64 (st+72) r != 555 || load64 calls r != 7 then 75 else 0
def hintChecks (t : UInt64) : UInt64 :=
  let t := zero st 64 (zero attachment 32 (zero parked 256 (zero calls 4 t)))
  let t := store64 st 77 (store64 (st+152) 1 (store64 (st+8) 999 (store64 (st+88) 123 t)))
  let t := store64 ciphertext 0xaabb t
  let r := queueAttachment 55 72 (attachmentCommand 77 0 1 1 t)
  if status r != 6 || !attachmentWaiting r || !attachmentHintMatches 55 77 0 1 1 r ||
    load64 (st+8) r != 999 || load64 (st+88) r != 123 || load64 attachment r != 0 ||
    load64 ciphertext r != 0xaabb || load64 calls r != 0 then 40 else
  let r := queueAttachment 55 72 (store64 (attachmentHint+48) 9 r)
  if status r != 6 || load64 (attachmentHint+48) r != 9 then 41 else
  let r := queueAttachment 56 72 r
  if status r != 4 || !attachmentHintMatches 55 77 0 1 1 r then 42 else
  let r := queueAttachment 55 72 (attachmentCommand 78 0 1 1 r)
  if status r != 4 || !attachmentHintMatches 55 77 0 1 1 r then 43 else
  let r := queueAttachment 55 72 (attachmentCommand 77 1 1 1 r)
  if status r != 4 || !attachmentHintMatches 55 77 0 1 1 r then 44 else
  let r := queueAttachment 55 72 (attachmentCommand 77 0 2 1 r)
  if status r != 4 || !attachmentHintMatches 55 77 0 1 1 r then 45 else
  let r := queueAttachment 55 72 (attachmentCommand 77 0 1 0 r)
  if status r != 4 || !attachmentHintMatches 55 77 0 1 1 r then 46 else
  let r := queueAttachment 55 64 (attachmentCommand 77 0 1 1 r)
  if status r != 2 || load64 (attachmentHint+48) r != 9 then 47 else
  let t := attachmentHintQuantum r
  if load64 (attachmentHint+48) t != 10 || load64 (st+8) t != 999 ||
    load64 (st+88) t != 123 || load64 attachment t != 0 || load64 calls t != 0 then 48 else
  if attachmentReceiveAllowed 1 0 0 || !attachmentReceiveAllowed 1 1 0 ||
    !attachmentReceiveAllowed 1 2 0 || !attachmentReceiveAllowed 1 3 0 ||
    !attachmentReceiveAllowed 1 4 0 || !attachmentReceiveAllowed 1 0 123 then 49 else
  let t := store64 (st+8) 0 (store64 (st+88) 0 t)
  let t := receiveQuantum t
  if load64 calls t != 0 || load64 (st+8) t != 0 || load64 (st+88) t != 0 then 50 else
  -- ACK promotion happens before the background suppression gate. The fixture
  -- rejects network readiness; it must still reach ACK phase3 with its row.
  let t := store64 parked 99 (store64 (parked+96) 1 (store64 (st+248) 1 t))
  let t := receiveQuantum t
  if load64 (st+160) t != 3 || load64 (st+304) t != parked || !attachmentWaiting t then 51 else
  let t := zero parked 256 (store64 (st+160) 0 (store64 (st+248) 0 (zero calls 4 t)))
  let t := attachmentHintQuantum (store64 (attachmentHint+48) 8191 t)
  if load64 attachmentHint t != 2 || load64 (attachmentHint+48) t != 8192 ||
    !attachmentReceiveAllowed 2 0 0 || load64 calls t != 0 then 52 else
  let r := queueAttachment 55 72 (attachmentCommand 77 0 1 1 t)
  if status r != 14 || load64 attachmentHint r != 0 || load64 calls r != 0 then 53 else
  let t := store64 (st+88) 123 (deferAttachment 55 77 0 1 1 r)
  let t := attachmentHintQuantum (store64 (attachmentHint+48) 8191 t)
  let r := queueAttachment 56 72 (attachmentCommand 88 0 2 1 t)
  if status r != 6 || !attachmentHintMatches 56 88 0 2 1 r || load64 (attachmentHint+48) r != 0 then 54 else
  let t := zero calls 4 (store64 (st+88) 0 r)
  -- A saved hint never runs itself. The next actual native dispatch checks131
  -- again; rejected authority leaves the hint and owner request untouched.
  let r := dispatch 56 799 999 72 t
  if status r != 1 || load64 calls r != 1 || load64 (calls+8) r != 131 ||
    !attachmentHintMatches 56 88 0 2 1 r || load64 attachment r != 0 then 55 else
  let t := store64 (calls+16) 1 (zero calls 4 r)
  let r := dispatch 56 799 1000 72 t
  if status r != 14 || load64 attachmentHint r != 0 || load64 calls r != 2 ||
    load64 (calls+8) r != 128 then 56 else
  let t := deferAttachment 55 77 0 1 1 r
  let t := failSend 14 t
  if load64 attachmentHint t != 0 then 57 else
  let t := failReceive 9 (deferAttachment 55 77 0 1 1 t)
  if load64 attachmentHint t != 0 then 58 else
  let t := zero st 64 (zero attachment 32 (zero parked 256 (zero calls 4 t)))
  let t := store64 st 77 (store64 (st+152) 1 (store64 (st+8) 999 (store64 (st+88) 123 (store64 (calls+16) 1 t))))
  let t := store64 command 462 (attachmentCommand 77 0 1 1 (deferAttachment 55 77 0 1 1 t))
  let r := dispatch 56 799 1001 64 t
  if status r != 3 || !attachmentWaiting r || load64 (st+8) r != 999 || load64 (st+88) r != 123 then 59 else
  let r := dispatch 55 799 1002 64 r
  if status r != 3 || load64 attachmentHint r != 0 || load64 (st+8) r != 999 || load64 (st+88) r != 123 then 60 else
  let t := store64 (st+8) 0 (store64 (st+88) 0 (deferAttachment 55 77 0 1 1 r))
  let t := receiveQuantum (store64 (st+160) 1 (store64 (st+248) 1 t))
  if load64 (st+160) t != 1 || !attachmentWaiting t then 61 else
  let t := receiveQuantum (store64 (st+160) 2 (zero calls 4 t))
  if load64 (st+160) t != 2 || !attachmentWaiting t || load64 calls t != 0 then 62 else
  let t := receiveQuantum (store64 (st+160) 4 (store64 (st+248) 1 t))
  if load64 (st+160) t != 4 || !attachmentWaiting t then 63 else
  let t := receiveQuantum (store64 (st+160) 0 (store64 (st+280) parked (store64 (st+248) 1 t)))
  if load64 (st+280) t != parked || !attachmentWaiting t then 64 else
  let t := zero command 128 (zero calls 4 t)
  let t := store64 command 464 (store64 (command+16) 3 (store64 (command+56) 1 t))
  let t := store64 (st+24) 7 (store64 (st+112) 14 (store64 attachment 7 (store64 (attachment+64) 3
    (store64 (attachmentHint+48) 9 (store64 (st+8) 999 (store64 (st+88) 123 (store64 (calls+16) 1 t)))))))
  let r := dispatch 55 799 1003 64 t
  if status r != 1 || load64 (st+8) r != 999 || load64 (st+88) r != 123 || load64 (st+24) r != 7 then 65 else
  let r := dispatch 55 0x100000000 1004 64 r
  if r != 64 || status r != 0 || load64 (wire+8) r != 7 || load64 (wire+16) r != 14 ||
    load64 (wire+24) r != 7 || load64 (wire+32) r != 3 || load64 (wire+40) r != 1 ||
    load64 (wire+48) r != 9 || load64 (wire+56) r != 1 then 66 else
  if load64 (st+8) r != 999 || load64 (st+88) r != 123 || load64 attachment r != 7 ||
    load64 (attachment+64) r != 3 || load64 (st+112) r != 14 || load64 (attachmentHint+48) r != 9 ||
    load64 calls r != 2 || load64 (calls+8) r != 131 then 67 else
  let result := reconciliationChecks r
  if result != 0 then result else reconciliationHintChecks r
def opaqueReply (h id value t : UInt64) : UInt64 :=
  let t := zero answer 128 t
  let t := store64 (answer+8) h (store64 (answer+16) 112 (store64 (answer+32) 112 t))
  let t := store64 (answer+64) blobMagic (store64 (answer+72) 1 t)
  let t := copy id (answer+80) 32 t
  let t := store64 (answer+120) 1 (store64 (answer+136) 32 t)
  let t := store64 (answer+144) value (store64 (answer+152) value (store64 (answer+160) value (store64 (answer+168) value t)))
  rpcCompleted 10 176 t
def check (t : UInt64) : UInt64 :=
  let t := zero st 64 (zero parked 256 (zero blob 1024 t))
  let t := store64 idA 11 (store64 (idA+8) 12 (store64 (idA+16) 13 (store64 (idA+24) 14 t)))
  let t := store64 idB 21 (store64 (idB+8) 22 (store64 (idB+16) 23 (store64 (idB+24) 24 t)))
  let t := opaqueReply 101 idA 0xaaaa t
  let p := parkFind 101 0 t
  if p == 0 then 1 else
  let r := fetchAttachment 77 0 idA 0 t
  if r != 64 || status r != 6 || load64 (st+280) r != p then 2 else
  let t := opaqueReply 101 idA 0xaaaa r
  let r := fetchAttachment 77 0 idA 0 t
  if r != 96 || status r != 0 || load64 (wire+64) r != 0xaaaa then 3 else
  let t := store64 answer 0 (store64 (st+304) p r)
  let t := rpcCompleted 11 64 t
  if load64 p t != 0 || load64 (st+296) t != 0 || load64 (st+280) t != 0 || !Guest.ProjectGraph.allZero blob 8192 t then 4 else
  let t := opaqueReply 102 idB 0xbbbb t
  let q := parkFind 102 0 t
  if q != p then 5 else
  let r := fetchAttachment 88 0 idB 0 t
  if status r != 6 || load64 (st+280) r != p then 6 else
  let t := opaqueReply 102 idB 0xbbbb r
  let r := fetchAttachment 88 0 idB 0 t
  if r != 96 || status r != 0 || load64 (wire+64) r != 0xbbbb then 7 else
  -- Matching recycled row addresses never authorize a different transfer ID.
  let t := copy idA (blob+16) 32 r
  let r := fetchAttachment 88 0 idB 0 t
  if status r != 6 || load64 (st+296) r != 0 || !Guest.ProjectGraph.allZero blob 8192 r then 8 else
  let t := store64 (st+152) 1 (store64 (st+96) 10 r)
  let t := rpcFailure 14 t
  let r := fetchAttachment 77 0 idA 0 t
  if status r != 14 || load64 (st+160) r != 7 then 17 else
  let r := fetchAttachment 77 0 idA 1 r
  if status r != 14 || load64 (st+160) r != 7 then 18 else
  let r := fetchAttachment 88 0 idB 0 r
  if status r != 14 || load64 (st+160) r != 7 || load64 (p+112) r != 0 then 9 else
  let r := fetchAttachment 88 0 idB 1 r
  if status r != 6 || load64 (st+160) r != 0 || load64 (st+200) r != 0 || load64 (p+112) r != 1 || load64 (p+96) r != 0 then 10 else
  let t := opaqueReply 102 idB 0xbbbb r
  let r := fetchAttachment 88 0 idB 0 t
  if r != 96 || status r != 0 || load64 (wire+64) r != 0xbbbb then 11 else
  let t := failReceive 1 (store64 (st+96) 10 r)
  let r := fetchAttachment 88 0 idB 1 t
  if status r != 14 || load64 (st+160) r != 7 || load64 (p+112) r != 1 then 12 else
  let t := failReceive 9 r
  let r := fetchAttachment 88 0 idB 1 t
  if status r != 14 || load64 (st+160) r != 7 then 13 else
  let t := failReceive 14 (store64 (st+96) 11 r)
  let r := fetchAttachment 88 0 idB 1 t
  if status r != 14 || load64 (st+160) r != 7 then 14 else
  let t := failReceive 14 (store64 (st+96) 10 (store64 (p+112) 3 r))
  let r := fetchAttachment 88 0 idB 1 t
  if status r != 14 || load64 (p+112) r != 3 then 15 else
  let t := store64 answer 0 (store64 (answer+16) 2 (store64 (st+304) p r))
  let t := rpcCompleted 12 64 t
  if load64 p t != 0 || load64 (st+296) t != 0 || !Guest.ProjectGraph.allZero blob 8192 t then 16 else
  let t := Guest.ForgeRouted.init (zero foreground 20 (zero st 64 t))
  let t := store64 st 77 (store64 (st+152) 1 (store64 (st+8) 999 (store64 (st+88) 123 t)))
  let t := copy idA (command+64) 32 (copy idB (command+96) 32 (store64 (command+128) 1 t))
  -- An older successful inspector must never masquerade as this queued request.
  let t := store64 Guest.ForgeRouted.st 3 t
  let r := queueForge 55 t
  if r != 128 || status r != 0 || result r != 6 || !forgePending r ||
    load64 (st+8) r != 999 || load64 (st+88) r != 123 then 17 else
  let r := queueForge 55 (store64 (foreground+16) 9 r)
  if r != 128 || status r != 0 || result r != 6 || load64 (foreground+16) r != 9 then 18 else
  let r := queueForge 56 r
  if status r != 6 || load64 (foreground+8) r != 55 then 19 else
  let r := queueForge 55 (store64 (command+128) 2 r)
  if status r != 6 || load64 (foreground+88) r != 1 then 20 else
  let t := store64 Guest.ForgeRouted.st 0 (store64 (foreground+16) 8192 r)
  let t := queuedForgeQuantum t
  if forgePending t || Guest.ForgeRouted.phase t != 4 || load64 (Guest.ForgeRouted.st+24) t != 14 ||
    load64 (foreground+96) t != 55 || load64 (st+8) t != 999 || load64 (st+88) t != 123 then 21 else
  if requestCallerAllowed 0 55 || requestCallerAllowed 55 56 || !requestCallerAllowed 55 55 then 22 else
  -- A cached acceptance is scoped to the original approved contact, even when
  -- the local handle, caller and exact ciphertext are reused.
  let t := zero st 64 (zero command 128 t)
  let t := store64 st 77 (store64 (st+24) 11 (store64 (st+32) 123 (store64 (st+40) 55 (store64 (st+48) 8 (store64 (st+64) 1 t)))))
  let t := store64 (command+8) 123 (store64 (command+16) 8 (store64 (command+24) 1 (store64 (command+32) 1 (store64 (command+96) 0x12345678 t))))
  let t := hash (command+96) 8 commitment t
  let t := copy commitment (command+64) 32 t
  let r := queue 55 104 t
  if status r != 0 || load64 (wire+16) r != 2 then 23 else
  let r := queue 55 104 (store64 (command+32) 2 r)
  if status r != 12 || load64 (st+64) r != 1 || load64 (st+24) r != 11 then 24 else hintChecks r
end build.NativeMessengerDelivery
'''

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--backend',action='append',choices=('qemu','x86_64','aarch64'));a=p.parse_args()
 B.mkdir(parents=True,exist_ok=True);source=ROOT/'build/NativeMessengerDelivery.lean';source.write_text(SOURCE)
 for name in ('MessengerDelivery',):driver.lean(['-o',ROOT/f'Guest/{name}.olean',ROOT/f'Guest/{name}.lean'])
 driver.lean(['-o',source.with_suffix('.olean'),source]);assembly=B/'check.S'
 driver.lean(['--run','Compiler/Main.lean','build.NativeMessengerDelivery',assembly,'build.NativeMessengerDelivery.check'])
 boot=BOOT.replace('lt_Examples_StructuredConsumer_check','lt_build_NativeMessengerDelivery_check').replace(' li t1,0x40000cf',' li t1,0x201000cf\n sd t1,24(t0)\n li t1,0x40000cf')
 # VA7a0080 maps to PA805a0080 in this fixture's2MiB leaf. The trap rejects
 # every foreign operation except an explicitly toggled current-token check.
 boot=boot.replace(' la t0,fatal',' la t0,fixtureTrap')+'''
fixtureTrap:
 csrr t0,mcause
 li t1,9
 bne t0,t1,fatal
 li t0,0x805a0080
 ld t1,0(t0)
 addi t1,t1,1
 sd t1,0(t0)
 sd a7,8(t0)
 li a0,-1
 li t1,131
 bne a7,t1,fixtureReturn
 ld t1,16(t0)
 beqz t1,fixtureReturn
 li a0,0
fixtureReturn:
 csrr t0,mepc
 addi t0,t0,4
 csrw mepc,t0
 mret
'''
 boot=boot.replace(' call lt_finish\nfatal:', ' beqz a0,okay\n slli t4,a0,16\n li t0,0x100000\n li t1,0x3333\n or t1,t1,t4\n sw t1,0(t0)\n1: j 1b\nokay:\n call lt_finish\nfatal:')
 (B/'boot.S').write_text(boot);objects=[]
 for i,path in enumerate((assembly,B/'boot.S',ROOT/'runtime/primitives.S')):
  obj=B/f'{i}.o';driver.asm(path,obj);objects.append(obj)
 elf=B/'check.elf';binary=B/'check.bin';driver.run([driver.tool('ld.lld'),'-m','elf64lriscv','--no-relax','-T',ROOT/'runtime/kernel.ld',*objects,'-o',elf]);driver.run([driver.tool('llvm-objcopy'),'-O','binary',elf,binary]);checks=[]
 for backend in a.backend or('qemu',):
  if backend=='qemu':command=[driver.tool('qemu-system-riscv64'),'-M','virt','-cpu','rv64','-m','64M','-smp','1','-bios','none','-nographic','-monitor','none','-kernel',binary]
  else:
   obj=B/(backend+'.o');exe=B/('lt-'+backend);driver.asm(ROOT/f'emulator/{backend}.S',obj,backend+'-linux-gnu');driver.run([driver.tool('ld.lld'),'-static','-e','_start',obj,'-o',exe]);command=([driver.tool('qemu-aarch64')]if backend=='aarch64'else[])+[exe,binary,'--interactive']
  began=time.monotonic();result=subprocess.run(list(map(str,command)),capture_output=True,timeout=120)
  if result.returncode:raise RuntimeError((backend,result.returncode,result.stdout.hex(),result.stderr.decode()))
  checks.append(dict(backend=backend,result='pass',seconds=time.monotonic()-began))
 report=dict(schema=1,result='pass',checks=checks,image_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),image_bytes=binary.stat().st_size,
  boundaries=['native decoder parks and refetches first opaque blob','actual immediate and polled ACK completion clear resident cache','second transfer reuses freed row without stale ciphertext','resident access rechecks random transfer identity','failed fetch including unknown blob stays unavailable until eligible explicit retry','explicit unavailable-fetch retry resumes selected blob only','authorization integrity ACK failures and exhausted retry budget remain failed','foreground Forge admission preserves in-flight work and returns queued phase instead of stale success','exact queued foreground retry preserves its bound and different callers or references conflict','bounded foreground admission failure preserves unrelated admitted RPC tokens','cached exact-ciphertext acceptance rejects a changed contact without replacing its original state'],
  limits='Direct compiled coordinator-transition fixture with opaque reply bytes. A bounded guest trap supplies rejected/current-token syscall131 results and rejects owner endpoint/network admission; it checks native dispatch revalidation and counts attempted foreign calls, not live kernel grant semantics. No real route, mailbox durability or AEAD/session claim. ARM backend, when selected, is emulated.')
 report['boundaries']+=['bounded immutable attachment scheduling hint preserves admitted RPC and Owner tokens','exact repeat does not renew the8192work bound and conflicting caller or reference cannot replace it','new background phase0fetch yields while partial fetch, Owner commit, ACK and selected fetch remain eligible','ACK promotion occurs before the suppression gate','passive hint quantum performs no Owner or Network admission','expiry returns native unavailable on the next exact real request and releases scheduling priority','a distinct valid caller can replace expired intent without a deadcaller blockade','next native460dispatch rechecks131 and owner endpoint before admission; revoked current-token result never executes saved intent','send and receive failure clear passive intent','exact caller and handle cancellation clears only the passive hint while normal cancellation semantics continue','actual partial receive and ACK-poll phases remain eligible while Owner-commit phase remains untouched','selected incoming fetch bypasses the background-only suppression gate','readonly administrator464action3 rejects ordinary rights and exposes only the eight scalar state words while preserving tokens and state','failed attachment reconciliation also reserves bounded receive-free admission; exact retry cannot renew it, drain preserves ciphertext and expiry stays unavailable','explicit missing-receipt reconciliation flag is admitted only for reason11 and keeps exact ciphertext request commitment caps handle and index','integrity or authorization failures and unconfirmed retries force strict fresh0; changedcaller index and rejected current-token checks cannot admit reconciliation']
 (B/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
