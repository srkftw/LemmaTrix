"""Focused compiled RV64 ownership/reclamation checks; no binary-assurance claim."""
import argparse, hashlib, json, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import driver, live_build, onion_crypto as native
SOURCE='''import Guest.Network
import Guest.Mailbox
namespace build.NativeSharedContexts
open Guest Guest.LiveSDK
@[noinline] def terminalLimitChecks (t : UInt64) : UInt64 :=
  let t := zero Guest.TorRouter.state 8192 (zero Guest.Transport.st 4096 t)
  let t := store64 Guest.TorRouter.state 1 (store64 (Guest.TorRouter.state+8) 2 t)
  let t := store64 (Guest.TorRouter.channel 0) 4 (store64 (Guest.TorRouter.channel 1) 4
    (store64 (Guest.TorRouter.channel 2) 4 (store64 (Guest.TorRouter.channel 3) 4 t)))
  let t := store64 (Guest.TorRouter.circuit 0) 1 (store64 (Guest.TorRouter.circuit 0+16) 1
    (store64 (Guest.TorRouter.circuit 1) 4 (store64 (Guest.TorRouter.circuit 1+40) 0
    (store64 (Guest.TorRouter.circuit 2) 1 (store64 (Guest.TorRouter.circuit 2+16) 3
    (store64 (Guest.TorRouter.circuit 3) 4 (store64 (Guest.TorRouter.circuit 3+40) 2 t)))))))
  -- A terminal output is charged after another pair was the scheduler cursor.
  -- Exhaustion must tear down the charged pair, not that unrelated cursor.
  let t := store64 (Guest.TorRouter.state+72) 2 t
  let t := store64 (Guest.TorRouter.channel 0+112) 10 (store64 (Guest.TorRouter.channel 0+128) 10 t)
  let t := Guest.TorRouter.queueTerminal 0 17 Guest.OnionTerminal.sealed 1 t
  if load64 (Guest.TorRouter.channel 0) t != 0 || load64 (Guest.TorRouter.channel 1) t != 0 ||
    load64 (Guest.TorRouter.channel 2) t != 4 || load64 (Guest.TorRouter.channel 3) t != 4 then 36 else
  let t := zero Guest.OnionTerminal.control 64 (zero Guest.OnionTerminal.st 4096 t)
  let t := zero 0x770000 8192 t
  let t := store64 (Guest.TorRouter.channel 0) 4 (zero (Guest.TorRouter.circuit 0) 16 t)
  let t := store64 Guest.OnionTerminal.st 2 (store64 (Guest.OnionTerminal.st+32) 0
    (store64 (Guest.OnionTerminal.st+176) 123 (store64 (Guest.OnionTerminal.control+16) 9 t)))
  let t := store64 (Guest.OnionTerminal.st+48) 960 (store64 (Guest.OnionTerminal.st+56) 400
    (store64 (Guest.OnionTerminal.st+184) 99 t))
  let t := store64 Guest.OnionTerminal.noiseBank 0xaa (store64 Guest.OnionTerminal.received 0xbb
    (store64 Guest.OnionTerminal.outgoing 0xcc (store64 (Guest.OnionTerminal.bank 0+512) 0xdd t)))
  let t := store64 (Guest.OnionTerminal.bank 1) 2 (store64 (Guest.OnionTerminal.bank 1+24) 18
    (store64 (Guest.OnionTerminal.bank 1+32) 2 (store64 (Guest.OnionTerminal.bank 1+168) 9
    (store64 (Guest.OnionTerminal.bank 1+176) 456 (store64 (Guest.OnionTerminal.bank 1+512) 0xee t)))))
  let t := store64 (Guest.OnionTerminal.control+32) 456 t
  let t := Guest.OnionTerminal.expireWork 100 t
  if load64 Guest.OnionTerminal.st t != 0 || load64 (Guest.TorRouter.channel 0) t != 0 ||
    load64 (Guest.TorRouter.channel 2) t != 4 || load64 Guest.OnionTerminal.noiseBank t != 0 ||
    load64 Guest.OnionTerminal.received t != 0 || load64 Guest.OnionTerminal.outgoing t != 0 ||
    load64 (Guest.OnionTerminal.bank 0+512) t != 0 || load64 (Guest.OnionTerminal.bank 1+512) t != 0xee ||
    load64 (Guest.OnionTerminal.control+32) t != 456 || load64 (Guest.OnionTerminal.control+16) t != 9 then 37 else
  let t := store64 (Guest.TorRouter.channel 0) 4 (zero (Guest.TorRouter.circuit 0) 16 t)
  let t := store64 Guest.OnionTerminal.st 2 (store64 (Guest.OnionTerminal.st+32) 0
    (store64 (Guest.OnionTerminal.st+176) 123 (store64 (Guest.OnionTerminal.st+112) 77
    (store64 (Guest.OnionTerminal.st+152) 99 (store64 (Guest.OnionTerminal.control+32) 123 t)))))
  let t := Guest.OnionTerminal.expireWork 100 t
  if load64 0x718200 t != 77 || load64 Guest.OnionTerminal.st t != 0 ||
    load64 (Guest.OnionTerminal.control+32) t != 0 || load64 (Guest.TorRouter.channel 0) t != 0 ||
    load64 (Guest.TorRouter.channel 2) t != 4 || load64 (Guest.OnionTerminal.bank 1+512) t != 0xee then 38 else
  -- Healthy idle relationships are reusable, even after old deadline values.
  let t := store64 Guest.OnionTerminal.st 2 (store64 (Guest.OnionTerminal.st+8) 3 (store64 (Guest.OnionTerminal.st+32) 2
    (store64 (Guest.OnionTerminal.st+152) 0 (store64 (Guest.OnionTerminal.st+184) 0 t))))
  let t := Guest.OnionTerminal.expireWork 100 t
  if load64 Guest.OnionTerminal.st t != 2 || load64 (Guest.TorRouter.channel 2) t != 4 ||
    Guest.OnionTerminal.workDeadline 0xffffffffffffffff 100000 != 0xffffffffffffffff then 39 else
  -- An expired old bank cannot close a channel that was reused at a new epoch.
  let t := store64 (Guest.OnionTerminal.st+48) 960 (store64 (Guest.OnionTerminal.st+56) 400
    (store64 (Guest.OnionTerminal.st+184) 99 (store64 (Guest.OnionTerminal.st+168) 7
    (store64 (Guest.TorRouter.channel 2+24) 9 t))))
  let t := Guest.OnionTerminal.expireWork 100 t
  if load64 Guest.OnionTerminal.st t != 0 || load64 (Guest.TorRouter.channel 2) t != 4 then 40 else
  -- Full requests waiting behind another IPC retain their own absolute bound.
  let t := store64 Guest.OnionTerminal.st 2 (store64 (Guest.OnionTerminal.st+32) 0
    (store64 (Guest.OnionTerminal.st+48) 64 (store64 (Guest.OnionTerminal.st+56) 64
    (store64 (Guest.OnionTerminal.st+240) 99 (store64 (Guest.OnionTerminal.control+32) 456 t)))))
  let t := Guest.OnionTerminal.expireWork 100 t
  if load64 Guest.OnionTerminal.st t != 0 || load64 (Guest.OnionTerminal.control+32) t != 456 then 41 else
  -- A half-open handshake is finite; healthy authenticated idle is not.
  let t := store64 Guest.OnionTerminal.st 2 (store64 (Guest.OnionTerminal.st+8) 1
    (store64 (Guest.OnionTerminal.st+32) 0 (store64 (Guest.OnionTerminal.st+224) 99 t)))
  let t := Guest.OnionTerminal.expireWork 100 t
  if load64 Guest.OnionTerminal.st t != 0 then 42 else 0
@[noinline] def primaryPinChecks (t : UInt64) : UInt64 :=
  let t := zero Guest.TorRouter.state 8192 (zero Guest.Transport.st 4096
    (zero Guest.OnionTerminal.control 64 (zero Guest.OnionTerminal.st 4096 (zero 0x770000 8192 t))))
  let t := store64 Guest.TorRouter.state 1 (store64 (Guest.TorRouter.state+8) 2 t)
  let t := store64 (Guest.TorRouter.channel 0) 4 (store64 (Guest.TorRouter.channel 1) 4
    (store64 (Guest.TorRouter.channel 2) 4 (store64 (Guest.TorRouter.channel 3) 4 t)))
  let t := store64 (Guest.TorRouter.channel 0+24) 7 (store64 (Guest.TorRouter.channel 2+24) 9 t)
  let t := store64 (Guest.TorRouter.circuit 0) 1 (store64 (Guest.TorRouter.circuit 0+16) 1
    (store64 (Guest.TorRouter.circuit 2) 1 (store64 (Guest.TorRouter.circuit 2+16) 3 t)))
  let t := store64 Guest.OnionTerminal.st 2 (store64 (Guest.OnionTerminal.st+8) 3
    (store64 (Guest.OnionTerminal.st+32) 0 (store64 (Guest.OnionTerminal.st+168) 7
    (store64 (Guest.OnionTerminal.st+176) 123 t))))
  let t := store64 (Guest.OnionTerminal.st+248) 555 t
  let t := store64 Guest.OnionTerminal.noiseBank 0xaa t
  let t := Guest.OnionTerminal.selectContext 1 t
  let t := store64 Guest.OnionTerminal.st 2 (store64 (Guest.OnionTerminal.st+8) 3
    (store64 (Guest.OnionTerminal.st+32) 2 (store64 (Guest.OnionTerminal.st+168) 9
    (store64 (Guest.OnionTerminal.st+176) 456 t))))
  -- An unrelated Registry-style bank has no primary pin; its exact target is
  -- separately selected in control48. Neither changes with this primary app.
  let t := store64 (Guest.OnionTerminal.st+248) 0 (store64 (Guest.OnionTerminal.control+48) 999 t)
  let t := store64 Guest.OnionTerminal.noiseBank 0xee t
  let t := Guest.OnionTerminal.selectContext 0 t
  if load64 (Guest.OnionTerminal.st+248) t != 555 || load64 (Guest.OnionTerminal.bank 1+248) t != 0 then 43 else
  -- The fixture supplies only the result of128. Actual kernel binding and
  -- process-replacement enforcement are exercised by the installed probe.
  let t := store64 0x718208 777 (store64 0x718210 0 t)
  let t := store64 (Guest.NodeEnrollment.localNode+208) 8 t
  let t := store64 (Guest.OnionTerminal.st+48) 64 (store64 (Guest.OnionTerminal.st+56) 64 t)
  let t := store64 Guest.OnionTerminal.received 441 (store64 (Guest.OnionTerminal.received+56) 1 t)
  let t := Guest.OnionTerminal.serverQuantum t
  if load64 0x718210 t != 0 || load64 Guest.OnionTerminal.st t != 0 ||
    load64 (Guest.OnionTerminal.st+160) t != 25 || load64 (Guest.TorRouter.channel 0) t != 0 ||
    load64 (Guest.TorRouter.channel 1) t != 0 || load64 (Guest.TorRouter.channel 2) t != 4 ||
    load64 (Guest.OnionTerminal.bank 0+248) t != 0 || load64 (Guest.OnionTerminal.bank 1+512) t != 0xee ||
    load64 (Guest.OnionTerminal.control+48) t != 999 then 44 else
  -- A saved primary pin cannot close a channel reused by a newer epoch.
  let t := store64 Guest.OnionTerminal.st 2 (store64 (Guest.OnionTerminal.st+32) 0
    (store64 (Guest.OnionTerminal.st+168) 7 (store64 (Guest.OnionTerminal.st+176) 123
    (store64 (Guest.OnionTerminal.st+248) 555 t))))
  let t := store64 (Guest.TorRouter.channel 0) 4 (store64 (Guest.TorRouter.channel 0+24) 11
    (store64 (Guest.OnionTerminal.control+32) 456 t))
  let t := Guest.OnionTerminal.retireOwned 25 t
  if load64 Guest.OnionTerminal.st t != 0 || load64 (Guest.TorRouter.channel 0) t != 4 ||
    load64 (Guest.OnionTerminal.control+32) t != 456 || load64 (Guest.OnionTerminal.bank 1+512) t != 0xee then 45 else
  0
@[noinline] def bulkChecks (t : UInt64) : UInt64 :=
  let t := zero Guest.Network.control 512 (zero Guest.Network.st 64
    (zero Guest.Noise.state 52 (zero Guest.Transport.st 4096 t)))
  let t := store64 (Guest.Network.st+136) 31 t
  let t := Guest.Network.saveContext 0 t
  let t := store64 (Guest.Network.st+136) 7 t
  let t := Guest.Network.saveContext 1 t
  let t := Guest.Network.loadContext 0 t
  if load64 (Guest.Network.st+136) t != 31 then 15 else
  let t := Guest.Network.loadContext 1 t
  if load64 (Guest.Network.st+136) t != 7 then 16 else
  let own := Guest.NodeEnrollment.localNode
  let peer := Guest.NodeEnrollment.peer 0
  let stamp := Guest.PeerDescription.st
  let d := Guest.PeerDescription.description
  let t := zero own 68 (zero peer 68 (zero stamp 16 t))
  let t := store64 Guest.Transport.st 1 (store64 own 1 (store64 peer 1
    (store64 stamp 2 (store64 (stamp+8) 1 t))))
  let t := store64 (Guest.Network.control+128) 1 (store64 (Guest.Network.st+8) 2
    (store64 (Guest.Network.st+136) 0 (store64 Guest.Network.st 1000 t)))
  let t := store64 (Guest.Network.st+128) 2 (store64 (d+16) 7 (store64 (d+24) 3
    (store64 (d+160) 4 (store64 (d+168) 0x41424344 t))))
  let t := Guest.Network.reconnectBulk t
  if load64 (Guest.Network.st+136) t != 1 || load64 (Guest.Network.st+88) t != 1200 ||
    load64 (Guest.Transport.channel 13+24) t != 1 ||
    ((load64 Guest.Transport.output t >>> 40) &&& 255) != 13 then 17 else
  let t := Guest.Network.reconnectBulk (store64 Guest.Network.st 1300 t)
  if load64 (Guest.Network.st+136) t != 1 then 18 else
  let held := load64 Guest.Transport.output t
  let t := Guest.Network.connectSelected true t
  if status t != 0 || load64 (Guest.Network.st+136) t != 0 ||
    load64 Guest.Transport.output t != held || load64 (Guest.Transport.channel 13+24) t != 1 then 26 else
  let t := Guest.Network.connectSelected false (store64 (Guest.Network.st+136) 7 t)
  if status t != 0 || load64 (Guest.Network.st+136) t != 7 || load64 Guest.Transport.output t != held then 27 else
  let t := store64 (Guest.Transport.channel 13+24) 0 (store64 (Guest.Transport.st+16) 0
    (store64 (Guest.Network.st+136) 32 t))
  let t := Guest.Network.reconnectBulk t
  if load64 (Guest.Network.st+136) t != 32 || load64 (Guest.Transport.st+16) t != 0 then 19 else
  let g := Guest.Network.grantAt 0
  let j := Guest.Network.jobAt 0
  let t := store64 g 1 (store64 (g+8) 17 (store64 (g+16) 33
    (store64 (g+32) 4096 (store64 (g+40) 512 (store64 (g+56) 1500 t)))))
  let t := store64 j 1 (store64 (Guest.Network.inbox 0) 17 t)
  let t := Guest.Network.disconnect 10 t
  if load64 g t != 1 || load64 (g+40) t != 512 || load64 (g+56) t != 1500 ||
    load64 j t != 5 || load64 (Guest.Network.inbox 0) t != 0 || Guest.Network.session t != 0 then 21 else
  if Guest.Network.findGrant 17 33 0 (store64 Guest.Network.st 1600 t) != error then 22 else
  let t := store64 (own+512) 99 (store64 (Guest.Network.st+136) 31 t)
  let t := Guest.Network.reconnectBulk t
  if load64 (Guest.Network.st+136) t != 31 || load64 (Guest.Transport.st+16) t != 0 then 20 else
  let t := Guest.Network.disconnect 10 t
  if load64 g t != 0 then 23 else
  let t := Guest.Network.disconnect 16 (store64 g 1 (store64 (own+512) 0 t))
  if load64 g t != 0 then 24 else 0
@[noinline] def contextChecks (t : UInt64) : UInt64 :=
  let t := zero Guest.TorRouter.state 8192 (zero Guest.Transport.st 4096 t)
  -- An idle listener can outlive its old setup deadline. Only acceptance
  -- starts that new client's finite window; neither outbound nor repeated
  -- in-progress checks can extend an admitted handshake.
  let p := Guest.TorRouter.channel 4
  let t := store64 p 1 (store64 (p+8) 2 (store64 (p+88) 1 (store64 (p+160) 500000 t)))
  let t := Guest.TorRouter.acceptedWindow 4 t
  if load64 (p+88) t != 600000 then 28 else
  let t := Guest.TorRouter.acceptedWindow 4 (store64 p 2 (store64 (p+160) 700000 t))
  if load64 (p+88) t != 600000 then 29 else
  let t := Guest.TorRouter.acceptedWindow 4 (store64 p 1 (store64 (p+8) 1 (store64 (p+88) 77 t)))
  if load64 (p+88) t != 77 then 30 else
  let t := store64 Guest.TorRouter.state 1 (store64 (Guest.TorRouter.state+8) 2 t)
  let t := store64 (Guest.TorRouter.state+72) 0 t
  let t := store64 (Guest.TorRouter.channel 0) 4 (store64 (Guest.TorRouter.channel 1) 4
    (store64 (Guest.TorRouter.channel 2) 4 (store64 (Guest.TorRouter.channel 3) 4 t)))
  let t := store64 (Guest.TorRouter.circuit 0) 1 (store64 (Guest.TorRouter.circuit 0+16) 1
    (store64 (Guest.TorRouter.circuit 1) 4 (store64 (Guest.TorRouter.circuit 1+40) 0 t)))
  let t := store64 (Guest.TorRouter.circuit 2) 1 (store64 (Guest.TorRouter.circuit 2+16) 3
    (store64 (Guest.TorRouter.circuit 3) 4 (store64 (Guest.TorRouter.circuit 3+40) 2 t)))
  let t := Guest.TorRouter.abort 34 t
  if !Guest.TorRouter.enabled t || load64 (Guest.TorRouter.channel 0) t != 0 ||
    load64 (Guest.TorRouter.channel 1) t != 0 || load64 (Guest.TorRouter.channel 2) t != 4 ||
    load64 (Guest.TorRouter.channel 3) t != 4 then 1 else
  if load64 (Guest.Transport.channel 0+48) t != 1 || load64 (Guest.Transport.channel 1+48) t != 1 ||
    load64 (Guest.Transport.channel 2+48) t != 0 then 2 else
  let t := zero Guest.OnionTerminal.control 64 (zero Guest.OnionTerminal.st 4096 t)
  let t := zero 0x770000 8192 t
  let t := store64 Guest.OnionTerminal.st 2 (store64 (Guest.OnionTerminal.st+24) 17
    (store64 (Guest.OnionTerminal.st+32) 2 (store64 (Guest.OnionTerminal.st+168) 7
      (store64 (Guest.OnionTerminal.st+176) 123 t))))
  let t := store64 Guest.OnionTerminal.noiseBank 0xaa
    (store64 Guest.OnionTerminal.received 0xbb (store64 Guest.OnionTerminal.outgoing 0xcc t))
  let t := Guest.OnionTerminal.selectContext 1 t
  let t := store64 Guest.OnionTerminal.st 2 (store64 (Guest.OnionTerminal.st+24) 18
    (store64 (Guest.OnionTerminal.st+32) 3 (store64 (Guest.OnionTerminal.st+168) 9
      (store64 (Guest.OnionTerminal.st+176) 456 t))))
  let t := store64 Guest.OnionTerminal.noiseBank 0xdd
    (store64 Guest.OnionTerminal.received 0xee (store64 Guest.OnionTerminal.outgoing 0xff t))
  if Guest.OnionTerminal.findContext 2 17 7 0 t != 0 ||
    Guest.OnionTerminal.findContext 2 17 8 0 t != error ||
    Guest.OnionTerminal.findContext 3 18 9 0 t != 1 then 3 else
  let t := Guest.OnionTerminal.selectContext 0 t
  if load64 Guest.OnionTerminal.noiseBank t != 0xaa || load64 Guest.OnionTerminal.received t != 0xbb ||
    load64 Guest.OnionTerminal.outgoing t != 0xcc || load64 (Guest.OnionTerminal.st+176) t != 123 then 4 else
  let t := store64 (Guest.OnionTerminal.control+16) 9 t
  let t := Guest.OnionTerminal.clearAll t
  if load64 (Guest.OnionTerminal.control+16) t != 9 then 14 else
  let t := zero Guest.MailboxReceipt.st 512 (zero Guest.Mailbox.st 64 (zero 0x750000 6144 t))
  let t := store64 (Guest.Mailbox.st+48) 77 (store64 (Guest.Mailbox.st+56) 100
    (store64 (Guest.Mailbox.st+336) 123 (store64 Guest.Mailbox.staged 0xaabb t)))
  let t := Guest.Mailbox.selectStage 1 t
  let t := store64 (Guest.Mailbox.st+48) 77 (store64 (Guest.Mailbox.st+56) 101
    (store64 (Guest.Mailbox.st+336) 456 (store64 Guest.Mailbox.staged 0xccdd t)))
  if Guest.Mailbox.findStage 77 123 100 0 t != 0 || Guest.Mailbox.findStage 77 456 101 0 t != 1 ||
    Guest.Mailbox.findStage 77 456 100 0 t != error then 5 else
  let t := Guest.Mailbox.selectStage 0 (store64 (command+48) 456 t)
  if Guest.Mailbox.ownsStage 77 t then 6 else
  let t := store64 (command+48) 123 t
  if !Guest.Mailbox.ownsStage 77 t || Guest.Mailbox.ownsStage 88 t || load64 Guest.Mailbox.staged t != 0xaabb then 7 else
  let t := Guest.Mailbox.selectStage 1 t
  if load64 Guest.Mailbox.staged t != 0xccdd then 81 else
  if load64 Guest.MailboxReceipt.st t != 0 then 82 else
  if load64 (Guest.MailboxReceipt.st+8) t != 0 then 83 else
  let t := Guest.MailboxReceipt.pump t
  if Guest.Mailbox.findStage 77 123 100 0 t != 0 then 13 else
  let t := zero Guest.Transport.st 4096 t
  let t := Guest.Transport.queue 3 15 1 0 Guest.Transport.input 0 t
  if t == error || (load64 Guest.Transport.output t &&& 0xffffffff) != 0x334d544c then 9 else
  if Guest.Transport.queue 3 16 1 0 Guest.Transport.input 0 t != error then 10 else
  let t := zero Guest.TorRouter.state 8192 t
  let t := store64 Guest.TorRouter.state 1 (store64 (Guest.TorRouter.state+8) 2
    (store64 (Guest.TorRouter.state+120) 1 t))
  let t := store64 (Guest.NodeEnrollment.localNode+208) 7 t
  let t := store64 (Guest.TorRouter.channel 0) 4 (store64 (Guest.TorRouter.channel 1) 4
    (store64 (Guest.TorRouter.channel 2) 4 (store64 (Guest.TorRouter.channel 3) 4
    (store64 (Guest.TorRouter.channel 4) 4 (store64 (Guest.TorRouter.channel 5) 4
    (store64 (Guest.TorRouter.channel 6) 4 (store64 (Guest.TorRouter.channel 7) 4
    (store64 (Guest.TorRouter.channel 8) 4 (store64 (Guest.TorRouter.channel 9) 4
    (store64 (Guest.TorRouter.channel 10) 4 (store64 (Guest.TorRouter.channel 11) 4 t)))))))))))
  let t := Guest.TorRouter.replenish t
  if Guest.TorRouter.freeChannel 0 t != error || !Guest.TorRouter.enabled t then 11 else
  let t := Guest.TorRouter.retireChannel 10 t
  let t := Guest.TorRouter.replenish t
  if Guest.TorRouter.freeChannel 0 t != 10 || load64 (Guest.TorRouter.channel 9) t != 4 then 12 else
  let t := Guest.TorRouter.retireChannel 11 t
  let t := store64 Guest.NodeEnrollment.localNode 1 t
  let t := Guest.TorRouter.replenish t
  if load64 (Guest.TorRouter.channel 10) t != 1 || Guest.TorRouter.freeChannel 0 t != 11 ||
    load64 (Guest.TorRouter.channel 9) t != 4 then 25 else
  let t := store64 (Guest.TorRouter.channel 10+144) 0 t
  let t := store64 Guest.Transport.input (Guest.Transport.magic ||| ((6 : UInt64) <<< 32) ||| ((10 : UInt64) <<< 40))
    (store64 (Guest.Transport.input+8) ((98 : UInt64) <<< 32) t)
  let t := Guest.Transport.event t
  if load64 (Guest.Transport.channel 10+1104) t != 6 || !Guest.TorRouter.listenerLost 10 t then 31 else
  let t := Guest.TorRouter.listenerFailure 10 1000000 t
  if load64 (Guest.TorRouter.channel 10) t != 0 || load64 (Guest.TorRouter.channel 9) t != 4 ||
    load64 (Guest.TorRouter.state+128) t != 1 || load64 (Guest.TorRouter.state+136) t != 1000200 then 32 else
  let t := Guest.TorRouter.replenish t
  if load64 (Guest.TorRouter.channel 10) t != 0 then 33 else
  let t := Guest.TorRouter.replenish (store64 (Guest.TorRouter.state+128) 32 t)
  if load64 (Guest.TorRouter.channel 10) t != 0 then 34 else
  let t := Guest.TorRouter.dispatch 30 10 64 t
  if load64 (Guest.TorRouter.state+128) t != 0 || load64 (Guest.TorRouter.state+136) t != 0 ||
    load64 (Guest.TorRouter.channel 10) t != 1 || load64 (Guest.TorRouter.channel 9) t != 4 then 35 else
  0
def check (t : UInt64) : UInt64 :=
  let checked := terminalLimitChecks t
  if checked != 0 then checked else
  let checked := primaryPinChecks checked
  if checked != 0 then checked else
  let checked := contextChecks checked
  if checked != 0 then checked else bulkChecks checked
end build.NativeSharedContexts
'''
def main():
 p=argparse.ArgumentParser();p.add_argument('--backend',action='append',choices=('qemu','x86_64','aarch64'));a=p.parse_args()
 native.B=ROOT/'build/native-shared-contexts'
 for module in ('Guest.Network','Guest.Mailbox'):live_build.compile_module(module)
 binary=native.build(SOURCE,'NativeSharedContexts')
 # Replenishing a reclaimed pair creates a real native setup deadline. This
 # bounded oracle supplies monotonic tick100 and records exact IPC cancellation;
 # it is not a kernel cancellation implementation. Other traps fail.
 boot=native.B/'boot.S'
 boot.write_text(boot.read_text().replace(' la t0,fatal',' la t0,fixtureClock')+'''
fixtureClock:
 csrr t0,mcause
 li t1,9
 bne t0,t1,fatal
 li t1,135
 beq a7,t1,fixtureCancel
 li t1,128
 beq a7,t1,fixturePrimary
 li t1,133
 beq a7,t1,fixtureDispatch
 li t1,110
 bne a7,t1,fatal
 li a0,100
 j fixtureReturn
fixtureCancel:
 li t1,0x80518200
 sd a0,0(t1)
 li a0,0
 j fixtureReturn
fixturePrimary:
 li t1,0x80518208
 ld a0,0(t1)
 j fixtureReturn
fixtureDispatch:
 li t1,0x80518210
 ld t2,0(t1)
 addi t2,t2,1
 sd t2,0(t1)
 li a0,-1
fixtureReturn:
 csrr t0,mepc
 addi t0,t0,4
 csrw mepc,t0
 mret
''')
 driver.asm(boot,native.B/'1.o')
 driver.run([driver.tool('ld.lld'),'-m','elf64lriscv','--no-relax','-T',ROOT/'runtime/kernel.ld',*(native.B/f'{i}.o'for i in range(3)),'-o',native.B/'check.elf'])
 driver.run([driver.tool('llvm-objcopy'),'-O','binary',native.B/'check.elf',binary])
 report=dict(schema=1,result='pass',image_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),checks=[native.execute(binary,b) for b in a.backend or ['qemu','aarch64']],boundaries=['saved terminal primary target pins survive context switching; changed target retires only the selected epoch-owned pair before dispatch133, leaving unrelated bank/Registry pin intact; stale epochs cannot close a reused channel','terminal output link quota exhaustion closes the actual charged pair even when another pair was last pumped','partial terminal frames and pending typed IPC expire independently; exact cancellation frees the dispatch lane and wipes only the selected key/buffer snapshot','healthy idle terminal contexts do not expire; deadline addition saturates instead of disabling near clock exhaustion','relay integrity failure closes only dependent incoming/outgoing pair','expired idle listener gets a finite setup window only when accepted; outbound and ongoing handshake deadlines do not renew','failed LISTEN retires only that listener, backs off within32 failures, and explicit operator listen renews its allowance','terminal keys/buffers banked by channel, stream and epoch; stale epoch rejects','mailbox sameNetworkcaller different terminalorigin cannot append or collect foreignstaging','adapterv3 accepts slot15 and rejects slot16','bulk reconnect attempts remain context-private, finite32 and pending admission does not renew them','current native Feed relationship preserves exact used allowance and expiry only on link loss; lost jobs and inbox cleared, expired/pin-changed or explicit-stop grants cannot revive'],limitations='Focused compiled RV64 state transitions, including provisioned predicate inputs for bulk reconnect and a declared128 target-result oracle plus133 dispatch counter; no claim that this oracle implements kernel binding/replacement; no native certificate-admission claim from this fixture. AArch64 assembly emulator runs under qemu-aarch64; no physical hardware or full native Messenger qualification.')
 (native.B/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
