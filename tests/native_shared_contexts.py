"""Focused compiled RV64 ownership/reclamation checks; no binary-assurance claim."""
import argparse, hashlib, json, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tests')]
import driver, live_build, onion_crypto as native
SOURCE='''import Guest.OnionTerminal
import Guest.Mailbox
namespace build.NativeSharedContexts
open Guest Guest.LiveSDK
def check (t : UInt64) : UInt64 :=
  let t := zero Guest.TorRouter.state 8192 (zero Guest.Transport.st 4096 t)
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
  let t := zero Guest.Mailbox.st 64 (zero 0x740000 6144 t)
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
  if load64 Guest.Mailbox.staged t != 0xccdd then 8 else
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
  0
end build.NativeSharedContexts
'''
def main():
 p=argparse.ArgumentParser();p.add_argument('--backend',action='append',choices=('qemu','x86_64','aarch64'));a=p.parse_args()
 native.B=ROOT/'build/native-shared-contexts'
 for module in ('Guest.OnionTerminal','Guest.Mailbox'):live_build.compile_module(module)
 binary=native.build(SOURCE,'NativeSharedContexts')
 report=dict(schema=1,result='pass',image_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),checks=[native.execute(binary,b) for b in a.backend or ['qemu','aarch64']],boundaries=['relay integrity failure closes only dependent incoming/outgoing pair','terminal keys/buffers banked by channel, stream and epoch; stale epoch rejects','mailbox sameNetworkcaller different terminalorigin cannot append or collect foreignstaging','adapterv3 accepts slot15 and rejects slot16'],limitations='Focused compiled RV64 state transitions. AArch64 assembly emulator runs under qemu-aarch64; no physical hardware or full native Messenger qualification.')
 (native.B/'evidence.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
