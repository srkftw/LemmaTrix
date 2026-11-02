"""Compiled authenticated END/ACK and cancellation-race state checks.

Published deterministic fixture keys exercise three actual cell layers locally;
this is not evidence of independent routed guests or deployed Tor compatibility.
"""
import argparse, hashlib, json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'tools'), str(ROOT / 'tests')]
import live_build, onion_crypto as native
from network_crypto import store_bytes


def source():
    keys = [hashlib.shake_256(f'Campaign010 END fixture hop {i}'.encode()).digest(92) for i in range(3)]
    text = b'a response already accepted before local cancellation'
    padding = hashlib.shake_256(b'Campaign010 END fixture padding').digest(509)
    s = '''import Guest.TorRouter
set_option maxRecDepth 10000
namespace build.Campaign010TerminalSwitching
open Guest Guest.LiveSDK
-- The sender has three separate hop contexts, mirroring the client's layers.
def remoteHop (i : UInt64) : UInt64 := 0x7b0000+i*4096
def emit (command stream data n t : UInt64) : UInt64 :=
  let t := Guest.TorCells.prepare Guest.TorRouter.body command stream data n 0x7a1000 t
  let t := Guest.TorCells.originate (remoteHop 2) 0x7a4000 1 Guest.TorRouter.body t
  let t := Guest.TorCells.cryptLayer (remoteHop 1) 1 Guest.TorRouter.body t
  let t := Guest.TorCells.cryptLayer (remoteHop 0) 1 Guest.TorRouter.body t
  Guest.TorRouter.clientPeel 0 3 t
def check (t : UInt64) : UInt64 :=
  let t := zero Guest.TorRouter.state 8192 t
  let t := store64 Guest.TorRouter.state 1 (store64 (Guest.TorRouter.state+8) 1
    (store64 (Guest.TorRouter.state+24) 3 (store64 (Guest.TorRouter.state+144) 1
    (store64 (Guest.TorRouter.state+152) 17 (store64 (Guest.TorRouter.state+160) 17 t)))))
'''
    for i, key in enumerate(keys):
        s += store_bytes(0x7a2000 + i * 256, key) + '\n'
        s += f'  let t := Guest.TorCells.init (Guest.TorRouter.hop {i}) 0x7a4000 {0x7a2000 + i * 256} t\n'
        s += f'  let t := Guest.TorCells.init (remoteHop {i}) 0x7a4000 {0x7a2000 + i * 256} t\n'
    s += store_bytes(0x7a0000, text) + '\n' + store_bytes(0x7a1000, padding) + '\n'
    s += '''  -- Bind the same selected endpoint stream before ending. These are
  -- public fixture inputs; no application or process authority is fabricated.
  let t := Guest.TorCells.prepare Guest.TorRouter.body 1 17 0x7a0000 0 0x7a1000 t
  let t := Guest.TorCells.selectStream (Guest.TorRouter.hop 2) Guest.TorRouter.body t
  let t := Guest.TorCells.selectStream (remoteHop 2) Guest.TorRouter.body t
  let t := emit 4 17 0x7a0000 0 t
  if !Guest.TorRouter.enabled t || load64 (Guest.TorRouter.state+112) t != 0 ||
    load64 (Guest.TorRouter.state+144) t != 1 then 1 else
'''
    s += f'  let t := emit 2 17 0x7a0000 {len(text)} t\n'
    s += '''  if !Guest.TorRouter.enabled t || load64 (Guest.TorRouter.state+80) t != 0 ||
    load64 (Guest.TorCells.deliverWindow (Guest.TorRouter.hop 2) 1) t != 999 ||
    load64 (Guest.TorCells.received (Guest.TorRouter.hop 2) 1) t != 1 then 2 else
  let t := store8 0x7a0000 6 t
  let t := emit 3 17 0x7a0000 1 t
  if !Guest.TorRouter.enabled t || load64 (Guest.TorRouter.state+144) t != 2 ||
    load64 (Guest.TorRouter.state+168) t != 6 ||
    load64 (Guest.TorCells.streamId (Guest.TorRouter.hop 2)) t != 0 ||
    load64 (Guest.TorCells.deliverWindow (Guest.TorRouter.hop 2) 1) t != 999 ||
    load64 (Guest.TorCells.count (Guest.TorRouter.hop 2) 1) t != 3 ||
    load64 (Guest.TorCells.received (Guest.TorRouter.hop 2) 1) t != 1 then 3 else
  -- Retirement erases only per-stream state. New streams reuse ongoing hop
  -- crypto/circuit windows, with fresh IDs and unchanged finite route totals.
  let t := Guest.TorCells.retireStream (remoteHop 2) 17 t
  if t == error then 4 else
  let t := store64 (Guest.TorRouter.state+144) 0 (store64 (Guest.TorRouter.state+152) 18 t)
  let t := emit 4 18 0x7a0000 0 t
  if !Guest.TorRouter.enabled t || load64 (Guest.TorRouter.state+112) t != 1 ||
    load64 (Guest.TorCells.count (Guest.TorRouter.hop 2) 1) t != 4 ||
    load64 (Guest.TorCells.streamDeliver (Guest.TorRouter.hop 2) 1) t != 500 then 5 else
  -- Busy is an authenticated END for the selected pending BEGIN, not a new
  -- route, key reset, or refresh of lifetime DATA credit.
  let t := Guest.TorCells.retireStream (remoteHop 2) 18 t
  let t := Guest.TorCells.retireStream (Guest.TorRouter.hop 2) 18 t
  let t := store64 (Guest.TorRouter.state+112) 0 (store64 (Guest.TorRouter.state+152) 19 t)
  let t := store8 0x7a0000 4 t
  let t := emit 3 19 0x7a0000 1 t
  if !Guest.TorRouter.enabled t || load64 (Guest.TorRouter.state+144) t != 3 ||
    load64 (Guest.TorRouter.state+168) t != 4 ||
    load64 (Guest.TorCells.count (Guest.TorRouter.hop 2) 1) t != 5 ||
    load64 (Guest.TorCells.deliverWindow (Guest.TorRouter.hop 2) 1) t != 999 then 6 else
  let r := Guest.TorCells.retireStream (Guest.TorRouter.hop 2) 18 t
  if r != error then 7 else
  -- An existing immutable output cell retains the exact pending END instead
  -- of spending a digest/cipher state that cannot yet be queued.
  let t := store64 (Guest.TorRouter.channel 5) 4 (store64 (Guest.TorRouter.channel 5+48) 532
    (store64 (Guest.TorCells.count (Guest.TorRouter.hop 5) 1) 42 t))
  let t := Guest.TorRouter.relayEnd 5 23 4 t
  if t == error || load64 (Guest.TorRouter.circuit 5+56) t != 4 ||
    load64 (Guest.TorRouter.circuit 5+64) t != 23 ||
    load64 (Guest.TorCells.count (Guest.TorRouter.hop 5) 1) t != 42 then 8 else 0
end build.Campaign010TerminalSwitching
'''
    return s


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--backend', action='append', choices=('qemu', 'x86_64', 'aarch64'))
    args = p.parse_args()
    live_build.compile_module('Guest.TorRouter')
    native.B = ROOT / 'build/campaign010-terminal-switching'
    binary = native.build(source(), 'Campaign010TerminalSwitching')
    record = dict(schema=1, image_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                  checks=[native.execute(binary, b) for b in args.backend or ['qemu']],
                  behavior=['authenticated CONNECTED and DATA drain during exact-stream cancellation',
                            'authenticated END acknowledgement releases only its stream',
                            'fresh stream preserves ongoing crypto counters and circuit windows',
                            'authenticated terminal busy preserves the existing route',
                            'wrong-stream retirement is refused',
                            'pending immutable output retains exact END without spending cipher state'],
                  limits='Locally linked three-hop fixture with published deterministic keys; no live peer enrollment, remote terminal, or independent network administration claim.')
    (native.B / 'execution.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    main()
