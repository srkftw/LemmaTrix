"""Compiled native listener reuse controls against real adapter event ordering.

Only the fixture image is compiled. Existing Guest oleans must already match
their sources; production modules and the installed OS image are not rebuilt.
"""
import argparse
import hashlib
import json
from pathlib import Path
import socket
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'tools'), str(ROOT/'tests')]
import driver
import onion_crypto as native
from transport import HEADER, MAGIC, MultiplexStream

SOURCE = '''import Guest.TorRouter
namespace build.NativeListenerReuse
open Guest Guest.LiveSDK
def incoming (op epoch t : UInt64) : UInt64 :=
 let t := store64 Guest.Transport.input (Guest.Transport.magic ||| (op <<< 32)) t
 Guest.Transport.event (store64 (Guest.Transport.input+8) epoch t)
def listener (t : UInt64) : UInt64 :=
 let t := store64 0x718220 100 t
 let t := store64 (Guest.Transport.st+16) 0 (store64 (Guest.Transport.channel 0+48) 0 t)
 let t := Guest.TorRouter.openChannel 0 2 4 t
 Guest.Transport.flush t
def check (t : UInt64) : UInt64 :=
 let t := zero Guest.TorRouter.state 8192 (zero Guest.Transport.st 4096 t)
 let t := store64 Guest.TorRouter.state 1 (store64 (Guest.TorRouter.state+8) 2
  (store64 (Guest.TorRouter.state+120) 1 t))
 let t := store64 Guest.NodeEnrollment.localNode 1 (store64 (Guest.NodeEnrollment.localNode+368) 1
  (store8 (Guest.NodeEnrollment.localNode+376) 120 t))
 let t := store64 (Guest.TorRouter.channel 2) 4 t
 let t := store64 (Guest.Transport.channel 0) 7 t
 let t := listener t
 if load64 (Guest.Transport.channel 0+24) t != 1 then 1 else
 -- Adapter cleanup may be the final complete event in a device quantum.
 let t := incoming 5 8 t
 if load64 (Guest.Transport.channel 0+24) t != 1 || Guest.TorRouter.listenerLost 0 t then 2 else
 let t := Guest.TorRouter.pumpChannel 0 t
 if load64 (Guest.TorRouter.channel 0) t != 1 then 3 else
 let t := incoming 9 8 t
 if load64 (Guest.Transport.channel 0+24) t != 2 then 4 else
 -- A delayed previous acknowledgement can precede another cleanup/new9.
 let t := listener t
 let t := incoming 9 8 t
 let t := incoming 5 9 t
 if load64 (Guest.Transport.channel 0+24) t != 2 then 5 else
 let t := Guest.TorRouter.pumpChannel 0 t
 let t := incoming 9 9 t
 if load64 (Guest.TorRouter.channel 0) t != 1 || load64 (Guest.Transport.channel 0+24) t != 2 then 6 else
 -- Neither older acknowledgements nor any9 after explicit close revives it.
 let t := store64 (Guest.Transport.channel 0+24) 1 t
 let t := incoming 9 8 t
 if load64 (Guest.Transport.channel 0+24) t != 1 then 7 else
 let t := Guest.Transport.close 0 t
 let t := incoming 9 9 t
 if load64 (Guest.Transport.channel 0+24) t != 0 then 8 else
 -- A failed LISTEN clears creation intent and enters finite native backoff.
 let t := listener t
 let t := incoming 6 9 t
 if load64 (Guest.Transport.channel 0+24) t != 0 || !Guest.TorRouter.listenerLost 0 t then 9 else
 let t := Guest.TorRouter.pumpChannel 0 t
 if load64 (Guest.TorRouter.channel 0) t != 0 || load64 (Guest.TorRouter.state+48) t != 58 ||
  load64 (Guest.TorRouter.state+128) t != 1 || load64 (Guest.TorRouter.channel 2) t != 4 then 10 else
 -- Fresh CONNECTED4 and ACCEPTED8 end intent; their later HUP5 is real loss.
 let t := listener t
 let t := incoming 4 10 t
 if load64 (Guest.Transport.channel 0+24) t != 0 || load64 (Guest.Transport.channel 0+8) t != 1 then 11 else
 let t := incoming 5 11 t
 if load64 (Guest.Transport.channel 0+24) t != 0 || load64 (Guest.Transport.channel 0+8) t != 0 then 12 else
 let t := listener t
 let t := incoming 8 12 t
 if load64 (Guest.Transport.channel 0+24) t != 0 || load64 (Guest.Transport.channel 0+8) t != 1 then 13 else
 let t := store64 (Guest.TorRouter.channel 0) 4 t
 let t := incoming 5 13 t
 let t := Guest.TorRouter.pumpChannel 0 t
 if load64 (Guest.TorRouter.channel 0) t != 0 || load64 (Guest.TorRouter.state+48) t != 38 ||
  load64 (Guest.TorRouter.channel 2) t != 4 then 14 else
 -- Pending creation has a deadline; acknowledged idle LISTEN does not.
 let t := listener t
 let t := store64 0x718220 100101 t
 let t := Guest.TorRouter.pumpChannel 0 t
 if load64 (Guest.TorRouter.channel 0) t != 0 || load64 (Guest.TorRouter.state+48) t != 51 then 15 else
 let t := listener t
 let t := incoming 9 13 t
 let t := store64 0x718220 900000 t
 let t := Guest.TorRouter.pumpChannel 0 t
 if load64 (Guest.TorRouter.channel 0) t != 1 || load64 (Guest.Transport.channel 0+24) t != 2 ||
  load64 (Guest.TorRouter.channel 2) t != 4 then 16 else 0
end build.NativeListenerReuse
'''


def adapter_ordering():
    adapter = MultiplexStream();adapter.start()
    guest = adapter.guest;guest.settimeout(3);pending = bytearray()
    def send(op, data=b''):
        guest.sendall(HEADER.pack(MAGIC, op, 0, len(data), 0, 1008)+data)
    def event():
        while len(pending) < 16:pending.extend(guest.recv(4096))
        q = HEADER.unpack_from(pending)
        while len(pending) < 16+q[3]:pending.extend(guest.recv(4096))
        del pending[:16+q[3]]
        return dict(op=q[1], slot=q[2], epoch=q[4], value=q[5])
    probe = socket.socket();probe.bind(('127.0.0.1', 0))
    endpoint = f'127.0.0.1:{probe.getsockname()[1]}'.encode();probe.close()
    try:
        send(2, endpoint);first = event();assert first['op'] == 9
        send(2, endpoint);repeated = [event(), event()]
        send(3);send(2, endpoint);closed = [event(), event()]
        assert [row['op'] for row in repeated] == [5, 9]
        assert [row['op'] for row in closed] == [5, 9]
        return dict(initial=first, repeated_listen=repeated, close_then_listen=closed)
    finally:adapter.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--backend', action='append', choices=('qemu', 'aarch64', 'x86_64'))
    args = parser.parse_args()
    out = args.output.resolve();out.mkdir(parents=True, exist_ok=False)
    adapter = adapter_ordering()
    for name in ('Primitives', 'AES', 'SHA1', 'SHA3', 'Noise25519', 'Transport', 'TorRouter'):
        path = ROOT/f'Guest/{name}.lean';olean = path.with_suffix('.olean')
        assert olean.exists() and olean.stat().st_mtime >= path.stat().st_mtime, ('production dependency build not authorized', name)
    native.B = out;binary = native.build(SOURCE, 'NativeListenerReuse')
    boot = out/'boot.S'
    boot.write_text(boot.read_text().replace(' la t0,fatal', ' la t0,fixtureTrap')+'''
fixtureTrap:
 csrr t0,mcause
 li t1,9
 bne t0,t1,fatal
 li t1,110
 beq a7,t1,fixtureClock
 li t1,103
 bne a7,t1,fatal
 mv a0,a2
 j fixtureReturn
fixtureClock:
 li t1,0x80518220
 ld a0,0(t1)
fixtureReturn:
 csrr t0,mepc
 addi t0,t0,4
 csrw mepc,t0
 mret
''')
    driver.asm(boot, out/'1.o')
    driver.run([driver.tool('ld.lld'), '-m', 'elf64lriscv', '--no-relax', '-T', ROOT/'runtime/kernel.ld',
                *(out/f'{i}.o' for i in range(3)), '-o', out/'check.elf'])
    driver.run([driver.tool('llvm-objcopy'), '-O', 'binary', out/'check.elf', binary])
    report = dict(schema=1, result='pass', adapter=adapter,
                  image_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                  checks=[native.execute(binary, backend) for backend in args.backend or ('qemu', 'aarch64')],
                  boundaries=['cleanup5/new9 and old9/cleanup5/new9 preserve owned listener intent',
                              'older9 and9 after explicit close cannot restore intent',
                              'LISTEN failure6 clears intent and enters scoped bounded backoff',
                              'fresh CONNECTED4/ACCEPTED8 end intent; actual HUP5 retires only its own link',
                              'pending creation expires51; acknowledged healthy idle listener remains available'],
                  limits='Real opaque adapter event order plus compiled RV64 Transport and TorRouter state transitions. Explicit syscall103 completion and110 monotonic-clock oracle; no complete kernel/socket or active-community causal-trace claim. AArch64 assembly emulator runs under qemu-aarch64.')
    (out/'evidence.json').write_text(json.dumps(report, indent=2)+'\n');print(json.dumps(report, indent=2))


if __name__ == '__main__':main()
