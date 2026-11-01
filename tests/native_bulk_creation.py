"""Focused native bulk creation failure/retry and per-context deadline controls.

Only this fixture image is compiled. Production Guest modules must already be
fresh. Provisioned predicate inputs do not claim native certificate admission.
"""
import argparse
import hashlib
import json
from pathlib import Path
import socket
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'tools'), str(ROOT/'tests')]
import onion_crypto as native
from transport import HEADER, MAGIC, MultiplexStream

SOURCE = '''import Guest.Network
namespace build.NativeBulkCreation
open Guest Guest.LiveSDK
def incoming (op epoch reason t : UInt64) : UInt64 :=
 let t := store64 Guest.Transport.input (Guest.Transport.magic ||| (op <<< 32) ||| ((12 : UInt64) <<< 40)) t
 Guest.Transport.event (store64 (Guest.Transport.input+8) (epoch ||| (reason <<< 32)) t)
def seed (t : UInt64) : UInt64 :=
 let t := zero Guest.Network.control 64 (zero Guest.Network.st 64
  (zero Guest.Noise.state 52 (zero Guest.Transport.st 4096 t)))
 let own := Guest.NodeEnrollment.localNode
 let peer := Guest.NodeEnrollment.peer 0
 let stamp := Guest.PeerDescription.st
 let d := Guest.PeerDescription.description
 let t := zero own 68 (zero peer 68 (zero stamp 16 t))
 let t := store64 Guest.Transport.st 1 (store64 own 1 (store64 peer 1
  (store64 stamp 2 (store64 (stamp+8) 1 t))))
 let t := store64 (Guest.Network.control+128) 1 (store64 (Guest.Network.st+8) 1
  (store64 Guest.Network.st 1000 t))
 let t := store64 (Guest.Network.st+128) 2 (store64 (d+16) 7 (store64 (d+24) 3
  (store64 (d+160) 4 (store64 (d+168) 0x41424344 t))))
 let g := Guest.Network.grantAt 0
 let t := store64 g 1 (store64 (g+8) 17 (store64 (g+16) 33
  (store64 (g+32) 4096 (store64 (g+40) 512 (store64 (g+48) 1024
  (store64 (g+56) 2000000 (store64 (g+64) 1000 (store64 (g+72) 128 t))))))))
 let t := store64 (Guest.Network.jobAt 0) 1 (store64 (Guest.Network.jobAt 1) 3
  (store64 (Guest.Network.inbox 0) 17 t))
 let t := store64 (Guest.Transport.channel 13) 99 (store64 (Guest.Transport.channel 13+8) 1 t)
 Guest.Transport.choose 12 t
def grantUnchanged (t : UInt64) : Bool :=
 let g := Guest.Network.grantAt 0
 load64 g t == 1 && load64 (g+8) t == 17 && load64 (g+16) t == 33 &&
 load64 (g+32) t == 4096 && load64 (g+40) t == 512 && load64 (g+48) t == 1024 &&
 load64 (g+56) t == 2000000 && load64 (g+64) t == 1000 && load64 (g+72) t == 128
@[noinline] def check (t : UInt64) : UInt64 :=
 let t := seed t
 -- Bank1 owns a different pending deadline, budget and job; save/load must
 -- include the new152nd state byte without leaking it across contexts.
 let t := store64 (Guest.Network.st+144) 777
  (store64 (Guest.Network.grantAt 0+40) 777 (store64 (Guest.Network.jobAt 0) 2 t))
 let t := Guest.Network.saveContext 1 t
 let t := store64 (Guest.Network.st+144) 0
  (store64 (Guest.Network.grantAt 0+40) 512 (store64 (Guest.Network.jobAt 0) 1 t))
 let t := Guest.Network.saveContext 0 t
 let t := Guest.Network.loadContext 0 t
 let p := Guest.Transport.channel 12
 let t := store64 p 7 (store64 (p+24) 1 t)
 -- Replacement cleanup is distinguishable from async CONNECT failure.
 let t := incoming 5 8 0 t
 if load64 (p+24) t != 1 then 1 else
 let t := incoming 9 8 0 t
 if load64 (p+24) t != 2 then 2 else
 let t := incoming 5 9 111 t
 if load64 (p+24) t != 0 || load64 (p+16) t != 111 || load64 (p+8) t != 0 then 3 else
 let t := Guest.Network.reconnectBulk t
 if load64 (Guest.Network.st+136) t != 1 || load64 (p+24) t != 1 ||
  ((load64 Guest.Transport.output t >>> 40) &&& 255) != 12 || !grantUnchanged t then 4 else
 -- Declared adapter-output completion: the immutable command was consumed.
 let t := store64 (Guest.Transport.st+16) 0 t
 let t := incoming 5 8 111 t
 if load64 (p+24) t != 1 then 5 else
 let t := Guest.Network.maintainBulkCreation t
 if load64 (Guest.Network.st+144) t != 101000 then 6 else
 let t := Guest.Network.maintainBulkCreation (store64 Guest.Network.st 1001 t)
 if load64 (Guest.Network.st+144) t != 101000 then 7 else
 let t := Guest.Network.maintainBulkCreation (store64 Guest.Network.st 101000 t)
 if load64 (Guest.Network.st+144) t != 0 || load64 (Guest.Network.st+80) t != 10 ||
  load64 (p+24) t != 0 || load64 (p+48) t != 1 || !grantUnchanged t ||
  load64 (Guest.Network.jobAt 0) t != 5 || load64 (Guest.Network.jobAt 1) t != 3 ||
  load64 (Guest.Network.inbox 0) t != 0 || Guest.Network.session t != 0 then 8 else
 if load64 (Guest.Transport.channel 13) t != 99 ||
  load64 (Guest.Transport.channel 13+8) t != 1 then 9 else
 let t := Guest.Network.saveContext 0 t
 let t := Guest.Network.loadContext 1 t
 if load64 (Guest.Network.st+144) t != 777 || load64 (Guest.Network.grantAt 0+40) t != 777 ||
  load64 (Guest.Network.jobAt 0) t != 2 then 10 else
 let t := Guest.Network.loadContext 0 t
 if load64 (Guest.Network.st+144) t != 0 || !grantUnchanged t then 11 else
 -- Pending CLOSE prevents reconnect until that exact channel is drained.
 let t := Guest.Network.reconnectBulk (store64 Guest.Network.st 101020 t)
 if load64 (Guest.Network.st+136) t != 1 then 12 else
 let t := Guest.Transport.pendingClose 0 t
 if ((load64 Guest.Transport.output t >>> 32) &&& 255) != 3 ||
  ((load64 Guest.Transport.output t >>> 40) &&& 255) != 12 || load64 (p+48) t != 0 then 13 else
 let t := Guest.Network.reconnectBulk (store64 (Guest.Transport.st+16) 0 t)
 if load64 (Guest.Network.st+136) t != 2 || load64 (p+24) t != 1 || !grantUnchanged t then 14 else
 let t := Guest.Network.maintainBulkCreation t
 if load64 (Guest.Network.st+144) t != 201020 then 15 else
 -- Acknowledged idle LISTEN has no creation expiry, even after its old
 -- deadline. A fresh connected event also clears the creation deadline.
 let t := incoming 9 9 0 t
 let t := Guest.Network.maintainBulkCreation (store64 Guest.Network.st 900000 t)
 if load64 (Guest.Network.st+144) t != 0 || load64 (p+24) t != 2 ||
  load64 (p+48) t != 0 || !grantUnchanged t then 16 else
 let t := incoming 8 10 1008 t
 let t := Guest.Network.maintainBulkCreation (store64 (Guest.Network.st+144) 1 t)
 if load64 (Guest.Network.st+144) t != 0 || load64 (p+8) t != 1 then 17 else
 -- Pure link loss preserves finite grant bytes/expiry; neither counter32
 -- nor expired authority can be revived by this recovery path.
 let t := incoming 5 11 104 t
 let t := Guest.Network.disconnect 10 t
 if !grantUnchanged t then 18 else
 let t := store64 (Guest.Transport.st+16) 0 (store64 (Guest.Network.st+136) 32 t)
 let t := Guest.Network.reconnectBulk (store64 Guest.Network.st 900020 t)
 if load64 (Guest.Network.st+136) t != 32 || load64 (Guest.Transport.st+16) t != 0 then 19 else
 if Guest.Network.findGrant 17 33 0 (store64 Guest.Network.st 2000000 t) != error then 20 else
 -- Revoked peer authority prevents both reconnect and allowance retention.
 let t := store64 (Guest.NodeEnrollment.peer 0) 0 (store64 (Guest.Network.st+136) 31 t)
 let t := Guest.Network.reconnectBulk t
 if load64 (Guest.Network.st+136) t != 31 || load64 (Guest.Transport.st+16) t != 0 then 21 else
 let t := Guest.Network.disconnect 10 t
 if load64 (Guest.Network.grantAt 0) t != 0 then 22 else
 let t := Guest.Network.disconnect 16 (store64 (Guest.Network.grantAt 0) 1
  (store64 (Guest.NodeEnrollment.peer 0) 1 t))
 if load64 (Guest.Network.grantAt 0) t != 0 then 23 else
 let t := Guest.Network.loadContext 1 t
 if load64 (Guest.Network.st+144) t != 777 || load64 (Guest.Network.grantAt 0+40) t != 777 ||
  load64 (Guest.Network.jobAt 0) t != 2 || load64 (Guest.Transport.channel 13+8) t != 1 then 24 else 0
end build.NativeBulkCreation
'''


def adapter_failure():
    adapter = MultiplexStream();adapter.start()
    guest = adapter.guest;guest.settimeout(5);pending = bytearray()
    # Bound but not listening: Linux accepts the nonblocking command and then
    # reports ECONNREFUSED through the async completion path.
    refused = socket.socket();refused.bind(('127.0.0.1', 0))
    endpoint = f'127.0.0.1:{refused.getsockname()[1]}'.encode()
    try:
        guest.sendall(HEADER.pack(MAGIC, 1, 12, len(endpoint), 0, 1008)+endpoint)
        while len(pending) < 16:pending.extend(guest.recv(4096))
        row = HEADER.unpack_from(pending)
        assert row[1] == 5 and row[2] == 12 and row[5] != 0, row
        return dict(op=row[1], slot=row[2], epoch=row[4], errno=row[5],
                    endpoint_class='localhost bound non-listening opaque byte adapter fixture')
    finally:
        refused.close();adapter.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--backend', action='append', choices=('qemu', 'aarch64', 'x86_64'))
    args = parser.parse_args()
    out = args.output.resolve();out.mkdir(parents=True, exist_ok=False)
    for name in ('Primitives', 'AES', 'SHA1', 'SHA3', 'Noise25519', 'Transport', 'Network'):
        path = ROOT/f'Guest/{name}.lean';olean = path.with_suffix('.olean')
        assert olean.exists() and olean.stat().st_mtime >= path.stat().st_mtime, ('production dependency build not authorized', name)
    before = {str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (ROOT/'Guest').glob('*.olean')}
    adapter = adapter_failure()
    native.B = out;binary = native.build(SOURCE, 'NativeBulkCreation')
    report = dict(schema=1, result='pass', adapter=adapter,
                  image_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                  fixture_source_sha256=hashlib.sha256(SOURCE.encode()).hexdigest(),
                  production_source_sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()
                                            for p in (ROOT/'Guest/Transport.lean',ROOT/'Guest/Network.lean')},
                  checks=[native.execute(binary, backend) for backend in args.backend or ('qemu', 'aarch64')],
                  boundaries=['real adapter failed asynchronous CONNECT emits5 with nonzero errno',
                              'cleanup5(0) preserves intent; failure5(errno) clears it and permits finite native reconnect',
                              'pending creation deadline arms once and expires only its selected channel; pending CLOSE blocks premature retry',
                              'late ACK2 and connected state clear creation deadline; healthy idle listener does not expire',
                              '152-byte bank preserves independent creation deadlines, grants, jobs and unrelated transport channel',
                              'pure link loss preserves exact consumed grant bytes/rate/expiry and fails only active local jobs; expired or revoked authority cannot revive;32 attempts remain finite'],
                  limits='Actual opaque adapter failure plus compiled RV64 Transport.event/Network.reconnectBulk/maintainBulkCreation state transitions. Native Feed peer predicates are provisioned with public sentinel inputs, not admitted certificates; output completion is explicitly modeled. No complete kernel/socket handshake, cryptographic authentication, installed Feed restart, or current-community recovery claim. AArch64 assembly emulator runs under qemu-aarch64.')
    after = {str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (ROOT/'Guest').glob('*.olean')}
    assert before == after, 'fixture unexpectedly recompiled production Guest modules'
    report['production_olean_files_unchanged'] = len(before)
    (out/'evidence.json').write_text(json.dumps(report, indent=2)+'\n');print(json.dumps(report, indent=2))


if __name__ == '__main__':main()
