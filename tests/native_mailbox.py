"""Execute native mailbox capability, publication, retry and restart boundaries.

This is a mailbox component test. It does not claim routing, X3DH, recipient
decryption, graphical acceptance, physical durability or independent operators.
"""
from __future__ import annotations
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import live
import nodes
import releases
import server_store
import messenger


def words(raw):
    assert len(raw) >= 64, raw.hex()
    return struct.unpack_from('<8Q', raw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--binary', type=Path, default=ROOT / 'build/live/apps/mailbox.bin')
    parser.add_argument('--backend', choices=('qemu', 'x86_64', 'aarch64'), default='qemu')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--iterations', type=int, default=20)
    parser.add_argument('--restore-store', type=Path)
    args = parser.parse_args()
    folder = args.output.resolve()
    folder.mkdir(parents=True, exist_ok=False)
    image = folder / 'guest.bin'
    image.write_bytes(args.image.read_bytes())
    store = folder / 'operator.img'
    if args.restore_store:store.write_bytes(args.restore_store.read_bytes())
    else:server_store.provision(store)
    key = ROOT / 'tests/keys/development-rsa.pem'
    public = ROOT / 'tests/keys/development-rsa-public.pem'
    package, _ = releases.make(args.binary, 'mailbox-component', '1.0.0', 2048,
                               key, profile=2, license='NOASSERTION')
    package_path = folder / 'mailbox.ltrel'
    package_path.write_bytes(package)
    package_info = releases.inspect(package)
    identity = package_info['release_id']
    # Test-only capabilities are NOT node identity/session keys. The native
    # production boundary receives only hashes at operator enrollment.
    recipient = hashlib.sha256(b'mailbox component recipient').digest()
    deposit = hashlib.sha256(b'test-only deposit capability').digest()
    fetch = hashlib.sha256(b'test-only distinct fetch capability').digest()
    namespace = hashlib.sha256(b'explicit native mailbox namespace').digest()
    checks = []
    process = client = log = None
    socket = folder / 'guest.sock'
    service = None

    def check(name):
        checks.append(name)
        print('PASS', name, flush=True)

    def stop():
        nonlocal process, client, log
        if client:
            client.close()
            client = None
        if process and process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(20)
        if log:
            log.close()
        process = log = None
        socket.unlink(missing_ok=True)

    def start():
        nonlocal process, client, log, service
        log = (folder / 'guest.log').open('ab')
        command = [str(ROOT / 'lt'), 'run', '--backend', args.backend,
                   '--image', str(image), '--socket', str(socket), '--server-store', str(store)]
        process = subprocess.Popen(command, cwd=ROOT, stdout=log, stderr=log,
                                   start_new_session=True)
        deadline = time.monotonic() + (360 if args.backend == 'aarch64' else 90)
        while not socket.exists():
            if process.poll() is not None:
                raise RuntimeError((folder / 'guest.log').read_text())
            if time.monotonic() > deadline:
                raise TimeoutError('native mailbox guest startup')
            time.sleep(.05)
        client = live.Client(socket, timeout=600 if args.backend == 'aarch64' else 120)
        service = nodes.start_package(client, nodes.approved_package(
            package_path, public, identity, 2048), package)
        launcher = next(struct.unpack_from('<Q', client.request(2), i)[0]
                        for i in range(0, 384, 32)
                        if struct.unpack_from('<Q', client.request(2), i)[0] & 255 == 1)
        for operation in (440, 441):
            body = (struct.pack('<6Q', 1, 3, service, launcher, operation, 0) +
                    bytes.fromhex(identity) + bytes(48))
            result = struct.unpack('<Q', client.request(171, body))[0]
            assert result != 2**64 - 1
        server_store.call(client, 230)
        grant = server_store.call(client, 231, service, 2, 1048576, namespace)[0][1]
        assert call(440, 0, grant)[0] == 0

    def call(op, action, a=0, b=0, c=0, data=b''):
        if op == 441 and action in (2, 3, 7) or (op == 441 and action == 4 and a != 0):
            data = recipient + deposit + data
        return messenger.invoke(client,3,op,h=action,a=a,b=b,c=c,data=data,allowed_status=tuple(range(15)))[0]

    def raw_call(op, action, a=0, b=0, c=0, data=b''):
        return messenger.invoke(client,3,op,h=action,a=a,b=b,c=c,data=data,allowed_status=tuple(range(15)))

    def published(handle=0):
        deadline = time.monotonic() + (600 if args.backend == 'aarch64' else 120)
        while True:
            response = call(441, 4, handle)
            if response[0] != 6:
                assert response[0] == 0, response
                return response
            if time.monotonic() > deadline:
                raise TimeoutError(('mailbox snapshot publication', response))
            time.sleep(.02)

    def deposit_ciphertext(request, payload, fresh=1):
        commitment = hashlib.sha256(payload).digest()
        authority = recipient + deposit + request + commitment
        admission = call(441, 1, len(payload), fresh, data=authority)
        assert admission[0] == 0, admission
        handle = admission[1]
        denied, _ = raw_call(441, 2, handle, 0, data=recipient+bytes(32)+payload[:512])
        assert denied[0] == 2, denied
        for offset in range(0, len(payload), 512):
            appended = call(441, 2, handle, offset, data=payload[offset:offset+512])
            assert appended[0] == 0, appended
        denied, _ = raw_call(441, 3, handle, data=recipient+bytes(32))
        assert denied[0] == 2, denied
        assert call(441, 3, handle)[0] == 6
        published(handle)
        assert call(441, 1, len(payload), fresh, data=authority)[:3] == (0, handle, len(payload))
        return handle, commitment

    def retrieve(handle, payload):
        recovered = bytearray()
        for offset in range(0, len(payload), 512):
            response, data = raw_call(441, 5, handle, offset, 512, recipient + fetch)
            assert response[0] == 0 and response[1] == handle and response[2] == len(payload), response
            recovered.extend(data)
        assert recovered == payload

    began = time.monotonic()
    try:
        start()
        if args.restore_store:
            # The backing is copied opaquely. Only the native service reads the
            # legacy snapshot and publishes the next versioned snapshot.
            inventory=[call(440,2,i) for i in range(16)]
            assert all(row[0]==0 for row in inventory)
            check('native service recovers the opaque legacy schema1 backing')
            recipient=hashlib.sha256(b'new recipient after native migration').digest()
            enrollment=recipient+hashlib.sha256(deposit).digest()+hashlib.sha256(fetch).digest()
            assert call(440,1,8388608,256,data=enrollment)[0]==6
            published()
            stop();start()
            assert call(440,1,8388608,256,data=enrollment)[0]==0
            payload=hashlib.shake_256(b'native migration exact ciphertext').digest(1031)
            handle,root=deposit_ciphertext(hashlib.sha256(b'migrated request').digest(),payload)
            retrieve(handle,payload)
            check('native schema2 publication survives another real guest restart and accepts ciphertext')
            (folder/'result.json').write_text(json.dumps(dict(schema=1,result='passed',checks=checks,
                source_store_sha256=hashlib.sha256(args.restore_store.read_bytes()).hexdigest(),
                image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),package_release=identity,
                binary_sha256=package_info['executable_sha256'],elapsed_seconds=time.monotonic()-began,
                backend=args.backend,limitations=['component migration only; no host database edits']),indent=2)+'\n')
            return
        enrollment = recipient + hashlib.sha256(deposit).digest() + hashlib.sha256(fetch).digest()
        assert call(440, 1, 8388608, 256, data=enrollment)[0] == 6
        published()
        assert call(440, 1, 8388608, 256, data=enrollment)[0] == 0
        check('recipient capability hashes durably enrolled without private session/node keys')
        # Mailbox carries recipient-authorized public bundles opaquely; these
        # public fixtures are not session keys and do not test XEdDSA validity.
        bundle=bytearray(struct.pack('<4Q',0x31424d544c,1,1,1))
        for label,length in [(b'IK',32),(b'SPK',32),(b'OPK',32),(b'XEd-signature',64),(b'fed',32),(b'device',32)]:
            bundle.extend(hashlib.shake_256(b'public mailbox prekey fixture '+label).digest(length))
        assert len(bundle)==256
        staged_payload=hashlib.shake_256(b'bounded incomplete upload during prekey work').digest(512)
        staged_request=hashlib.sha256(b'independent incomplete staging operation').digest()
        admission=call(441,1,len(staged_payload),1,data=recipient+deposit+staged_request+hashlib.sha256(staged_payload).digest())
        assert admission[0]==0,admission
        staged_handle=admission[1]
        assert call(441,8,data=recipient+deposit+bundle)[0]==1
        assert call(441,8,data=recipient+fetch+bundle)[0]==6
        published()
        claim=hashlib.sha256(b'one native sender claim').digest()
        other_claim=hashlib.sha256(b'another native sender claim').digest()
        assert call(441,9,data=recipient+fetch+claim)[0]==1
        assert call(441,9,data=recipient+deposit+claim)[0]==6
        published()
        claimed,claimed_bundle=raw_call(441,9,data=recipient+deposit+claim)
        assert claimed[0]==0 and claimed_bundle==bundle
        _,without_opk=raw_call(441,9,data=recipient+deposit+other_claim)
        assert struct.unpack_from('<Q',without_opk,24)[0]==0 and without_opk[96:128]==bytes(32)
        depleted=bytearray(bundle);struct.pack_into('<Q',depleted,24,0);depleted[96:128]=bytes(32)
        for offset in (32,64,128,192,224):
            changed=bytearray(depleted);changed[offset]^=1
            assert call(441,8,data=recipient+fetch+changed)[0]==12
        malformed=bytearray(depleted);malformed[96]=1
        assert call(441,8,data=recipient+fetch+malformed)[0]==2
        assert call(441,8,data=recipient+fetch+depleted)[0]==6
        published()
        assert call(441,8,data=recipient+fetch+bundle)[0]==12
        assert call(441,8,data=recipient+fetch+depleted)[0]==0
        _,depleted_claim=raw_call(441,9,data=recipient+deposit+claim)
        assert depleted_claim==depleted
        assert call(440,6)[1]==1,'prekey publication/claim cleared another admitted upload'
        assert call(441,7,staged_handle)[0]==0
        check('native prekey publication and one-time claim commit while an admitted upload is incomplete; cancellation remains owned')
        stop();start()
        assert call(441,8,data=recipient+fetch+bundle)[0]==12
        _,depleted_claim=raw_call(441,9,data=recipient+deposit+claim)
        assert depleted_claim==depleted
        newer=bytearray(bundle);struct.pack_into('<Q',newer,16,2)
        assert call(441,8,data=recipient+fetch+newer)[0]==6
        published()
        assert call(441,9,data=recipient+deposit+other_claim)[0]==6
        published()
        _,new_claim=raw_call(441,9,data=recipient+deposit+other_claim)
        assert new_claim==newer
        check('recipient-authorized same-generation OPK depletion survives restart, denies substitution/replenishment, and a newer generation permits a fresh claim')
        payload = hashlib.shake_256(b'opaque ciphertext component fixture').digest(1103)
        request = hashlib.sha256(b'request interrupted around remote acceptance').digest()
        handle, commitment = deposit_ciphertext(request, payload)
        assert call(441, 1, len(payload)+1, 1,
                    data=recipient+deposit+request+commitment)[0] == 12
        assert call(441, 5, handle, 0, 512, recipient + deposit)[0] == 1
        check('exact ciphertext retry succeeds, conflict and deposit-token retrieval deny')
        retrieve(handle, payload)
        old_service = service
        stop()
        start()
        assert service != old_service
        retrieve(handle, payload)
        assert call(441, 1, len(payload), 0,
                    data=recipient+deposit+request+commitment)[:3] == (0, handle, len(payload))
        check('actual guest restart recovers durable ciphertext under a fresh exact store grant')
        assert call(441, 6, handle, data=recipient+deposit+commitment)[0] == 1
        assert call(441, 6, handle, data=recipient+fetch+bytes(32))[0] == 1
        assert call(441, 6, handle, data=recipient+fetch+commitment)[0] == 6
        published(handle)
        assert call(441, 6, handle, data=recipient+fetch+commitment)[0] == 0
        check('fetch authority and exact commitment required before durable idempotent acknowledgment')
        for i in range(args.iterations):
            body = hashlib.shake_256(b'opaque envelope'+struct.pack('<Q', i)).digest(513+i)
            req = hashlib.sha256(b'reclaim request'+struct.pack('<Q', i)).digest()
            item, root = deposit_ciphertext(req, body)
            retrieve(item, body)
            assert call(441, 6, item, data=recipient+fetch+root)[0] == 6
            published(item)
        check('completed deposits reclaim ciphertext beyond sixteen physical queue rows')
        assert call(441, 1, len(payload), 0,
                    data=recipient+deposit+request+commitment)[0] == 11
        assert call(441, 5, handle, 0, 512, recipient+fetch)[0] in (6, 1)
        check('evicted old request requires explicit reconciliation and old allocation cannot retrieve reused row')
        assert call(440, 3, data=recipient)[0] == 6
        published()
        assert call(441, 5, 0, 0, 512, recipient+fetch)[0] == 1
        check('recipient revocation durably denies fetch capability')
        report = dict(schema=1, result='passed', backend=args.backend, checks=checks,
                      elapsed_seconds=time.monotonic()-began,
                      image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),
                      package_release=identity, binary_sha256=package_info['executable_sha256'],
                      iterations=args.iterations, slots=16, envelope_bytes=8192,
                      resident_snapshot_bytes=141312, maximum_serialized_bytes=139776,
                      serialized_schema=2, storage='explicit purpose2 ServerStore namespace',
                      limitations=['mailbox component only; no route or recipient decryption',
                                   'AArch64 backend is emulated ARM on this host',
                                   'no whole-backing rollback freshness anchor or physical power-loss assertion'])
        (folder / 'result.json').write_text(json.dumps(report, indent=2)+'\n')
    finally:
        stop()


if __name__ == '__main__':
    main()
