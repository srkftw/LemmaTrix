"""Actual installed Identity-v1 service, independent guests and scoped callers.

Only public descriptors/certificates leave the signer. The fixture publisher key
authenticates code packages, never identity seeds. All cryptography under test
executes in compiled Lean in the freestanding guest.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'tools'))
sys.path.insert(0, str(ROOT/'tests'))
import driver
import identity
import live_acceptance as accept
import releases
import live_build


def package(module, entry, name, directory):
    binary = live_build.app(module, entry, name, 2)
    key = ROOT/'tests/keys/development-rsa.pem'
    raw, _ = releases.make(binary, name, '1.0.0', 0, key, profile=2)
    path = directory/(name+'.ltrel')
    path.write_bytes(raw)
    return path


def verify(public, body, signature, directory):
    directory.mkdir(parents=True, exist_ok=True)
    (directory/'public.der').write_bytes(bytes.fromhex('302a300506032b6570032100')+public)
    (directory/'body.bin').write_bytes(body)
    (directory/'signature.bin').write_bytes(signature)
    driver.run([driver.tool('openssl'), 'pkeyutl', '-verify', '-pubin', '-inkey', directory/'public.der',
                '-keyform', 'DER', '-rawin', '-in', directory/'body.bin', '-sigfile', directory/'signature.bin'],
               capture_output=True)


def client_call(c, probe, inner):
    raw = c.request(150, struct.pack('<Q', probe)+accept.command(500, data=inner))
    return accept.fields(raw), raw[64:]


def contact_body(device, mailbox):
    return struct.pack('<4Q', identity.CONTACT_MAGIC, 1, 1, 3)+device+hashlib.sha256(device+b'device').digest()+mailbox


def run(backend, directory, signer_package, probe_package):
    checks = []
    def passed(description, **data):
        checks.append(dict(check=description, result='passed', **data))
        print(backend, 'PASS', description, flush=True)
    def denied(call):
        try:
            call()
        except ValueError:
            return
        raise AssertionError('forbidden call succeeded')
    with accept.Session(backend, directory) as c:
        service = identity.start(c, signer_package, ROOT/'tests/keys/development-rsa-public.pem')
        before = {r[0] for r in identity.instances(c) if 0 < r[1] < 5}
        # A valid newer admission reaches start/bind; reinstalling the identical
        # version would be rejected earlier and would not test compensation.
        duplicate = directory/'identity-duplicate.ltrel'
        newer, _ = releases.make(ROOT/'build/live/apps/identity.bin', 'identity', '1.0.1', 0,
                                 ROOT/'tests/keys/development-rsa.pem', parent=service['release'], profile=2)
        duplicate.write_bytes(newer)
        denied(lambda: identity.start(c, duplicate, ROOT/'tests/keys/development-rsa-public.pem'))
        after = {r[0] for r in identity.instances(c) if 0 < r[1] < 5}
        assert before == after
        passed('failed duplicate provisioning reclaims its process and preserves the current signer')
        launcher = next(row[0] for row in identity.instances(c) if row[0] & 255 == 1)
        assert next(row[2] for row in identity.instances(c) if row[0] == service['service']) == 0
        federation = hashlib.sha256(b'qualification selected federation').digest()
        scope = hashlib.sha256(b'qualification contact approval').digest()
        began = time.monotonic()
        f, exported = identity.invoke(c, 400, a=2, data=federation+scope)
        elapsed = time.monotonic()-began
        key = f[1]
        public = identity.decode_public(exported)
        verify(exported[96:128], exported[:192], exported[192:256], directory/'verify-identity')
        passed('native fresh identity and independently verified canonical public descriptor', seconds=elapsed,
               key=key, public_key=public['public_key'], fingerprint=public['fingerprint'])
        # Same scope is deliberate; separately created roles must still get independent seeds.
        f2, second = identity.invoke(c, 400, a=3, data=federation+scope)
        assert second[96:128] != exported[96:128]
        passed('separate node and Messenger identity keys are independently generated')
        probe_info = releases.inspect(probe_package.read_bytes())
        c.request(10, probe_package.read_bytes()[128:160] + releases.public_modulus(ROOT/'tests/keys/development-rsa-public.pem'))
        slot, admitted = c.install(probe_package)
        probe = accept.value(c.request(25, struct.pack('<Q', slot)))
        bindings = {op: identity.bind(c, service['service'], probe, bytes.fromhex(service['release']),
                                    bytes.fromhex(admitted['release_id']), op) for op in (401, 402, 400)}
        f, _ = client_call(c, probe, accept.command(400, a=2, data=federation+scope))
        assert f[0] == 1
        passed('operation binding does not give an ordinary application identity-creation authority')
        f, _ = client_call(c, probe, accept.command(401, h=key))
        assert f[0] == 1
        passed('public export binding cannot enumerate or link separate scoped keys')
        for op in (501, 502):
            raw = c.request(150, struct.pack('<Q', probe)+accept.command(op))
            assert accept.fields(raw)[1] == 2**64-1
        passed('unregistered caller denied signer entropy and Network raw entropy')
        body = contact_body(second[96:128], hashlib.sha256(b'opaque qualification mailbox').digest())
        f, _ = identity.invoke(c, 405, h=key, a=probe, b=1, c=len(body), data=hashlib.sha256(body).digest())
        permit = f[1]
        forged = bytearray(body); forged[100] ^= 1
        f, _ = client_call(c, probe, accept.command(402, h=permit, data=bytes(forged)))
        assert f[0] == 1
        denied(lambda: identity.invoke(c, 402, h=permit, data=body))
        f, certificate = client_call(c, probe, accept.command(402, h=permit, data=body))
        assert f[0] == 0 and len(certificate) == 352
        assert struct.unpack_from('<Q', certificate)[0] == identity.SIGNING_MAGIC
        assert certificate[48:80] == federation and certificate[80:112] == scope and certificate[160:288] == body
        verify(certificate[112:144], certificate[:288], certificate[288:], directory/'verify-contact')
        f, _ = client_call(c, probe, accept.command(402, h=permit, data=body))
        assert f[0] == 3
        passed('one-use certificate authority binds exact caller, purpose, federation, scope and canonical body')
        denied(lambda: identity.invoke(c, 405, h=f2[1], a=probe, b=1, c=len(body), data=hashlib.sha256(body).digest()))
        passed('node signing scope cannot certify Messenger contact material')
        for _ in range(20):
            f, _ = identity.invoke(c, 405, h=key, a=probe, b=1, c=len(body), data=hashlib.sha256(body).digest())
            identity.invoke(c, 407, h=f[1])
        passed('cancelled one-use approvals reclaim capacity through more than16 operations')
        f, _ = identity.invoke(c, 405, h=key, a=probe, b=1, c=len(body), data=hashlib.sha256(body).digest())
        old_permit = f[1]
        c.request(173, struct.pack('<4Q', 1, probe, 402, bindings[402]))
        bindings[402] = identity.bind(c, service['service'], probe, bytes.fromhex(service['release']),
                                     bytes.fromhex(admitted['release_id']), 402)
        f, _ = client_call(c, probe, accept.command(402, h=old_permit, data=body))
        assert f[0] == 3
        passed('fresh IPC binding cannot revive an approval issued under a revoked generation')
        # Typed service declaration uses current supported mode3 only. It does not
        # claim relay/mailbox enrollment or replace legacy RSA Network pins.
        declaration = bytearray(256)
        struct.pack_into('<8Q', declaration, 0, identity.NODE_MAGIC, 1, 1, 3, 1, 1048576, 1000, 1)
        for offset, label in ((64,b'handshake public'), (96,b'approved image'), (128,b'operator family')):
            declaration[offset:offset+32] = hashlib.sha256(label).digest()
        endpoint = b'127.0.0.1:9001'
        struct.pack_into('<3Q', declaration, 160, 1, 0, len(endpoint))
        declaration[184:184+len(endpoint)] = endpoint
        f, _ = identity.invoke(c, 405, h=f2[1], a=launcher, b=2, c=256, data=hashlib.sha256(declaration).digest())
        _, cert = identity.invoke(c, 402, h=f[1], data=declaration)
        verify(cert[112:144], cert[:416], cert[416:], directory/'verify-node')
        passed('native typed numeric-endpoint service declaration signature verified independently')
        identity.invoke(c, 403, h=key)
        denied(lambda: identity.invoke(c, 401, h=key))
        _, unchanged = identity.invoke(c, 401, h=f2[1])
        assert unchanged == second
        passed('key revocation wipes selected key and leaves unrelated scoped identity usable')
        # Invalid binding CAS and package hash cannot upgrade an admitted instance.
        denied(lambda: identity.bind(c, service['service'], probe, bytes(32), bytes.fromhex(probe_info['release_id']), 402))
        generation = service['bindings'][401]
        c.request(173, struct.pack('<4Q', 1, launcher, 401, generation))
        denied(lambda: identity.invoke(c, 401, h=f2[1]))
        denied(lambda: c.request(150, struct.pack('<Q',service['service'])+accept.command(401,h=f2[1])))
        passed('binding revocation denies discovery and guessed direct endpoint access')
        identity.bind(c, service['service'], launcher, bytes.fromhex(service['release']), bytes(32), 401)
        identity.invoke(c, 404)
        denied(lambda: identity.invoke(c, 401, h=f2[1]))
        c.request(26, struct.pack('<Q', service['service']))
        denied(lambda: identity.endpoint(c, 400))
        passed('lock and service termination invalidate old keys and live bindings')
        object_handle = c.import_object(b'Campaign006 Objects still operates after signer teardown')
        assert c.read_object(object_handle).startswith(b'Campaign006')
        passed('existing Objects flow remains usable after isolated signer teardown')
    with accept.Session(backend, directory/'fresh-session') as c:
        identity.start(c, signer_package, ROOT/'tests/keys/development-rsa-public.pem')
        denied(lambda: identity.invoke(c, 401, h=key))
        f, fresh = identity.invoke(c, 400, a=2, data=federation+scope)
        assert fresh[96:128] != exported[96:128]
        assert f[1] != key
        denied(lambda: identity.invoke(c, 401, h=key))
        passed('independent new guest owns a new key and cannot recover unretained old authority')
    return {'backend':backend, 'checks':checks, 'public':public, 'limits':{'identity_keys':8,'one_use_approvals':16,'private_arena_bytes':2097152}}


def main():
    p = argparse.ArgumentParser(); p.add_argument('--backend', choices=['qemu','x86_64','aarch64','all'], default='qemu')
    p.add_argument('--output', type=Path, default=ROOT/'build/campaign007/native-identity')
    args = p.parse_args(); args.output.mkdir(parents=True, exist_ok=True)
    signer = package('Guest.Identity','Guest.Identity.main','identity',args.output)
    probe = package('tests.fixtures.IdentityClientProbe','Guest.IdentityClientProbe.main','identity-client-probe',args.output)
    backends = ['qemu','x86_64','aarch64'] if args.backend == 'all' else [args.backend]
    results = [run(b, args.output/b, signer, probe) for b in backends]
    report = {'image_sha256':hashlib.sha256((ROOT/'build/live/guest.bin').read_bytes()).hexdigest(),
              'signer_sha256':hashlib.sha256((ROOT/'build/live/apps/identity.bin').read_bytes()).hexdigest(),
              'signer_release':releases.inspect(signer.read_bytes())['release_id'],
              'results':results, 'unsupported':['Messenger application','mode1 circuits','mailbox','durable personal keys','X3DH','Double Ratchet']}
    (args.output/'evidence.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
