"""Fixed native capsule for the guest package verifier.

The tracked development RSA key is intentionally public test material. It must
never establish production identity or admission. Ordinary keys are generated
only by explicit keygen with functioning OS entropy, and are never guessed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

try:
    from . import packaging as pkg
except ImportError:
    import packaging as pkg

HEADER_SIZE = 128
IMAGE_LIMIT = 65536
SIGNATURE_OFFSET = 0x10100
SIGNATURE_SIZE = 256
CAPSULE_SIZE = SIGNATURE_OFFSET + SIGNATURE_SIZE
MAGIC = 0x31474b50544c
SCHEMA = 1
MACHINE = 1
RUNTIME = 1
ENTRY = 0x400000
MODE_SIGNED_RSA2048 = 2


def development_key():
    """Return the publicly distributed, non-production development fixture."""
    return pkg.ROOT / 'tests/keys/development-rsa.pem'


def _tlv(data, offset=0):
    pkg.require(offset + 2 <= len(data), 'truncated RSA DER field')
    tag = data[offset]
    size = data[offset + 1]
    offset += 2
    if size & 128:
        count = size & 127
        pkg.require(1 <= count <= 4 and offset + count <= len(data), 'invalid RSA DER length')
        pkg.require(data[offset] != 0, 'noncanonical RSA DER length')
        size = int.from_bytes(data[offset:offset + count], 'big')
        pkg.require(size >= 128, 'noncanonical RSA DER short length')
        offset += count
    pkg.require(size <= len(data) - offset, 'truncated RSA DER content')
    return tag, data[offset:offset + size], offset + size


def _rsa_public(signing_key):
    der = pkg.crypto(['pkey', '-in', signing_key, '-pubout', '-outform', 'DER']).stdout
    tag, sequence, end = _tlv(der)
    pkg.require(tag == 0x30 and end == len(der), 'invalid RSA SubjectPublicKeyInfo')
    tag, algorithm, cursor = _tlv(sequence)
    pkg.require(tag == 0x30 and algorithm == bytes.fromhex('06092a864886f70d0101010500'),
                'capsules require an ordinary rsaEncryption key')
    tag, bitstring, end = _tlv(sequence, cursor)
    pkg.require(tag == 3 and end == len(sequence) and bitstring[:1] == b'\0', 'invalid RSA public bitstring')
    tag, public, end = _tlv(bitstring[1:])
    pkg.require(tag == 0x30 and end == len(bitstring) - 1, 'invalid RSA public key')
    tag, number, cursor = _tlv(public)
    pkg.require(tag == 2 and len(number) == 257 and number[:1] == b'\0'
                and number[1] & 128 and number[-1] & 1,
                'capsules require an odd full-width RSA-2048 modulus')
    tag, exponent, end = _tlv(public, cursor)
    pkg.require(tag == 2 and exponent == b'\x01\x00\x01' and end == len(public),
                'capsules require the RSA public exponent 65537')
    return der, number[1:]


def modulus(signing_key):
    """Export the exact 256-byte big-endian modulus the boot policy trusts."""
    return _rsa_public(signing_key)[1]


def generate_key(private, public):
    private, public = Path(private), Path(public)
    pkg.require(private.resolve() != public.resolve(), 'private and public key outputs must differ')
    pkg.require(not private.exists() and not public.exists(), 'refusing to overwrite existing RSA keys')
    pkg.require(private.parent.is_dir() and public.parent.is_dir(), 'key output parent must exist')
    pkg.require(len(os.getrandom(32)) == 32, 'OS cryptographic entropy unavailable; key generation disabled')
    with tempfile.TemporaryDirectory(prefix='lt-rsa-keygen-') as directory:
        path = Path(directory) / 'private.pem'
        pkg.crypto(['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048',
                    '-pkeyopt', 'rsa_keygen_pubexp:65537', '-out', path])
        der, number = _rsa_public(path)
        pem = pkg.crypto(['pkey', '-in', path, '-pubout']).stdout
        pkg.write_new(private, path.read_bytes(), 0o600)
        try:
            pkg.write_new(public, pem)
        except BaseException:
            private.unlink()
            raise
    return hashlib.sha256(number).hexdigest()


def build_capsule(raw, version, caps, runtime=RUNTIME, signing_key=None):
    """Sign fixed header + SHA-256 payload commitment; return padded capsule.

    Signing is RSA-2048 EMSA-PKCS1-v1_5 with SHA-256 and exponent 65537.
    The guest authenticates the header and independently hashes actual code.
    Callers must explicitly select a key, including for development fixtures.
    """
    pkg.require(isinstance(raw, bytes) and 0 < len(raw) <= IMAGE_LIMIT and len(raw) % 4 == 0,
                'native capsule image must be nonempty aligned RV64IM code <=64 KiB')
    pkg.integer(version, 'capsule version', 1)
    pkg.integer(caps, 'capsule capability mask')
    pkg.integer(runtime, 'capsule runtime', 1)
    pkg.require(signing_key is not None, 'capsule signing key must be explicitly selected')
    _rsa_public(signing_key)
    header = bytearray(HEADER_SIZE)
    struct.pack_into('<8Q', header, 0, MAGIC, SCHEMA, MACHINE, runtime, ENTRY, len(raw), caps, version)
    header[64:96] = hashlib.sha256(raw).digest()
    struct.pack_into('<Q', header, 96, MODE_SIGNED_RSA2048)
    with tempfile.TemporaryDirectory(prefix='lt-capsule-sign-') as directory:
        path = Path(directory) / 'header'
        path.write_bytes(header)
        signature = pkg.crypto(['dgst', '-sha256', '-sign', signing_key, path]).stdout
    pkg.require(len(signature) == SIGNATURE_SIZE, 'RSA signer returned an invalid signature size')
    result = bytearray(CAPSULE_SIZE)
    result[:HEADER_SIZE] = header
    result[HEADER_SIZE:HEADER_SIZE + len(raw)] = raw
    result[SIGNATURE_OFFSET:] = signature
    return bytes(result)



def capability_mask(names):
    """Map the implemented object-authority groups to the guest ABI bitmask.

    create/revise share one right; share/revoke share one right. Console output
    is part of the user ABI. Package lifecycle remains a trusted launcher action.
    """
    pkg.require(isinstance(names, list) and all(isinstance(name, str) for name in names),
                'invalid package capability declaration')
    rights = {'object.read': 1, 'object.create': 2, 'object.revise': 2,
              'object.share': 4, 'object.revoke': 4, 'console.write': 0}
    unsupported = set(names) - set(rights)
    pkg.require(not unsupported, 'unsupported application authority: ' + ', '.join(sorted(unsupported)))
    result = 0
    for name in names:
        result |= rights[name]
    return result


def from_package(path, version, signing_key, *, allow_development=False,
                 trust_keys=(), approved_caps=(), require_signature=True):
    """Authenticate a source-first release and produce its actual guest capsule.

    The host verifies the complete Ed25519 release manifest and ELF/source
    commitments; the guest's trusted RSA issuer authenticates only executable
    bytes, ABI compatibility, authority group mask and session generation.
    Generation is a launcher policy value distinct from release semantic version.
    """
    package, _ = pkg.read_package(path)
    pkg.validate(package, allow_development=allow_development, trust_keys=trust_keys,
                 approved_caps=approved_caps, require_signature=require_signature)
    caps = capability_mask(package['manifest']['capabilities'])
    raw = pkg.unb64(package['binary'], IMAGE_LIMIT, 'native package binary')
    return build_capsule(raw, version, caps, signing_key=signing_key)


def inspect_capsule(capsule, trusted_modulus=None):
    """Check bounded structure and actual payload hash, plus optional host RSA check.

    This API is useful for export diagnostics. Guest policy independently checks
    the header, capabilities, compatibility, hash and RSA signature before use.
    """
    pkg.require(isinstance(capsule, bytes) and len(capsule) == CAPSULE_SIZE, 'invalid fixed capsule size')
    magic, schema, machine, runtime, entry, length, caps, version = struct.unpack_from('<8Q', capsule)
    pkg.require(magic == MAGIC and schema == SCHEMA and machine == MACHINE, 'incompatible capsule schema/machine')
    pkg.require(runtime == RUNTIME and entry == ENTRY, 'incompatible capsule runtime/entry')
    pkg.require(0 < length <= IMAGE_LIMIT and length % 4 == 0 and version > 0, 'invalid capsule image/version')
    pkg.require(struct.unpack_from('<Q', capsule, 96)[0] == MODE_SIGNED_RSA2048,
                'only RSA-signed capsules are accepted')
    pkg.require(capsule[104:128] == bytes(24), 'nonzero reserved capsule header')
    image = capsule[HEADER_SIZE:HEADER_SIZE + length]
    pkg.require(hashlib.sha256(image).digest() == capsule[64:96], 'capsule payload SHA-256 mismatch')
    pkg.require(capsule[HEADER_SIZE + length:SIGNATURE_OFFSET] == bytes(SIGNATURE_OFFSET - HEADER_SIZE - length),
                'nonzero capsule padding')
    if trusted_modulus is not None:
        pkg.require(isinstance(trusted_modulus, bytes) and len(trusted_modulus) == 256
                    and trusted_modulus[0] & 128 and trusted_modulus[-1] & 1,
                    'invalid trusted RSA-2048 modulus')
        signature = int.from_bytes(capsule[SIGNATURE_OFFSET:], 'big')
        number = int.from_bytes(trusted_modulus, 'big')
        pkg.require(signature < number, 'RSA signature representative out of range')
        decoded = pow(signature, 65537, number).to_bytes(256, 'big')
        digest_info = bytes.fromhex('3031300d060960864801650304020105000420') + hashlib.sha256(capsule[:128]).digest()
        expected = b'\0\x01' + b'\xff' * 202 + b'\0' + digest_info
        pkg.require(decoded == expected, 'capsule RSA PKCS1-v1_5/SHA-256 signature mismatch')
    return {'schema': schema, 'machine': machine, 'runtime': runtime, 'entry': entry,
            'image_size': length, 'caps': caps, 'version': version,
            'image_sha256': hashlib.sha256(image).hexdigest(),
            'capsule_sha256': hashlib.sha256(capsule).hexdigest(),
            'signature': 'verified-host-RSA2048' if trusted_modulus is not None else 'unchecked'}


def main(argv=None):
    parser = argparse.ArgumentParser(description='Guest-verifiable RSA-2048 native development capsules')
    commands = parser.add_subparsers(dest='command', required=True)
    key = commands.add_parser('keygen')
    key.add_argument('--private', required=True, type=Path)
    key.add_argument('--public', required=True, type=Path)
    new = commands.add_parser('create')
    new.add_argument('binary', type=Path)
    new.add_argument('--version', required=True, type=int)
    new.add_argument('--caps', required=True, type=lambda value: int(value, 0))
    new.add_argument('--runtime', default=RUNTIME, type=int)
    new.add_argument('--sign-key', required=True, type=Path)
    new.add_argument('--output', required=True, type=Path)
    new.add_argument('--modulus-output', type=Path)
    check = commands.add_parser('check')
    check.add_argument('capsule', type=Path)
    check.add_argument('--trusted-modulus', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == 'keygen':
            result = {'algorithm': 'RSA-2048/65537', 'modulus_sha256': generate_key(args.private, args.public)}
        elif args.command == 'create':
            raw = pkg.bounded_file(args.binary, IMAGE_LIMIT, 'native binary')
            result_bytes = build_capsule(raw, args.version, args.caps, args.runtime, args.sign_key)
            trust = modulus(args.sign_key)
            result = inspect_capsule(result_bytes, trust)
            if args.modulus_output is not None:
                pkg.require(not args.modulus_output.exists(), 'refusing to overwrite trusted modulus')
            pkg.write_new(args.output, result_bytes)
            if args.modulus_output is not None:
                pkg.write_new(args.modulus_output, trust)
        else:
            raw = pkg.bounded_file(args.capsule, CAPSULE_SIZE, 'capsule')
            trust = pkg.bounded_file(args.trusted_modulus, 256, 'trusted modulus')
            result = inspect_capsule(raw, trust)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (pkg.PackageError, OSError, subprocess.TimeoutExpired) as exc:
        print('lt capsule:', exc, file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
