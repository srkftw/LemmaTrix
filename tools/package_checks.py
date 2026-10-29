"""Focused package/crypto boundary checks; all generated keys are disposable."""
from __future__ import annotations
import copy
from pathlib import Path
import struct
import tempfile

import packaging as pkg
import capsule


def main():
    root = pkg.ROOT
    require = pkg.require
    checks = []
    def passed(label):
        checks.append(label)
    def rejected(label, operation, expected):
        try:
            operation()
        except pkg.PackageError as exc:
            require(expected in str(exc), f'{label}: unexpected rejection: {exc}')
            passed(label)
            return
        raise pkg.PackageError(label + ': accepted invalid input')

    require(pkg.sha256(b'') == 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'SHA-256 empty vector')
    require(pkg.sha256(b'abc') == 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', 'SHA-256 abc vector')
    passed('SHA-256 known-answer vectors')
    with tempfile.TemporaryDirectory(prefix='lt-package-check-') as directory:
        directory = Path(directory)
        private, public = directory / 'private.pem', directory / 'public.pem'
        pkg.keygen(private, public)
        # RFC 8032 section 7.1, TEST 2; fixed seed is exclusively a test fixture.
        # Source: https://www.rfc-editor.org/rfc/rfc8032.html#section-7.1
        seed = bytes.fromhex('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb')
        expected_public = bytes.fromhex('3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c')
        expected_signature = bytes.fromhex(
            '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da'
            '085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00')
        fixture = directory / 'rfc8032.der'
        fixture.write_bytes(bytes.fromhex('302e020100300506032b657004220420') + seed)
        derived = pkg.crypto(['pkey', '-inform', 'DER', '-in', fixture, '-pubout', '-outform', 'DER']).stdout
        require(derived == bytes.fromhex('302a300506032b6570032100') + expected_public, 'Ed25519 RFC public key mismatch')
        empty = directory / 'empty'
        empty.write_bytes(b'\x72')
        signature = pkg.crypto(['pkeyutl', '-sign', '-keyform', 'DER', '-inkey', fixture, '-rawin', '-in', empty]).stdout
        require(signature == expected_signature, 'Ed25519 RFC signature mismatch')
        signature_path, public_path = directory / 'rfc.sig', directory / 'rfc.pub'
        signature_path.write_bytes(signature)
        public_path.write_bytes(derived)
        verified = pkg.crypto(['pkeyutl', '-verify', '-pubin', '-keyform', 'DER', '-inkey', public_path,
                               '-rawin', '-in', empty, '-sigfile', signature_path], check=False)
        require(verified.returncode == 0, 'Ed25519 RFC signature verify failed')
        passed('RFC 8032 Ed25519 key/sign/verify known-answer vector')
        output = directory / 'workbench.ltpkg'
        args = pkg.parser().parse_args([
            'create', '--name', 'workbench', '--version', '1.0.0',
            '--elf', str(root / 'build/workbench.elf'), '--binary', str(root / 'build/workbench.bin'),
            '--source', str(root / 'Guest/Workbench.lean'), '--source', str(root / 'Guest/SDK.lean'),
            '--capability', 'object.read', '--capability', 'console.write',
            '--sign-key', str(private), '--output', str(output),
        ])
        pkg.create(args)
        package, raw = pkg.read_package(output)
        policy = dict(allow_development=True, trust_keys=[public],
                      approved_caps=['object.read', 'console.write'], require_signature=True)
        pkg.check(output, **policy)
        passed('actual freestanding native ELF and signed package accepted')
        native = capsule.from_package(output, 1, capsule.development_key(), **policy)
        native_report = capsule.inspect_capsule(native, capsule.modulus(capsule.development_key()))
        require(native_report['caps'] == 1 and native[128:128 + native_report['image_size']] ==
                pkg.unb64(package['binary'], 65536, 'binary'), 'release/capsule authority or executable binding mismatch')
        passed('authenticated source-first release becomes the exact guest RSA capsule')
        rejected('launcher authority cannot become app authority',
                 lambda: capsule.capability_mask(['package.lifecycle']), 'unsupported application authority')
        rejected('missing local development policy', lambda: pkg.check(output, trust_keys=[public],
                 approved_caps=policy['approved_caps'], require_signature=True), 'explicit --allow-development')
        denied = dict(policy, approved_caps=['console.write'])
        rejected('capability increase requires renewed approval', lambda: pkg.validate(package, **denied), 'capability approval')
        other_private, other_public = directory / 'other-private.pem', directory / 'other-public.pem'
        pkg.keygen(other_private, other_public)
        rejected('untrusted signer denied', lambda: pkg.validate(package, **dict(policy, trust_keys=[other_public])), 'not explicitly trusted')
        stripped = copy.deepcopy(package)
        stripped['signature'] = None
        rejected('signature stripping denied', lambda: pkg.validate(stripped, **policy), 'trusted signature is required')
        unsigned_policy = dict(allow_development=True, approved_caps=policy['approved_caps'])
        pkg.validate(stripped, **unsigned_policy)
        passed('unsigned package requires explicit separate local development policy')
        changed = copy.deepcopy(package)
        binary = bytearray(pkg.unb64(changed['binary'], 65536, 'binary'))
        binary[0] ^= 16
        changed['binary'] = pkg.b64(binary)
        rejected('tampered native payload denied', lambda: pkg.validate(changed, **policy), 'content hash')
        changed = copy.deepcopy(package)
        changed['manifest']['version'] = '2.0.0'
        changed['manifest_sha256'] = pkg.sha256(pkg.canonical(changed['manifest']))
        rejected('tampered rehashed manifest denied', lambda: pkg.validate(changed, **policy), 'signature verification')
        changed = copy.deepcopy(package)
        signature = bytearray(pkg.unb64(changed['signature']['value'], 64, 'signature'))
        signature[0] ^= 1
        changed['signature']['value'] = pkg.b64(signature)
        rejected('invalid signature denied', lambda: pkg.validate(changed, **policy), 'signature verification')
        changed = copy.deepcopy(package)
        changed['manifest']['machine'] = 'foreign-machine'
        rejected('incompatible machine denied', lambda: pkg.validate(changed, **policy), 'incompatible machine')
        changed = copy.deepcopy(package)
        changed['sources'][0]['path'] = '../escape.lean'
        rejected('source path traversal denied', lambda: pkg.validate(changed, **policy), 'relative POSIX')
        rejected('duplicate JSON fields denied', lambda: pkg.parse_json(b'{"format":1,"format":1}'), 'duplicate')
        rejected('noncanonical JSON denied', lambda: pkg.parse_json(b'{ "format":1}'), 'canonical')
        rejected('unsupported compressed ELF denied',
                 lambda: pkg.validate_elf(pkg.unb64(package['elf'], pkg.MAX_ELF, 'ELF')[:48] +
                     b'\x01\0\0\0' + pkg.unb64(package['elf'], pkg.MAX_ELF, 'ELF')[52:],
                     pkg.unb64(package['binary'], 65536, 'binary')), 'extension flags')
        rejected('mismatched ELF/raw image denied',
                 lambda: pkg.validate_elf(pkg.unb64(package['elf'], pkg.MAX_ELF, 'ELF'), bytes(binary)),
                 'do not match ELF')
        original_elf = pkg.unb64(package['elf'], pkg.MAX_ELF, 'ELF')
        changed_elf = bytearray(original_elf)
        program_headers = struct.unpack_from('<Q', original_elf, 32)[0]
        struct.pack_into('<I', changed_elf, program_headers + 4, 7)
        rejected('writable global ELF segment denied',
                 lambda: pkg.validate_elf(bytes(changed_elf), pkg.unb64(package['binary'], 65536, 'binary')),
                 'writable global')
        changed_elf = bytearray(original_elf)
        section_headers = struct.unpack_from('<Q', original_elf, 40)[0]
        section_count = struct.unpack_from('<H', original_elf, 60)[0]
        for index in range(section_count):
            section = section_headers + index * 64
            if struct.unpack_from('<Q', original_elf, section + 8)[0] & 4:
                original_offset = struct.unpack_from('<Q', original_elf, section + 24)[0]
                struct.pack_into('<Q', changed_elf, section + 24, original_offset + 4)
                break
        rejected('forged ELF code-section binding denied',
                 lambda: pkg.validate_elf(bytes(changed_elf), pkg.unb64(package['binary'], 65536, 'binary')),
                 'does not match executable load')
        destination = directory / 'export'
        pkg.export(output, destination, **policy)
        require((destination / 'release.ltpkg').read_bytes() == raw, 'export changed package identity')
        require((destination / 'source/Guest/Workbench.lean').read_bytes() == (root / 'Guest/Workbench.lean').read_bytes(), 'export changed source bytes')
        passed('verified source/native package export preserves exact bytes')
        denied_export = directory / 'denied-export'
        rejected('denied export performs no write', lambda: pkg.export(output, denied_export, **denied), 'capability approval')
        require(not denied_export.exists(), 'denied export changed filesystem')
    print('PACKAGE CHECK PASS (' + str(len(checks)) + ' focused checks)')
    for label in checks:
        print('  ' + label)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
