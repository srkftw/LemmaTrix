"""Bounded native development packages and host Ed25519 release verification.

This host bootstrap tool does not implement guest signer authentication or catalog
admission. Packages and key files are written only to explicitly supplied paths.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
MACHINE = 'LT-Dev-RV64IM-Sv39-v1'
RUNTIME = 'LT-U64-v1'
CAPABILITIES = frozenset({
    'object.read', 'object.create', 'object.revise', 'object.share',
    'object.revoke', 'console.write', 'package.lifecycle',
})
MAX_PACKAGE = 4 * 1024 * 1024
MAX_ELF = 1024 * 1024
MAX_SOURCE = 128 * 1024
MAX_SOURCES = 128
MAX_SOURCE_TOTAL = 1024 * 1024
ENTRY = 0x400000
END = 0x410000
DOMAIN = b'LTPKG-RELEASE-v1\n'


class PackageError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise PackageError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def b64(data):
    return base64.b64encode(data).decode('ascii')


def unb64(value, maximum, label):
    require(isinstance(value, str) and len(value) <= 4 * ((maximum + 2) // 3),
            f'{label}: base64 value exceeds limit or is not a string')
    try:
        data = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise PackageError(f'{label}: invalid base64') from exc
    require(len(data) <= maximum and b64(data) == value,
            f'{label}: noncanonical or oversized base64')
    return data


def bounded_file(path, maximum, label):
    with Path(path).open('rb') as stream:
        data = stream.read(maximum + 1)
    require(len(data) <= maximum, f'{label}: file exceeds {maximum} bytes')
    return data


def exact_keys(value, keys, label):
    require(isinstance(value, dict) and set(value) == set(keys),
            f'{label}: missing, unexpected, or invalid fields')


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f'duplicate JSON field: {key}')
        result[key] = value
    return result


def parse_json(data):
    try:
        value = json.loads(data.decode('utf-8'), object_pairs_hook=no_duplicates,
                           parse_constant=lambda _: (_ for _ in ()).throw(PackageError('nonfinite JSON number')))
        require(canonical(value) == data, 'package must use canonical UTF-8 JSON')
        return value
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise PackageError('malformed UTF-8 JSON package') from exc
    except ValueError as exc:
        if isinstance(exc, PackageError):
            raise
        raise PackageError('malformed bounded JSON number') from exc


def text(value, label, maximum=256):
    require(isinstance(value, str) and 0 < len(value.encode('utf-8')) <= maximum
            and '\x00' not in value, f'{label}: invalid bounded string')
    return value


def digest(value, label):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None,
            f'{label}: expected lowercase SHA-256 digest')


def integer(value, label, minimum=0, maximum=2**64-1):
    require(type(value) is int and minimum <= value <= maximum,
            f'{label}: invalid bounded integer')


def source_path(value):
    text(value, 'source path', 240)
    path = PurePosixPath(value)
    require(not path.is_absolute() and path.as_posix() == value
            and not any(part in ('', '.', '..') for part in path.parts)
            and '\\' not in value and ':' not in value,
            'source path must be a normalized relative POSIX path')
    return value


def openssl():
    lock = json.loads((ROOT / 'toolchain.lock.json').read_text())
    candidate = os.environ.get('LT_OPENSSL') or lock.get('nix_store', {}).get('openssl')
    if candidate and Path(candidate).is_file():
        return candidate
    candidate = shutil.which('openssl')
    require(candidate is not None, 'OpenSSL is required; set LT_OPENSSL to the pinned executable')
    return candidate


def crypto(args, *, data=None, check=True):
    result = subprocess.run([openssl(), *map(str, args)], input=data,
                            capture_output=True, timeout=15)
    if check:
        require(result.returncode == 0, 'OpenSSL operation failed: ' +
                result.stderr.decode('utf-8', 'replace')[:512].strip())
    return result


def public_der(private):
    der = crypto(['pkey', '-in', private, '-pubout', '-outform', 'DER']).stdout
    validate_public(der)
    return der


def validate_public(der):
    # RFC 8410 SubjectPublicKeyInfo: id-Ed25519, no parameters, 32-byte key.
    require(len(der) == 44 and der[:12] == bytes.fromhex('302a300506032b6570032100'),
            'signing key must be an Ed25519 public key in RFC 8410 DER format')


def trusted_der(path):
    data = bounded_file(path, 4096, 'trusted public key')
    if data.startswith(b'-----BEGIN PUBLIC KEY-----'):
        data = crypto(['pkey', '-pubin', '-in', path, '-outform', 'DER']).stdout
    validate_public(data)
    return data


def write_new(path, data, mode=0o644):
    path = Path(path)
    require(path.parent.is_dir(), f'output parent does not exist: {path.parent}')
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(data)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def keygen(private, public):
    private, public = Path(private), Path(public)
    require(private.resolve() != public.resolve(), 'private and public paths must differ')
    require(not private.exists() and not public.exists(), 'refusing to overwrite an existing key')
    require(private.parent.is_dir() and public.parent.is_dir(), 'key output parent must exist')
    # OpenSSL obtains cryptographic entropy from the Linux OS random provider.
    # os.getrandom verifies that this environment actually supplies OS entropy.
    require(len(os.getrandom(32)) == 32, 'OS cryptographic entropy unavailable; key generation disabled')
    with tempfile.TemporaryDirectory(prefix='lt-ed25519-') as directory:
        temp = Path(directory) / 'private.pem'
        crypto(['genpkey', '-algorithm', 'ED25519', '-out', temp])
        der = public_der(temp)
        pem = crypto(['pkey', '-pubin', '-inform', 'DER', '-pubout'], data=der).stdout
        write_new(private, temp.read_bytes(), 0o600)
        try:
            write_new(public, pem)
        except BaseException:
            private.unlink()
            raise
    return sha256(der)


def section_data(elf, offset, size, label):
    require(offset <= len(elf) and size <= len(elf) - offset, f'ELF: truncated {label}')
    return elf[offset:offset + size]


def instruction_supported(word):
    opcode, funct3, funct7 = word & 127, (word >> 12) & 7, word >> 25
    if opcode in (0x37, 0x17, 0x6f):
        return True
    if opcode == 0x67:
        return funct3 == 0
    if opcode == 0x63:
        return funct3 in (0, 1, 4, 5, 6, 7)
    if opcode == 0x03:
        return funct3 <= 6
    if opcode == 0x23:
        return funct3 <= 3
    if opcode == 0x13:
        return (funct3 not in (1, 5)
                or (funct3 == 1 and word >> 26 == 0)
                or (funct3 == 5 and word >> 26 in (0, 16)))
    if opcode == 0x1b:
        return (funct3 == 0 or (funct3 == 1 and funct7 == 0)
                or (funct3 == 5 and funct7 in (0, 32)))
    if opcode == 0x33:
        return funct7 in (0, 1) or (funct7 == 32 and funct3 in (0, 5))
    if opcode == 0x3b:
        return ((funct7 in (0, 32) and funct3 in (0, 5))
                or (funct7 == 0 and funct3 == 1)
                or (funct7 == 1 and funct3 in (0, 4, 5, 6, 7)))
    if opcode == 0x0f:
        return funct3 == 0 or word == 0x0000100f
    if opcode == 0x73:
        if funct3 in (1, 2, 3, 5, 6, 7):
            return True
        return word in (0x73, 0x100073, 0x10200073, 0x30200073, 0x10500073) or (
            word & 0xfe007fff == 0x12000073)
    return False


def validate_elf(elf, binary):
    require(64 <= len(elf) <= MAX_ELF, 'ELF: invalid size')
    header = struct.unpack_from('<16sHHIQQQIHHHHHH', elf)
    ident, kind, machine, version, entry, phoff, shoff, flags, ehsize, phsize, phnum, shsize, shnum, shstr = header
    require(ident[:9] == b'\x7fELF\x02\x01\x01\x00\x00', 'ELF: expected little-endian ELF64 System V')
    require(kind == 2 and machine == 243 and version == 1, 'ELF: expected RISC-V ET_EXEC')
    require(flags == 0, 'ELF: compressed, floating-point, RVE, and other extension flags are unsupported')
    require(entry == ENTRY and ehsize == 64, 'ELF: incorrect native application entry/header')
    require(phsize == 56 and 1 <= phnum <= 32, 'ELF: invalid program headers')
    section_data(elf, phoff, phnum * phsize, 'program header table')
    segments = []
    highest = ENTRY
    for index in range(phnum):
        ptype, permissions, offset, virtual, physical, filesz, memsz, alignment = struct.unpack_from(
            '<IIQQQQQQ', elf, phoff + index * phsize)
        require(ptype in (0, 1, 0x6474e551), 'ELF: dynamic/interpreted or unknown segment type')
        if ptype != 1:
            continue
        require(ENTRY <= virtual < END and filesz <= memsz <= END - virtual,
                'ELF: load segment exceeds 64 KiB application mapping')
        require(physical == virtual, 'ELF: physical and virtual load addresses must match')
        require(permissions in (4, 5), 'ELF: writable global segments are unsupported; use the bounded user buffer/stack')
        require(alignment in (0, 1) or (alignment & (alignment - 1) == 0
                and alignment <= 4096 and (virtual - offset) % alignment == 0),
                'ELF: unsupported segment alignment')
        data = section_data(elf, offset, filesz, 'load segment')
        require(all(virtual + memsz <= prior[0] or virtual >= prior[0] + prior[2]
                    for prior in segments), 'ELF: overlapping load segments')
        segments.append((virtual, data, memsz, permissions))
        highest = max(highest, virtual + filesz)
    require(segments and any(v <= entry < v + len(data) and perm & 1
                            for v, data, _, perm in segments), 'ELF: entry is not executable')
    reconstructed = bytearray(highest - ENTRY)
    for virtual, data, _, _ in segments:
        reconstructed[virtual - ENTRY:virtual - ENTRY + len(data)] = data
    require(bytes(reconstructed) == binary, 'raw executable bytes do not match ELF load segments')
    require(shsize == 64 and 1 <= shnum <= 512 and shstr < shnum,
            'ELF: bounded section/symbol metadata is required')
    section_data(elf, shoff, shnum * shsize, 'section table')
    sections = [struct.unpack_from('<IIQQQQIIQQ', elf, shoff + index * shsize)
                for index in range(shnum)]
    names = section_data(elf, sections[shstr][4], sections[shstr][5], 'section names')
    saw_code = False
    checked_entry = False
    for section in sections:
        name, stype, attributes, address, offset, size, link, info, alignment, entsize = section
        require(name < len(names) and b'\0' in names[name:], 'ELF: invalid section name')
        if stype in (4, 9):
            require(size == 0, 'ELF: unresolved relocations are unsupported')
        if attributes & 4:  # SHF_EXECINSTR
            require(stype == 1 and address % 4 == 0 and size % 4 == 0,
                    'ELF: unsupported executable section layout')
            data = section_data(elf, offset, size, 'executable section')
            require(any(v <= address and address + size <= v + len(part) and permissions & 1
                        and data == part[address - v:address - v + size]
                        for v, part, _, permissions in segments), 'ELF: code section does not match executable load bytes')
            checked_entry = checked_entry or address <= entry < address + size
            for index in range(0, len(data), 4):
                word = int.from_bytes(data[index:index + 4], 'little')
                require(instruction_supported(word),
                        f'ELF: unsupported RV64IM instruction 0x{word:08x} at 0x{address + index:x}')
            saw_code = saw_code or bool(data)
        if stype == 2:  # SHT_SYMTAB
            require(entsize == 24 and size % 24 == 0, 'ELF: invalid symbol table')
            symbols = section_data(elf, offset, size, 'symbol table')
            for index in range(24, len(symbols), 24):
                symbol_name, _, _, section_index, _, _ = struct.unpack_from('<IBBHQQ', symbols, index)
                require(not symbol_name or section_index != 0, 'ELF: unresolved named symbol')
    require(saw_code and checked_entry, 'ELF: entry has no inspectable executable section')
    return {'entry': entry, 'image_size': len(binary), 'load_segments': len(segments)}


def descriptor(data):
    return {'sha256': sha256(data), 'size': len(data)}


def check_descriptor(value, data, label):
    exact_keys(value, ('sha256', 'size'), label)
    digest(value['sha256'], label + ' hash')
    integer(value['size'], label + ' size')
    require(value == descriptor(data), label + ': content hash or length mismatch')


def read_package(path):
    data = bounded_file(path, MAX_PACKAGE, 'package')
    return parse_json(data), data


def validate(package, *, allow_development=False, trust_keys=(), approved_caps=(),
             enforce_authorization=True, require_signature=False):
    exact_keys(package, ('format', 'manifest', 'manifest_sha256', 'binary', 'elf', 'sources', 'signature'), 'package')
    require(package['format'] == 'LTPKG-1', 'unsupported package format')
    manifest = package['manifest']
    exact_keys(manifest, ('schema', 'record_type', 'project', 'version', 'release_kind',
               'admission', 'machine', 'runtime', 'abi', 'entry', 'binary', 'elf', 'source_root',
               'sources', 'lineage', 'rights', 'capabilities', 'dependencies', 'toolchain_lock',
               'evidence', 'limitations', 'persistence', 'network', 'signer'), 'manifest')
    require(manifest['schema'] == 1 and type(manifest['schema']) is int, 'unsupported manifest schema')
    require(manifest['record_type'] == 'Release' and manifest['release_kind'] == 'NativeApplication',
            'only native application Release records are supported')
    require(manifest['admission'] == 'development-only', 'catalog admission is not implemented')
    require(manifest['machine'] == MACHINE, 'incompatible machine profile')
    require(manifest['runtime'] == RUNTIME and manifest['abi'] == 1
            and type(manifest['abi']) is int, 'incompatible runtime/ABI')
    integer(manifest['entry'], 'entry')
    require(manifest['entry'] == ENTRY, 'invalid application entry')
    require(isinstance(manifest['project'], str) and re.fullmatch('[a-z0-9][a-z0-9._-]{0,63}', manifest['project']),
            'invalid project ID')
    require(isinstance(manifest['version'], str) and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?', manifest['version'])
            and len(manifest['version']) <= 64, 'invalid bounded semantic version')
    require(manifest['persistence'] == 'ephemeral' and manifest['network'] == 'unavailable',
            'persistent and networked packages are unavailable in this profile')
    require(manifest['dependencies'] == [], 'runtime dependency loading is not supported; use a statically linked package')
    caps = manifest['capabilities']
    require(isinstance(caps, list) and all(isinstance(cap, str) for cap in caps)
            and caps == sorted(set(caps)) and set(caps) <= CAPABILITIES, 'unknown or duplicate capability')
    if enforce_authorization:
        require(set(caps) <= set(approved_caps),
                'capability approval required: ' + ', '.join(sorted(set(caps) - set(approved_caps))))
        require(allow_development, 'local development packages require explicit --allow-development policy')
    exact_keys(manifest['rights'], ('license', 'distribution_authority'), 'rights')
    text(manifest['rights']['license'], 'license', 128)
    text(manifest['rights']['distribution_authority'], 'distribution authority', 1024)
    text(manifest['signer'], 'signer')
    require(isinstance(manifest['lineage'], list) and len(manifest['lineage']) <= 16, 'invalid lineage list')
    for ancestor in manifest['lineage']:
        digest(ancestor, 'lineage parent')
    require(len(set(manifest['lineage'])) == len(manifest['lineage']), 'duplicate lineage parent')
    require(isinstance(manifest['evidence'], list) and len(manifest['evidence']) <= 32, 'invalid evidence list')
    for evidence in manifest['evidence']:
        text(evidence, 'evidence reference', 1024)
    require(isinstance(manifest['limitations'], list) and 1 <= len(manifest['limitations']) <= 32,
            'explicit limitations are required')
    for limitation in manifest['limitations']:
        text(limitation, 'limitation', 1024)
    require(isinstance(manifest['toolchain_lock'], dict)
            and 1 <= len(canonical(manifest['toolchain_lock'])) <= 32768, 'invalid toolchain lock')
    binary = unb64(package['binary'], END - ENTRY, 'binary')
    elf = unb64(package['elf'], MAX_ELF, 'ELF')
    require(binary, 'empty native binary')
    check_descriptor(manifest['binary'], binary, 'binary')
    check_descriptor(manifest['elf'], elf, 'ELF')
    elf_info = validate_elf(elf, binary)
    require(isinstance(package['sources'], list) and 1 <= len(package['sources']) <= MAX_SOURCES,
            'a bounded source snapshot is required')
    require(isinstance(manifest['sources'], list) and len(manifest['sources']) == len(package['sources']),
            'source manifest length mismatch')
    sources = []
    source_descriptors = []
    total = 0
    for source in package['sources']:
        exact_keys(source, ('path', 'data'), 'source snapshot')
        path = source_path(source['path'])
        raw = unb64(source['data'], MAX_SOURCE, 'source ' + path)
        total += len(raw)
        require(total <= MAX_SOURCE_TOTAL, 'source snapshot exceeds 1 MiB')
        sources.append((path, raw))
        source_descriptors.append({'path': path, **descriptor(raw)})
    require([path for path, _ in sources] == sorted(set(path for path, _ in sources)),
            'source paths must be unique and sorted')
    require(source_descriptors == manifest['sources'], 'source content hashes/lengths do not match manifest')
    digest(manifest['source_root'], 'source root')
    require(sha256(canonical(source_descriptors)) == manifest['source_root'], 'source root hash mismatch')
    digest(package['manifest_sha256'], 'manifest hash')
    message = canonical(manifest)
    require(sha256(message) == package['manifest_sha256'], 'manifest hash mismatch')
    signature = package['signature']
    signer_fingerprint = None
    if enforce_authorization and (require_signature or trust_keys):
        require(signature is not None, 'a trusted signature is required by local policy')
    if signature is not None:
        exact_keys(signature, ('algorithm', 'public_key', 'key_id', 'value'), 'signature')
        require(signature['algorithm'] == 'Ed25519', 'unsupported signature algorithm')
        public = unb64(signature['public_key'], 44, 'public key')
        validate_public(public)
        signer_fingerprint = sha256(public)
        require(signature['key_id'] == signer_fingerprint, 'signer key fingerprint mismatch')
        signed = unb64(signature['value'], 64, 'signature')
        require(len(signed) == 64, 'invalid Ed25519 signature length')
        with tempfile.TemporaryDirectory(prefix='lt-verify-') as directory:
            directory = Path(directory)
            (directory / 'public.der').write_bytes(public)
            (directory / 'signature').write_bytes(signed)
            (directory / 'message').write_bytes(DOMAIN + message)
            result = crypto(['pkeyutl', '-verify', '-pubin', '-inkey', directory / 'public.der',
                             '-keyform', 'DER', '-rawin', '-in', directory / 'message',
                             '-sigfile', directory / 'signature'], check=False)
        require(result.returncode == 0, 'Ed25519 signature verification failed')
        if enforce_authorization:
            trusted = {sha256(trusted_der(path)) for path in trust_keys}
            require(signer_fingerprint in trusted, 'signer is not explicitly trusted; supply --trust-key')
    return {'project': manifest['project'], 'version': manifest['version'],
            'manifest_sha256': package['manifest_sha256'], 'source_root': manifest['source_root'],
            'signature': 'verified-host-Ed25519' if signature is not None else 'unsigned-development',
            'signer_key_id': signer_fingerprint, 'admission': 'development-only',
            'capabilities': caps, 'elf': elf_info}, sources


def create(args):
    binary = bounded_file(args.binary, END - ENTRY, 'binary')
    elf = bounded_file(args.elf, MAX_ELF, 'ELF')
    validate_elf(elf, binary)
    sources = []
    for value in args.source:
        path = Path(value)
        absolute = path.resolve()
        require(absolute.is_relative_to(ROOT), 'source files must be inside this checkout')
        relative = source_path(absolute.relative_to(ROOT).as_posix())
        sources.append({'path': relative, 'data': b64(bounded_file(absolute, MAX_SOURCE, 'source'))})
    sources.sort(key=lambda value: value['path'])
    descriptors = [{'path': source['path'], **descriptor(unb64(source['data'], MAX_SOURCE, 'source'))}
                   for source in sources]
    manifest = {
        'schema': 1, 'record_type': 'Release', 'project': args.name, 'version': args.version,
        'release_kind': 'NativeApplication', 'admission': 'development-only', 'machine': MACHINE,
        'runtime': RUNTIME, 'abi': 1, 'entry': ENTRY, 'binary': descriptor(binary),
        'elf': descriptor(elf), 'source_root': sha256(canonical(descriptors)), 'sources': descriptors,
        'lineage': args.parent, 'rights': {'license': args.license,
        'distribution_authority': args.distribution_authority}, 'capabilities': sorted(args.capability),
        'dependencies': [], 'toolchain_lock': json.loads((ROOT / 'toolchain.lock.json').read_text()),
        'evidence': args.evidence,
        'limitations': ['Guest compiler is not verified; source theorems do not establish binary correctness.',
                         'Release metadata Ed25519 verification runs on the bootstrap host; guest RSA authenticates the executable capsule header.',
                         'Local development release; no catalog or federation admission.',
                         'Package generations and personal objects are ephemeral.'] + args.limitation,
        'persistence': 'ephemeral', 'network': 'unavailable', 'signer': args.signer,
    }
    package = {'format': 'LTPKG-1', 'manifest': manifest, 'manifest_sha256': sha256(canonical(manifest)),
               'binary': b64(binary), 'elf': b64(elf), 'sources': sources, 'signature': None}
    if args.sign_key:
        public = public_der(args.sign_key)
        with tempfile.TemporaryDirectory(prefix='lt-sign-') as directory:
            message = Path(directory) / 'message'
            message.write_bytes(DOMAIN + canonical(manifest))
            signed = crypto(['pkeyutl', '-sign', '-inkey', args.sign_key,
                             '-rawin', '-in', message]).stdout
        package['signature'] = {'algorithm': 'Ed25519', 'public_key': b64(public),
                                'key_id': sha256(public), 'value': b64(signed)}
    report, _ = validate(package, enforce_authorization=False)
    data = canonical(package)
    require(len(data) <= MAX_PACKAGE, 'resulting package exceeds 4 MiB')
    write_new(args.output, data)
    return {**report, 'package_sha256': sha256(data), 'path': str(args.output)}


def check(path, **policy):
    package, data = read_package(path)
    report, _ = validate(package, **policy)
    return {**report, 'package_sha256': sha256(data)}


def export(path, output, **policy):
    package, raw = read_package(path)
    report, sources = validate(package, **policy)
    output = Path(output).absolute()
    require(output.parent.is_dir() and not output.exists(), 'export requires a new directory inside an existing parent')
    with tempfile.TemporaryDirectory(prefix='.lt-export-', dir=output.parent) as directory:
        tree = Path(directory) / 'export'
        tree.mkdir(mode=0o700)
        (tree / 'manifest.json').write_bytes(canonical(package['manifest']))
        (tree / 'release.ltpkg').write_bytes(raw)
        (tree / 'app.bin').write_bytes(unb64(package['binary'], END - ENTRY, 'binary'))
        (tree / 'app.elf').write_bytes(unb64(package['elf'], MAX_ELF, 'ELF'))
        for relative, content in sources:
            target = tree / 'source' / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        os.rename(tree, output)
    return {**report, 'export': str(output), 'package_sha256': sha256(raw)}


def parser():
    root = argparse.ArgumentParser(description='LemmaTrix native development package and host Ed25519 tools')
    commands = root.add_subparsers(dest='command', required=True)
    key = commands.add_parser('keygen', help='generate a disposable/local Ed25519 key using OS entropy')
    key.add_argument('--private', required=True, type=Path)
    key.add_argument('--public', required=True, type=Path)
    new = commands.add_parser('create', help='package an actual freestanding RISC-V ELF, raw image and source snapshot')
    new.add_argument('--name', required=True)
    new.add_argument('--version', required=True)
    new.add_argument('--elf', required=True, type=Path)
    new.add_argument('--binary', required=True, type=Path)
    new.add_argument('--source', required=True, action='append')
    new.add_argument('--capability', action='append', default=[])
    new.add_argument('--parent', action='append', default=[])
    new.add_argument('--license', default='NOASSERTION')
    new.add_argument('--distribution-authority', default='local-development-only; no distribution rights asserted')
    new.add_argument('--signer', default='local-developer')
    new.add_argument('--evidence', action='append', default=[])
    new.add_argument('--limitation', action='append', default=[])
    new.add_argument('--sign-key', type=Path)
    new.add_argument('--output', required=True, type=Path)
    for command in ('check', 'export'):
        item = commands.add_parser(command)
        item.add_argument('package', type=Path)
        item.add_argument('--allow-development', action='store_true')
        item.add_argument('--trust-key', action='append', default=[], type=Path)
        item.add_argument('--require-signature', action='store_true')
        item.add_argument('--approve-cap', action='append', default=[])
        if command == 'export':
            item.add_argument('--output', required=True, type=Path)
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command == 'keygen':
            result = {'algorithm': 'Ed25519', 'key_id': keygen(args.private, args.public),
                      'private': str(args.private), 'public': str(args.public)}
        elif args.command == 'create':
            result = create(args)
        else:
            policy = {'allow_development': args.allow_development, 'trust_keys': args.trust_key,
                      'approved_caps': args.approve_cap, 'require_signature': args.require_signature}
            if args.command == 'export':
                result = export(args.package, args.output, **policy)
            else:
                result = check(args.package, **policy)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (PackageError, OSError, subprocess.TimeoutExpired) as exc:
        print('lt package:', exc, file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
