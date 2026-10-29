#!/usr/bin/env python3
"""Bounded checks of the built guest, real compilers, and assembly backends."""
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'tools'))
import driver

BUILD = ROOT / 'build'
CHECK = BUILD / 'checks'
BACKENDS = ('qemu', 'x86_64', 'aarch64')
REPORT = {'scope': 'development evidence; not an MVP release gate', 'checks': {}}


def command(args, *, timeout=45, cwd=ROOT, env=None, successful=True):
    result = subprocess.run([str(a) for a in args], cwd=cwd, env=env,
                            capture_output=True, timeout=timeout)
    if successful and result.returncode:
        raise AssertionError(f"command exited {result.returncode}: {' '.join(str(a) for a in args)}\n"
                             + result.stdout.decode(errors='replace')
                             + result.stderr.decode(errors='replace'))
    return result


def sha(data):
    return hashlib.sha256(data).hexdigest()


def execute(backend, image, label, *, expected_exit=0):
    if backend == 'qemu':
        args = [driver.tool('qemu-system-riscv64'), '-M', 'virt', '-cpu', 'rv64',
                '-m', '16M', '-smp', '1', '-bios', 'none', '-nographic',
                '-monitor', 'none', '-kernel', image]
    elif backend == 'x86_64':
        args = [BUILD / 'lt-x86_64', image]
    else:
        args = [driver.tool('qemu-aarch64'), BUILD / 'lt-aarch64', image]
    result = command(args, successful=False)
    (CHECK / f'{label}-{backend}.log').write_bytes(result.stdout + result.stderr)
    expect(result.returncode == expected_exit,
           f'{backend}: expected exit {expected_exit}, got {result.returncode}: '
           + (result.stdout + result.stderr).decode(errors='replace'))
    return result.stdout


def expect(condition, message):
    if not condition:
        raise AssertionError(message)


def validate_trace(output, imported, *, transformed=None):
    transformed = imported.upper() if transformed is None else transformed
    for marker in (b'LT session ephemeral ABI1', b'REVISION parent=1',
                   b'SHARE object=3', b'REVOKE object=3', b'DENIED pid=1',
                   b'DENIED pid=2', b'FAULT pid=2', b'SESSION PASS',
                   b'INSTALL generation=1', b'UPDATE generation=2', b'ROLLBACK generation=1',
                   b'REJECT package=1', b'REJECT package=2', b'REJECT package=3', b'REJECT package=4',
                   b'HEALTHY after fault'):
        expect(marker in output, f'missing guest evidence {marker!r}')
    if imported:
        expect(imported in output, 'application did not print the actual imported bytes')
        expect(output.count(transformed) >= 2,
               'both compartments must read the actual transformed object content')
    expected_objects = [b'3', b'5', b'7']
    expect(re.findall(rb'SHARE object=([0-9a-f]+)', output) == expected_objects,
           'denied calls changed protected object allocation or package/object lineage')
    expect(re.findall(rb'REVOKE object=([0-9a-f]+)', output) == expected_objects,
           'not every shared generation was revoked')
    fault_record = re.search(rb'FAULT pid=2\n([0-9a-f]{16})\n([0-9a-f]{16})\n', output)
    expect(fault_record and int(fault_record[1], 16) == 13 and int(fault_record[2], 16) == 0x80000000,
           'observer did not fault on the intended supervisor-only load')
    shared = output.index(b'SHARE object=3')
    revoked = output.index(b'REVOKE object=3', shared)
    expect(shared < revoked, 'revocation must follow sharing')
    expect(b'DENIED pid=2' in output[revoked:], 'revoked client access was not exercised')
    fault = output.index(b'FAULT pid=2')
    expect(output.index(b'HEALTHY after fault') > fault, 'healthy continuation marker preceded the actual user fault')
    expect(b'REVISION parent=1' in output[fault:], 'no useful healthy application operation after the other app faulted')
    preemptions = re.search(rb'PREEMPTIONS=([0-9a-f]+)', output)
    expect(preemptions and int(preemptions[1], 16) > 0, 'busy user compartment did not exercise timer preemption')
    for earlier, later in ((b'INSTALL generation=1', b'UPDATE generation=2'),
                           (b'UPDATE generation=2', b'ROLLBACK generation=1')):
        expect(output.index(earlier) < output.index(later), 'package lifecycle events are out of order')
    # Counts of timer and waiting-denial messages vary with host scheduling.
    return Counter(re.findall(rb'(?:REVISION parent=[0-9a-f]+|SHARE object=[0-9a-f]+|'
                              rb'REVOKE object=[0-9a-f]+|FAULT pid=[0-9a-f]+|SESSION PASS|INSTALL generation=[0-9a-f]+|'
                              rb'UPDATE generation=[0-9a-f]+|ROLLBACK generation=[0-9a-f]+|REJECT package=[0-9a-f]+)', output))


def probe():
    obj, elf, image = [CHECK / ('isa.' + suffix) for suffix in ('o', 'elf', 'bin')]
    driver.asm(ROOT / 'emulator/probes.S', obj)
    command([driver.tool('ld.lld'), '-m', 'elf64lriscv', '--no-relax',
             '-Ttext=0x80000000', obj, '-o', elf])
    command([driver.tool('llvm-objcopy'), '-O', 'binary', elf, image])
    for backend in BACKENDS:
        output = execute(backend, image, 'isa')
        expect(output == b'ISA MMU TIMER PASS\n', f'{backend}: ISA/MMU/timer probe failed')
    REPORT['checks']['isa_mmu_timer'] = {
        'image_sha256': sha(image.read_bytes()), 'backends': list(BACKENDS),
        'properties': ['signed/unsigned arithmetic and branch edges', 'RV64 W sign extension',
                       'load widths', 'division zero/overflow', 'high products',
                       'illegal instruction trap and mret', 'machine timer interrupt',
                       'Sv39 M/S/U transitions', 'kernel and UART user-access denial',
                       'privileged CSR denial']}


def lean_environment():
    return dict(os.environ, LEAN_PATH=str(ROOT) + ':' + str(CHECK),
                PATH=str(Path(driver.tool('lean')).parent) + ':' + os.environ['PATH'])


def compile_module(name, source):
    path = CHECK / (name + '.lean')
    path.write_text(source, encoding='utf-8')
    command([driver.tool('lean'), '-Dcompiler.extract_closed=false', '-o',
             CHECK / (name + '.olean'), path], cwd=CHECK, env=lean_environment())


def emit_module(module, output, root, *, successful=True):
    return command([driver.tool('lean'), '-Dcompiler.extract_closed=false', '--run',
                    ROOT / 'Compiler/Main.lean', module, output, root],
                   env=lean_environment(), successful=successful)


def rejected_language():
    cases = {
        'CheckHeap': ('namespace Check\ndef entry (x : UInt64) : String :=\n'
                      '  if x == 0 then "allocated" else "heap"\nend Check\n'),
        'CheckExtern': ('namespace Check\n@[never_extract, extern "lt_unapproved_host"]\n'
                        'opaque forbidden (x : UInt64) : UInt64\n'
                        'def entry (x : UInt64) : UInt64 := forbidden x\nend Check\n'),
    }
    diagnostics = {}
    for name, source in cases.items():
        compile_module(name, source)
        output = CHECK / (name + '.S')
        output.unlink(missing_ok=True)
        result = emit_module(name, output, 'Check.entry', successful=False)
        message = (result.stdout + result.stderr).decode(errors='replace')
        expect(result.returncode != 0 and not output.exists(),
               f'{name}: unsupported Lean unexpectedly emitted executable assembly')
        expect('freestanding compiler:' in message, f'{name}: missing useful compiler diagnostic')
        diagnostics[name] = message.strip()
    REPORT['checks']['unsupported_language_and_extern_rejected'] = diagnostics


def source_change(image, imported):
    original = (ROOT / 'Guest/Workbench.lean').read_text(encoding='utf-8')
    expect('upper buffer len t' in original, 'source-change check needs the actual Workbench transform')
    changed = original.replace('upper buffer len t', 'store8 buffer 90 t', 1)
    compile_module('CheckMutation', changed)
    assembly = CHECK / 'mutation.S'
    emit_module('CheckMutation', assembly, 'Guest.appMain')
    objects = []
    for index, source in enumerate((assembly, ROOT / 'runtime/app.S', ROOT / 'runtime/primitives.S')):
        obj = CHECK / f'mutation{index}.o'
        driver.asm(source, obj)
        objects.append(obj)
    elf = CHECK / 'mutation.elf'
    command([driver.tool('ld.lld'), '-m', 'elf64lriscv', '--no-relax',
             '-T', ROOT / 'runtime/app.ld', *objects, '-o', elf])
    app = CHECK / 'mutation.bin'
    command([driver.tool('llvm-objcopy'), '-O', 'binary', elf, app])
    expect(app.read_bytes() != (BUILD / 'workbench.bin').read_bytes(),
           'Lean source/control-flow change did not alter the emitted application')
    # Install the compiled variant into a copy of the same development image.
    # The canonical kernel, imported personal text and checked-in sources stay intact.
    payload = bytearray(image.read_bytes())
    app_bytes = app.read_bytes()
    transformed = b'Z' + imported[1:] if imported else b''
    if not imported or transformed == imported.upper():
        imported = b'Lean source mutation 37\n'
        payload[0x800000:0x800008] = len(imported).to_bytes(8, 'little')
        payload[0x800008:0x800008 + len(imported)] = imported
        baseline = CHECK / 'source-change-baseline.bin'
        baseline.write_bytes(payload)
        validate_trace(execute('x86_64', baseline, 'mutation-baseline'), imported)
    # Boot's package service loads the actual signed development capsule.
    import capsule
    record = capsule.build_capsule(app_bytes, version=1, caps=7, signing_key=capsule.development_key())
    payload[0xa00000:0xa00000 + len(record)] = record
    mutated_image = CHECK / 'source-change.bin'
    mutated_image.write_bytes(payload)
    output = execute('x86_64', mutated_image, 'source-change')
    transformed = b'Z' + imported[1:] if imported else b''
    validate_trace(output, imported, transformed=transformed)
    REPORT['checks']['actual_lean_source_change'] = {
        'source': 'Guest.Workbench.runWorkbench: upper call replaced by store8 buffer 90',
        'backend': 'x86_64', 'application_sha256': sha(app_bytes),
        'image_sha256': sha(payload), 'observed_changed_content_hex': transformed.hex(),
        'limit': 'unverified backend; this demonstrates compilation, not compiler correctness'}


def invalid_signature(image):
    import capsule
    data = bytearray(image.read_bytes())
    data[0xa00000 + capsule.SIGNATURE_OFFSET] ^= 1
    negative = CHECK / 'invalid-initial-signature.bin'
    negative.write_bytes(data)
    output = execute('x86_64', negative, 'invalid-initial-signature', expected_exit=1)
    expect(b'SESSION PASS' not in output and b'REVISION parent=' not in output,
           'invalid initial release signature reached the application')
    REPORT['checks']['guest_invalid_initial_signature'] = {
        'backend': 'x86_64', 'exit': 1, 'image_sha256': sha(data),
        'mutation': 'one RSA signature bit changed; header and code unchanged'}


def generic_user_fault(image):
    data = bytearray(image.read_bytes())
    # Attempt CSRRW to the read-only cycle CSR before any observer SDK call.
    data[0x500000:0x500004] = (0xc0001073).to_bytes(4, 'little')
    negative = CHECK / 'illegal-observer.bin'
    negative.write_bytes(data)
    evidence = {}
    for backend in BACKENDS:
        output = execute(backend, negative, 'illegal-observer')
        record = re.search(rb'FAULT pid=2\n([0-9a-f]{16})\n([0-9a-f]{16})\n', output)
        expect(record and int(record[1], 16) == 2, f'{backend}: privileged CSR misuse did not cause illegal-instruction fault')
        fault = output.index(b'FAULT pid=2')
        expect(b'REVISION parent=1' in output[fault:] and b'SESSION PASS' in output[fault:],
               f'{backend}: early unexpected user fault prevented healthy object/package work')
        expect(b'UPDATE generation=2' in output[fault:] and b'ROLLBACK generation=1' in output[fault:],
               f'{backend}: package lifecycle did not survive independent client failure')
        evidence[backend] = {'cause': int(record[1], 16), 'tval': int(record[2], 16)}
    REPORT['checks']['generic_early_user_fault_contained'] = {
        'image_sha256': sha(data), 'backends': evidence}


def proof_dependencies():
    names = ('revoked_denies', 'stale_denies', 'missing_right_denies', 'denied_preserves_generation')
    source = 'import Guest.Policy\n' + ''.join(f'#print axioms Guest.Policy.{name}\n' for name in names)
    path = CHECK / 'ProofAudit.lean'
    path.write_text(source, encoding='utf-8')
    result = command([driver.tool('lean'), path], env=lean_environment())
    output = (result.stdout + result.stderr).decode()
    expect('sorryAx' not in output, 'claimed policy evidence depends on sorryAx')
    (CHECK / 'proof-dependencies.log').write_text(output, encoding='utf-8')
    REPORT['checks']['proof_dependencies'] = output.strip()


def main():
    CHECK.mkdir(parents=True, exist_ok=True)
    image = BUILD / 'guest.bin'
    data = image.read_bytes()
    image_hash = sha(data)
    length = int.from_bytes(data[0x800000:0x800008], 'little')
    expect(length <= 256, 'invalid imported fixture length')
    imported = data[0x800008:0x800008 + length]
    REPORT['image_sha256'] = image_hash
    REPORT['toolchain_versions'] = {name: driver.LOCK[name] for name in ('lean', 'llvm', 'qemu')}
    REPORT['emulator_binaries'] = {name: sha((BUILD / ('lt-' + name)).read_bytes())
                                   for name in ('x86_64', 'aarch64')}
    REPORT['guest_artifacts'] = {name: sha((BUILD / (name + '.elf')).read_bytes())
                                 for name in ('kernel', 'workbench', 'workbench-v2', 'observer')}
    REPORT['host'] = {'machine': platform.machine(), 'system': platform.system(),
                      'aarch64_execution': 'Linux/AArch64 executable under qemu-aarch64; not native hardware'}
    try:
        traces = {}
        for backend in BACKENDS:
            output = execute(backend, image, 'guest')
            traces[backend] = validate_trace(output, imported)
            print(f'PASS guest {backend}: actual object transformation, sharing, revocation, fault containment', flush=True)
        expect(traces['qemu'] == traces['x86_64'] == traces['aarch64'],
               'same image produced different semantic event counts across backends')
        REPORT['checks']['same_guest_image'] = list(BACKENDS)
        again = execute('x86_64', image, 'ephemeral-reset')
        expect(validate_trace(again, imported) == traces['x86_64'],
               'fresh ephemeral boot retained previous object generations or grants')
        REPORT['checks']['ephemeral_reset'] = 'fresh process restarts the guest with its original image; no host vault used'
        probe()
        print('PASS same-byte ISA, Sv39 privilege, trap and timer probes on all backends', flush=True)
        rejected_language()
        source_change(image, imported)
        invalid_signature(image)
        generic_user_fault(image)
        print('PASS actual Lean source change changes guest behavior; unsupported heap and extern rejected', flush=True)
        proof_dependencies()
        expect(sha(image.read_bytes()) == image_hash, 'acceptance changed the canonical guest image')
        REPORT['result'] = 'PASS'
    except Exception as error:
        REPORT['result'] = 'FAIL'
        REPORT['error'] = str(error)
        raise
    finally:
        (BUILD / 'acceptance.json').write_text(json.dumps(REPORT, indent=2) + '\n', encoding='utf-8')
    print('ACCEPTANCE PASS; evidence: build/acceptance.json and build/checks/', flush=True)


if __name__ == '__main__':
    main()
