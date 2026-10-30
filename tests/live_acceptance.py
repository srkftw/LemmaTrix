"""Acceptance through the live guest's actual management and IPC interfaces.

The host transports bytes, selects explicit fixtures and checks outputs. Guest
services own objects, process identity, authorization, signatures and retention.
No kernel image is rebuilt or patched by these checks.
"""
from __future__ import annotations
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import socket
import signal
import struct
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import driver
import live
import releases
import capsule
import packaging as pkg
JOURNAL = []


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def passed(report, description, **details):
    entry = dict(check=description, result='pass', **details)
    report.append(entry)
    JOURNAL.append(entry)
    print('  PASS', description, flush=True)


def fields(raw):
    require(len(raw) >= 64, 'service reply is shorter than its versioned header')
    return struct.unpack_from('<8Q', raw)


def command(op, h=0, a=0, b=0, c=0, d=0, e=0, data=b''):
    return struct.pack('<8Q', op, h, a, b, c, d, e, 1) + data


def value(raw):
    require(len(raw) >= 16, 'management result is truncated')
    return struct.unpack_from('<Q', raw, 8)[0]


def rejected(operation, label):
    try:
        operation()
    except ValueError:
        return
    raise AssertionError(label + ': guest accepted forbidden operation')


class Session:
    def __init__(self, backend, directory, vault=None, readonly=False):
        self.backend = backend
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.socket_directory = Path(tempfile.mkdtemp(prefix='lt-live-', dir='/tmp'))
        self.path = self.socket_directory / 'portal.sock'
        self.closed = False
        self.log = (self.directory / 'transport.log').open('wb')
        args = [sys.executable, ROOT / 'lt', 'session', '--backend', backend, '--socket', self.path]
        if vault is not None:
            args += ['--vault', vault]
        if readonly:
            args += ['--vault-readonly']
        self.process = subprocess.Popen(list(map(str, args)), cwd=ROOT, stdout=self.log, stderr=self.log, start_new_session=True)
        deadline = time.monotonic() + 75
        while not self.path.exists():
            if self.process.poll() is not None:
                raise RuntimeError('session transport exited before socket creation; see ' + str(self.directory / 'transport.log'))
            if time.monotonic() >= deadline:
                raise TimeoutError('session transport did not create its socket')
            time.sleep(0.01)
        try:
            self.client = live.Client(self.path, timeout=180)
            # The actual guest emits this after its UART reset. Sending before
            # it is ready can lose bytes on QEMU's finite hardware FIFO.
            while len(self.client.buffer) < 32:
                data = self.client.stream.recv(65536)
                require(data, 'guest exited before management readiness')
                self.client.buffer.extend(data)
            ready = struct.unpack_from('<4sIQQQ', self.client.buffer)
            require(ready == (live.REPLY, 0, 0, 0, 0), 'guest emitted an invalid initial readiness frame')
            del self.client.buffer[:32]
            require(value(self.client.request(1)) == 2, 'live ABI ping did not return version 2')
        except BaseException:
            self.abort()
            raise

    def close(self):
        if self.closed:
            return
        if getattr(self, 'client', None) is not None:
            with contextlib.suppress(EOFError, OSError, ValueError):
                self.client.request(70)
            self.client.close()
            self.client = None
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(self.process.pid, signal.SIGTERM)
            self.process.wait(timeout=10)
        self.log.close()
        self.path.unlink(missing_ok=True)
        Path(str(self.path)+'.client.lock').unlink(missing_ok=True)
        self.socket_directory.rmdir()
        self.closed = True
        require(self.process.returncode == 0, 'guest session did not terminate successfully')

    def abort(self):
        if self.closed:
            return
        if getattr(self, 'client', None) is not None:
            self.client.close()
            self.client = None
        with contextlib.suppress(ProcessLookupError):
            os.killpg(self.process.pid, signal.SIGKILL)
        self.process.wait(timeout=10)
        self.log.close()
        self.path.unlink(missing_ok=True)
        Path(str(self.path)+'.client.lock').unlink(missing_ok=True)
        self.socket_directory.rmdir()
        self.closed = True

    def __enter__(self):
        return self.client

    def __exit__(self, kind, error, traceback):
        if kind is None:
            self.close()
        else:
            self.abort()


def processes(client):
    raw = client.request(2)
    require(len(raw) == 384, 'process table does not contain the bounded 12 slots')
    return [dict(zip(('instance', 'state', 'rights', 'exit_cause'), struct.unpack_from('<4Q', raw, index)))
            for index in range(0, len(raw), 32)]


def smoke(backend, directory, data):
    with Session(backend, directory) as client:
        rows = processes(client)
        require(all(any((row['instance'] & 255) == pid and row['state'] in (1, 2, 3, 4) for row in rows)
                    for pid in (1, 2, 3)), 'launcher, Objects and Vault did not boot as live compartments')
        handle = client.import_object(data)
        require(client.read_object(handle) == data, 'chunked live object read differs from imported bytes')
        require(client.read_object(handle, export=True) == data, 'explicit export differs from imported bytes')
        metadata, digest = client.objects(5, handle)
        require(metadata[2] == len(data) and digest == hashlib.sha256(data).digest(), 'guest metadata hash/size mismatch')
        return {'backend': backend, 'result': 'pass', 'check': 'one live session, 64 KiB import/read/export and metadata',
                'bytes': len(data), 'sha256': digest.hex(), 'handle': handle}


def app(client, instance, operation, handle=0, a=0, b=0, data=b'', success=True):
    try:
        raw = client.request(150, struct.pack('<Q', instance) + command(operation, handle, a, b, data=data))
    except ValueError as error:
        state = [row for row in processes(client) if row['instance'] == instance] if success else 'expected denial'
        raise ValueError(f'app operation {operation}, instance {instance}, state {state}: {error}') from error
    header = fields(raw)
    if success:
        require(header[0] == 0, 'native app rejected a permitted operation with status ' + str(header[0]))
    else:
        require(header[0] != 0, 'native app accepted a forbidden operation')
    return header, raw[64:]


def trust(client, name, private):
    modulus = capsule.modulus(private)
    answer = client.request(10, releases.project(name) + modulus)
    require(answer == hashlib.sha256(modulus).digest(), 'trusted publisher identity differs from original key')


def release_file(binary, name, version, mask, private, directory, suffix='', parent=None):
    sources = [ROOT / 'Guest/LiveApps.lean', ROOT / 'Guest/LiveSDK.lean']
    if Path(binary).name.startswith('check-'):
        sources.append(ROOT / 'build/LiveAcceptance.lean')
    raw, manifest = releases.make(binary, name, version, mask, private,
                                  sources=sources,
                                  parent=parent, license='NOASSERTION')
    path = directory / (name + '-' + version + suffix + '.ltrel')
    pkg.write_new(path, raw)
    pkg.write_new(Path(str(path) + '.manifest.json'), pkg.canonical(manifest))
    return path, releases.inspect(raw)


def install(client, path):
    info = client.stage(path)
    rejected(lambda: client.request(24), 'activation without exact release approval')
    client.request(23, bytes.fromhex(info['release_id']) + struct.pack('<Q', info['rights']))
    slot = value(client.request(24))
    return slot, info


def active(client, name):
    header = client.request(29, releases.project(name))
    require(len(header) == 512, 'active release metadata is truncated')
    return header[160:192].hex()


def start(client, slot):
    return value(client.request(25, struct.pack('<Q', slot)))


def stop(client, identity):
    client.request(26, struct.pack('<Q', identity))


def row_for(client, identity):
    matches = [row for row in processes(client) if row['instance'] == identity]
    require(len(matches) == 1, 'kernel process identity was not found exactly once')
    return matches[0]


def host_counts(data):
    words, inside = 0, False
    for byte in data:
        whitespace = byte in (32, 9, 10, 13)
        if not whitespace and not inside:
            words += 1
        inside = not whitespace
    return words, data.count(b'\n')


def build_extra_apps(directory):
    # Host compilation happens while the original OS session is still alive.
    import live_build
    source = ROOT / 'build/LiveAcceptance.lean'
    source.write_text('''import Guest.LiveApps
namespace Guest.LiveAcceptance
open Guest.LiveSDK
partial def variantServe (endpoint t : UInt64) : UInt64 :=
  let length := receive endpoint t
  if length == error then variantServe endpoint length else
    let caller := load64 incoming length
    let replyToken := load64 (incoming+8) length
    let rights := load64 (incoming+16) length
    let abi := load64 (incoming+24) length
    let t := if length >= 96 && load64 command length == 20 then store64 (command+16) 2 length else length
    let result := if length >= 96 && abi == 2 && (rights &&& 0x100000000) != 0 then
      Guest.LiveApps.dispatch 1 caller rights (length-32) t else Guest.LiveApps.fail 1 t
    variantServe endpoint (reply replyToken result result)
def variantMain (initial : UInt64) : UInt64 := variantServe (self initial) initial
partial def spin (value : UInt64) : UInt64 := spin (value+1)
def busyMain (initial : UInt64) : UInt64 := spin initial
def faultMain (initial : UInt64) : UInt64 := load64 0x80000000 initial
partial def consoleServe (endpoint t : UInt64) : UInt64 :=
  let length := receive endpoint t
  if length == error then consoleServe endpoint length else
    let replyToken := load64 (incoming+8) length
    let result := if length >= 96 && load64 (incoming+24) length == 2 then
      console (command+64) (length-96) length else error
    let t := zero wire 8 result
    let t := store64 (wire+8) result t
    consoleServe endpoint (reply replyToken 64 t)
def consoleMain (initial : UInt64) : UInt64 := consoleServe (self initial) initial
end Guest.LiveAcceptance
''')
    driver.lean(['-o', source.with_suffix('.olean'), source])
    result = {}
    for kind in ('variant', 'busy', 'fault', 'console'):
        result[kind] = live_build.artifact('build.LiveAcceptance', 'Guest.LiveAcceptance.' + kind + 'Main',
                                            'check-' + kind)
    return result


def application_checks(client, directory, selected, capacity, report):
    publisher, public = directory / 'publisher.pem', directory / 'publisher.pub'
    capsule.generate_key(publisher, public)
    other, other_public = directory / 'untrusted.pem', directory / 'untrusted.pub'
    capsule.generate_key(other, other_public)
    masks = {'workbench': 1 | 4 | 8 | 16 | 64, 'inspector': 1, 'worker': 1}
    installed, info = {}, {}
    for name in ('workbench', 'inspector', 'worker'):
        project = 'accept-' + name
        trust(client, project, publisher)
        path, _ = release_file(ROOT / f'build/live/{name}.bin', project, '1.0.0', masks[name], publisher, directory)
        slot, meta = install(client, path)
        installed[name] = {'slot': slot, 'instance': start(client, slot), 'path': path}
        info[name] = meta
    identities = [installed[name]['instance'] for name in installed]
    require(len(set(identities)) == 3 and all((item & 255) >= 4 for item in identities),
            'three native clients do not have distinct kernel-owned user instances')
    for name, proc in installed.items():
        require(row_for(client, proc['instance'])['rights'] == masks[name], 'declared process authority differs from kernel authority')
    passed(report, 'three original-publisher signed native clients installed and launched after OS boot',
           instances=dict(zip(installed, identities)))
    big = client.import_object(capacity)
    selected_handle = client.import_object(selected)
    require(client.read_object(big, export=True) == capacity, '64 KiB explicit export differs from selected fixture')
    source_meta, source_hash = client.objects(5, big)
    wb = installed['workbench']['instance']
    inspector = installed['inspector']['instance']
    worker = installed['worker']['instance']
    wb_grant = client.objects(6, big, wb, 13)[0][1]
    inspector_grant = client.objects(6, big, inspector, 1)[0][1]
    worker_grant = client.objects(6, big, worker, 1)[0][1]
    metadata, native_digest = app(client, inspector, 22, inspector_grant)
    require(metadata[2] == len(capacity) and native_digest == hashlib.sha256(capacity).digest(), 'native inspector metadata differs from source')
    counts, digest = app(client, worker, 21, worker_grant)
    expected_words, expected_lines = host_counts(capacity)
    require((counts[1], counts[2], counts[3]) == (expected_words, len(capacity), expected_lines)
            and digest == source_hash, 'independent native word/line/hash client computed an incorrect result')
    revision, _ = app(client, wb, 20, wb_grant, 1)
    derived = revision[1]
    uppercase = bytes(byte - 32 if 97 <= byte <= 122 else byte for byte in capacity)
    require(client.read_object(derived, export=True) == uppercase, 'native streamed 64 KiB transformation is incorrect')
    derived_meta, _ = client.objects(5, derived)
    require(derived_meta[3] == source_meta[7], 'native revision lost immutable source lineage')
    passed(report, '64 KiB source reaches native inspector, independent word counter and streamed revision',
           source_sha256=source_hash.hex(), revision_sha256=hashlib.sha256(uppercase).hexdigest())
    # Exact process identity, grant scope, caller rights and export distinctions.
    app(client, inspector, 4, big, 0, 16, success=False)
    app(client, inspector, 14, inspector_grant, 0, 16, success=False)
    app(client, inspector, 1, 0, 4, 1, data=hashlib.sha256(b'test').digest(), success=False)
    rejected(lambda: client.objects(6, big, inspector, 13), 'delegation beyond target declared rights')
    rejected(lambda: client.objects(6, big, wb ^ 0x100, 1), 'forged target process generation')
    client.objects(7, big, inspector_grant)
    app(client, inspector, 22, inspector_grant, success=False)
    reused = client.objects(6, big, inspector, 1)[0][1]
    require(reused != inspector_grant, 'revoked handle was reused without a new generation')
    app(client, inspector, 22, inspector_grant, success=False)
    app(client, inspector, 22, reused)
    require(client.read_object(big) == capacity, 'denied requests changed protected source bytes')
    passed(report, 'forged, revoked, stale, out-of-scope and export authority denied without source mutation')
    # Bad commit hashes cannot expose or activate staged content.
    stage = client.objects(1, 0, 4, 1, 1, data=hashlib.sha256(b'good').digest())[0][1]
    client.objects(2, stage, 0, data=b'bad!')
    rejected(lambda: client.objects(3, stage, data=hashlib.sha256(b'bad!').digest()), 'begin commitment mismatch')
    rejected(lambda: client.objects(4, stage, 0, 4), 'uncommitted object read')
    client.objects(13, stage)
    # The actual native byte editor creates a new immutable object, not a host edit.
    edit_grant = client.objects(6, selected_handle, wb, 13)[0][1]
    offset = min(16, len(selected))
    deleted = min(5, len(selected) - offset)
    inserted = b'PATCH'[:deleted] if len(selected) == 65536 else b'PATCH'
    edited, _ = app(client, wb, 23, edit_grant, offset, deleted, inserted)
    expected = selected[:offset] + inserted + selected[offset + deleted:]
    require(client.read_object(edited[1], export=True) == expected, 'native selected-source edit differs from exact patch')
    require(client.read_object(selected_handle) == selected, 'native edit modified its immutable parent')
    passed(report, 'native Workbench byte edit preserves source and publishes exact revision')
    original_active = active(client, 'accept-workbench')
    wrong_path, _ = release_file(ROOT / 'build/live/workbench.bin', 'accept-workbench', '2.0.0', masks['workbench'], other, directory, '-wrong-key')
    rejected(lambda: client.stage(wrong_path), 'untrusted original publisher')
    valid = installed['workbench']['path'].read_bytes()
    for label, position in (('tampered-code', 768), ('invalid-signature', 512)):
        damaged = bytearray(valid)
        damaged[position] ^= 1
        path = directory / (label + '.ltrel')
        path.write_bytes(damaged)
        rejected(lambda path=path: client.stage(path), label)
        require(active(client, 'accept-workbench') == original_active, 'rejected release changed active generation')
    wrong_parent, _ = release_file(ROOT / 'build/live/workbench.bin', 'accept-workbench', '1.1.0', masks['workbench'], publisher, directory, '-wrong-parent')
    candidate = client.stage(wrong_parent)
    client.request(23, bytes.fromhex(candidate['release_id']) + struct.pack('<Q', candidate['rights']))
    rejected(lambda: client.request(24), 'original signer update omits authenticated parent continuity')
    client.request(3)
    require(active(client, 'accept-workbench') == original_active, 'rejected parent mismatch changed active generation')
    escalation, escalation_meta = release_file(ROOT / 'build/live/workbench.bin', 'accept-workbench', '3.0.0', masks['workbench'] | 2, publisher, directory, '-escalation', parent=original_active)
    candidate = client.stage(escalation)
    rejected(lambda: client.request(24), 'authority increase without approval')
    rejected(lambda: client.request(23, bytes.fromhex(candidate['release_id']) + struct.pack('<Q', masks['workbench'])),
             'approval mask differs from signed candidate')
    client.request(3)
    require(active(client, 'accept-workbench') == original_active, 'cancelled escalation changed active generation')
    # Compile useful new application behavior while this exact OS remains running.
    before_compile = hashlib.sha256((ROOT / 'build/live/guest.bin').read_bytes()).hexdigest()
    extras = build_extra_apps(directory)
    require(hashlib.sha256((ROOT / 'build/live/guest.bin').read_bytes()).hexdigest() == before_compile,
            'compiling independent user releases modified the OS image')
    require(value(client.request(1)) == 2, 'host app compilation stopped the running OS')
    variant, variant_meta = release_file(extras['variant'], 'accept-workbench', '2.0.0', masks['workbench'], publisher,
                                         directory, parent=original_active)
    new_slot, meta = install(client, variant)
    require(active(client, 'accept-workbench') == meta['release_id'], 'valid release was not activated atomically')
    # Invalid restart cannot stop the existing healthy process.
    rejected(lambda: client.request(27, struct.pack('<2Q', wb, 16)), 'restart with empty release slot')
    require(row_for(client, wb)['state'] in (1, 2, 3), 'failed restart stopped the previous app')
    next_wb = value(client.request(27, struct.pack('<2Q', wb, new_slot)))
    require(next_wb != wb and (next_wb & 255) == (wb & 255), 'restart did not advance process generation')
    rejected(lambda: app(client, wb, 22, wb_grant), 'stale process endpoint')
    app(client, next_wb, 4, wb_grant, 0, 16, success=False)
    next_grant = client.objects(6, selected_handle, next_wb, 13)[0][1]
    rotated, _ = app(client, next_wb, 20, next_grant, 1)
    rot13 = bytes((byte - 97 + 13) % 26 + 97 if 97 <= byte <= 122 else byte for byte in selected)
    require(client.read_object(rotated[1], export=True) == rot13, 'compiled second version did not change native behavior')
    rollback_slot = value(client.request(28, releases.project('accept-workbench')))
    require(rollback_slot == installed['workbench']['slot'] and active(client, 'accept-workbench') == original_active,
            'explicit rollback did not select previous authenticated generation')
    wb_rollback = value(client.request(27, struct.pack('<2Q', next_wb, rollback_slot)))
    rollback_grant = client.objects(6, selected_handle, wb_rollback, 13)[0][1]
    after_rollback, _ = app(client, wb_rollback, 20, rollback_grant, 1)
    require(client.read_object(after_rollback[1], export=True) == bytes(byte - 32 if 97 <= byte <= 122 else byte for byte in selected),
            'rolled-back native computation differs from original version')
    client.request(30, bytes.fromhex(meta['release_id']))
    rejected(lambda: start(client, new_slot), 'start of explicitly revoked release')
    rejected(lambda: client.request(27, struct.pack('<2Q', wb_rollback, new_slot)), 'restart into revoked release')
    require(row_for(client, wb_rollback)['state'] in (1, 2, 3)
            and active(client, 'accept-workbench') == original_active, 'revoked restart disrupted the active app')
    passed(report, 'original signatures, exact approval, cancellation, failed restart, compiled update and explicit rollback',
           publisher_key_id=info['workbench']['publisher_key_id'], v1=original_active, v2=meta['release_id'])
    # Non-yielding and faulting native code has no authority over healthy peers.
    for name in ('busy', 'fault'):
        project = 'accept-' + name
        trust(client, project, publisher)
        path, _ = release_file(extras[name], project, '1.0.0', 0, publisher, directory)
        slot, _ = install(client, path)
        instance = start(client, slot)
        require(value(client.request(1)) == 2, name + ' app monopolized or stopped management')
        counted, _ = app(client, worker, 21, worker_grant)
        require(counted[1] == expected_words, name + ' app stopped the healthy native worker')
        status = row_for(client, instance)
        if name == 'busy':
            require(status['state'] == 1, 'non-yielding app did not remain runnable under timer preemption')
            # Send an authentic request to the unresponsive endpoint, then a
            # second control request. The UART wakes/cancels the pending RPC.
            client.counter = max(client.counter + 1, time.time_ns())
            payload = struct.pack('<Q', instance) + command(22)
            client.stream.sendall(struct.pack('<4sIQQQ', live.MAGIC, len(payload), client.counter, 150, 0) + payload)
            time.sleep(0.1)
            began = time.monotonic()
            require(value(client.request(1)) == 2, 'pending unresponsive RPC blocked management')
            require(time.monotonic() - began < 10, 'management waited for the full unresponsive app deadline')
            stop(client, instance)
        else:
            require(status['state'] == 5 and status['exit_cause'] == 13, 'malicious kernel read was not contained as a user page fault')
    passed(report, 'timer preempts non-yielding user code, cancels blocked management RPC and contains kernel-memory access')
    # Apps may print only with their exact console right. Even an authorized
    # binary reply-header injection is framed as encoded application output.
    for name, mask in (('console-denied', 0), ('console-authorized', 128)):
        project = 'accept-' + name
        trust(client, project, publisher)
        path, _ = release_file(extras['console'], project, '1.0.0', mask, publisher, directory)
        slot, _ = install(client, path)
        instance = start(client, slot)
        rid = max(client.counter + 1, time.time_ns())
        fake = struct.pack('<4sIQQQ2Q', live.REPLY, 0, rid, 16, 0, 0, 0xDEADBEEF)
        payload = struct.pack('<Q', instance) + command(1, data=fake)
        raw = client.request(150, payload, rid=rid)
        client.counter = rid
        answer = fields(raw)
        require(len(raw) == 64 and answer[0] == 0 and answer[1] == (0 if mask else 0xffffffffffffffff),
                'console authority or binary control-frame isolation failed')
        require(value(client.request(1)) == 2, 'application console output corrupted management framing')
        stop(client, instance)
    passed(report, 'console right is enforced and authorized binary reply-frame injection remains encoded app output')
    client.request(11, bytes.fromhex(info['workbench']['publisher_key_id']))
    rejected(lambda: start(client, installed['worker']['slot']), 'future launch after publisher trust revocation')
    rejected(lambda: client.request(27, struct.pack('<2Q', wb_rollback, rollback_slot)), 'restart after publisher trust revocation')
    require(row_for(client, wb_rollback)['state'] in (1, 2, 3), 'revoked publisher restart stopped an existing process')
    app(client, worker, 21, worker_grant)
    trust(client, 'accept-workbench', publisher)
    passed(report, 'release and publisher revocation block future launch/restart without stopping healthy existing compartments')
    return {'selected_handle': selected_handle, 'capacity_handle': big, 'selected': selected,
            'capacity': capacity, 'worker': worker, 'worker_grant': worker_grant,
            'workbench': wb_rollback, 'installed': installed, 'publisher': publisher, 'public': public}


def service_restart_checks(client, state, report):
    service = next(row['instance'] for row in processes(client) if (row['instance'] & 255) == 2)
    client.request(32, struct.pack('<Q', service))
    require(row_for(client, service)['state'] == 5, 'Objects service did not stop')
    rejected(lambda: client.objects(5, state['capacity_handle']), 'request to stopped Objects service')
    replacement = value(client.request(33, struct.pack('<Q', service)))
    require(replacement != service and (replacement & 255) == 2, 'service restart did not advance exact kernel identity')
    rejected(lambda: client.request(32, struct.pack('<Q', service)), 'stale service control identity')
    rejected(lambda: client.objects(5, state['capacity_handle']), 'old service epoch object handle')
    app(client, state['worker'], 21, state['worker_grant'], success=False)
    fresh = client.import_object(state['selected'])
    require(fresh != state['capacity_handle'], 'Objects restart reused a stale handle')
    grant = client.objects(6, fresh, state['worker'], 1)[0][1]
    counts, digest = app(client, state['worker'], 21, grant)
    require(counts[2] == len(state['selected']) and digest == hashlib.sha256(state['selected']).digest(),
            'healthy client could not use the restarted Objects service')
    passed(report, 'Objects stop/restart invalidates service epoch, stale controls and grants while healthy clients recover',
           previous_instance=service, replacement_instance=replacement)


def separate_client(session, operation):
    # The public REL API owns one connection per explicit operation. The byte
    # portal admits one control client at a time, so relinquish ours first.
    session.client.close()
    session.client = None
    try:
        return operation()
    finally:
        session.client = live.Client(session.path, timeout=180)


def live_rel_checks(session, directory, state, report):
    import live_rel
    source = ROOT / 'examples/rel/rotation.py'
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    project = directory / 'source-first-project'
    name = 'accept-rel'
    initial = separate_client(session, lambda: live_rel.import_source(
        source, project, 'CC0-1.0', 'Repository-authored CC0 fixture; explicit acceptance-test selection', session.path))
    trust(session.client, name, state['publisher'])
    first_path = directory / 'rel-1.0.0.ltrel'
    first_build = separate_client(session, lambda: live_rel.build(
        project, session.path, state['publisher'], name, '1.0.0', first_path))
    first_slot, first_info = install(session.client, first_path)
    instance = start(session.client, first_slot)
    original = separate_client(session, lambda: live_rel.compare(project, session.path, instance))
    require(original['native_cases'] == 256 and not original['edited_semantics']
            and original['actual_output_sha256'] == original['original_source_output_sha256'],
            'native REL baseline does not match the explicitly selected source on all byte values')
    edited = separate_client(session, lambda: live_rel.edit(project, 7, state['workbench'], session.path))
    require(edited['head_handle'] != initial['head_handle'] and edited['parent_object'] == initial['head_object_sha256'],
            'REL native edit lost its semantic parent or reused a mutable object')
    second_path = directory / 'rel-2.0.0.ltrel'
    second_build = separate_client(session, lambda: live_rel.build(
        project, session.path, state['publisher'], name, '2.0.0', second_path))
    second_slot, second_info = install(session.client, second_path)
    require(second_info['parent'] == first_info['release_id'], 'edited REL native release lost original-signer ancestry')
    changed_instance = value(session.client.request(27, struct.pack('<2Q', instance, second_slot)))
    changed = separate_client(session, lambda: live_rel.compare(project, session.path, changed_instance))
    require(changed['native_cases'] == 256 and changed['edited_semantics']
            and changed['actual_output_sha256'] != changed['original_source_output_sha256'],
            'edited semantic model did not change actual native output')
    exported = directory / 'source-first-export'
    separate_client(session, lambda: live_rel.export(project, exported, session.path, second_path, state['public']))
    require(hashlib.sha256(source.read_bytes()).hexdigest() == before, 'REL changed the authorized original source fixture')
    require((exported / 'authoritative-object.json').exists() and (exported / 'reconstruct/reconstruction.json').exists(),
            'REL export omitted authoritative semantic bytes or native reconstruction inputs')
    stop(session.client, changed_instance)
    passed(report, 'authorized source becomes live semantic Object; native edit regenerates signed consumer and passes 256 differential cases',
           source_sha256=before, original_release=first_info['release_id'], edited_release=second_info['release_id'],
           original_native_output_sha256=original['actual_output_sha256'], edited_native_output_sha256=changed['actual_output_sha256'])


def applications(backend, directory, selected, capacity):
    with Session(backend, directory) as client:
        report = []
        state = application_checks(client, directory, selected, capacity, report)
        service_restart_checks(client, state, report)
        return {'backend': backend, 'result': 'pass', 'checks': report}


def vault(client, operation, data=b'', domain=3, expected=0):
    raw = client.request(operation, command(operation, a=domain, data=data))
    answer = fields(raw)
    require(answer[0] == expected, f'vault operation {operation} returned {answer[0]}, expected {expected}')
    return answer, raw[64:]


def retain(client, handle, expected=0):
    raw = client.request(203, struct.pack('<Q', handle))
    answer = fields(raw)
    require(answer[0] == expected, f'vault retain returned {answer[0]}, expected {expected}')
    return answer


def recover(client, expected):
    answer = fields(client.request(207))
    require(answer[0] == 0, 'recovered plaintext could not be committed by Objects')
    handle = answer[1]
    require(client.read_object(handle, export=True) == expected, 'authenticated recovery differs from explicitly retained object')
    metadata, digest = client.objects(5, handle)
    require(metadata[2] == len(expected) and digest == hashlib.sha256(expected).digest(), 'restored object hash or size mismatch')
    return handle


def begin_retention(client, backing, key, capacity, report):
    print('  vault: import selected 64 KiB and volatile object', flush=True)
    initial = client.import_object(capacity)
    volatile = client.import_object(b'volatile-only selection: ' + os.urandom(96))
    print('  vault: locked and domain authorization checks', flush=True)
    vault(client, 202)
    retain(client, initial, expected=3)
    rejected(lambda: client.request(207), 'recovery while locked')
    for domain in (1, 2):
        vault(client, 202, domain=domain, expected=1)
        vault(client, 200, data=key, domain=domain, expected=1)
    vault(client, 200, data=key[:-1], expected=2)
    print('  vault: explicit unlock and first encrypted retention', flush=True)
    vault(client, 200, data=key)
    first = retain(client, initial)
    require(first[1] == 1 and first[7] == 1, 'first durable generation is incorrect')
    first_image = backing.read_bytes()
    first_nonce = first_image[512 + 104:512 + 116]
    second_data = bytes(byte ^ 0x23 for byte in capacity)
    print('  vault: second encrypted retention', flush=True)
    second = client.import_object(second_data)
    second_answer = retain(client, second)
    require(second_answer[1] == 2 and second_answer[7] == 2, 'second durable generation is incorrect')
    persisted = backing.read_bytes()
    require(struct.unpack_from('<Q', persisted, 24)[0] == 2, 'acknowledged retention root was not written to backing')
    second_nonce = persisted[104:116]
    require(first_nonce != second_nonce, 'two real retention commits reused the AEAD nonce')
    ciphertext = persisted[8 * 512 + 128:8 * 512 + 128 + len(second_data)]
    require(ciphertext != second_data and key not in persisted, 'backing contains plaintext or the raw unlock key')
    require(second_data[:128] not in persisted and capacity[:128] not in persisted,
            'selected payload appears as plaintext in durable backing')
    vault(client, 201)
    retain(client, second, expected=3)
    rejected(lambda: client.request(207), 'recovery after explicit lock')
    passed(report, 'explicit Objects-only retention encrypts 64 KiB, advances durable roots and uses fresh entropy nonces',
           generation=2, nonce1=first_nonce.hex(), nonce2=second_nonce.hex(), ciphertext_sha256=hashlib.sha256(ciphertext).hexdigest())
    return dict(first=capacity, latest=second_data, initial_handle=initial, latest_handle=second,
                volatile_handle=volatile, disk_sha256=hashlib.sha256(persisted).hexdigest())


def interrupt_retention(session, backing, handle, report):
    # Observe only the explicit backing file. Freeze/kill the actual emulator
    # after its first inactive-bank write, before it publishes a new root.
    client = session.client
    before = backing.read_bytes()
    generation = max(struct.unpack_from('<Q', before, offset + 24)[0] for offset in (0, 512)) + 1
    sector = 8 if generation % 2 == 0 else 152
    bank_offset = sector * 512
    old_header = before[bank_offset:bank_offset + 128]
    client.counter = max(client.counter + 1, time.time_ns())
    payload = struct.pack('<Q', handle)
    client.stream.sendall(struct.pack('<4sIQQQ', live.MAGIC, len(payload), client.counter, 203, 0) + payload)
    descriptor = os.open(backing, os.O_RDONLY)
    began = time.monotonic()
    try:
        while os.pread(descriptor, 128, bank_offset) == old_header:
            require(time.monotonic() - began < 180, 'retention never wrote its inactive bank')
            require(session.process.poll() is None, 'guest exited before interrupted-write observation')
            time.sleep(0.0001)
        os.killpg(session.process.pid, signal.SIGSTOP)
        roots = os.pread(descriptor, 1024, 0)
        changed = os.pread(descriptor, 4096, bank_offset) != before[bank_offset:bank_offset + 4096]
        require(changed and roots == before[:1024], 'interruption missed the window before durable root publication')
    finally:
        os.close(descriptor)
        session.abort()
    passed(report, 'actual process interruption after inactive-bank write preserves the previous commit roots',
           interrupted_generation=generation, inactive_bank_sector=sector)


def retention_reboots(backend, directory, backing, key, state, report):
    # Same immutable OS, fresh volatile state and explicit user-selected backing.
    with Session(backend, directory / 'reset', backing) as client:
        require(all((row['instance'] & 255) < 4 or row['state'] == 0 for row in processes(client)),
                'user applications unexpectedly survived volatile reset')
        for handle in (state['initial_handle'], state['latest_handle'], state['volatile_handle']):
            rejected(lambda handle=handle: client.objects(5, handle), 'pre-reset object capability')
        rejected(lambda: client.request(207), 'automatic recovery without explicit unlock')
        vault(client, 200, data=bytes(byte ^ 1 for byte in key), expected=5)
        rejected(lambda: client.request(207), 'recovery using wrong key')
        vault(client, 200, data=key)
        restored = recover(client, state['latest'])
        require(restored not in (state['initial_handle'], state['latest_handle'], state['volatile_handle']),
                'recovery reused an invalid pre-reset capability')
        passed(report, 'reset loses volatile apps/objects/capabilities; explicit correct key recovers exact authenticated object')
    before_readonly = hashlib.sha256(backing.read_bytes()).hexdigest()
    with Session(backend, directory / 'readonly', backing, readonly=True) as client:
        vault(client, 200, data=key)
        recover(client, state['latest'])
        replacement = client.import_object(state['first'])
        retain(client, replacement, expected=4)
        require(hashlib.sha256(backing.read_bytes()).hexdigest() == before_readonly,
                'failed read-only commit changed the durable backing')
    with Session(backend, directory / 'after-readonly', backing) as client:
        vault(client, 200, data=key)
        recover(client, state['latest'])
    passed(report, 'real read-only device commit fails without changing the previous authenticated retained generation')
    # Ciphertext damage to the newer bank must select the older authenticated
    # commit; damage to both commits must fail closed rather than expose bytes.
    authentic = backing.read_bytes()
    tampered = directory / 'tampered-explicit-copy.img'
    damaged = bytearray(authentic)
    damaged[8 * 512 + 128 + 31] ^= 1
    tampered.write_bytes(damaged)
    with Session(backend, directory / 'tamper-fallback', tampered) as client:
        vault(client, 200, data=key)
        recover(client, state['first'])
    damaged[152 * 512 + 128 + 31] ^= 1
    tampered.write_bytes(damaged)
    with Session(backend, directory / 'tamper-closed', tampered) as client:
        vault(client, 200, data=key, expected=5)
        rejected(lambda: client.request(207), 'recovery after both ciphertext banks were tampered')
    passed(report, 'tampered newest ciphertext falls back to older authenticated root; two damaged roots fail closed')
    # Interrupt a real 64 KiB retain. No disk contents or guest memory are patched.
    session = Session(backend, directory / 'interrupted', backing)
    try:
        client = session.client
        vault(client, 200, data=key)
        pending = client.import_object(state['first'])
        interrupt_retention(session, backing, pending, report)
    finally:
        session.abort()
    with Session(backend, directory / 'after-interruption', backing) as client:
        vault(client, 200, data=key)
        recover(client, state['latest'])
        # Logical deletion is intentionally distinct from physical erasure.
        vault(client, 205)
    require(backing.read_bytes()[:1024] == bytes(1024), 'logical deletion did not invalidate both durable roots')
    with Session(backend, directory / 'after-delete', backing) as client:
        vault(client, 200, data=key)
        rejected(lambda: client.request(207), 'recovery after explicit retention deletion')
    passed(report, 'interrupted commit recovers prior object; explicit logical deletion prevents later recovery')


def retention(backend, directory, selected, capacity, with_apps=False):
    directory.mkdir(parents=True)
    backing = directory / 'explicit-vault.img'
    backing.write_bytes(bytes(512 * 512))
    key_path = directory / 'explicit-unlock.key'
    key = os.urandom(32)
    descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as output:
        output.write(key)
    report = []
    session = Session(backend, directory / 'initial', backing)
    with session as client:
        if with_apps:
            import framing_checks
            checks = framing_checks.check(client)
            passed(report, 'real UART resynchronization, exact replay, conflicting requests, bounded frames and truncated-payload recovery',
                   cases=checks)
            state = application_checks(client, directory, selected, capacity, report)
            service_restart_checks(client, state, report)
            live_rel_checks(session, directory, state, report)
            client = session.client
        state = begin_retention(client, backing, key, capacity, report)
    retention_reboots(backend, directory, backing, key, state, report)
    return {'backend': backend, 'result': 'pass', 'checks': report,
            'explicit_backing': str(backing), 'explicit_test_key': str(key_path)}


def main(argv=None):
    parser = argparse.ArgumentParser(description='Actual live guest acceptance; no kernel rebuild')
    parser.add_argument('--backend', action='append', choices=('x86_64', 'qemu', 'aarch64'), default=[])
    parser.add_argument('--source', type=Path, default=ROOT / 'Examples/NativeUtility.lean')
    parser.add_argument('--phase', choices=('smoke', 'apps', 'vault', 'full'), default='full')
    args = parser.parse_args(argv)
    selected = args.source.read_bytes()
    require(len(selected) <= 65536, 'selected source exceeds the 64 KiB platform limit')
    seed = selected or b'authorized empty-source capacity fixture\n'
    capacity = (seed * (65536 // len(seed) + 1))[:65536]
    image = ROOT / 'build/live/guest.bin'
    image_hash = hashlib.sha256(image.read_bytes()).hexdigest()
    output = ROOT / 'build/live-checks' / ('run-' + str(time.time_ns()))
    output.mkdir(parents=True)
    report = {'schema': 1, 'image_sha256': image_hash, 'source_sha256': hashlib.sha256(selected).hexdigest(),
              'checks': [], 'completed_observations': JOURNAL,
              'environment': 'Linux x86-64; ARM64 assembly executes under qemu-aarch64'}
    try:
        for backend in args.backend or ('x86_64', 'qemu', 'aarch64'):
            print('LIVE CHECK', args.phase, backend, flush=True)
            if args.phase == 'smoke':
                checked = smoke(backend, output / backend, capacity)
            elif args.phase == 'apps':
                checked = applications(backend, output / backend, selected, capacity)
            else:
                checked = retention(backend, output / backend, selected, capacity, args.phase == 'full')
            report['checks'].append(checked)
            after_hash = hashlib.sha256(image.read_bytes()).hexdigest()
            report['canonical_image_sha256_after_checks'] = after_hash
            if args.phase == 'full':
                require(after_hash == image_hash, 'live image changed during full acceptance')
        report['result'] = 'PASS'
    except BaseException as error:
        report['result'] = 'FAIL'
        report['error'] = str(error)
        raise
    finally:
        (output / 'evidence.json').write_text(json.dumps(report, indent=2) + '\n')
    print('LIVE ACCEPTANCE PASS; evidence:', output / 'evidence.json', flush=True)
    return report


if __name__ == '__main__':
    main()
