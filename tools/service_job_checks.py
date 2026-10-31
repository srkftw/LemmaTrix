"""Execute durable ServiceJobs transitions in a real guest and fresh test backing.

These are controlled provider assertions over an existing source artifact, not a
mailbox delivery, compilation result, protocol vector, or independent audit.
"""
import argparse
import hashlib
import json
import os
import signal
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import driver
import live
import server_store
import service_jobs


def denied(client, status, op, handle, *args, **kwargs):
    fields, _ = service_jobs.call(client, op, handle, *args, allow=(status,), **kwargs)
    assert fields[0] == status, (op, handle, fields)


def start(image, backend, backing, folder):
    socket = folder / 'guest.sock'
    socket.unlink(missing_ok=True)
    log = (folder / 'guest.log').open('ab')
    process = None
    try:
        process = subprocess.Popen([sys.executable, str(driver.ROOT / 'lt'),
            'run', '--backend', backend, '--socket', str(socket), '--image', str(image),
            '--server-store', str(backing)], cwd=driver.ROOT, stdout=log, stderr=log,
            start_new_session=True)
        deadline = time.monotonic() + (300 if backend == 'aarch64' else 60)
        while not socket.exists():
            if process.poll() is not None:
                raise AssertionError((folder / 'guest.log').read_text())
            if time.monotonic() >= deadline:
                raise TimeoutError('test guest startup')
            time.sleep(.05)
        client = live.Client(socket, timeout=300 if backend == 'aarch64' else 60)
        return process, client, log
    except BaseException:
        # Startup and portal-open failures happen before qualify owns a Client.
        # Reap the entire opaque adapter/guest group, rather than just its
        # Python wrapper, and close the private log on those paths too.
        if process is None:
            log.close()
        else:
            stop(process, None, log)
        raise


def stop(process, client, log):
    if client:
        client.close()
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
    log.close()


def qualify(image, backend, iterations):
    source = driver.ROOT / 'Guest/ServiceJobs.lean'
    source_bytes = source.read_bytes()
    artifact = hashlib.sha256(source_bytes).digest()
    digest = lambda text: hashlib.sha256(text.encode()).hexdigest()
    with tempfile.TemporaryDirectory(prefix='lt-service-jobs-') as temporary:
        folder = Path(temporary)
        # A private copy fixes the image for this run while other work builds.
        selected = folder / 'guest.bin'
        selected.write_bytes(Path(image).read_bytes())
        backing = folder / 'operator.img'
        server_store.provision(backing)
        process, client, log = start(selected, backend, backing, folder)
        began = time.monotonic()
        handles = []
        terms = []
        try:
            service_jobs.call(client, 280)
            owner = struct.unpack_from('<Q', client.request(2), 32)[0]
            handle = 0
            for i in range(iterations):
                canonical = service_jobs.terms(digest(f'operation-{i}'), digest('requester'),
                    artifact.hex(), digest('policy'), 'storage', 1, len(source_bytes) * 2,
                    8, 100, digest('description'), expected=artifact.hex())
                handle = service_jobs.submit(client, 16, canonical, new_operation=True)
                assert handle == i << 8, (i, handle)
                handles.append(handle)
                terms.append(canonical)
                before = service_jobs.inspect(client, handle)
                assert before['allocation_epoch'] == i and before['record_schema'] == 2
                assert service_jobs.submit(client, handle, canonical) == handle
                denied(client, 2, 281, handle, data=canonical[:-1] + bytes([canonical[-1] ^ 1]))
                service_jobs.call(client, 282, handle, owner)
                service_jobs.call(client, 283, handle, len(source_bytes), len(source_bytes), 1)
                service_jobs.call(client, 290, handle, len(source_bytes), data=artifact)
                complete = service_jobs.inspect(client, handle)
                service_jobs.call(client, 290, handle, len(source_bytes), data=artifact)
                assert service_jobs.inspect(client, handle) == complete
                if i:
                    for op in (282, 283, 285, 288, 299):
                        denied(client, 9, op, handles[i-1], owner if op == 282 else 0)
                    denied(client, 8, 281, 16, data=terms[0])
                if i + 1 != iterations:
                    service_jobs.call(client, 299, handle)
                    denied(client, 8, 281, handle, data=canonical)
                    denied(client, 2, 281, handle, data=canonical[:-1] + bytes([canonical[-1] ^ 1]))
            assert sum(service_jobs.inspect(client, i, by_index=True) is not None for i in range(16)) == 1
            final = service_jobs.inspect(client, handle)
            assert final['allocation_epoch'] == iterations - 1
            assert final['generation'] > iterations * 3
            live_seconds = time.monotonic() - began
        finally:
            stop(process, client, log)
        process, client, log = start(selected, backend, backing, folder)
        try:
            service_jobs.call(client, 280)
            recovered = service_jobs.inspect(client, handle)
            assert recovered == final, (recovered, final)
            assert service_jobs.inspect(client, 0, by_index=True) == final
            assert service_jobs.submit(client, handle, terms[-1]) == handle
            assert service_jobs.inspect(client, handle) == final
            if iterations > 1:
                denied(client, 9, 288, handles[0])
                denied(client, 8, 281, 16, data=terms[0])
            denied(client, 1, 283, handle, 1, 0, 1)
            restart_generation = recovered['generation']
            # A later publication is deliberately corrupted after stopping the
            # guest: recovery must select the prior checked complete bank.
            service_jobs.call(client, 299, handle)
        finally:
            stop(process, client, log)
        with backing.open('r+b') as stream:
            stream.seek((24 + ((restart_generation + 1) % 2)) * 512)
            damaged = bytearray(stream.read(512))
            damaged[448] ^= 1
            stream.seek((24 + ((restart_generation + 1) % 2)) * 512)
            stream.write(damaged)
            stream.flush()
        process, client, log = start(selected, backend, backing, folder)
        try:
            service_jobs.call(client, 280)
            assert service_jobs.inspect(client, handle) == final
        finally:
            stop(process, client, log)
        return dict(backend=backend, image_sha256=hashlib.sha256(selected.read_bytes()).hexdigest(),
            source_sha256=artifact.hex(), source_bytes=len(source_bytes), sequential_operations=iterations,
            physical_rows_used=1, reboot_during_sequence=False, capacity_increased=False,
            last_handle=handle, last_publication_generation=final['generation'], seconds=live_seconds,
            checks=['same-boot terminal reclamation and allocation epoch increments',
                'exact completion retry leaves reservations, work, attempts and generation unchanged',
                'conflicting idempotency terms, stale owner/admin handles and retired operations reject',
                'evicted unknown retry cannot automatically acquire another allowance',
                'reused high-generation row recovers after guest termination without old-bank resurrection',
                'fresh boot restores no owner binding',
                'corrupted latest bank falls back to preceding checked complete publication'],
            scope='native durable service journal; no mailbox, routing or message-delivery claim',
            arm_execution='qemu-aarch64 emulation on x86-64' if backend == 'aarch64' else None)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, default=driver.BUILD / 'live/guest.bin')
    parser.add_argument('--backend', choices=('qemu', 'x86_64', 'aarch64'), default='qemu')
    parser.add_argument('--iterations', type=int, default=40)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    if not 2 <= args.iterations <= 64:
        parser.error('iterations must be within2..64')
    result = qualify(args.image, args.backend, args.iterations)
    encoded = json.dumps(result, indent=2) + '\n'
    if args.output:
        args.output.write_text(encoded)
    print(encoded, end='')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
