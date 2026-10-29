"""Actual headless source upload, quote, frozen enqueue and cancellation.

Only the graphical requester imports source. The ordinary node operator CLI
starts a provider without display/input rights; source and all job authority
must arrive through the guest protocol. The compiler worker is never executed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'tools'), str(ROOT / 'tests')]
import build_jobs
import forge
import live
import network
import projects
import releases
import remote_build
import server_store
from creator_journey import rendered_text
from forge_journey import Node, import_project, wait


class Provider:
    def __init__(self, path, endpoint, credential, package, public, image, role):
        self.path = path
        path.mkdir(parents=True)
        self.sock = path / 'portal.sock'
        self.log = (path / 'node.log').open('wb')
        self.process = None
        self.role = role
        info = releases.inspect(package.read_bytes())
        assert info['rights'] == 3199 and not info['rights'] & 768
        self.config = path / 'node.json'
        store = path / 'server.img'
        server_store.provision(store)
        command = [str(ROOT / 'lt'), 'node', 'init', str(self.config), '--role', role,
                   '--package', str(package), '--public', str(public), '--credentials', str(credential),
                   '--release-id', info['release_id'], '--rights', '3199', '--store', str(store),
                   '--namespace', os.getrandom(32).hex(), '--bytes', '1048576',
                   '--endpoint', endpoint, '--listen']
        initialized = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=True)
        (path / 'initialized.json').write_text(initialized.stdout)
        self.process = subprocess.Popen([str(ROOT / 'lt'), 'node', 'run', str(self.config),
            '--socket', str(self.sock), '--image', str(image)], cwd=ROOT,
            stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True)

        def ready():
            output = (path / 'node.log').read_text()
            if self.process.poll() is not None:
                raise AssertionError(('node startup failed', self.process.returncode, output))
            marker = output.find('{\n')
            if marker < 0 or '"headless": true' not in output:
                return None
            return json.loads(output[marker:])

        self.started = wait(ready, 'normal explicitly configured headless build node starts', 180)
        self.instance = self.started['instance']

    def client(self):
        return live.Client(self.sock, timeout=180)

    def inspect(self):
        client = self.client()
        try:
            return forge.inspect(client, self.instance)
        finally:
            client.close()

    def roots(self):
        client = self.client()
        try:
            return projects.roots(client)
        finally:
            client.close()

    def stop(self):
        if self.process and self.process.poll() is None:
            try:
                result = subprocess.run([str(ROOT / 'lt'), 'node', 'stop', '--socket', str(self.sock)],
                    cwd=ROOT, capture_output=True, text=True, timeout=20)
                (self.path / 'stop.stdout').write_text(result.stdout)
                assert result.returncode == 0, result.stderr
                self.process.wait(timeout=12)
            except (OSError, AssertionError, subprocess.TimeoutExpired):
                children = Path(f'/proc/{self.process.pid}/task/{self.process.pid}/children')
                if children.exists():
                    for child in children.read_text().split():
                        try:
                            os.killpg(int(child), signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.process.wait()
        self.log.close()


def remote(node, ingest=False):
    client = node.client()
    try:
        return (remote_build.ingest_inspect if ingest else remote_build.inspect)(client, node.instance)
    finally:
        client.close()


def package(binary, name, rights, key, output):
    raw, manifest = releases.make(binary, name, '0.4.4', rights, key, profile=2,
        sources=[ROOT / 'Guest/Forge.lean', ROOT / 'Guest/RemoteIngest.lean'], source_base=ROOT)
    output.write_bytes(raw)
    Path(str(output) + '.manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return output


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--image', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--role', choices=('builder', 'verifier'), default='builder')
    parser.add_argument('--client-binary', type=Path, default=ROOT / 'build/live/apps/native-forge-ingest.bin')
    parser.add_argument('--provider-binary', type=Path, default=ROOT / 'build/live/apps/forge-server-ingest.bin')
    parser.add_argument('--operator-key', type=Path, default=ROOT / 'build/forge-server-recovery-final2/operator.pem')
    parser.add_argument('--operator-public', type=Path, default=ROOT / 'build/forge-server-recovery-final2/operator.pub')
    args = parser.parse_args()
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    args.image = args.image.resolve()
    os.environ['LT_GUEST_IMAGE'] = str(args.image)
    client_package = package(args.client_binary, 'native-forge', 3967, args.operator_key, args.output / 'client.ltrel')
    provider_package = package(args.provider_binary, 'forge-builder-headless', 3199, args.operator_key,
                               args.output / 'provider.ltrel')
    probe = socket.socket()
    probe.bind(('127.0.0.1', 0))
    endpoint = f'127.0.0.1:{probe.getsockname()[1]}'
    probe.close()
    credentials = [args.output / 'client.credential', args.output / 'provider.credential']
    network.provision(*credentials, os.getrandom(32), os.getrandom(32),
                      hashlib.sha256(b'LT headless SourceUpload-v1 ' + args.role.encode()).digest())
    provider = requester = None
    checks = []

    def passed(label, **facts):
        checks.append(dict(check=label, status='passed', **facts))
        report = dict(image=hashlib.sha256(args.image.read_bytes()).hexdigest(),
            client_package=releases.inspect(client_package.read_bytes()),
            provider_package=releases.inspect(provider_package.read_bytes()), role=args.role,
            profile='SourceUpload1 wire16/17, Forge1 streamed import, RemoteBuild1',
            environment='Two isolated QEMU guests on one development host; normal headless node commands',
            remote_compiler_executions=0, checks=checks)
        (args.output / 'evidence.json').write_text(json.dumps(report, indent=2) + '\n')
        print('PASS', label, flush=True)

    try:
        provider = Provider(args.output / 'provider', endpoint, credentials[1], provider_package,
                            args.operator_public, args.image, args.role)
        requester = Node(args.output / 'requester', endpoint)
        client = requester.client()
        try:
            network.configure(client, credentials[0])
        finally:
            client.close()

        def authenticated():
            values = []
            for node in (requester, provider):
                client = node.client()
                try:
                    values.append(network.status(client)['endpoint_authenticated'])
                finally:
                    client.close()
            return all(values)

        wait(authenticated, 'headless provider and graphical requester authenticate', 180)
        requester.install(client_package, args.operator_public)
        client = requester.client()
        try:
            forge.configure(client, requester.instance, credentials[0])
            remote_build.configure(client, requester.instance, credentials[0], 'client', args.role)
        finally:
            client.close()
        client = provider.client()
        try:
            processes = client.request(2)
            row = next(struct.unpack_from('<4Q', processes, offset) for offset in range(0, len(processes), 32)
                       if struct.unpack_from('<Q', processes, offset)[0] == provider.instance)
            assert row[2] == 3199 and not row[2] & 768
            assert struct.unpack('<Q', client.request(183))[0] == provider.instance
            assert not projects.roots(client) and projects.queued_build(client) is None
        finally:
            client.close()
        passed('ordinary node builder starts without display, input, source or queued jobs',
               instance=provider.instance, rights=row[2], build_requester=provider.instance,
               source_preloaded=False, initial_roots=0)

        root, head, files, private = import_project(requester)
        requester.select('creator')
        requester.ui.press(62)
        wait(lambda: requester.inspect()['offered_nodes'], 'physical F4 freezes exact source offer')
        metadata = wait(lambda: (state if (state := provider.inspect())['metadata_nodes'] else None),
                        'ordinary metadata reaches headless provider')
        assert not provider.roots() and remote(provider, True)['phase'] == 0
        assert remote(provider)['local_job'] == 0
        client = requester.client()
        try:
            logical = projects.project_identity(client, root)
        finally:
            client.close()
        toolchain = build_jobs.compiler_identity()
        role = 2 if args.role == 'builder' else 3

        def source_packet(nonce, root=head, requested_role=role):
            return struct.pack('<8Q', 0x3145475246544c, 1, 16, struct.unpack_from('<Q', nonce)[0],
                               requested_role, metadata['metadata_nodes'], metadata['metadata_bytes'], 1) + \
                bytes.fromhex(root) + nonce + bytes.fromhex(logical) + bytes.fromhex(toolchain)

        def fault_grant():
            side, material = network.load_credentials(credentials[0])
            assert side == 1
            client = requester.client()
            try:
                return network.call(client, 2, a=3, b=3, c=8192, d=65536, e=100000,
                                    data=material[32:64] + material[64:96] + bytes(32) + struct.pack('<Q', 1))[0][1]
            finally:
                client.close()

        def inject(grant, packet):
            client = requester.client()
            try:
                job = network.call(client, 3, grant, a=1, data=packet)[0][1]
                wait(lambda: network.call(client, 4, job)[0][2] == 3,
                     'actual malformed or repeated authenticated frame transmitted')
            finally:
                client.close()

        grant = fault_grant()
        rejected = remote(provider, True)['rejected_messages']
        for label, packet in [
            ('truncated source request', source_packet(os.getrandom(32))[:-1]),
            ('wrong provider role', source_packet(os.getrandom(32), requested_role=3 if role == 2 else 2)),
            ('source root substituted from offered metadata', source_packet(os.getrandom(32), root=os.getrandom(32).hex()))]:
            inject(grant, packet)
            denied = wait(lambda: (state if (state := remote(provider, True))['rejected_messages'] > rejected else None),
                          'guest source upload parser rejects ' + label)
            rejected = denied['rejected_messages']
            assert denied['phase'] == 0 and not provider.roots() and remote(provider)['local_job'] == 0
            passed(label + ' rejected without source import or job authority', state=denied)
        client = requester.client()
        try:
            network.call(client, 8, grant)
        finally:
            client.close()
        passed('ordinary source metadata grants no automatic upload or execution', metadata=metadata,
               provider_roots=0, compiler_run=False)

        requester.ui.press(65)
        quote = wait(lambda: (state if (state := remote(requester))['state'] == 1 else None),
                     'physical F7 uploads exact source and waits for actual provider quote', 240)
        provider_quote = remote(provider)
        assert provider_quote['state'] == 1 and provider_quote['local_job'] == 0
        assert quote['source_root'] == provider_quote['source_root'] == head
        assert quote['project_id'] == provider_quote['project_id'] == logical
        assert quote['request_id'] == provider_quote['request_id']
        client = provider.client()
        try:
            roots = projects.roots(client)
            assert len(roots) == 1 and roots[0]['head'] == head, roots
            actual, received = projects.snapshot(client, roots[0]['cap'])
            assert actual == head and received == files and projects.queued_build(client) is None
            ids, cursor = [], 0
            while True:
                fields, data = client.objects(26, roots[0]['cap'], cursor)
                if not fields[1]:
                    break
                ids.append(data[:32].hex())
                cursor = fields[3]
            assert private not in ids
        finally:
            client.close()
        frame = wait(lambda: (frame if rendered_text(frame := requester.ui.frame(), 284, 354, 2,
                                                     0xe9bc75) == '01' else None),
                     'actual native UI presents unapproved quoted state', 120)
        (requester.path / 'quoted.ppm').write_bytes(frame.ppm())
        passed('physical F7 sends real source to headless provider and obtains a quote without execution',
               source_root=head, project=logical, request_id=quote['request_id'], source_bytes=sum(map(len, files.values())),
               graph_bytes=metadata['metadata_bytes'], files=len(files), private_absent=True,
               ingested=remote(provider, True), local_job=0)

        requester.ui.press(68)
        admitted = wait(lambda: (state if (state := remote(provider))['state'] == 2 and state['local_job'] else None),
                        'physical F10 separately approves one real frozen BuildJob', 180)
        client = provider.client()
        try:
            raw = projects.queued_build(client)
            assert raw is not None
            job = projects.frozen_build(client, raw)
            assert job['job_id'] == admitted['local_job'] and job['job_service'] == admitted['job_service']
            assert job['source_root'] == head and job['project_id'] == logical and job['toolchain_id'] == toolchain
            assert job['requester'] == job['delegator'] == provider.instance and job['recipe'] == 1
            actual, frozen_files = projects.snapshot(client, job['source_root_capability'], head)
            assert actual == head and frozen_files == files
        finally:
            client.close()
        passed('separate physical approval enqueues exact capped job through public executor interface',
               job=job, request_id=admitted['request_id'], compiler_run=False,
               hard_budget=dict(cpu_seconds=60, wall_seconds=120, output_bytes=65536, price=0))
        grant = fault_grant()
        inject(grant, source_packet(bytes.fromhex(quote['request_id'])))
        wait(lambda: remote(provider, True)['phase'] == 13, 'idempotent source request receives readiness only')
        assert remote(provider)['local_job'] == job['job_id']
        client = requester.client()
        try:
            network.call(client, 8, grant)
        finally:
            client.close()
        requester.ui.press(1)
        wait(lambda: remote(provider)['state'] == 5, 'physical Esc cancels admitted remote job', 120)
        client = provider.client()
        try:
            assert projects.queued_build(client) is None, 'duplicate source request enqueued a second job'
        finally:
            client.close()
        passed('repeated source request is idempotent and cancellation leaves no executor work',
               job=job['job_id'], provider_state=5, queued_jobs=0, compiler_run=False)
    except BaseException:
        for node in (requester, provider):
            if node:
                try:
                    (node.path / 'failure-state.json').write_text(json.dumps(dict(
                        forge=node.inspect(), remote={k: v for k, v in remote(node).items() if k != 'contract'},
                        ingestion=remote(node, True)), indent=2))
                    if isinstance(node, Node):
                        (node.path / 'failure.ppm').write_bytes(node.ui.frame().ppm())
                except BaseException:
                    pass
        raise
    finally:
        if requester:
            requester.stop()
        if provider:
            provider.stop()


if __name__ == '__main__':
    main()
