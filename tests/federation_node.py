"""A real isolated registry started through the normal explicit node commands."""
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'tools'), str(ROOT / 'tests')]
import forge
import live
import nodes
import projects
import releases
import server_store
from forge_journey import wait


class HeadlessRegistryNode:
    def __init__(self, path, endpoint, credential, forge_package, registry_package,
                 operator_public, federation_public, policy, image, recover=False):
        self.path = Path(path)
        self.path.mkdir(parents=True, exist_ok=True)
        self.sock = self.path / 'portal.sock'
        self.ui = None
        self.proc = None
        self.log = None
        if self.sock.exists():
            raise ValueError('registry endpoint already exists; refusing to replace a guest')
        package, registry = map(Path, (forge_package, registry_package))
        first, second = releases.inspect(package.read_bytes()), releases.inspect(registry.read_bytes())
        assert first['rights'] == 1151 and second['rights'] == 2175
        self.config = self.path / 'node.json'
        store = self.path / 'server.img'
        if not self.config.exists():
            if recover:
                raise ValueError('recovery requires this node’s existing operator configuration')
            server_store.provision(store)
            command = [str(ROOT / 'lt'), 'node', 'init', str(self.config), '--role', 'registry',
                '--package', str(package), '--public', str(operator_public),
                '--credentials', str(credential), '--release-id', first['release_id'], '--rights', '1151',
                '--store', str(store), '--namespace', os.getrandom(32).hex(), '--bytes', '1048576',
                '--endpoint', endpoint, '--listen', '--registry-package', str(registry),
                '--registry-public', str(operator_public), '--registry-release-id', second['release_id'],
                '--registry-rights', '2175', '--federation-public', str(federation_public),
                '--federation-policy', policy]
            initialized = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=True)
            (self.path / 'initialized.json').write_text(initialized.stdout)
        else:
            config = json.loads(self.config.read_text())
            assert config['role'] == 'registry' and config['endpoint'] == endpoint
            assert config['release_id'] == first['release_id'] and config['registry']['release_id'] == second['release_id']
            assert config['registry']['policy'] == policy
            assert Path(config['credentials']) == Path(credential).resolve()
            assert Path(config['registry']['federation_public']) == Path(federation_public).resolve()
            assert Path(config['server_store']) == store.resolve()
        log_path = self.path / ('recovery.log' if recover else 'guest.log')
        self.log = log_path.open('wb')
        command = [str(ROOT / 'lt'), 'node', 'run', str(self.config), '--socket', str(self.sock),
                   '--image', str(Path(image).resolve())]
        if recover:
            command.append('--recover-catalog')
        self.proc = subprocess.Popen(command, cwd=ROOT, stdout=self.log,
            stderr=subprocess.STDOUT, start_new_session=True)
        try:
            def ready():
                text = log_path.read_text()
                if self.proc.poll() is not None:
                    raise AssertionError(('operator registry startup failed', self.proc.returncode, text))
                return '"headless": true' in text
            wait(ready, 'normal operator registry startup', 180)
            client = self.client()
            try:
                raw = client.request(2)
                active = [struct.unpack_from('<4Q', raw, offset) for offset in range(0, len(raw), 32)]
                active = [row for row in active if 7 <= row[0] & 255 < 12 and 0 < row[1] < 5]
                assert len(active) == 2 and [row[2] for row in active] == [1151, 2175], active
                self.instance, self.registry_instance = active[0][0], active[1][0]
                configured = forge.inspect(client, self.instance)
                assert configured['configured'] and configured['role'] == 1
                assert configured['server_store_grant'] == 0, 'network-facing Forge acquired Registry storage authority'
                federation = forge.federation_inspect(client, self.instance)
                assert federation['required']
                self.startup_catalog = nodes.catalog(client, self.registry_instance)
                assert not projects.roots(client), 'operator startup restored graph payload into metadata-only Registry'
            finally:
                client.close()
        except BaseException:
            self.stop()
            raise

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
        if self.proc and self.proc.poll() is None:
            try:
                result = subprocess.run([str(ROOT / 'lt'), 'node', 'stop', '--socket', str(self.sock)],
                    cwd=ROOT, capture_output=True, text=True, timeout=20)
                (self.path / 'stop.stdout').write_text(result.stdout)
                (self.path / 'stop.stderr').write_text(result.stderr)
                if result.returncode:
                    raise RuntimeError(result.stderr)
                self.proc.wait(timeout=12)
            except (OSError, RuntimeError, subprocess.TimeoutExpired):
                # Only process groups created by this exact operator subprocess
                # are eligible for cleanup after a failed explicit fault test.
                children = Path(f'/proc/{self.proc.pid}/task/{self.proc.pid}/children')
                if children.exists():
                    for child in children.read_text().split():
                        try:
                            os.killpg(int(child), signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                try:
                    os.killpg(self.proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.proc.wait()
        if self.log:
            self.log.close()
            self.log = None
