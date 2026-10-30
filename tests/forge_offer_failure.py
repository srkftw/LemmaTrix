"""Native offer quota failure withdraws availability; early receipts fail closed."""
import argparse, hashlib, json, os, socket, struct, sys, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'tools'), str(ROOT / 'tests')]
import forge, network, projects, releases
from forge_journey import wait
from signed_forge_journey import ClientNode

def imported(node, name, count):
    files = {f'part{i:02}.lean': f'def value{i:02} : UInt64 := {i}\n'.encode() for i in range(count)}
    records, entries = [], []
    for path, payload in sorted(files.items()):
        identity = projects.canonical_node(10, payload)
        records.append(dict(kind=10, id=identity, payload=payload))
        entries.append((path, 10, identity))
    payload = projects.manifest(entries)
    head = projects.canonical_node(11, payload)
    records.append(dict(kind=11, id=head, payload=payload))
    c = node.client()
    try:
        root = projects.import_records(c, [dict(name=name, head=head)], records)[0]['cap']
        shell = struct.unpack_from('<Q', c.request(2), 4 * 32)[0]
        c.objects(27, root, shell, 127)
        return root, head, files
    finally:
        c.close()

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--image', type=Path, required=True)
    p.add_argument('--package', type=Path, required=True)
    p.add_argument('--public', type=Path, required=True)
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)
    os.environ['LT_GUEST_IMAGE'] = str(a.image.resolve())
    probe = socket.socket(); probe.bind(('127.0.0.1', 0))
    endpoint = f'127.0.0.1:{probe.getsockname()[1]}'; probe.close()
    credentials = [a.output / 'creator.credential', a.output / 'peer.credential']
    network.provision(*credentials, os.getrandom(32), os.getrandom(32), os.getrandom(32))
    nodes, checks = [], []
    def passed(check, **fields):
        checks.append(dict(check=check, status='passed', **fields))
        (a.output / 'evidence.json').write_text(json.dumps(dict(
            image=hashlib.sha256(a.image.read_bytes()).hexdigest(),
            forge_release=releases.inspect(a.package.read_bytes())['release_id'], checks=checks,
            environment='two isolated QEMU guests on one development host; physical native controls; explicitly authorized malformed peer receipt injection'), indent=2) + '\n')
        print('PASS', check, flush=True)
    try:
        peer = ClientNode(a.output / 'peer', endpoint, True); nodes.append(peer)
        creator = ClientNode(a.output / 'creator', endpoint); nodes.append(creator)
        for node, credential in zip((creator, peer), credentials):
            c = node.client()
            try: network.configure(c, credential)
            finally: c.close()
        def authenticated():
            statuses = []
            for node in nodes:
                c = node.client()
                try: statuses.append(network.status(c)['endpoint_authenticated'])
                finally: c.close()
            return all(statuses)
        wait(authenticated, 'actual encrypted guest relationship', 120)
        for node, credential in zip((creator, peer), credentials):
            node.install(a.package, a.public)
            c = node.client()
            try: forge.configure(c, node.instance, credential)
            finally: c.close()
        small_root, small_head, small_files = imported(creator, 'small-offer', 1)
        large_root, large_head, large_files = imported(creator, 'over-offer-quota', 24)
        creator.select('small-offer'); creator.ui.press(62)
        offered = wait(lambda: (s if (s := creator.inspect())['offered_nodes'] == 2 and not s['pending_job'] else None), 'initial native offer', 120)
        # Fault injection is deliberately administrative, over the real broker.
        # No normal client action, application memory or UI setter is replaced.
        role, material = network.load_credentials(credentials[1])
        target = material[32:64] if role == 1 else material[:32]
        c = peer.client()
        try:
            f, _ = network.call(c, 2, a=3, b=3, c=8192, d=65536, e=100000,
                                data=target + material[64:96] + bytes.fromhex(small_head) + struct.pack('<Q', 1))
            grant = f[1]
            packet = struct.pack('<8Q', 0x3145475246544c, 1, 8, 0, 0, 0, 0, 0) + bytes.fromhex(small_head)
            f, _ = network.call(c, 3, grant, a=1, data=packet)
            job = f[1]
            wait(lambda: network.call(c, 4, job)[0][2] == 3, 'injected authenticated early receipt accepted by device', 120)
            denied = wait(lambda: (s if (s := creator.inspect())['status'] == 9 else None), 'early completion receipt rejected', 120)
            assert denied['send_phase'] == 0 and denied['offered_nodes'] == 2
            network.call(c, 8, grant)
        finally: c.close()
        passed('matching-root receipt before send cannot report completion', state=denied)
        creator.select('over-offer-quota'); creator.ui.press(62)
        failed = wait(lambda: (s if (s := creator.inspect())['status'] == 3 and not s['pending_job'] else None), 'bounded native offer quota failure', 120)
        assert failed['selected_root'] and not failed['frozen_root'] and not failed['offered_nodes'] and not failed['offered_bytes'], failed
        c = creator.client()
        try:
            assert projects.snapshot(c, small_root) == (small_head, small_files)
            assert projects.snapshot(c, large_root) == (large_head, large_files)
        finally: c.close()
        (creator.path / 'quota-withdrawn.ppm').write_bytes(creator.ui.frame().ppm())
        passed('25-node offer failure withdraws all availability and preserves usable selected roots', old=offered, failed=failed,
               oversized_records=25, small_head=small_head, large_head=large_head)
        creator.select('small-offer'); creator.ui.press(62)
        wait(lambda: creator.inspect()['offered_nodes'] == 2 and not creator.inspect()['pending_job'], 'fresh supported offer after quota failure', 120)
        peer.ui.press(61)
        wait(lambda: peer.inspect()['metadata_nodes'] == 2, 'fresh native metadata after withdrawal', 120)
        peer.ui.press(63)
        completed = wait(lambda: (s if (s := peer.inspect())['status'] == 11 and not s['import_transaction'] else None), 'supported graph completes', 180)
        receipt = wait(lambda: (s if (s := creator.inspect())['status'] == 10 and not s['send_phase'] else None), 'valid terminal receipt accepted', 120)
        c = peer.client()
        try:
            roots = projects.roots(c)
            assert len(roots) == 1 and projects.snapshot(c, roots[0]['cap']) == (small_head, small_files)
        finally: c.close()
        passed('supported fresh offer and actual terminal receipt still complete', recipient=completed, sender=receipt)
    finally:
        for node in reversed(nodes):
            try: node.stop()
            except BaseException: pass

if __name__ == '__main__': main()
