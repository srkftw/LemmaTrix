"""A fresh native verifier supersedes an imported signed Registry decision.

The original Project Release fixture and disclosed Registry RSA admission
bootstrap are reused. No Feed authority, history, or private key is involved.
The raw Registry code and static guest image are supplied, never rebuilt here.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'tools'), str(ROOT/'tests')]
import capsule
import feed
import federation
import projects
import releases
from messenger_journey import Guest, PUB, SIGN, wait


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--image', type=Path, required=True)
    p.add_argument('--registry', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    out = a.output.resolve();out.mkdir(parents=True, exist_ok=False)
    image = out/'guest.bin';image.write_bytes(a.image.read_bytes())
    fixture = ROOT/'tests/fixtures/campaign008-existing-forge-closure.json'
    publisher = ROOT/'tests/fixtures/campaign008-existing-forge-publisher.pub'
    began = time.monotonic()
    record = dict(schema=1, result='running', image=dict(path=str(a.image), sha256=sha(image)),
                  registry=dict(path=str(a.registry), bytes=a.registry.stat().st_size, sha256=sha(a.registry)),
                  original_graph=dict(path=str(fixture.relative_to(ROOT)), sha256=sha(fixture)),
                  native_build_performed=False, active_community_accessed=False,
                  authority='Existing disclosed RSA Project Release and Registry admission bootstrap only',
                  checks=[])
    def save():
        (out/'evidence.json').write_text(json.dumps(record, indent=2)+'\n')
    def passed(label, **values):
        record['checks'].append(dict(check=label, result='pass', **values));save()
        print('PASS', label, json.dumps(values), flush=True)
    save()
    g = None
    try:
        g = Guest('registry', 'qemu', out, image)
        g.start()
        instances = []
        for name in ('source', 'incoming'):
            raw, _ = releases.make(a.registry, 'registry-imported-revocation-'+name,
                                   '0.9.0', 2175, SIGN, profile=2, license='NOASSERTION')
            path = out/(name+'.ltrel');path.write_bytes(raw)
            owner, _ = feed.install_or_launch(g.client, path, PUB, 2175)
            instances.append(owner)
        source, incoming = instances
        key, public = out/'admission.pem', out/'admission.pub'
        capsule.generate_key(key, public)
        for owner in instances:federation.configure(g.client, owner, public, 'portable', bind=False)
        # B has never authored a decision or recovered a catalog. Its original
        # incoming-only verifier leaves the native authoring counter at zero.
        try:federation.call(g.client, incoming, 6)
        except ValueError as error:assert str(error) == 'native registry status6'
        else:raise AssertionError('fresh incoming Registry unexpectedly had a listing')
        archive = json.loads(fixture.read_text())
        records = [dict(row, payload=base64.b64decode(row['payload'], validate=True)) for row in archive['nodes']]
        roots = projects.import_records(g.client, archive['selected'], records)
        root = next(row for row in roots if row['head'] == archive['selected'][0]['head'])
        logical = projects.project_identity(g.client, root['cap'])
        assert logical == archive['project_id']
        modulus = releases.public_modulus(publisher)
        publication = releases.publication(logical, hashlib.sha256(modulus).hexdigest())
        federation.call(g.client, source, 3, data=publication+modulus)
        delegated = g.client.objects(27, root['cap'], source, 25)[0][1]
        federation.call(g.client, source, 2, h=delegated)
        admission = wait(lambda: federation.sign_once(g.client, source, key, 'portable'),
                         180, 'native original project admission')
        fields, original = federation.call(g.client, source, 6)
        assert len(original) == 768 and fields[1] >= 1
        assert struct.unpack_from('<Q', original, 16)[0] == 2
        assert original[64:96].hex() == logical and original[320:352].hex() == root['head']
        (out/'original-admission.bin').write_bytes(original)
        passed('source natively evaluates genuine signed Project Release and original admission',
               instance=source, sequence=fields[1], descriptor_sha256=hashlib.sha256(original).hexdigest(),
               root=root['head'], project_id=logical, admission=admission)
        verified, cached = federation.call(g.client, incoming, 11, data=original+original[320:352])
        assert cached == original and verified[1] == 2
        fields, cached = federation.call(g.client, incoming, 6)
        assert cached == original
        original_sequence, original_slot = fields[1], fields[2]
        federation.call(g.client, incoming, 22, data=original+original[320:352])
        passed('fresh B verifies and caches exact original768 with no prior local authoring',
               instance=incoming, imported_sequence=original_sequence, imported_slot=original_slot)
        revoked, _ = federation.call(g.client, incoming, 8, h=original_slot, a=original_sequence)
        pending_fields, pending = federation.call(g.client, incoming, 4)
        pending_sequence = struct.unpack_from('<Q', pending, 48)[0]
        assert revoked[1] == pending_fields[1] == pending_sequence > original_sequence
        assert struct.unpack_from('<Q', pending, 16)[0] == 3
        assert pending[64:160] == original[64:160] and pending[320:352] == original[320:352]
        revocation = federation.sign_once(g.client, incoming, key, 'portable')
        assert revocation['sequence'] == pending_sequence and revocation['listing'] == 3
        try:federation.call(g.client, incoming, 22, data=original+original[320:352])
        except ValueError as error:assert str(error) == 'native registry status3'
        else:raise AssertionError('old imported positive admission remained current after revocation')
        latest_fields, latest = federation.call(g.client, incoming, 6)
        assert latest_fields[1] == pending_sequence and struct.unpack_from('<Q', latest, 16)[0] == 3
        federation.call(g.client, incoming, 22, data=latest+latest[320:352])
        assert federation.call(g.client, source, 6)[1] == original
        (out/'native-revocation.bin').write_bytes(latest)
        passed('authorized B revocation supersedes imported sequence and old positive is refused3',
               native_pending_sequence=pending_sequence, original_sequence=original_sequence,
               latest_listing=3, old_current_status=3, original_source_bytes_unchanged=True,
               revocation_sha256=hashlib.sha256(latest).hexdigest())
        assert sha(fixture) == record['original_graph']['sha256']
        record.update(result='pass', seconds=time.monotonic()-began,
                      limits='One isolated QEMU guest; no persistence/restart, graphical Feed, or connected project-action claim. Sequence-wrap refusal is source-reviewed, not executed.')
        save();print(json.dumps(record, indent=2), flush=True)
    except BaseException as error:
        record.update(result='failure', error=repr(error), seconds=time.monotonic()-began);save();raise
    finally:
        if g:g.stop()


if __name__ == '__main__':main()
