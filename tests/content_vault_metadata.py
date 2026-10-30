"""Publish/admit original media through the native Registry for v4 vault tests.

The host bootstrap signs explicitly selected publisher/federation records. The
native Registry parses shared graph material and decides consumer admission.
Only public signed metadata is exported as a reproducible comparison fixture.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import capsule
import consumers
import content
import federation
import live
import nodes
import releases


def create(client, directory, seconds=1):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    keys = {}
    for role in ('publisher', 'federation', 'registry-package'):
        private = directory / (role + '.pem')
        public = directory / (role + '.pub')
        if not private.exists():
            capsule.generate_key(private, public)
        keys[role] = private, public
    binary = Path(__file__).resolve().parents[1] / 'build/live/apps/registry-consumer-check.bin'
    package_raw, _ = releases.make(binary, 'content-vault-registry', '1.0.0', 2175,
                                   keys['registry-package'][0], profile=2, license='NOASSERTION')
    package = directory / 'registry.ltrel'
    package.write_bytes(package_raw)
    package_id = releases.inspect(package_raw)['release_id']
    approved = nodes.approved_package(package, keys['registry-package'][1], package_id, 2175)
    registry = nodes.start_package(client, approved, package_raw)
    configured = federation.configure(client, registry, keys['federation'][1], 'consumer', allowed_rights=768)
    raw = content.original_wave(seconds, 2)
    manifest, _, _ = content.commitments(raw)
    signed = consumers.create(key=keys['publisher'][0], project='content-vault-original-media',
                              collection=content.COLLECTION, item=hashlib.sha256(b'Original vault test item').digest(),
                              edition=hashlib.sha256(b'lossless stereo').digest(), title='Open Courtyard: retained stereo',
                              resource=manifest, frames=int(seconds * 48000), channels=2, license_id=1)
    attached = consumers.attach(client, signed, manifest, name='vault-consumer-metadata')
    modulus = releases.public_modulus(keys['publisher'][1])
    federation.call(client, registry, 3, data=signed[32:64] + modulus)
    delegated = client.objects(27, attached['root'], registry, 25)[0][1]
    pending, _ = federation.call(client, registry, 2, h=delegated)
    assert pending[1] == 1, pending
    admission = federation.sign_once(client, registry, keys['federation'][0], 'consumer', allowed_rights=768)
    assert admission and admission['listing'] == 4, admission
    _, descriptor = federation.call(client, registry, 6)
    assert len(descriptor) == 768
    metadata = descriptor + signed
    (directory / 'selected.metadata').write_bytes(metadata)
    info = {'registry_package': package_id, 'federation': configured['federation_id'],
            'consumer_sha256': hashlib.sha256(signed).hexdigest(),
            'metadata_sha256': hashlib.sha256(metadata).hexdigest(),
            'manifest_sha256': hashlib.sha256(manifest).hexdigest(),
            'catalog_source': 'actual native Registry consumer admission, publisher and federation signatures',
            'payload_transferred_during_admission': False}
    (directory / 'metadata-evidence.json').write_text(json.dumps(info, indent=2) + '\n')
    return info


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--seconds', type=float, default=1)
    args = parser.parse_args()
    client = live.Client(args.socket, timeout=180)
    try:
        result = create(client, args.output, args.seconds)
    finally:
        client.close()
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
