"""Four purpose2 archive slots, origin checks and real retained-byte recovery.

Run retain, restart the common image against the same selected backing, then
recover. No personal vault, host payload copy or guest memory patch is used.
"""
import argparse
import hashlib
import json
import struct
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import content
import server_content
import nodes
import releases
from live import Client


def denied(fn, code=1):
    try:
        fn()
    except ValueError as error:
        assert f'status{code}' in str(error), str(error)
    else:
        raise AssertionError('cross-origin or invalid slot authority accepted')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket', required=True, type=Path)
    parser.add_argument('--phase', choices=('retain', 'recover'), required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--probe-package', type=Path)
    parser.add_argument('--probe-public', type=Path, default=Path('build/campaign005/publisher.pub'))
    args = parser.parse_args()
    client = content.ContentClient(Client(args.socket, timeout=180))
    results = []
    try:
        owner = struct.unpack_from('<Q', client.request(2), 32)[0]
        vault = struct.unpack_from('<Q', client.request(2), 96)[0]
        operation = time.time_ns() & 0x7fffffffffffffff
        probe = None
        if args.phase == 'retain' and args.probe_package:
            info = releases.inspect(args.probe_package.read_bytes(), releases.public_modulus(args.probe_public))
            probe = nodes.start_package(client, nodes.approved_package(args.probe_package, args.probe_public, info['release_id'], 2057), args.probe_package.read_bytes())
        def probe_call(op, h=0, a=0, b=0, c=0):
            reply = client.request(150, struct.pack('<Q8Q', probe, op, h, a, b, c, 0, 0, 1))
            fields = struct.unpack_from('<8Q', reply)
            if fields[0]:
                raise ValueError(f'DelegationProbe status{fields[0]}')
            return fields, reply[64:]
        metadata = client.import_object(b'explicit-origin-probe', kind=2)
        assert client.objects(15, metadata, owner)[0][0] == 0
        denied(lambda: client.objects(15, metadata, vault))
        # A real delegated read scope is owned by Vault, so the issuing process
        # cannot use that scope as its own, even though it knows its number.
        delegated_metadata = client.objects(6, metadata, vault, 25)[0][1]
        denied(lambda: client.objects(15, delegated_metadata, owner))
        client.objects(7, metadata, delegated_metadata)
        for slot in range(4):
            raw = content.original_wave(.05 + slot*.01, 2, later=slot % 2 == 1)
            manifest, chunks, _ = content.commitments(raw)
            namespace = hashlib.sha256(b'explicit-selected-archive-slot' + bytes([slot])).digest()
            grant = server_content.permit(client, owner, namespace, content.sha(manifest), len(raw), slot)
            if args.phase == 'retain':
                selected, _ = content.import_content(client, raw, operation + slot*10,
                    hashlib.sha256(b'explicit-source-provider').digest(),
                    hashlib.sha256(b'explicit-source-federation').digest())
                assert client.objects(316, selected, owner)[0][0] == 0
                denied(lambda: client.objects(316, selected, vault))
                delegated = client.objects(308, selected, vault)[0][1]
                denied(lambda: client.objects(316, delegated, owner))
                # Undelegated, caller-owned root cannot be consumed as Vault's.
                denied(lambda: server_content.call(client, 251, grant, selected, 0, operation + slot*10 + 1))
                assert client.objects(306, selected)[0][2] == 2
                # Pass a known Vault-owned Object grant in the content position:
                # numeric knowledge alone never provides an eligible delegation.
                false_content = client.objects(6, metadata, vault, 25)[0][1]
                denied(lambda: server_content.call(client, 251, grant, false_content, 0, operation + slot*10 + 2))
                client.objects(7, metadata, false_content)
                if probe and slot == 0:
                    probe_content = client.objects(308, selected, probe)[0][1]
                    foreign_content = probe_call(850, probe_content, vault)[0][1]
                    probe_metadata = client.objects(6, metadata, probe, 9)[0][1]
                    foreign_metadata = probe_call(851, probe_metadata, vault)[0][1]
                    # Both are actual Vault-owned delegations from another live
                    # issuer, not fabricated handles. Launcher may not borrow them.
                    denied(lambda: server_content.call(client, 251, grant, foreign_content, 0, operation + 5))
                    denied(lambda: server_content.call(client, 251, grant, delegated, foreign_metadata, operation + 6))
                    # The failed metadata check also leaves the legitimate
                    # caller's content scope intact for its later valid request.
                    probe_grant = server_content.permit(client, probe, namespace, content.sha(manifest), len(raw), slot)
                    probe_call(852, probe_grant, foreign_content, 0, operation + 7)
                    # status252 must originate from the owned caller too.
                    # Probe op855 forwards it without broadening its authority.
                    deadline = time.monotonic() + 180
                    while True:
                        fields, _ = probe_call(855, probe_grant)
                        if fields[2] >= 4:
                            assert fields[2] == 4, fields
                            break
                        assert time.monotonic() < deadline
                        time.sleep(.02)
                    server_content.call(client, 256, probe_grant)
                    assert probe_call(854, probe_metadata, len(b'explicit-origin-probe'))[1] == b'explicit-origin-probe'
                    client.objects(7, metadata, probe_metadata)
                    probe_call(856, probe_content)
                # Normal path checks exact content issuer before closing it.
                server_content.call(client, 251, grant, delegated, 0, operation + slot*10 + 3)
                fields, _ = server_content.wait(client, grant, operation + slot*10 + 3)
                client.objects(309, selected)
            else:
                recovered = server_content.recover(client, grant, operation + slot*10)
                selected = recovered['content_handle']
                actual = bytearray()
                for offset in range(0, len(raw), 512):
                    actual.extend(client.objects(307, selected, offset, min(512, len(raw)-offset))[1])
                assert bytes(actual) == raw
                fields = [0, 0, 0, 0, len(raw), recovered['generation']]
                client.objects(309, selected)
            inventory, stored_manifest = server_content.call(client, 255, grant)
            assert stored_manifest == manifest and inventory[3] == len(raw)
            server_content.call(client, 256, grant)
            denied(lambda: server_content.call(client, 255, grant))
            results.append(dict(slot=slot, bytes=len(raw), chunks=len(chunks), generation=fields[5],
                namespace=namespace.hex(), manifest_sha256=content.sha(manifest).hex(),
                actual_payload_sha256=content.sha(raw).hex()))
        denied(lambda: server_content.permit(client, owner, bytes(32), content.sha(manifest), len(raw), 4))
        client.objects(8, metadata)
    finally:
        client.close()
    result = dict(schema=1, phase=args.phase, slots=results, personal_vault_used=False,
        checks=['four isolated selected archive slots', 'Objects15 exact issuer and recipient binding',
                'fresh operator grant and revoked grant rejection'] +
            (['Content316 exact issuer and recipient binding',
              'Server251 rejects nondelegated and cross-service handles without consuming them'] +
             (['Server251 rejects real foreign-issuer Content and Objects delegations before use; rightful issuer later retains same content'] if probe else [])
             if args.phase == 'retain' else ['all actual recovered bytes checked against source composition']))
    text = json.dumps(result, indent=2) + '\n'
    if args.output:
        args.output.write_text(text)
    print(text, end='')


if __name__ == '__main__':
    main()
