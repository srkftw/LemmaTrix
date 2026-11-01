"""Recover one real Feed operator from its own native backing.

Node and moderator keys must first be explicitly sealed by native commands.
This controller never edits backing, supplies private seeds, authors events,
or moves replication traffic. Repeated configuration must preserve allowance.
"""
import argparse
import hashlib
import json
import struct
import sys
import time
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'tools'), str(ROOT / 'tests')]
from messenger_journey import Guest, PUB
import feed
import identity
import network
import onion
import onion_route
import releases


def snapshot(client, prior):
    fields, public = feed.invoke(client, 490, action=9)
    assert fields[1] == prior['event_count']
    assert fields[2] == prior['content_bytes']
    assert public[64:96].hex() == prior['public_moderator']
    _, moderator = feed.invoke(client, 490, action=6)
    assert len(moderator) == 256
    assert struct.unpack_from('<Q', moderator, 16)[0] == 6
    generation = struct.unpack_from('<Q', moderator, 24)[0]
    checkpoint = feed.invoke(client, 490, action=3)[0][4]
    recovered = []
    # Read the useful long post and the appealed reply after recovery. The
    # original signature envelope commits the exact bytes and original event ID.
    for cursor in (1, 2):
        header, record = feed.invoke(client, 491, action=5, handle=cursor)
        assert len(record) == 512
        assert hashlib.sha256(record[32:]).digest() == record[:32]
        assert header[5] == 1
        chunks = []
        for offset in range(0, header[4], 512):
            _, chunk = feed.invoke(client, 491, action=6, offset=offset,
                                   count=min(512, header[4] - offset), data=record[:32])
            chunks.append(chunk)
        body = b''.join(chunks)
        assert len(body) == header[4]
        assert hashlib.sha256(body).digest() == record[256:288]
        recovered.append(dict(event_id=record[:32].hex(), body_bytes=len(body),
                              body_sha256=hashlib.sha256(body).hexdigest(), visible=header[5]))
    budget, policy = feed.invoke(client, 490, action=12)
    return dict(moderator_generation=generation, event_count=fields[1],
                content_bytes=fields[2], checkpoint=checkpoint,
                recovered_checked_content=recovered, budget=list(budget),
                policy_hash=policy.hex())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--attach', type=Path, required=True)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--packages', type=Path, required=True)
    parser.add_argument('--iterations', type=int, choices=range(1, 4), default=2)
    args = parser.parse_args()
    out, bundle = args.attach.resolve(), args.packages.resolve()
    state = json.loads((out / 'continuation.json').read_text())
    prior = json.loads((out / 'operator5.pre-restart.json').read_text())
    frozen = out / 'operator5-final-guest.bin'
    frozen.write_bytes(args.image.read_bytes())
    guest = Guest('node5', 'qemu', out, frozen, store=out / 'operator5.img').attach(None)
    runs = []
    baseline = None
    try:
        try:
            baseline = snapshot(guest.client, prior)
        except ValueError:
            # The first invocation may attach after node recovery but before
            # Feed has been mounted. No absent baseline is claimed as verified.
            pass
        initial_baseline = baseline
        for iteration in range(args.iterations):
            began = time.monotonic()
            print('Restarting only historical Beta operator', iteration + 1, flush=True)
            guest.stop()
            guest = Guest('node5', 'qemu', out, frozen, store=out / 'operator5.img').start()
            identity.start(guest.client, bundle / 'identity.ltrel', PUB)
            network_owner = next(row[0] for row in identity.instances(guest.client)
                                 if row[0] & 255 == 6)
            guest.client.request(178, struct.pack('<2Q', network_owner, 1))
            node_status, _ = onion.call(guest.client, 44,
                                       data=(out / 'operator5.node-unlock').read_bytes())
            _, certificate = onion.call(guest.client, 25, h=4)
            assert certificate[:480] == (out / 'node5.certificate').read_bytes()
            print('Recovered identical native node certificate', iteration + 1, flush=True)
            onion_route.enroll(guest.client, 0, (out / 'node4.certificate').read_bytes())
            config = SimpleNamespace(
                release=bundle / 'feed-federation.ltrel', identity=bundle / 'identity.ltrel',
                public=PUB, namespace=hashlib.sha256(b'Campaign009 Feed store5').hexdigest(),
                federation=state['personal']['selected_peer'], peer=state['personal']['federation'],
                moderator=prior['public_moderator'], recover_key=out / 'operator5.unlock',
                events=64, bytes=917504, policy=1)
            print('Recovering native Feed index and moderator seal', iteration + 1, flush=True)
            service = feed.federation_start(guest.client, config)
            recovered = snapshot(guest.client, prior)
            if baseline:
                assert recovered['moderator_generation'] == baseline['moderator_generation'] + 1
                assert recovered['checkpoint'] == baseline['checkpoint']
                assert recovered['budget'] == baseline['budget']
                assert recovered['policy_hash'] == baseline['policy_hash']
            before = recovered['budget'][3]
            network.call(guest.client, 30, slot=0)
            relationship_args = SimpleNamespace(
                peer=0, side='client', slot=0, scope=state['replication'][1]['scope'],
                endpoint=state['bulk_endpoint'], bytes=16777216, rate=65536, lifetime=100000)
            print('Allocating from the persisted finite allowance', iteration + 1, flush=True)
            feed.replication(guest.client, relationship_args)
            budget, policy = feed.invoke(guest.client, 490, action=12)
            assert budget[1] == 16777216
            assert budget[3] == before + min(1048576, 16777216 - before)
            feed.replication(guest.client, relationship_args)
            assert feed.invoke(guest.client, 490, action=12)[0] == budget
            recovered.update(iteration=iteration + 1, service=service, budget=list(budget),
                             policy_hash=policy.hex(), node_recovered=list(node_status),
                             same_certificate=True, repeated_configuration_unchanged=True,
                             seconds=time.monotonic() - began)
            runs.append(recovered)
            (out / 'restart-progress.json').write_text(json.dumps(runs, indent=2) + '\n')
            baseline = recovered
            print('PASS native operator recovery', json.dumps(recovered), flush=True)
        report = dict(
            schema=1, result='pass', image_sha256=hashlib.sha256(frozen.read_bytes()).hexdigest(),
            package_ids={name: releases.inspect((bundle / (name + '.ltrel')).read_bytes())['release_id']
                         for name in ('identity', 'feed-federation')},
            baseline=initial_baseline, runs=runs, private_keys_exported=False, host_backing_edits=False,
            limits='Only Beta restarted; Alpha remains on historical image4. Unused transport '
                   'allocations are conservatively burned. No live grants are restored.')
        (out / 'restart.json').write_text(json.dumps(report, indent=2) + '\n')
    except BaseException as error:
        (out / 'restart-failure.json').write_text(json.dumps(
            dict(schema=1, error=repr(error), completed_runs=runs, baseline=baseline), indent=2) + '\n')
        raise
    finally:
        if guest.client:
            guest.client.close()


if __name__ == '__main__':
    main()
