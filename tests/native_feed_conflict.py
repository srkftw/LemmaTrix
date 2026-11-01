"""Actual native Feed refuses valid signed sequence conflicts and finite quota.

An isolated installed typed signer consumer obtains fresh native entropy keys
and separate one-use native approvals. The host selects canonical boundary-test
inputs and transports outputs; it never obtains a seed or signs an event. This
is an application refusal probe, not graphical community acceptance.
"""
import argparse
import hashlib
import json
import struct
import sys
import time
from pathlib import Path
from types import SimpleNamespace as NS
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'tools'), str(ROOT/'tests')]
import feed
import identity
import live_acceptance as accept
import messenger
import releases
import server_store
from messenger_journey import Guest, PUB, wait
from native_identity import verify


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--feed-packages', type=Path, required=True)
    parser.add_argument('--probe', type=Path, default=ROOT/'build/feed-signer-exact-consumer/feed-signer-client.ltrel')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out, bundle = args.output.resolve(), args.feed_packages.resolve()
    out.mkdir(parents=True, exist_ok=False)
    image = out/'guest.bin'
    image.write_bytes(args.image.read_bytes())
    backing = out/'operator.img'
    server_store.provision(backing)
    guest = Guest('conflict', 'qemu', out, image, store=backing).start()
    checks = []
    began = time.monotonic()
    def passed(label, **details):
        checks.append(dict(check=label, result='pass', **details))
        print('PASS', label, details, flush=True)
    try:
        signer = identity.start(guest.client, bundle/'identity.ltrel', PUB)
        home = hashlib.sha256(b'Campaign009 isolated native conflict federation').hexdigest()
        peer = hashlib.sha256(b'Campaign009 isolated unselected peer').hexdigest()
        service = feed.federation_start(guest.client, NS(
            release=bundle/'feed-federation.ltrel', identity=bundle/'identity.ltrel', public=PUB,
            namespace=hashlib.sha256(b'Campaign009 isolated conflict purpose2 store').hexdigest(),
            federation=home, peer=peer, moderator=None, events=1, bytes=16384, policy=1))
        probe, probe_id = feed.install_or_launch(guest.client, args.probe, PUB, 1024)
        launcher = messenger.launcher(guest.client)
        messenger.bind(guest.client, 5, probe, launcher, 480, probe_id)
        signer_id = bytes.fromhex(releases.inspect((bundle/'identity.ltrel').read_bytes())['release_id'])
        for op in (402, 410):
            identity.bind(guest.client, signer['service'], probe, signer_id, probe_id, op)
        def request(inner):
            raw = guest.client.request(150, struct.pack('<Q', probe)+accept.command(480, data=inner))
            fields = accept.fields(raw)
            assert fields[0] == 0
            job = fields[1]
            def complete():
                raw = guest.client.request(150, struct.pack('<Q', probe)+accept.command(480, h=1, a=job))
                fields = accept.fields(raw)
                return (fields, raw[64:]) if fields[0] != 6 else None
            return wait(complete, 300, 'current typed native signer consumer completion')
        scope = hashlib.sha256(b'Campaign009 isolated author exact account scope').digest()
        fields, descriptor = request(accept.command(410, data=bytes.fromhex(home)+scope))
        assert fields[0] == 0 and len(descriptor) == 288
        key, public = fields[1], descriptor[96:128]
        verify(public, descriptor[:192], descriptor[192:256], out/'descriptor')
        passed('current exact role5 consumer creates a native entropy Ed25519 key', public=public.hex())
        def sign(sequence, text):
            body = bytearray(256)
            struct.pack_into('<4Q', body, 0, 0x3144564546544c, 1, 1, sequence)
            body[64:96] = hashlib.sha256(text).digest()
            struct.pack_into('<Q', body, 96, len(text))
            body[112:144] = bytes.fromhex(home)
            approval, _ = request(accept.command(410, h=1, a=key, data=hashlib.sha256(body).digest()))
            assert approval[0] == 0
            result, event = request(accept.command(402, h=approval[1], data=body))
            assert result[0] == 0 and len(event) == 480
            assert event[160:416] == body and event[112:144] == public
            verify(public, event[:416], event[416:], out/('event-'+str(approval[1])))
            return event
        first_text = b'First exact commitment for the isolated native author-sequence boundary.'
        conflicting_text = b'Different exact commitment for that same native author and sequence.'
        next_text = b'A fresh native author sequence still respects the one-event operator quota.'
        first = sign(1, first_text)
        conflict = sign(1, conflicting_text)
        next_event = sign(2, next_text)
        assert first[112:144] == conflict[112:144] == next_event[112:144] == public
        assert first != conflict and first[160+24:160+32] == conflict[160+24:160+32]
        for label, event in [('first', first), ('conflicting', conflict), ('over-quota', next_event)]:
            (out/(label+'.signed-event')).write_bytes(event)
        passed('three canonical valid events receive independent one-use native approvals and native signatures', same_author=True, first_sequence=1, conflicting_sequence=1, next_sequence=2)
        fields, _ = feed.invoke(guest.client, 491, action=1, data=first)
        handle = fields[1]
        event_id = hashlib.sha256(first).digest()
        feed.invoke(guest.client, 491, action=2, handle=handle, count=len(first_text), data=event_id+first_text)
        feed.invoke(guest.client, 491, action=3, handle=handle, data=event_id, allowed=(0, 6))
        wait(lambda: feed.invoke(guest.client, 491, action=4, data=event_id, allowed=(0, 6))[0][0] == 0,
             300, 'native content and metadata commit before accepted')
        usage = feed.invoke(guest.client, 490, action=9)[0]
        budget = feed.invoke(guest.client, 490, action=12)[0]
        assert usage[1] == 1 and usage[2] == len(first_text)
        duplicate, _ = feed.invoke(guest.client, 491, action=1, data=first)
        assert duplicate[1] == 1 and duplicate[2] == 2
        assert feed.invoke(guest.client, 490, action=9)[0] == usage
        assert feed.invoke(guest.client, 490, action=12)[0] == budget
        passed('exact duplicate reconciles committed acceptance before exhausted quota without new event, bytes or reservation', event=event_id.hex(), usage=list(usage), budget=list(budget))
        refused, _ = feed.invoke(guest.client, 491, action=1, data=conflict, allowed=(12,))
        assert refused[0] == 12
        quota, _ = feed.invoke(guest.client, 491, action=1, data=next_event, allowed=(4,))
        assert quota[0] == 4
        assert feed.invoke(guest.client, 490, action=9)[0] == usage
        assert feed.invoke(guest.client, 490, action=12)[0] == budget
        passed('actual native service refuses a valid different same-author sequence commitment with12 and valid next sequence at finite quota with4', conflict=refused[0], quota=quota[0])
        fields, row = feed.invoke(guest.client, 491, action=5)
        assert row == event_id+first and fields[4] == len(first_text)
        _, body = feed.invoke(guest.client, 491, action=6, count=len(first_text), data=event_id)
        assert body == first_text
        passed('original signed event and checked immutable content remain readable after both refusals')
        report = dict(schema=1, result='pass', image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),
                      packages={name: releases.inspect((bundle/(name+'.ltrel')).read_bytes())['release_id'] for name in ('identity', 'feed-federation')},
                      probe_release=releases.inspect(args.probe.read_bytes())['release_id'], service=service,
                      native_public_key=public.hex(), checks=checks, seconds=time.monotonic()-began,
                      host_private_keys=False, authoritative_host_feed_database=False,
                      limits='Isolated all-QEMU native application refusal probe. Canonical boundary inputs are explicit test data; this is not UI-authored connected community history.')
        (out/'evidence.json').write_text(json.dumps(report, indent=2)+'\n')
    except BaseException as error:
        (out/'failure.json').write_text(json.dumps(dict(schema=1, result='failed', error=repr(error), checks=checks), indent=2)+'\n')
        raise
    finally:
        guest.stop()


if __name__ == '__main__':
    main()
