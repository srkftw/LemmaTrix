"""Two native operators exercise explicitly finite replication lease rollover.

Only native code signs the test event, commits backing and exchanges replica
frames. SIGSTOP delays an opaque recipient; the controller observes original
signed bytes after resumption. Manual consent, finite exhaustion and revoked
peer authority are separate isolated native refusal cases.
"""
import argparse
import contextlib
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import signal
import struct
import sys
import time
from types import SimpleNamespace as NS
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'tools'), str(ROOT/'tests')]
import feed
import identity
import live_acceptance as accept
import messenger
import network
import onion
import onion_route
import releases
import server_store
from messenger_journey import Guest, PUB, SIGN, port, wait


def budget(g):
    fields, policy = feed.invoke(g.client, 490, action=12)
    return dict(fields=list(fields), policy=policy.hex(),
                authority=list(feed.invoke(g.client, 490, action=13)[0]),
                phase=list(feed.invoke(g.client, 490, action=3)[0]))


def attempts(g):
    n = feed.invoke(g.client, 490, action=9)[0][1]
    return [list(feed.invoke(g.client, 490, action=14, handle=i)[0]) for i in range(n)]


def admit_parent(client, path):
    raw = path.read_bytes()
    client.request(10, raw[128:160]+releases.public_modulus(PUB))
    client.stage(path)
    client.request(23, raw[160:192]+struct.pack('<Q', 3072))
    client.request(24)


def sign_event(g, bundle, probe_path, home, peer, text):
    probe, probe_id = feed.install_or_launch(g.client, probe_path, PUB, 1024)
    messenger.bind(g.client, 5, probe, messenger.launcher(g.client), 480, probe_id)
    signer = identity.endpoint(g.client, 410)
    signer_id = bytes.fromhex(releases.inspect((bundle/'identity.ltrel').read_bytes())['release_id'])
    for op in (402, 410):
        identity.bind(g.client, signer, probe, signer_id, probe_id, op)
    def request(inner):
        raw = g.client.request(150, struct.pack('<Q', probe)+accept.command(480, data=inner))
        f = accept.fields(raw)
        assert f[0] == 0
        job = f[1]
        def complete():
            raw = g.client.request(150, struct.pack('<Q', probe)+accept.command(480, h=1, a=job))
            f = accept.fields(raw)
            return (f, raw[64:]) if f[0] != 6 else None
        return wait(complete, 300, 'native exact typed signing consumer')
    f, public = request(accept.command(410, data=bytes.fromhex(home)+hashlib.sha256(b'isolated rolling author scope').digest()))
    assert f[0] == 0
    body = bytearray(256)
    struct.pack_into('<4Q', body, 0, 0x3144564546544c, 1, 1, 1)
    body[64:96] = hashlib.sha256(text).digest()
    struct.pack_into('<Q', body, 96, len(text))
    body[112:144], body[144:176] = bytes.fromhex(home), bytes.fromhex(peer)
    approved, _ = request(accept.command(410, h=1, a=f[1], data=hashlib.sha256(body).digest()))
    signed, event = request(accept.command(402, h=approved[1], data=body))
    assert signed[0] == 0 and len(event) == 480 and event[160:416] == body
    assert public[96:128] == event[112:144]
    return event


def commit(g, event, text):
    f, _ = feed.invoke(g.client, 491, action=1, data=event)
    handle, event_id = f[1], hashlib.sha256(event).digest()
    for offset in range(0, len(text), 512):
        chunk = text[offset:offset+512]
        feed.invoke(g.client, 491, action=2, handle=handle, offset=offset, count=len(chunk), data=event_id+chunk)
    feed.invoke(g.client, 491, action=3, handle=handle, data=event_id, allowed=(0, 6))
    wait(lambda: feed.invoke(g.client, 491, action=4, data=event_id, allowed=(0, 6))[0][0] == 0,
         120, 'native immutable event acceptance')
    return event_id


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--image', type=Path, required=True)
    p.add_argument('--feed-packages', type=Path, required=True)
    p.add_argument('--rolling-package', type=Path, required=True)
    p.add_argument('--probe', type=Path, default=ROOT/'build/feed-signer-exact-consumer/feed-signer-client.ltrel')
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    out, bundle = a.output.resolve(), a.feed_packages.resolve()
    out.mkdir(parents=True, exist_ok=False)
    image = out/'guest.bin'
    image.write_bytes(a.image.read_bytes())
    guests, checks = [], []
    began = time.monotonic()
    def passed(label, **kw):
        checks.append(dict(check=label, result='pass', **kw))
        (out/'progress.json').write_text(json.dumps(checks, indent=2)+'\n')
        print('PASS', label, json.dumps(kw), flush=True)
    homes = [hashlib.sha256(b'Campaign009 isolated rolling '+bytes([i])).hexdigest() for i in range(2)]
    def start(name, own, peer):
        path = out/(name+'.img')
        server_store.provision(path)
        g = Guest(name, 'qemu', out, image, store=path).start()
        guests.append(g)
        identity.start(g.client, bundle/'identity.ltrel', PUB)
        endpoint = '127.0.0.1:'+str(port())
        cert, _ = onion_route.create(g.client, endpoint, 'isolated rolling '+name, kind=16)
        (out/(name+'.certificate')).write_bytes(cert)
        admit_parent(g.client, bundle/'feed-federation.ltrel')
        service = feed.federation_start(g.client, NS(
            release=a.rolling_package, identity=bundle/'identity.ltrel', public=PUB,
            namespace=hashlib.sha256(b'isolated rolling native backing '+name.encode()).hexdigest(),
            federation=own, peer=peer, moderator=None, events=8, bytes=131072, policy=1))
        return g, cert, service
    try:
        with ThreadPoolExecutor(2) as executor:
            f = executor.submit(start, 'rolling-alpha', homes[0], homes[1])
            h = executor.submit(start, 'rolling-beta', homes[1], homes[0])
            alpha, cert_a, service_a = f.result()
            beta, cert_b, service_b = h.result()
        onion_route.enroll(alpha.client, 0, cert_b)
        onion_route.enroll(beta.client, 0, cert_a)
        # The long-running onion listener remains independently enabled while
        # the expressly approved bulk relationship uses separate channels.
        onion.call(alpha.client, 30)
        onion.call(beta.client, 30)
        bulk = '127.0.0.1:'+str(port())
        scope = hashlib.sha256(b'isolated explicitly rolling replica policy').hexdigest()
        cfg_a = NS(peer=0, side='server', slot=0, endpoint=bulk, scope=scope,
                   bytes=4194304, rate=65536, lifetime=2000, auto_renew=True)
        cfg_b = NS(**vars(cfg_a));cfg_b.side = 'client'
        # Sign before allocating time-limited transport authority. The native
        # probe has only its exact current role5 consumer signing authority.
        text = (b'This isolated native replication review must survive a finite transport lease while its recipient is delayed. '
                b'The original signed event, exact selected federation audience, committed body and charged attempts must remain unchanged. '
                b'Resuming a recipient must not need operator stop/listen, a replacement event, or a renewed semantic allowance.')
        event = sign_event(alpha, bundle, a.probe, homes[0], homes[1], text)
        (out/'native-original.signed-event').write_bytes(event)
        config_b = feed.replication(beta.client, cfg_b)
        os.killpg(beta.process.pid, signal.SIGSTOP)
        stopped = True
        try:
            config_a = feed.replication(alpha.client, cfg_a)
            event_id = commit(alpha, event, text)
            first = wait(lambda: s if (s:=budget(alpha))['fields'][2] > 0 else None,
                         60, 'positive durable event reservation before rollover')
            first_attempts = attempts(alpha)
            print('Committed native event with opaque recipient stalled', first, first_attempts, flush=True)
            def rolled():
                s = budget(alpha)
                if s['authority'][3] == 2:
                    raise AssertionError(('native rollover failed', s))
                return s if s['fields'][3] >= 2097152 and s['authority'][3] == 0 else None
            second = wait(rolled, 100, 'native durable rolling allocation while exact event remains pending')
            assert second['policy'] == first['policy']
            assert second['fields'][1] == first['fields'][1]
            assert second['fields'][2] >= first['fields'][2] > 0
            assert second['fields'][5] >= first['fields'][5] > 0
            after_attempts = attempts(alpha)
            assert after_attempts[0][3] >= first_attempts[0][3] and after_attempts[0][3] <= 9
            assert after_attempts[0][4:6] == first_attempts[0][4:6]
            passed('native finite rollover preserves a pending exact event, its positive reservation and charged attempts',
                   before=first, after=second, attempts_before=first_attempts, attempts_after=after_attempts)
        finally:
            if stopped:
                os.killpg(beta.process.pid, signal.SIGCONT)
                stopped = False
        def received():
            f, row = feed.invoke(beta.client, 491, action=5, allowed=(0, 6))
            if f[0] == 6:
                for g in (alpha, beta):
                    s = budget(g)
                    if s['authority'][3] == 2:
                        raise AssertionError(('native rolling peer stopped before actual replication', g.name, s))
                return None
            assert row == event_id+event
            return f
        got = wait(received, 150, 'two native operators replicate exact committed event after rolling renewal')
        _, body = feed.invoke(beta.client, 491, action=6, count=len(text), data=event_id)
        assert body == text and hashlib.sha256(body).digest() == event[224:256]
        passed('two native role16 operators resume the delayed recipient and replicate original signed bytes/content after renewal without host renewal',
               event=event_id.hex(), body_bytes=len(body), alpha=budget(alpha), beta=budget(beta),
               native_network_contexts=[list(network.call(g.client, 7, slot=0)[0]) for g in (alpha, beta)])
        def exhausted():
            s = budget(alpha)
            return s if s['authority'][3] == 2 and s['authority'][4] == 4 else None
        exhausted_at = wait(exhausted, 150, 'finite rolling policy exhaustion')
        assert exhausted_at['fields'][3] == exhausted_at['fields'][1] == 4194304
        time.sleep(3)
        stable = budget(alpha)
        assert stable['fields'] == exhausted_at['fields'] and stable['authority'][2:5] == [0, 2, 4]
        passed('exhausted finite pool stops with quota4 and no repeated allocation', before=exhausted_at, after=stable)
        # Free both native services before independent manual/revocation cases.
        for g in (alpha, beta):g.stop()
        manual, cert_m, _ = start('manual', homes[0], homes[1])
        onion_route.enroll(manual.client, 0, cert_b)
        onion.call(manual.client, 30)
        cfg_m = NS(peer=0, side='server', slot=0, endpoint='127.0.0.1:'+str(port()),
                   scope=scope, bytes=3145728, rate=65536, lifetime=500, auto_renew=False)
        feed.replication(manual.client, cfg_m)
        manual_first = budget(manual)
        expired = wait(lambda: s if (s:=budget(manual))['phase'][1:4:2] == [6, 3] else None,
                       40, 'manual finite grant expiry')
        time.sleep(2)
        assert budget(manual)['fields'] == manual_first['fields']
        assert expired['authority'][1:4] == [1, 0, 0]
        cfg_m.auto_renew = True
        try:
            feed.replication(manual.client, cfg_m)
        except ValueError as e:
            assert str(e) == 'native service status11'
        else:raise AssertionError('manual retained policy silently upgraded rolling consent')
        assert budget(manual)['fields'] == manual_first['fields']
        passed('legacy manual policy neither renews nor silently upgrades its retained consent', before=manual_first, expired=expired)
        manual.stop()
        revoked, cert_r, _ = start('revoked', homes[0], homes[1])
        onion_route.enroll(revoked.client, 0, cert_b)
        onion.call(revoked.client, 30)
        cfg_r = NS(peer=0, side='server', slot=0, endpoint='127.0.0.1:'+str(port()),
                   scope=scope, bytes=3145728, rate=65536, lifetime=500, auto_renew=True)
        feed.replication(revoked.client, cfg_r)
        before_revoke = budget(revoked)
        onion.call(revoked.client, 24, h=0)
        def denied():
            s = budget(revoked)
            return s if s['authority'][3] == 2 else None
        denied_at = wait(denied, 40, 'revoked native enrollment stops fresh rolling authority')
        assert denied_at['authority'][2:5] == [0, 2, 3]
        assert denied_at['fields'][3] <= before_revoke['fields'][3]+1048576
        time.sleep(3)
        assert budget(revoked)['fields'] == denied_at['fields']
        passed('revoked native peer causes at most one conservative allocation then a stable failure latch', before=before_revoke, after=denied_at)
        report = dict(schema=1, result='pass', image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),
                      original_federation_parent=releases.inspect((bundle/'feed-federation.ltrel').read_bytes())['release_id'],
                      rolling_release=releases.inspect(a.rolling_package.read_bytes())['release_id'],
                      identity_release=releases.inspect((bundle/'identity.ltrel').read_bytes())['release_id'],
                      services=[service_a, service_b], checks=checks, seconds=time.monotonic()-began,
                      host_signing=False, host_backing_edits=False, host_replication=False,
                      limits='Isolated all-QEMU two-operator application/runtime probe with explicit native test-consumer approvals. It does not replace the graphical multi-user common campaign or independently administered operation.')
        (out/'evidence.json').write_text(json.dumps(report, indent=2)+'\n')
    except BaseException as e:
        (out/'failure.json').write_text(json.dumps(dict(schema=1, result='failed', error=repr(e), checks=checks), indent=2)+'\n')
        raise
    finally:
        for g in guests:
            with contextlib.suppress(Exception):os.killpg(g.process.pid, signal.SIGCONT)
            g.stop()


if __name__ == '__main__':main()
