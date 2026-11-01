"""Replace only a native Mailbox app beneath idle authenticated terminal users.

Public capabilities and opaque staging bytes are component test inputs. Native
operators generate their own keys, persist recipient policy, dispatch typed RPC
and own all transport. A separate real Feed terminal must remain usable. This
does not claim signed Messenger message delivery or graphical Feed acceptance.
"""
import argparse
import contextlib
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import struct
import sys
import time
from types import SimpleNamespace as NS
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'tools'), str(ROOT/'tests')]
import feed
import identity
import messenger
import onion_route
import releases
import server_store
from messenger_journey import Guest, PUB, enroll, net, port, wait


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--image', type=Path, required=True)
    p.add_argument('--feed-packages', type=Path, required=True)
    p.add_argument('--mailbox', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    out, bundle = a.output.resolve(), a.feed_packages.resolve()
    out.mkdir(parents=True, exist_ok=False)
    image = out/'guest.bin';image.write_bytes(a.image.read_bytes())
    guests, checks, serials = [], [], {}
    began = time.monotonic()
    def passed(label, **fields):
        checks.append(dict(check=label, result='pass', **fields))
        (out/'progress.json').write_text(json.dumps(checks, indent=2)+'\n')
        print('PASS', label, json.dumps(fields), flush=True)
    def operator(name, kind, store=False):
        backing = out/(name+'.img') if store else None
        if backing:server_store.provision(backing)
        g = Guest(name, 'qemu', out, image, store=backing).start();guests.append(g)
        identity.start(g.client, bundle/'identity.ltrel', PUB)
        g.certificate, _ = onion_route.create(g.client, '127.0.0.1:'+str(port()),
                                               'independent replacement operator '+name, kind)
        (out/(name+'.certificate')).write_bytes(g.certificate)
        return g
    def client(name):
        g = Guest(name, 'qemu', out, image).start();guests.append(g)
        g.terminal_owner = messenger.launcher(g.client)
        return g
    def mailbox_start(g):
        owner, sid = feed.install_or_launch(g.client, a.mailbox, PUB, 2048)
        for op in (440, 441):messenger.bind(g.client, 3, owner, messenger.launcher(g.client), op, sid)
        messenger.bind(g.client, 3, owner, g.network, 441, sid)
        server_store.call(g.client, 230)
        grant = server_store.call(g.client, 231, owner, 2, 1048576,
                                 hashlib.sha256(b'isolated terminal replacement mailbox namespace').digest())[0][1]
        messenger.invoke(g.client, 3, 440, a=grant)
        return owner
    def rpc(g, operation, action, handle=0, offset=0, count=0, data=b''):
        serials[g.name] = serials.get(g.name, 0)+1
        serial = serials[g.name]
        net(g, 39, h=serial, data=struct.pack('<8Q', operation, action, handle, offset, count, 0, 0, 1)+data)
        def answer():
            f, raw = net(g, 40, h=serial, allow=(3, 6, 8))
            if f[0] == 6:return None
            if f[0]:return dict(terminal=list(f), application=None)
            assert len(raw) >= 64
            return dict(terminal=list(f), application=list(struct.unpack_from('<8Q', raw)), body=raw[64:].hex())
        return wait(answer, 180, g.name+' typed native application response')
    def selected(g, destination, relays):
        net(g, 42);net(g, 35)
        for i, relay in enumerate(relays):enroll(g, i, relay.certificate)
        enroll(g, 3, destination.certificate)
        net(g, 31)
        def route():
            f, _ = net(g, 32)
            if f[1] == 0 and f[3]:raise RuntimeError((g.name, 'selected native route failed', f))
            return f[2] == 3
        wait(route, 600, g.name+' selected native circuit')
        net(g, 38, h=3, a=23, b=g.terminal_owner, cword=1048576, d=256)
        def terminal():
            f, pin = net(g, 41)
            if f[2] == 4:raise RuntimeError((g.name, 'terminal unavailable', f))
            if f[2] != 3:return None
            assert pin == hashlib.sha256(destination.certificate).digest()
            return list(f)
        return wait(terminal, 600, g.name+' authenticated selected terminal')
    try:
        with ThreadPoolExecutor(5) as ex:
            futures = [ex.submit(operator, 'relay'+str(i), 7) for i in (1, 2, 3)]
            fm, ff = ex.submit(operator, 'mailbox', 8, True), ex.submit(operator, 'feed', 16, True)
            relays = [f.result() for f in futures]
            mailbox, federation = fm.result(), ff.result()
        mail_client, feed_client = client('mail-client'), client('feed-client')
        old_mailbox = mailbox_start(mailbox)
        home, peer = (hashlib.sha256(b'isolated replacement Feed '+v).hexdigest() for v in (b'home', b'peer'))
        feed_service = feed.federation_start(federation.client, NS(
            release=bundle/'feed-federation.ltrel', identity=bundle/'identity.ltrel', public=PUB,
            namespace=hashlib.sha256(b'isolated replacement Feed namespace').hexdigest(),
            federation=home, peer=peer, moderator=None, events=8, bytes=131072, policy=1))
        recipient = hashlib.sha256(b'isolated recipient').digest()
        deposit = hashlib.sha256(b'isolated component deposit capability').digest()
        fetch = hashlib.sha256(b'isolated component fetch capability').digest()
        f, _ = messenger.invoke(mailbox.client, 3, 440, h=1, a=65536, b=32,
                                data=recipient+hashlib.sha256(deposit).digest()+hashlib.sha256(fetch).digest(),
                                allowed_status=(0, 6))
        wait(lambda: messenger.invoke(mailbox.client, 3, 441, h=4, allowed_status=(0, 6))[0][0] == 0,
             180, 'native recipient capability policy committed')
        onion_route.enroll(relays[0].client, 0, relays[1].certificate)
        onion_route.enroll(relays[1].client, 0, relays[2].certificate)
        onion_route.enroll(relays[2].client, 0, mailbox.certificate)
        onion_route.enroll(relays[2].client, 1, federation.certificate)
        for g in (*relays, mailbox, federation):net(g, 30)
        selected(mail_client, mailbox, relays)
        selected(feed_client, federation, relays)
        first_feed = rpc(feed_client, 491, 8)
        assert first_feed['application'][0] == 0
        text = b'Uncommitted opaque component ciphertext for the old mailbox generation.'
        request = hashlib.sha256(b'isolated old exact application commitment').digest()
        old = rpc(mail_client, 441, 1, len(text), 1,
                  data=recipient+deposit+request+hashlib.sha256(text).digest())
        assert old['application'][0] == 0
        old_handle = old['application'][1]
        canceled = rpc(mail_client, 441, 7, old_handle, data=recipient+deposit)
        assert canceled['application'][0] == 0 and net(mail_client, 41)[0][2] == 3
        passed('old terminal owns and cancels an uncommitted stage while a different primary service remains authenticated',
               old_mailbox=old_mailbox, old_handle=old_handle, feed_status=first_feed,
               mailbox_network=mailbox.network, terminal=list(net(mail_client, 41)[0]))
        # Process replacement invalidates only the old application and exact
        # operation grants. Network, relay listeners and node credentials stay.
        mailbox.client.request(26, struct.pack('<Q', old_mailbox))
        new_mailbox = mailbox_start(mailbox)
        assert new_mailbox != old_mailbox
        assert mailbox.network == next(r[0] for r in identity.instances(mailbox.client) if r[0]&255 == 6)
        _, certificate = net(mailbox, 25, h=4)
        assert certificate[:480] == mailbox.certificate
        assert net(feed_client, 41)[0][2] == 3
        before = messenger.invoke(mailbox.client, 3, 440, h=6)[0]
        assert before[1] == 0
        second_request = hashlib.sha256(b'isolated new exact application commitment').digest()
        new_text = b'Fresh opaque component ciphertext authorized only after a fresh terminal relationship.'
        # Without an exact primary-target pin this BEGIN reaches the new app
        # through old NK keys/origin, allocates the canceled handle again, and a
        # stale append can address it. The fixed boundary retires before133.
        denied = rpc(mail_client, 441, 1, len(new_text), 1,
                     data=recipient+deposit+second_request+hashlib.sha256(new_text).digest())
        assert denied['application'] is None, ('old terminal dispatched to replacement', denied)
        wait(lambda: net(mail_client, 32)[0][1] == 0, 180, 'only affected terminal route retired after target replacement')
        after = messenger.invoke(mailbox.client, 3, 440, h=6)[0]
        assert after[1] == 0 and after[2:5] == before[2:5]
        fresh_feed = rpc(feed_client, 491, 8)
        assert fresh_feed['application'][0] == 0 and net(feed_client, 41)[0][2] == 3
        passed('idle old NK session cannot dispatch to a replacement primary app; unrelated Feed context still completes native RPC',
               old_mailbox=old_mailbox, new_mailbox=new_mailbox, stale_session_result=denied,
               unchanged_network=mailbox.network, new_stage_before=list(before), new_stage_after=list(after),
               unaffected_feed=fresh_feed, feed_terminal=list(net(feed_client, 41)[0]),
               relay_states={g.name:list(net(g, 32)[0]) for g in relays})
        selected(mail_client, mailbox, relays)
        fresh = rpc(mail_client, 441, 1, len(new_text), 1,
                    data=recipient+deposit+second_request+hashlib.sha256(new_text).digest())
        assert fresh['application'][0] == 0
        fresh_handle = fresh['application'][1]
        appended = rpc(mail_client, 441, 2, fresh_handle, data=recipient+deposit+new_text)
        assert appended['application'][0] == 0
        canceled = rpc(mail_client, 441, 7, fresh_handle, data=recipient+deposit)
        assert canceled['application'][0] == 0
        passed('fresh authenticated transport can use the replacement under current capability and exact app grant',
               old_uncommitted_handle=old_handle, new_handle=fresh_handle,
               serial_reuse_under_fresh_context=fresh_handle == old_handle,
               fresh_terminal=list(net(mail_client, 41)[0]), final_feed=rpc(feed_client, 491, 8))
        report = dict(schema=1, result='pass', image_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),
                      packages={name:releases.inspect(path.read_bytes())['release_id'] for name, path in
                                [('identity', bundle/'identity.ltrel'), ('feed-federation', bundle/'feed-federation.ltrel'), ('mailbox', a.mailbox)]},
                      feed_service=feed_service, checks=checks, seconds=time.monotonic()-began,
                      host_private_keys=False, host_relay=False, operator_stop_listen=False,
                      limits='Isolated all-QEMU native context replacement probe. Opaque ciphertext/capability inputs qualify staging authority, not signed Messenger acceptance or graphical community history. Feed is a real role16 service; same-Network Registry bank isolation is qualified separately by focused native state transitions.')
        (out/'evidence.json').write_text(json.dumps(report, indent=2)+'\n')
    except BaseException as error:
        (out/'failure.json').write_text(json.dumps(dict(schema=1, result='failed', error=repr(error), checks=checks), indent=2)+'\n')
        raise
    finally:
        for g in guests:g.stop()


if __name__ == '__main__':main()
