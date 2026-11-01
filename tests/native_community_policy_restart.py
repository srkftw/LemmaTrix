"""Continue the common native community with policy and operator recovery.

The native UI authors reports, appeals and maintenance discussion. Operators
request native signed decisions and retain encrypted native key state. The only
fault is availability of exact opaque guest process groups; no host event,
policy result, private identity seed or replication message is supplied.
"""
import argparse
import hashlib
import json
import os
import signal
import struct
import sys
import time
import traceback
from pathlib import Path
from types import SimpleNamespace as NS

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'tools'), str(ROOT / 'tests')]
import feed
import identity
import onion
import releases
from messenger_journey import Guest, PUB, net, screenshot, wait
from native_community_campaign import attach_campaign, feed_ui, focus_application, select_feed_route

BETA_NOTE = ('This project review remains committed while its Beta federation operator restarts. '
             'The replacement service must recover the original signed event, its finite retry '
             'reservation and its selected Alpha audience before continuing replication.')
ALPHA_NOTE = ('Alpha accepted this independent release review while Beta was offline for maintenance. '
              'The approved native peer relationship must resume delivery after Beta recovers; '
              'operator restart must preserve policy and spent replication allowances.')
HOME_NOTE = 'This Beta-only review note explains that private moderation reports and appeals stay with their intended federation; selecting a peer audience for other discussion does not broaden this post.'
REPORT = 'Please review my own reply under the Beta federation visibility policy. This report is intended only for its moderators.'
APPEAL = 'I appeal the local visibility decision on my own reply and request an explicit reviewed result.'


def rows(guest, private=False):
    result, cursor = [], 0
    for _ in range(64):
        fields, record = feed.invoke(guest.client, 490 if private else 491,
                                     action=1 if private else 5, handle=cursor, allowed=(0, 6))
        if fields[0] == 6:
            return result
        assert len(record) == 512
        assert hashlib.sha256(record[32:]).digest() == record[:32]
        result.append((fields, record))
        cursor = fields[1]
    raise RuntimeError('native bounded event index has no termination')


def find(guest, *, event_id=None, author=None, kind=None, text=None, target=None, action=None, private=False):
    for fields, record in rows(guest, private):
        event = record[32:]
        if event_id is not None and record[:32] != event_id:
            continue
        if author is not None and event[112:144] != author:
            continue
        if kind is not None and struct.unpack_from('<Q', event, 176)[0] != kind:
            continue
        if text is not None and event[224:256] != hashlib.sha256(text.encode()).digest():
            continue
        if target is not None and event[368:400] != target:
            continue
        if action is not None and struct.unpack_from('<Q', event, 400)[0] != action:
            continue
        return fields, record
    return None


def select(guest, event_id):
    focus_application(guest, 'feed')
    guest.device.press(104)
    for _ in range(64):
        wait(lambda: feed_ui(guest)[0][4] in (15, 16, 26, 40), 300,
             'native checked event or explicit visibility marker')
        _, selected = feed_ui(guest, 795)
        if selected[:32] == event_id:
            return feed_ui(guest)[0]
        previous = selected[:32]
        guest.device.press(28)
        wait(lambda: feed_ui(guest, 795)[1][:32] != previous, 300,
             'native next chronological event')
    raise RuntimeError('native selected event was not found')


def compose(guest, text, key=61):
    focus_application(guest, 'feed')
    wait(lambda: feed_ui(guest)[0][5] in (0, 6, 7), 300,
         'native previous publication settled')
    guest.device.press(key)
    wait(lambda: feed_ui(guest)[0][2] in (1, 6, 7), 120, 'native compose')
    guest.device.textASCII(text, delay=.035)
    wait(lambda: feed_ui(guest)[0][3] == len(text), 300, 'native complete input')
    guest.device.press(62)
    wait(lambda: feed_ui(guest)[0][2] == 9, 120, 'native exact preview')
    guest.device.press(63)


def checked_body(guest, record, length):
    result = []
    for offset in range(0, length, 512):
        _, chunk = feed.invoke(guest.client, 491, action=6, offset=offset,
                               count=min(512, length-offset), data=record[:32])
        result.append(chunk)
    body = b''.join(result)
    assert len(body) == length and hashlib.sha256(body).digest() == record[256:288]
    return body


def key_credential(path):
    if not path.exists():
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            assert os.write(fd, os.urandom(32)) == 32
            os.fsync(fd)
        finally:
            os.close(fd)
    value = path.read_bytes()
    assert len(value) == 32
    return value


def moderator(guest):
    _, descriptor = feed.invoke(guest.client, 490, action=6)
    assert len(descriptor) == 256 and struct.unpack_from('<Q', descriptor, 16)[0] == 6
    return dict(generation=struct.unpack_from('<Q', descriptor, 24)[0], public=descriptor[96:128].hex())



def check_replication_lease(guest, operator, endpoint):
    """Explicit operator stage boundary; never a per-event reset or keepalive.

    Native authority expires normally. Only an observed stale/expired grant3
    permits one same-policy reauthorization from the remaining durable total.
    The existing ABI exposes aggregate reservations, not row568 attempt counts.
    """
    before_phase = feed.invoke(guest.client, 490, action=3)[0]
    before, policy = feed.invoke(guest.client, 490, action=12)
    result = dict(operator=guest.name, before_phase=list(before_phase),
                  before_budget=list(before), policy_hash=policy.hex(), renewed=False,
                  row_attempt_counts='not exposed by the existing native operator API',
                  attempt_authority='durable per-event attempts remain charged; no reset operation is invoked')
    if before_phase[1] == 6:
        if before_phase[3] != 3:
            raise RuntimeError(('native replication stopped for a reason other than lease expiry/stale authority', guest.name, before_phase))
        previous = operator['replication']
        feed.replication(guest.client, NS(
            peer=0, side='server' if guest.name == 'alpha' else 'client', slot=0,
            scope=previous['scope'], endpoint=endpoint,
            bytes=previous['bytes'], rate=previous['rate'], lifetime=previous['lifetime']))
        after, after_policy = feed.invoke(guest.client, 490, action=12)
        assert after_policy == policy
        assert after[1] == before[1] and after[4:7] == before[4:7]
        assert after[2] == before[2] and after[5] == before[5]
        assert 0 < after[3]-before[3] <= 1048576 and after[3] <= after[1]
        result.update(renewed=True, after_budget=list(after),
                      after_phase=list(feed.invoke(guest.client, 490, action=3)[0]),
                      disclosure='explicit operator renewal of expired finite transport authority from the same persisted policy; no event quota, total allowance, lifetime or hash was changed')
    else:
        result.update(after_budget=list(before), after_phase=list(before_phase),
                      disclosure='current authority remains within its finite approved lifetime; no renewal was attempted')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--attach', type=Path, required=True)
    parser.add_argument('--feed-packages', type=Path, required=True)
    parser.add_argument('--stage', choices=('moderation', 'restart'), required=True)
    parser.add_argument('--resume', action='store_true')
    args = parser.parse_args()
    out, bundle = args.attach.resolve(), args.feed_packages.resolve()
    progress = out / 'policy-restart-progress.json'
    state = json.loads(progress.read_text()) if args.resume else dict(schema=1, done={}, checks=[])
    assert args.resume or not progress.exists(), 'use --resume to preserve prior observations'
    began, stage, paused_alpha = time.monotonic(), 'attach common actors', None

    def save():
        progress.write_text(json.dumps(state, indent=2) + '\n')

    def record(key, label, **extra):
        state['done'][key] = True
        state['checks'].append(dict(check=label, result='pass', **extra))
        save()
        print('PASS', label, extra, flush=True)

    skip = ('beta',) if args.stage == 'restart' and state['done'].get('pending-beta') and not state['done'].get('recovered') else ()
    with attach_campaign(out, graphical=('alice', 'bob'), skip=skip) as campaign:
        assert campaign.state['done'].get('cancel'), 'core connected contention journey must finish first'
        assert all(releases.inspect((bundle/(name+'.ltrel')).read_bytes())['release_id'] ==
                   campaign.state['configuration']['feed'][name]
                   for name in ('identity', 'feed', 'feed-account', 'feed-federation'))
        actors = campaign.actors
        alpha, beta = actors['alpha'], actors.get('beta')
        alice, bob = actors['alice'], actors['bob']
        relays = [actors['relay'+str(i)] for i in (1, 2, 3)]
        author = bytes.fromhex(campaign.state['personal']['alice']['feed_public'])
        target = bytes.fromhex(campaign.state['events']['reply']['id'])
        state['configuration'] = campaign.state['configuration']
        state['target'] = target.hex()
        try:
            lease_checks = []
            for name in ('alpha', 'beta'):
                if actors.get(name) is not None:
                    lease_checks.append(check_replication_lease(
                        actors[name], campaign.state['actors'][name], campaign.state['bulk_endpoint']))
            state.setdefault('lease_checks', []).append(dict(stage=args.stage, operators=lease_checks))
            save()
            print('Native finite lease stage checks', json.dumps(lease_checks), flush=True)
            if args.stage == 'moderation':
                select_feed_route(alice, beta, relays)
                select_feed_route(bob, alpha, relays)
                original = find(beta, event_id=target)
                assert original and original[1][144:176] == author
                if not state['done'].get('block'):
                    select(bob, target)
                    bob.device.press(66)
                    wait(lambda: feed_ui(bob)[0][4] == 18, 180, 'native private local block')
                    record('block', 'Alpha reader privately blocks the Beta reply author')
                report = find(beta, author=author, kind=6, target=target, private=True)
                if report is None:
                    select(alice, target)
                    compose(alice, REPORT, 67)
                    report = wait(lambda: find(beta, author=author, kind=6, target=target, private=True),
                                  600, 'native private report committed')
                state['report'] = report[1][:32].hex()
                assert find(alpha, event_id=report[1][:32], private=True) is None
                record('report', 'native report reaches only its intended federation and grants no moderator authority', event=state['report'])

                def decide(action, reason):
                    found = find(beta, kind=8, target=target, action=action, private=True)
                    if found:
                        return found[1][:32]
                    feed.invoke(beta.client, 490, action=5, handle=action,
                                data=target+reason.encode(), allowed=(0, 6))
                    def finished():
                        f, body = feed.invoke(beta.client, 490, action=6, allowed=(0, 6))
                        return body if f[0] == 0 and len(body) == 32 else None
                    return wait(finished, 600, 'native authorized signed policy decision')

                hidden = decide(1, 'Reviewed report: hide this reply under Beta local policy version1.')
                if not state['done'].get('hidden'):
                    assert find(beta, event_id=target)[0][5] == 0
                    denied, _ = feed.invoke(beta.client, 491, action=6, count=134,
                                            data=target, allowed=(1,))
                    assert denied[0] == 1 and find(alpha, event_id=target)[0][5] == 1
                state['hidden'] = hidden.hex()
                record('hidden', 'authorized Beta policy hides the exact event and refuses ordinary direct reads while Alpha keeps its permitted view')
                appeal = find(beta, author=author, kind=7, target=target, private=True)
                if appeal is None:
                    select(alice, hidden)
                    compose(alice, APPEAL, 68)
                    appeal = wait(lambda: find(beta, author=author, kind=7, target=target, private=True),
                                  600, 'native author appeal committed')
                state['appeal'] = appeal[1][:32].hex()
                assert find(alpha, event_id=appeal[1][:32], private=True) is None
                reversed_id = decide(3, 'Appeal reviewed: reverse the local visibility decision and preserve signed policy history.')
                after = find(beta, event_id=target)
                assert after[0][5] == 1 and after[1] == original[1]
                reversal = find(beta, event_id=reversed_id, private=True)[1]
                assert reversal[224:256] == hidden
                select(alice, reversed_id)
                assert feed_ui(alice, 795)[1] == reversal
                assert select(bob, target)[4] == 16
                assert find(alpha, event_id=target)[1] == original[1]
                state['reversal'] = reversed_id.hex()
                state['original'] = original[1].hex()
                state['frames'] = {g.name: screenshot(g, 'native-policy-result') for g in (alice, bob)}
                record('moderation', 'requester inspects authorized superseding appeal reversal; original author bytes, independent Alpha policy and private local block remain intact', event=state['reversal'])
                if not state['done'].get('refusals'):
                    home = find(beta, author=author, kind=1, text=HOME_NOTE)
                    if home is None:
                        alice.device.press(30)
                        compose(alice, HOME_NOTE)
                        home = wait(lambda: find(beta, author=author, kind=1, text=HOME_NOTE),
                                    600, 'native explicit home-only publication accepted')
                    assert home[1][336:368] == bytes(32)
                    assert find(alpha, event_id=home[1][:32]) is None
                    wrong, _ = feed.invoke(alpha.client, 491, action=1,
                                            data=home[1][32:], allowed=(11,))
                    altered = bytearray(original[1][32:])
                    altered[-1] ^= 1
                    bad, _ = feed.invoke(beta.client, 491, action=1,
                                          data=altered, allowed=(10,))
                    usage = feed.invoke(beta.client, 490, action=9)[0]
                    budget = feed.invoke(beta.client, 490, action=12)[0]
                    duplicate, _ = feed.invoke(beta.client, 491, action=1, data=home[1][32:])
                    assert duplicate[2] == 2
                    assert feed.invoke(beta.client, 490, action=9)[0] == usage
                    assert feed.invoke(beta.client, 490, action=12)[0] == budget
                    alice.device.press(30)
                    state['home_only'] = home[1][:32].hex()
                    record('refusals', 'actual native home-only signed event is refused by Alpha with11; altered signature is refused with10; exact retry preserves event count, storage and finite replica allowance', wrong_audience=wrong[0], altered_signature=bad[0], exact_duplicate=list(duplicate), event=state['home_only'])
            else:
                assert state['done'].get('moderation'), 'run the moderation stage first'
                if not state['done'].get('pending-beta'):
                    select_feed_route(alice, beta, relays)
                if not state['done'].get('pending-alpha'):
                    select_feed_route(bob, alpha, relays)
                if not state['done'].get('sealed'):
                    node_key = key_credential(out/'beta.node-unlock')
                    mod_key = key_credential(out/'beta.moderator-unlock')
                    beta.client.request(178, struct.pack('<2Q', beta.network, 1))
                    onion.call(beta.client, 43, data=node_key)
                    feed.invoke(beta.client, 490, action=7, data=mod_key, allowed=(0, 6))
                    wait(lambda: feed.invoke(beta.client, 490, action=6, allowed=(0, 6))[0][0] == 0,
                         600, 'native moderator seal committed')
                    state['before_moderator'] = moderator(beta)
                    record('sealed', 'operator explicitly retains native node and moderator keys under independent unlock credentials; no identity seeds are exported')
                if not state['done'].get('pending-beta'):
                    if 'before_beta_budget' not in state:
                        state['before_beta_budget'] = list(feed.invoke(beta.client, 490, action=12)[0])
                        save()
                    paused_alpha = alpha.process.pid
                    os.killpg(paused_alpha, signal.SIGSTOP)
                    if not find(beta, author=author, kind=1, text=BETA_NOTE):
                        compose(alice, BETA_NOTE)
                    row = wait(lambda: find(beta, author=author, kind=1, text=BETA_NOTE),
                               600, 'native Beta event committed while exact Alpha peer is unavailable')
                    wait(lambda: feed.invoke(beta.client, 490, action=12)[0][2] > state['before_beta_budget'][2],
                         600, 'native exact event retry reservation committed before transmission')
                    publication, _ = feed.invoke(beta.client, 491, action=4, data=row[1][:32])
                    assert publication[2] == 2
                    state['beta_pending'] = row[1].hex()
                    state['reserved_beta_budget'] = list(feed.invoke(beta.client, 490, action=12)[0])
                    state['beta_checkpoint'] = feed.invoke(beta.client, 490, action=3)[0][4]
                    state['beta_counts'] = list(feed.invoke(beta.client, 490, action=9)[0])
                    save()
                    beta.stop()
                    os.killpg(paused_alpha, signal.SIGCONT)
                    paused_alpha = None
                    record('pending-beta', 'native Beta accepts an original event and reserves finite retry work before its operator stops; Alpha resumes independently')
                if not state['done'].get('pending-alpha'):
                    bob_author = bytes.fromhex(campaign.state['personal']['bob']['feed_public'])
                    if not find(alpha, author=bob_author, kind=1, text=ALPHA_NOTE):
                        compose(bob, ALPHA_NOTE)
                    row = wait(lambda: find(alpha, author=bob_author, kind=1, text=ALPHA_NOTE),
                               600, 'native Alpha event accepted while Beta operator is offline')
                    state['alpha_pending'] = row[1].hex()
                    state['alpha_budget'] = list(feed.invoke(alpha.client, 490, action=12)[0])
                    record('pending-alpha', 'unrelated Alpha native service accepts another author while Beta is offline')
                if not state['done'].get('recovered'):
                    stage = 'cold native Beta operator recovery'
                    if beta is None and (out/'beta.sock').exists():
                        # An interrupted recovery may have a replacement process
                        # but no confirmed grants. Restart only that exact guest;
                        # current counters remain in its native backing.
                        partial = Guest('beta', 'qemu', out, out/'guest.bin', store=out/'beta.img').attach(None)
                        partial.stop()
                    replacement = Guest('beta', 'qemu', out, out/'guest.bin', store=out/'beta.img').start()
                    actors['beta'] = beta = replacement
                    identity.start(beta.client, bundle/'identity.ltrel', PUB)
                    beta.client.request(178, struct.pack('<2Q', beta.network, 1))
                    onion.call(beta.client, 44, data=key_credential(out/'beta.node-unlock'))
                    _, certificate = onion.call(beta.client, 25, h=4)
                    assert certificate[:480] == (out/'beta.certificate').read_bytes()
                    beta.certificate = certificate[:480]
                    from messenger_journey import enroll
                    enroll(beta, 0, alpha.certificate)
                    previous = campaign.state['actors']['beta']['feed']
                    service = feed.federation_start(beta.client, NS(
                        release=bundle/'feed-federation.ltrel', identity=bundle/'identity.ltrel', public=PUB,
                        namespace=previous['namespace'], federation=previous['federation'], peer=previous['peer'],
                        moderator=previous['moderator_public'], recover_key=out/'beta.moderator-unlock',
                        events=64, bytes=917504, policy=1))
                    recovered = moderator(beta)
                    assert recovered['public'] == state['before_moderator']['public']
                    assert recovered['generation'] == state['before_moderator']['generation']+1
                    assert list(feed.invoke(beta.client, 490, action=12)[0]) == state['reserved_beta_budget']
                    assert feed.invoke(beta.client, 490, action=3)[0][4] == state['beta_checkpoint']
                    assert list(feed.invoke(beta.client, 490, action=9)[0])[1:3] == state['beta_counts'][1:3]
                    assert find(beta, event_id=bytes.fromhex(state['beta_pending'])[:32])[1].hex() == state['beta_pending']
                    assert find(beta, event_id=target)[0][5] == 1
                    net(beta, 30)
                    replication = feed.replication(beta.client, NS(
                        peer=0, side='client', slot=0,
                        scope=campaign.state['actors']['beta']['replication']['scope'],
                        endpoint=campaign.state['bulk_endpoint'], bytes=16777216, rate=65536, lifetime=100000))
                    campaign.state['actors']['beta'].update(network=beta.network, feed=service, replication=replication)
                    (out/'native-actors.json').write_text(json.dumps(campaign.state, indent=2)+'\n')
                    public = out/'continuations.json'
                    if public.exists():
                        continuation = json.loads(public.read_text())
                        continuation['actors']['beta'] = campaign.state['actors']['beta']
                        public.write_text(json.dumps(continuation, indent=2)+'\n')
                    record('recovered', 'Beta cold recovery recreates current grants and preserves exact pending event, checkpoint, moderator policy and spent event/transport allowances', moderator=recovered)
                for key, destination in (('beta_pending', alpha), ('alpha_pending', beta)):
                    original = bytes.fromhex(state[key])
                    row = wait(lambda: find(destination, event_id=original[:32]),
                               900, 'native automatic pending event replication resumes after operator recovery')
                    assert row[1] == original
                    checked_body(destination, original, struct.unpack_from('<Q', original, 288)[0])
                after = list(feed.invoke(beta.client, 490, action=12)[0])
                assert after[2] == state['reserved_beta_budget'][2]
                assert after[3] == state['reserved_beta_budget'][3]+1048576
                assert after[5] == state['reserved_beta_budget'][5]
                assert feed.invoke(alpha.client, 490, action=12)[0][3] == state['alpha_budget'][3]
                assert select(bob, target)[4] == 16
                select_feed_route(alice, beta, relays)
                alice.device.press(63 if feed_ui(alice)[0][5] == 8 else 19)
                wait(lambda: feed_ui(alice)[0][5] == 7, 600, 'author obtains actual replication evidence for its original accepted event through a fresh selected route')
                state['after_beta_budget'] = after
                record('restart', 'both final-image peers automatically resume original signed pending events without operator peer reset or renewed event budget; persisted appeal reversal and local block survive')
            state.update(result='pass-'+args.stage, elapsed_seconds=time.monotonic()-began)
            save()
            (out/('policy-'+args.stage+'.json')).write_text(json.dumps(state, indent=2)+'\n')
        except BaseException as error:
            state.update(result='failure-preserved-common-community', stage=stage, error=repr(error),
                         traceback=traceback.format_exc(), elapsed_seconds=time.monotonic()-began)
            save()
            (out/'policy-restart-failure.json').write_text(json.dumps(state, indent=2)+'\n')
            raise
        finally:
            if paused_alpha is not None:
                os.killpg(paused_alpha, signal.SIGCONT)


if __name__ == '__main__':
    main()
