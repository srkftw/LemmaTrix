"""Useful native Messenger text/reply after naturally completed empty probes.

Run only after the capacity controller releases the same actors, and only when
its normal work has already crossed512 empty probes. No idle padding, process
replacement, route selection or authority renewal is performed here.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'tools'), str(ROOT/'tests')]
import messenger
import releases
from messenger_journey import inspect, net, role, send_ui, wait
from native_community_campaign import attach_campaign, focus_application

TEXT = 'The community remained available during relay capacity checks. This message follows native empty-mailbox checks beyond512.'
REPLY = 'This reply confirms useful Messenger work on the same approved private session after the long community operation.'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--attach', type=Path, required=True)
    args = p.parse_args()
    out = args.attach.resolve();path = out/'delivery-idle-useful-work.json'
    assert not path.exists(), 'preserve the prior installed idle-liveness result'
    package = out/'delivery-recovery-0.8.2.ltrel'
    info = releases.inspect(package.read_bytes())
    assert info['version'] == '0.8.2' and info['rights'] == 1024
    began = time.monotonic()
    report = dict(schema=1, result='running', package_release=info['release_id'],
                  controller_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  idle_wait_added=False, process_or_route_replacement=False,
                  operator_stop_listen=False, authority_renewal=False)
    def save():path.write_text(json.dumps(report, indent=2)+'\n')
    with attach_campaign(out, graphical=('alice', 'bob')) as campaign:
        alice, bob = (campaign.actors[n] for n in ('alice', 'bob'))
        report['configuration'] = campaign.state['configuration']
        def observe(g):
            assert campaign.state['current_runtime_packages']['messenger_by_person'][g.name]['delivery'] == info['release_id']
            assert g.client.request(14, bytes.fromhex(info['project_id']))[64:96].hex() == info['release_id']
            assert messenger.endpoint(g.client, 4, 464) == g.delivery
            counter = role(g, 4, 464, a=5)[0]
            terminal, pin = net(g, 41)
            assert counter[0] == 0 and counter[1] <= 512 and counter[4] != 7, (g.name, counter)
            assert terminal[1:3] == (1, 3), (g.name, terminal)
            return dict(delivery=g.delivery, owner=g.owner, ui=g.ui, counters=list(counter),
                        terminal=list(terminal), pin=pin.hex())
        def received(g, text):
            status = role(g, 2, 420)[0]
            for cursor in range(1, status[4]+1):
                fields, body = role(g, 2, 429, h=cursor, allow=(3,))
                if fields[0] == 0 and body == text.encode():return list(fields)
        def send(g, recipient, text):
            focus_application(g, 'messenger')
            previous = inspect(g)[0];assert previous[2:4] == (0, 0)
            started = time.monotonic();serial, _ = send_ui(g, text)
            answer = wait(lambda: received(recipient, text), 600,
                          'new native plaintext after more than512 naturally completed empty probes')
            return dict(sender=g.name, recipient=recipient.name, serial=serial,
                        prior_ui_serial=previous[6], body_sha256=hashlib.sha256(text.encode()).hexdigest(),
                        native_inbox=answer, seconds=time.monotonic()-started)
        try:
            report['before'] = {g.name:observe(g) for g in (alice, bob)};save()
            assert any(x['counters'][6] >= 513 for x in report['before'].values()), 'this case requires naturally observed513 empty probes before any useful-work gesture'
            report['text'] = send(alice, bob, TEXT);save()
            report['reply'] = send(bob, alice, REPLY);save()
            report['after'] = {g.name:observe(g) for g in (alice, bob)}
            for name, before in report['before'].items():
                after = report['after'][name]
                assert after['delivery'] == before['delivery'] and after['owner'] == before['owner'] and after['ui'] == before['ui']
                assert after['pin'] == before['pin']
                assert after['counters'][2] > before['counters'][2]
                assert after['counters'][6] >= before['counters'][6]
                assert after['terminal'][4] < before['terminal'][4] and after['terminal'][5] < before['terminal'][5]
            report.update(result='pass', elapsed_seconds=time.monotonic()-began,
                          checks=['actual native UI text and reply decrypt in unchanged private session owners',
                                  'more than512 completed empty probes arose during the preceding normal community work',
                                  'same0.8.2 coordinators and selected routes continue spending finite parent bytes/attempts'],
                          limits=['Local integration on the identified common image; previous scoped route loss and authorized recovery remain separate evidence.',
                                  'This test neither renews terminal allowances nor asserts unlimited unattended operation.'])
            save();print(json.dumps(report, indent=2), flush=True)
        except BaseException as error:
            report.update(result='failed', error=repr(error), elapsed_seconds=time.monotonic()-began)
            save();raise


if __name__ == '__main__':main()
