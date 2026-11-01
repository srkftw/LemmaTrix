"""Fill the final native relay's six paired routes, refuse one and reuse one.

This continuation preserves existing community actors. Extra bare native
clients explicitly select public certificates and Launcher-owned terminal
contexts through the supported operator API; they only read real Feed status.
No application identity, event, private key, operator handoff or host relay is
created. A full OS listener backlog can delay native refusal to the existing
100000-tick handshake deadline; that latency is measured, not shortened here.
"""
import argparse
import contextlib
import hashlib
import json
from pathlib import Path
import struct
import sys
import time
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'tools'), str(ROOT/'tests')]
import messenger
from messenger_journey import Guest, enroll, net, wait
from native_community_campaign import attach_campaign, select_destination


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--attach', type=Path, required=True)
    p.add_argument('--refusal-timeout', type=int, default=1500,
                   help='wall-clock bound; native setup deadline remains100000 local ticks')
    a = p.parse_args()
    out = a.attach.resolve()
    evidence = out/'relay-capacity'
    evidence.mkdir(exist_ok=False)
    started, probes, checks = time.monotonic(), [], []
    serials = {}
    def save():
        (evidence/'progress.json').write_text(json.dumps(dict(checks=checks,
            elapsed_seconds=time.monotonic()-started), indent=2)+'\n')
    def passed(label, **fields):
        checks.append(dict(check=label, result='pass', **fields));save()
        print('PASS', label, json.dumps(fields), flush=True)
    with attach_campaign(out, graphical=()) as campaign:
        actors = campaign.actors
        alice, bob, charlie = (actors[n] for n in ('alice', 'bob', 'charlie'))
        relays = [actors['relay'+str(i)] for i in (1, 2, 3)]
        alpha = actors['alpha']
        original = {}
        def unaffected():
            current = {}
            for g in (alice, bob):
                f, pin = net(g, 41)
                assert f[1] == 1 and f[2] == 3, (g.name, f)
                if g.name in original:
                    assert pin.hex() == original[g.name]['pin'], (g.name, 'terminal pin changed')
                current[g.name] = dict(terminal=list(f), pin=pin.hex())
            return current
        def observe():
            return dict(personal=unaffected(), relays={g.name:list(net(g, 32)[0]) for g in relays})
        def circuit(g, label):
            net(g, 31)
            last = [0.0]
            def ready():
                f, _ = net(g, 32)
                if time.monotonic()-last[0] >= 30:
                    last[0] = time.monotonic()
                    print('Native capacity route', label, list(f), flush=True)
                    unaffected()
                if f[1] == 0 and f[3] != 0:
                    raise RuntimeError((label, 'native route failed before six-pair capacity', f))
                return f if f[2] == 3 else None
            return wait(ready, 900, label+' native selected three-hop circuit')
        def terminal(g, owner, label):
            net(g, 38, h=3, a=31, b=owner, cword=1048576, d=256)
            def ready():
                f, pin = net(g, 41)
                if f[2] == 4:
                    raise RuntimeError((label, 'native terminal refused', f))
                if f[2] != 3:return None
                assert pin == hashlib.sha256(alpha.certificate).digest()
                return dict(terminal=list(f), pin=pin.hex())
            return wait(ready, 600, label+' authenticated Alpha terminal')
        def rpc(g):
            serials[g.name] = serials.get(g.name, 0)+1
            serial = serials[g.name]
            # Public typed491/status is served by the actual role16 operator.
            # The remote Network injects its own transport origin as usual.
            net(g, 39, h=serial, data=struct.pack('<8Q', 491, 8, 0, 0, 0, 0, 0, 1))
            def complete():
                f, raw = net(g, 40, h=serial, allow=(6,))
                if f[0] == 6:return None
                assert len(raw) == 64
                answer = struct.unpack('<8Q', raw)
                assert answer[0] == 0
                return list(answer)
            return wait(complete, 180, g.name+' native Feed status round trip')
        def owned_close(g):
            # These are only this independent personal guest's Network roles.
            # No relay, terminal operator or shared service receives stop/listen.
            net(g, 42);net(g, 35)
        try:
            original.update(unaffected())
            f, _ = net(charlie, 41)
            restored_charlie = False
            if f[2] != 3:
                # The preceding no-vault case deliberately closed Charlie's
                # route before replacing its owner. Re-establish transport only;
                # no new account key or retained state is created here.
                owned_close(charlie)
                for slot, relay in enumerate(relays):enroll(charlie, slot, relay.certificate)
                select_destination(charlie, alpha.certificate)
                circuit(charlie, 'fresh no-vault Charlie')
                terminal(charlie, charlie.feed_owner, 'fresh no-vault Charlie')
                restored_charlie = True
            passed('three existing personal guests remain concurrently admitted on the selected relays',
                   restored_only_charlie_transport=restored_charlie,
                   charlie_terminal=list(net(charlie, 41)[0]), observed=observe())
            for i in range(4):
                g = Guest('capacity-probe'+str(i+1), 'qemu', evidence, out/'guest.bin').start()
                probes.append(g)
                for slot, relay in enumerate(relays):enroll(g, slot, relay.certificate)
                enroll(g, 3, alpha.certificate)
                g.capacity_owner = messenger.launcher(g.client)
                if i == 3:continue
                began = time.monotonic()
                route = circuit(g, g.name)
                admitted = terminal(g, g.capacity_owner, g.name)
                status = rpc(g)
                passed('independent headless native client joins the same three relays and real Alpha service',
                       client=g.name, selected_owner=g.capacity_owner, owner='current native Launcher',
                       circuit=list(route), **admitted, feed_status=status,
                       simultaneous_complete_routes=4+i, seconds=time.monotonic()-began,
                       unrelated=unaffected())
            active = probes[:3]
            six = {g.name:dict(terminal=list(net(g, 41)[0]), feed_status=rpc(g)) for g in active}
            assert all(record['terminal'][2] == 3 for record in six.values())
            assert net(charlie, 41)[0][2] == 3
            passed('six complete native routes coexist across twelve channels per selected relay',
                   extra_clients=six, observed=observe(),
                   accounting='Each admitted route owns an incoming/outgoing pair in each relay; six authenticated client terminals imply twelve occupied channels. Existing read-only32 exposes channels0/1 only, so no unimplemented full census is claimed.')
            overflow = probes[3]
            began = time.monotonic()
            initial, _ = net(overflow, 31)
            observations, last = [], [0.0]
            def refused():
                f, _ = net(overflow, 32)
                now = time.monotonic()
                if now-last[0] >= 30:
                    last[0] = now
                    sample = dict(seconds=now-began, overflow=list(f), unrelated=unaffected(),
                                  six_extra_terminals={g.name:list(net(g, 41)[0]) for g in active})
                    observations.append(sample)
                    (evidence/'overflow-observations.json').write_text(json.dumps(observations, indent=2)+'\n')
                    print('Native full-capacity admission remains pending', json.dumps(sample), flush=True)
                if f[2] == 3:
                    raise AssertionError(('seventh route unexpectedly admitted before any owned release', f))
                if f[1] == 0 and f[3] != 0:return f
                return None
            rejected = wait(refused, a.refusal_timeout, 'actual native seventh-client refusal at unchanged setup deadline')
            assert all(net(g, 41)[0][2] == 3 for g in active)
            assert net(charlie, 41)[0][2] == 3
            passed('seventh incoming client receives an actual bounded native refusal while six admitted clients remain healthy',
                   initial=list(initial), refusal=list(rejected), seconds=time.monotonic()-began,
                   native_setup_deadline_ticks=100000,
                   pending_probe_application_requests_submitted=0,
                   feed_round_trips={g.name:rpc(g) for g in active}, observed=observe(),
                   material_limit='The retained OS listener can queue an overflow TCP connection until the native handshake deadline; this is measured native refusal latency, not a controller cancellation.')
            # Close one probe's own circuit. The other five routes and operators
            # keep their keys, contexts and listener operation throughout.
            victim = active[0]
            owned_close(victim)
            began = time.monotonic()
            route = circuit(overflow, overflow.name+' retry after one owned close')
            admitted = terminal(overflow, overflow.capacity_owner, overflow.name+' reused capacity')
            status = rpc(overflow)
            passed('the refused independent client reuses one released pair without operator reset',
                   closed_only=victim.name, reused_by=overflow.name,
                   circuit=list(route), **admitted, feed_status=status,
                   survivors={g.name:dict(terminal=list(net(g, 41)[0]), feed_status=rpc(g)) for g in active[1:]},
                   observed=observe(), seconds=time.monotonic()-began)
            report = dict(schema=1, result='pass', image_sha256=hashlib.sha256((out/'guest.bin').read_bytes()).hexdigest(),
                          selected_public_certificates={g.name:hashlib.sha256(g.certificate).hexdigest() for g in (*relays, alpha)},
                          checks=checks, elapsed_seconds=time.monotonic()-started,
                          declared_capacity=dict(onion_channels_per_relay=12, complete_paired_routes_per_relay=6,
                                                 independent_extra_native_guests=4, terminal_bytes=1048576, terminal_requests=256),
                          private_keys_exported=False, host_data_plane=False, operator_stop_listen_handoffs=False,
                          limits=['Local common-image continuation; relay2 may use the RV64 interpreter on native-x86.',
                                  'Headless clients explicitly use native Launcher-owned read-only typed Feed transport contexts; they are not new graphical Feed authors.',
                                  'Native32 lacks a full per-channel census; exact pairing is evidenced by six independently authenticated three-hop terminals and the implementation resource contract.'])
            (out/'relay-capacity.json').write_text(json.dumps(report, indent=2)+'\n')
        except BaseException as error:
            (out/'relay-capacity-failure.json').write_text(json.dumps(dict(schema=1, result='failed',
                error=repr(error), checks=checks, elapsed_seconds=time.monotonic()-started), indent=2)+'\n')
            raise
        finally:
            for g in probes:
                if g.client:
                    with contextlib.suppress(Exception):owned_close(g)
                g.stop()


if __name__ == '__main__':main()
