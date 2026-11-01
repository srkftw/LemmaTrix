#!/usr/bin/env python3
"""Exercise the observed POSIX submit/interrupt token-ownership boundary.

These stubs send real process signals but never launch or contact native actors.
"""
import os
import signal
import struct

import identity
import messenger
import messenger_journey
import messenger_retention
import onion
import onion_route


class Bridge:
    def __init__(self, interrupt=None, submit_error=False):
        self.interrupt = interrupt
        self.submit_error = submit_error
        self.calls = []

    def request(self, operation, payload=b''):
        self.calls.append((operation, payload))
        if operation == 2:
            return struct.pack('<4Q', 6, 1, 0, 0)
        if operation == 172:
            return struct.pack('<Q', 7)
        if operation == 175:
            if self.submit_error:
                raise OSError('submit was not admitted')
            if self.interrupt == 'submit':
                os.kill(os.getpid(), signal.SIGINT)
            return struct.pack('<Q', 99)
        if operation == 176:
            if self.interrupt == 'collect':
                os.kill(os.getpid(), signal.SIGINT)
            return bytes(64) + b'checked-response'
        if operation == 177:
            assert struct.unpack('<Q', payload) == (99,)
            return bytes(8)
        raise AssertionError(operation)


helpers = [
    ('Messenger operator', lambda bridge: messenger.invoke(bridge, 6, 490)),
    ('Onion operator', lambda bridge: onion.call(bridge, 20)),
    ('Identity operator', lambda bridge: identity.invoke(bridge, 410)),
    ('Messenger journey', lambda bridge: messenger_journey.async_call(bridge, 6, 32)),
    ('Onion journey', lambda bridge: onion_route.route(bridge, 32)),
    ('Messenger retention', lambda bridge: messenger_retention.invoke(bridge, 420)),
]

before = signal.pthread_sigmask(signal.SIG_BLOCK, set())
try:
    # Retain an unrelated existing blocked signal as well as the usual mask.
    for mask in (before, before | {signal.SIGUSR1}):
        signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        for label, invoke in helpers:
            for stage in ('submit', 'collect'):
                bridge = Bridge(interrupt=stage)
                try:
                    invoke(bridge)
                except KeyboardInterrupt:
                    pass
                else:
                    raise AssertionError((label, stage, 'signal was not delivered'))
                operations = [op for op, _ in bridge.calls]
                assert operations[-1] == 177 and operations.count(177) == 1, (label, stage, operations)
                assert signal.pthread_sigmask(signal.SIG_BLOCK, set()) == mask, (label, stage)
            assert invoke(Bridge()) == ((0,) * 8, b'checked-response'), label
            failed = Bridge(submit_error=True)
            try:
                invoke(failed)
            except OSError:
                pass
            else:
                raise AssertionError((label, 'submit error was swallowed'))
            assert 177 not in [op for op, _ in failed.calls], label
            assert signal.pthread_sigmask(signal.SIG_BLOCK, set()) == mask, label
finally:
    signal.pthread_sigmask(signal.SIG_SETMASK, before)

print('PASS six operator/journey helpers: real submit/collect SIGINT cancels the exact acquired token; successful completion, submit error and prior masks preserved')
