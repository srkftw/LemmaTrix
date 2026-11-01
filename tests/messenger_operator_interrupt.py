#!/usr/bin/env python3
"""Exercise the observed POSIX submit/interrupt token-ownership boundary."""
import os
import signal
import struct

import messenger


class Bridge:
    def __init__(self, interrupt=False):
        self.interrupt = interrupt
        self.calls = []

    def request(self, operation, payload=b''):
        self.calls.append((operation, payload))
        if operation == 172:
            return struct.pack('<Q', 7)
        if operation == 175:
            if self.interrupt:
                os.kill(os.getpid(), signal.SIGINT)
            return struct.pack('<Q', 99)
        if operation == 176:
            return bytes(64) + b'checked-response'
        if operation == 177:
            assert struct.unpack('<Q', payload) == (99,)
            return bytes(8)
        raise AssertionError(operation)


before = signal.pthread_sigmask(signal.SIG_BLOCK, set())
bridge = Bridge(interrupt=True)
try:
    messenger.invoke(bridge, 6, 490)
except KeyboardInterrupt:
    pass
else:
    raise AssertionError('the submit-time signal was not delivered')
assert [op for op, _ in bridge.calls] == [172, 175, 177]
assert signal.pthread_sigmask(signal.SIG_BLOCK, set()) == before
assert messenger.invoke(Bridge(), 6, 490) == ((0,) * 8, b'checked-response')
assert signal.pthread_sigmask(signal.SIG_BLOCK, set()) == before
print('PASS real submit-time SIGINT cancels its exact returned token; completion and prior mask preserved')
