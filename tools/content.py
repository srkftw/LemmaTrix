"""Explicit content import/bootstrap and reproducible original PCM resources.

The adapter constructs commitments and transports selected bytes to ContentJobs.
The Lean ContentStore independently validates every hash, Merkle path, quota,
publication and scoped range read. This module is never a playback decoder,
consumer catalog, acquisition scheduler, persistent store or network authority.
"""
import argparse
import array
import hashlib
import json
import struct
import sys
import time
from pathlib import Path

MANIFEST_MAGIC = 0x31544e434d544c
LEAF_DOMAIN = 0x314641454c544c
BRANCH_DOMAIN = 0x3148434e42544c
CHUNK = 4096
CAPACITY = 1472 * CHUNK
RECIPE = b'LemmaTrix Original: Open Courtyard; integer triangle score v1; 48000 Hz; CC0-1.0 dedication for generated audio only'
COLLECTION = hashlib.sha256(b'LemmaTrix Open Courtyard original collection v1').digest()


class ContentClient:
    """Opaque ABI2 command adapter; operation meanings stay in the guest."""
    def __init__(self, client):
        self.client = client

    def objects(self, op, h=0, a=0, b=0, c=0, d=0, e=0, data=b''):
        if not 300 <= op <= 316:
            return self.client.objects(op, h, a, b, c, d, e, data=data)
        raw = self.client.request(160, struct.pack('<8Q', op, h, a, b, c, d, e, 1) + data)
        if len(raw) < 64:
            raise ValueError('short ContentJobs response')
        fields = struct.unpack_from('<8Q', raw)
        if fields[0]:
            raise ValueError(f'ContentJobs status{fields[0]}')
        return fields, raw[64:]

    def __getattr__(self, name):
        return getattr(self.client, name)


def api(client):
    return client if isinstance(client, ContentClient) else ContentClient(client)


def sha(raw):
    return hashlib.sha256(raw).digest()


def leaf(index, length, digest):
    return sha(struct.pack('<3Q', LEAF_DOMAIN, index, length) + digest)


def branch(left, right):
    return sha(struct.pack('<Q', BRANCH_DOMAIN) + left + right)


def commitments(raw, content_id=None, provenance=sha(RECIPE)):
    if not 0 < len(raw) <= CAPACITY:
        raise ValueError('content exceeds the explicitly volatile 6,029,312-byte profile')
    chunks = [raw[offset:offset + CHUNK] for offset in range(0, len(raw), CHUNK)]
    hashes = [sha(part) for part in chunks]
    width = 1 << (len(chunks) - 1).bit_length()
    level = [leaf(i, len(chunks[i]), hashes[i]) if i < len(chunks)
             else leaf(i, 0, sha(b'')) for i in range(width)]
    levels = [level]
    while len(level) > 1:
        level = [branch(level[i], level[i + 1]) for i in range(0, len(level), 2)]
        levels.append(level)
    content_id = content_id if content_id is not None else sha(b'LT-CONTENT-1' + sha(raw))
    if len(content_id) != 32:
        raise ValueError('immutable content identity must contain exactly 32 bytes')
    manifest = (struct.pack('<8Q', MANIFEST_MAGIC, 1, CHUNK, len(raw), len(chunks), 1,
                            len(levels) - 1, 0) + content_id + level[0] + provenance + bytes(96))
    proofs = []
    for i, digest in enumerate(hashes):
        proof = bytearray(digest)
        cursor = i
        for level in levels[:-1]:
            proof.extend(level[cursor ^ 1])
            cursor //= 2
        proofs.append(bytes(proof))
    return manifest, chunks, proofs


def triangle(phase):
    x = (phase >> 16) & 65535
    return x * 2 - 32768 if x < 32768 else 98303 - x * 2


def original_wave(seconds=30, channels=2, later=False):
    """Original deterministic score. No external recording or licensed sample.

    The integer oscillators, fixed score, tick envelopes and sample packing
    make every byte reproducible without floating point/libm dependencies.
    """
    if channels not in (1, 2) or not 0 < seconds <= 30:
        raise ValueError('supported recipe is >0–30 seconds, mono/stereo')
    rate = 48000
    frames = int(seconds * rate)
    melody = ([392, 440, 523, 587, 659, 587, 523, 440,
               349, 392, 440, 523, 587, 523, 440, 392] if later else
              [262, 330, 392, 523, 440, 392, 330, 294,
               349, 440, 523, 659, 587, 523, 440, 392])
    chords = [(131, 165, 196), (110, 131, 165), (87, 110, 131), (98, 123, 147)]
    phases = [0, 0, 0, 0]
    output = array.array('h')
    for frame in range(frames):
        note = (frame // 12000) % len(melody)
        chord = chords[(frame // 180000) % len(chords)]
        frequencies = [melody[note], *chord]
        values = []
        for voice, frequency in enumerate(frequencies):
            phases[voice] = (phases[voice] + frequency * 4294967296 // rate) & 0xffffffff
            values.append(triangle(phases[voice]))
        tick = frame % 12000
        envelope = min(tick, 12000 - tick, 900)  # articulated, click-free notes
        fade = min(frame, frames - 1 - frame, 4800)
        tune = values[0] * envelope // 900
        left = (tune * 4 + values[1] * 2 + values[2] + values[3]) * fade // (16 * 4800)
        right = (tune * 3 + values[1] + values[2] * 2 + values[3] * 2) * fade // (16 * 4800)
        if channels == 1:
            output.append((left + right) // 2)
        else:
            output.extend((left, right))
    if sys.byteorder != 'little':
        output.byteswap()
    pcm = output.tobytes()
    header = (b'RIFF' + struct.pack('<I', 36 + len(pcm)) + b'WAVEfmt ' +
              struct.pack('<IHHIIHH', 16, 1, channels, rate, rate * channels * 2, channels * 2, 16) +
              b'data' + struct.pack('<I', len(pcm)))
    return header + pcm


def generate(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    entries = []
    for name, channels, later in [('courtyard-stereo', 2, False),
                                   ('courtyard-mono', 1, False),
                                   ('courtyard-later', 1, True)]:
        raw = original_wave(30, channels, later)
        manifest, chunks, _ = commitments(raw)
        (directory / (name + '.wav')).write_bytes(raw)
        (directory / (name + '.ltcontent')).write_bytes(manifest)
        entries.append({'item': name, 'edition': 'lossless-stereo' if channels == 2 else 'lossless-mono',
                        'sequence': 2 if later else 1, 'format': 'RIFF/WAVE PCM-s16le-48000',
                        'channels': channels, 'duration_frames': 1440000, 'bytes': len(raw),
                        'chunks': len(chunks), 'content_sha256': sha(raw).hex(),
                        'manifest_sha256': sha(manifest).hex(), 'license': 'CC0-1.0',
                        'provenance': RECIPE.decode(), 'recipe_sha256': sha(RECIPE).hex()})
    (directory / 'original-audio.json').write_text(json.dumps({'schema': 1, 'items': entries}, indent=2) + '\n')
    return entries


def wait_job(client, handle, timeout=120):
    client = api(client)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        fields, _ = client.objects(304, handle)
        if fields[2] == 4:
            return fields
        if fields[2] >= 5:
            raise RuntimeError(f'content job terminal state {fields[2]}, reason {fields[5]}')
    raise TimeoutError('job continues to be queryable; timeout does not roll back its effects')


def reserve(client, raw, operation, provider, federation, durable=False):
    client = api(client)
    if len(provider) != 32 or len(federation) != 32:
        raise ValueError('provider and federation must be explicit 32-byte identities')
    manifest, chunks, proofs = commitments(raw)
    binding = manifest + sha(manifest) + provider + federation
    fields, _ = client.objects(300, a=operation, b=len(raw), c=3, d=int(durable), data=binding)
    return fields[1], manifest, chunks, proofs


def ingest_chunk(client, content, index, raw, proof, timeout=120):
    client = api(client)
    fields, _ = client.objects(301, content, index, data=proof)
    if fields[1] == 0 and fields[2] == 4:
        return
    handle = fields[1]
    for offset in range(0, len(raw), 512):
        client.objects(302, handle, offset, data=raw[offset:offset + 512])
    client.objects(303, handle)
    wait_job(client, handle, timeout)
    client.objects(305, handle, 4)


def import_content(client, raw, operation, provider, federation, progress=None):
    client = api(client)
    content, manifest, chunks, proofs = reserve(client, raw, operation, provider, federation)
    for index, (part, proof) in enumerate(zip(chunks, proofs)):
        ingest_chunk(client, content, index, part, proof)
        if progress:
            progress(min((index + 1) * CHUNK, len(raw)), len(raw))
    fields, _ = client.objects(310, content)
    if fields[1] != content:
        wait_job(client, fields[1])
        client.objects(305, fields[1], 4)
    return content, manifest


def vault_call(client, op, handle=0, a=0, b=0):
    raw = client.request(op, struct.pack('<8Q', op, handle, 3, a, b, 0, 0, 1))
    if len(raw) < 64:
        raise ValueError('short ContentVault response')
    fields = struct.unpack_from('<8Q', raw)
    if fields[0]:
        raise ValueError(f'ContentVault status{fields[0]}')
    return fields, raw[64:]


def wait_vault(client, operation, timeout=3600):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        fields, payload = vault_call(client, 241)
        if fields[1] != operation:
            raise RuntimeError('the selected operation identity changed')
        if fields[2] >= 4:
            if fields[2] != 4:
                raise RuntimeError(f'ContentVault state {fields[2]}, reason {fields[6]}')
            return fields, payload
        time.sleep(.02)
    raise TimeoutError('ContentVault completion remains queryable; no rollback is implied')


def retain(client, selected, operation, timeout=3600, metadata=None):
    client = api(client)
    selected_state = client.objects(306, selected)[0][2]
    processes = client.request(2)
    vault_instance = struct.unpack_from('<Q', processes, 96)[0]
    delegated = client.objects(308, selected, vault_instance)[0][1]
    delegated_metadata = client.objects(6, metadata, vault_instance, 25)[0][1] if metadata else 0
    try:
        vault_call(client, 240, delegated, operation, delegated_metadata)
        fields, _ = wait_vault(client, operation, timeout)
    finally:
        if delegated_metadata:
            client.objects(7, metadata, delegated_metadata)
    return {'operation': fields[1], 'state': fields[2], 'bytes': fields[4], 'verified_bytes': fields[3],
            'generation': fields[5], 'format': 5 if selected_state == 1 else (4 if metadata else 3), 'encrypted': True}


def recover(client, operation, recipient=None, timeout=3600):
    if recipient is None:
        recipient = struct.unpack_from('<Q', client.request(2), 32)[0]
    vault_call(client, 243, a=recipient, b=operation)
    fields, payload = wait_vault(client, operation, timeout)
    handle = struct.unpack_from('<Q', payload)[0]
    metadata_handle = struct.unpack_from('<Q', payload, 8)[0] if len(payload) >= 16 else 0
    return {'operation': fields[1], 'state': fields[2], 'bytes': fields[4],
            'generation': fields[5], 'handle': handle, 'recipient': recipient,
            'metadata_handle': metadata_handle,
            'restored_transport_or_execution_authority': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    recipe = commands.add_parser('generate-original-audio')
    recipe.add_argument('--output', required=True)
    load = commands.add_parser('import')
    load.add_argument('--socket', required=True)
    load.add_argument('--input', required=True)
    load.add_argument('--operation', type=int, required=True)
    load.add_argument('--provider-id', required=True)
    load.add_argument('--federation-id', required=True)
    inspect = commands.add_parser('inspect')
    inspect.add_argument('--socket', required=True)
    inspect.add_argument('handle', type=lambda value: int(value, 0))
    for name in ('vault-retain', 'vault-recover', 'vault-inspect'):
        command = commands.add_parser(name)
        command.add_argument('--socket', required=True)
        command.add_argument('--key', required=True, type=Path)
        if name != 'vault-inspect':
            command.add_argument('--operation', type=int, required=True)
        if name == 'vault-retain':
            command.add_argument('handle', type=lambda value: int(value, 0))
    args = parser.parse_args(argv)
    if args.command == 'generate-original-audio':
        print(json.dumps(generate(args.output), indent=2))
        return
    from live import Client
    client = ContentClient(Client(Path(args.socket)))
    if args.command.startswith('vault-'):
        from project_vault import unlock
        unlock(client, args.key.read_bytes())
        if args.command == 'vault-retain':
            result = retain(client, args.handle, args.operation)
        elif args.command == 'vault-recover':
            result = recover(client, args.operation)
        else:
            fields, manifest = vault_call(client, 246)
            result = {'generation': fields[1], 'bytes': fields[3], 'chunks': fields[5],
                      'manifest_sha256': sha(manifest).hex(), 'format': 3}
        print(json.dumps(result, indent=2))
    elif args.command == 'inspect':
        fields, manifest = client.objects(306, args.handle)
        print(json.dumps({'handle': fields[1], 'state': fields[2], 'verified_bytes': fields[3],
                          'total_bytes': fields[4], 'verified_chunks': fields[5],
                          'total_chunks': fields[6], 'manifest_sha256': sha(manifest).hex()}, indent=2))
    else:
        raw = Path(args.input).read_bytes()
        started = time.monotonic()
        handle, manifest = import_content(client, raw, args.operation,
                                          bytes.fromhex(args.provider_id), bytes.fromhex(args.federation_id))
        print(json.dumps({'handle': handle, 'bytes': len(raw), 'manifest_sha256': sha(manifest).hex(),
                          'elapsed_seconds': time.monotonic() - started,
                          'storage': 'guest-owned volatile RAM; no vault retention'}, indent=2))


if __name__ == '__main__':
    main()
