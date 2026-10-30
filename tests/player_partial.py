"""Focused native partial-content buffering and verified-range resumption.

Uses the existing Player, scoped Content jobs and PCM device. The original
one-second audio only checks the changed partial-reader boundary, not the
substantial retained collection or physical speaker acceptance.
"""
import argparse
import hashlib
import json
import struct
import sys
import time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'tools'), str(ROOT / 'tests')]
import content
from creator_journey import require
from library_journey import appcall, wait
from player_audio import AudioJourney, captured_bytes


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--player', type=Path, required=True)
    p.add_argument('--public', type=Path, required=True)
    p.add_argument('--image', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    a.output = a.output.resolve()
    a.backend = 'qemu'
    a.pcm_play = False
    j = AudioJourney(a)
    try:
        j.boot()
        package, player = j.trust_stage(a.player, 'native-player')
        j.wait_text(16, 60, 'LEMMA PLAYER')
        raw = content.original_wave(1, 2)
        with j.client() as c:
            root, manifest, parts, proofs = content.reserve(c, raw, 61001, b'p' * 32, b'f' * 32)
            grant = content.api(c).objects(308, root, player)[0][1]
            initial = appcall(c, player, 600, grant, 2, 48000)[0]
        require(initial[2] == 4 and initial[1] == grant and initial[6] == 0,
                'missing header discarded the approved partial reader or started audio')
        j.ui.press(57)  # Explicit playback intent while the header is missing.
        with j.client() as c:
            before = appcall(c, player, 601)[0]
            require(before[2] == 4 and before[6] == 0, 'missing header falsely played')
            content.ingest_chunk(c, root, 0, parts[0], proofs[0])

        def state():
            with j.client() as c:
                return appcall(c, player, 601)[0]

        stalled = wait(lambda: s if (s := state())[2] == 4 and s[3] > 0 else None,
                       120, 'play verified first chunk then buffer at missing range')
        prefix = captured_bytes(j.capture, stalled[3] * 4)
        require(prefix == raw[44:44 + len(prefix)], 'unverified or incorrect partial PCM escaped')
        with j.client() as c:
            obj = c.import_object(b'foreground object remains usable during partial buffering')
            require(c.objects(4, obj, 0, 57)[1] == b'foreground object remains usable during partial buffering',
                    'unrelated Objects work failed during buffering')
            still = appcall(c, player, 601)[0]
            require(still[2] == 4 and still[3] == stalled[3], 'missing range fabricated playback progress')
            for index in range(1, len(parts)):
                content.ingest_chunk(c, root, index, parts[index], proofs[index])
            fields, _ = content.api(c).objects(310, root)
            if fields[1] != root:
                content.wait_job(c, fields[1])
                content.api(c).objects(305, fields[1], 4)
        wait(lambda: state()[2] == 5, 180, 'verified range publication resumes to exact end')
        pcm = captured_bytes(j.capture, len(raw) - 44)
        require(pcm == raw[44:], 'partial resumption duplicated, omitted or changed samples')
        j.passed('missing header keeps scoped reader; verified partial playback buffers and resumes',
                 player_release=package['release_id'], manifest_sha256=hashlib.sha256(manifest).hexdigest(),
                 payload_sha256=hashlib.sha256(raw).hexdigest(), payload_bytes=len(raw),
                 played_before_next_chunk_frames=stalled[3], pcm_bytes=len(pcm),
                 pcm_sha256=hashlib.sha256(pcm).hexdigest(), unrelated_objects=True,
                 complete_before_play=False, host_payload_decoder=False,
                 speaker_output=False, durable_collection=False)
        # An unsupported actual header is not mistaken for temporary absence.
        bad = bytearray(raw)
        struct.pack_into('<I', bad, 24, 44100)
        with j.client() as c:
            root2, _, chunks2, paths2 = content.reserve(c, bytes(bad), 61002, b'p' * 32, b'f' * 32)
            content.ingest_chunk(c, root2, 0, chunks2[0], paths2[0])
            bad_grant = content.api(c).objects(308, root2, player)[0][1]
            rejected = appcall(c, player, 600, bad_grant, 2, 48000)[0]
        require(rejected[2] == 6 and rejected[1] == 0 and rejected[6] == 0,
                'unsupported actual header retained a playing/buffering scope')
        j.passed('unsupported partial header fails closed and releases only that reader',
                 sample_rate=44100, state=rejected[2], output_epoch=rejected[6])
        print(json.dumps(dict(image=j.image, checks=j.report), indent=2))
    finally:
        j.stop()


if __name__ == '__main__':
    main()
