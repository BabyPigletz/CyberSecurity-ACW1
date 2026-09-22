import wave
from pathlib import Path

import pytest

from core import crypto
from core.errors import CapacityError
from media import audio_stego
from core.verdict import Verdict

KEYS = Path(__file__).resolve().parent.parent / "keys"


def _keys():
    demo_a = crypto.load_keypair(KEYS / "demo_a_pub.pem", KEYS / "demo_a_priv.pem")
    return demo_a


def _make_wav(path: Path, n_frames=20000, n_channels=1, sampwidth=2, framerate=44100, seed=1):
    import random

    rng = random.Random(seed)
    frames = bytearray()
    for _ in range(n_frames * n_channels):
        sample = rng.randint(-30000, 30000)
        frames += int(sample).to_bytes(2, "little", signed=True)
    with wave.open(str(path), "wb") as wf:
        wf.setnchannels(n_channels)
        wf.setsampwidth(sampwidth)
        wf.setframerate(framerate)
        wf.writeframes(bytes(frames))


@pytest.fixture
def cover_wav(tmp_path):
    path = tmp_path / "cover.wav"
    _make_wav(path)
    return path


def test_capacity_bytes_only_counts_low_bytes_at_16bit(cover_wav):
    with wave.open(str(cover_wav), "rb") as wf:
        n_frames = wf.getnframes()
    # 16-bit mono: carrier_len = n_frames (one low byte per sample)
    assert audio_stego.capacity_bytes(cover_wav, num_lsb=1) == (n_frames * 1) // 8


def test_encode_decode_round_trip_authentic(cover_wav, tmp_path):
    demo_a = _keys()
    trusted = {demo_a.key_id: demo_a.public_key}
    stego_path = tmp_path / "stego.wav"

    start = audio_stego.encode(cover_wav, stego_path, {"meta": {"team": "P1-6"}}, "hunter2", demo_a, num_lsb=2)
    assert start > 0

    verdict, extracted = audio_stego.decode(stego_path, "hunter2", trusted)
    assert verdict == Verdict.AUTHENTIC
    assert extracted.cover_hash_matches
    assert extracted.payload["meta"]["team"] == "P1-6"


def test_wrong_passphrase_does_not_verify(cover_wav, tmp_path):
    demo_a = _keys()
    trusted = {demo_a.key_id: demo_a.public_key}
    stego_path = tmp_path / "stego.wav"
    audio_stego.encode(cover_wav, stego_path, {}, "correct-pass", demo_a, num_lsb=2)

    verdict, extracted = audio_stego.decode(stego_path, "wrong-pass", trusted)
    assert verdict in (Verdict.PAYLOAD_MISSING, Verdict.WRONG_START_LOCATION)
    assert extracted is None


def test_high_byte_of_16bit_sample_never_touched(cover_wav, tmp_path):
    """§2's most common failure mode: writing to the high byte of a 16-bit
    sample shifts it audibly. Confirm every odd-indexed frame byte (the high
    byte, little-endian) is bit-for-bit identical before and after embedding
    at every LSB depth.
    """
    demo_a = _keys()
    with open(cover_wav, "rb") as f:
        before = f.read()
    with wave.open(str(cover_wav), "rb") as wf:
        before_frames = wf.readframes(wf.getnframes())

    for num_lsb in (1, 4, 8):
        stego_path = tmp_path / f"stego_{num_lsb}.wav"
        audio_stego.encode(cover_wav, stego_path, {}, "hunter2", demo_a, num_lsb=num_lsb)
        with wave.open(str(stego_path), "rb") as wf:
            after_frames = wf.readframes(wf.getnframes())
        assert before_frames[1::2] == after_frames[1::2], f"high bytes changed at num_lsb={num_lsb}"


def test_oversized_payload_rejected_before_writing(tmp_path):
    demo_a = _keys()
    tiny_path = tmp_path / "tiny.wav"
    _make_wav(tiny_path, n_frames=10)  # far too small for prefix+body
    with pytest.raises(CapacityError):
        audio_stego.encode(tiny_path, tmp_path / "out.wav", {}, "hunter2", demo_a, num_lsb=1)
    assert not (tmp_path / "out.wav").exists()


def test_tampered_carrier_byte_after_embed_is_tampered(cover_wav, tmp_path):
    demo_a = _keys()
    trusted = {demo_a.key_id: demo_a.public_key}
    stego_path = tmp_path / "stego.wav"
    audio_stego.encode(cover_wav, stego_path, {}, "hunter2", demo_a, num_lsb=2)

    with wave.open(str(stego_path), "rb") as wf:
        params = wf.getparams()
        frames = bytearray(wf.readframes(wf.getnframes()))
    # Flip a bit above num_lsb=2 on the LOW byte of a 16-bit sample (index 0,
    # 2, 4, ... - the carrier per §2). This is within canonical_hash's scope
    # and must be caught.
    frames[0] ^= 0b10000000
    with wave.open(str(stego_path), "wb") as wf:
        wf.setparams(params)
        wf.writeframes(bytes(frames))

    verdict, extracted = audio_stego.decode(stego_path, "hunter2", trusted)
    assert verdict == Verdict.TAMPERED
    assert extracted is not None and not extracted.cover_hash_matches


def test_KNOWN_GAP_high_byte_tamper_is_invisible_to_cover_hash(cover_wav, tmp_path):
    """Documents a real, significant limitation found during implementation
    (see the final report): canonical_hash(carrier, num_lsb) only ever sees
    `carrier`, and for 16-bit PCM §2 defines carrier as the LOW byte of each
    sample only. The HIGH byte - the dominant, audible half of every sample -
    is therefore completely outside the cover-hash's coverage, not just its
    low num_lsb bits. This test asserts the *current, spec-literal* behaviour
    (AUTHENTIC despite an audible-magnitude edit) so this gap is visible and
    intentional in the suite rather than silently regressed past later. This
    is NOT the same as - and considerably worse than - §8's documented "low
    num_lsb bits are unprotected" limitation.
    """
    demo_a = _keys()
    trusted = {demo_a.key_id: demo_a.public_key}
    stego_path = tmp_path / "stego.wav"
    audio_stego.encode(cover_wav, stego_path, {}, "hunter2", demo_a, num_lsb=2)

    with wave.open(str(stego_path), "rb") as wf:
        params = wf.getparams()
        frames = bytearray(wf.readframes(wf.getnframes()))
    frames[1] ^= 0b10000000  # high byte of the first 16-bit sample - not a carrier byte at all
    with wave.open(str(stego_path), "wb") as wf:
        wf.setparams(params)
        wf.writeframes(bytes(frames))

    verdict, _ = audio_stego.decode(stego_path, "hunter2", trusted)
    assert verdict == Verdict.AUTHENTIC, (
        "if this now fails, canonical_hash's scope has been widened to cover "
        "high bytes too - update this test and the limitation note in README.md"
    )

def test_dsss_audio_encode_decode_round_trip(tmp_path):
    """Tests DSSS spread spectrum embedding and extraction on audio."""
    demo_a = _keys()
    trusted = {demo_a.key_id: demo_a.public_key}
    
    # Generate WAV with 300,000 frames to accommodate 279,040 DSSS samples
    cover_wav = tmp_path / "large_cover.wav"
    _make_wav(cover_wav, n_frames=300000)
    
    stego_path = tmp_path / "stego_dsss.wav"

    # 1. Encode via DSSS
    status = audio_stego.encode_dsss(
        cover_wav, 
        stego_path, 
        {"message": "DSSS resilient payload"}, 
        "hunter2", 
        demo_a, 
        chip_length=64  # Smaller chip length for faster unit test execution
    )
    assert stego_path.exists()

    # 2. Decode via DSSS
    verdict, extracted = audio_stego.decode_dsss(
        stego_path, 
        "hunter2", 
        trusted, 
        chip_length=64
    )

    # 3. Assertions
    assert verdict == Verdict.AUTHENTIC
    assert extracted.payload["message"] == "DSSS resilient payload"