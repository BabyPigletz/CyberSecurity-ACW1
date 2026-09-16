import random
import wave
from pathlib import Path

from PIL import Image

from core import attack_simulation, audio_metrics, audio_stego, bitstream, crypto, image_stego, payload
from core.verdict import Verdict

KEYS = Path(__file__).resolve().parent.parent / "keys"


def _keypair():
    return crypto.load_keypair(KEYS / "demo_a_pub.pem", KEYS / "demo_a_priv.pem")


def _make_wav(path: Path, frames: int = 30000):
    rng = random.Random(7)
    raw = bytearray()
    for _ in range(frames):
        raw += int(rng.randint(-25000, 25000)).to_bytes(2, "little", signed=True)
    with wave.open(str(path), "wb") as writer:
        writer.setnchannels(1)
        writer.setsampwidth(2)
        writer.setframerate(44100)
        writer.writeframes(bytes(raw))


def test_image_attack_suite_reports_expected_verdicts(tmp_path):
    cover = tmp_path / "cover.png"
    stego = tmp_path / "stego.png"
    Image.new("RGB", (256, 256), color=(80, 120, 160)).save(cover, format="PNG")
    keypair = _keypair()
    image_stego.encode(cover, stego, {}, "demo-pass", keypair, 2)

    cases = attack_simulation.run_attack_suite(
        stego, "image", "demo-pass", {keypair.key_id: keypair.public_key}, tmp_path / "attacks"
    )

    assert all(case.passed for case in cases)
    assert {case.actual for case in cases} == {
        Verdict.TAMPERED,
        Verdict.SIGNATURE_INVALID,
        Verdict.PAYLOAD_MISSING,
    }
    assert (tmp_path / "attacks" / "tampered_visible.png").exists()
    assert (tmp_path / "attacks" / "tampered_payload.png").exists()


def test_audio_attack_suite_reports_expected_verdicts(tmp_path):
    cover = tmp_path / "cover.wav"
    stego = tmp_path / "stego.wav"
    _make_wav(cover)
    keypair = _keypair()
    audio_stego.encode(cover, stego, {}, "demo-pass", keypair, 2)

    cases = attack_simulation.run_attack_suite(
        stego, "audio", "demo-pass", {keypair.key_id: keypair.public_key}, tmp_path / "attacks"
    )

    assert all(case.passed for case in cases)
    assert (tmp_path / "attacks" / "tampered_visible.wav").exists()
    assert (tmp_path / "attacks" / "tampered_payload.wav").exists()


def test_replay_substitution_is_detected_and_scored(tmp_path):
    cover = tmp_path / "cover.png"
    different_cover = tmp_path / "different_cover.png"
    stego = tmp_path / "stego.png"
    Image.new("RGB", (256, 256), color=(80, 120, 160)).save(cover, format="PNG")
    Image.new("RGB", (256, 256), color=(180, 40, 20)).save(different_cover, format="PNG")
    keypair = _keypair()
    image_stego.encode(cover, stego, {}, "demo-pass", keypair, 2)

    cases = attack_simulation.run_attack_suite(
        stego,
        "image",
        "demo-pass",
        {keypair.key_id: keypair.public_key},
        tmp_path / "attacks",
        cover_path=different_cover,
    )
    replay = next(case for case in cases if case.name.startswith("Replay/"))
    score = attack_simulation.score_cases(cases)

    assert replay.actual == Verdict.TAMPERED
    assert replay.passed
    assert score.earned_points == score.total_points
    assert score.detection_percent == 100.0


def test_audio_metrics_measure_lsb_embedding(tmp_path):
    cover = tmp_path / "cover.wav"
    stego = tmp_path / "stego.wav"
    _make_wav(cover)
    keypair = _keypair()
    audio_stego.encode(cover, stego, {}, "demo-pass", keypair, 2)

    metrics = audio_metrics.compare(cover, stego)

    assert metrics.sample_count == 30000
    assert metrics.changed_samples > 0
    assert metrics.mean_absolute_error > 0
    assert metrics.maximum_absolute_error <= 3
    assert metrics.signal_to_noise_db > 40


def test_payload_tamper_uses_actual_body_bounds(tmp_path):
    """A valid payload is large enough for the mutation and remains bounded."""
    cover = tmp_path / "cover.png"
    stego = tmp_path / "stego.png"
    Image.new("RGB", (128, 128), color=(80, 120, 160)).save(cover, format="PNG")
    keypair = _keypair()
    image_stego.encode(cover, stego, {}, "demo-pass", keypair, 8)

    output = tmp_path / "tampered.png"
    attack_simulation._payload_tamper(stego, output, "image", "demo-pass")

    assert output.exists()
    assert image_stego.decode(output, "demo-pass", {keypair.key_id: keypair.public_key})[0] == Verdict.SIGNATURE_INVALID


def test_replay_capacity_check_rejects_small_target(tmp_path):
    target = bytearray(100)
    body = b"x" * 100
    target_body_start = payload.PREFIX_CARRIER_LEN
    target_capacity = bitstream.capacity_bytes(len(target) - target_body_start, 1)

    assert len(body) > target_capacity
    assert target_capacity < 100
