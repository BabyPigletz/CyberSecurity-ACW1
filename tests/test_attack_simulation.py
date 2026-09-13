import random
import wave
from pathlib import Path

from PIL import Image

from core import attack_simulation, audio_stego, crypto, image_stego
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
