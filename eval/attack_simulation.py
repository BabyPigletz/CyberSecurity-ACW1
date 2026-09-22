"""Reproducible attack simulations for the ACW1 security demonstration.

The simulator creates controlled copies of an existing stego object and runs
those copies through the real image/audio verification APIs. It is deliberately
an evaluation layer: it does not change the embedding format or weaken the
normal verification path.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import wave
import numpy as np

from PIL import Image

from core import bitstream, location, payload
from eval import audio_metrics
from media import audio_stego, image_stego
from core.verdict import Verdict


@dataclass(frozen=True)
class AttackCase:
    name: str
    expected: Verdict | tuple[Verdict, ...]
    actual: Verdict
    output_path: Optional[Path]
    category: str = "integrity"
    weight: int = 1
    audio_quality: Optional[audio_metrics.AudioQualityMetrics] = None

    @property
    def passed(self) -> bool:
        allowed = self.expected if isinstance(self.expected, tuple) else (self.expected,)
        return self.actual in allowed


@dataclass(frozen=True)
class AttackScore:
    cases: tuple[AttackCase, ...]
    earned_points: int
    total_points: int

    @property
    def detection_percent(self) -> float:
        return (self.earned_points / self.total_points * 100.0) if self.total_points else 0.0


def score_cases(cases: list[AttackCase]) -> AttackScore:
    """Calculate a weighted detection score for the attack matrix."""
    total = sum(case.weight for case in cases)
    earned = sum(case.weight for case in cases if case.passed)
    return AttackScore(tuple(cases), earned, total)


def _verify(path: Path, kind: str, passphrase: str, trusted_keys: dict) -> Verdict:
    if kind == "image":
        verdict, _ = image_stego.decode(path, passphrase, trusted_keys)
    else:
        verdict, _ = audio_stego.decode(path, passphrase, trusted_keys)
    return verdict


def _visible_tamper(source: Path, target: Path, kind: str) -> None:
    """Change a high-order carrier bit without intentionally corrupting payload bits."""
    if kind == "image":
        image = Image.open(source).convert("RGB")
        red, green, blue = image.getpixel((0, 0))
        image.putpixel((0, 0), (red ^ 0x80, green, blue))
        image.save(target, format="PNG")
        return

    with wave.open(str(source), "rb") as reader:
        params = reader.getparams()
        frames = bytearray(reader.readframes(reader.getnframes()))
    if len(frames) < 2:
        raise ValueError("audio file must contain at least two raw sample bytes")

    frames[0] ^= 0x80
    with wave.open(str(target), "wb") as writer:
        writer.setparams(params)
        writer.writeframes(bytes(frames))


def _payload_tamper(source: Path, target: Path, kind: str, passphrase: str) -> None:
    """Corrupt payload beyond ECC recovery capacity to trigger signature or decoding failure."""
    if kind == "image":
        carrier, meta = image_stego._load_carrier(source)
        cover_id = location.cover_id_for_image(meta["width"], meta["height"])
        save = image_stego._save_carrier
    else:
        carrier, meta = audio_stego._load_carrier(source)
        cover_id = location.cover_id_for_audio(meta["sampwidth"], meta["n_channels"], meta["n_frames"])
        save = audio_stego._save_carrier

    start = location.derive_start(cover_id, passphrase, len(carrier))
    prefix_raw = bitstream.read_bits(carrier, start, payload.PREFIX_LEN, num_lsb=1)
    prefix_info = payload.parse_prefix_bytes(prefix_raw)
    if not prefix_info.magic_ok or not 1 <= prefix_info.num_lsb <= 8:
        raise ValueError("stego object has no valid payload prefix")

    body_start = start + payload.PREFIX_CARRIER_LEN
    body_carrier_needed = -(-(prefix_info.body_len * 8) // prefix_info.num_lsb)
    if body_carrier_needed < 16 or body_start + body_carrier_needed > len(carrier):
        raise ValueError("stego object is too small for payload corruption simulation")

    # Corrupt 18 consecutive carrier bytes to ensure ECC limits (>8 corruptible bytes) are overwhelmed
    corruption_len = min(18, body_carrier_needed)
    for i in range(corruption_len):
        carrier[body_start + i] ^= 0xFF

    save(target, carrier, meta)


def _substitute_payload(source: Path, target_cover: Path, target: Path, kind: str, passphrase: str) -> None:
    """Place a valid payload from one object into a different cover object."""
    if kind == "image":
        source_carrier, source_meta = image_stego._load_carrier(source)
        target_carrier, target_meta = image_stego._load_carrier(target_cover)
        source_id = location.cover_id_for_image(source_meta["width"], source_meta["height"])
        target_id = location.cover_id_for_image(target_meta["width"], target_meta["height"])
        save = image_stego._save_carrier
    else:
        source_carrier, source_meta = audio_stego._load_carrier(source)
        target_carrier, target_meta = audio_stego._load_carrier(target_cover)
        source_id = location.cover_id_for_audio(
            source_meta["sampwidth"], source_meta["n_channels"], source_meta["n_frames"]
        )
        target_id = location.cover_id_for_audio(
            target_meta["sampwidth"], target_meta["n_channels"], target_meta["n_frames"]
        )
        save = audio_stego._save_carrier

    source_start = location.derive_start(source_id, passphrase, len(source_carrier))
    prefix = bitstream.read_bits(source_carrier, source_start, payload.PREFIX_LEN, num_lsb=1)
    prefix_info = payload.parse_prefix_bytes(prefix)
    body_start = source_start + payload.PREFIX_CARRIER_LEN
    body = bitstream.read_bits(source_carrier, body_start, prefix_info.body_len, prefix_info.num_lsb)

    if not 1 <= prefix_info.num_lsb <= 8:
        raise ValueError("source payload contains an invalid LSB count")

    target_start = location.derive_start(target_id, passphrase, len(target_carrier))
    body_carrier_needed = -(-(len(body) * 8) // prefix_info.num_lsb)
    target_body_start = target_start + payload.PREFIX_CARRIER_LEN
    target_capacity = (
        bitstream.capacity_bytes(len(target_carrier) - target_body_start, prefix_info.num_lsb)
        if target_body_start <= len(target_carrier)
        else 0
    )
    if len(body) > target_capacity or target_body_start + body_carrier_needed > len(target_carrier):
        raise ValueError("target cover is too small for the substituted payload")

    bitstream.write_bits(target_carrier, target_start, prefix, num_lsb=1)
    bitstream.write_bits(
        target_carrier,
        target_body_start,
        body,
        num_lsb=prefix_info.num_lsb,
    )
    save(target, target_carrier, target_meta)


def run_attack_suite(
    stego_path: Path,
    kind: str,
    passphrase: str,
    trusted_keys: dict,
    output_dir: Path,
    cover_path: Optional[Path] = None,
) -> list[AttackCase]:
    """Run repeatable attacks and return expected-versus-actual verdicts."""
    output_dir.mkdir(parents=True, exist_ok=True)
    suffix = ".png" if kind == "image" else ".wav"
    visible_path = output_dir / f"tampered_visible{suffix}"
    payload_path = output_dir / f"tampered_payload{suffix}"

    _visible_tamper(stego_path, visible_path, kind)

    cases = []
    try:
        _payload_tamper(stego_path, payload_path, kind, passphrase)
    except ValueError:
        cases.append(
            AttackCase(
                "Hidden payload corruption",
                Verdict.SIGNATURE_INVALID,
                Verdict.CANNOT_VERIFY,
                None,
                "payload integrity",
                2,
            )
        )

    audio_quality = None
    if kind == "audio" and cover_path is not None:
        audio_quality = audio_metrics.compare(cover_path, stego_path)

    cases.extend([
        AttackCase(
            "Visible carrier modification",
            Verdict.TAMPERED,
            _verify(visible_path, kind, passphrase, trusted_keys),
            visible_path,
            "carrier integrity",
            2,
            audio_quality,
        ),
        *([] if any(case.name == "Hidden payload corruption" for case in cases) else [
            AttackCase(
                "Hidden payload corruption",
                (Verdict.SIGNATURE_INVALID, Verdict.CANNOT_VERIFY),
                _verify(payload_path, kind, passphrase, trusted_keys),
                payload_path,
                "payload integrity",
                2,
            )
        ]),
        AttackCase(
            "Wrong passphrase",
            (Verdict.PAYLOAD_MISSING, Verdict.WRONG_START_LOCATION),
            _verify(stego_path, kind, "incorrect-passphrase", trusted_keys),
            None,
            "keyed location",
            1,
        ),
        AttackCase(
            "Untrusted signing key",
            Verdict.SIGNATURE_INVALID,
            _verify(stego_path, kind, passphrase, {}),
            None,
            "authentication",
            2,
        ),
    ])
    if cover_path is not None:
        replay_cover_path = output_dir / f"replay_target_cover{suffix}"
        _visible_tamper(cover_path, replay_cover_path, kind)
        replay_path = output_dir / f"replay_substitution{suffix}"
        try:
            _substitute_payload(stego_path, replay_cover_path, replay_path, kind, passphrase)
            cases.append(
                AttackCase(
                    "Replay/substitution into another cover",
                    Verdict.TAMPERED,
                    _verify(replay_path, kind, passphrase, trusted_keys),
                    replay_path,
                    "replay resistance",
                    3,
                )
            )
        except ValueError:
            cases.append(
                AttackCase(
                    "Replay/substitution into another cover",
                    Verdict.TAMPERED,
                    Verdict.CANNOT_VERIFY,
                    None,
                    "replay resistance",
                    3,
                )
            )
    return cases


def attack_gaussian_noise(source: Path, target: Path, std_dev: float = 25.0) -> None:
    """Adds white noise to WAV audio to simulate analog channel interference."""
    with wave.open(str(source), "rb") as reader:
        params = reader.getparams()
        frames = np.frombuffer(reader.readframes(reader.getnframes()), dtype=np.int16)

    noise = np.random.normal(0, std_dev, frames.shape)
    corrupted = np.clip(frames + noise, -32768, 32767).astype(np.int16)

    with wave.open(str(target), "wb") as writer:
        writer.setparams(params)
        writer.writeframes(corrupted.tobytes())