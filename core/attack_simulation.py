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

from PIL import Image

from core import audio_stego, image_stego, location, payload
from core.verdict import Verdict


@dataclass(frozen=True)
class AttackCase:
    name: str
    expected: Verdict
    actual: Verdict
    output_path: Optional[Path]

    @property
    def passed(self) -> bool:
        return self.expected == self.actual


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
    if not frames:
        raise ValueError("audio file has no samples")
    frames[0] ^= 0x80
    with wave.open(str(target), "wb") as writer:
        writer.setparams(params)
        writer.writeframes(bytes(frames))


def _payload_tamper(source: Path, target: Path, kind: str, passphrase: str) -> None:
    """Flip a byte in the signed body, producing a signature failure."""
    if kind == "image":
        carrier, meta = image_stego._load_carrier(source)
        cover_id = location.cover_id_for_image(meta["width"], meta["height"])
        save = image_stego._save_carrier
    else:
        carrier, meta = audio_stego._load_carrier(source)
        cover_id = location.cover_id_for_audio(meta["sampwidth"], meta["n_channels"], meta["n_frames"])
        save = audio_stego._save_carrier

    start = location.derive_start(cover_id, passphrase, len(carrier))
    mutation_index = start + payload.PREFIX_CARRIER_LEN + 40
    if mutation_index >= len(carrier):
        raise ValueError("stego object is too small for payload corruption simulation")
    carrier[mutation_index] ^= 0x01
    save(target, carrier, meta)


def run_attack_suite(
    stego_path: Path,
    kind: str,
    passphrase: str,
    trusted_keys: dict,
    output_dir: Path,
) -> list[AttackCase]:
    """Run repeatable attacks and return expected-versus-actual verdicts.

    The output directory receives only generated attack copies. The original
    stego object is never modified.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    suffix = ".png" if kind == "image" else ".wav"
    visible_path = output_dir / f"tampered_visible{suffix}"
    payload_path = output_dir / f"tampered_payload{suffix}"

    _visible_tamper(stego_path, visible_path, kind)
    _payload_tamper(stego_path, payload_path, kind, passphrase)

    cases = [
        AttackCase(
            "Visible carrier modification",
            Verdict.TAMPERED,
            _verify(visible_path, kind, passphrase, trusted_keys),
            visible_path,
        ),
        AttackCase(
            "Hidden payload corruption",
            Verdict.SIGNATURE_INVALID,
            _verify(payload_path, kind, passphrase, trusted_keys),
            payload_path,
        ),
        AttackCase(
            "Wrong passphrase",
            Verdict.PAYLOAD_MISSING,
            _verify(stego_path, kind, "incorrect-passphrase", trusted_keys),
            None,
        ),
        AttackCase(
            "Untrusted signing key",
            Verdict.SIGNATURE_INVALID,
            _verify(stego_path, kind, passphrase, {}),
            None,
        ),
    ]
    return cases
