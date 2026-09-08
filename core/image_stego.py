"""LSB Replacement Steganography for image cover objects (PNG, RGB, alpha excluded).

Knows PNG/PIL I/O and docs/format.md §2's carrier-selection rule only - all
crypto, framing, and verdict logic live in core/payload.py and are called
here as black boxes.
"""

from pathlib import Path

from PIL import Image

from core import bitstream, location
from core import payload as payload_mod
from core.crypto import KeyPair
from core.verdict import Verdict

CHANNELS = 3  # RGB; alpha excluded (§2) - visible transparency edits are conspicuous


def capacity_bytes(image: Image.Image, num_lsb: int = 1) -> int:
    """Rough max payload size (bytes) this image can hold at num_lsb bits/channel.

    Matches docs/format.md §3's capacity_bytes(C, num_lsb) formula, where
    C = width * height * 3 (RGB carrier, alpha excluded per §2). Actual
    usable capacity is roughly half of this once the derived start location
    (§7) is accounted for.
    """
    width, height = image.size
    return bitstream.capacity_bytes(width * height * CHANNELS, num_lsb)


def _load_carrier(path: Path):
    # §2 permits loading a JPEG *cover* (it's decoded to raw RGB in memory and
    # always re-saved as PNG below) - it only forbids saving the *stego output*
    # as JPEG, which would recompress and destroy the just-written LSB data.
    # _save_carrier always writes PNG regardless of out_path's extension, so
    # that constraint is enforced structurally rather than by rejecting inputs.
    img = Image.open(path)
    img = img.convert("RGB")
    width, height = img.size
    carrier = bytearray(img.tobytes())  # row-major R,G,B,R,G,B,...
    return carrier, {"width": width, "height": height}


def _save_carrier(path: Path, carrier: bytearray, meta: dict) -> None:
    img = Image.frombytes("RGB", (meta["width"], meta["height"]), bytes(carrier))
    img.save(path, format="PNG")


def encode(in_path: Path, out_path: Path, payload_fields: dict, passphrase: str, keypair: KeyPair, num_lsb: int) -> int:
    """Embed a signed, encrypted payload into in_path, writing the result to
    out_path. Returns the derived start offset (informational display only -
    never fed back in as a parameter; see docs/format.md §7).
    """
    carrier, meta = _load_carrier(in_path)
    cover_id = location.cover_id_for_image(meta["width"], meta["height"])
    start = payload_mod.embed(carrier, cover_id, payload_fields, passphrase, keypair, num_lsb)
    _save_carrier(out_path, carrier, meta)
    return start


def decode(path: Path, passphrase: str, trusted_keys: dict):
    """Extract and verify. Never raises for expected failure modes - always
    returns (Verdict, payload_dict_or_None).
    """
    try:
        carrier, meta = _load_carrier(path)
    except OSError:
        return Verdict.CANNOT_VERIFY, None

    cover_id = location.cover_id_for_image(meta["width"], meta["height"])
    return payload_mod.verify(carrier, cover_id, passphrase, trusted_keys)
