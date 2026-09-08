"""Start-location derivation (docs/format.md §7).

Derived, never stored. Knows nothing about bitstream framing, image/audio
file I/O, or crypto internals beyond calling crypto.derive_offset_key.
"""

import hashlib
import hmac

from core import crypto
from core.errors import CapacityError


def derive_start(cover_id: str, passphrase: str, carrier_len: int) -> int:
    """HMAC-SHA256(derive_offset_key(passphrase), cover_id) mod (carrier_len // 2).

    Raises CapacityError if carrier_len < 2 (mod-by-zero guard - not explicit
    in the original §7 formula, added defensively: a carrier this small can
    never hold even the 80-carrier-byte prefix, so failing fast here rather
    than with a raw ZeroDivisionError is only a usability improvement, not a
    behaviour change for any realistic cover).
    """
    if carrier_len < 2:
        raise CapacityError(f"carrier too small ({carrier_len} bytes) to derive a start location")

    hmac_key = crypto.derive_offset_key(passphrase)
    digest = hmac.new(hmac_key, cover_id.encode("utf-8"), hashlib.sha256).digest()
    return int.from_bytes(digest, "big") % (carrier_len // 2)


def cover_id_for_image(width: int, height: int) -> str:
    return f"png:{width}x{height}x3"


def cover_id_for_audio(sample_width: int, num_channels: int, num_frames: int) -> str:
    return f"wav:{sample_width}:{num_channels}:{num_frames}"
