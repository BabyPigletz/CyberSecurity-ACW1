"""LSB Replacement Steganography for audio cover objects (uncompressed PCM WAV).

Knows WAV/`wave` I/O and docs/format.md §2's carrier-selection rule only -
all crypto, framing, and verdict logic live in core/payload.py and are
called here as black boxes. Mirrors core/image_stego.py's structure so both
codecs can be read/graded independently.
"""

import wave
from pathlib import Path

from core import bitstream, location
from core import payload as payload_mod
from core.crypto import KeyPair
from core.errors import UnsupportedFormatError
from core.verdict import Verdict


def _carrier_len(raw_len: int, sampwidth: int) -> int:
    # 16-bit: only the low byte of each little-endian sample is a carrier byte
    # (§2) - writing the high byte shifts a sample by up to 256x. 8-bit: every
    # byte is a carrier.
    return raw_len // 2 if sampwidth == 2 else raw_len


def capacity_bytes(path: Path, num_lsb: int = 1) -> int:
    with wave.open(str(path), "rb") as wf:
        sampwidth = wf.getsampwidth()
        raw_len = wf.getnframes() * wf.getnchannels() * sampwidth
    return bitstream.capacity_bytes(_carrier_len(raw_len, sampwidth), num_lsb)


def _load_carrier(path: Path):
    with wave.open(str(path), "rb") as wf:
        n_channels = wf.getnchannels()
        sampwidth = wf.getsampwidth()
        framerate = wf.getframerate()
        n_frames = wf.getnframes()
        comptype = wf.getcomptype()
        raw = wf.readframes(n_frames)

    if comptype != "NONE":
        raise UnsupportedFormatError(f"compressed WAV ({comptype}) is not supported")
    if sampwidth not in (1, 2):
        raise UnsupportedFormatError(f"unsupported sample width: {sampwidth * 8}-bit")

    if sampwidth == 2:
        carrier = bytearray(raw[0::2])
    else:
        carrier = bytearray(raw)

    meta = {
        "n_channels": n_channels,
        "sampwidth": sampwidth,
        "framerate": framerate,
        "n_frames": n_frames,
        "raw": raw,
    }
    return carrier, meta


def _save_carrier(path: Path, carrier: bytearray, meta: dict) -> None:
    raw = bytearray(meta["raw"])
    if meta["sampwidth"] == 2:
        raw[0::2] = carrier
    else:
        raw[:] = carrier

    with wave.open(str(path), "wb") as wf:
        wf.setnchannels(meta["n_channels"])
        wf.setsampwidth(meta["sampwidth"])
        wf.setframerate(meta["framerate"])
        wf.writeframes(bytes(raw))


def encode(in_path: Path, out_path: Path, payload_fields: dict, passphrase: str, keypair: KeyPair, num_lsb: int) -> int:
    """Embed a signed, encrypted payload into in_path, writing the result to
    out_path. Returns the derived start offset (informational display only).
    """
    carrier, meta = _load_carrier(in_path)
    cover_id = location.cover_id_for_audio(meta["sampwidth"], meta["n_channels"], meta["n_frames"])
    start = payload_mod.embed(carrier, cover_id, payload_fields, passphrase, keypair, num_lsb)
    _save_carrier(out_path, carrier, meta)
    return start


def decode(path: Path, passphrase: str, trusted_keys: dict):
    """Extract and verify. Never raises for expected failure modes - always
    returns (Verdict, payload_dict_or_None).
    """
    try:
        carrier, meta = _load_carrier(path)
    except (UnsupportedFormatError, wave.Error, OSError):
        return Verdict.CANNOT_VERIFY, None

    cover_id = location.cover_id_for_audio(meta["sampwidth"], meta["n_channels"], meta["n_frames"])
    return payload_mod.verify(carrier, cover_id, passphrase, trusted_keys)
