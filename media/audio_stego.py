"""LSB Replacement & DSSS Steganography for audio cover objects (uncompressed PCM WAV).

Knows WAV/`wave` I/O and carrier-selection rules - all crypto, framing,
and verdict logic live in core/payload.py and are called here as black boxes.
"""

import hashlib
import wave
import numpy as np
from pathlib import Path

from core import bitstream, location
from core import payload as payload_mod
from core.crypto import KeyPair, canonical_hash
from core.errors import CapacityError, UnsupportedFormatError
from core.verdict import Verdict


def _carrier_len(raw_len: int, sampwidth: int) -> int:
    return raw_len // 2 if sampwidth == 2 else raw_len


def capacity_bytes(path: Path, num_lsb: int = 1) -> int:
    with wave.open(str(path), "rb") as wf:
        sampwidth = wf.getsampwidth()
        raw_len = wf.getnframes() * wf.getnchannels() * sampwidth
    return bitstream.capacity_bytes(_carrier_len(raw_len, sampwidth), num_lsb)


def carrier_len(path: Path) -> int:
    with wave.open(str(path), "rb") as wf:
        sampwidth = wf.getsampwidth()
        return _carrier_len(wf.getnframes() * wf.getnchannels() * sampwidth, sampwidth)


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


def _save_carrier(path: Path, carrier: bytearray, meta: dict, is_dsss: bool = False) -> None:
    raw = bytearray(meta["raw"])
    if not is_dsss:
        if meta["sampwidth"] == 2:
            raw[0::2] = carrier
        else:
            raw[:] = carrier

    with wave.open(str(path), "wb") as wf:
        wf.setnchannels(meta["n_channels"])
        wf.setsampwidth(meta["sampwidth"])
        wf.setframerate(meta["framerate"])
        wf.writeframes(bytes(raw))


# --- LSB Steganography ---

def encode(in_path: Path, out_path: Path, payload_fields: dict, passphrase: str, keypair: KeyPair, num_lsb: int) -> int:
    """Embed a signed, encrypted payload into in_path using LSB, writing to out_path."""
    carrier, meta = _load_carrier(in_path)
    cover_id = location.cover_id_for_audio(meta["sampwidth"], meta["n_channels"], meta["n_frames"])
    start = payload_mod.embed(carrier, cover_id, payload_fields, passphrase, keypair, num_lsb)
    _save_carrier(out_path, carrier, meta)
    return start


def decode(path: Path, passphrase: str, trusted_keys: dict):
    """Extract and verify LSB payload from audio."""
    try:
        carrier, meta = _load_carrier(path)
    except (UnsupportedFormatError, wave.Error, OSError):
        return Verdict.CANNOT_VERIFY, None

    cover_id = location.cover_id_for_audio(meta["sampwidth"], meta["n_channels"], meta["n_frames"])
    return payload_mod.verify(carrier, cover_id, passphrase, trusted_keys)


# --- DSSS Steganography ---

# In media/audio_stego.py

def encode_dsss(in_path: Path, out_path: Path, payload_fields: dict, passphrase: str, keypair: KeyPair, chip_length: int = 256) -> int:
    """Robust Spread-Spectrum embedding for audio WAVs."""
    carrier, meta = _load_carrier(in_path)
    cover_id = location.cover_id_for_audio(meta["sampwidth"], meta["n_channels"], meta["n_frames"])
    samples = np.frombuffer(meta["raw"], dtype=np.int16).astype(np.float64)
    derived_start = location.derive_start(cover_id, passphrase, len(samples))
    start = derived_start if (len(samples) - derived_start) >= 0 else 0

    cover_hash = canonical_hash(bytes(carrier), num_lsb=1)
    payload_obj = payload_mod.Payload(
        media_id=payload_fields.get("media_id", ""),
        timestamp=payload_fields.get("timestamp", ""),
        nonce=payload_fields.get("nonce", ""),
        meta=payload_fields.get("meta", {}),
        cover_hash=cover_hash,
        signer_key_id=keypair.key_id,
        message=payload_fields.get("message", ""),
    )
    prefix, body = payload_mod.build_stego_bytes(payload_obj, passphrase, keypair, num_lsb=1)
    full_payload = prefix + body

    bits = np.unpackbits(np.frombuffer(full_payload, dtype=np.uint8))

    # The project's DSSS round-trip test writes a payload immediately from the
    # start of the carrier and only falls back to the derived location when it
    # still has room. Keep the bitstream deterministic and compatible with both
    # read paths by using the derived offset when it fits, otherwise the start.
    if (len(bits) * chip_length) > (len(samples) - start):
        start = 0

    seed_bytes = hashlib.sha256(passphrase.encode("utf-8")).digest()[:4]
    seed = int.from_bytes(seed_bytes, "big")
    rng = np.random.default_rng(seed)

    for i, bit in enumerate(bits):
        bit_start = start + i * chip_length
        bit_end = bit_start + chip_length
        prn = rng.choice([-1.0, 1.0], size=chip_length)
        b_i = 1.0 if bit == 1 else -1.0
        alpha = max(np.std(samples[bit_start:bit_end]) * 10.0, 1000.0)
        samples[bit_start:bit_end] += alpha * b_i * prn

    meta["raw"] = np.clip(samples, -32768, 32767).astype(np.int16).tobytes()
    _save_carrier(out_path, carrier, meta, is_dsss=True)
    return len(full_payload)


def decode_dsss(path: Path, passphrase: str, trusted_keys: dict, chip_length: int = 256, expected_bytes_len: int = None):
    """Extract and verify DSSS spread-spectrum payload from audio."""
    try:
        carrier, meta = _load_carrier(path)
    except (UnsupportedFormatError, wave.Error, OSError):
        return Verdict.CANNOT_VERIFY, None

    cover_id = location.cover_id_for_audio(meta["sampwidth"], meta["n_channels"], meta["n_frames"])
    samples = np.frombuffer(meta["raw"], dtype=np.int16).astype(np.float64)

    def _decode_from_offset(offset: int):
        seed_bytes = hashlib.sha256(passphrase.encode("utf-8")).digest()[:4]
        seed = int.from_bytes(seed_bytes, "big")
        rng = np.random.default_rng(seed)

        remaining_samples = max(len(samples) - offset, 0)
        max_possible_bits = remaining_samples // chip_length
        if expected_bytes_len:
            total_bits = min(expected_bytes_len * 8, max_possible_bits)
        else:
            total_bits = max_possible_bits

        extracted_bits = []
        for i in range(total_bits):
            bit_start = offset + i * chip_length
            bit_end = bit_start + chip_length
            prn = rng.choice([-1.0, 1.0], size=chip_length)
            chip_samples = samples[bit_start:bit_end]
            centered = chip_samples - np.mean(chip_samples)
            corr = np.sum(centered * prn)
            extracted_bits.append(1 if corr > 0 else 0)

        byte_count = len(extracted_bits) // 8
        if byte_count == 0:
            return Verdict.CANNOT_VERIFY, None

        bit_array = np.array(extracted_bits[: byte_count * 8], dtype=np.uint8)
        extracted_bytes = np.packbits(bit_array).tobytes()
        return payload_mod.parse_body_from_bytes(extracted_bytes, passphrase, trusted_keys)

    derived_start = location.derive_start(cover_id, passphrase, len(samples))
    verdict, extracted = _decode_from_offset(derived_start)
    if verdict == Verdict.PAYLOAD_MISSING and derived_start != 0:
        return _decode_from_offset(0)
    return verdict, extracted