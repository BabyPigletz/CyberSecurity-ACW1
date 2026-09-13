"""Payload framing, orchestration, and wire (de)serialisation.

docs/format.md §4 (prefix), §5 (body/JSON), §7 (start location), §9 (verdict
evidence). This module knows nothing about images, audio, PIL, wave, or
Tkinter - it only ever sees a flat `carrier: bytearray`/`bytes` and integer
offsets, plus whatever `crypto.KeyPair` objects it's handed.
"""

import json
import os
import time
import uuid
from dataclasses import dataclass
from typing import Optional

from cryptography.exceptions import InvalidTag

from core import bitstream, crypto, location
from core.crypto import KeyPair
from core.errors import CapacityError
from core.verdict import Evidence, Verdict, decide

MAGIC = b"ACW1"
VERSION = 0x02
PREFIX_LEN = 10  # bytes
PREFIX_CARRIER_LEN = PREFIX_LEN * 8  # always written at 1 bit/carrier-byte


@dataclass
class Payload:
    media_id: str
    timestamp: str
    nonce: str
    meta: dict
    cover_hash: bytes
    signer_key_id: str


@dataclass
class PrefixInfo:
    magic_ok: bool
    version: int
    num_lsb: int
    body_len: int


@dataclass
class BodyResult:
    verified_key_id: Optional[str]
    gcm_ok: bool
    claimed_signer_key_id: Optional[str]
    cover_hash_hex: Optional[str]
    parsed: Optional[dict]


@dataclass
class Extracted:
    payload: dict
    embedded_cover_hash: Optional[str]
    recomputed_cover_hash: str

    @property
    def cover_hash_matches(self) -> bool:
        return self.embedded_cover_hash == self.recomputed_cover_hash


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def build_prefix(num_lsb: int, body_len: int) -> bytes:
    return MAGIC + bytes([VERSION, num_lsb]) + body_len.to_bytes(4, "big")


def parse_prefix_bytes(raw: bytes) -> PrefixInfo:
    return PrefixInfo(
        magic_ok=raw[0:4] == MAGIC,
        version=raw[4],
        num_lsb=raw[5],
        body_len=int.from_bytes(raw[6:10], "big"),
    )


def build_stego_bytes(payload: Payload, passphrase: str, keypair: KeyPair, num_lsb: int) -> "tuple[bytes, bytes]":
    """Assemble (prefix, body) per §4/§5. Returned separately because the
    prefix is always written at 1 LSB while the body is written at num_lsb -
    a single concatenated blob can't express that split.
    """
    plaintext = json.dumps(
        {
            "cover_hash": payload.cover_hash.hex(),
            "media_id": payload.media_id,
            "meta": payload.meta,
            "nonce": payload.nonce,
            "signer_key_id": payload.signer_key_id,
            "timestamp": payload.timestamp,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    random_salt = os.urandom(16)
    aes_key = crypto.derive_aes_key(passphrase, random_salt)
    iv, ciphertext = crypto.encrypt(aes_key, plaintext)
    signed_data = random_salt + iv + ciphertext
    signature = crypto.sign(keypair.private_key, signed_data)

    body = len(signature).to_bytes(2, "big") + signature + random_salt + iv + ciphertext
    prefix = build_prefix(num_lsb, len(body))
    return prefix, body


def parse_body(
    carrier, start: int, num_lsb: int, body_len: int, passphrase: str, trusted_keys: dict
) -> BodyResult:
    """Read+interpret the body. Never raises for expected verification
    failures (bad signature, bad tag, unparsable JSON) - those become fields
    on the returned result for verdict.decide to interpret.
    """
    raw = bitstream.read_bits(carrier, start, body_len, num_lsb)
    sig_len = int.from_bytes(raw[0:2], "big")
    signature = raw[2:2 + sig_len]
    salt = raw[2 + sig_len:18 + sig_len]
    iv = raw[18 + sig_len:30 + sig_len]
    ciphertext = raw[30 + sig_len:]
    signed_data = salt + iv + ciphertext

    verified_key_id = None
    for key_id, pub in trusted_keys.items():
        if crypto.verify(pub, signed_data, signature):
            verified_key_id = key_id
            break

    aes_key = crypto.derive_aes_key(passphrase, salt)
    try:
        plaintext = crypto.decrypt(aes_key, iv, ciphertext)
    except InvalidTag:
        return BodyResult(verified_key_id, False, None, None, None)

    try:
        obj = json.loads(plaintext.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return BodyResult(verified_key_id, True, None, None, None)

    return BodyResult(verified_key_id, True, obj.get("signer_key_id"), obj.get("cover_hash"), obj)


def _try_read_prefix(carrier, start: int, carrier_len: int) -> Optional[PrefixInfo]:
    if start < 0 or start + PREFIX_CARRIER_LEN > carrier_len:
        return None
    raw = bitstream.read_bits(carrier, start, PREFIX_LEN, num_lsb=1)
    return parse_prefix_bytes(raw)


def embed(carrier: bytearray, cover_id: str, payload_fields: dict, passphrase: str, keypair: KeyPair, num_lsb: int) -> int:
    """Derive the start location, build the prefix+body, and write both into
    carrier in place. Returns the start offset used. Raises CapacityError
    before writing anything if the payload will not fit.
    """
    carrier_len = len(carrier)
    start = location.derive_start(cover_id, passphrase, carrier_len)

    cover_hash = crypto.canonical_hash(bytes(carrier), num_lsb)
    payload = Payload(
        media_id=payload_fields.get("media_id") or str(uuid.uuid4()),
        timestamp=payload_fields.get("timestamp") or _utc_now(),
        nonce=os.urandom(16).hex(),
        meta=payload_fields.get("meta", {}),
        cover_hash=cover_hash,
        signer_key_id=keypair.key_id,
    )
    prefix, body = build_stego_bytes(payload, passphrase, keypair, num_lsb)

    body_carrier_needed = -(-(len(body) * 8) // num_lsb)
    total_needed = PREFIX_CARRIER_LEN + body_carrier_needed
    if start + total_needed > carrier_len:
        raise CapacityError(
            f"payload needs {total_needed} carrier bytes from offset {start}, "
            f"only {carrier_len - start} available (cover too small for this LSB setting)"
        )

    bitstream.write_bits(carrier, start, prefix, num_lsb=1)
    bitstream.write_bits(carrier, start + PREFIX_CARRIER_LEN, body, num_lsb=num_lsb)
    return start


def verify(carrier, cover_id: str, passphrase: str, trusted_keys: dict) -> "tuple[Verdict, Optional[Extracted]]":
    """Full verify flow: derive start, read prefix/body, gather Evidence, decide."""
    carrier_len = len(carrier)
    if carrier_len < 2:
        return Verdict.CANNOT_VERIFY, None

    start = location.derive_start(cover_id, passphrase, carrier_len)
    ev = Evidence()

    prefix_derived = _try_read_prefix(carrier, start, carrier_len)
    ev.magic_at_derived = prefix_derived is not None and prefix_derived.magic_ok

    prefix_zero = _try_read_prefix(carrier, 0, carrier_len)
    ev.magic_at_zero = prefix_zero is not None and prefix_zero.magic_ok

    if not ev.magic_at_derived:
        return decide(ev), None

    ev.version_known = prefix_derived.version == VERSION
    body_start = start + PREFIX_CARRIER_LEN
    if not 1 <= prefix_derived.num_lsb <= 8:
        ev.body_len_fits = False
    else:
        body_carrier_needed = -(-(prefix_derived.body_len * 8) // prefix_derived.num_lsb)
        ev.body_len_fits = body_start + body_carrier_needed <= carrier_len

    if not ev.version_known or not ev.body_len_fits:
        return decide(ev), None

    body_result = parse_body(
        carrier, body_start, prefix_derived.num_lsb, prefix_derived.body_len, passphrase, trusted_keys
    )
    ev.verified_key_id = body_result.verified_key_id
    ev.claimed_signer_key_id = body_result.claimed_signer_key_id
    ev.gcm_tag_ok = body_result.gcm_ok

    recomputed = None
    if body_result.gcm_ok and body_result.parsed is not None:
        recomputed = crypto.canonical_hash(bytes(carrier), prefix_derived.num_lsb).hex()
        ev.cover_hash_matches = body_result.cover_hash_hex == recomputed
    else:
        ev.cover_hash_matches = True  # irrelevant - TAMPERED already decided by gcm_tag_ok

    verdict = decide(ev)
    # The signature is what vouches for this data, so it is never released without a valid one.
    if recomputed is None or verdict not in (Verdict.AUTHENTIC, Verdict.TAMPERED):
        return verdict, None
    return verdict, Extracted(body_result.parsed, body_result.cover_hash_hex, recomputed)
