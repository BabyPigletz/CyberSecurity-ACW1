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
from reedsolo import RSCodec, ReedSolomonError

MAGIC = b"ACW1"
VERSION = 0x02
PREFIX_LEN = 10  # bytes
PREFIX_CARRIER_LEN = PREFIX_LEN * 8  # always written at 1 bit/carrier-byte
SIG_LEN_FIELD = 2
SALT_LEN = 16
IV_LEN = 12
GCM_TAG_LEN = 16
ECC_SYMBOLS = 16  # Can recover up to 8 corrupted bytes


@dataclass
class Payload:
    media_id: str
    timestamp: str
    nonce: str
    meta: dict
    cover_hash: bytes
    signer_key_id: str
    message: str = ""


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


def apply_ecc(data: bytes, nsym: int = ECC_SYMBOLS) -> bytes:
    rsc = RSCodec(nsym)
    return bytes(rsc.encode(data))


def remove_ecc(data: bytes, nsym: int = ECC_SYMBOLS) -> bytes:
    rsc = RSCodec(nsym)
    try:
        return bytes(rsc.decode(data)[0])
    except ReedSolomonError as e:
        raise ValueError("Payload unrecoverable due to corruption.") from e


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


def _plaintext(payload: Payload) -> bytes:
    fields = {
        "cover_hash": payload.cover_hash.hex(),
        "media_id": payload.media_id,
        "meta": payload.meta,
        "nonce": payload.nonce,
        "signer_key_id": payload.signer_key_id,
        "timestamp": payload.timestamp,
    }
    if payload.message:
        fields["message"] = payload.message
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def estimate_body_len(message: str, meta: dict, keypair: KeyPair) -> int:
    """Exact body size for an auto-generated payload.

    The body layout includes a variable-length RSA signature and Reed-Solomon
    ECC, so the safe and exact strategy is to mirror the real encoder's body
    assembly rather than approximating from a hand-derived plaintext-length
    formula. The passphrase only affects key derivation, not the encoded length,
    so we can use a fixed dummy value here without changing the result.
    """
    placeholder = Payload(
        media_id=str(uuid.UUID(int=0)),
        timestamp=_utc_now(),
        nonce="0" * 32,
        meta=meta,
        cover_hash=bytes(32),
        signer_key_id=keypair.key_id,
        message=message,
    )
    _, body = build_stego_bytes(placeholder, "estimate-body-len", keypair, num_lsb=1)
    return len(body)


def max_body_len(carrier_len: int, start: int, num_lsb: int) -> int:
    """Largest body, in bytes, that fits after the prefix when written from start at num_lsb."""
    return max(carrier_len - start - PREFIX_CARRIER_LEN, 0) * num_lsb // 8


def build_stego_bytes(payload: Payload, passphrase: str, keypair: KeyPair, num_lsb: int) -> "tuple[bytes, bytes]":
    """Assemble (prefix, body) per §4/§5 with Reed-Solomon protection."""
    plaintext = _plaintext(payload)
    random_salt = os.urandom(SALT_LEN)
    aes_key = crypto.derive_aes_key(passphrase, random_salt)
    iv, ciphertext = crypto.encrypt(aes_key, plaintext)
    signed_data = random_salt + iv + ciphertext
    signature = crypto.sign(keypair.private_key, signed_data)

    protected_body = apply_ecc(signed_data)
    body = len(signature).to_bytes(SIG_LEN_FIELD, "big") + signature + protected_body
    prefix = build_prefix(num_lsb, len(body))
    return prefix, body


def parse_body(
    carrier, start: int, num_lsb: int, body_len: int, passphrase: str, trusted_keys: dict
) -> BodyResult:
    """Read+interpret the body with Reed-Solomon recovery."""
    raw = bitstream.read_bits(carrier, start, body_len, num_lsb)
    sig_len = int.from_bytes(raw[0:2], "big")
    signature = raw[2:2 + sig_len]

    try:
        signed_data = remove_ecc(raw[2 + sig_len:])
        salt = signed_data[0:SALT_LEN]
        iv = signed_data[SALT_LEN:SALT_LEN + IV_LEN]
        ciphertext = signed_data[SALT_LEN + IV_LEN:]
    except ValueError:
        return BodyResult(None, False, None, None, None)

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


def parse_body_from_bytes(raw: bytes, passphrase: str, trusted_keys: dict) -> "tuple[Verdict, Optional[Extracted]]":
    """Parse a raw payload byte stream (as produced by DSSS extraction) without a carrier.

    The payload format is still the same prefix + signed body layout from the carrier-based
    decoder. This helper is intentionally lighter-weight: it verifies the embedded signature and
    AES-GCM content and returns the same verdict/extracted payload shape that the DSSS decoder
    expects, without trying to re-derive a cover hash from the carrier itself.
    """
    if len(raw) < PREFIX_LEN:
        return Verdict.PAYLOAD_MISSING, None

    prefix = parse_prefix_bytes(raw[:PREFIX_LEN])
    if not prefix.magic_ok:
        return Verdict.PAYLOAD_MISSING, None

    if prefix.version != VERSION or not 1 <= prefix.num_lsb <= 8:
        return Verdict.CANNOT_VERIFY, None

    body_start = PREFIX_LEN
    body_end = body_start + prefix.body_len
    if len(raw) < body_end:
        return Verdict.CANNOT_VERIFY, None

    body = raw[body_start:body_end]
    sig_len = int.from_bytes(body[0:2], "big")
    signature = body[2:2 + sig_len]

    try:
        signed_data = remove_ecc(body[2 + sig_len:])
        salt = signed_data[0:SALT_LEN]
        iv = signed_data[SALT_LEN:SALT_LEN + IV_LEN]
        ciphertext = signed_data[SALT_LEN + IV_LEN:]
    except ValueError:
        return Verdict.TAMPERED, None

    verified_key_id = None
    for key_id, pub in trusted_keys.items():
        if crypto.verify(pub, signed_data, signature):
            verified_key_id = key_id
            break

    if verified_key_id is None:
        return Verdict.SIGNATURE_INVALID, None

    aes_key = crypto.derive_aes_key(passphrase, salt)
    try:
        plaintext = crypto.decrypt(aes_key, iv, ciphertext)
    except InvalidTag:
        return Verdict.TAMPERED, None

    try:
        obj = json.loads(plaintext.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return Verdict.CANNOT_VERIFY, None

    if obj.get("signer_key_id") is not None and verified_key_id != obj.get("signer_key_id"):
        return Verdict.SIGNATURE_INVALID, None

    cover_hash_hex = obj.get("cover_hash")
    extracted = Extracted(obj, cover_hash_hex, cover_hash_hex or "")
    return Verdict.AUTHENTIC, extracted


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
        message=payload_fields.get("message", ""),
    )
    prefix, body = build_stego_bytes(payload, passphrase, keypair, num_lsb)

    capacity = max_body_len(carrier_len, start, num_lsb)
    if len(body) > capacity:
        raise CapacityError(
            f"Payload is {len(body):,} bytes (message {len(payload.message.encode('utf-8')):,} bytes), "
            f"but this cover holds at most {capacity:,} bytes at {num_lsb} LSB from the derived offset "
            f"{start:,}. Use more LSBs, a larger cover, or a shorter message."
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
        ev.cover_hash_matches = True

    verdict = decide(ev)
    if recomputed is None or verdict not in (Verdict.AUTHENTIC, Verdict.TAMPERED):
        return verdict, None
    return verdict, Extracted(body_result.parsed, body_result.cover_hash_hex, recomputed)