"""Verdict decision logic (docs/format.md §9).

Pure and total: decide() knows nothing about how Evidence was gathered - no
crypto, no bitstream, no file formats, no I/O, no exceptions.
"""

from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional


class Verdict(Enum):
    AUTHENTIC = auto()
    TAMPERED = auto()
    SIGNATURE_INVALID = auto()
    PAYLOAD_MISSING = auto()
    WRONG_START_LOCATION = auto()
    CANNOT_VERIFY = auto()


@dataclass
class Evidence:
    readable: bool = True
    magic_at_derived: bool = False
    magic_at_zero: bool = False
    version_known: bool = True
    body_len_fits: bool = True
    verified_key_id: Optional[str] = None
    claimed_signer_key_id: Optional[str] = None
    gcm_tag_ok: bool = True
    cover_hash_matches: bool = True


def decide(e: Evidence) -> Verdict:
    """Implements §9's table (rows 2/3 as corrected: WRONG_START_LOCATION now
    requires magic present at offset 0, making it mutually exclusive with
    PAYLOAD_MISSING).

    Note on the signer_key_id clause: it only applies when a claim is actually
    available (i.e. decryption + JSON parsing succeeded). If GCM decryption
    failed, claimed_signer_key_id is None and this clause is skipped so a
    genuinely-tampered ciphertext under an otherwise-valid signature reports
    TAMPERED, not SIGNATURE_INVALID.
    """
    if not e.readable:
        return Verdict.CANNOT_VERIFY

    if not e.magic_at_derived and e.magic_at_zero:
        return Verdict.WRONG_START_LOCATION
    if not e.magic_at_derived and not e.magic_at_zero:
        return Verdict.PAYLOAD_MISSING

    if not e.version_known or not e.body_len_fits:
        return Verdict.CANNOT_VERIFY

    if e.verified_key_id is None:
        return Verdict.SIGNATURE_INVALID
    if e.claimed_signer_key_id is not None and e.verified_key_id != e.claimed_signer_key_id:
        return Verdict.SIGNATURE_INVALID

    if not e.gcm_tag_ok:
        return Verdict.TAMPERED
    if not e.cover_hash_matches:
        return Verdict.TAMPERED

    return Verdict.AUTHENTIC
