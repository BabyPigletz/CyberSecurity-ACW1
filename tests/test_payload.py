import os
from pathlib import Path

import pytest

from core import bitstream, crypto, location, payload as payload_mod
from core.errors import CapacityError
from core.verdict import Verdict

KEYS = Path(__file__).resolve().parent.parent / "keys"
COVER_ID = "test:synthetic"


def _keys():
    demo_a = crypto.load_keypair(KEYS / "demo_a_pub.pem", KEYS / "demo_a_priv.pem")
    demo_b = crypto.load_keypair(KEYS / "demo_b_pub.pem")
    return demo_a, demo_b


def test_round_trip_authentic():
    demo_a, _ = _keys()
    trusted = {demo_a.key_id: demo_a.public_key}
    carrier = bytearray(os.urandom(20000))

    start = payload_mod.embed(carrier, COVER_ID, {"meta": {"team": "P1-6"}}, "hunter2", demo_a, num_lsb=3)
    assert start > 0

    verdict, extracted = payload_mod.verify(carrier, COVER_ID, "hunter2", trusted)
    assert verdict == Verdict.AUTHENTIC
    assert extracted.cover_hash_matches
    assert extracted.payload["signer_key_id"] == demo_a.key_id
    assert extracted.payload["meta"]["team"] == "P1-6"


SHORT_MESSAGE = "Meet at the library at 3pm."
UNICODE_MESSAGE = "Line one — “smart quotes”, café, 中文\nemoji: 😀\n\ttrailing spaces   "


def _embedded_body_len(carrier, passphrase):
    start = location.derive_start(COVER_ID, passphrase, len(carrier))
    raw = bitstream.read_bits(carrier, start, payload_mod.PREFIX_LEN, num_lsb=1)
    return payload_mod.parse_prefix_bytes(raw).body_len


def test_message_round_trips_byte_for_byte():
    demo_a, _ = _keys()
    trusted = {demo_a.key_id: demo_a.public_key}
    for message in (SHORT_MESSAGE, UNICODE_MESSAGE, "x" * 5000):
        carrier = bytearray(os.urandom(200000))
        payload_mod.embed(carrier, COVER_ID, {"message": message}, "hunter2", demo_a, num_lsb=2)

        verdict, extracted = payload_mod.verify(carrier, COVER_ID, "hunter2", trusted)
        assert verdict == Verdict.AUTHENTIC
        assert extracted.payload["message"].encode("utf-8") == message.encode("utf-8")


def test_empty_message_keeps_metadata_only_payload():
    demo_a, _ = _keys()
    trusted = {demo_a.key_id: demo_a.public_key}
    body_lens = []
    for fields in ({}, {"message": ""}):
        carrier = bytearray(os.urandom(20000))
        payload_mod.embed(carrier, COVER_ID, fields, "hunter2", demo_a, num_lsb=2)

        verdict, extracted = payload_mod.verify(carrier, COVER_ID, "hunter2", trusted)
        assert verdict == Verdict.AUTHENTIC
        assert "message" not in extracted.payload
        body_lens.append(_embedded_body_len(carrier, "hunter2"))
    assert body_lens[0] == body_lens[1]


def test_estimate_body_len_matches_real_embed():
    demo_a, _ = _keys()
    meta = {"team": "P1-6"}
    for message in ("", SHORT_MESSAGE, UNICODE_MESSAGE, 'q"uote\\' * 300):
        carrier = bytearray(os.urandom(60000))
        payload_mod.embed(carrier, COVER_ID, {"message": message, "meta": meta}, "hunter2", demo_a, num_lsb=1)
        assert _embedded_body_len(carrier, "hunter2") == payload_mod.estimate_body_len(message, meta, demo_a)


def test_capacity_boundary_exact_fit_then_one_byte_over():
    demo_a, _ = _keys()
    carrier_len, num_lsb, passphrase = 30000, 1, "hunter2"
    start = location.derive_start(COVER_ID, passphrase, carrier_len)
    capacity = payload_mod.max_body_len(carrier_len, start, num_lsb)
    low, high = 0, capacity
    while low < high:
        candidate = (low + high + 1) // 2
        if payload_mod.estimate_body_len("a" * candidate, {}, demo_a) <= capacity:
            low = candidate
        else:
            high = candidate - 1
    exact_fit = "a" * low

    payload_mod.embed(bytearray(os.urandom(carrier_len)), COVER_ID, {"message": exact_fit}, passphrase, demo_a, num_lsb)

    with pytest.raises(CapacityError) as excinfo:
        payload_mod.embed(
            bytearray(os.urandom(carrier_len)), COVER_ID, {"message": exact_fit + "a"}, passphrase, demo_a, num_lsb
        )
    assert f"at most {capacity:,} bytes" in str(excinfo.value)


def test_wrong_passphrase_is_payload_missing_or_wrong_location():
    demo_a, _ = _keys()
    trusted = {demo_a.key_id: demo_a.public_key}
    carrier = bytearray(os.urandom(20000))
    payload_mod.embed(carrier, COVER_ID, {}, "correct-pass", demo_a, num_lsb=2)

    verdict, extracted = payload_mod.verify(carrier, COVER_ID, "wrong-pass", trusted)
    assert verdict in (Verdict.PAYLOAD_MISSING, Verdict.WRONG_START_LOCATION)
    assert extracted is None


def test_wrong_key_is_signature_invalid():
    demo_a, demo_b = _keys()
    # Embed signed by demo_a, but the verifier only trusts demo_b. The passphrase is
    # correct, so decryption succeeds - the payload must still be withheld.
    carrier = bytearray(os.urandom(20000))
    payload_mod.embed(carrier, COVER_ID, {}, "hunter2", demo_a, num_lsb=1)

    verdict, extracted = payload_mod.verify(carrier, COVER_ID, "hunter2", {demo_b.key_id: demo_b.public_key})
    assert verdict == Verdict.SIGNATURE_INVALID
    assert extracted is None


def test_tampered_high_bit_after_embed_is_tampered():
    demo_a, _ = _keys()
    trusted = {demo_a.key_id: demo_a.public_key}
    carrier = bytearray(os.urandom(20000))
    payload_mod.embed(carrier, COVER_ID, {}, "hunter2", demo_a, num_lsb=2)

    # Flip a high bit (well above num_lsb=2) on a carrier byte far from the
    # payload region - simulates a visible pixel/sample edit after signing.
    victim = len(carrier) - 1
    carrier[victim] ^= 0b10000000

    verdict, extracted = payload_mod.verify(carrier, COVER_ID, "hunter2", trusted)
    assert verdict == Verdict.TAMPERED
    assert extracted is not None and not extracted.cover_hash_matches
    assert extracted.payload["signer_key_id"] == demo_a.key_id


def test_tampered_ciphertext_byte_is_signature_invalid_not_gcm():
    """Under encrypt-then-sign with signed_data = salt||iv||ciphertext (the whole
    body payload), ANY bit flip inside that range breaks the RSA-PSS signature
    before GCM ever gets a chance to reject it - signature verification is
    checked first (§9 row 5 precedes row 6) and its scope is a strict superset
    of GCM's. This means row 6 (valid signature, broken GCM tag) is not
    reachable via external tampering in this design; see the final report for
    why that's an accepted tradeoff rather than a bug.
    """
    demo_a, _ = _keys()
    trusted = {demo_a.key_id: demo_a.public_key}
    carrier = bytearray(os.urandom(20000))
    start = payload_mod.embed(carrier, COVER_ID, {}, "hunter2", demo_a, num_lsb=8)

    victim = start + payload_mod.PREFIX_CARRIER_LEN + 40
    carrier[victim] ^= 0x01

    verdict, extracted = payload_mod.verify(carrier, COVER_ID, "hunter2", trusted)
    assert verdict == Verdict.SIGNATURE_INVALID
    assert extracted is None


def test_no_payload_at_all_is_payload_missing():
    demo_a, _ = _keys()
    trusted = {demo_a.key_id: demo_a.public_key}
    carrier = bytearray(os.urandom(20000))  # never embedded into

    verdict, extracted = payload_mod.verify(carrier, COVER_ID, "hunter2", trusted)
    assert verdict == Verdict.PAYLOAD_MISSING
    assert extracted is None


def test_stray_magic_at_zero_is_wrong_start_location():
    demo_a, _ = _keys()
    trusted = {demo_a.key_id: demo_a.public_key}
    carrier = bytearray(os.urandom(20000))

    # Simulate a doctored fixture: a valid-looking prefix planted at offset 0,
    # with no real payload at the (different) derived offset.
    bitstream.write_bits(carrier, 0, payload_mod.build_prefix(1, 999), num_lsb=1)

    verdict, extracted = payload_mod.verify(carrier, COVER_ID, "hunter2", trusted)
    assert verdict == Verdict.WRONG_START_LOCATION
    assert extracted is None


def test_capacity_error_raised_before_writing_anything():
    demo_a, _ = _keys()
    tiny_carrier = bytearray(os.urandom(50))  # far too small for prefix+body
    before = bytes(tiny_carrier)
    try:
        payload_mod.embed(tiny_carrier, COVER_ID, {}, "hunter2", demo_a, num_lsb=1)
        assert False, "expected CapacityError"
    except Exception as exc:
        assert type(exc).__name__ == "CapacityError"
    assert bytes(tiny_carrier) == before, "carrier must be untouched on capacity failure"


def test_signature_stripping_is_caught_by_signer_key_id():
    """The scenario docs/format.md §5's v0.3 amendment defends against: an
    attacker holding a second trusted keypair strips the original signature
    off a captured ciphertext and re-signs it with their own key. RSA-PSS
    verification then succeeds legitimately under the attacker's key, but the
    decrypted plaintext still claims the original signer - signer_key_id
    catches the mismatch and the verdict must be SIGNATURE_INVALID, not
    AUTHENTIC.
    """
    from cryptography.hazmat.primitives.asymmetric import rsa

    demo_a, _ = _keys()
    # A throwaway keypair standing in for "a second trusted signer" - generated
    # in-memory only, since demo_b's private half is deliberately not committed
    # to the repo (see keys/README.md) and isn't needed here: the point is any
    # second trusted key, not specifically demo_b's.
    forged_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged_kp = type(demo_a)(
        key_id=crypto._fingerprint(forged_private.public_key()),
        public_key=forged_private.public_key(),
        private_key=forged_private,
    )

    carrier = bytearray(os.urandom(20000))
    start = payload_mod.embed(carrier, COVER_ID, {}, "hunter2", demo_a, num_lsb=1)

    # Read back the framing to locate signed_data, then re-sign with the forged
    # key and splice the substitute signature in place (same length: both RSA-2048).
    prefix_raw = bitstream.read_bits(carrier, start, payload_mod.PREFIX_LEN, num_lsb=1)
    prefix = payload_mod.parse_prefix_bytes(prefix_raw)
    body_start = start + payload_mod.PREFIX_CARRIER_LEN
    body = bitstream.read_bits(carrier, body_start, prefix.body_len, num_lsb=1)

    sig_len = int.from_bytes(body[0:2], "big")
    salt_iv_ct = body[2 + sig_len:]
    forged_signature = crypto.sign(forged_kp.private_key, salt_iv_ct)
    assert len(forged_signature) == sig_len

    forged_body = body[0:2] + forged_signature + salt_iv_ct
    bitstream.write_bits(carrier, body_start, forged_body, num_lsb=1)

    # Verifier trusts both keys (the scenario signer_key_id is meant for).
    trusted = {demo_a.key_id: demo_a.public_key, forged_kp.key_id: forged_kp.public_key}
    verdict, extracted = payload_mod.verify(carrier, COVER_ID, "hunter2", trusted)
    assert verdict == Verdict.SIGNATURE_INVALID
    assert extracted is None
