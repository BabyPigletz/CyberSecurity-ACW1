import os
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from core import crypto

KEYS = Path(__file__).resolve().parent.parent / "keys"


def test_offset_key_is_deterministic_and_needs_no_file():
    a = crypto.derive_offset_key("correct horse battery staple")
    b = crypto.derive_offset_key("correct horse battery staple")
    assert a == b
    assert len(a) == 32


def test_offset_key_differs_by_passphrase():
    a = crypto.derive_offset_key("passphrase one")
    b = crypto.derive_offset_key("passphrase two")
    assert a != b


def test_aes_key_differs_by_random_salt_same_passphrase():
    a = crypto.derive_aes_key("same passphrase", os.urandom(16))
    b = crypto.derive_aes_key("same passphrase", os.urandom(16))
    assert a != b


def test_offset_and_aes_keys_are_domain_separated():
    salt = os.urandom(16)
    offset_key = crypto.derive_offset_key("same passphrase")
    aes_key = crypto.derive_aes_key("same passphrase", salt)
    assert offset_key != aes_key
    assert len(offset_key) == len(aes_key) == 32


def test_encrypt_decrypt_round_trip():
    key = crypto.derive_aes_key("pw", os.urandom(16))
    iv, ct = crypto.encrypt(key, b"hello world")
    assert crypto.decrypt(key, iv, ct) == b"hello world"


def test_decrypt_wrong_key_raises_invalid_tag():
    key1 = crypto.derive_aes_key("pw", os.urandom(16))
    key2 = crypto.derive_aes_key("other", os.urandom(16))
    iv, ct = crypto.encrypt(key1, b"secret")
    with pytest.raises(InvalidTag):
        crypto.decrypt(key2, iv, ct)


def test_decrypt_tampered_ciphertext_raises_invalid_tag():
    key = crypto.derive_aes_key("pw", os.urandom(16))
    iv, ct = crypto.encrypt(key, b"secret")
    tampered = bytes([ct[0] ^ 0x01]) + ct[1:]
    with pytest.raises(InvalidTag):
        crypto.decrypt(key, iv, tampered)


def test_sign_verify_round_trip():
    kp = crypto.load_keypair(KEYS / "demo_a_pub.pem", KEYS / "demo_a_priv.pem")
    sig = crypto.sign(kp.private_key, b"data to sign")
    assert crypto.verify(kp.public_key, b"data to sign", sig) is True


def test_verify_fails_on_tampered_data():
    kp = crypto.load_keypair(KEYS / "demo_a_pub.pem", KEYS / "demo_a_priv.pem")
    sig = crypto.sign(kp.private_key, b"data to sign")
    assert crypto.verify(kp.public_key, b"different data", sig) is False


def test_verify_fails_with_wrong_public_key():
    kp_a = crypto.load_keypair(KEYS / "demo_a_pub.pem", KEYS / "demo_a_priv.pem")
    kp_b = crypto.load_keypair(KEYS / "demo_b_pub.pem")
    sig = crypto.sign(kp_a.private_key, b"data to sign")
    assert crypto.verify(kp_b.public_key, b"data to sign", sig) is False


def test_rsa_pss_signature_length_is_fixed():
    kp = crypto.load_keypair(KEYS / "demo_a_pub.pem", KEYS / "demo_a_priv.pem")
    assert len(crypto.sign(kp.private_key, b"x")) == 256
    assert len(crypto.sign(kp.private_key, b"x" * 5000)) == 256


def test_canonical_hash_ignores_low_bits_only():
    carrier = bytes([0b10110010, 0b01110001, 0b11111111])
    masked_variant = bytes([0b10110000, 0b01110000, 0b11111100])  # low 2 bits zeroed
    assert crypto.canonical_hash(carrier, 2) == crypto.canonical_hash(masked_variant, 2)


def test_canonical_hash_changes_on_high_bit_flip():
    carrier = bytes([0b10110010])
    flipped_high_bit = bytes([0b00110010])  # bit 7 flipped, well above 2 LSBs
    assert crypto.canonical_hash(carrier, 2) != crypto.canonical_hash(flipped_high_bit, 2)


def test_key_ids_differ_and_are_stable():
    kp_a1 = crypto.load_keypair(KEYS / "demo_a_pub.pem")
    kp_a2 = crypto.load_keypair(KEYS / "demo_a_pub.pem")
    kp_b = crypto.load_keypair(KEYS / "demo_b_pub.pem")
    assert kp_a1.key_id == kp_a2.key_id
    assert kp_a1.key_id != kp_b.key_id
    assert len(kp_a1.key_id) == 16
