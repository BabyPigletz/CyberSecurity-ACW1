import pytest
from core import ecc
from core.errors import ECCError  # Adjust exception name if different in your codebase


def test_ecc_encode_decode_clean():
    """Validates that uncorrupted data passes through ECC intact."""
    data = b"Steganography baseline message with ECC protection."
    encoded = ecc.encode(data)
    decoded = ecc.decode(encoded)
    assert decoded == data


def test_ecc_recovers_from_corrupted_bytes():
    """Validates that Reed-Solomon successfully fixes bit/byte flips within its error budget."""
    data = b"Critical cryptographic payload"
    encoded = bytearray(ecc.encode(data))

    # Introduce intentional corruption (flip bits in the middle of the payload)
    encoded[5] ^= 0xFF
    encoded[10] ^= 0xAA

    decoded = ecc.decode(bytes(encoded))
    assert decoded == data


def test_ecc_fails_when_errors_exceed_capacity():
    """Validates that exceeding the correctable symbol threshold raises an explicit error."""
    data = b"Short payload"
    encoded = bytearray(ecc.encode(data))

    # Heavily corrupt the encoded data beyond recovery limit
    for i in range(len(encoded) // 2):
        encoded[i] ^= 0xFF

    with pytest.raises(Exception):  # Catch ECCError or relevant error
        ecc.decode(bytes(encoded))