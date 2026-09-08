import os

import pytest

from core.bitstream import capacity_bytes, read_bits, write_bits
from core.errors import CapacityError


@pytest.mark.parametrize("num_lsb", range(1, 9))
def test_round_trip_various_starts(num_lsb):
    carrier = bytearray(os.urandom(4000))
    data = os.urandom(37)
    needed = -(-(len(data) * 8) // num_lsb)
    last_valid_start = 4000 - needed
    for start in (0, 1, 17, last_valid_start):
        c = bytearray(carrier)
        write_bits(c, start, data, num_lsb)
        assert read_bits(c, start, len(data), num_lsb) == data


@pytest.mark.parametrize("num_lsb", range(1, 9))
def test_capacity_exact_fit_and_overflow(num_lsb):
    carrier_len = 1000
    max_bytes = capacity_bytes(carrier_len, num_lsb)
    carrier = bytearray(carrier_len)
    data = bytes(max_bytes)
    write_bits(carrier, 0, data, num_lsb)  # exact fit must not raise

    with pytest.raises(CapacityError):
        write_bits(bytearray(carrier_len), 0, bytes(max_bytes + 1), num_lsb)


def test_capacity_bytes_formula():
    assert capacity_bytes(8, 1) == 1
    assert capacity_bytes(8, 8) == 8
    assert capacity_bytes(0, 1) == 0
    assert capacity_bytes(7, 8) == 7


def test_read_bits_too_short_raises():
    carrier = bytearray(10)
    with pytest.raises(CapacityError):
        read_bits(carrier, 5, 100, 1)


@pytest.mark.parametrize("num_lsb", range(1, 8))
def test_write_bits_preserves_high_bits(num_lsb):
    carrier = bytearray([0xFF] * 100)
    write_bits(carrier, 10, bytes([0x00]), num_lsb)
    high_mask = (0xFF << num_lsb) & 0xFF
    for b in carrier[10:10 + (-(-8 // num_lsb))]:
        assert b & high_mask == high_mask, "bits above num_lsb must be untouched"


def test_write_bits_start_out_of_range():
    carrier = bytearray(10)
    with pytest.raises(CapacityError):
        write_bits(carrier, -1, b"x", 1)
