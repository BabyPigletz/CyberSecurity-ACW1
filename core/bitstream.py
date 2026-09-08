"""Codec-agnostic LSB bit packing (docs/format.md §3).

Knows nothing about images, audio, JSON, or crypto - only integer/byte math
over a flat carrier byte sequence.
"""

from core.errors import CapacityError


def capacity_bytes(carrier_len: int, num_lsb: int) -> int:
    """Max whole payload bytes storable in carrier_len carrier bytes at num_lsb bits/byte."""
    if not 1 <= num_lsb <= 8:
        raise ValueError("num_lsb must be between 1 and 8")
    return (carrier_len * num_lsb) // 8


def _bits_of_bytes(data: bytes):
    for byte in data:
        for shift in range(7, -1, -1):
            yield (byte >> shift) & 1


def write_bits(carrier: bytearray, start: int, data: bytes, num_lsb: int) -> None:
    """Write data into carrier[start:] at num_lsb bits per byte.

    Data bytes are consumed MSB-first; within each carrier byte the bits fill
    from bit 0 upward. Mutates carrier in place. Raises CapacityError if data
    does not fit starting at start.
    """
    if not 1 <= num_lsb <= 8:
        raise ValueError("num_lsb must be between 1 and 8")
    total_bits = len(data) * 8
    n_carrier = -(-total_bits // num_lsb)  # ceil
    if start < 0 or start + n_carrier > len(carrier):
        raise CapacityError(
            f"need {n_carrier} carrier bytes from index {start}, "
            f"only {max(len(carrier) - start, 0)} available"
        )

    bits = list(_bits_of_bytes(data))
    bits.extend([0] * (n_carrier * num_lsb - total_bits))  # pad the last chunk
    clear_mask = (0xFF << num_lsb) & 0xFF

    for i in range(n_carrier):
        chunk = bits[i * num_lsb:(i + 1) * num_lsb]
        value = 0
        for bit_index, bit in enumerate(chunk):
            value |= bit << bit_index
        carrier[start + i] = (carrier[start + i] & clear_mask) | value


def read_bits(carrier, start: int, n_bytes: int, num_lsb: int) -> bytes:
    """Inverse of write_bits: read n_bytes from carrier[start:], num_lsb bits per byte.

    Raises CapacityError if the required carrier span exceeds len(carrier).
    """
    if not 1 <= num_lsb <= 8:
        raise ValueError("num_lsb must be between 1 and 8")
    total_bits = n_bytes * 8
    n_carrier = -(-total_bits // num_lsb)
    if start < 0 or start + n_carrier > len(carrier):
        raise CapacityError(
            f"need {n_carrier} carrier bytes from index {start}, "
            f"only {max(len(carrier) - start, 0)} available"
        )

    mask = (1 << num_lsb) - 1
    bits = []
    for i in range(n_carrier):
        value = carrier[start + i] & mask
        for bit_index in range(num_lsb):
            bits.append((value >> bit_index) & 1)
    bits = bits[:total_bits]

    out = bytearray(n_bytes)
    for byte_index in range(n_bytes):
        b = 0
        for bit_offset in range(8):
            b = (b << 1) | bits[byte_index * 8 + bit_offset]
        out[byte_index] = b
    return bytes(out)
