from reedsolo import RSCodec, ReedSolomonError

from core.errors import ECCError


class PayloadECC:
    """Wraps encrypted payload bytes with Reed-Solomon parity symbols."""
    
    def __init__(self, nsyntax_symbols: int = 16):
        # 16 parity symbols can correct up to 8 corrupted bytes
        self.rs = RSCodec(nsyntax_symbols)

    def encode(self, data: bytes) -> bytes:
        return bytes(self.rs.encode(data))

    def decode(self, encoded_data: bytes) -> bytes:
        try:
            return bytes(self.rs.decode(encoded_data)[0])
        except ReedSolomonError as e:
            raise ECCError("Unrecoverable payload corruption.") from e


def encode(data: bytes, nsyntax_symbols: int = 16) -> bytes:
    """Encode payload bytes with Reed-Solomon ECC."""
    return PayloadECC(nsyntax_symbols).encode(data)


def decode(encoded_data: bytes, nsyntax_symbols: int = 16) -> bytes:
    """Decode and correct Reed-Solomon ECC data."""
    return PayloadECC(nsyntax_symbols).decode(encoded_data)