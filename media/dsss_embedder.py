import hashlib

import numpy as np

from core.ecc import PayloadECC


def _seed_for_passphrase(passphrase: str, offset: int = 0) -> int:
    digest = hashlib.sha256(passphrase.encode("utf-8") + offset.to_bytes(4, "big")).digest()
    return int.from_bytes(digest[:8], "big")


def generate_chip_sequence(seed: int, length: int) -> np.ndarray:
    """Deterministic PRN chip sequence with balanced +1/-1 values."""
    rng = np.random.default_rng(seed)
    return rng.choice([-1.0, 1.0], size=length).astype(np.float64)


def embed_bits(carrier_signal: np.ndarray, message_bits, passphrase: str, chip_length: int = 256) -> np.ndarray:
    """Spread a message bitstream across a 1D carrier using a passphrase-derived PRN sequence."""
    bits = np.asarray(message_bits, dtype=np.int8)
    if bits.size == 0:
        return np.array(carrier_signal, dtype=np.float64, copy=True)
    if bits.size * chip_length > len(carrier_signal):
        raise ValueError("Carrier signal is too short for the requested bitstream.")

    stego = np.array(carrier_signal, dtype=np.float64, copy=True)
    for i, bit in enumerate(bits):
        chip = generate_chip_sequence(_seed_for_passphrase(passphrase, i), chip_length)
        sign = 1.0 if bit else -1.0
        segment = stego[i * chip_length:(i + 1) * chip_length]
        scale = max(float(np.std(segment)), 1.0) * 8.0
        centered = segment - np.mean(segment)
        stego[i * chip_length:(i + 1) * chip_length] = centered + sign * chip * scale
    return stego


def extract_bits(stego_signal: np.ndarray, num_bits: int, passphrase: str, chip_length: int = 256) -> list[int]:
    """Recover message bits by correlating with the same chip sequence used during embedding."""
    if num_bits * chip_length > len(stego_signal):
        raise ValueError("Signal is too short to contain the requested number of bits.")

    extracted: list[int] = []
    for i in range(num_bits):
        chip = generate_chip_sequence(_seed_for_passphrase(passphrase, i), chip_length)
        window = stego_signal[i * chip_length:(i + 1) * chip_length]
        corr = float(np.dot(window - np.mean(window), chip))
        extracted.append(1 if corr >= 0 else 0)
    return extracted

class DSSSAudioEmbedder:
    """
    Direct Sequence Spread Spectrum (DSSS) Audio Steganography Engine.
    Spreads payload bits across audio frequency spectrum using PRN sequences.
    """
    
    def __init__(self, key: int = 1337, chip_length: int = 512, ecc_symbols: int = 16):
        self.key = key
        self.chip_length = chip_length
        self.ecc_symbols = ecc_symbols
        self.ecc = PayloadECC(nsymbols=ecc_symbols)

    def embed(self, cover_audio: np.ndarray, raw_payload: bytes) -> np.ndarray:
        # Step 1: Encode payload with Error Correction
        ecc_payload = self.ecc.encode(raw_payload)
        
        # Step 2: Convert byte stream to bit array
        bits = np.unpackbits(np.frombuffer(ecc_payload, dtype=np.uint8))
        
        # Step 3: Spread bits across audio using pseudo-random noise
        stego_audio = cover_audio.astype(np.float64).copy()
        rng = np.random.default_rng(self.key)
        
        for i, bit in enumerate(bits):
            start = i * self.chip_length
            end = start + self.chip_length
            if end > len(stego_audio):
                raise ValueError("Audio carrier too short for robust payload.")
                
            # Dynamic energy scaling based on local audio variance
            local_std = np.std(stego_audio[start:end]) + 1e-5
            alpha = min(max(local_std * 0.05, 2.0), 20.0)
            
            # Modulate PRN chip sequence (-1 or +1)
            prn = rng.choice([-1.0, 1.0], size=self.chip_length)
            b_i = 1.0 if bit == 1 else -1.0
            
            stego_audio[start:end] += alpha * b_i * prn

        return np.clip(stego_audio, -32768, 32767).astype(np.int16)

    def embed_bits(self, carrier_signal: np.ndarray, message_bits, passphrase: str, chip_length: int = 256) -> np.ndarray:
        return embed_bits(carrier_signal, message_bits, passphrase, chip_length=chip_length)

    def extract(self, stego_audio: np.ndarray, payload_len_bytes: int) -> bytes:
        # Fixed: Calculate total bytes using self.ecc_symbols instead of self.ecc.rs.nsym
        total_bytes = payload_len_bytes + self.ecc_symbols
        total_bits = total_bytes * 8
        
        samples = stego_audio.astype(np.float64)
        rng = np.random.default_rng(self.key)
        extracted_bits = []

        for i in range(total_bits):
            start = i * self.chip_length
            end = start + self.chip_length
            if end > len(samples):
                raise ValueError("Stego audio ended prematurely during DSSS extraction.")
            
            prn = rng.choice([-1.0, 1.0], size=self.chip_length)
            chip_samples = samples[start:end]
            
            # Cross-correlation decision rule
            corr = np.sum(chip_samples * prn)
            extracted_bits.append(1 if corr > 0 else 0)

        # Step 4: Reconstruct bytes and run Reed-Solomon error correction
        bit_array = np.array(extracted_bits, dtype=np.uint8)
        packed_bytes = np.packbits(bit_array).tobytes()
        
        return self.ecc.decode(packed_bytes)

    def extract_bits(self, stego_signal: np.ndarray, num_bits: int, passphrase: str, chip_length: int = 256) -> list[int]:
        return extract_bits(stego_signal, num_bits, passphrase, chip_length=chip_length)