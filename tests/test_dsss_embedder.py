import numpy as np
import pytest
from media import dsss_embedder  # Or 'from core.media import dsss_embedder' depending on your layout


def test_dsss_sequence_orthogonality():
    """Ensures pseudo-random chip sequences have strong cross-correlation properties."""
    seq1 = dsss_embedder.generate_chip_sequence(seed=42, length=1024)
    seq2 = dsss_embedder.generate_chip_sequence(seed=99, length=1024)

    # Normalized dot product of orthogonal sequences should be close to 0
    dot_product = np.dot(seq1, seq2) / len(seq1)
    assert abs(dot_product) < 0.1


def test_dsss_bit_embed_and_extract_clean():
    """Verifies basic spread spectrum modulation and demodulation on a 1D signal vector."""
    message_bits = [1, 0, 1, 1, 0, 1, 0, 0]
    carrier_signal = np.random.randint(-1000, 1000, size=2048, dtype=np.int16)
    passphrase = "test_passphrase"

    stego_signal = dsss_embedder.embed_bits(carrier_signal, message_bits, passphrase, chip_length=256)
    extracted_bits = dsss_embedder.extract_bits(stego_signal, len(message_bits), passphrase, chip_length=256)

    assert extracted_bits == message_bits


def test_dsss_resilience_against_additive_noise():
    """Proves DSSS spread spectrum advantage by extracting bits despite high background noise."""
    message_bits = [1, 1, 0, 1, 0]
    carrier_signal = np.zeros(1280, dtype=np.float32)
    passphrase = "robustness_key"

    stego_signal = dsss_embedder.embed_bits(carrier_signal, message_bits, passphrase, chip_length=256)

    # Add Gaussian noise
    noise = np.random.normal(0, 0.5, size=stego_signal.shape)
    noisy_stego = stego_signal + noise

    extracted_bits = dsss_embedder.extract_bits(noisy_stego, len(message_bits), passphrase, chip_length=256)
    assert extracted_bits == message_bits