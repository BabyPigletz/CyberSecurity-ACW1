"""Key management and cryptographic primitives (docs/format.md §6, §8).

Knows nothing about the wire format's byte layout, image/audio carriers, or
verdict semantics - pure key derivation, AEAD, and signing.
"""

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Fixed, public constant - the offset-derivation key must NOT depend on the
# random per-embed salt (that salt lives inside the body, which cannot be
# located until the offset is already known). See docs/format.md §6.
_FIXED_OFFSET_SALT = b"ACW1-offset-salt"
_PBKDF2_ITERATIONS = 200_000


@dataclass(frozen=True)
class KeyPair:
    key_id: str
    public_key: rsa.RSAPublicKey
    private_key: "rsa.RSAPrivateKey | None" = None


def _fingerprint(public_key: rsa.RSAPublicKey) -> str:
    der = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der).digest()[:8].hex()


def load_keypair(pub_path: Path, priv_path: "Path | None" = None) -> KeyPair:
    """Load PEM key(s). key_id = sha256(DER SubjectPublicKeyInfo)[:8].hex() (docs/format.md §5)."""
    with open(pub_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    private_key = None
    if priv_path is not None:
        with open(priv_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)

    return KeyPair(key_id=_fingerprint(public_key), public_key=public_key, private_key=private_key)


def _derive_master_key(passphrase: str, salt: bytes) -> bytes:
    """Derive one passphrase-bound master value for a specific salt context."""
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=64, salt=salt, iterations=_PBKDF2_ITERATIONS
    ).derive(passphrase.encode("utf-8"))


def _derive_subkey(master: bytes, context: bytes) -> bytes:
    """Derive an independent 256-bit subkey using a domain-separated label."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=context).derive(master)


def derive_offset_key(passphrase: str) -> bytes:
    """Derive the location key from a fixed pre-embedding salt context."""
    return _derive_subkey(_derive_master_key(passphrase, _FIXED_OFFSET_SALT), b"ACW1-offset")


def derive_aes_key(passphrase: str, random_salt: bytes) -> bytes:
    """aes_key from a random, per-embed salt (stored in the body, read before this is called on decode)."""
    return _derive_subkey(_derive_master_key(passphrase, random_salt), b"ACW1-aes")


def encrypt(aes_key: bytes, plaintext: bytes) -> "tuple[bytes, bytes]":
    """AES-256-GCM. Returns (iv, ciphertext_with_tag)."""
    iv = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(iv, plaintext, None)
    return iv, ciphertext


def decrypt(aes_key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """Normalize malformed/nonces into the caller-visible GCM authentication failure.

    A malformed nonce or truncated payload is not a recoverable decrypt condition;
    callers treat this as a tampered payload and surface it as TAMPERED or
    SIGNATURE_INVALID rather than crashing with a raw ValueError.
    """
    try:
        return AESGCM(aes_key).decrypt(iv, ciphertext, None)
    except ValueError as exc:
        raise InvalidTag("Malformed AES-GCM nonce or ciphertext") from exc


def sign(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    """RSA-PSS / SHA-256 / MGF1 signature over the exact given bytes."""
    return private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def verify(public_key: rsa.RSAPublicKey, data: bytes, signature: bytes) -> bool:
    """Never raises; False on any verification failure."""
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


def canonical_hash(carrier: bytes, num_lsb: int) -> bytes:
    """SHA-256 over carrier with every byte's low num_lsb bits masked to 0 (docs/format.md §8)."""
    mask = (0xFF << num_lsb) & 0xFF
    return hashlib.sha256(bytes(b & mask for b in carrier)).digest()
