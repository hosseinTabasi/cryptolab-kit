"""Hybrid envelope encryption: AES-256-GCM + RSA-OAEP key wrap.

A random 256-bit file key encrypts the payload with AES-GCM. That file
key is wrapped with the recipient's RSA public key (OAEP-SHA256) and
stored next to the ciphertext in a single ``.enc`` package.

**This is the production-oriented envelope.** It is not the textbook RSA
module. Minimum RSA size is 2048 bits.

Package layout (all multi-byte integers big-endian)::

    magic          4 bytes   b"CLB1"
    wrap_len       4 bytes   length of wrapped AES key
    wrapped_key    wrap_len  RSA-OAEP ciphertext
    nonce+ct+tag   rest      AES-256-GCM blob (12-byte nonce prefix)

Associated data for GCM is the constant ``b"cryptolab-kit/hybrid/v1"``
so a package cannot be reinterpreted as a raw AES-GCM file.
"""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from cryptolab.modern.aes_gcm import AES_KEY_SIZE, decrypt_bytes, encrypt_bytes, generate_aes_key
from cryptolab.modern.rsa import rsa_oaep_decrypt, rsa_oaep_encrypt
from cryptolab.utils import as_path, read_bytes, write_bytes

MAGIC = b"CLB1"
AAD = b"cryptolab-kit/hybrid/v1"
HEADER_LEN = 8  # magic + wrap_len


def pack_envelope(wrapped_key: bytes, aes_blob: bytes) -> bytes:
    """Serialize a hybrid package from an OAEP-wrapped key and AES blob."""
    if len(wrapped_key) > 0xFFFFFFFF:
        raise ValueError("wrapped key is too large")
    return MAGIC + len(wrapped_key).to_bytes(4, "big") + wrapped_key + aes_blob


def unpack_envelope(package: bytes) -> tuple[bytes, bytes]:
    """Split a hybrid package into ``(wrapped_key, aes_blob)``.

    Raises
    ------
    ValueError
        If the magic, lengths, or truncation checks fail.
    """
    if len(package) < HEADER_LEN:
        raise ValueError("hybrid package is truncated")
    if package[:4] != MAGIC:
        raise ValueError(
            f"unknown package magic {package[:4]!r}; expected {MAGIC!r}"
        )
    wrap_len = int.from_bytes(package[4:8], "big")
    body = package[8:]
    if wrap_len < 1 or wrap_len > len(body):
        raise ValueError("hybrid package has an invalid wrapped-key length")
    wrapped_key = body[:wrap_len]
    aes_blob = body[wrap_len:]
    if not aes_blob:
        raise ValueError("hybrid package is missing the AES-GCM payload")
    return wrapped_key, aes_blob


def hybrid_encrypt(
    plaintext: bytes,
    public_key: RSAPublicKey,
) -> bytes:
    """Encrypt ``plaintext`` under a fresh AES key wrapped with ``public_key``."""
    file_key = generate_aes_key()
    aes_blob = encrypt_bytes(plaintext, file_key, associated_data=AAD)
    wrapped = rsa_oaep_encrypt(file_key, public_key)
    return pack_envelope(wrapped, aes_blob)


def hybrid_decrypt(
    package: bytes,
    private_key: RSAPrivateKey,
) -> bytes:
    """Decrypt a hybrid package with the recipient RSA private key."""
    wrapped, aes_blob = unpack_envelope(package)
    file_key = rsa_oaep_decrypt(wrapped, private_key)
    if len(file_key) != AES_KEY_SIZE:
        raise ValueError("unwrapped file key is not 32 bytes")
    return decrypt_bytes(aes_blob, file_key, associated_data=AAD)


def hybrid_encrypt_file(
    src: str | os.PathLike[str],
    dest: str | os.PathLike[str],
    public_key: RSAPublicKey,
) -> Path:
    """Encrypt a file into a ``.enc`` hybrid package."""
    plaintext = read_bytes(src)
    package = hybrid_encrypt(plaintext, public_key)
    return write_bytes(dest, package)


def hybrid_decrypt_file(
    src: str | os.PathLike[str],
    dest: str | os.PathLike[str],
    private_key: RSAPrivateKey,
) -> Path:
    """Decrypt a hybrid package to a plaintext file."""
    package = read_bytes(src)
    plaintext = hybrid_decrypt(package, private_key)
    return write_bytes(dest, plaintext)


def default_enc_path(src: str | os.PathLike[str]) -> Path:
    """Return ``src`` with a ``.enc`` suffix."""
    path = as_path(src)
    return path.with_suffix(path.suffix + ".enc") if path.suffix != ".enc" else path
