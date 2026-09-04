"""AES-256-GCM authenticated encryption via the ``cryptography`` package.

Nonce is 96 bits (NIST SP 800-38D recommended size) and is prepended to
the ciphertext. The GCM authentication tag is the trailing 16 bytes of
the ciphertext produced by ``AESGCM``.

File format: ``nonce (12 bytes) || ciphertext || tag (16 bytes)``.
"""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cryptolab.utils import as_path, read_bytes, write_bytes

AES_KEY_SIZE = 32  # AES-256
GCM_NONCE_SIZE = 12
GCM_TAG_SIZE = 16


def generate_aes_key() -> bytes:
    """Return a fresh 32-byte AES-256 key from the OS CSPRNG."""
    return os.urandom(AES_KEY_SIZE)


def _require_key(key: bytes) -> None:
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"AES-256-GCM key must be {AES_KEY_SIZE} bytes, got {len(key)}")


def encrypt_bytes(
    plaintext: bytes,
    key: bytes,
    *,
    associated_data: bytes | None = None,
    nonce: bytes | None = None,
) -> bytes:
    """Encrypt ``plaintext`` with AES-256-GCM.

    Returns ``nonce || ciphertext || tag``. A random 96-bit nonce is
    generated unless ``nonce`` is supplied (tests only).

    Raises
    ------
    ValueError
        If the key is not 32 bytes or a caller-supplied nonce is not
        12 bytes.
    """
    _require_key(key)
    if nonce is None:
        nonce = os.urandom(GCM_NONCE_SIZE)
    elif len(nonce) != GCM_NONCE_SIZE:
        raise ValueError(f"GCM nonce must be {GCM_NONCE_SIZE} bytes")
    ct = AESGCM(key).encrypt(nonce, plaintext, associated_data)
    return nonce + ct


def decrypt_bytes(
    blob: bytes,
    key: bytes,
    *,
    associated_data: bytes | None = None,
) -> bytes:
    """Decrypt a blob produced by :func:`encrypt_bytes`.

    Raises
    ------
    ValueError
        If the blob is truncated or the key length is wrong.
    cryptography.exceptions.InvalidTag
        If authentication fails (wrong key, nonce, AAD, or ciphertext).
    """
    _require_key(key)
    min_len = GCM_NONCE_SIZE + GCM_TAG_SIZE
    if len(blob) < min_len:
        raise ValueError(
            f"ciphertext too short: need at least {min_len} bytes, got {len(blob)}"
        )
    nonce, ct = blob[:GCM_NONCE_SIZE], blob[GCM_NONCE_SIZE:]
    return AESGCM(key).decrypt(nonce, ct, associated_data)


def encrypt_string(
    plaintext: str,
    key: bytes,
    *,
    associated_data: bytes | None = None,
) -> bytes:
    """UTF-8 encode ``plaintext`` and encrypt with AES-256-GCM."""
    return encrypt_bytes(plaintext.encode("utf-8"), key, associated_data=associated_data)


def decrypt_string(
    blob: bytes,
    key: bytes,
    *,
    associated_data: bytes | None = None,
) -> str:
    """Decrypt a blob and UTF-8 decode the plaintext."""
    return decrypt_bytes(blob, key, associated_data=associated_data).decode("utf-8")


def encrypt_file(
    src: str | os.PathLike[str],
    dest: str | os.PathLike[str],
    key: bytes,
    *,
    associated_data: bytes | None = None,
) -> Path:
    """Encrypt a file with AES-256-GCM and write ``nonce||ct||tag`` to ``dest``."""
    plaintext = read_bytes(src)
    blob = encrypt_bytes(plaintext, key, associated_data=associated_data)
    return write_bytes(dest, blob)


def decrypt_file(
    src: str | os.PathLike[str],
    dest: str | os.PathLike[str],
    key: bytes,
    *,
    associated_data: bytes | None = None,
) -> Path:
    """Decrypt an AES-256-GCM file blob and write the plaintext to ``dest``."""
    blob = read_bytes(src)
    plaintext = decrypt_bytes(blob, key, associated_data=associated_data)
    return write_bytes(dest, plaintext)


# Re-export Path for type checkers that follow encrypt_file's return.
__all__ = [
    "AES_KEY_SIZE",
    "GCM_NONCE_SIZE",
    "GCM_TAG_SIZE",
    "decrypt_bytes",
    "decrypt_file",
    "decrypt_string",
    "encrypt_bytes",
    "encrypt_file",
    "encrypt_string",
    "generate_aes_key",
]
