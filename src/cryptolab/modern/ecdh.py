"""X25519 Diffie–Hellman via the ``cryptography`` package (RFC 7748)."""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from cryptolab.utils import read_bytes, write_bytes


def generate_x25519_keypair() -> tuple[X25519PrivateKey, X25519PublicKey]:
    """Generate an X25519 key pair."""
    private = X25519PrivateKey.generate()
    return private, private.public_key()


def save_x25519_private(
    key: X25519PrivateKey,
    path: str | os.PathLike[str],
    *,
    password: bytes | None = None,
) -> Path:
    """Write a PEM-encoded PKCS#8 X25519 private key."""
    if password is None:
        encryption: serialization.KeySerializationEncryption = serialization.NoEncryption()
    else:
        encryption = serialization.BestAvailableEncryption(password)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    return write_bytes(path, pem)


def save_x25519_public(key: X25519PublicKey, path: str | os.PathLike[str]) -> Path:
    """Write a PEM-encoded X25519 public key."""
    pem = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return write_bytes(path, pem)


def load_x25519_private(
    path: str | os.PathLike[str],
    *,
    password: bytes | None = None,
) -> X25519PrivateKey:
    """Load a PEM X25519 private key."""
    key = serialization.load_pem_private_key(read_bytes(path), password=password)
    if not isinstance(key, X25519PrivateKey):
        raise TypeError(f"{path} is not an X25519 private key")
    return key


def load_x25519_public(path: str | os.PathLike[str]) -> X25519PublicKey:
    """Load a PEM X25519 public key."""
    key = serialization.load_pem_public_key(read_bytes(path))
    if not isinstance(key, X25519PublicKey):
        raise TypeError(f"{path} is not an X25519 public key")
    return key


def x25519_exchange(private_key: X25519PrivateKey, peer_public: X25519PublicKey) -> bytes:
    """Return the 32-byte X25519 shared secret.

    The raw DH output should be passed through HKDF (see
    :func:`cryptolab.modern.kdf.hkdf_sha256`) before use as a key.
    """
    return private_key.exchange(peer_public)
