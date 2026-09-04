"""Ed25519 signatures via the ``cryptography`` package (RFC 8032)."""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from cryptolab.utils import read_bytes, write_bytes


def generate_ed25519_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate an Ed25519 key pair."""
    private = Ed25519PrivateKey.generate()
    return private, private.public_key()


def save_ed25519_private(
    key: Ed25519PrivateKey,
    path: str | os.PathLike[str],
    *,
    password: bytes | None = None,
) -> Path:
    """Write a PEM-encoded PKCS#8 Ed25519 private key."""
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


def save_ed25519_public(key: Ed25519PublicKey, path: str | os.PathLike[str]) -> Path:
    """Write a PEM-encoded Ed25519 public key."""
    pem = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return write_bytes(path, pem)


def load_ed25519_private(
    path: str | os.PathLike[str],
    *,
    password: bytes | None = None,
) -> Ed25519PrivateKey:
    """Load a PEM Ed25519 private key."""
    key = serialization.load_pem_private_key(read_bytes(path), password=password)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError(f"{path} is not an Ed25519 private key")
    return key


def load_ed25519_public(path: str | os.PathLike[str]) -> Ed25519PublicKey:
    """Load a PEM Ed25519 public key."""
    key = serialization.load_pem_public_key(read_bytes(path))
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError(f"{path} is not an Ed25519 public key")
    return key


def sign_ed25519(message: bytes, private_key: Ed25519PrivateKey) -> bytes:
    """Return a 64-byte Ed25519 signature over ``message``."""
    return private_key.sign(message)


def verify_ed25519(
    message: bytes,
    signature: bytes,
    public_key: Ed25519PublicKey,
) -> bool:
    """Return True if ``signature`` is valid for ``message``."""
    try:
        public_key.verify(signature, message)
    except InvalidSignature:
        return False
    return True
