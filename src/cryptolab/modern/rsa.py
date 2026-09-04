"""RSA-OAEP encryption and RSA-PSS signatures (2048-bit minimum).

Keys and operations come from the ``cryptography`` package. OAEP uses
SHA-256 and MGF1-SHA-256. PSS uses SHA-256 and maximum salt length.

These are the production RSA APIs. Do not confuse them with
:mod:`cryptolab.rsa_edu.textbook_rsa`.
"""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from cryptolab.utils import as_path, read_bytes, write_bytes

MIN_KEY_SIZE = 2048
_OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)
_PSS = padding.PSS(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH,
)


def generate_rsa_keypair(key_size: int = MIN_KEY_SIZE) -> tuple[RSAPrivateKey, RSAPublicKey]:
    """Generate an RSA key pair.

    Raises
    ------
    ValueError
        If ``key_size`` is below 2048.
    """
    if key_size < MIN_KEY_SIZE:
        raise ValueError(f"RSA key_size must be >= {MIN_KEY_SIZE} (got {key_size})")
    private = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return private, private.public_key()


def save_rsa_private(
    key: RSAPrivateKey,
    path: str | os.PathLike[str],
    *,
    password: bytes | None = None,
) -> Path:
    """Write a PEM-encoded PKCS#8 private key.

    If ``password`` is set, the PEM is encrypted with BestAvailableEncryption.
    Lab keys are often stored unencrypted in a gitignored ``keys/`` directory;
    see ``docs/SECURITY.md``.
    """
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


def save_rsa_public(key: RSAPublicKey, path: str | os.PathLike[str]) -> Path:
    """Write a PEM-encoded SubjectPublicKeyInfo public key."""
    pem = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return write_bytes(path, pem)


def load_rsa_private(
    path: str | os.PathLike[str],
    *,
    password: bytes | None = None,
) -> RSAPrivateKey:
    """Load a PEM RSA private key."""
    key = serialization.load_pem_private_key(read_bytes(path), password=password)
    if not isinstance(key, RSAPrivateKey):
        raise TypeError(f"{path} is not an RSA private key")
    if key.key_size < MIN_KEY_SIZE:
        raise ValueError(f"RSA key in {path} is {key.key_size} bits; minimum is {MIN_KEY_SIZE}")
    return key


def load_rsa_public(path: str | os.PathLike[str]) -> RSAPublicKey:
    """Load a PEM RSA public key (SPKI or PKCS#1)."""
    data = read_bytes(path)
    try:
        key = serialization.load_pem_public_key(data)
    except ValueError:
        loaded = serialization.load_pem_private_key(data, password=None)
        if not isinstance(loaded, RSAPrivateKey):
            raise TypeError(f"{path} is not an RSA key") from None
        key = loaded.public_key()
    if not isinstance(key, RSAPublicKey):
        raise TypeError(f"{path} is not an RSA public key")
    if key.key_size < MIN_KEY_SIZE:
        raise ValueError(f"RSA key in {path} is {key.key_size} bits; minimum is {MIN_KEY_SIZE}")
    return key


def rsa_oaep_encrypt(plaintext: bytes, public_key: RSAPublicKey) -> bytes:
    """Encrypt ``plaintext`` with RSA-OAEP (SHA-256).

    Plaintext must fit the OAEP size limit for the key (for 2048-bit RSA
    with SHA-256 that is 190 bytes).
    """
    if public_key.key_size < MIN_KEY_SIZE:
        raise ValueError("RSA public key is below 2048 bits")
    return public_key.encrypt(plaintext, _OAEP)


def rsa_oaep_decrypt(ciphertext: bytes, private_key: RSAPrivateKey) -> bytes:
    """Decrypt an RSA-OAEP ciphertext."""
    if private_key.key_size < MIN_KEY_SIZE:
        raise ValueError("RSA private key is below 2048 bits")
    return private_key.decrypt(ciphertext, _OAEP)


def rsa_pss_sign(message: bytes, private_key: RSAPrivateKey) -> bytes:
    """Sign ``message`` with RSA-PSS (SHA-256, max salt)."""
    if private_key.key_size < MIN_KEY_SIZE:
        raise ValueError("RSA private key is below 2048 bits")
    return private_key.sign(message, _PSS, hashes.SHA256())


def rsa_pss_verify(message: bytes, signature: bytes, public_key: RSAPublicKey) -> bool:
    """Return True if ``signature`` is a valid RSA-PSS signature on ``message``."""
    from cryptography.exceptions import InvalidSignature

    if public_key.key_size < MIN_KEY_SIZE:
        raise ValueError("RSA public key is below 2048 bits")
    try:
        public_key.verify(signature, message, _PSS, hashes.SHA256())
    except InvalidSignature:
        return False
    return True


def pem_private_preview(path: str | os.PathLike[str]) -> str:
    """Return the PEM header line only (never the body)."""
    text = as_path(path).read_text(encoding="utf-8")
    first = text.strip().splitlines()[0] if text.strip() else ""
    return first
