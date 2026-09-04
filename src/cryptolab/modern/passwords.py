"""Argon2id password hashing via ``argon2-cffi``.

Argon2id is the hybrid variant recommended by RFC 9106. Parameters here
are conservative for a local toolkit (not a high-traffic service).
Tune ``time_cost`` / ``memory_cost`` for your threat model.
"""

from __future__ import annotations

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from argon2.low_level import hash_secret_raw

# Local-lab defaults: ~64 MiB, 3 iterations, single lane.
_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=1,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)


def hash_password(password: str) -> str:
    """Return a PHC-encoded Argon2id hash (random salt).

    The returned string is safe to store. It includes algorithm,
    parameters, salt, and digest.
    """
    if not password:
        raise ValueError("password must be non-empty")
    return _HASHER.hash(password)


def verify_password(password: str, encoded: str) -> bool:
    """Return True if ``password`` matches the PHC-encoded Argon2id hash."""
    try:
        return _HASHER.verify(encoded, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def argon2id_kdf(
    password: bytes,
    salt: bytes,
    *,
    length: int = 32,
    time_cost: int = 3,
    memory_cost: int = 65536,
    parallelism: int = 1,
) -> bytes:
    """Derive ``length`` bytes with Argon2id (raw, deterministic given salt).

    ``salt`` must be at least 8 bytes (RFC 9106 recommends 16).
    """
    if len(salt) < 8:
        raise ValueError("salt must be at least 8 bytes")
    if length < 1:
        raise ValueError("length must be positive")
    if not password:
        raise ValueError("password must be non-empty")
    return hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=length,
        type=Type.ID,
    )
