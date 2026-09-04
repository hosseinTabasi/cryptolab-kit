"""Diffie–Hellman over a tiny documented safe prime.

**EDUCATIONAL — NOT PRODUCTION-SAFE.**

This demo uses the 5-bit safe prime ``p = 23`` with generator ``g = 5``.
``(p - 1) / 2 = 11`` is also prime, so 23 is a safe prime and 5 is a
primitive root modulo 23 (order 22). The construction matches the
textbook presentation of ephemeral DH, but a 5-bit modulus is
brute-forced by enumerating 22 group elements.

Never use these parameters (or any homemade group) for real key
agreement. Production ECDH is :mod:`cryptolab.modern.ecdh` (X25519,
RFC 7748) via the ``cryptography`` package.

References: Stallings (Diffie–Hellman); HAC ch. 12; Katz & Lindell
(CDH / DDH). The 23/5 toy parameters appear widely in classroom notes.
"""

from __future__ import annotations

import secrets

from cryptolab.number_theory.arithmetic import modexp

# Safe prime: p = 2q + 1 with q = 11 prime. Generator g = 5 is a
# primitive root modulo 23 (order p-1 = 22).
DH_SAFE_PRIME = 23
DH_GENERATOR = 5
DH_Q = (DH_SAFE_PRIME - 1) // 2  # 11, Sophie Germain prime


def dh_generate_keypair(
    *,
    private_key: int | None = None,
) -> tuple[int, int]:
    """Return ``(private, public)`` with ``public = g^private mod p``.

    If ``private_key`` is omitted, a uniform secret in ``[1, p-2]`` is
    drawn from :func:`secrets.randbelow`. Tests pass an explicit secret
    for determinism.

    **EDUCATIONAL — not production-safe.**
    """
    p = DH_SAFE_PRIME
    g = DH_GENERATOR
    if private_key is None:
        secret = secrets.randbelow(p - 2) + 1
    else:
        if not (1 <= private_key <= p - 2):
            raise ValueError(f"private_key must be in [1, {p - 2}]")
        secret = private_key
    public = modexp(g, secret, p)
    return secret, public


def dh_shared_secret(private_key: int, peer_public: int) -> int:
    """Compute ``peer_public^private_key mod p``.

    **EDUCATIONAL — not production-safe.** Does not authenticate the
    peer (classic DH is unauthenticated and MITM-able).
    """
    p = DH_SAFE_PRIME
    if not (1 <= private_key <= p - 2):
        raise ValueError(f"private_key must be in [1, {p - 2}]")
    if not (1 <= peer_public <= p - 1):
        raise ValueError(f"peer_public must be in [1, {p - 1}]")
    if peer_public % p == 0:
        raise ValueError("peer_public is 0 modulo p")
    return modexp(peer_public, private_key, p)
