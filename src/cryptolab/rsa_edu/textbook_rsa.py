"""Textbook RSA on small primes.

**EDUCATIONAL — NOT PRODUCTION-SAFE.**

This module implements the raw RSA trapdoor permutation
``c = m^e mod n``, ``m = c^d mod n`` with **no padding** (no OAEP, no
PKCS#1 v1.5). Signatures are ``s = H(m)^d mod n`` where ``H(m)`` is
reduced modulo ``n``. That construction is existentially forgeable and
completely inappropriate for any real authentication.

Insecurity checklist (non-exhaustive):

* Tiny moduli (a few hundred at most, often two-digit primes in tests)
  are factored instantly.
* Unpadded RSA is deterministic and malleable (homomorphic under
  multiplication).
* Small public exponents without padding leak plaintext bits.
* Hash-then-reduce signatures collide once ``n`` is smaller than the
  hash, which it always is here.

For production RSA use :mod:`cryptolab.modern.rsa` (OAEP + PSS, 2048-bit
or larger keys from the ``cryptography`` package).

References: HAC ch. 8; Stallings RSA chapter; Katz & Lindell,
*Introduction to Modern Cryptography* (why padding is required).
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

from cryptolab.number_theory.arithmetic import egcd, gcd, modexp, modinv

# Famous tiny example from many textbooks: p=61, q=53, n=3233, e=17.
DEMO_P = 61
DEMO_Q = 53
DEMO_E = 17


@dataclass(frozen=True)
class TextbookRSAPublicKey:
    """Public key ``(n, e)`` for textbook RSA.

    **EDUCATIONAL — not production-safe.**
    """

    n: int
    e: int


@dataclass(frozen=True)
class TextbookRSAPrivateKey:
    """Private key ``(n, d)`` plus the primes used to build it.

    **EDUCATIONAL — not production-safe.** Primes are stored so labs can
    inspect φ(n); never do this with real keys.
    """

    n: int
    d: int
    p: int
    q: int
    e: int

    @property
    def public_key(self) -> TextbookRSAPublicKey:
        """Corresponding public key."""
        return TextbookRSAPublicKey(n=self.n, e=self.e)


def _is_probable_prime_tiny(n: int) -> bool:
    """Deterministic trial division — only valid for tiny classroom primes."""
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    f = 3
    while f * f <= n:
        if n % f == 0:
            return False
        f += 2
    return True


def rsa_keygen(
    p: int,
    q: int,
    e: int = DEMO_E,
) -> TextbookRSAPrivateKey:
    """Build a textbook RSA key from two **small** primes.

    Parameters
    ----------
    p, q:
        Distinct primes. This function rejects primes larger than 10**6
        so it cannot be mistaken for a real key generator.
    e:
        Public exponent, coprime to φ(n). Default 17 (textbook demo).

    **EDUCATIONAL — not production-safe.**
    """
    limit = 1_000_000
    if p > limit or q > limit:
        raise ValueError(
            "educational RSA refuses primes larger than 10^6; "
            "use cryptolab.modern.rsa for real keys"
        )
    if p == q:
        raise ValueError("p and q must be distinct")
    if not _is_probable_prime_tiny(p) or not _is_probable_prime_tiny(q):
        raise ValueError("p and q must be prime")
    n = p * q
    phi = (p - 1) * (q - 1)
    if e <= 1 or e >= phi:
        raise ValueError("e must satisfy 1 < e < phi(n)")
    if gcd(e, phi) != 1:
        raise ValueError("e must be coprime to phi(n)")
    d = modinv(e, phi)
    return TextbookRSAPrivateKey(n=n, d=d, p=p, q=q, e=e)


def rsa_encrypt(message: int, public_key: TextbookRSAPublicKey) -> int:
    """Textbook encryption: ``c = m^e mod n`` (no padding).

    ``message`` must satisfy ``0 <= message < n``.

    **EDUCATIONAL — not production-safe.** Unpadded RSA is deterministic
    and malleable.
    """
    if message < 0 or message >= public_key.n:
        raise ValueError("message must satisfy 0 <= m < n")
    return modexp(message, public_key.e, public_key.n)


def rsa_decrypt(ciphertext: int, private_key: TextbookRSAPrivateKey) -> int:
    """Textbook decryption: ``m = c^d mod n``.

    **EDUCATIONAL — not production-safe.**
    """
    if ciphertext < 0 or ciphertext >= private_key.n:
        raise ValueError("ciphertext must satisfy 0 <= c < n")
    return modexp(ciphertext, private_key.d, private_key.n)


def _message_representative(message: bytes, n: int) -> int:
    """SHA-256 digest reduced modulo ``n``.

    **INSECURE** once ``n`` is smaller than 2^256, which it always is in
    this module. Used only so sign/verify have a byte-oriented API.
    """
    digest = sha256(message).digest()
    return int.from_bytes(digest, "big") % n


def rsa_sign(message: bytes, private_key: TextbookRSAPrivateKey) -> int:
    """Textbook signature: ``s = H(m)^d mod n`` (no padding).

    **EDUCATIONAL — not production-safe.** Existentially forgeable;
    hash is truncated by a tiny modulus. Use RSA-PSS in
    :mod:`cryptolab.modern.rsa` instead.
    """
    h = _message_representative(message, private_key.n)
    return modexp(h, private_key.d, private_key.n)


def rsa_verify(
    message: bytes,
    signature: int,
    public_key: TextbookRSAPublicKey,
) -> bool:
    """Verify a textbook RSA signature.

    **EDUCATIONAL — not production-safe.**
    """
    if signature < 0 or signature >= public_key.n:
        return False
    h = _message_representative(message, public_key.n)
    recovered = modexp(signature, public_key.e, public_key.n)
    return recovered == h


def bezout_check(a: int, b: int) -> tuple[int, int, int]:
    """Expose :func:`~cryptolab.number_theory.arithmetic.egcd` for labs."""
    return egcd(a, b)
