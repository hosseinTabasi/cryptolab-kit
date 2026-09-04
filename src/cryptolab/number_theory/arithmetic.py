"""Elementary number theory: gcd, extended gcd, modular inverse, modexp.

**EDUCATIONAL.** Implementations follow the usual textbook Euclidean
algorithm. They leak timing and memory access patterns and are not
suitable for secret-dependent production use.

References: Menezes, van Oorschot, Vanstone, *Handbook of Applied
Cryptography* (HAC), ch. 2; Stallings, *Cryptography and Network
Security*.
"""

from __future__ import annotations


def gcd(a: int, b: int) -> int:
    """Greatest common divisor of ``a`` and ``b`` (Euclidean algorithm).

    Returns a non-negative integer. ``gcd(0, 0)`` is defined as ``0``.
    """
    a, b = abs(a), abs(b)
    while b:
        a, b = b, a % b
    return a


def egcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclidean algorithm.

    Returns ``(g, x, y)`` such that ``a * x + b * y == g`` and
    ``g == gcd(a, b)``. Coefficients satisfy Bézout's identity.

    **EDUCATIONAL.** Not constant-time.
    """
    sign_a = 1 if a >= 0 else -1
    sign_b = 1 if b >= 0 else -1
    old_r, r = abs(a), abs(b)
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s * sign_a, old_t * sign_b


def modinv(a: int, m: int) -> int:
    """Modular multiplicative inverse of ``a`` modulo ``m``.

    Returns ``x`` in ``[0, m)`` with ``(a * x) % m == 1``.

    Raises
    ------
    ValueError
        If ``m <= 1`` or ``a`` is not invertible modulo ``m``.

    **EDUCATIONAL.** Uses :func:`egcd`; not constant-time.
    """
    if m <= 1:
        raise ValueError("modulus must be greater than 1")
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError(f"{a} is not invertible modulo {m} (gcd={g})")
    return x % m


def modexp(base: int, exponent: int, modulus: int) -> int:
    """Return ``pow(base, exponent, modulus)`` (binary modular exponentiation).

    Negative exponents are resolved via :func:`modinv` when the base is
    invertible.

    Raises
    ------
    ValueError
        If ``modulus <= 0``, or if the exponent is negative and the base
        is not invertible.

    **EDUCATIONAL.** Python's built-in ``pow`` is used; this wrapper
    exists so lab code can call a named primitive. Still not a
    constant-time production exponentiation routine.
    """
    if modulus <= 0:
        raise ValueError("modulus must be positive")
    if exponent < 0:
        inv = modinv(base, modulus)
        return pow(inv, -exponent, modulus)
    return pow(base, exponent, modulus)
