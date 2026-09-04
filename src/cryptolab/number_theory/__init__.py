"""Integer arithmetic used by textbook ciphers.

**EDUCATIONAL.** These routines are for learning modular arithmetic.
They are not constant-time and must not be used to implement production
public-key cryptography.
"""

from cryptolab.number_theory.arithmetic import egcd, gcd, modexp, modinv

__all__ = ["egcd", "gcd", "modexp", "modinv"]
