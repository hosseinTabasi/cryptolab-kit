"""Textbook RSA and tiny Diffie–Hellman.

**EDUCATIONAL — NOT PRODUCTION-SAFE.**

Textbook RSA has no padding, uses tiny primes, and is broken by
factoring, chosen-ciphertext attacks, and lattice attacks on small ``e``.
The Diffie–Hellman demo uses a 5-bit safe prime. Use
``cryptolab.modern`` for real keys.
"""

from cryptolab.rsa_edu.diffie_hellman import (
    DH_GENERATOR,
    DH_SAFE_PRIME,
    dh_generate_keypair,
    dh_shared_secret,
)
from cryptolab.rsa_edu.textbook_rsa import (
    TextbookRSAPrivateKey,
    TextbookRSAPublicKey,
    rsa_decrypt,
    rsa_encrypt,
    rsa_keygen,
    rsa_sign,
    rsa_verify,
)

__all__ = [
    "DH_GENERATOR",
    "DH_SAFE_PRIME",
    "TextbookRSAPrivateKey",
    "TextbookRSAPublicKey",
    "dh_generate_keypair",
    "dh_shared_secret",
    "rsa_decrypt",
    "rsa_encrypt",
    "rsa_keygen",
    "rsa_sign",
    "rsa_verify",
]
