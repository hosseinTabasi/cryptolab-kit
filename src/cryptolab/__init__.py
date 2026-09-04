"""cryptolab-kit: educational and practical cryptography toolkit.

Educational modules (``classic``, ``number_theory``, ``rsa_edu``) implement
textbook algorithms that are **not** production-safe. Practical modules
(``modern``, ``hybrid``) wrap well-reviewed constructions from the
``cryptography`` and ``argon2-cffi`` packages.

See ``docs/SECURITY.md`` before using any API.
"""

from __future__ import annotations

__version__ = "0.1.0"
__author__ = "Hossein Tabasi"

from cryptolab.hybrid import hybrid_decrypt_file, hybrid_encrypt_file
from cryptolab.modern.aes_gcm import decrypt_bytes, encrypt_bytes
from cryptolab.modern.passwords import hash_password, verify_password

__all__ = [
    "__author__",
    "__version__",
    "decrypt_bytes",
    "encrypt_bytes",
    "hash_password",
    "hybrid_decrypt_file",
    "hybrid_encrypt_file",
    "verify_password",
]
