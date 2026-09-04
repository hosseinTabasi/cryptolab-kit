"""HMAC-SHA256 and HKDF-SHA256 via the ``cryptography`` package.

HMAC: FIPS 198-1 / RFC 2104. HKDF: RFC 5869. SHA-256: FIPS 180-4.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """Return the 32-byte HMAC-SHA256 of ``data`` under ``key``."""
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


def hkdf_sha256(
    ikm: bytes,
    *,
    length: int = 32,
    salt: bytes | None = None,
    info: bytes = b"",
) -> bytes:
    """HKDF-SHA256 extract-and-expand.

    Parameters
    ----------
    ikm:
        Input keying material (for example an X25519 shared secret).
    length:
        Output length in bytes (must be positive and at most 255 * 32).
    salt:
        Optional salt; if omitted, RFC 5869 uses a string of zeros.
    info:
        Optional context/application string.
    """
    if length < 1:
        raise ValueError("length must be positive")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(ikm)
