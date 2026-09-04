"""Shared helpers: hex I/O, path checks, and key-file loading.

These utilities do not implement cryptographic primitives. Randomness
comes from :func:`os.urandom`.
"""

from __future__ import annotations

import binascii
import os
from pathlib import Path


def as_path(path: str | os.PathLike[str]) -> Path:
    """Return ``path`` as a :class:`~pathlib.Path`."""
    return Path(path)


def read_bytes(path: str | os.PathLike[str]) -> bytes:
    """Read a file as raw bytes."""
    return as_path(path).read_bytes()


def write_bytes(path: str | os.PathLike[str], data: bytes, *, overwrite: bool = True) -> Path:
    """Write ``data`` to ``path``, creating parent directories.

    Parameters
    ----------
    overwrite:
        If false and the destination exists, raise :class:`FileExistsError`.
    """
    dest = as_path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and not overwrite:
        raise FileExistsError(f"refusing to overwrite existing file: {dest}")
    dest.write_bytes(data)
    return dest


def write_text(path: str | os.PathLike[str], text: str, *, overwrite: bool = True) -> Path:
    """Write UTF-8 text to ``path``, creating parent directories."""
    dest = as_path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and not overwrite:
        raise FileExistsError(f"refusing to overwrite existing file: {dest}")
    dest.write_text(text, encoding="utf-8")
    return dest


def to_hex(data: bytes) -> str:
    """Lowercase hex encoding of ``data``."""
    return data.hex()


def from_hex(text: str) -> bytes:
    """Decode a hex string, ignoring whitespace.

    Raises
    ------
    ValueError
        If the string is not valid hex.
    """
    cleaned = "".join(text.split())
    try:
        return binascii.unhexlify(cleaned)
    except binascii.Error as exc:
        raise ValueError(f"invalid hex: {exc}") from exc


def load_key_bytes(path: str | os.PathLike[str], *, expected_len: int | None = None) -> bytes:
    """Load a key from a file as raw bytes or hex text.

    If the file contains only hex digits (and whitespace) of even length,
    it is decoded as hex. Otherwise the raw file bytes are used. When
    ``expected_len`` is set, a :class:`ValueError` is raised on mismatch.
    """
    raw = read_bytes(path)
    stripped = raw.strip()
    key: bytes
    try:
        as_text = stripped.decode("ascii")
    except UnicodeDecodeError:
        key = raw
    else:
        if as_text and all(c in "0123456789abcdefABCDEF \t\r\n" for c in as_text):
            if len("".join(as_text.split())) % 2 == 0:
                key = from_hex(as_text)
            else:
                key = raw
        else:
            key = raw
    if expected_len is not None and len(key) != expected_len:
        raise ValueError(
            f"key in {path} is {len(key)} bytes; expected {expected_len}"
        )
    return key


def random_bytes(n: int) -> bytes:
    """Return ``n`` bytes from the operating-system CSPRNG."""
    if n < 1:
        raise ValueError("n must be positive")
    return os.urandom(n)


def ensure_dir(path: str | os.PathLike[str]) -> Path:
    """Create ``path`` (and parents) if needed and return it."""
    dest = as_path(path)
    dest.mkdir(parents=True, exist_ok=True)
    return dest
