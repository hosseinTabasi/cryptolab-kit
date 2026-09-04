"""Simplified Feistel network on 64-bit blocks.

**EDUCATIONAL.** A real Feistel cipher (DES, FEAL, Blowfish) uses a
carefully designed round function, many rounds, and a key schedule
with proven mixing properties. This toy uses four rounds and a
non-cryptographic mixer. It exists so students can step through
L/R splits, round keys, and invertibility. **Never use it to hide
real data.**

Reference: Stallings, Feistel cipher structure; HAC ch. 7.
"""

from __future__ import annotations

ROUNDS = 4
BLOCK_SIZE = 8  # bytes (64-bit blocks)


def _f(right: int, round_key: int) -> int:
    """Toy round function (not a PRF, not production-safe)."""
    x = (right ^ round_key) & 0xFFFFFFFF
    x = (x * 0x45D9F3B) & 0xFFFFFFFF
    x = (x ^ (x >> 16)) & 0xFFFFFFFF
    return x


def _round_keys(key: int, rounds: int) -> list[int]:
    """Expand a 64-bit integer key into ``rounds`` 32-bit round keys.

    **EDUCATIONAL.** This is not a real key schedule.
    """
    keys: list[int] = []
    state = key & 0xFFFFFFFFFFFFFFFF
    for i in range(rounds):
        state = (state * 0x5DEECE66D + 11 + i) & 0xFFFFFFFFFFFFFFFF
        keys.append(state & 0xFFFFFFFF)
    return keys


def _pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def _pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("invalid padded data length")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("invalid PKCS#7 padding")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("invalid PKCS#7 padding")
    return data[:-pad_len]


def _enc_block(block: bytes, keys: list[int]) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError("block must be 8 bytes")
    left = int.from_bytes(block[:4], "big")
    right = int.from_bytes(block[4:], "big")
    for k in keys:
        left, right = right, left ^ _f(right, k)
    return left.to_bytes(4, "big") + right.to_bytes(4, "big")


def _dec_block(block: bytes, keys: list[int]) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError("block must be 8 bytes")
    left = int.from_bytes(block[:4], "big")
    right = int.from_bytes(block[4:], "big")
    for k in reversed(keys):
        left, right = right ^ _f(left, k), left
    return left.to_bytes(4, "big") + right.to_bytes(4, "big")


def feistel_encrypt(plaintext: bytes, key: int, *, rounds: int = ROUNDS) -> bytes:
    """Encrypt ``plaintext`` with the toy Feistel cipher.

    PKCS#7 padding is applied to 8-byte blocks. ``key`` is a non-negative
    integer (only the low 64 bits are used). ``rounds`` defaults to 4.

    **EDUCATIONAL — not production-safe.**
    """
    if rounds < 1:
        raise ValueError("rounds must be at least 1")
    if key < 0:
        raise ValueError("key must be non-negative")
    keys = _round_keys(key, rounds)
    padded = _pkcs7_pad(plaintext)
    out = bytearray()
    for i in range(0, len(padded), BLOCK_SIZE):
        out.extend(_enc_block(padded[i : i + BLOCK_SIZE], keys))
    return bytes(out)


def feistel_decrypt(ciphertext: bytes, key: int, *, rounds: int = ROUNDS) -> bytes:
    """Decrypt toy Feistel ciphertext produced by :func:`feistel_encrypt`.

    **EDUCATIONAL — not production-safe.**
    """
    if rounds < 1:
        raise ValueError("rounds must be at least 1")
    if key < 0:
        raise ValueError("key must be non-negative")
    if len(ciphertext) == 0 or len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("ciphertext length must be a positive multiple of 8")
    keys = _round_keys(key, rounds)
    out = bytearray()
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        out.extend(_dec_block(ciphertext[i : i + BLOCK_SIZE], keys))
    return _pkcs7_unpad(bytes(out))
