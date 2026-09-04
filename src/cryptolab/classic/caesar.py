"""Caesar (shift) cipher.

**EDUCATIONAL.** A monoalphabetic substitution with 26 keys. Trivial to
break by brute force or frequency analysis. Never use for real secrets.

Reference: Stallings, *Cryptography and Network Security*, classical
encryption techniques.
"""

from __future__ import annotations

_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _shift_char(ch: str, shift: int) -> str:
    if "A" <= ch <= "Z":
        return _ALPHABET[(ord(ch) - 65 + shift) % 26]
    if "a" <= ch <= "z":
        return _ALPHABET[(ord(ch) - 97 + shift) % 26].lower()
    return ch


def caesar_encrypt(plaintext: str, shift: int) -> str:
    """Encrypt ``plaintext`` by shifting letters by ``shift`` positions.

    Non-letters are copied unchanged. ``shift`` is taken modulo 26.

    **EDUCATIONAL — not production-safe.**
    """
    shift = shift % 26
    return "".join(_shift_char(ch, shift) for ch in plaintext)


def caesar_decrypt(ciphertext: str, shift: int) -> str:
    """Decrypt Caesar ciphertext with the given ``shift``.

    **EDUCATIONAL — not production-safe.**
    """
    return caesar_encrypt(ciphertext, -shift)
