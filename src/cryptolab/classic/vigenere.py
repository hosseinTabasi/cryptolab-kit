"""Vigenère polyalphabetic substitution.

**EDUCATIONAL.** Repeating-key Caesar. Broken by Kasiski examination and
Friedman index-of-coincidence methods once the key length leaks. Never
use for real secrets.

Reference: Stallings, *Cryptography and Network Security*; HAC ch. 7
(classical ciphers).
"""

from __future__ import annotations


def _key_shifts(key: str) -> list[int]:
    shifts: list[int] = []
    for ch in key:
        if "A" <= ch <= "Z":
            shifts.append(ord(ch) - 65)
        elif "a" <= ch <= "z":
            shifts.append(ord(ch) - 97)
    if not shifts:
        raise ValueError("Vigenère key must contain at least one letter")
    return shifts


def _apply(text: str, key: str, direction: int) -> str:
    shifts = _key_shifts(key)
    out: list[str] = []
    i = 0
    for ch in text:
        if "A" <= ch <= "Z":
            s = (ord(ch) - 65 + direction * shifts[i % len(shifts)]) % 26
            out.append(chr(s + 65))
            i += 1
        elif "a" <= ch <= "z":
            s = (ord(ch) - 97 + direction * shifts[i % len(shifts)]) % 26
            out.append(chr(s + 97))
            i += 1
        else:
            out.append(ch)
    return "".join(out)


def vigenere_encrypt(plaintext: str, key: str) -> str:
    """Encrypt ``plaintext`` with a repeating alphabetic ``key``.

    Non-letters are copied unchanged and do not consume key letters.

    **EDUCATIONAL — not production-safe.**
    """
    return _apply(plaintext, key, +1)


def vigenere_decrypt(ciphertext: str, key: str) -> str:
    """Decrypt Vigenère ciphertext with ``key``.

    **EDUCATIONAL — not production-safe.**
    """
    return _apply(ciphertext, key, -1)
