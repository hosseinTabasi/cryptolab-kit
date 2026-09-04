"""Deterministic tests for classical ciphers and the canned attack demo."""

from __future__ import annotations

import pytest

from cryptolab.classic.caesar import caesar_decrypt, caesar_encrypt
from cryptolab.classic.feistel import feistel_decrypt, feistel_encrypt
from cryptolab.classic.frequency import (
    CANNED_CIPHERTEXT,
    CANNED_SHIFT,
    attack_caesar,
    score_english,
)
from cryptolab.classic.vigenere import vigenere_decrypt, vigenere_encrypt


def test_caesar_round_trip() -> None:
    plain = "Hello, World! xyz XYZ 123"
    for shift in range(26):
        ct = caesar_encrypt(plain, shift)
        assert caesar_decrypt(ct, shift) == plain
    assert caesar_encrypt("ABC", 1) == "BCD"
    assert caesar_encrypt("xyz", 3) == "abc"
    assert caesar_encrypt("ABC", 26) == "ABC"
    assert caesar_encrypt("ABC", -1) == "ZAB"


def test_vigenere_known_vector() -> None:
    # Classic "LEMON" / "ATTACKATDAWN" textbook vector (letters only).
    plain = "ATTACKATDAWN"
    key = "LEMON"
    ct = vigenere_encrypt(plain, key)
    assert ct == "LXFOPVEFRNHR"
    assert vigenere_decrypt(ct, key) == plain
    mixed = "Attack at dawn!"
    assert vigenere_decrypt(vigenere_encrypt(mixed, "lemon"), "LEMON") == mixed


def test_vigenere_rejects_empty_key() -> None:
    with pytest.raises(ValueError, match="at least one letter"):
        vigenere_encrypt("hi", "123")


def test_feistel_round_trip() -> None:
    key = 0x0123456789ABCDEF
    for plain in (b"", b"a", b"1234567", b"12345678", b"hello cryptolab-kit"):
        ct = feistel_encrypt(plain, key)
        assert feistel_decrypt(ct, key) == plain
        assert len(ct) % 8 == 0
    # Different keys must not decrypt (padding error or garbage).
    ct = feistel_encrypt(b"secret", 1)
    try:
        pt = feistel_decrypt(ct, 2)
        assert pt != b"secret"
    except ValueError:
        pass


def test_feistel_deterministic() -> None:
    ct1 = feistel_encrypt(b"abc", 99, rounds=4)
    ct2 = feistel_encrypt(b"abc", 99, rounds=4)
    assert ct1 == ct2
    assert feistel_decrypt(ct1, 99, rounds=4) == b"abc"


def test_frequency_recovers_canned_shift() -> None:
    ranked = attack_caesar(CANNED_CIPHERTEXT, top=5)
    best_shift, best_score, best_plain = ranked[0]
    assert best_shift == CANNED_SHIFT
    assert "CRYPTOGRAPHY" in best_plain
    assert "FREQUENCY ANALYSIS" in best_plain
    # The correct English plaintext must score better than a random shift.
    wrong = score_english(caesar_decrypt(CANNED_CIPHERTEXT, (CANNED_SHIFT + 7) % 26))
    assert best_score < wrong


def test_canned_ciphertext_is_fixed() -> None:
    # Guard the demo against accidental plaintext edits.
    assert CANNED_SHIFT == 12
    assert CANNED_CIPHERTEXT.startswith("FTQ MDF")
