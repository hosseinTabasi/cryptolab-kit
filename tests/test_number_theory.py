"""Deterministic tests for educational number theory."""

from __future__ import annotations

import pytest

from cryptolab.number_theory import egcd, gcd, modexp, modinv
from cryptolab.rsa_edu.diffie_hellman import (
    DH_GENERATOR,
    DH_SAFE_PRIME,
    dh_generate_keypair,
    dh_shared_secret,
)
from cryptolab.rsa_edu.textbook_rsa import (
    DEMO_E,
    DEMO_P,
    DEMO_Q,
    rsa_decrypt,
    rsa_encrypt,
    rsa_keygen,
    rsa_sign,
    rsa_verify,
)


def test_gcd_known_values() -> None:
    assert gcd(48, 18) == 6
    assert gcd(18, 48) == 6
    assert gcd(0, 5) == 5
    assert gcd(5, 0) == 5
    assert gcd(0, 0) == 0
    assert gcd(-48, 18) == 6
    assert gcd(17, 13) == 1


def test_egcd_bezout() -> None:
    g, x, y = egcd(48, 18)
    assert g == 6
    assert 48 * x + 18 * y == g
    g2, x2, y2 = egcd(17, 13)
    assert g2 == 1
    assert 17 * x2 + 13 * y2 == 1
    g3, x3, y3 = egcd(-35, 15)
    assert g3 == 5
    assert -35 * x3 + 15 * y3 == 5


def test_modinv_known() -> None:
    assert modinv(3, 11) == 4  # 3*4 = 12 ≡ 1 (mod 11)
    assert (17 * modinv(17, 3120)) % 3120 == 1
    with pytest.raises(ValueError):
        modinv(2, 4)
    with pytest.raises(ValueError):
        modinv(1, 1)


def test_modexp_known() -> None:
    assert modexp(2, 10, 17) == 1024 % 17
    assert modexp(5, 6, 23) == pow(5, 6, 23)
    # 3^{-1} ≡ 4 (mod 11), so 3^{-2} ≡ 16 ≡ 5 (mod 11)
    assert modexp(3, -1, 11) == 4
    assert modexp(3, -2, 11) == 5


def test_textbook_rsa_fixed_primes() -> None:
    # p=61, q=53, n=3233, e=17, φ=3120, d=2753 (classic textbook example)
    key = rsa_keygen(DEMO_P, DEMO_Q, DEMO_E)
    assert key.n == 3233
    assert key.e == 17
    assert key.d == 2753
    pub = key.public_key
    # m=65 is the well-known "A" example (65^17 mod 3233 = 2790)
    ct = rsa_encrypt(65, pub)
    assert ct == 2790
    assert rsa_decrypt(ct, key) == 65
    for m in (0, 1, 42, 1000, 3232):
        assert rsa_decrypt(rsa_encrypt(m, pub), key) == m


def test_textbook_rsa_sign_verify() -> None:
    key = rsa_keygen(DEMO_P, DEMO_Q, DEMO_E)
    msg = b"educational signature"
    sig = rsa_sign(msg, key)
    assert rsa_verify(msg, sig, key.public_key)
    assert not rsa_verify(b"tampered", sig, key.public_key)
    assert not rsa_verify(msg, (sig + 1) % key.n, key.public_key)


def test_textbook_rsa_rejects_large_primes() -> None:
    with pytest.raises(ValueError, match="10\\^6"):
        rsa_keygen(1_000_003, 1_000_033, 17)


def test_dh_fixed_secrets() -> None:
    # Stallings-style toy: p=23, g=5, a=6, b=15
    # A = 5^6 mod 23 = 8; B = 5^15 mod 23 = 19; s = 2
    a_priv, a_pub = dh_generate_keypair(private_key=6)
    b_priv, b_pub = dh_generate_keypair(private_key=15)
    assert DH_SAFE_PRIME == 23
    assert DH_GENERATOR == 5
    assert a_pub == 8
    assert b_pub == 19
    assert dh_shared_secret(a_priv, b_pub) == 2
    assert dh_shared_secret(b_priv, a_pub) == 2
