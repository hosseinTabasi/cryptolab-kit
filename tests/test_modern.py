"""Tests for production wrappers: AES-GCM, RSA, Ed25519, X25519, HMAC, HKDF, Argon2id."""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from cryptolab.modern.aes_gcm import (
    decrypt_bytes,
    decrypt_file,
    decrypt_string,
    encrypt_bytes,
    encrypt_file,
    encrypt_string,
    generate_aes_key,
)
from cryptolab.modern.ecdh import generate_x25519_keypair, x25519_exchange
from cryptolab.modern.kdf import hkdf_sha256, hmac_sha256
from cryptolab.modern.passwords import argon2id_kdf, hash_password, verify_password
from cryptolab.modern.rsa import (
    generate_rsa_keypair,
    rsa_oaep_decrypt,
    rsa_oaep_encrypt,
    rsa_pss_sign,
    rsa_pss_verify,
    save_rsa_private,
    save_rsa_public,
    load_rsa_private,
    load_rsa_public,
)
from cryptolab.modern.signatures import (
    generate_ed25519_keypair,
    sign_ed25519,
    verify_ed25519,
)


def test_aes_gcm_round_trip() -> None:
    key = generate_aes_key()
    assert len(key) == 32
    pt = b"authenticated encryption"
    blob = encrypt_bytes(pt, key)
    assert decrypt_bytes(blob, key) == pt
    assert encrypt_bytes(pt, key) != blob  # random nonce
    with pytest.raises(InvalidTag):
        decrypt_bytes(blob, generate_aes_key())
    tampered = blob[:-1] + bytes([(blob[-1] ^ 0x01)])
    with pytest.raises(InvalidTag):
        decrypt_bytes(tampered, key)


def test_aes_gcm_string_and_aad() -> None:
    key = generate_aes_key()
    blob = encrypt_string("hola", key, associated_data=b"hdr")
    assert decrypt_string(blob, key, associated_data=b"hdr") == "hola"
    with pytest.raises(InvalidTag):
        decrypt_string(blob, key, associated_data=b"other")


def test_aes_gcm_file(tmp_path: Path) -> None:
    key = generate_aes_key()
    src = tmp_path / "plain.txt"
    enc = tmp_path / "plain.bin"
    out = tmp_path / "out.txt"
    src.write_text("file payload", encoding="utf-8")
    encrypt_file(src, enc, key)
    decrypt_file(enc, out, key)
    assert out.read_text(encoding="utf-8") == "file payload"


def test_aes_rejects_wrong_key_size() -> None:
    with pytest.raises(ValueError, match="32"):
        encrypt_bytes(b"x", b"short")


def test_hmac_rfc4231_case_1() -> None:
    # RFC 4231, test case 1, HMAC-SHA-256
    key = b"\x0b" * 20
    data = b"Hi There"
    expected = bytes.fromhex(
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    )
    assert hmac_sha256(key, data) == expected


def test_hmac_rfc4231_case_2() -> None:
    # RFC 4231, test case 2, HMAC-SHA-256
    key = b"Jefe"
    data = b"what do ya want for nothing?"
    expected = bytes.fromhex(
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    )
    assert hmac_sha256(key, data) == expected


def test_hkdf_rfc5869_case_1() -> None:
    # RFC 5869 Appendix A.1 (SHA-256, L=42)
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    expected = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )
    assert len(expected) == 42
    assert hkdf_sha256(ikm, length=42, salt=salt, info=info) == expected


def test_rsa_oaep_and_pss_round_trip(tmp_path: Path) -> None:
    priv, pub = generate_rsa_keypair(2048)
    msg = b"oaep payload"
    ct = rsa_oaep_encrypt(msg, pub)
    assert rsa_oaep_decrypt(ct, priv) == msg
    sig = rsa_pss_sign(b"document", priv)
    assert rsa_pss_verify(b"document", sig, pub)
    assert not rsa_pss_verify(b"other", sig, pub)
    save_rsa_private(priv, tmp_path / "k.pem")
    save_rsa_public(pub, tmp_path / "k.pub.pem")
    priv2 = load_rsa_private(tmp_path / "k.pem")
    pub2 = load_rsa_public(tmp_path / "k.pub.pem")
    assert rsa_oaep_decrypt(ct, priv2) == msg
    assert rsa_pss_verify(b"document", sig, pub2)


def test_rsa_rejects_small_keys() -> None:
    with pytest.raises(ValueError, match="2048"):
        generate_rsa_keypair(1024)


def test_ed25519_sign_verify() -> None:
    priv, pub = generate_ed25519_keypair()
    msg = b"ed25519 message"
    sig = sign_ed25519(msg, priv)
    assert len(sig) == 64
    assert verify_ed25519(msg, sig, pub)
    assert not verify_ed25519(b"nope", sig, pub)
    other, _ = generate_ed25519_keypair()
    assert not verify_ed25519(msg, sign_ed25519(msg, other), pub)


def test_x25519_ecdh() -> None:
    a_priv, a_pub = generate_x25519_keypair()
    b_priv, b_pub = generate_x25519_keypair()
    shared_ab = x25519_exchange(a_priv, b_pub)
    shared_ba = x25519_exchange(b_priv, a_pub)
    assert shared_ab == shared_ba
    assert len(shared_ab) == 32
    c_priv, _ = generate_x25519_keypair()
    assert x25519_exchange(c_priv, b_pub) != shared_ab


def test_argon2id_hash_verify() -> None:
    encoded = hash_password("correct horse battery staple")
    assert encoded.startswith("$argon2id$")
    assert verify_password("correct horse battery staple", encoded)
    assert not verify_password("wrong password", encoded)
    assert not verify_password("correct horse battery staple", "not-a-hash")


def test_argon2id_kdf_deterministic() -> None:
    salt = b"0123456789abcdef"
    a = argon2id_kdf(b"password", salt, time_cost=2, memory_cost=32, parallelism=1)
    b = argon2id_kdf(b"password", salt, time_cost=2, memory_cost=32, parallelism=1)
    c = argon2id_kdf(b"other", salt, time_cost=2, memory_cost=32, parallelism=1)
    assert a == b
    assert a != c
    assert len(a) == 32
