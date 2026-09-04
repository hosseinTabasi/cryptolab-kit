"""Production-oriented wrappers around the ``cryptography`` library.

These APIs use AES-256-GCM, RSA-OAEP/PSS (2048-bit+), Ed25519, X25519,
HKDF, HMAC-SHA256, and Argon2id. They are the **safe** side of
cryptolab-kit. Algorithm choices are documented in
``docs/ALGORITHMS.md``.
"""

from cryptolab.modern.aes_gcm import (
    AES_KEY_SIZE,
    decrypt_bytes,
    decrypt_file,
    decrypt_string,
    encrypt_bytes,
    encrypt_file,
    encrypt_string,
    generate_aes_key,
)
from cryptolab.modern.ecdh import (
    generate_x25519_keypair,
    load_x25519_private,
    load_x25519_public,
    save_x25519_private,
    save_x25519_public,
    x25519_exchange,
)
from cryptolab.modern.kdf import hkdf_sha256, hmac_sha256
from cryptolab.modern.passwords import hash_password, verify_password
from cryptolab.modern.rsa import (
    generate_rsa_keypair,
    load_rsa_private,
    load_rsa_public,
    rsa_oaep_decrypt,
    rsa_oaep_encrypt,
    rsa_pss_sign,
    rsa_pss_verify,
    save_rsa_private,
    save_rsa_public,
)
from cryptolab.modern.signatures import (
    generate_ed25519_keypair,
    load_ed25519_private,
    load_ed25519_public,
    save_ed25519_private,
    save_ed25519_public,
    sign_ed25519,
    verify_ed25519,
)

__all__ = [
    "AES_KEY_SIZE",
    "decrypt_bytes",
    "decrypt_file",
    "decrypt_string",
    "encrypt_bytes",
    "encrypt_file",
    "encrypt_string",
    "generate_aes_key",
    "generate_ed25519_keypair",
    "generate_rsa_keypair",
    "generate_x25519_keypair",
    "hash_password",
    "hkdf_sha256",
    "hmac_sha256",
    "load_ed25519_private",
    "load_ed25519_public",
    "load_rsa_private",
    "load_rsa_public",
    "load_x25519_private",
    "load_x25519_public",
    "rsa_oaep_decrypt",
    "rsa_oaep_encrypt",
    "rsa_pss_sign",
    "rsa_pss_verify",
    "save_ed25519_private",
    "save_ed25519_public",
    "save_rsa_private",
    "save_rsa_public",
    "save_x25519_private",
    "save_x25519_public",
    "sign_ed25519",
    "verify_ed25519",
    "verify_password",
    "x25519_exchange",
]
