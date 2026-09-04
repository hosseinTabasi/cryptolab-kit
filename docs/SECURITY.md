# Security model

**cryptolab-kit is a laboratory and teaching toolkit.** Treat every
educational primitive as broken by design. The “safe” APIs wrap
well-reviewed constructions from the `cryptography` and `argon2-cffi`
packages; they are still only as safe as how you use them (key
storage, nonce reuse, who you encrypt to).

## Educational (do not use for real secrets)

| Component | Why it is unsafe |
|-----------|------------------|
| Caesar / Vigenère | Tiny key space; letter frequencies survive. |
| Frequency demo | Brute-forces a 26-key cipher on a **canned** English sentence. |
| Toy Feistel | Four rounds, homemade mixer, 64-bit blocks. Not a PRF. |
| Number theory (`gcd`, `egcd`, `modinv`, `modexp`) | Correct math, **not** constant-time. |
| Textbook RSA (`rsa_edu`) | Tiny primes, **no padding**, malleable, forgeable signatures. The module refuses primes larger than 10^6 so it cannot be mistaken for a real generator. |
| Tiny Diffie–Hellman | Safe prime `p = 23`, generator `g = 5`. The group has 22 elements. Unauthenticated (MITM). |

Loud `EDUCATIONAL  not production-safe` notes appear in those
docstrings and in CLI `demo` output.

## Production-oriented (use these)

| Construction | Library | Notes |
|--------------|---------|--------|
| AES-256-GCM | `cryptography` AESGCM | Random 96-bit nonce prepended to the ciphertext. Never reuse a (key, nonce) pair. |
| RSA-OAEP (SHA-256) | `cryptography` | Minimum 2048-bit keys. For wrapping small secrets (e.g. a 32-byte file key), not bulk data. |
| RSA-PSS (SHA-256) | `cryptography` | Signatures. Maximum salt length. |
| Ed25519 | `cryptography` | RFC 8032 signatures. Prefer this over RSA-PSS for new signing keys. |
| X25519 | `cryptography` | RFC 7748 ECDH. Pass the shared secret through HKDF before using it as a key. |
| HKDF-SHA256 / HMAC-SHA256 | `cryptography` | RFC 5869 / RFC 2104. |
| Argon2id | `argon2-cffi` | RFC 9106 password hashing. Tune memory/time for your threat model. |
| Hybrid envelope | AES-GCM + RSA-OAEP | Random file key, GCM payload, OAEP-wrapped key in a `CLB1` package. |

## Operational rules

1. **No hardcoded secrets.** Keys are generated (`cryptolab keygen`) or
   loaded from files you control. `keys/` is gitignored.
   2. **Private keys are not printed** unless you pass `--show-private`.
   3. **PEM files written by this toolkit are unencrypted by default** so
      lab sessions stay simple. Protect the directory (permissions, disk
         encryption). Pass a password into the Python APIs if you need
            encrypted PKCS#8.
            4. **AES-GCM nonces** are generated with `os.urandom(12)` per message.
               Do not supply your own nonce outside tests.
               5. **Hybrid packages** bind GCM associated data to
                  `cryptolab-kit/hybrid/v1` so a `.enc` file cannot be fed to
                     `decrypt-file` as if it were a raw GCM blob.
                     6. **This project does not implement** malware, ransomware, keyloggers,
                        traffic interceptors, or exploit code. The frequency-analysis demo
                           runs only on a canned English ciphertext shipped in the repo.

                           ## What this toolkit is not

                           - Not a FIPS 140 module.
                           - Not constant-time in the educational arithmetic.
                           - Not a substitute for TLS, age, GPG, or a hardware security module.
                           - Not audited. Read the `cryptography` docs and NIST/RFC references
                             in `ALGORITHMS.md` before building a real system on top.
                             
