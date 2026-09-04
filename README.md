# cryptolab-kit

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)

Educational and practical cryptography toolkit by **Hossein Tabasi**.
Textbook number theory, classical ciphers, and tiny RSA/DH sit next to
production wrappers for AES-256-GCM, RSA-OAEP/PSS, Ed25519, X25519,
HKDF, HMAC-SHA256, Argon2id, and a hybrid AES+RSA envelope — all
driven from `python -m cryptolab` or the `cryptolab` console script.

**This project is a laboratory. Educational modules are labelled
EDUCATIONAL and must never protect real secrets. Safe commands use
the `cryptography` and `argon2-cffi` packages; they still require
careful key handling. Read [docs/SECURITY.md](docs/SECURITY.md).**

## Features

| | Educational (not production-safe) | Safe (library-backed) |
|---|---|---|
| Symmetric | Caesar, Vigenère, toy 4-round Feistel | AES-256-GCM (files and strings) |
| Public key | Textbook RSA on tiny primes; DH over `p=23` | RSA-OAEP 2048+, RSA-PSS, Ed25519, X25519 |
| Analysis | Frequency attack on **canned English ciphertext only** | — |
| KDF / MAC / passwords | `gcd` / `egcd` / `modinv` / `modexp` (not constant-time) | HKDF-SHA256, HMAC-SHA256, Argon2id |
| Composition | — | Hybrid envelope: random AES key, GCM payload, RSA-OAEP wrap, single `.enc` package |

Topics: `cryptography`, `aes-gcm`, `rsa`, `ed25519`, `hybrid-encryption`, `educational`.

## Install

Python 3.11 or newer.

```bash
python -m venv .venv && source .venv/bin/activate && pip install -e ".[dev]"
```

On Windows PowerShell: `python -m venv .venv; .venv\Scripts\Activate.ps1; pip install -e ".[dev]"`

## Quickstart

```bash
cryptolab hash examples/sample.txt
cryptolab keygen aes --out keys
cryptolab encrypt-file examples/sample.txt /tmp/sample.gcm --key keys/aes.key
cryptolab decrypt-file /tmp/sample.gcm /tmp/sample.out --key keys/aes.key

cryptolab keygen rsa --out keys
cryptolab hybrid-encrypt examples/sample.txt --pubkey keys/rsa_public.pem --out /tmp/sample.enc
cryptolab hybrid-decrypt /tmp/sample.enc --privkey keys/rsa_private.pem --out /tmp/sample.dec

cryptolab keygen ed25519 --out keys
cryptolab sign examples/sample.txt --key keys/ed25519_private.pem --out /tmp/sample.sig
cryptolab verify examples/sample.txt --key keys/ed25519_public.pem --sig /tmp/sample.sig

cryptolab demo classic
cryptolab demo attacks
```

Private keys are written under `keys/` (gitignored) and are **not**
printed unless you pass `--show-private`.

## Example output

```text
$ cryptolab hash examples/sample.txt
sha256 (examples/sample.txt) = 6d7f0eeb3ee9e61622aadf33aa6cc5f3c144719eded45e27e589924ca7323c24

$ cryptolab demo attacks
=== EDUCATIONAL demo: frequency analysis on CANNED English ciphertext ===
This command never fetches or attacks arbitrary network traffic.
Canned Caesar ciphertext (known classroom shift=12):
  FTQ MDF QA NDKbfa… 
Top-3 recovered shifts …
  shift=12  chi2=   …  THE ART OF CRYPTOGRAPHY RESTS ON …  <-- best
```

```text
$ python -c "from cryptolab.rsa_edu import rsa_keygen, rsa_encrypt, rsa_decrypt; k=rsa_keygen(61,53,17); print(k.n, rsa_decrypt(rsa_encrypt(65,k.public_key),k))"
3233 65
```

More copy-paste sessions: [examples/demo_session.md](examples/demo_session.md).
Algorithm notes and citations: [docs/ALGORITHMS.md](docs/ALGORITHMS.md).

## Tests

No network is required.

```bash
pytest -q
```

## License

MIT. Copyright (c) 2026 Hossein Tabasi. See [LICENSE](LICENSE).

GitHub: [hosseinTabasi](https://github.com/hosseinTabasi)
