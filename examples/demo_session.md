# Demo session (copy-paste)

Commands assume the project root, a POSIX shell, and:

```bash
python -m venv .venv && source .venv/bin/activate && pip install -e ".[dev]"
```

`python -m cryptolab` is equivalent to the `cryptolab` console script.

## Hash a file or a string

```bash
cryptolab hash examples/sample.txt
cryptolab hash "hello cryptolab" --algo sha256
cryptolab hash examples/sample.txt --algo blake2b
```

## AES-256-GCM file encryption

```bash
cryptolab keygen aes --out keys
cryptolab encrypt-file examples/sample.txt /tmp/sample.gcm --key keys/aes.key
cryptolab decrypt-file /tmp/sample.gcm /tmp/sample.out --key keys/aes.key
cmp examples/sample.txt /tmp/sample.out && echo round-trip-ok
```

## Ed25519 sign / verify

```bash
cryptolab keygen ed25519 --out keys
cryptolab sign examples/sample.txt --key keys/ed25519_private.pem --out /tmp/sample.sig
cryptolab verify examples/sample.txt --key keys/ed25519_public.pem --sig /tmp/sample.sig
```

RSA-PSS works the same way if `--key` points at `keys/rsa_private.pem`
(sign) or `keys/rsa_public.pem` (verify).

## Hybrid envelope (AES-GCM + RSA-OAEP)

```bash
cryptolab keygen rsa --out keys --bits 2048
cryptolab hybrid-encrypt examples/sample.txt --pubkey keys/rsa_public.pem --out /tmp/sample.enc
cryptolab hybrid-decrypt /tmp/sample.enc --privkey keys/rsa_private.pem --out /tmp/sample.dec
cmp examples/sample.txt /tmp/sample.dec && echo hybrid-ok
```

## X25519 key agreement (Python API)

The CLI writes X25519 PEMs; derivation is a few lines of Python
because both parties' keys are needed:

```bash
cryptolab keygen x25519 --out keys/alice
cryptolab keygen x25519 --out keys/bob
python - <<'PY'
from cryptolab.modern.ecdh import load_x25519_private, load_x25519_public, x25519_exchange
from cryptolab.modern.kdf import hkdf_sha256
a = load_x25519_private("keys/alice/x25519_private.pem")
b_pub = load_x25519_public("keys/bob/x25519_public.pem")
shared = x25519_exchange(a, b_pub)
print(hkdf_sha256(shared, info=b"cryptolab-kit/x25519").hex())
PY
```

## Educational demos (not production-safe)

```bash
cryptolab demo classic
cryptolab demo attacks
```

`demo attacks` runs frequency analysis on the canned English
ciphertext shipped in `cryptolab.classic.frequency`. It does not
accept a user ciphertext on the command line.

## Usage errors

Missing arguments print argparse help. Bad paths and wrong key types
print a one-line `error:` and exit 2. Failed signature verification
exits 1.

```bash
cryptolab encrypt-file
cryptolab decrypt-file /no/such/file /tmp/out --key keys/aes.key
cryptolab keygen rsa --bits 1024
```
