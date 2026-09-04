# Algorithms

Short notes and primary references. Educational constructions are
marked as such; they exist so a student can step through the math.

## Number theory (educational)

Binary GCD, extended Euclidean algorithm (Bézout coefficients),
modular inverse, and modular exponentiation.

- Menezes, van Oorschot, Vanstone, *Handbook of Applied Cryptography*
  (HAC), chapter 2.
- Stallings, *Cryptography and Network Security*, public-key
  mathematics chapters.

## Classical ciphers (educational)

**Caesar** is a 26-key shift. **Vigenère** is a repeating-key Caesar.
Both are broken by frequency statistics; the CLI `demo attacks`
command recovers a canned Caesar shift with a chi-squared score
against standard English letter frequencies (ETAOIN tables used in
undergraduate cryptanalysis).

**Toy Feistel:** 64-bit blocks, four rounds, a non-cryptographic mixer
as the round function, PKCS#7 padding. Invertible because Feistel
networks are involutions of the L/R split regardless of `F`. This is
**not** DES, not Luby–Rackoff with a PRF, and not production-safe.

- Stallings, classical encryption techniques and Feistel structure.
- HAC, chapter 7.

## Textbook RSA and tiny DH (educational)

Unpadded RSA (`c = m^e mod n`) on classroom primes
(`p = 61`, `q = 53`, `n = 3233`, `e = 17`). Signatures hash with
SHA-256 then reduce modulo `n` — insecure once `n` is smaller than
the hash, which it always is here.

Diffie–Hellman uses the documented safe prime `p = 23`
(`(p-1)/2 = 11` is prime) and generator `g = 5` (primitive root
modulo 23). Group order 22.

- HAC, chapters 8 and 12.
- Stallings, RSA and Diffie–Hellman chapters.
- Katz and Lindell, *Introduction to Modern Cryptography* — why
  padding (OAEP/PSS) and authenticators are required; CDH/DDH.

## AES-256-GCM (safe)

NIST SP 800-38D, *Recommendation for Block Cipher Modes of Operation:
Galois/Counter Mode (GCM) and GMAC*. 256-bit keys, 96-bit IVs
(recommended IV length in SP 800-38D §5.2.1.1), 128-bit tags.
Implemented by `cryptography.hazmat.primitives.ciphers.aead.AESGCM`.
Wire format: `nonce || ciphertext || tag`.

## RSA-OAEP and RSA-PSS (safe)

- RSAES-OAEP: PKCS #1 v2.2 / RFC 8017, SHA-256, MGF1-SHA-256.
- RSASSA-PSS: RFC 8017, SHA-256, maximum salt length.
- Minimum modulus 2048 bits (NIST SP 800-57 Part 1 key-size guidance
  for RSA at the 112-bit security level; 3072+ for longer horizons).

## Ed25519 (safe)

RFC 8032, *Edwards-Curve Digital Signature Algorithm (EdDSA)*.
PureEdDSA over Edwards25519, 32-byte public keys, 64-byte signatures.
`cryptography` `Ed25519PrivateKey` / `Ed25519PublicKey`.

## X25519 (safe)

RFC 7748, *Elliptic Curves for Security*, §5. Montgomery u-coordinate
Diffie–Hellman on Curve25519. 32-byte shared secret; **always** run
it through HKDF before using it as a symmetric key.

## HMAC-SHA256 and HKDF-SHA256 (safe)

- HMAC: RFC 2104; SHA-256 is FIPS 180-4.
- HKDF: RFC 5869 (extract-then-expand). Test vectors in this repo
  come from RFC 4231 (HMAC) and RFC 5869 Appendix A.1 (HKDF).

## Argon2id (safe)

RFC 9106, *Argon2 Memory-Hard Function for Password Hashing and
Proof-of-Work*. The hybrid Argon2id variant is the RFC’s primary
recommendation. Default lab parameters: 64 MiB, 3 iterations, one
lane, 32-byte tag. Raise `memory_cost` / `time_cost` for online
services.

## Hybrid envelope (safe composition)

1. Draw a 256-bit file key from the OS CSPRNG.
2. Encrypt the payload with AES-256-GCM (AAD =
   `cryptolab-kit/hybrid/v1`).
3. Wrap the file key with RSA-OAEP (recipient public key).
4. Pack `CLB1 || wrap_len || wrapped_key || nonce||ct||tag`.

This is the standard KEM/DEM (key-encapsulation / data-encapsulation)
pattern described in HAC and in modern hybrid-encryption literature.
It is **not** ECIES; RSA-OAEP is the KEM.

## Intentionally omitted

A line-by-line SHA-256 compression-function walkthrough is omitted:
it would be easy to confuse with a FIPS implementation, and hashlib /
`cryptography` already provide the real hash.
