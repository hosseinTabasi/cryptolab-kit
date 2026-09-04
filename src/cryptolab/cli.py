"""Command-line interface for cryptolab-kit.

Private key material is written to files and is never printed unless
``--show-private`` is passed to ``keygen``.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from collections.abc import Sequence
from pathlib import Path

from cryptolab import __version__
from cryptolab.classic.caesar import caesar_decrypt, caesar_encrypt
from cryptolab.classic.feistel import feistel_decrypt, feistel_encrypt
from cryptolab.classic.frequency import CANNED_CIPHERTEXT, CANNED_SHIFT, attack_caesar
from cryptolab.classic.vigenere import vigenere_decrypt, vigenere_encrypt
from cryptolab.hybrid import hybrid_decrypt_file, hybrid_encrypt_file
from cryptolab.modern.aes_gcm import (
    AES_KEY_SIZE,
    decrypt_file,
    encrypt_file,
    generate_aes_key,
)
from cryptolab.modern.ecdh import (
    generate_x25519_keypair,
    load_x25519_private,
    load_x25519_public,
    save_x25519_private,
    save_x25519_public,
)
from cryptolab.modern.rsa import (
    generate_rsa_keypair,
    load_rsa_private,
    load_rsa_public,
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
from cryptolab.utils import (
    as_path,
    ensure_dir,
    load_key_bytes,
    read_bytes,
    to_hex,
    write_bytes,
    write_text,
)

_HASH_ALGOS = {
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
    "sha3_256": hashlib.sha3_256,
    "blake2b": lambda: hashlib.blake2b(digest_size=32),
}


class CliError(Exception):
    """User-facing usage or runtime error (printed without a traceback)."""


def _die(message: str, code: int = 2) -> int:
    print(f"error: {message}", file=sys.stderr)
    return code


def _cmd_hash(args: argparse.Namespace) -> int:
    algo = args.algo.lower()
    if algo not in _HASH_ALGOS:
        raise CliError(
            f"unknown hash algorithm {args.algo!r}; "
            f"choose one of: {', '.join(sorted(_HASH_ALGOS))}"
        )
    target = args.target
    path = Path(target)
    if path.is_file():
        data = path.read_bytes()
        label = str(path)
    else:
        data = target.encode("utf-8")
        label = "text"
    digest = _HASH_ALGOS[algo]()
    digest.update(data)
    print(f"{algo} ({label}) = {digest.hexdigest()}")
    return 0


def _cmd_keygen(args: argparse.Namespace) -> int:
    out = ensure_dir(args.out)
    kind = args.kind
    if kind == "rsa":
        bits = args.bits
        if bits < 2048:
            raise CliError("RSA key size must be at least 2048 bits")
        priv, pub = generate_rsa_keypair(bits)
        priv_path = out / "rsa_private.pem"
        pub_path = out / "rsa_public.pem"
        save_rsa_private(priv, priv_path)
        save_rsa_public(pub, pub_path)
        print(f"wrote RSA-{bits} public key  -> {pub_path}")
        print(f"wrote RSA-{bits} private key -> {priv_path}")
        if args.show_private:
            print(priv_path.read_text(encoding="utf-8"), end="")
        else:
            print("private key not printed (pass --show-private to display PEM)")
        return 0
    if kind == "ed25519":
        priv, pub = generate_ed25519_keypair()
        priv_path = out / "ed25519_private.pem"
        pub_path = out / "ed25519_public.pem"
        save_ed25519_private(priv, priv_path)
        save_ed25519_public(pub, pub_path)
        print(f"wrote Ed25519 public key  -> {pub_path}")
        print(f"wrote Ed25519 private key -> {priv_path}")
        if args.show_private:
            print(priv_path.read_text(encoding="utf-8"), end="")
        else:
            print("private key not printed (pass --show-private to display PEM)")
        return 0
    if kind == "x25519":
        priv, pub = generate_x25519_keypair()
        priv_path = out / "x25519_private.pem"
        pub_path = out / "x25519_public.pem"
        save_x25519_private(priv, priv_path)
        save_x25519_public(pub, pub_path)
        print(f"wrote X25519 public key  -> {pub_path}")
        print(f"wrote X25519 private key -> {priv_path}")
        if args.show_private:
            print(priv_path.read_text(encoding="utf-8"), end="")
        else:
            print("private key not printed (pass --show-private to display PEM)")
        return 0
    if kind == "aes":
        key = generate_aes_key()
        key_path = out / "aes.key"
        write_text(key_path, to_hex(key) + "\n")
        print(f"wrote AES-256 key (hex) -> {key_path}")
        if args.show_private:
            print(to_hex(key))
        else:
            print("key material not printed (pass --show-private to display hex)")
        return 0
    raise CliError(f"unknown key type {kind!r}; choose rsa, ed25519, x25519, or aes")


def _cmd_encrypt_file(args: argparse.Namespace) -> int:
    src = as_path(args.input)
    dest = as_path(args.output)
    if not src.is_file():
        raise CliError(f"input file not found: {src}")
    key = load_key_bytes(args.key, expected_len=AES_KEY_SIZE)
    encrypt_file(src, dest, key)
    print(f"encrypted {src} -> {dest} (AES-256-GCM)")
    return 0


def _cmd_decrypt_file(args: argparse.Namespace) -> int:
    src = as_path(args.input)
    dest = as_path(args.output)
    if not src.is_file():
        raise CliError(f"input file not found: {src}")
    key = load_key_bytes(args.key, expected_len=AES_KEY_SIZE)
    try:
        decrypt_file(src, dest, key)
    except Exception as exc:  # InvalidTag and length errors
        raise CliError(f"decryption failed: {exc}") from exc
    print(f"decrypted {src} -> {dest} (AES-256-GCM)")
    return 0


def _sniff_private(path: Path) -> str:
    text = path.read_text(encoding="utf-8", errors="replace")
    if "BEGIN" not in text:
        raise CliError(f"{path} does not look like a PEM key")
    # Load by trying each type. Order matters only for error messages.
    try:
        load_ed25519_private(path)
        return "ed25519"
    except (TypeError, ValueError):
        pass
    try:
        load_rsa_private(path)
        return "rsa"
    except (TypeError, ValueError):
        pass
    try:
        load_x25519_private(path)
        return "x25519"
    except (TypeError, ValueError):
        pass
    raise CliError(f"could not load a signing key from {path}")


def _sniff_public(path: Path) -> str:
    try:
        load_ed25519_public(path)
        return "ed25519"
    except (TypeError, ValueError):
        pass
    try:
        load_rsa_public(path)
        return "rsa"
    except (TypeError, ValueError):
        pass
    try:
        load_x25519_public(path)
        return "x25519"
    except (TypeError, ValueError):
        pass
    raise CliError(f"could not load a public key from {path}")


def _cmd_sign(args: argparse.Namespace) -> int:
    src = as_path(args.input)
    if not src.is_file():
        raise CliError(f"input file not found: {src}")
    key_path = as_path(args.key)
    if not key_path.is_file():
        raise CliError(f"private key not found: {key_path}")
    data = read_bytes(src)
    kind = _sniff_private(key_path)
    if kind == "ed25519":
        sig = sign_ed25519(data, load_ed25519_private(key_path))
        alg = "Ed25519"
    elif kind == "rsa":
        sig = rsa_pss_sign(data, load_rsa_private(key_path))
        alg = "RSA-PSS"
    else:
        raise CliError("X25519 keys cannot sign; use Ed25519 or RSA")
    dest = as_path(args.out) if args.out else Path(str(src) + ".sig")
    write_bytes(dest, sig)
    print(f"signed {src} with {alg} -> {dest} ({len(sig)} bytes)")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    src = as_path(args.input)
    sig_path = as_path(args.sig)
    key_path = as_path(args.key)
    if not src.is_file():
        raise CliError(f"input file not found: {src}")
    if not sig_path.is_file():
        raise CliError(f"signature file not found: {sig_path}")
    if not key_path.is_file():
        raise CliError(f"public key not found: {key_path}")
    data = read_bytes(src)
    sig = read_bytes(sig_path)
    kind = _sniff_public(key_path)
    if kind == "ed25519":
        ok = verify_ed25519(data, sig, load_ed25519_public(key_path))
        alg = "Ed25519"
    elif kind == "rsa":
        ok = rsa_pss_verify(data, sig, load_rsa_public(key_path))
        alg = "RSA-PSS"
    else:
        raise CliError("X25519 keys cannot verify signatures; use Ed25519 or RSA")
    if ok:
        print(f"OK  {alg} signature matches {src}")
        return 0
    print(f"FAIL  {alg} signature does not match {src}", file=sys.stderr)
    return 1


def _cmd_hybrid_encrypt(args: argparse.Namespace) -> int:
    src = as_path(args.input)
    if not src.is_file():
        raise CliError(f"input file not found: {src}")
    pub_path = as_path(args.pubkey)
    if not pub_path.is_file():
        raise CliError(f"RSA public key not found: {pub_path}")
    dest = as_path(args.out) if args.out else Path(str(src) + ".enc")
    try:
        pub = load_rsa_public(pub_path)
    except (TypeError, ValueError) as exc:
        raise CliError(f"failed to load RSA public key: {exc}") from exc
    hybrid_encrypt_file(src, dest, pub)
    print(f"hybrid-encrypted {src} -> {dest} (AES-256-GCM + RSA-OAEP)")
    return 0


def _cmd_hybrid_decrypt(args: argparse.Namespace) -> int:
    src = as_path(args.input)
    if not src.is_file():
        raise CliError(f"package not found: {src}")
    priv_path = as_path(args.privkey)
    if not priv_path.is_file():
        raise CliError(f"RSA private key not found: {priv_path}")
    dest = as_path(args.out) if args.out else Path(str(src).removesuffix(".enc") + ".dec")
    try:
        priv = load_rsa_private(priv_path)
    except (TypeError, ValueError) as exc:
        raise CliError(f"failed to load RSA private key: {exc}") from exc
    try:
        hybrid_decrypt_file(src, dest, priv)
    except Exception as exc:
        raise CliError(f"hybrid decryption failed: {exc}") from exc
    print(f"hybrid-decrypted {src} -> {dest}")
    return 0


def _cmd_demo_classic(args: argparse.Namespace) -> int:
    del args
    print("=== EDUCATIONAL demo: classical ciphers (NOT production-safe) ===\n")
    plain = "Attack at dawn!"
    shift = 3
    c = caesar_encrypt(plain, shift)
    print(f"Caesar shift={shift}")
    print(f"  plaintext : {plain}")
    print(f"  ciphertext: {c}")
    print(f"  decrypt   : {caesar_decrypt(c, shift)}")
    print()
    key = "LEMON"
    vg_plain = "Attack at dawn"
    vg_ct = vigenere_encrypt(vg_plain, key)
    print(f"Vigenère key={key!r}")
    print(f"  plaintext : {vg_plain}")
    print(f"  ciphertext: {vg_ct}")
    print(f"  decrypt   : {vigenere_decrypt(vg_ct, key)}")
    print()
    fe_plain = b"Feistel toy"
    fe_key = 0xC0FFEE
    fe_ct = feistel_encrypt(fe_plain, fe_key)
    fe_pt = feistel_decrypt(fe_ct, fe_key)
    print("Toy Feistel (4 rounds, 64-bit blocks) — EDUCATIONAL")
    print(f"  plaintext : {fe_plain!r}")
    print(f"  ciphertext: {to_hex(fe_ct)}")
    print(f"  decrypt   : {fe_pt!r}")
    print()
    rsa_priv = rsa_keygen(DEMO_P, DEMO_Q, DEMO_E)
    rsa_pub = rsa_priv.public_key
    msg = 42
    rsa_ct = rsa_encrypt(msg, rsa_pub)
    rsa_pt = rsa_decrypt(rsa_ct, rsa_priv)
    sig = rsa_sign(b"hello", rsa_priv)
    ok = rsa_verify(b"hello", sig, rsa_pub)
    print("Textbook RSA (p=61, q=53, e=17, n=3233) — EDUCATIONAL, NOT SAFE")
    print(f"  n={rsa_pub.n}  e={rsa_pub.e}  d={rsa_priv.d}")
    print(f"  encrypt(42) = {rsa_ct}; decrypt = {rsa_pt}")
    print(f"  sign/verify 'hello' ok={ok}  signature={sig}")
    print()
    a_priv, a_pub = dh_generate_keypair(private_key=6)
    b_priv, b_pub = dh_generate_keypair(private_key=15)
    ss_a = dh_shared_secret(a_priv, b_pub)
    ss_b = dh_shared_secret(b_priv, a_pub)
    print(f"Tiny Diffie–Hellman (p={DH_SAFE_PRIME}, g={DH_GENERATOR}) — EDUCATIONAL")
    print(f"  Alice pub={a_pub}  Bob pub={b_pub}  shared={ss_a} (match={ss_a == ss_b})")
    print("\nUse `cryptolab demo attacks` for the canned frequency-analysis demo.")
    return 0


def _cmd_demo_attacks(args: argparse.Namespace) -> int:
    del args
    print("=== EDUCATIONAL demo: frequency analysis on CANNED English ciphertext ===")
    print("This command never fetches or attacks arbitrary network traffic.")
    print(f"Canned Caesar ciphertext (known classroom shift={CANNED_SHIFT}):")
    print(f"  {CANNED_CIPHERTEXT}")
    print()
    ranked = attack_caesar(CANNED_CIPHERTEXT, top=3)
    print("Top-3 recovered shifts (chi-squared vs English letter frequencies, lower is better):")
    for shift, score, plain in ranked:
        preview = plain[:88] + ("…" if len(plain) > 88 else "")
        marker = "  <-- best" if shift == ranked[0][0] else ""
        print(f"  shift={shift:2d}  chi2={score:8.2f}  {preview}{marker}")
    best_shift, _, best_plain = ranked[0]
    print()
    print(f"Best candidate shift={best_shift}")
    print(f"  {best_plain}")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cryptolab",
        description=(
            "cryptolab-kit: educational classical ciphers and practical "
            "AES-GCM / RSA-OAEP / Ed25519 / X25519 / hybrid envelopes."
        ),
        epilog=(
            "Educational commands are labelled as such and must not be used "
            "to protect real secrets. See docs/SECURITY.md."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"cryptolab-kit {__version__}",
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p_hash = sub.add_parser("hash", help="SHA-256 (or other) digest of a file or text")
    p_hash.add_argument("target", help="file path, or literal text if the path does not exist")
    p_hash.add_argument(
        "--algo",
        default="sha256",
        help="sha256 (default), sha384, sha512, sha3_256, blake2b",
    )
    p_hash.set_defaults(func=_cmd_hash)

    p_keygen = sub.add_parser("keygen", help="Generate RSA, Ed25519, X25519, or AES keys")
    p_keygen.add_argument(
        "kind",
        choices=["rsa", "ed25519", "x25519", "aes"],
        help="key type (aes writes a 32-byte hex key for encrypt-file)",
    )
    p_keygen.add_argument(
        "--out",
        default="keys",
        help="output directory (default: keys/)",
    )
    p_keygen.add_argument(
        "--bits",
        type=int,
        default=2048,
        help="RSA modulus size in bits (minimum 2048, default 2048)",
    )
    p_keygen.add_argument(
        "--show-private",
        action="store_true",
        help="print private key material to stdout (off by default)",
    )
    p_keygen.set_defaults(func=_cmd_keygen)

    p_enc = sub.add_parser("encrypt-file", help="AES-256-GCM encrypt a file")
    p_enc.add_argument("input", help="plaintext file")
    p_enc.add_argument("output", help="ciphertext output path")
    p_enc.add_argument(
        "--key",
        required=True,
        help="32-byte AES key file (raw or hex)",
    )
    p_enc.set_defaults(func=_cmd_encrypt_file)

    p_dec = sub.add_parser("decrypt-file", help="AES-256-GCM decrypt a file")
    p_dec.add_argument("input", help="ciphertext file")
    p_dec.add_argument("output", help="plaintext output path")
    p_dec.add_argument(
        "--key",
        required=True,
        help="32-byte AES key file (raw or hex)",
    )
    p_dec.set_defaults(func=_cmd_decrypt_file)

    p_sign = sub.add_parser("sign", help="Sign a file with Ed25519 or RSA-PSS")
    p_sign.add_argument("input", help="file to sign")
    p_sign.add_argument("--key", required=True, help="PEM private key")
    p_sign.add_argument("--out", default=None, help="signature output (default: INPUT.sig)")
    p_sign.set_defaults(func=_cmd_sign)

    p_verify = sub.add_parser("verify", help="Verify an Ed25519 or RSA-PSS signature")
    p_verify.add_argument("input", help="signed file")
    p_verify.add_argument("--key", required=True, help="PEM public key")
    p_verify.add_argument("--sig", required=True, help="signature file")
    p_verify.set_defaults(func=_cmd_verify)

    p_he = sub.add_parser(
        "hybrid-encrypt",
        help="Encrypt a file: AES-256-GCM + RSA-OAEP wrapped key (.enc)",
    )
    p_he.add_argument("input", help="plaintext file")
    p_he.add_argument("--pubkey", required=True, help="recipient RSA public key PEM")
    p_he.add_argument("--out", default=None, help="package path (default: INPUT.enc)")
    p_he.set_defaults(func=_cmd_hybrid_encrypt)

    p_hd = sub.add_parser("hybrid-decrypt", help="Decrypt a hybrid .enc package")
    p_hd.add_argument("input", help="hybrid package")
    p_hd.add_argument("--privkey", required=True, help="recipient RSA private key PEM")
    p_hd.add_argument("--out", default=None, help="plaintext output path")
    p_hd.set_defaults(func=_cmd_hybrid_decrypt)

    p_demo = sub.add_parser("demo", help="Run educational demonstrations")
    demo_sub = p_demo.add_subparsers(dest="demo_kind", metavar="KIND")
    d_classic = demo_sub.add_parser(
        "classic",
        help="Caesar, Vigenère, toy Feistel, textbook RSA, tiny DH",
    )
    d_classic.set_defaults(func=_cmd_demo_classic)
    d_attacks = demo_sub.add_parser(
        "attacks",
        help="Frequency analysis on canned English ciphertext only",
    )
    d_attacks.set_defaults(func=_cmd_demo_attacks)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code."""
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    if not getattr(args, "command", None):
        parser.print_help()
        return 2
    if args.command == "demo" and not getattr(args, "demo_kind", None):
        parser.parse_args(["demo", "--help"])
        return 2
    func = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        return 2
    try:
        return int(func(args))
    except CliError as exc:
        return _die(str(exc), 2)
    except FileNotFoundError as exc:
        return _die(str(exc), 2)
    except ValueError as exc:
        return _die(str(exc), 2)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
