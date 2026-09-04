"""Letter-frequency analysis demo on a canned English ciphertext.

**EDUCATIONAL.** This module ships a fixed English sentence encrypted
under a Caesar shift. The attack enumerates all 26 keys and ranks them
with a chi-squared statistic against published English letter
frequencies. It does **not** accept arbitrary user ciphertext for
attack automation; ``attack_caesar`` is intended for the canned demo
and classroom Caesar ciphertext.

Reference: Stallings, *Cryptography and Network Security* (classical
cryptanalysis); English frequencies after Beker & Piper / standard
cryptanalysis tables.
"""

from __future__ import annotations

from cryptolab.classic.caesar import caesar_decrypt, caesar_encrypt

# Approximate English letter probabilities (A–Z), summing to 1.0.
# Source: common cryptanalysis tables (ETAOIN SHRDLU ordering).
ENGLISH_FREQ: dict[str, float] = {
    "A": 0.08167,
    "B": 0.01492,
    "C": 0.02782,
    "D": 0.04253,
    "E": 0.12702,
    "F": 0.02228,
    "G": 0.02015,
    "H": 0.06094,
    "I": 0.06966,
    "J": 0.00153,
    "K": 0.00772,
    "L": 0.04025,
    "M": 0.02406,
    "N": 0.06749,
    "O": 0.07507,
    "P": 0.01929,
    "Q": 0.00095,
    "R": 0.05987,
    "S": 0.06327,
    "T": 0.09056,
    "U": 0.02758,
    "V": 0.00978,
    "W": 0.02360,
    "X": 0.00150,
    "Y": 0.01974,
    "Z": 0.00074,
}

# Fixed classroom plaintext. Encrypted once at import with a published shift
# so tests and the CLI demo stay deterministic.
_CANNED_PLAINTEXT = (
    "THE ART OF CRYPTOGRAPHY RESTS ON MATHEMATICAL PROBLEMS THAT ARE "
    "BELIEVED TO BE HARD. CLASSICAL CIPHERS SUCH AS CAESAR AND VIGENERE "
    "FAIL BECAUSE LETTER FREQUENCIES SURVIVE THE SUBSTITUTION. THIS "
    "CANNED CIPHERTEXT IS PROVIDED FOR A FREQUENCY ANALYSIS DEMO ONLY."
)
CANNED_SHIFT = 12
CANNED_CIPHERTEXT = caesar_encrypt(_CANNED_PLAINTEXT, CANNED_SHIFT)


def score_english(text: str) -> float:
    """Chi-squared score of ``text`` against English letter frequencies.

    Lower is a better match. Non-letters are ignored. An empty letter
    stream scores as positive infinity.
    """
    letters = [ch.upper() for ch in text if "A" <= ch.upper() <= "Z"]
    n = len(letters)
    if n == 0:
        return float("inf")
    counts = {ch: 0 for ch in ENGLISH_FREQ}
    for ch in letters:
        counts[ch] += 1
    chi = 0.0
    for ch, p in ENGLISH_FREQ.items():
        expected = p * n
        if expected == 0:
            continue
        diff = counts[ch] - expected
        chi += (diff * diff) / expected
    return chi


def attack_caesar(ciphertext: str, *, top: int = 3) -> list[tuple[int, float, str]]:
    """Rank Caesar keys for ``ciphertext`` by English frequency score.

    Returns a list of ``(shift, score, candidate_plaintext)`` sorted by
    increasing chi-squared score (best first), truncated to ``top``.

    **EDUCATIONAL.** Brute-forcing a 26-key cipher is a classroom
    demonstration, not a general cryptanalytic toolkit. The CLI demo
    runs this only on :data:`CANNED_CIPHERTEXT`.
    """
    if top < 1:
        raise ValueError("top must be at least 1")
    ranked: list[tuple[int, float, str]] = []
    for shift in range(26):
        plain = caesar_decrypt(ciphertext, shift)
        ranked.append((shift, score_english(plain), plain))
    ranked.sort(key=lambda item: item[1])
    return ranked[:top]
