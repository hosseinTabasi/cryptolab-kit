"""Textbook classical ciphers.

**EDUCATIONAL.** Caesar, Vigenère, a toy Feistel network, and a frequency-analysis demo on a canned English ciphertext. None provide confidentiality against a modern adversary.
"""
from cryptolab.classic.caesar import caesar_decrypt,caesar_encrypt
from cryptolab.classic.feistel import feistel_decrypt,feistel_encrypt
from cryptolab.classic.frequency import CANNED_CIPHERTEXT,attack_caesar,score_english
from cryptolab.classic.vigenere import vigenere_decrypt,vigenere_encrypt
__all__=["CANNED_CIPHERTEXT","attack_caesar","caesar_decrypt","caesar_encrypt","feistel_decrypt","feistel_encrypt","score_english","vigenere_decrypt","vigenere_encrypt"]
