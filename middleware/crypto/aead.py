"""AES-GCM authenticated encryption (transport and at rest).

A fresh random 12-byte nonce is drawn for every message; nonces are never
reused with the same key. Tampering with the ciphertext, the tag, the nonce or
the AAD makes `decrypt` raise `cryptography.exceptions.InvalidTag`.
"""
from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag  # re-exported for callers
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_LEN = 12
TAG_LEN = 16
CIPHER_NAMES = {16: "AES-128-GCM", 32: "AES-256-GCM"}

__all__ = ["encrypt", "decrypt", "new_key", "cipher_name", "InvalidTag", "NONCE_LEN", "TAG_LEN"]


def new_key(length: int = 32) -> bytes:
    if length not in CIPHER_NAMES:
        raise ValueError("AES-GCM key must be 16 or 32 bytes")
    return os.urandom(length)


def cipher_name(key: bytes) -> str:
    return CIPHER_NAMES[len(key)]


def encrypt(key: bytes, plaintext: bytes, aad: bytes | None = None) -> tuple[bytes, bytes]:
    """Return (nonce, ciphertext || 16-byte tag)."""
    nonce = os.urandom(NONCE_LEN)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes | None = None) -> bytes:
    if len(nonce) != NONCE_LEN:
        raise InvalidTag()
    return AESGCM(key).decrypt(nonce, ciphertext, aad)
