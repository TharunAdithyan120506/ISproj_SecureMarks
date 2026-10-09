"""Session key agreement.

Default: X25519 with a fresh keypair on both sides per session, then
HKDF-SHA256 (salt = session ID bytes, info = b"securemarks/v1/session").
P1 comparison: RSA-OAEP-2048 (SHA-256) key transport for the `legacy-rsa` policy.
"""
from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HKDF_INFO = b"securemarks/v1/session"


# --- X25519 -----------------------------------------------------------------

def x25519_keypair() -> tuple[X25519PrivateKey, bytes]:
    priv = X25519PrivateKey.generate()
    return priv, x25519_public_bytes(priv)


def x25519_public_bytes(priv: X25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def x25519_shared(priv: X25519PrivateKey, peer_pub: bytes) -> bytes:
    return priv.exchange(X25519PublicKey.from_public_bytes(peer_pub))


def hkdf_derive(shared: bytes, salt: bytes, length: int, info: bytes = HKDF_INFO) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(shared)


def session_salt(session_id: str) -> bytes:
    """Session IDs are 32 hex chars; the salt is their 16 raw bytes."""
    return bytes.fromhex(session_id)


# --- RSA-OAEP-2048 (legacy-rsa policy, benchmark) ----------------------------

_OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def rsa_keypair(bits: int = 2048) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def rsa_public_der(priv: rsa.RSAPrivateKey) -> bytes:
    return priv.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def rsa_wrap(public_der: bytes, secret: bytes) -> bytes:
    pub = serialization.load_der_public_key(public_der)
    return pub.encrypt(secret, _OAEP)


def rsa_unwrap(priv: rsa.RSAPrivateKey, wrapped: bytes) -> bytes:
    return priv.decrypt(wrapped, _OAEP)


def rsa_session_secret() -> bytes:
    return os.urandom(32)
