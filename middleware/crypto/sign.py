"""Record signatures.

Default: Ed25519 over the SHA-256 digest of the canonical record (64-byte
signature, 32-byte public key). P1 comparison: RSA-PSS-2048 (SHA-256).
"""
from __future__ import annotations

import hashlib

from cryptography.exceptions import InvalidSignature  # re-exported for callers
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

__all__ = [
    "InvalidSignature", "ed25519_keypair", "ed25519_public_bytes", "ed25519_sign", "ed25519_verify",
    "rsa_pss_sign", "rsa_pss_verify", "fingerprint", "save_private_pem", "load_private_pem",
    "public_bytes", "sign", "verify", "ED25519", "RSA_PSS",
]

ED25519 = "Ed25519"
RSA_PSS = "RSA-PSS-2048"


def ed25519_keypair() -> tuple[Ed25519PrivateKey, bytes]:
    priv = Ed25519PrivateKey.generate()
    return priv, ed25519_public_bytes(priv)


def ed25519_public_bytes(priv: Ed25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def ed25519_sign(priv: Ed25519PrivateKey, digest: bytes) -> bytes:
    return priv.sign(digest)


def ed25519_verify(public_key: bytes, signature: bytes, digest: bytes) -> None:
    """Raises InvalidSignature on failure."""
    Ed25519PublicKey.from_public_bytes(public_key).verify(signature, digest)


_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


def rsa_pss_sign(priv: rsa.RSAPrivateKey, digest: bytes) -> bytes:
    return priv.sign(digest, _PSS, hashes.SHA256())


def rsa_pss_verify(public_der: bytes, signature: bytes, digest: bytes) -> None:
    pub = serialization.load_der_public_key(public_der)
    pub.verify(signature, digest, _PSS, hashes.SHA256())


def public_bytes(priv) -> bytes:
    """Wire form of a signing public key: raw 32 bytes (Ed25519) or DER (RSA)."""
    if isinstance(priv, Ed25519PrivateKey):
        return ed25519_public_bytes(priv)
    return priv.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def sign(priv, digest: bytes) -> tuple[str, bytes]:
    """Sign with whichever key type is given; returns (alg, signature)."""
    if isinstance(priv, Ed25519PrivateKey):
        return ED25519, ed25519_sign(priv, digest)
    return RSA_PSS, rsa_pss_sign(priv, digest)


def verify(alg: str, public_key: bytes, signature: bytes, digest: bytes) -> None:
    if alg == ED25519:
        ed25519_verify(public_key, signature, digest)
    elif alg == RSA_PSS:
        rsa_pss_verify(public_key, signature, digest)
    else:
        raise InvalidSignature(f"unsupported signature algorithm {alg}")


def fingerprint(public_key: bytes) -> str:
    """First 8 bytes of SHA-256 of the public key, hex."""
    return hashlib.sha256(public_key).digest()[:8].hex()


def save_private_pem(priv, password: str) -> bytes:
    return priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password.encode()),
    )


def load_private_pem(pem: bytes, password: str):
    return serialization.load_pem_private_key(pem, password=password.encode())
