"""Argon2id password hashing (argon2-cffi library defaults)."""
from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_ph = PasswordHasher()

# Verifying against this keeps the timing of "unknown user" close to "wrong password".
_DUMMY_HASH = _ph.hash("securemarks-timing-equaliser")


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(pw_hash: str | None, password: str) -> bool:
    try:
        return _ph.verify(pw_hash or _DUMMY_HASH, password) and pw_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
