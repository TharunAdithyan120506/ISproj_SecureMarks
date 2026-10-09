"""15-minute HS256 JWTs. The secret lives in .env (written by setup_demo.py)."""
from __future__ import annotations

import time
import uuid

import jwt

ALG = "HS256"


class TokenError(Exception):
    pass


def issue(secret: str, *, username: str, role: str, roll_no: str | None, courses: list[str], ttl_s: int) -> str:
    now = int(time.time())
    claims = {
        "sub": username,
        "role": role,
        "roll_no": roll_no,
        "courses": courses,
        "iat": now,
        "exp": now + ttl_s,
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(claims, secret, algorithm=ALG)


def verify(secret: str, token: str) -> dict:
    try:
        return jwt.decode(token, secret, algorithms=[ALG], options={"require": ["sub", "role", "exp"]})
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("token expired") from exc
    except jwt.PyJWTError as exc:
        raise TokenError(f"invalid token: {exc}") from exc


def subject_if_valid(secret: str, token: str) -> str | None:
    """Used by the rate limiter: the `sub` of a correctly signed token, even if
    expired, so a client cannot dodge its own bucket by presenting a stale token."""
    try:
        claims = jwt.decode(token, secret, algorithms=[ALG], options={"verify_exp": False})
        return claims.get("sub")
    except jwt.PyJWTError:
        return None


def bearer(header: str | None) -> str | None:
    if header and header.lower().startswith("bearer "):
        return header[7:].strip() or None
    return None
