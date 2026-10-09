"""Small encoding helpers shared by the server, the SDK and the portal."""
from __future__ import annotations

import base64


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def short(data: bytes, n: int = 4) -> str:
    """Demo-safe rendering of key material: first and last `n` bytes in hex."""
    h = data.hex()
    if len(data) <= 2 * n:
        return h
    return f"{h[: 2 * n]}…{h[-2 * n:]}"
