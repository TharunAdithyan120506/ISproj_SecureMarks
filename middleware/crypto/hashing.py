"""SHA-256 fingerprints and the helpers the playground and analyser share."""
from __future__ import annotations

import hashlib
import math
from collections import Counter


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def bit_difference(a: bytes, b: bytes) -> int:
    """Number of differing bits between two equal-length byte strings."""
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte: H = -sum p_i log2 p_i."""
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())
