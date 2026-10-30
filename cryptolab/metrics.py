"""The security metrics, each with its formula and the value an ideal cipher gives.

Text / byte streams
    bit_diff_pct     fraction of differing bits                      ideal 50 %
    byte_diff_pct    fraction of differing bytes ("characters")      ideal 255/256 = 99.61 %
    entropy          H = -sum p_i log2 p_i over byte values          ideal 8 bits/byte
    chi_square       sum (O_i - E)^2 / E over 256 byte values        < 293.25 (df 255, alpha 0.05)
    pearson          linear correlation of two sequences             ideal 0

Images (uint8 arrays, H x W x 3)
    npcr             % of pixels that differ between two cipher images    ideal 99.6094 %
    uaci             mean |C1 - C2| / 255, in %                           ideal 33.4635 %
    mse / psnr       mean squared error; 10 log10(255^2 / MSE) in dB      plain vs cipher: PSNR < 10 dB
    adjacent_corr    correlation of neighbouring pixels (H, V, D)        plain ~0.9+, cipher ~0

NPCR / UACI critical values follow Wu, Noonan and Agaian, "NPCR and UACI
Randomness Tests for Image Encryption", Cyber Journals (JSAT), 2011.
"""
from __future__ import annotations

import math
from statistics import NormalDist

import numpy as np

NPCR_IDEAL = (1 - 2 ** -8) * 100          # 99.609375
UACI_IDEAL = (256 + 1) / (3 * 256) * 100  # 33.4635 (F = 255: (F + 2) / (3F + 3))
CHI2_CRITICAL_255 = 293.2478             # chi-square, 255 degrees of freedom, alpha = 0.05


def _u8(data) -> np.ndarray:
    if isinstance(data, np.ndarray):
        return data.astype(np.uint8, copy=False).reshape(-1)
    return np.frombuffer(bytes(data), dtype=np.uint8)


# --- byte streams ------------------------------------------------------------------------------------

def bit_diff_pct(a: bytes, b: bytes) -> float:
    """Differing bits over the common length, in percent."""
    n = min(len(a), len(b))
    if n == 0:
        return 0.0
    x = np.bitwise_xor(_u8(a)[:n], _u8(b)[:n])
    return float(np.unpackbits(x).mean() * 100)


def byte_diff_pct(a: bytes, b: bytes) -> float:
    """Differing bytes ("character-level change") over the common length, in percent."""
    n = min(len(a), len(b))
    if n == 0:
        return 0.0
    return float((_u8(a)[:n] != _u8(b)[:n]).mean() * 100)


def entropy(data) -> float:
    """Shannon entropy in bits per byte. A sample of n bytes can show at most log2(n)."""
    x = _u8(data)
    if x.size == 0:
        return 0.0
    counts = np.bincount(x, minlength=256)
    p = counts[counts > 0] / x.size
    return float(-(p * np.log2(p)).sum())


def max_entropy_for(n: int) -> float:
    """The largest entropy n bytes can reach (all distinct up to 256 values)."""
    return math.log2(min(max(n, 1), 256))


def chi_square(data) -> float:
    """Uniformity of the byte histogram against 256 equal bins (lower is more uniform)."""
    x = _u8(data)
    if x.size == 0:
        return 0.0
    expected = x.size / 256
    counts = np.bincount(x, minlength=256)
    return float(((counts - expected) ** 2 / expected).sum())


def pearson(a, b) -> float:
    x, y = _u8(a).astype(np.float64), _u8(b).astype(np.float64)
    n = min(x.size, y.size)
    if n < 2:
        return 0.0
    x, y = x[:n], y[:n]
    if x.std() == 0 or y.std() == 0:
        return 0.0
    return float(np.corrcoef(x, y)[0, 1])


def histogram(data) -> list[int]:
    return np.bincount(_u8(data), minlength=256).astype(int).tolist()


# --- images ------------------------------------------------------------------------------------------

def npcr(c1: np.ndarray, c2: np.ndarray) -> float:
    """Number of Pixels Change Rate: share of positions where two cipher images differ."""
    return float((c1 != c2).mean() * 100)


def uaci(c1: np.ndarray, c2: np.ndarray) -> float:
    """Unified Average Changing Intensity."""
    return float((np.abs(c1.astype(np.int16) - c2.astype(np.int16)) / 255).mean() * 100)


def npcr_critical(pixels: int, alpha: float = 0.05) -> float:
    """Smallest NPCR that passes the randomness test for an image of `pixels` values per channel."""
    f = 255
    z = NormalDist().inv_cdf(1 - alpha)  # upper-tail quantile, 1.645 for alpha = 0.05
    return (f - z * math.sqrt(f / pixels)) / (f + 1) * 100


def uaci_interval(pixels: int, alpha: float = 0.05) -> tuple[float, float]:
    f = 255
    mu = (f + 2) / (3 * f + 3)
    var = (f + 2) * (f * f + 2 * f + 3) / (18 * (f + 1) ** 2 * pixels * f)
    z = NormalDist().inv_cdf(1 - alpha / 2)
    return ((mu - z * math.sqrt(var)) * 100, (mu + z * math.sqrt(var)) * 100)


def mse(a: np.ndarray, b: np.ndarray) -> float:
    return float(((a.astype(np.float64) - b.astype(np.float64)) ** 2).mean())


def psnr(a: np.ndarray, b: np.ndarray) -> float:
    """Peak signal-to-noise ratio in dB; infinite when the images are identical."""
    m = mse(a, b)
    return math.inf if m == 0 else 10 * math.log10(255 ** 2 / m)


DIRECTIONS = {"horizontal": (0, 1), "vertical": (1, 0), "diagonal": (1, 1)}


def adjacent_pairs(channel: np.ndarray, direction: str, n: int = 3000, seed: int = 7) -> tuple[np.ndarray, np.ndarray]:
    """n random (pixel, neighbour) pairs from one channel in the given direction."""
    dy, dx = DIRECTIONS[direction]
    h, w = channel.shape
    rng = np.random.default_rng(seed)
    n = min(n, (h - dy) * (w - dx))
    ys = rng.integers(0, h - dy, n)
    xs = rng.integers(0, w - dx, n)
    return channel[ys, xs], channel[ys + dy, xs + dx]


def adjacent_corr(channel: np.ndarray, direction: str) -> float:
    """Correlation over ALL neighbouring pairs (sampling 3,000 pairs adds +/-0.02 of noise)."""
    dy, dx = DIRECTIONS[direction]
    h, w = channel.shape
    return pearson(channel[: h - dy, : w - dx], channel[dy:, dx:])


def safe(value: float) -> float | str:
    """JSON-friendly number: infinity becomes the string "inf"."""
    if isinstance(value, float) and math.isinf(value):
        return "inf"
    return round(float(value), 6)
