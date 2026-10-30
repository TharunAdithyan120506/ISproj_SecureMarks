"""Hash functions: full digests, generation time, avalanche, and the three
resistance properties demonstrated experimentally.

A brute-force attack on an n-bit hash needs, on average:
    pre-image          find m with H(m) = h               ~2^n tries
    second pre-image   given m1, find m2 != m1, same hash ~2^n tries
    collision          find any m1 != m2, same hash       ~2^(n/2) tries (birthday bound)

Searching a full 256-bit digest is impossible, so the experiments attack the
first k bits of the real digest (k = 8 .. 32), measure the tries, compare them
with the theory line, and extrapolate to the full digest length at the hash
rate measured on this machine.

djb2 (Lab 5, exercise 1: start at 5381, multiply by 33, add each character,
keep 32 bits) is included as the weak, non-cryptographic contrast: its
collisions appear after a few tens of thousands of strings.
"""
from __future__ import annotations

import hashlib
import math
import os
import random
import statistics
import time

from . import metrics as m
from .perf import KB, MB, mbps, median_ms, runs_for, size_label

SECONDS_PER_YEAR = 365.25 * 24 * 3600


def djb2(data: bytes) -> bytes:
    h = 5381
    for byte in data:
        h = ((h << 5) + h + byte) & 0xFFFFFFFF  # h * 33 + c, masked to 32 bits
    return h.to_bytes(4, "big")


ALGORITHMS: dict[str, dict] = {
    "MD5": {"bits": 128, "fn": lambda d: hashlib.md5(d).digest(), "status": "broken: collisions in seconds (Wang et al. 2004)"},
    "SHA-1": {"bits": 160, "fn": lambda d: hashlib.sha1(d).digest(), "status": "broken: practical collision (SHAttered, 2017)"},
    "SHA-256": {"bits": 256, "fn": lambda d: hashlib.sha256(d).digest(), "status": "secure; used by SecureMarks"},
    "SHA-512": {"bits": 512, "fn": lambda d: hashlib.sha512(d).digest(), "status": "secure"},
    "SHA3-256": {"bits": 256, "fn": lambda d: hashlib.sha3_256(d).digest(), "status": "secure (Keccak sponge)"},
    "BLAKE2b": {"bits": 512, "fn": lambda d: hashlib.blake2b(d).digest(), "status": "secure"},
    "djb2": {"bits": 32, "fn": djb2, "status": "not cryptographic (Lab 5 exercise 1)"},
}
NAMES = list(ALGORITHMS)
CRYPTO = [n for n in NAMES if n != "djb2"]


def digest(alg: str, data: bytes) -> bytes:
    return ALGORITHMS[alg]["fn"](data)


def digest_all(data: bytes, names: list[str] | None = None) -> list[dict]:
    """Complete hex digest of `data` under every algorithm, with generation time."""
    rows = []
    for name in names or NAMES:
        fn = ALGORITHMS[name]["fn"]
        runs = 300 if len(data) <= 64 * KB else 20
        ms = median_ms(lambda: fn(data), runs)
        d = fn(data)
        rows.append({"algorithm": name, "bits": ALGORITHMS[name]["bits"], "hex": d.hex(),
                     "time_us": round(ms * 1000, 3), "status": ALGORITHMS[name]["status"]})
    return rows


def _flip(data: bytes, bit: int) -> bytes:
    b = bytearray(data)
    b[bit // 8] ^= 1 << (7 - bit % 8)
    return bytes(b)


def avalanche(alg: str, data: bytes, trials: int = 64, seed: int = 4) -> dict:
    """Flip one input bit, count changed output bits (ideal 50 %)."""
    rng = random.Random(seed)
    data = data or b"\x00"
    base = digest(alg, data)
    pct = [m.bit_diff_pct(base, digest(alg, _flip(data, rng.randrange(len(data) * 8)))) for _ in range(trials)]
    return {"algorithm": alg, "trials": trials, "bit_pct": round(statistics.fmean(pct), 3),
            "bit_sd": round(statistics.pstdev(pct), 3), "min": round(min(pct), 3), "max": round(max(pct), 3)}


def compare_two(alg: str, a: bytes, b: bytes) -> dict:
    """The two digests and the bit-by-bit difference grid."""
    da, db = digest(alg, a), digest(alg, b)
    bits = [((x >> (7 - i)) & 1) != ((y >> (7 - i)) & 1) for x, y in zip(da, db) for i in range(8)]
    return {"algorithm": alg, "a_hex": da.hex(), "b_hex": db.hex(), "differing_bits": sum(bits),
            "total_bits": len(bits), "pct": round(sum(bits) / len(bits) * 100, 3), "grid": bits}


def _prefix(d: bytes, k: int) -> int:
    """The first k bits of a digest as an integer."""
    head = d[:8]
    return int.from_bytes(head, "big") >> (len(head) * 8 - k)


def preimage_trial(alg: str, k: int, rng: random.Random, cap: int) -> int:
    """Tries needed to find any message whose digest starts with a random k-bit target."""
    fn = ALGORITHMS[alg]["fn"]
    target = rng.getrandbits(k)
    salt = rng.getrandbits(64).to_bytes(8, "big")
    for i in range(1, cap + 1):
        if _prefix(fn(salt + i.to_bytes(8, "big")), k) == target:
            return i
    return cap


def second_preimage_trial(alg: str, k: int, rng: random.Random, cap: int) -> int:
    """Tries to find m2 != m1 whose digest shares the first k bits of a given m1's digest."""
    fn = ALGORITHMS[alg]["fn"]
    m1 = rng.getrandbits(128).to_bytes(16, "big")
    target = _prefix(fn(m1), k)
    salt = rng.getrandbits(64).to_bytes(8, "big")
    for i in range(1, cap + 1):
        m2 = salt + i.to_bytes(8, "big")
        if m2 != m1 and _prefix(fn(m2), k) == target:
            return i
    return cap


def collision_trial(alg: str, k: int, rng: random.Random, cap: int) -> int:
    """Tries until two different messages share the first k bits (birthday attack)."""
    fn = ALGORITHMS[alg]["fn"]
    seen: dict[int, int] = {}
    salt = rng.getrandbits(64).to_bytes(8, "big")
    for i in range(1, cap + 1):
        p = _prefix(fn(salt + i.to_bytes(8, "big")), k)
        if p in seen:
            return i
        seen[p] = i
    return cap


def resistance(alg: str = "SHA-256", *, preimage_bits=(8, 10, 12, 14, 16), collision_bits=(8, 12, 16, 20, 24, 28),
               trials: int = 5, seed: int = 9) -> dict:
    """Run the three attacks on truncated digests and compare with theory."""
    rng = random.Random(seed)
    rate = hash_rate(alg)

    def run(kind, bits_list, trial_fn, theory):
        rows = []
        for k in bits_list:
            cap = int(theory(k) * 20) + 1000
            tries = [trial_fn(alg, k, rng, cap) for _ in range(trials)]
            rows.append({"bits": k, "mean_tries": round(statistics.fmean(tries), 1),
                         "median_tries": statistics.median(tries), "min": min(tries), "max": max(tries),
                         "theory": round(theory(k), 1), "log2_mean": round(math.log2(statistics.fmean(tries)), 3),
                         "log2_theory": round(math.log2(theory(k)), 3)})
        return {"kind": kind, "rows": rows}

    full = ALGORITHMS[alg]["bits"]
    return {
        "algorithm": alg, "digest_bits": full, "trials": trials, "hashes_per_second": round(rate),
        "preimage": run("pre-image", preimage_bits, preimage_trial, lambda k: 2.0 ** k),
        "second_preimage": run("second pre-image", preimage_bits, second_preimage_trial, lambda k: 2.0 ** k),
        "collision": run("collision", collision_bits, collision_trial,
                         lambda k: math.sqrt(math.pi / 2 * 2.0 ** k)),
        "extrapolation": extrapolate(alg, rate),
    }


def hash_rate(alg: str, seconds: float = 0.25) -> float:
    fn = ALGORITHMS[alg]["fn"]
    n, t0 = 0, time.perf_counter()
    while time.perf_counter() - t0 < seconds:
        for i in range(2000):
            fn(i.to_bytes(8, "big") + b"securemarks")
        n += 2000
    return n / (time.perf_counter() - t0)


def extrapolate(alg: str, rate: float | None = None) -> list[dict]:
    """Expected brute-force effort on the full digest, at this machine's hash rate."""
    rate = rate or hash_rate(alg)
    n = ALGORITHMS[alg]["bits"]
    out = []
    for kind, log2_tries in (("pre-image", n), ("second pre-image", n), ("collision", n / 2)):
        log2_years = log2_tries - math.log2(rate) - math.log2(SECONDS_PER_YEAR)
        out.append({"attack": kind, "log2_tries": log2_tries, "tries": f"2^{log2_tries:g}",
                    "years": _fmt_pow2(log2_years), "log2_years": round(log2_years, 2)})
    return out


def _fmt_pow2(log2_value: float) -> str:
    if log2_value < 0:
        secs = 2 ** log2_value * SECONDS_PER_YEAR
        return f"{secs:.3g} seconds" if secs < 3600 else f"{secs / 3600:.3g} hours"
    if log2_value < 40:
        return f"{2 ** log2_value:,.0f} years"
    return f"≈10^{log2_value * math.log10(2):.0f} years"


def lab5_dataset(n: int = 100, seed: int = 5) -> dict:
    """Lab 5 exercise 3: hash 50-100 random strings with MD5, SHA-1, SHA-256; time it; look for collisions."""
    rng = random.Random(seed)
    strings = ["".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(rng.randint(8, 32)))
               for _ in range(n)]
    rows = []
    for alg in ("MD5", "SHA-1", "SHA-256", "djb2"):
        fn = ALGORITHMS[alg]["fn"]
        t0 = time.perf_counter()
        digests = [fn(s.encode()) for s in strings]
        ms = (time.perf_counter() - t0) * 1000
        rows.append({"algorithm": alg, "strings": n, "total_ms": round(ms, 4), "per_hash_us": round(ms * 1000 / n, 3),
                     "collisions": n - len(set(digests))})
    return {"strings": n, "rows": rows}


def djb2_collision(seed: int = 6, cap: int = 2_000_000) -> dict:
    """Birthday search on the full 32-bit djb2: two different strings, same hash."""
    rng = random.Random(seed)
    seen: dict[bytes, str] = {}
    t0 = time.perf_counter()
    for i in range(1, cap + 1):
        s = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(10))
        h = djb2(s.encode())
        if h in seen and seen[h] != s:
            return {"found": True, "tries": i, "a": seen[h], "b": s, "hash": h.hex(),
                    "ms": round((time.perf_counter() - t0) * 1000, 1), "theory": round(math.sqrt(math.pi / 2 * 2 ** 32))}
        seen[h] = s
    return {"found": False, "tries": cap}


def sweep(sizes: list[int] | None = None, names: list[str] | None = None) -> list[dict]:
    """Hash time and throughput against input size."""
    sizes = sizes or [64, KB, 16 * KB, 256 * KB, MB]
    rows = []
    for name in names or CRYPTO:
        fn = ALGORITHMS[name]["fn"]
        for size in sizes:
            data = os.urandom(size)
            ms = median_ms(lambda: fn(data), runs_for(size))
            rows.append({"algorithm": name, "size_bytes": size, "size": size_label(size),
                         "time_ms": round(ms, 5), "MBps": round(mbps(size, ms), 2)})
    return rows
