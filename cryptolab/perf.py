"""Timing helpers (time.perf_counter, warm-up runs, medians) and the size sweeps
behind the "time / speed vs plaintext length" graphs."""
from __future__ import annotations

import os
import statistics
import time

KB, MB = 1024, 1024 * 1024
TEXT_SIZES = [16, 64, 256, KB, 4 * KB, 16 * KB, 64 * KB, 256 * KB, MB]
TEXT_SIZES_FULL = TEXT_SIZES + [4 * MB, 10 * MB]


def median_ms(fn, runs: int, warmup: int = 2) -> float:
    for _ in range(warmup):
        fn()
    times = []
    for _ in range(runs):
        t0 = time.perf_counter()
        fn()
        times.append((time.perf_counter() - t0) * 1000)
    return statistics.median(times)


def timings_ms(fn, runs: int, warmup: int = 2) -> list[float]:
    """Every individual run, for distribution charts."""
    for _ in range(warmup):
        fn()
    out = []
    for _ in range(runs):
        t0 = time.perf_counter()
        fn()
        out.append((time.perf_counter() - t0) * 1000)
    return out


def runs_for(size: int) -> int:
    return 200 if size <= 10 * KB else 50 if size <= 100 * KB else 10 if size <= MB else 5 if size <= 10 * MB else 3


def mbps(size: int, ms: float) -> float:
    return size / MB / (ms / 1000) if ms > 0 else 0.0


def size_label(n: int) -> str:
    return f"{n // MB} MB" if n >= MB else f"{n // KB} KB" if n >= KB else f"{n} B"


def sweep_schemes(schemes: list[str], sizes: list[int], *, slow_cap: int = 256 * KB) -> list[dict]:
    """Encrypt and decrypt time and throughput for every scheme at every plaintext length.

    The pure-Python logistic-map cipher is capped at `slow_cap` bytes so a sweep stays fast.
    """
    from . import schemes as sc

    rows = []
    key = sc.new_key()
    for name in schemes:
        for size in sizes:
            if name == "Logistic-map" and size > slow_cap:
                continue
            data = os.urandom(size)
            nonce = sc.new_nonce(name)
            runs = runs_for(size) if name != "Logistic-map" else max(3, min(20, runs_for(size) // 10))
            env = sc.encrypt(name, key, data, nonce=nonce)
            enc = median_ms(lambda: sc.encrypt(name, key, data, nonce=nonce), runs, warmup=1)
            dec = median_ms(lambda: sc.decrypt(env, key), runs, warmup=1)
            rows.append({
                "scheme": name, "size_bytes": size, "size": size_label(size), "runs": runs,
                "encrypt_ms": round(enc, 5), "decrypt_ms": round(dec, 5),
                "encrypt_MBps": round(mbps(size, enc), 2), "decrypt_MBps": round(mbps(size, dec), 2),
                "ciphertext_bytes": len(env.body) + len(env.tag),
                "overhead_bytes": len(env.body) + len(env.tag) + len(env.nonce) - size,
            })
    return rows
