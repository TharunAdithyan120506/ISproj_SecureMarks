"""Text encryption: encrypt/decrypt with visible ciphertext, plus the confusion,
diffusion and avalanche measurements.

Avalanche (diffusion)   flip ONE plaintext bit, same key and nonce, compare ciphertexts.
                        Ideal: 50 % of ciphertext bits and ~100 % (255/256) of bytes change.
Key sensitivity         flip ONE key bit, same plaintext and nonce. This is how confusion
(confusion)             is measured: each ciphertext bit should depend on the whole key
                        in a complex way, so ~50 % of bits change.
Diffusion map           which output bytes change when each input bit flips.

The nonce is held fixed during a measurement. That is the only way to isolate
the effect of the one flipped bit; in real use every message gets a fresh nonce.
"""
from __future__ import annotations

import os
import random
import statistics

import numpy as np

from . import metrics as m
from . import schemes as sc
from .perf import median_ms


def _flip_bit(data: bytes, bit: int) -> bytes:
    b = bytearray(data)
    b[bit // 8] ^= 1 << (7 - bit % 8)
    return bytes(b)


def encrypt_text(scheme: str, plaintext: str, *, key: bytes | None = None, aad: str = "",
                 nonce: bytes | None = None, tamper: bool = False) -> dict:
    """One full round trip, with everything shown: key, nonce, ciphertext, tag, JSON envelope."""
    key = key or sc.new_key()
    data = plaintext.encode("utf-8")
    env = sc.encrypt(scheme, key, data, nonce=nonce, aad=aad.encode())
    dec_env = env
    if tamper and env.body:
        dec_env = sc.Envelope(env.scheme, env.nonce, bytes([env.body[0] ^ 0x01]) + env.body[1:], env.tag, env.aad,
                              env.plaintext_len, env.key_fingerprint)
    runs = 50 if scheme != "Logistic-map" else 10
    enc_ms = median_ms(lambda: sc.encrypt(scheme, key, data, nonce=env.nonce, aad=env.aad), runs, warmup=1)
    dec_ms = median_ms(lambda: sc.decrypt(env, key), runs, warmup=1)
    result = {
        "scheme": scheme, "key_hex": key.hex(), "envelope": env.to_json(),
        "plaintext": plaintext, "plaintext_hex": data.hex(), "plaintext_bytes": len(data),
        "encrypt_ms": round(enc_ms, 5), "decrypt_ms": round(dec_ms, 5),
        "tampered": tamper, "decrypt_ok": False, "decrypted": None, "error": None,
        "ciphertext_entropy": round(m.entropy(env.wire), 4),
        "plaintext_entropy": round(m.entropy(data), 4),
        "max_entropy_for_length": round(m.max_entropy_for(len(env.wire)), 4),
    }
    try:
        out = sc.decrypt(dec_env, key)
        result.update(decrypt_ok=True, decrypted=out.decode("utf-8", errors="replace"),
                      matches=out == data)
    except sc.InvalidTag:
        result["error"] = "InvalidTag: the authentication tag no longer matches (tampering detected)"
    except ValueError as exc:  # bad padding after tampering CBC/ECB
        result["error"] = f"{type(exc).__name__}: {exc}"
    if tamper and result["decrypt_ok"] and not result.get("matches", True):
        result["error"] = "decrypted WITHOUT error but to the wrong plaintext: this mode has no integrity check"
    return result


def avalanche(scheme: str, plaintext: bytes, *, trials: int = 64, seed: int = 1) -> dict:
    """Flip one random plaintext bit per trial (same key + nonce); report bit- and byte-level change."""
    rng = random.Random(seed)
    key, nonce = sc.new_key(), sc.new_nonce(scheme)
    base = sc.encrypt(scheme, key, plaintext, nonce=nonce).wire
    bits, chars = [], []
    for _ in range(trials):
        flipped = _flip_bit(plaintext, rng.randrange(len(plaintext) * 8))
        other = sc.encrypt(scheme, key, flipped, nonce=nonce).wire
        bits.append(m.bit_diff_pct(base, other))
        chars.append(m.byte_diff_pct(base, other))
    return _summary(bits, chars, trials)


def key_sensitivity(scheme: str, plaintext: bytes, *, trials: int = 64, seed: int = 2) -> dict:
    """Flip one random key bit per trial (same plaintext + nonce)."""
    rng = random.Random(seed)
    key, nonce = sc.new_key(), sc.new_nonce(scheme)
    base = sc.encrypt(scheme, key, plaintext, nonce=nonce).wire
    bits, chars = [], []
    for _ in range(trials):
        other = sc.encrypt(scheme, _flip_bit(key, rng.randrange(256)), plaintext, nonce=nonce).wire
        bits.append(m.bit_diff_pct(base, other))
        chars.append(m.byte_diff_pct(base, other))
    return _summary(bits, chars, trials)


def _summary(bits: list[float], chars: list[float], trials: int) -> dict:
    return {
        "trials": trials,
        "bit_pct": round(statistics.fmean(bits), 3), "bit_sd": round(statistics.pstdev(bits), 3),
        "char_pct": round(statistics.fmean(chars), 3), "char_sd": round(statistics.pstdev(chars), 3),
        "bit_min": round(min(bits), 3), "bit_max": round(max(bits), 3),
        "samples": [round(x, 3) for x in bits],
    }


def diffusion_map(scheme: str, *, length: int = 16, samples: int = 6, seed: int = 3) -> dict:
    """matrix[i][j] = share of output bits of byte j that flip when input bit i flips.

    For a perfect diffuser every cell is ~0.5. CTR/GCM show a single diagonal,
    ECB/CBC show a block-shaped region, GCM-SIV is uniform.
    """
    rng = np.random.default_rng(seed)
    key, nonce = sc.new_key(), sc.new_nonce(scheme)
    out_len = len(sc.encrypt(scheme, key, bytes(length), nonce=nonce).wire)
    acc = np.zeros((length * 8, out_len))
    for _ in range(samples):
        p = rng.integers(0, 256, length, dtype=np.uint8).tobytes()
        base = np.frombuffer(sc.encrypt(scheme, key, p, nonce=nonce).wire, dtype=np.uint8)
        for i in range(length * 8):
            other = np.frombuffer(sc.encrypt(scheme, key, _flip_bit(p, i), nonce=nonce).wire, dtype=np.uint8)
            acc[i] += np.unpackbits(np.bitwise_xor(base, other).reshape(-1, 1), axis=1).mean(axis=1)
    acc /= samples
    return {"scheme": scheme, "input_bits": length * 8, "output_bytes": out_len,
            "matrix": np.round(acc, 3).tolist(), "mean": round(float(acc.mean()), 4)}


def ecb_repeats(scheme: str, *, blocks: int = 8) -> dict:
    """Encrypt a plaintext made of one repeated 16-byte block and count repeated ciphertext blocks."""
    block = b"MARKS:IT301=045|"
    pt = block * blocks
    env = sc.encrypt(scheme, sc.new_key(), pt)
    chunks = [env.body[i:i + 16] for i in range(0, blocks * 16, 16)]
    distinct = len(set(chunks))
    return {"plaintext_blocks": blocks, "distinct_ciphertext_blocks": distinct, "leaks_pattern": distinct < blocks}


def stats(scheme: str, plaintext: bytes) -> dict:
    """Ciphertext statistics for one encryption of `plaintext`."""
    key = sc.new_key()
    env = sc.encrypt(scheme, key, plaintext)
    ct = env.wire
    return {
        "plaintext_entropy": round(m.entropy(plaintext), 4),
        "ciphertext_entropy": round(m.entropy(ct), 4),
        "max_entropy_for_length": round(m.max_entropy_for(len(ct)), 4),
        "chi_square": round(m.chi_square(ct), 2),
        "chi_square_critical": m.CHI2_CRITICAL_255,
        "pt_ct_correlation": round(m.pearson(plaintext, env.body), 5),
        "ciphertext_bytes": len(ct), "overhead_bytes": len(ct) + len(env.nonce) - len(plaintext),
        "plaintext_histogram": m.histogram(plaintext), "ciphertext_histogram": m.histogram(ct),
    }


def compare_schemes(plaintext: bytes, *, trials: int = 48, names: list[str] | None = None) -> list[dict]:
    """One row per scheme: avalanche, key sensitivity, statistics, timing, pattern leak."""
    rows = []
    long = (plaintext * (4096 // max(len(plaintext), 1) + 1))[:4096]  # same text, repeated to 4 KB
    for name in names or sc.NAMES:
        av = avalanche(name, plaintext, trials=trials)
        ks = key_sensitivity(name, plaintext, trials=trials)
        st = stats(name, long)
        key = sc.new_key()
        env = sc.encrypt(name, key, plaintext)
        runs = 200 if name != "Logistic-map" else 30
        enc = median_ms(lambda: sc.encrypt(name, key, plaintext, nonce=env.nonce), runs)
        dec = median_ms(lambda: sc.decrypt(env, key), runs)
        rows.append({
            "scheme": name, "kind": sc.SCHEMES[name]["kind"], "authenticated": sc.SCHEMES[name]["tag"],
            "avalanche_bit_pct": av["bit_pct"], "avalanche_char_pct": av["char_pct"],
            "key_sens_bit_pct": ks["bit_pct"], "key_sens_char_pct": ks["char_pct"],
            "ciphertext_entropy_4k": st["ciphertext_entropy"], "chi_square_4k": st["chi_square"],
            "pt_ct_correlation": st["pt_ct_correlation"],
            "encrypt_us": round(enc * 1000, 2), "decrypt_us": round(dec * 1000, 2),
            "overhead_bytes": len(env.wire) + len(env.nonce) - len(plaintext),
            "leaks_pattern": ecb_repeats(name)["leaks_pattern"],
        })
    return rows


DEFAULT_TEXT = ('{"course":"IT301","roll_no":"240911608","midsem":27,"endsem":45,"total":72,'
                '"teacher":"t104","published_at":"2026-10-31T09:30:00Z"}')


def random_text(n: int) -> bytes:
    return os.urandom(n)
