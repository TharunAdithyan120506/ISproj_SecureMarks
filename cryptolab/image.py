"""Image encryption: RGB pixels in, cipher pixels out, and the standard image
security metrics.

The H x W x 3 uint8 pixel buffer is encrypted as one byte string; the first
H*W*3 ciphertext bytes are reshaped back into an image (the "cipher image").
Tag, nonce and any padding stay in the envelope, so decryption is exact.

Metrics, for one key:
    NPCR / UACI       plaintext sensitivity: change ONE pixel of the plain image,
                      encrypt both with the same key and nonce, compare cipher images
    entropy           per channel, plain vs cipher (ideal 8)
    correlation       adjacent pixels, horizontal / vertical / diagonal (cipher ideal 0)
    MSE / PSNR        plain vs cipher (large MSE, PSNR below ~10 dB) and
                      plain vs decrypted (MSE 0, PSNR infinite = lossless)
    key sensitivity   decrypt with a key that differs in one bit
"""
from __future__ import annotations

import io
import time

import numpy as np
from PIL import Image

from . import metrics as m
from . import schemes as sc
from .perf import mbps, median_ms

CHANNELS = ("R", "G", "B")
DEFAULT_SIDE = 256


def load(data: bytes | str, max_side: int = DEFAULT_SIDE) -> np.ndarray:
    """Decode any PIL-readable image to an RGB uint8 array, longest side <= max_side."""
    img = Image.open(io.BytesIO(data) if isinstance(data, (bytes, bytearray)) else data)
    img = img.convert("RGB")
    if max(img.size) > max_side:
        img.thumbnail((max_side, max_side), Image.Resampling.LANCZOS)
    return np.asarray(img, dtype=np.uint8).copy()


def to_png(arr: np.ndarray) -> bytes:
    buf = io.BytesIO()
    Image.fromarray(arr.astype(np.uint8)).save(buf, format="PNG", optimize=True)
    return buf.getvalue()


def channel_view(arr: np.ndarray, c: int) -> np.ndarray:
    """One channel shown in its own colour (others zeroed)."""
    out = np.zeros_like(arr)
    out[..., c] = arr[..., c]
    return out


def encrypt_image(scheme: str, key: bytes, img: np.ndarray, *, nonce: bytes | None = None) -> tuple[np.ndarray, sc.Envelope]:
    env = sc.encrypt(scheme, key, img.tobytes(), nonce=nonce)
    n = img.size
    cipher = np.frombuffer(env.body[:n], dtype=np.uint8).reshape(img.shape)
    return cipher, env


def decrypt_image(env: sc.Envelope, key: bytes, shape: tuple) -> np.ndarray:
    return np.frombuffer(sc.decrypt(env, key), dtype=np.uint8).reshape(shape)


def _one_pixel_change(img: np.ndarray, seed: int = 11) -> tuple[np.ndarray, tuple[int, int, int]]:
    rng = np.random.default_rng(seed)
    y, x, c = int(rng.integers(img.shape[0])), int(rng.integers(img.shape[1])), int(rng.integers(3))
    changed = img.copy()
    changed[y, x, c] = (int(changed[y, x, c]) + 1) % 256
    return changed, (y, x, c)


def correlations(arr: np.ndarray) -> dict:
    """{direction: {R: r, G: r, B: r, mean: r}} over every adjacent pixel pair."""
    out = {}
    for d in m.DIRECTIONS:
        vals = {ch: m.adjacent_corr(arr[..., i], d) for i, ch in enumerate(CHANNELS)}
        vals["mean"] = float(np.mean(list(vals.values())))
        out[d] = {k: round(v, 5) for k, v in vals.items()}
    return out


def scatter_samples(arr: np.ndarray, n: int = 1200) -> dict:
    """Pixel/neighbour pairs of the luminance-free R channel, for the scatter plots."""
    out = {}
    for d in m.DIRECTIONS:
        x, y = m.adjacent_pairs(arr[..., 0], d, n, seed=5)
        out[d] = [[int(a), int(b)] for a, b in zip(x, y)]
    return out


def entropies(arr: np.ndarray) -> dict:
    vals = {ch: m.entropy(arr[..., i]) for i, ch in enumerate(CHANNELS)}
    vals["all"] = m.entropy(arr)
    return {k: round(v, 5) for k, v in vals.items()}


def histograms(arr: np.ndarray) -> dict:
    return {ch: m.histogram(arr[..., i]) for i, ch in enumerate(CHANNELS)}


def analyze(img: np.ndarray, scheme: str = sc.PRIMARY, *, key: bytes | None = None, full: bool = True) -> dict:
    """Every image metric for one scheme. Returns plain JSON-ready data plus the arrays under '_arrays'."""
    key = key or sc.new_key()
    nonce = sc.new_nonce(scheme)
    h, w, _ = img.shape
    pixels = h * w

    t0 = time.perf_counter()
    cipher, env = encrypt_image(scheme, key, img, nonce=nonce)
    enc_ms = (time.perf_counter() - t0) * 1000
    t0 = time.perf_counter()
    try:
        decrypted = decrypt_image(env, key, img.shape)
    except (sc.InvalidTag, ValueError):
        decrypted = np.zeros_like(img)
    dec_ms = (time.perf_counter() - t0) * 1000
    if full and scheme != "Logistic-map":  # steadier medians for the fast schemes
        enc_ms = median_ms(lambda: sc.encrypt(scheme, key, img.tobytes(), nonce=nonce), 7, warmup=1)
        dec_ms = median_ms(lambda: sc.decrypt(env, key), 7, warmup=1)

    changed, where = _one_pixel_change(img)
    cipher2, _ = encrypt_image(scheme, key, changed, nonce=nonce)

    # key sensitivity: decrypt with a key differing in one bit
    wrong_key = bytes([key[0] ^ 0x01]) + key[1:]
    try:
        wrong = decrypt_image(env, wrong_key, img.shape)
        key_sens = {"result": "decrypted to noise", "pixels_differ_pct": round(m.npcr(img, wrong), 4)}
    except sc.InvalidTag:
        wrong = None
        key_sens = {"result": "InvalidTag: refused to decrypt (authenticated)", "pixels_differ_pct": None}
    except ValueError:  # CBC / ECB: the padding check fails, show the raw noise instead
        raw = sc.decrypt_raw(env, wrong_key)[:img.size]
        wrong = np.frombuffer(raw, dtype=np.uint8).reshape(img.shape)
        key_sens = {"result": "decrypted to noise (padding check also failed)",
                    "pixels_differ_pct": round(m.npcr(img, wrong), 4)}

    n_bytes = img.size
    lo, hi = m.uaci_interval(pixels)
    result = {
        "scheme": scheme, "kind": sc.SCHEMES[scheme]["kind"], "width": w, "height": h, "bytes": n_bytes,
        "key_fingerprint": sc.fingerprint(key),
        "envelope": env.to_json(preview=256),
        "timing": {"encrypt_ms": round(enc_ms, 3), "decrypt_ms": round(dec_ms, 3),
                   "encrypt_MBps": round(mbps(n_bytes, enc_ms), 2), "decrypt_MBps": round(mbps(n_bytes, dec_ms), 2)},
        "npcr": round(m.npcr(cipher, cipher2), 4),
        "npcr_per_channel": {ch: round(m.npcr(cipher[..., i], cipher2[..., i]), 4) for i, ch in enumerate(CHANNELS)},
        "uaci": round(m.uaci(cipher, cipher2), 4),
        "uaci_per_channel": {ch: round(m.uaci(cipher[..., i], cipher2[..., i]), 4) for i, ch in enumerate(CHANNELS)},
        "npcr_ideal": round(m.NPCR_IDEAL, 4), "uaci_ideal": round(m.UACI_IDEAL, 4),
        "npcr_critical": round(m.npcr_critical(pixels), 4), "uaci_interval": [round(lo, 4), round(hi, 4)],
        "changed_pixel": {"y": where[0], "x": where[1], "channel": CHANNELS[where[2]]},
        "entropy_plain": entropies(img), "entropy_cipher": entropies(cipher),
        "corr_plain": correlations(img), "corr_cipher": correlations(cipher),
        "mse_plain_cipher": round(m.mse(img, cipher), 3), "psnr_plain_cipher": m.safe(m.psnr(img, cipher)),
        "mse_plain_decrypted": round(m.mse(img, decrypted), 3), "psnr_plain_decrypted": m.safe(m.psnr(img, decrypted)),
        "lossless": bool(np.array_equal(img, decrypted)),
        "key_sensitivity": key_sens,
    }
    if full:
        result["hist_plain"] = histograms(img)
        result["hist_cipher"] = histograms(cipher)
        result["scatter_plain"] = scatter_samples(img)
        result["scatter_cipher"] = scatter_samples(cipher)
    result["verdict"] = verdict(result)
    result["_arrays"] = {"plain": img, "cipher": cipher, "decrypted": decrypted, "cipher_changed": cipher2,
                         "wrong_key": wrong}
    return result


def verdict(r: dict) -> dict:
    """Pass/fail of each metric against its accepted threshold."""
    lo, hi = r["uaci_interval"]
    psnr = r["psnr_plain_cipher"]
    return {
        "npcr": r["npcr"] >= r["npcr_critical"],
        "uaci": lo <= r["uaci"] <= hi,
        "entropy": r["entropy_cipher"]["all"] >= 7.99,
        "correlation": all(abs(r["corr_cipher"][d]["mean"]) < 0.01 for d in m.DIRECTIONS),
        "psnr": psnr != "inf" and psnr < 10,
        "lossless": r["lossless"],
    }


def compare(img: np.ndarray, names: list[str] | None = None) -> list[dict]:
    """One summary row (and cipher image) per scheme."""
    rows = []
    key = sc.new_key()
    for name in names or sc.NAMES:
        r = analyze(img, name, key=key, full=False)
        rows.append({
            "scheme": name, "kind": r["kind"], "npcr": r["npcr"], "uaci": r["uaci"],
            "entropy": r["entropy_cipher"]["all"], "corr_h": r["corr_cipher"]["horizontal"]["mean"],
            "corr_v": r["corr_cipher"]["vertical"]["mean"], "corr_d": r["corr_cipher"]["diagonal"]["mean"],
            "mse": r["mse_plain_cipher"], "psnr": r["psnr_plain_cipher"], **r["timing"],
            "passes": sum(r["verdict"].values()), "checks": len(r["verdict"]),
            "_cipher": r["_arrays"]["cipher"],
        })
    return rows


def sweep_sizes(img: np.ndarray, names: list[str], sides: list[int] = (64, 128, 256, 512)) -> list[dict]:
    """Encryption / decryption time and speed against image size."""
    rows = []
    key = sc.new_key()
    pil = Image.fromarray(img)
    for side in sides:
        arr = np.asarray(pil.resize((side, side), Image.Resampling.BILINEAR), dtype=np.uint8)
        data = arr.tobytes()
        for name in names:
            if name == "Logistic-map" and side > 256:
                continue
            nonce = sc.new_nonce(name)
            env = sc.encrypt(name, key, data, nonce=nonce)
            runs = 9 if name != "Logistic-map" else 3
            enc = median_ms(lambda: sc.encrypt(name, key, data, nonce=nonce), runs, warmup=1)
            dec = median_ms(lambda: sc.decrypt(env, key), runs, warmup=1)
            rows.append({"scheme": name, "side": side, "pixels": side * side, "bytes": len(data),
                         "encrypt_ms": round(enc, 4), "decrypt_ms": round(dec, 4),
                         "encrypt_MBps": round(mbps(len(data), enc), 2), "decrypt_MBps": round(mbps(len(data), dec), 2)})
    return rows


def pixel_grid(arr: np.ndarray, y: int = 0, x: int = 0, size: int = 8) -> list[list[list[int]]]:
    """size x size block of [R, G, B] values starting at (y, x)."""
    y = max(0, min(y, arr.shape[0] - size))
    x = max(0, min(x, arr.shape[1] - size))
    return arr[y:y + size, x:x + size].astype(int).tolist()
