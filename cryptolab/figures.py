"""Static PNG figures for the report and README, in the same visual system as
analysis/plots.py (light surface, hairline grid, fixed categorical order)."""
from __future__ import annotations

import math
from pathlib import Path

import numpy as np

from analysis import plots
from analysis.plots import BASELINE, CRITICAL, GOOD, INK_2, MUTED, SERIES, _fig, _save, _style, bench_bars

plt = plots.plt
SCHEME_COLOR = {"AES-256-GCM-SIV": SERIES[0], "AES-256-GCM": SERIES[1], "AES-256-CTR": SERIES[2],
                "AES-256-CBC": SERIES[3], "AES-256-ECB": SERIES[7], "Logistic-map": SERIES[6]}
CH_COLOR = {"R": "#e34948", "G": "#1baf7a", "B": "#2a78d6"}


def _short(name: str) -> str:
    return name.replace("AES-256-", "")


def _save_titled(fig, path: Path, note: str | None = None, top: float = 0.88) -> Path:
    """_save for figures with a suptitle: leave headroom so it never overlaps the panels."""
    if note:
        fig.text(0.01, 0.01, note, fontsize=7.5, color=MUTED, ha="left", va="bottom")
    fig.tight_layout(rect=(0, 0.04 if note else 0, 1, top))
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path)
    plt.close(fig)
    return path


def text_avalanche(rows: list[dict], path: Path) -> Path:
    groups = [_short(r["scheme"]) for r in rows]
    series = {"plaintext avalanche, bits %": [r["avalanche_bit_pct"] for r in rows],
              "key sensitivity, bits %": [r["key_sens_bit_pct"] for r in rows]}
    fig, ax = _fig(8.6, 4.4)
    x = np.arange(len(groups))
    w = 0.38
    for i, (name, vals) in enumerate(series.items()):
        xs = x - 0.2 + i * w
        ax.bar(xs, vals, width=w - 0.04, color=SERIES[i], label=name)
        for xi, v in zip(xs, vals):
            ax.annotate(f"{v:.1f}", (xi, v), xytext=(0, 3), textcoords="offset points", ha="center", fontsize=7.5,
                        color=INK_2)
    ax.axhline(50, color=GOOD, lw=1, ls="--")
    ax.annotate("ideal 50 %", (len(groups) - 0.5, 50), xytext=(0, 4), textcoords="offset points", ha="right",
                fontsize=8, color=GOOD)
    ax.set_xticks(x, groups)
    ax.set_ylim(0, 62)
    ax.set_ylabel("ciphertext bits changed (%)")
    ax.set_title("Avalanche and key sensitivity: one flipped bit, same nonce")
    ax.legend(loc="upper center", ncol=2)
    return _save(fig, path, "GCM and CTR are stream modes: one plaintext bit flips one ciphertext bit (plus the tag). "
                            "GCM-SIV derives its IV from the whole plaintext.")


def text_perf(rows: list[dict], path: Path, metric: str = "encrypt_ms", title: str | None = None,
              ylabel: str = "time (ms, log)") -> Path:
    fig, ax = _fig(8.6, 4.6)
    for name in dict.fromkeys(r["scheme"] for r in rows):
        pts = [r for r in rows if r["scheme"] == name]
        ax.plot([p["size_bytes"] for p in pts], [p[metric] for p in pts], marker="o", markersize=4.5,
                color=SCHEME_COLOR.get(name, MUTED), label=_short(name))
    ax.set_xscale("log", base=2)
    if metric.endswith("_ms"):
        ax.set_yscale("log")
    ax.set_xlabel("plaintext length (bytes, log2)")
    ax.set_ylabel(ylabel)
    ax.set_title(title or "Encryption time against plaintext length")
    ax.legend(loc="upper left", ncol=3)
    return _save(fig, path, "median of repeated runs, time.perf_counter(); logistic map is pure Python and capped at 256 KB")


def image_gallery(arrays: dict[str, np.ndarray], path: Path, title: str) -> Path:
    _style()
    n = len(arrays)
    fig, axes = plt.subplots(1, n, figsize=(2.3 * n, 2.75), dpi=130)
    for ax, (label, arr) in zip(np.atleast_1d(axes), arrays.items()):
        ax.imshow(arr, interpolation="nearest")
        ax.set_title(label, fontsize=9, fontweight="normal", loc="center")
        ax.axis("off")
    fig.suptitle(title, x=0.01, ha="left", fontsize=12, fontweight="bold")
    return _save_titled(fig, path, top=0.84)


def histograms(hist_plain: dict, hist_cipher: dict, path: Path) -> Path:
    _style()
    fig, axes = plt.subplots(2, 3, figsize=(10, 4.8), dpi=130, sharex=True)
    for col, ch in enumerate("RGB"):
        for row, (label, hist) in enumerate((("plain", hist_plain), ("cipher", hist_cipher))):
            ax = axes[row, col]
            ax.bar(range(256), hist[ch], width=1.0, color=CH_COLOR[ch])
            ax.set_title(f"{ch} channel, {label}", fontsize=9.5)
            ax.grid(axis="x", visible=False)
            ax.set_yticks([])
    fig.suptitle("Pixel histograms: plain vs AES-256-GCM-SIV cipher image", x=0.01, ha="left", fontsize=12,
                 fontweight="bold")
    return _save_titled(fig, path, "a flat cipher histogram means the pixel values carry no information about the image")


def correlation_scatter(sc_plain: dict, sc_cipher: dict, corr_plain: dict, corr_cipher: dict, path: Path) -> Path:
    _style()
    fig, axes = plt.subplots(2, 3, figsize=(10, 6.4), dpi=130)
    for col, d in enumerate(("horizontal", "vertical", "diagonal")):
        for row, (label, pts, corr) in enumerate((("plain", sc_plain, corr_plain), ("cipher", sc_cipher, corr_cipher))):
            ax = axes[row, col]
            p = np.array(pts[d])
            ax.scatter(p[:, 0], p[:, 1], s=2, alpha=0.5, color=SERIES[0] if row == 0 else SERIES[1], linewidths=0)
            ax.set_xlim(0, 255)
            ax.set_ylim(0, 255)
            ax.set_title(f"{d}, {label}: r = {corr[d]['R']:+.4f}", fontsize=9.5)
            ax.set_xticks([0, 128, 255])
            ax.set_yticks([0, 128, 255])
    fig.suptitle("Adjacent-pixel correlation (R channel)", x=0.01, ha="left", fontsize=12, fontweight="bold")
    return _save_titled(fig, path, "x = pixel value, y = neighbour value; r computed over every adjacent pair")


def image_scheme_metrics(rows: list[dict], path: Path, npcr_ideal: float, uaci_ideal: float) -> Path:
    _style()
    fig, axes = plt.subplots(1, 2, figsize=(10, 4.2), dpi=130)
    groups = [_short(r["scheme"]) for r in rows]
    x = np.arange(len(groups))
    for ax, key, ideal, label in ((axes[0], "npcr", npcr_ideal, "NPCR (%)"), (axes[1], "uaci", uaci_ideal, "UACI (%)")):
        vals = [r[key] for r in rows]
        ax.bar(x, vals, color=[SCHEME_COLOR.get(r["scheme"], MUTED) for r in rows], width=0.66)
        for xi, v in zip(x, vals):
            ax.annotate(f"{v:.2f}", (xi, v), xytext=(0, 3), textcoords="offset points", ha="center", fontsize=7.5,
                        color=INK_2)
        ax.axhline(ideal, color=GOOD, lw=1, ls="--")
        ax.set_xticks(x, groups, rotation=20)
        ax.set_title(f"{label}, ideal {ideal:.2f}")
        ax.grid(axis="x", visible=False)
    return _save(fig, path, "one pixel of the plain image changed by 1, encrypted with the same key and nonce")


def image_perf(rows: list[dict], path: Path) -> Path:
    fig, ax = _fig(8.6, 4.4)
    for name in dict.fromkeys(r["scheme"] for r in rows):
        pts = [r for r in rows if r["scheme"] == name]
        ax.plot([f"{p['side']}²" for p in pts], [p["encrypt_ms"] for p in pts], marker="o", markersize=5,
                color=SCHEME_COLOR.get(name, MUTED), label=_short(name))
    ax.set_yscale("log")
    ax.set_xlabel("image size (pixels, RGB)")
    ax.set_ylabel("encryption time (ms, log)")
    ax.set_title("Image encryption time against image size")
    ax.legend(loc="upper left", ncol=3)
    return _save(fig, path)


def hash_resistance(res: dict, path: Path) -> Path:
    _style()
    fig, axes = plt.subplots(1, 3, figsize=(11, 4.0), dpi=130)
    for ax, key, color in zip(axes, ("preimage", "second_preimage", "collision"), SERIES):
        rows = res[key]["rows"]
        bits = [r["bits"] for r in rows]
        ax.plot(bits, [r["log2_theory"] for r in rows], color=BASELINE, ls="--", lw=1.5, label="theory")
        ax.plot(bits, [r["log2_mean"] for r in rows], color=color, marker="o", markersize=5, label="measured")
        ax.set_xlabel("digest bits attacked (k)")
        ax.set_ylabel("log2(tries)")
        ax.set_title(res[key]["kind"], fontsize=10.5)
        ax.legend(loc="upper left")
    fig.suptitle(f"{res['algorithm']} truncated to k bits: pre-image 2^k, collision 2^(k/2)", x=0.01, ha="left",
                 fontsize=12, fontweight="bold")
    return _save_titled(fig, path, f"{res['trials']} trials per point; the full {res['digest_bits']}-bit digest would need "
                            f"2^{res['digest_bits']} and 2^{res['digest_bits'] // 2} tries")


def hash_perf(rows: list[dict], path: Path) -> Path:
    sizes = list(dict.fromkeys(r["size"] for r in rows))
    series = {}
    for r in rows:
        series.setdefault(r["algorithm"], {})[r["size"]] = r["MBps"]
    return bench_bars(sizes, {a: [v.get(s, math.nan) for s in sizes] for a, v in series.items()}, path,
                      "Hash throughput against input size", "MB/s", fmt="{:.0f}")


def signature_times(rows: list[dict], path: Path) -> Path:
    groups = [r["algorithm"] for r in rows]
    return bench_bars(groups, {"sign (median ms)": [r["sign_ms"]["median"] for r in rows],
                               "verify (median ms)": [r["verify_ms"]["median"] for r in rows]},
                      path, "Signature generation and verification time", "ms (log)", log=True,
                      note="SHA-256 digest signed; RSA verifies fast because e = 65537, Ed25519 signs fastest")


__all__ = ["CRITICAL"]
