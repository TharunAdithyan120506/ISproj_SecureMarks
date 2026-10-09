"""Graphs for the analyser and the benchmark (matplotlib, PNG).

One visual system for every figure: light chart surface, recessive hairline
grid, thin marks, categorical hues assigned in a fixed order and tied to the
entity (a device keeps its colour in every graph), status red reserved for
error marks and always labelled.
"""
from __future__ import annotations

import logging
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
logging.getLogger("matplotlib.font_manager").setLevel(logging.ERROR)
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
from matplotlib.ticker import FuncFormatter  # noqa: E402

SURFACE = "#fcfcfb"
INK, INK_2, MUTED = "#0b0b0b", "#52514e", "#898781"
GRID, BASELINE = "#e1e0d9", "#c3c2b7"
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#4a3aa7", "#e34948"]
CRITICAL, GOOD = "#d03b3b", "#0ca30c"

DEVICE_ORDER = ["teacher-laptop", "student-laptop", "ctrl-pc", "admin-pc", "attacker"]


def device_color(device: str) -> str:
    return SERIES[DEVICE_ORDER.index(device)] if device in DEVICE_ORDER else MUTED


def _style():
    plt.rcParams.update({
        "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
        "axes.edgecolor": BASELINE, "axes.labelcolor": INK_2, "axes.titlecolor": INK,
        "axes.titlesize": 12, "axes.titleweight": "bold", "axes.titlelocation": "left", "axes.titlepad": 12,
        "axes.labelsize": 9.5, "xtick.color": MUTED, "ytick.color": MUTED, "xtick.labelsize": 8.5,
        "ytick.labelsize": 8.5, "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6,
        "axes.axisbelow": True, "axes.spines.top": False, "axes.spines.right": False,
        "legend.frameon": False, "legend.fontsize": 8.5, "legend.labelcolor": INK_2,
        "font.family": ["Segoe UI", "DejaVu Sans", "sans-serif"], "lines.linewidth": 2,
    })


def _fig(w: float = 8.0, h: float = 4.4):
    _style()
    fig, ax = plt.subplots(figsize=(w, h), dpi=130)
    ax.grid(axis="x", visible=False)
    return fig, ax


def _save(fig, path: Path, note: str | None = None) -> Path:
    if note:
        fig.text(0.01, 0.01, note, fontsize=7.5, color=MUTED, ha="left", va="bottom")
    fig.tight_layout(rect=(0, 0.03 if note else 0, 1, 1))
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path)
    plt.close(fig)
    return path


def _empty(path: Path, title: str, message: str) -> Path:
    fig, ax = _fig()
    ax.set_title(title)
    ax.axis("off")
    ax.text(0.5, 0.5, message, ha="center", va="center", color=MUTED, fontsize=10, transform=ax.transAxes)
    return _save(fig, path)


# --- analyser graphs -------------------------------------------------------------------------

def entropy_plain_vs_protected(df, path: Path) -> Path:
    """Body entropy (bits/byte): plain JSON vs AES-GCM ciphertext, small samples marked."""
    title = "Body entropy: plain JSON vs AES-GCM ciphertext"
    rows = []
    for _, r in df.iterrows():
        for side in ("req", "resp"):
            n = r[f"{side}_body_bytes"]
            kind = r[f"{side}_kind"]
            if n and kind in ("plain", "protected"):
                rows.append((kind, float(r[f"{side}_entropy"]), int(n)))
    if not rows:
        return _empty(path, title, "No /plain/* or protected bodies in this capture")
    fig, ax = _fig()
    ax.set_title(title)
    cats = [("protected", "Protected (/api/*, /demo/echo)", SERIES[0]), ("plain", "Plain (/plain/*)", SERIES[1])]
    rng = np.random.default_rng(7)
    for i, (kind, label, color) in enumerate(cats):
        pts = [(e, n) for k, e, n in rows if k == kind]
        if not pts:
            continue
        big = [e for e, n in pts if n >= 256]
        small = [e for e, n in pts if n < 256]
        if big:
            ax.scatter(i + rng.uniform(-0.18, 0.18, len(big)), big, s=46, color=color, edgecolor=SURFACE,
                       linewidth=1.5, zorder=3, label=f"{label} · body ≥ 256 B")
            ax.hlines(np.median(big), i - 0.3, i + 0.3, color=INK, linewidth=1.5, zorder=4)
            ax.annotate(f"median {np.median(big):.2f}", (i + 0.32, np.median(big)), fontsize=8.5, color=INK_2,
                        va="center")
        if small:
            ax.scatter(i + rng.uniform(-0.18, 0.18, len(small)), small, s=46, facecolor="none", edgecolor=color,
                       linewidth=1.5, zorder=3, label=f"{label} · body < 256 B (reads low)")
    ax.axhline(8.0, color=BASELINE, linewidth=1, linestyle="--")
    ax.annotate("8 bits/byte = uniformly random", (1.45, 8.0), fontsize=8, color=MUTED, va="bottom", ha="right")
    ax.set_xticks([0, 1], [c[1] for c in cats])
    ax.set_xlim(-0.6, 1.6)
    ax.set_ylim(0, 8.4)
    ax.set_ylabel("Shannon entropy (bits per byte)")
    ax.legend(loc="lower left", ncol=1)
    return _save(fig, path, "H = -Σ p_i log2 p_i over the body bytes; ciphertext ≥ 1 KB should read 7.8+, plain JSON 4-5.")


def overhead_bytes(df, path: Path) -> Path:
    """Per endpoint: mean HTTP body bytes vs mean bytes on the wire (request + response)."""
    title = "Bytes per call: body vs on the wire"
    if df.empty:
        return _empty(path, title, "No HTTP messages in this capture")
    g = df.assign(body=df.req_body_bytes + df.resp_body_bytes).groupby("path").agg(
        body=("body", "mean"), wire=("wire_bytes", "mean"), n=("path", "size")).sort_values("wire")
    g = g.tail(12)
    fig, ax = _fig(8.0, max(3.2, 0.42 * len(g) + 1.4))
    ax.set_title(title)
    ax.grid(axis="y", visible=False)
    ax.grid(axis="x", visible=True)
    y = np.arange(len(g))
    h = 0.36
    ax.barh(y + h / 2 + 0.02, g.wire, height=h, color=SERIES[0], label="bytes on the wire (frames)")
    ax.barh(y - h / 2 - 0.02, g.body, height=h, color=SERIES[1], label="HTTP body bytes")
    for yi, (w, b) in enumerate(zip(g.wire, g.body)):
        ax.annotate(f"{w:,.0f} B  (+{w - b:,.0f})", (w, yi + h / 2 + 0.02), xytext=(4, 0), textcoords="offset points",
                    fontsize=8, color=INK_2, va="center")
    ax.set_yticks(y, [f"{p}  (n={n})" for p, n in zip(g.index, g.n)])
    ax.set_xlabel("mean bytes per request + response")
    ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:,.0f}"))
    ax.set_xlim(0, g.wire.max() * 1.35)
    ax.legend(loc="lower right")
    return _save(fig, path, "Wire bytes include IP/TCP headers, HTTP headers, nonce, tag and request-ID metadata.")


def latency_by_device(df, path: Path) -> Path:
    title = "Latency by device"
    d = df.dropna(subset=["latency_ms"])
    if d.empty:
        return _empty(path, title, "No request/response pairs in this capture")
    devices = [x for x in DEVICE_ORDER if x in set(d.device)] + sorted(set(d.device) - set(DEVICE_ORDER))
    data = [d[d.device == dev].latency_ms.values for dev in devices]
    fig, ax = _fig()
    ax.set_title(title)
    bp = ax.boxplot(data, patch_artist=True, widths=0.5, showfliers=True,
                    medianprops={"color": INK, "linewidth": 1.5},
                    whiskerprops={"color": BASELINE}, capprops={"color": BASELINE},
                    flierprops={"marker": "o", "markersize": 4, "markerfacecolor": "none", "markeredgecolor": MUTED})
    for patch, dev in zip(bp["boxes"], devices):
        patch.set_facecolor(device_color(dev))
        patch.set_alpha(0.85)
        patch.set_edgecolor(SURFACE)
    for i, vals in enumerate(data, start=1):
        ax.annotate(f"p50 {np.median(vals):.1f} ms\nn={len(vals)}", (i, np.percentile(vals, 95)), xytext=(0, 8),
                    textcoords="offset points", ha="center", fontsize=8, color=INK_2)
    ax.set_xticks(range(1, len(devices) + 1), devices)
    ax.set_ylabel("request → response (ms)")
    ax.set_ylim(0, max(float(np.max(v)) for v in data) * 1.25)
    return _save(fig, path, "Latency measured from capture timestamps (first request frame to last response frame).")


def rate_timeline(df, path: Path) -> Path:
    title = "Requests per second by device (429 rate_limited marked)"
    if df.empty:
        return _empty(path, title, "No HTTP messages in this capture")
    t0 = df.req_ts.min()
    d = df.assign(sec=(df.req_ts - t0).astype(int))
    span = int(d.sec.max()) + 1
    fig, ax = _fig(8.4, 4.4)
    ax.set_title(title)
    devices = [x for x in DEVICE_ORDER if x in set(d.device)] + sorted(set(d.device) - set(DEVICE_ORDER))
    for dev in devices:
        counts = d[d.device == dev].groupby("sec").size().reindex(range(span), fill_value=0)
        ax.plot(counts.index, counts.values, color=device_color(dev), label=dev, drawstyle="steps-mid")
    limited = d[d.status == 429].groupby("sec").size()
    if not limited.empty:
        ax.scatter(limited.index, limited.values, marker="x", s=36, color=CRITICAL, linewidth=1.8, zorder=4,
                   label="429 rate_limited (count/s)")
    ax.set_xlabel("seconds since first request")
    ax.set_ylabel("requests per second")
    peak = max([d.groupby(["device", "sec"]).size().max()] + ([limited.max()] if not limited.empty else []))
    ax.set_ylim(0, peak * 1.45 + 1)  # headroom keeps the legend off the lines
    ax.legend(loc="upper left", ncol=3)
    return _save(fig, path)


# --- benchmark graphs ----------------------------------------------------------------------------

def bench_bars(groups: list[str], series: dict[str, list[float]], path: Path, title: str, ylabel: str,
               log: bool = False, note: str | None = None, fmt: str = "{:.3g}") -> Path:
    fig, ax = _fig(8.2, 4.4)
    n = len(series)
    x = np.arange(len(groups))
    w = 0.8 / max(n, 1)
    for i, (name, vals) in enumerate(series.items()):
        xs = x - 0.4 + w * (i + 0.5)
        ax.bar(xs, vals, width=w - 0.03, color=SERIES[i], label=name)
        for xi, v in zip(xs, vals):
            if v and not np.isnan(v):
                ax.annotate(fmt.format(v), (xi, v), xytext=(0, 3), textcoords="offset points", ha="center",
                            fontsize=7.5, color=INK_2)
    ax.set_xticks(x, groups)
    ax.set_ylabel(ylabel)
    if log:
        ax.set_yscale("log")
    ax.set_title(title)
    if n > 1:
        ax.legend(loc="upper left")
    return _save(fig, path, note)


def bench_lines(xlabels: list[str], series: dict[str, list[float]], path: Path, title: str, ylabel: str,
                note: str | None = None) -> Path:
    fig, ax = _fig(8.2, 4.4)
    x = np.arange(len(xlabels))
    for i, (name, vals) in enumerate(series.items()):
        ax.plot(x, vals, color=SERIES[i], marker="o", markersize=6, markeredgecolor=SURFACE, label=name)
        ax.annotate(f"{name}", (x[-1], vals[-1]), xytext=(6, 0), textcoords="offset points", fontsize=8.5,
                    color=INK_2, va="center")
    ax.set_xticks(x, xlabels)
    ax.set_ylabel(ylabel)
    ax.set_ylim(bottom=0)
    ax.set_xlim(-0.3, len(xlabels) - 0.3 + 0.9)
    ax.set_title(title)
    ax.legend(loc="upper left")
    return _save(fig, path, note)
