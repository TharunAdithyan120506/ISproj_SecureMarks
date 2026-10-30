"""Built-in test images.

    photo     Grace Hopper portrait shipped with matplotlib (US Navy photo, public domain).
              Natural image: strong neighbour correlation, uneven histogram.
    logo      Flat-colour badge drawn here. Large uniform areas make ECB's
              pattern leak visible: identical plaintext blocks -> identical cipher blocks.
    gradient  Smooth colour ramp: the most correlated image possible.
"""
from __future__ import annotations

import io
from pathlib import Path

import matplotlib
import numpy as np
from PIL import Image, ImageDraw

SAMPLES = {
    "photo": "Portrait photo (natural image)",
    "logo": "Flat-colour badge (shows the ECB leak)",
    "gradient": "Colour gradient (maximum correlation)",
}


def photo(side: int = 256) -> np.ndarray:
    path = Path(matplotlib.get_data_path()) / "sample_data" / "grace_hopper.jpg"
    img = Image.open(path).convert("RGB")
    w, h = img.size
    s = min(w, h)
    img = img.crop(((w - s) // 2, 0, (w - s) // 2 + s, s)).resize((side, side), Image.Resampling.LANCZOS)
    return np.asarray(img, dtype=np.uint8).copy()


def logo(side: int = 256) -> np.ndarray:
    img = Image.new("RGB", (side, side), (245, 245, 247))
    d = ImageDraw.Draw(img)
    u = side / 256
    d.rounded_rectangle([28 * u, 28 * u, 228 * u, 228 * u], radius=44 * u, fill=(10, 132, 255))
    d.polygon([(128 * u, 58 * u), (186 * u, 82 * u), (186 * u, 132 * u), (128 * u, 198 * u), (70 * u, 132 * u),
               (70 * u, 82 * u)], fill=(255, 255, 255))
    d.rectangle([104 * u, 112 * u, 152 * u, 156 * u], fill=(255, 159, 10))
    d.ellipse([112 * u, 88 * u, 144 * u, 120 * u], outline=(255, 159, 10), width=max(2, int(8 * u)))
    return np.asarray(img, dtype=np.uint8).copy()


def gradient(side: int = 256) -> np.ndarray:
    y, x = np.mgrid[0:side, 0:side] / (side - 1)
    arr = np.stack([x * 255, y * 255, (1 - x) * 200 + 30], axis=-1)
    return arr.astype(np.uint8)


def get(name: str, side: int = 256) -> np.ndarray:
    return {"photo": photo, "logo": logo, "gradient": gradient}[name](side)


def png_bytes(name: str, side: int = 512) -> bytes:
    buf = io.BytesIO()
    Image.fromarray(get(name, side)).save(buf, format="PNG")
    return buf.getvalue()
