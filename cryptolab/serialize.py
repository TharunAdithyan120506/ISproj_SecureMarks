"""JSON helpers for the portal: images as data URLs, arrays stripped from results."""
from __future__ import annotations

import base64

import numpy as np

from .image import channel_view, to_png


def data_url(arr: np.ndarray | None) -> str | None:
    if arr is None:
        return None
    return "data:image/png;base64," + base64.b64encode(to_png(arr)).decode("ascii")


def channels(arr: np.ndarray) -> dict:
    return {ch: data_url(channel_view(arr, i)) for i, ch in enumerate("RGB")}


def public(result: dict) -> dict:
    """Drop private keys (those starting with '_') recursively."""
    if isinstance(result, dict):
        return {k: public(v) for k, v in result.items() if not k.startswith("_")}
    if isinstance(result, list):
        return [public(v) for v in result]
    return result
