"""Freshness window and the seen-request-ID set (replay resistance).

A request ID is stored only after its ciphertext decrypts, so forged garbage
cannot fill the table; entries expire after 2 x the replay window.
"""
from __future__ import annotations

import threading
import time

from ..errors import ApiError


def check_freshness(timestamp_header: str | None, window_s: int, now: float | None = None) -> int:
    """Returns the request age in seconds or raises 409 stale_request."""
    if timestamp_header is None:
        raise ApiError("bad_request", "missing X-Timestamp")
    try:
        ts = int(timestamp_header)
    except ValueError as exc:
        raise ApiError("bad_request", "X-Timestamp must be integer unix seconds") from exc
    age = int((now or time.time()) - ts)
    if abs(age) > window_s:
        raise ApiError("stale_request", f"timestamp is {age} s old; window is {window_s} s")
    return age


class ReplayStore:
    def __init__(self):
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()
        self._last_purge = 0.0

    def seen(self, request_id: str) -> bool:
        with self._lock:
            expiry = self._seen.get(request_id)
            return expiry is not None and expiry > time.time()

    def add(self, request_id: str, ttl_s: float) -> bool:
        """Atomically mark as seen; False if it already was (a concurrent replay)."""
        now = time.time()
        with self._lock:
            if now - self._last_purge > 5:
                for rid in [r for r, exp in self._seen.items() if exp <= now]:
                    del self._seen[rid]
                self._last_purge = now
            if self._seen.get(request_id, 0) > now:
                return False
            self._seen[request_id] = now + ttl_s
            return True

    def __len__(self) -> int:
        return len(self._seen)
