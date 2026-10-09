"""Step 3 - per-client token bucket.

Keyed on the JWT `sub` when a correctly signed token is present (one bucket per
user and policy), otherwise on the source IP. Login and other unauthenticated
calls from one IP share a small bucket, which is what stops password guessing.
"""
from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass

from .base import is_guarded, meta_for, reject


@dataclass
class TokenBucket:
    capacity: float
    refill_per_sec: float
    tokens: float
    updated: float

    def take(self, now: float) -> tuple[bool, float]:
        self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.refill_per_sec)
        self.updated = now
        if self.tokens >= 1:
            self.tokens -= 1
            return True, 0.0
        return False, (1 - self.tokens) / self.refill_per_sec


class RateLimiter:
    def __init__(self):
        self._buckets: dict[str, TokenBucket] = {}
        self._lock = threading.Lock()

    def take(self, key: str, capacity: float, refill: float) -> tuple[bool, float, float]:
        now = time.monotonic()
        with self._lock:
            b = self._buckets.get(key)
            if b is None or b.capacity != capacity or b.refill_per_sec != refill:
                b = self._buckets[key] = TokenBucket(capacity, refill, capacity, now)
            ok, wait = b.take(now)
            return ok, wait, b.tokens

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()


class RateLimitMiddleware:
    def __init__(self, app, state):
        self.app = app
        self.state = state

    def bucket_for(self, meta) -> tuple[str, float, float]:
        s = self.state
        policy = s.policies.get(meta.policy_name) or s.policies.get("normal")
        if meta.actor:
            return f"user:{meta.actor}:{policy.name}", policy.rate_limit.capacity, policy.rate_limit.refill_per_sec
        if meta.path == "/api/auth/login":
            return f"ip:{meta.src_ip}:login", s.settings.login_rate_capacity, s.settings.login_rate_refill
        return f"ip:{meta.src_ip}:{policy.name}", policy.rate_limit.capacity, policy.rate_limit.refill_per_sec

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not is_guarded(scope["path"]):
            return await self.app(scope, receive, send)
        meta = meta_for(scope, self.state)
        key, capacity, refill = self.bucket_for(meta)
        ok, wait, left = self.state.limiter.take(key, capacity, refill)
        if not ok:
            retry = max(1, math.ceil(wait))
            return await reject(scope, send, self.state, "rate_limited",
                                f"bucket {key} empty ({capacity:g} cap, {refill:g}/s); retry in {retry} s",
                                "rate_limit", {"Retry-After": str(retry)})
        self.state.tracer.step(meta.trace_id, "rate_limit", f"bucket {key}: {left:.1f}/{capacity:g} tokens left")
        await self.app(scope, receive, send)
