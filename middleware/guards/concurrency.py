"""Step 1 - concurrency cap: at most 20 guarded requests in flight; when none
is free the request is refused at once with 503 busy (no queueing)."""
from __future__ import annotations

import asyncio

from .base import is_guarded, meta_for, reject


class ConcurrencyMiddleware:
    def __init__(self, app, state):
        self.app = app
        self.state = state
        self.cap = state.settings.concurrency_cap
        self.sem = asyncio.Semaphore(self.cap)
        self.in_flight = 0

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not is_guarded(scope["path"]):
            return await self.app(scope, receive, send)
        meta = meta_for(scope, self.state)
        if self.sem.locked():
            return await reject(scope, send, self.state, "busy",
                                f"all {self.cap} request slots are in use", "concurrency")
        async with self.sem:
            self.in_flight += 1
            try:
                self.state.tracer.step(meta.trace_id, "concurrency", f"slot {self.in_flight}/{self.cap}")
                await self.app(scope, receive, send)
            finally:
                self.in_flight -= 1
