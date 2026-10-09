"""Step 2 - payload size cap: the policy's max_payload_kb, never above the global
5 MB hard cap. Oversized bodies are drained (bounded) before the 413 so the
client sees a clean response rather than a reset; chunked bodies are counted."""
from __future__ import annotations

from .base import is_guarded, meta_for, reject

DRAIN_LIMIT = 16 * 1024 * 1024


class SizeLimitMiddleware:
    def __init__(self, app, state):
        self.app = app
        self.state = state

    def cap_for(self, policy_name: str | None) -> tuple[int, str]:
        hard = self.state.settings.hard_cap_bytes
        policy = self.state.policies.get(policy_name)
        if policy is None:
            return hard, "global hard cap"
        return min(policy.max_payload_bytes, hard), f"policy {policy.name}"

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not is_guarded(scope["path"]):
            return await self.app(scope, receive, send)
        meta = meta_for(scope, self.state)
        cap, source = self.cap_for(meta.policy_name)
        declared = meta.headers.get("content-length")

        if declared is not None:
            try:
                length = int(declared)
            except ValueError:
                return await reject(scope, send, self.state, "too_large", "invalid Content-Length", "size_cap")
            if length > cap:
                await _drain(receive, DRAIN_LIMIT)
                return await reject(scope, send, self.state, "too_large",
                                    f"{length} B > {cap} B ({source})", "size_cap")
            self.state.tracer.step(meta.trace_id, "size_cap", f"{length} B ≤ {cap // 1024} KB ({source})")
            return await self.app(scope, receive, send)

        # No Content-Length (chunked or bodiless): count while buffering, bounded.
        body, more, total = [], True, 0
        while more:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            total += len(chunk)
            if total > cap:
                await _drain(receive, DRAIN_LIMIT)
                return await reject(scope, send, self.state, "too_large",
                                    f"chunked body exceeded {cap} B ({source})", "size_cap")
            body.append(chunk)
            more = message.get("more_body", False)
        self.state.tracer.step(meta.trace_id, "size_cap", f"{total} B ≤ {cap // 1024} KB ({source})")
        replayed = False

        async def replay_receive():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": b"".join(body), "more_body": False}
            return await receive()

        return await self.app(scope, replay_receive, send)


async def _drain(receive, limit: int) -> None:
    seen = 0
    while seen < limit:
        message = await receive()
        if message["type"] != "http.request":
            return
        seen += len(message.get("body", b""))
        if not message.get("more_body", False):
            return
