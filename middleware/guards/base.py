"""Shared plumbing for the three Starlette guard middlewares (steps 1-3).

`meta_for(scope)` parses the request headers once and caches the result on the
ASGI scope, so the guards, the secure dependency and the error handler all see
the same request ID, trace ID, device and policy.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field

from ..audit import action_for_path
from ..auth import tokens
from ..errors import STATUS, error_body

GUARDED_PREFIXES = ("/api/", "/plain/", "/demo/echo")


def is_guarded(path: str) -> bool:
    return path.startswith(GUARDED_PREFIXES)


@dataclass
class RequestMeta:
    method: str
    path: str
    src_ip: str
    device: str
    policy_name: str | None
    request_id: str
    trace_id: str
    token: str | None
    headers: dict[str, str]
    action: str
    actor: str | None = None
    role: str | None = None
    extra: dict = field(default_factory=dict)


def _headers(scope) -> dict[str, str]:
    return {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}


def meta_for(scope, state) -> RequestMeta:
    st = scope.setdefault("state", {})
    if "sm_meta" in st:
        return st["sm_meta"]
    headers = _headers(scope)
    client = scope.get("client") or ("unknown", 0)
    src_ip = client[0]
    request_id = headers.get("x-request-id") or f"srv-{uuid.uuid4()}"
    # A known simulated-device IP wins over the (spoofable) X-Device header, so a
    # replayed teacher request sent from 127.0.0.66 is attributed to the attacker.
    # The header is the fallback when loopback IPs collapse to 127.0.0.1.
    device = state.device_for_ip(src_ip)
    if device == "unknown":
        device = headers.get("x-device") or "unknown"
    meta = RequestMeta(
        method=scope.get("method", "GET"),
        path=scope.get("path", "/"),
        src_ip=src_ip,
        device=device,
        policy_name=headers.get("x-policy"),
        request_id=request_id,
        trace_id=state.tracer.begin(request_id),
        token=tokens.bearer(headers.get("authorization")),
        headers=headers,
        action=action_for_path(scope.get("path", "/")),
    )
    if meta.token:
        meta.actor = tokens.subject_if_valid(state.settings.jwt_secret, meta.token)
    st["sm_meta"] = meta
    state.tracer.headline(meta.trace_id, f"──▶ {meta.method} {meta.path}  from {meta.device} {meta.src_ip}"
                          + (f"  policy={meta.policy_name}" if meta.policy_name else ""))
    return meta


def response_headers(meta: RequestMeta, extra: dict | None = None) -> dict[str, str]:
    h = {"X-Request-ID": meta.request_id, "X-Trace-ID": meta.trace_id}
    h.update(extra or {})
    return h


async def reject(scope, send, state, code: str, detail: str, step: str, extra_headers: dict | None = None) -> None:
    """Refuse a request from inside a guard middleware: trace, audit, plain JSON."""
    meta = meta_for(scope, state)
    state.tracer.step(meta.trace_id, step, detail, ok=False)
    state.finish_error(meta, code, detail)
    body = json.dumps(error_body(code, detail, meta.request_id)).encode()
    headers = response_headers(meta, extra_headers)
    raw = [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]
    raw += [(k.lower().encode(), str(v).encode()) for k, v in headers.items()]
    await send({"type": "http.response.start", "status": STATUS[code], "headers": raw})
    await send({"type": "http.response.body", "body": body})
