"""Turn SDK CallResults into JSON for the portal: outcome, payload, the merged
client + server inspector steps, and the exact wire envelope."""
from __future__ import annotations

import base64

from sdk.client import CallResult, SecureClient

PREVIEW = 512  # bytes of ciphertext shown inline; the download carries all of it


def merged_steps(res: CallResult, client: SecureClient | None) -> list[dict]:
    """Client-side SDK steps and the server's trace (GET /demo/trace/{id}) for one call, in time order."""
    steps = [dict(s, side=s.get("side", "client")) for s in res.trace]
    if client is not None:
        for tid in [*(res.extra.get("related_traces") or []), res.trace_id or res.request_id]:
            if tid:
                steps += [dict(s, side="server") for s in client.server_trace(tid)]
    steps.sort(key=lambda s: s.get("ts") or 0)
    t0 = (steps[0].get("ts") or 0) if steps else 0
    return [{"side": s["side"], "step": s["step"], "detail": s.get("detail") or "",
             "ok": None if s.get("ok") is None else bool(s.get("ok")),
             "t_ms": round(((s.get("ts") or t0) - t0) * 1000, 2)} for s in steps]


def wire_json(res: CallResult, *, full: bool = False) -> dict | None:
    """The protected request and response as they crossed the network, as JSON."""
    w = res.extra.get("wire")
    if not w:
        return None
    req, resp = w["request"], w["response"]
    body = req["body"] if full else req["body"][:PREVIEW]
    rbody = resp["body"] if full else resp["body"][:PREVIEW]
    return {
        "cipher": w["cipher"], "policy": w["policy"], "session_id": w["session_id"],
        "request": {
            "method": req["method"], "path": req["path"], "headers": req["headers"],
            "aad": req["aad"].decode("utf-8", errors="replace"), "nonce_hex": req["nonce"].hex(),
            "body_bytes": len(req["body"]), "ciphertext_bytes": len(req["body"]) - 16,
            "tag_hex": req["body"][-16:].hex(),
            "body_hex": body.hex(), "body_b64": base64.b64encode(body).decode(),
            "truncated": not full and len(req["body"]) > PREVIEW,
        },
        "response": {
            "status": resp["status"], "content_type": resp["content_type"], "nonce_b64": resp["nonce"],
            "body_bytes": len(resp["body"]), "body_hex": rbody.hex(),
            "truncated": not full and len(resp["body"]) > PREVIEW,
        },
    }


def call_json(res: CallResult, client: SecureClient | None, *, steps: bool = True) -> dict:
    return {
        "ok": res.ok, "status": res.status, "code": res.code, "error": res.error, "detail": res.detail,
        "elapsed_ms": round(res.elapsed_ms, 2), "request_id": res.request_id, "trace_id": res.trace_id,
        "path": res.path, "payload": res.payload,
        "steps": merged_steps(res, client) if steps else [],
        "wire": wire_json(res),
    }
