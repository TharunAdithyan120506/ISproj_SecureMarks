"""Error codes. Every failed check raises an ApiError, which is caught exactly
once (in main.py's handler or a guard middleware), audited, and returned as
plain JSON `{"error", "detail", "request_id"}`. Error bodies are readable in
Wireshark on purpose: they never carry secrets."""
from __future__ import annotations

STATUS = {
    "bad_request": 400,
    "integrity_failed": 400,
    "bad_signature": 400,
    "auth_failed": 401,
    "session_invalid": 401,
    "forbidden": 403,
    "policy_too_weak": 403,
    "key_revoked": 403,
    "not_found": 404,
    "stale_request": 409,
    "replay_detected": 409,
    "too_large": 413,
    "rate_limited": 429,
    "record_integrity_failed": 500,
    "dek_unavailable": 500,
    "internal_error": 500,
    "busy": 503,
    "timeout": 504,
}


class ApiError(Exception):
    def __init__(self, code: str, detail: str = "", *, action: str | None = None, headers: dict | None = None):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.status = STATUS[code]
        self.detail = detail
        self.action = action  # overrides the route's audit action (e.g. idor_blocked)
        self.headers = headers or {}


def error_body(code: str, detail: str, request_id: str) -> dict:
    return {"error": code, "detail": detail, "request_id": request_id}
