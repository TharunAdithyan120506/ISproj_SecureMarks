"""Block 4: guards, error codes and auditing."""
from __future__ import annotations

import asyncio
import dataclasses
import time
import uuid

import pytest
from fastapi.testclient import TestClient

from middleware.errors import ApiError
from middleware.guards.timeout import run_with_timeout
from middleware.main import create_app


def audit_codes(app, request_id):
    return [(e["outcome"], e["code"]) for e in app.state.sm.audit.list(request_id=request_id)]


def test_protected_echo_round_trip(client_for, app):
    c = client_for("s608")
    res = c.demo_echo({"hello": "world"})
    assert res.ok and res.payload == {"echo": {"hello": "world"}}
    assert ("allowed", "ok") in audit_codes(app, res.request_id)


def test_duplicate_request_id_is_a_replay(client_for, app):
    c = client_for("s608")
    rid = str(uuid.uuid4())
    assert c.view_marks(None).ok
    first = c.call("/api/marks/view", {"roll_no": c.roll_no}, request_id=rid)
    second = c.call("/api/marks/view", {"roll_no": c.roll_no}, request_id=rid)
    assert first.ok
    assert (second.status, second.error) == (409, "replay_detected")
    assert ("denied", "replay_detected") in audit_codes(app, rid)


def test_old_timestamp_is_stale(client_for, app):
    c = client_for("s608")
    res = c.call("/api/marks/view", {"roll_no": c.roll_no}, timestamp=int(time.time()) - 100)
    assert (res.status, res.error) == (409, "stale_request")
    assert ("denied", "stale_request") in audit_codes(app, res.request_id)


def test_eleven_fast_calls_hit_the_rate_limit(client_for, app):
    c = client_for("s612")
    statuses = [c.call("/api/marks/view", {"roll_no": c.roll_no}) for _ in range(11)]
    codes = [r.status for r in statuses]
    assert codes[0] == 200 and 429 in codes
    limited = next(r for r in statuses if r.status == 429)
    assert limited.error == "rate_limited"
    assert ("denied", "rate_limited") in audit_codes(app, limited.request_id)


def test_six_megabyte_body_is_too_large(http, app):
    rid = str(uuid.uuid4())
    r = http.post("/api/marks/publish", content=b"\0" * (6 * 1024 * 1024),
                  headers={"X-Request-ID": rid, "X-Policy": "confidential", "Content-Type": "application/octet-stream"})
    assert r.status_code == 413 and r.json()["error"] == "too_large"
    assert ("denied", "too_large") in audit_codes(app, rid)


def test_flipped_ciphertext_byte_is_integrity_failed(client_for, app):
    c = client_for("s608")
    res = c.call("/api/marks/view", {"roll_no": c.roll_no}, mutate_body=lambda b: bytes([b[0] ^ 1]) + b[1:])
    assert (res.status, res.error) == (400, "integrity_failed")
    assert ("denied", "integrity_failed") in audit_codes(app, res.request_id)
    # the forged request ID was not stored as seen
    assert not app.state.sm.replay.seen(res.request_id)


def test_missing_or_bad_token_is_401(http, client_for):
    c = client_for("s608")
    c.token = c.token[:-2] + ("AA" if not c.token.endswith("AA") else "BB")
    res = c.call("/api/marks/view", {"roll_no": "240911608"})
    assert (res.status, res.error) == (401, "auth_failed")


def test_unknown_session_is_401(client_for):
    c = client_for("s608")
    c.open_session("confidential")
    c.sessions["confidential"].session_id = "00" * 16
    res = c.call("/api/marks/view", {"roll_no": "240911608"}, retry_session=False)
    assert (res.status, res.error) == (401, "session_invalid")


def test_concurrency_cap_returns_busy(settings):
    app = create_app(dataclasses.replace(settings, concurrency_cap=0))
    with TestClient(app) as http:
        r = http.post("/api/auth/login", json={"username": "x", "password": "y"}, headers={"X-Request-ID": "busy-1"})
    assert r.status_code == 503 and r.json()["error"] == "busy"
    app.state.sm.db.dispose()


def test_handler_timeout_maps_to_504():
    with pytest.raises(ApiError) as exc:
        asyncio.run(run_with_timeout(time.sleep, 0.5, timeout_s=0.05))
    assert exc.value.status == 504 and exc.value.code == "timeout"


def test_login_bucket_blocks_password_guessing(http):
    statuses = [http.post("/api/auth/login", json={"username": "t104", "password": f"guess{i}"}).status_code
                for i in range(8)]
    assert statuses[0] == 401 and 429 in statuses


def test_every_outcome_is_audited_and_chain_holds(app):
    entries = app.state.sm.audit.list(limit=1000)
    assert {"allowed", "denied"} <= {e["outcome"] for e in entries}
    ok, broken = app.state.sm.audit.verify_chain()
    assert ok, f"chain broken at {broken}"
