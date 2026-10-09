"""The secure envelope: checks 4-9 of every protected call, plus the encrypted
response.

    secure_request(roles, min_policy, authorize)  ->  FastAPI dependency
        4 auth_jwt        JWT valid and unexpired             401 auth_failed
        5 session_lookup  exists, same user, same policy      401 session_invalid
          policy_check    session policy >= route minimum     403 policy_too_weak
        6 freshness       |now - X-Timestamp| <= window       409 stale_request
        7 replay_check    X-Request-ID not seen               409 replay_detected
        8 aesgcm_decrypt  session key + AAD                   400 integrity_failed
                          (only now is the request ID stored as seen)
        9 rbac            role + ownership                    403 forbidden

Wire format of a protected request: POST, Content-Type application/octet-stream,
body = raw AES-GCM ciphertext || tag of the JSON payload, and

    AAD = f"{method}|{path}|{session_id}|{request_id}|{timestamp}|{policy}"

so none of the bound headers can be edited without breaking decryption. The
response body is ciphertext under the same session key with a new X-Nonce and
AAD = f"resp|{request_id}".
"""
from __future__ import annotations

import json
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Callable

from fastapi import Request
from fastapi.responses import JSONResponse, Response
from starlette.concurrency import run_in_threadpool

from .auth import tokens
from .auth.rbac import Principal, require_role
from .crypto import aead
from .crypto.encoding import b64d, b64e, short
from .errors import ApiError
from .guards.base import meta_for, response_headers
from .guards.replay import check_freshness
from .guards.timeout import run_with_timeout
from .audit import READ_ONLY

PROTECTED_PLAN = ["auth_jwt", "session_lookup", "policy_check", "freshness", "replay_check", "aesgcm_decrypt", "rbac"]


def request_aad(method: str, path: str, session_id: str, request_id: str, timestamp: int | str, policy: str) -> bytes:
    return f"{method}|{path}|{session_id}|{request_id}|{timestamp}|{policy}".encode()


def response_aad(request_id: str) -> bytes:
    return f"resp|{request_id}".encode()


@dataclass
class StepRecord:
    detail: str = ""
    ok: bool | None = True


class RequestContext:
    """Per-request helper for traced steps, authentication and the final audit."""

    def __init__(self, request: Request, plan: list[str] | None = None):
        self.request = request
        self.state = request.app.state.sm
        self.meta = meta_for(request.scope, self.state)
        self.plan = list(plan or [])
        self.principal: Principal | None = None
        self.audit_detail = ""
        request.state.sm_ctx = self

    @contextmanager
    def step(self, name: str):
        rec = StepRecord()
        try:
            yield rec
        except ApiError as exc:
            self.state.tracer.step(self.meta.trace_id, name, exc.detail, ok=False)
            raise
        except Exception as exc:
            self.state.tracer.step(self.meta.trace_id, name, f"{type(exc).__name__}: {exc}", ok=False)
            raise
        self.state.tracer.step(self.meta.trace_id, name, rec.detail, ok=rec.ok)

    def authenticate(self) -> Principal:
        with self.step("auth_jwt") as st:
            if not self.meta.token:
                raise ApiError("auth_failed", "missing bearer token")
            try:
                claims = tokens.verify(self.state.settings.jwt_secret, self.meta.token)
            except tokens.TokenError as exc:
                raise ApiError("auth_failed", str(exc)) from exc
            self.principal = Principal.from_claims(claims)
            self.meta.actor, self.meta.role = self.principal.username, self.principal.role
            st.detail = f"HS256 ✓ sub={self.principal.username} role={self.principal.role} expires in {claims['exp'] - int(time.time())} s"
        return self.principal

    def ok_json(self, payload: dict, *, audit: bool = True, detail: str = "") -> JSONResponse:
        self.state.finish_ok(self.meta, detail or self.audit_detail, audit=audit)
        return JSONResponse(payload, headers=response_headers(self.meta))


class SecureRequest(RequestContext):
    """A protected call: decrypted payload, session and policy after checks 4-9."""

    def open(self, body: bytes, roles: tuple[str, ...], min_policy: str,
             authorize: Callable[[Principal, dict], str] | None) -> None:
        s, h, rid = self.state, self.meta.headers, self.meta.request_id
        principal = self.authenticate()

        with self.step("session_lookup") as st:
            sess = s.sessions.get(h.get("x-session-id"))
            if sess is None:
                raise ApiError("session_invalid", "unknown or expired session; open a new one")
            if sess.username != principal.username:
                raise ApiError("session_invalid", "session belongs to another user")
            if self.meta.policy_name != sess.policy:
                raise ApiError("session_invalid", f"X-Policy '{self.meta.policy_name}' does not match session policy '{sess.policy}'")
            st.detail = (f"session {sess.session_id[:8]}… {sess.kex} {aead.cipher_name(sess.key)} "
                         f"key {short(sess.key)} expires in {sess.expires_in} s")

        with self.step("policy_check") as st:
            if not s.policies.satisfies(sess.policy, min_policy):
                raise ApiError("policy_too_weak", f"route needs '{min_policy}', session is '{sess.policy}'")
            st.detail = f"session policy {sess.policy} ≥ route minimum {min_policy}"
        policy = s.policies.get(sess.policy)

        with self.step("freshness") as st:
            age = check_freshness(h.get("x-timestamp"), policy.replay_window_s)
            st.detail = f"X-Timestamp age {age} s ≤ {policy.replay_window_s} s window"

        with self.step("replay_check") as st:
            if s.replay.seen(rid):
                raise ApiError("replay_detected", f"request ID {rid} was already used")
            st.detail = f"request ID {rid[:8]}… not in seen set ({len(s.replay)} IDs)"

        with self.step("aesgcm_decrypt") as st:
            try:
                nonce = b64d(h.get("x-nonce", ""))
            except ValueError as exc:
                raise ApiError("bad_request", "X-Nonce must be base64 of 12 bytes") from exc
            aad = request_aad(self.meta.method, self.meta.path, sess.session_id, rid, h.get("x-timestamp"), sess.policy)
            try:
                plaintext = aead.decrypt(sess.key, nonce, body, aad)
            except aead.InvalidTag as exc:
                raise ApiError("integrity_failed", "AES-GCM tag check failed: ciphertext, nonce or a bound header was modified") from exc
            if not s.replay.add(rid, 2 * policy.replay_window_s):
                raise ApiError("replay_detected", f"request ID {rid} was already used (concurrent duplicate)")
            st.detail = (f"{aead.cipher_name(sess.key)} {len(body)} B → {len(plaintext)} B plaintext, nonce {nonce.hex()}, "
                         f"tag ✓, AAD = method|path|session|request-id|timestamp|policy")

        try:
            payload = json.loads(plaintext)
            if not isinstance(payload, dict):
                raise ValueError
        except ValueError as exc:
            raise ApiError("bad_request", "decrypted payload is not a JSON object") from exc

        with self.step("rbac") as st:
            parts = [require_role(principal, roles)]
            if authorize:
                parts.append(authorize(principal, payload))
            st.detail = "; ".join(parts)

        self.session, self.policy, self.payload = sess, policy, payload

    async def respond(self, handler: Callable[["SecureRequest"], dict]) -> Response:
        result = await run_with_timeout(handler, self, timeout_s=self.state.settings.handler_timeout_s)
        data = json.dumps(result).encode()
        with self.step("aesgcm_encrypt_response") as st:
            nonce, ct = aead.encrypt(self.session.key, data, response_aad(self.meta.request_id))
            st.detail = f"{len(data)} B → {len(ct)} B, new nonce {nonce.hex()}, AAD resp|{self.meta.request_id[:8]}…"
        audit = not (self.policy.audit == "decisions" and self.meta.action in READ_ONLY)
        self.state.finish_ok(self.meta, self.audit_detail, audit=audit)
        return Response(ct, media_type="application/octet-stream",
                        headers=response_headers(self.meta, {"X-Nonce": b64e(nonce)}))


def secure_request(roles: tuple[str, ...], min_policy: str,
                   authorize: Callable[[Principal, dict], str] | None = None,
                   handler_steps: tuple[str, ...] = ()):
    """FastAPI dependency running checks 4-9; returns the SecureRequest to the route."""

    async def dependency(request: Request) -> SecureRequest:
        ctx = SecureRequest(request, PROTECTED_PLAN + list(handler_steps) + ["aesgcm_encrypt_response"])
        body = await request.body()
        await run_in_threadpool(ctx.open, body, roles, min_policy, authorize)
        return ctx

    return dependency
