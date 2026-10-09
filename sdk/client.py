"""SecureClient: the client SDK used by the portal, the attack scripts, the
experiments and the benchmark.

    c = SecureClient.for_role("teacher")          # binds 127.0.0.2, X-Device teacher-laptop
    c.login("t104", "teach@104")
    key = load_signing_key("t104", "teach@104")
    payload, trace, request_id = c.publish_marks(key, "IT301", "240911608", 27, 45)

Every call returns a CallResult that unpacks to (payload, trace, request_id)
and also carries .status, .error, .elapsed_ms and .trace_id. `trace` is the
client-side half of the inspector; the server half comes from /demo/trace.
"""
from __future__ import annotations

import json
import socket
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import httpx
import yaml

from middleware.crypto import aead, kex, sign
from middleware.crypto.canonical import build_record, canonical_record
from middleware.crypto.encoding import b64d, b64e, short
from middleware.crypto.hashing import sha256, sha256_hex
from middleware.secure import request_aad, response_aad
from middleware.settings import ROOT, load_settings


# --- results ---------------------------------------------------------------------

@dataclass
class CallResult:
    payload: dict | None
    trace: list[dict]
    request_id: str
    status: int = 0
    error: str | None = None
    detail: str | None = None
    elapsed_ms: float = 0.0
    trace_id: str | None = None
    path: str = ""
    extra: dict = field(default_factory=dict)

    def __iter__(self):
        yield self.payload
        yield self.trace
        yield self.request_id

    @property
    def ok(self) -> bool:
        return self.status == 200

    @property
    def code(self) -> str:
        return "ok" if self.ok else (self.error or f"http_{self.status}")

    def summary(self) -> str:
        return f"{self.status} {self.code}" + (f" - {self.detail}" if self.detail and not self.ok else "")


@dataclass
class Session:
    session_id: str
    policy: str
    key: bytes
    expires_at: float
    kex: str

    @property
    def valid(self) -> bool:
        return time.time() < self.expires_at - 5


def _step(trace: list, step: str, detail: str, ok: bool | None = True) -> None:
    trace.append({"side": "client", "step": step, "detail": detail, "ok": ok, "ts": time.time()})


# --- helpers ------------------------------------------------------------------------

def load_devices() -> dict:
    return yaml.safe_load((ROOT / "config" / "devices.yaml").read_text(encoding="utf-8"))


def load_accounts() -> dict:
    return yaml.safe_load((ROOT / "config" / "demo_accounts.yaml").read_text(encoding="utf-8"))


def can_bind(ip: str) -> bool:
    try:
        with socket.socket() as s:
            s.bind((ip, 0))
        return True
    except OSError:
        return False


def load_signing_key(username: str, password: str, alg: str = "Ed25519", keys_dir: Path | None = None):
    """The teacher's private key lives only on the teacher's device, encrypted with their password."""
    keys_dir = keys_dir or load_settings().client_keys_dir
    name = f"{username}_ed25519.pem" if alg == "Ed25519" else f"{username}_rsa.pem"
    return sign.load_private_pem((keys_dir / name).read_bytes(), password)


# --- the client -------------------------------------------------------------------------

class SecureClient:
    def __init__(self, base_url: str | None = None, device_ip: str | None = None, device_label: str = "client",
                 *, http: httpx.Client | None = None, verify: bool | str = True, timeout: float = 20.0,
                 save_last_request: bool = True):
        settings = load_settings()
        self.settings = settings
        self.base_url = (base_url or settings.server_url).rstrip("/")
        self.device_label = device_label
        self.device_ip = device_ip if device_ip and can_bind(device_ip) else None
        self.bound = self.device_ip is not None
        if http is None:
            if self.base_url.startswith("https") and verify is True:
                verify = str(settings.secrets_dir / "server.crt")
            transport = httpx.HTTPTransport(local_address=self.device_ip, verify=verify, retries=0)
            http = httpx.Client(base_url=self.base_url, transport=transport, timeout=timeout,
                                headers={"User-Agent": f"SecureMarks-SDK/1.0 ({device_label})"})
        self.http = http
        self.save_last_request = save_last_request and settings.demo_mode
        self.token: str | None = None
        self.username: str | None = None
        self.role: str | None = None
        self.roll_no: str | None = None
        self.courses: list[str] = []
        self.token_expires_at = 0.0
        self.sessions: dict[str, Session] = {}
        self._key_cache: dict[tuple, dict] = {}

    @classmethod
    def for_role(cls, role: str, base_url: str | None = None, **kw) -> "SecureClient":
        dev = load_devices()["roles"][role]
        return cls(base_url, dev["ip"], dev["label"], **kw)

    def close(self) -> None:
        self.http.close()

    # --- plumbing --------------------------------------------------------------------------

    def _headers(self, request_id: str, policy: str | None = None, auth: bool = True) -> dict:
        h = {"X-Request-ID": request_id, "X-Device": self.device_label}
        if policy:
            h["X-Policy"] = policy
        if auth and self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def _send(self, method: str, path: str, *, request_id: str, headers: dict, content: bytes | None = None,
              json_body=None) -> tuple[httpx.Response | None, float, bytes, str | None]:
        req = self.http.build_request(method, path, headers=headers, content=content, json=json_body)
        t0 = time.perf_counter()
        try:
            resp = self.http.send(req)
            return resp, (time.perf_counter() - t0) * 1000, _raw_request(req), None
        except httpx.HTTPError as exc:
            return None, (time.perf_counter() - t0) * 1000, _raw_request(req), f"{type(exc).__name__}: {exc}"

    @staticmethod
    def _error(resp: httpx.Response) -> tuple[str, str]:
        try:
            body = resp.json()
            return body.get("error", f"http_{resp.status_code}"), body.get("detail", "")
        except ValueError:
            return f"http_{resp.status_code}", resp.text[:200]

    def plain_call(self, method: str, path: str, json_body=None, *, auth: bool = True, policy: str | None = None,
                   request_id: str | None = None, content: bytes | None = None) -> CallResult:
        rid = request_id or str(uuid.uuid4())
        trace: list[dict] = []
        headers = self._headers(rid, policy, auth)
        if content is not None:
            headers["Content-Type"] = "application/json"
        _step(trace, "send", f"{method} {path} plain JSON from {self.device_label} {self.device_ip or '127.0.0.1'}")
        resp, ms, _raw, err = self._send(method, path, request_id=rid, headers=headers, json_body=json_body, content=content)
        if resp is None:
            return CallResult(None, trace, rid, 0, "connection_error", err, ms, path=path)
        result = CallResult(None, trace, rid, resp.status_code, elapsed_ms=ms,
                            trace_id=resp.headers.get("x-trace-id"), path=path)
        if resp.status_code == 200:
            result.payload = resp.json()
        else:
            result.error, result.detail = self._error(resp)
        return result

    # --- login and handshake -------------------------------------------------------------------

    def login(self, username: str, password: str) -> CallResult:
        res = self.plain_call("POST", "/api/auth/login", {"username": username, "password": password}, auth=False)
        if res.ok:
            p = res.payload
            self.token, self.username, self.role = p["token"], username, p["role"]
            self.roll_no, self.courses = p.get("roll_no"), p.get("courses") or []
            self.token_expires_at = time.time() + p["expires_in"]
            self.sessions.clear()
            _step(res.trace, "login", f"JWT received for {username} ({self.role}), expires in {p['expires_in']} s")
        else:
            _step(res.trace, "login", f"{res.status} {res.error}", ok=False)
        return res

    def open_session(self, policy: str = "confidential") -> CallResult:
        rid = str(uuid.uuid4())
        trace: list[dict] = []
        if policy == "legacy-rsa":
            srv = self.plain_call("GET", "/api/keys/server")
            if not srv.ok:
                return srv
            secret = kex.rsa_session_secret()
            wrapped = kex.rsa_wrap(b64d(srv.payload["public_key_b64"]), secret)
            _step(trace, "rsa_oaep_wrap", f"random 32 B secret {short(secret)} wrapped to {len(wrapped)} B "
                                          f"for server key {srv.payload['fingerprint']}")
            body = {"policy": policy, "wrapped_key_b64": b64e(wrapped)}
        else:
            priv, pub = kex.x25519_keypair()
            _step(trace, "x25519_keypair", f"fresh client keypair, public {short(pub)}")
            body = {"policy": policy, "client_pub_b64": b64e(pub)}
        res = self.plain_call("POST", "/api/session", body, policy=policy, request_id=rid)
        res.trace = trace + res.trace
        if not res.ok:
            _step(res.trace, "handshake", f"{res.status} {res.error}", ok=False)
            return res
        p = res.payload
        if policy == "legacy-rsa":
            shared = secret
        else:
            server_pub = b64d(p["server_pub_b64"])
            shared = kex.x25519_shared(priv, server_pub)
        key = kex.hkdf_derive(shared, kex.session_salt(p["session_id"]), p["key_len"])
        _step(res.trace, "hkdf_derive", f"shared {short(shared)} → HKDF-SHA256 → {p['key_len']} B session key {short(key)} "
                                        f"(session {p['session_id'][:8]}…)")
        self.sessions[policy] = Session(p["session_id"], policy, key, time.time() + p["expires_in"], p["key_exchange"])
        return res

    def session(self, policy: str, trace: list | None = None) -> tuple[Session | None, CallResult | None]:
        """The cached session for `policy`, or a fresh handshake (returned so errors surface)."""
        sess = self.sessions.get(policy)
        if sess and sess.valid:
            return sess, None
        res = self.open_session(policy)
        if trace is not None:
            trace.extend(res.trace)
        return (self.sessions.get(policy) if res.ok else None), res

    # --- protected calls ----------------------------------------------------------------------------

    def call(self, path: str, payload: dict, *, policy: str = "confidential",
             mutate_body: Callable[[bytes], bytes] | None = None, request_id: str | None = None,
             timestamp: int | None = None, pre_trace: list | None = None, retry_session: bool = True) -> CallResult:
        trace: list[dict] = list(pre_trace or [])
        rid = request_id or str(uuid.uuid4())
        sess, handshake = self.session(policy, trace)
        if sess is None:
            return CallResult(None, trace, handshake.request_id, handshake.status, handshake.error,
                              f"handshake failed: {handshake.detail}", handshake.elapsed_ms,
                              trace_id=handshake.trace_id, path="/api/session")
        ts = int(timestamp if timestamp is not None else time.time())
        data = json.dumps(payload, separators=(",", ":")).encode()
        aad = request_aad("POST", path, sess.session_id, rid, ts, policy)
        nonce, ct = aead.encrypt(sess.key, data, aad)
        _step(trace, "aesgcm_encrypt", f"{aead.cipher_name(sess.key)} {len(data)} B → {len(ct)} B "
                                       f"(ciphertext {len(ct) - 16} B + tag {ct[-16:].hex()[:16]}…), nonce {nonce.hex()}")
        if mutate_body is not None:
            ct = mutate_body(ct)
            _step(trace, "mutate_body", f"attack hook changed the body on the wire ({len(ct)} B)", ok=False)
        headers = self._headers(rid, policy)
        headers.update({"Content-Type": "application/octet-stream", "X-Session-ID": sess.session_id,
                        "X-Timestamp": str(ts), "X-Nonce": b64e(nonce)})
        _step(trace, "send", f"POST {path} {len(ct)} B octet-stream, request ID {rid[:8]}…, from {self.device_label} "
                             f"{self.device_ip or '127.0.0.1'}")
        resp, ms, raw, err = self._send("POST", path, request_id=rid, headers=headers, content=ct)
        if self.save_last_request and path == "/api/marks/publish" and mutate_body is None:
            self._save_last_request(raw, rid, path)
        if resp is None:
            return CallResult(None, trace, rid, 0, "connection_error", err, ms, path=path)

        result = CallResult(None, trace, rid, resp.status_code, elapsed_ms=ms,
                            trace_id=resp.headers.get("x-trace-id"), path=path)
        result.extra.update(request_bytes=len(ct), response_bytes=len(resp.content),
                            related_traces=[handshake.trace_id] if handshake and handshake.trace_id else [])
        if resp.status_code == 200:
            try:
                plain = aead.decrypt(sess.key, b64d(resp.headers["x-nonce"]), resp.content, response_aad(rid))
                result.payload = json.loads(plain)
                _step(trace, "aesgcm_decrypt_response", f"{len(resp.content)} B → {len(plain)} B, tag ✓, AAD resp|{rid[:8]}…")
            except (aead.InvalidTag, KeyError, ValueError) as exc:
                _step(trace, "aesgcm_decrypt_response", f"response failed integrity check ({type(exc).__name__})", ok=False)
                result.status, result.error = 0, "response_integrity_failed"
        else:
            result.error, result.detail = self._error(resp)
            if result.error == "session_invalid" and retry_session:
                self.sessions.pop(policy, None)
                _step(trace, "session_retry", "server lost the session; opening a new one")
                return self.call(path, payload, policy=policy, mutate_body=mutate_body, timestamp=timestamp,
                                 pre_trace=trace, retry_session=False)
        return result

    def _save_last_request(self, raw: bytes, rid: str, path: str) -> None:
        out = self.settings.captures_dir
        out.mkdir(parents=True, exist_ok=True)
        (out / "last_request.bin").write_bytes(raw)
        (out / "last_request.json").write_text(json.dumps({
            "request_id": rid, "path": path, "saved_at": time.time(), "device": self.device_label,
            "base_url": self.base_url}), encoding="utf-8")

    # --- marks ------------------------------------------------------------------------------------------

    def publish_marks(self, signing_key, course: str, roll_no: str, midsem: int, endsem: int, *,
                      policy: str | None = None, mutate_body=None, record: dict | None = None) -> CallResult:
        trace: list[dict] = []
        record = record or build_record(course, roll_no, midsem, endsem, teacher=self.username)
        _step(trace, "build_record", f"{record['course']} · roll {record['roll_no']} · {len(record)} fields · "
                                     f"published_at {record['published_at']}")
        canon = canonical_record(record)
        _step(trace, "canonicalize", f"sorted-key compact JSON, {len(canon)} B")
        digest = sha256(canon)
        _step(trace, "sha256", digest.hex())
        alg, signature = sign.sign(signing_key, digest)
        _step(trace, "ed25519_sign" if alg == sign.ED25519 else "rsa_pss_sign",
              f"{alg} signature {len(signature)} B: {signature.hex()[:32]}…")
        policy = policy or ("legacy-rsa" if alg == sign.RSA_PSS else "confidential")
        payload = {"record": record, "signature_b64": b64e(signature), "sig_alg": alg}
        return self.call("/api/marks/publish", payload, policy=policy, mutate_body=mutate_body, pre_trace=trace)

    def signing_key_info(self, username: str, fingerprint: str | None = None) -> dict | None:
        cache_key = (username, fingerprint)
        if cache_key not in self._key_cache:
            q = f"?fingerprint={fingerprint}" if fingerprint else ""
            res = self.plain_call("GET", f"/api/keys/signing/{username}{q}")
            if not res.ok:
                return None
            self._key_cache[cache_key] = res.payload
        return self._key_cache[cache_key]

    def view_marks(self, roll_no: str | None = None) -> CallResult:
        roll_no = roll_no or self.roll_no
        res = self.call("/api/marks/view", {"roll_no": roll_no})
        if not res.ok:
            return res
        self._key_cache.clear()  # pick up revocations
        for item in res.payload.get("records", []):
            self._verify_record(item, res.trace)
        return res

    def _verify_record(self, item: dict, trace: list) -> None:
        """Student-side end-to-end check: recompute the hash, verify the teacher's signature."""
        record = item["record"]
        try:
            canon = canonical_record(record)
        except ValueError as exc:
            canon = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
            item["record_error"] = str(exc)
        digest = sha256(canon)
        sha_ok = digest.hex() == item["sha256"]
        _step(trace, "sha256_recompute", f"{record['course']}: {digest.hex()[:16]}… "
                                         f"{'matches' if sha_ok else 'DIFFERS FROM'} server's {item['sha256'][:16]}…", ok=sha_ok)
        key = self.signing_key_info(item["signer"], item.get("key_fingerprint"))
        sig_ok = False
        if key is not None:
            try:
                sign.verify(item["sig_alg"], b64d(key["public_key_b64"]), b64d(item["signature_b64"]), digest)
                sig_ok = True
            except sign.InvalidSignature:
                pass
        step = "ed25519_verify" if item["sig_alg"] == sign.ED25519 else "rsa_pss_verify"
        _step(trace, step, f"{item['sig_alg']} by {item['signer']} key {item.get('key_fingerprint')}: "
                           f"{'valid' if sig_ok else 'INVALID'}", ok=sig_ok)
        item.update(verified=sha_ok and sig_ok, sha_ok=sha_ok, signature_ok=sig_ok,
                    signer_fingerprint=key["fingerprint"] if key else None,
                    signer_key_status=key["status"] if key else "unknown",
                    signer_revoked_at=key.get("revoked_at") if key else None)

    def verify_record(self, record_id: int) -> CallResult:
        return self.call("/api/marks/verify", {"record_id": record_id}, policy="normal")

    def audit_list(self, limit: int = 100, since_id: int = 0, **filters) -> CallResult:
        return self.call("/api/audit/list", {"limit": limit, "since_id": since_id, **filters}, policy="normal")

    def keys_list(self) -> CallResult:
        return self.call("/api/admin/keys/list", {}, policy="normal")

    def rotate_data_key(self) -> CallResult:
        return self.call("/api/admin/keys/rotate", {}, policy="normal")

    def revoke_signing(self, username: str) -> CallResult:
        return self.call("/api/admin/signing/revoke", {"username": username}, policy="normal")

    # --- baseline and demo helpers ------------------------------------------------------------------------

    def plain_publish(self, record: dict) -> CallResult:
        return self.plain_call("POST", "/plain/publish", record, auth=False)

    def plain_view(self, roll_no: str) -> CallResult:
        return self.plain_call("GET", f"/plain/marks/{roll_no}", auth=False)

    def plain_echo(self, data) -> CallResult:
        return self.plain_call("POST", "/plain/echo", {"data": data}, auth=False)

    def demo_echo(self, data) -> CallResult:
        return self.call("/demo/echo", {"data": data}, policy="normal")

    def server_trace(self, trace_id: str) -> list[dict]:
        try:
            r = self.http.get(f"/demo/trace/{trace_id}", headers={"Authorization": f"Bearer {self.token}"})
            return r.json().get("steps", []) if r.status_code == 200 else []
        except (httpx.HTTPError, ValueError):
            return []

    def health(self) -> dict | None:
        try:
            r = self.http.get("/health", timeout=2)
            return r.json() if r.status_code == 200 else None
        except (httpx.HTTPError, ValueError):
            return None


def _raw_request(req: httpx.Request) -> bytes:
    """The exact HTTP/1.1 bytes httpx puts on the wire (used by replay.py --last)."""
    target = req.url.raw_path.decode("ascii")
    head = f"{req.method} {target} HTTP/1.1\r\n".encode()
    head += b"".join(k + b": " + v + b"\r\n" for k, v in req.headers.raw)
    return head + b"\r\n" + (req.content or b"")
