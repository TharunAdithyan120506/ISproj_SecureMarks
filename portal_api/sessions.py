"""One portal session per browser tab: its SecureClient, unlocked signing keys and last results."""
from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field

from fastapi import Header, HTTPException

from sdk.client import SecureClient, load_accounts, load_devices, load_signing_key

ROLE_LABEL = {"teacher": "Teacher", "student": "Student", "ctrl": "Exam controller", "admin": "Admin"}
IDLE_S = 4 * 3600


@dataclass
class PortalSession:
    sid: str
    client: SecureClient | None = None
    signing_key: object | None = None
    signing_key_rsa: object | None = None
    user: dict | None = None
    last: dict = field(default_factory=dict)  # last wire envelopes, for downloads
    touched: float = field(default_factory=time.time)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def logout(self) -> None:
        if self.client is not None:
            self.client.close()
        self.client = self.signing_key = self.signing_key_rsa = self.user = None
        self.last.clear()

    def me(self) -> dict | None:
        if not self.user or self.client is None:
            return None
        c = self.client
        sess = c.sessions.get("confidential") or c.sessions.get("normal")
        return {**self.user, "label": ROLE_LABEL[self.user["role"]],
                "token_expires_in": max(0, int(c.token_expires_at - time.time())),
                "session": {"id": sess.session_id[:8], "kex": sess.kex, "policy": sess.policy,
                            "expires_in": max(0, int(sess.expires_at - time.time()))} if sess else None}


_sessions: dict[str, PortalSession] = {}
_lock = threading.Lock()


def get_session(x_portal_session: str | None = Header(default=None)) -> PortalSession:
    sid = (x_portal_session or "").strip()
    if not sid or len(sid) > 64:
        raise HTTPException(400, "missing X-Portal-Session header")
    with _lock:
        _expire()
        s = _sessions.get(sid)
        if s is None:
            s = _sessions[sid] = PortalSession(sid)
        s.touched = time.time()
        return s


def _expire() -> None:
    now = time.time()
    for sid in [k for k, v in _sessions.items() if now - v.touched > IDLE_S]:
        _sessions.pop(sid).logout()


def login(s: PortalSession, username: str, password: str) -> tuple[bool, str]:
    accounts = load_accounts()
    role = accounts.get(username, {}).get("role", "student")
    c = SecureClient.for_role(role)
    res = c.login(username, password)
    if not res.ok:
        c.close()
        return False, f"{res.status} {res.code}" + (f": {res.detail}" if res.detail else "")
    signing_key = rsa_key = None
    if c.role == "teacher":
        try:
            signing_key = load_signing_key(username, password)
            rsa_key = load_signing_key(username, password, alg="RSA-PSS-2048")
        except (FileNotFoundError, ValueError) as exc:
            c.close()
            return False, f"signed in, but the signing key could not be unlocked: {exc}"
    dev = load_devices()["roles"][c.role]
    s.logout()
    s.client, s.signing_key, s.signing_key_rsa = c, signing_key, rsa_key
    s.user = {"username": username, "role": c.role, "roll_no": c.roll_no, "courses": c.courses,
              "device": dev["label"], "ip": dev["ip"], "bound": c.bound}
    return True, "ok"


def require(s: PortalSession, *roles: str) -> SecureClient:
    if not s.user or s.client is None:
        raise HTTPException(401, "sign in first")
    if roles and s.user["role"] not in roles:
        raise HTTPException(403, f"this page is for {' / '.join(ROLE_LABEL[r] for r in roles)}")
    if s.client.token_expires_at - time.time() < 30:
        raise HTTPException(401, "your 15-minute token expired; sign in again")
    return s.client


def new_id() -> str:
    return uuid.uuid4().hex
