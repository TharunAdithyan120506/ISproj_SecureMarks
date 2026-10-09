"""In-memory session store (one Uvicorn worker, so memory is the source of truth)."""
from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass


@dataclass
class SecureSession:
    session_id: str
    username: str
    policy: str
    key: bytes
    kex: str
    created: float
    expires: float

    @property
    def expires_in(self) -> int:
        return max(0, int(self.expires - time.time()))


class SessionStore:
    def __init__(self, ttl_s: int):
        self.ttl_s = ttl_s
        self._sessions: dict[str, SecureSession] = {}
        self._lock = threading.Lock()

    @staticmethod
    def new_id() -> str:
        return secrets.token_hex(16)

    def put(self, session_id: str, username: str, policy: str, key: bytes, kex: str) -> SecureSession:
        now = time.time()
        sess = SecureSession(session_id, username, policy, key, kex, now, now + self.ttl_s)
        with self._lock:
            self._purge(now)
            self._sessions[session_id] = sess
        return sess

    def get(self, session_id: str | None) -> SecureSession | None:
        if not session_id:
            return None
        with self._lock:
            sess = self._sessions.get(session_id)
            if sess and sess.expires < time.time():
                self._sessions.pop(session_id, None)
                return None
            return sess

    def __len__(self) -> int:
        return len(self._sessions)

    def _purge(self, now: float) -> None:
        for sid in [s for s, v in self._sessions.items() if v.expires < now]:
            self._sessions.pop(sid, None)
