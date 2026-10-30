"""Audit log: one row per decision, hash-chained (P1).

entry_hash = SHA-256(prev_hash + canonical entry), so editing or deleting any
row breaks every later hash; `verify_chain()` recomputes it for audit/list.
Never stores plaintext marks, passwords or keys: `detail` holds codes and
reasons only.
"""
from __future__ import annotations

import hashlib
import threading
import time

from sqlalchemy import select

from .crypto.canonical import canonical
from .db.models import AuditLog
from .db.session import Database

GENESIS = "0" * 64

ACTIONS = {
    "/api/auth/login": "login",
    "/api/session": "session_open",
    "/api/policies": "policies",
    "/api/marks/publish": "marks_publish",
    "/api/marks/view": "marks_view",
    "/api/marks/verify": "marks_verify",
    "/api/marks/attachment": "attachment_view",
    "/api/audit/list": "audit_list",
    "/api/admin/keys/list": "keys_list",
    "/api/admin/keys/rotate": "keys_rotate",
    "/api/admin/signing/revoke": "signing_revoke",
    "/plain/publish": "plain_publish",
    "/plain/echo": "plain_echo",
    "/demo/echo": "demo_echo",
}
READ_ONLY = {"audit_list", "keys_list", "policies", "key_lookup"}


def action_for_path(path: str) -> str:
    if path in ACTIONS:
        return ACTIONS[path]
    if path.startswith("/plain/marks/"):
        return "plain_view"
    if path.startswith("/api/keys/"):
        return "key_lookup"
    return path.strip("/").replace("/", "_") or "root"


def _entry_payload(e: dict) -> dict:
    return {k: e.get(k) for k in ("ts", "request_id", "actor", "role", "src_ip", "device", "action", "outcome", "code", "detail")}


def entry_hash(prev_hash: str, entry: dict) -> str:
    return hashlib.sha256(prev_hash.encode() + canonical(_entry_payload(entry))).hexdigest()


class AuditLogWriter:
    def __init__(self, db: Database):
        self.db = db
        self._lock = threading.Lock()

    def record(self, *, request_id: str, action: str, outcome: str, code: str, actor: str | None = None,
               role: str | None = None, src_ip: str | None = None, device: str | None = None,
               detail: str | None = None) -> dict:
        t0 = time.perf_counter()
        entry = {
            "ts": round(time.time(), 6), "request_id": request_id, "actor": actor, "role": role,
            "src_ip": src_ip, "device": device, "action": action, "outcome": outcome, "code": code,
            "detail": (detail or "")[:500],
        }
        with self._lock, self.db.session() as s:
            last = s.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(1)).first()
            prev = last.entry_hash if last else GENESIS
            row = AuditLog(**entry, prev_hash=prev, entry_hash=entry_hash(prev, entry))
            s.add(row)
            s.flush()
            entry["id"] = row.id
        entry["write_ms"] = (time.perf_counter() - t0) * 1000
        return entry

    def list(self, limit: int = 100, since_id: int = 0, action: str | None = None,
             outcome: str | None = None, request_id: str | None = None) -> list[dict]:
        q = select(AuditLog).where(AuditLog.id > since_id)
        if action:
            q = q.where(AuditLog.action == action)
        if outcome:
            q = q.where(AuditLog.outcome == outcome)
        if request_id:
            q = q.where(AuditLog.request_id == request_id)
        q = q.order_by(AuditLog.id.desc()).limit(max(1, min(int(limit), 1000)))
        with self.db.session() as s:
            return [row_to_dict(r) for r in s.scalars(q)]

    def verify_chain(self) -> tuple[bool, int | None]:
        """Recompute every hash; returns (ok, first broken entry id)."""
        prev = GENESIS
        with self.db.session() as s:
            for row in s.scalars(select(AuditLog).order_by(AuditLog.id)):
                d = row_to_dict(row)
                if row.prev_hash != prev or entry_hash(prev, d) != row.entry_hash:
                    return False, row.id
                prev = row.entry_hash
        return True, None


def row_to_dict(r: AuditLog) -> dict:
    return {
        "id": r.id, "ts": r.ts, "request_id": r.request_id, "actor": r.actor, "role": r.role,
        "src_ip": r.src_ip, "device": r.device, "action": r.action, "outcome": r.outcome,
        "code": r.code, "detail": r.detail, "prev_hash": r.prev_hash, "entry_hash": r.entry_hash,
    }
